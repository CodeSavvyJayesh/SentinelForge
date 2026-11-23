'use strict'

/**
 * Running the SentinelForge scanner and reading what it wrote.
 *
 * The extension contains no detection logic. It runs `python -m app.cli scan`
 * — the same command a build pipeline runs — and reads the JSON report. One
 * analyser means the editor, the pipeline and the web application cannot
 * disagree about what is a finding. A fix is asked for the same way
 * (`python -m app.cli fix`), so the editor cannot disagree with the scanner
 * about whether a change worked either: the scanner re-scans it and says.
 *
 * Three decisions here are about not being turned against the user:
 *
 * - **No shell.** The command is an executable and a list of arguments, so no
 *   part of a path or a setting is ever interpreted as shell syntax.
 * - **The working directory is the scanner's folder, never the workspace.**
 *   `python -m` puts the working directory first on its import path. Run from
 *   the workspace, a repository containing its own `app/cli` package would be
 *   executed instead of the scanner.
 * - **Every option is one token.** `--exclude=PATTERN`, not `--exclude`
 *   followed by the pattern, so a pattern that begins with `--` stays a
 *   pattern and cannot become another option.
 */

const childProcess = require('node:child_process')
const fs = require('node:fs/promises')
const os = require('node:os')
const path = require('node:path')

const { FixResultError, MODES, isFingerprint, isMode, parseFixResult } = require('./fixes')

const DEFAULT_TIMEOUT_MS = 120_000
const DEFAULT_MODEL_TIMEOUT_SECONDS = 300
// The fix command's own exit codes: a change the re-scan supports, no change
// to offer, and "could not be run". The first two both come with a result.
const EXIT_NO_FIX = 1
const MAX_OUTPUT_BYTES = 10 * 1024 * 1024
const MAX_REPORT_BYTES = 100 * 1024 * 1024

class ScanError extends Error {
  /**
   * @param {string} message  what to tell the user
   * @param {string} [detail] the scanner's own words, for the output channel
   */
  constructor(message, detail = '') {
    super(message)
    this.name = 'ScanError'
    this.detail = detail
  }
}

/**
 * A fix could not be attempted. `setup` is true when the cause is how the
 * extension is configured rather than the finding or the model.
 */
class FixError extends ScanError {
  constructor(message, detail = '', { setup = false } = {}) {
    super(message, detail)
    this.name = 'FixError'
    this.setup = setup
  }
}

function buildArguments({ folder, jsonPath, htmlPath, excludes = [] }) {
  const args = [
    '-m',
    'app.cli',
    'scan',
    folder,
    // The editor shows findings; it does not fail anything.
    '--fail-on=none',
    '--quiet',
    `--json=${jsonPath}`,
  ]
  if (htmlPath) args.push(`--html=${htmlPath}`)
  for (const pattern of Array.isArray(excludes) ? excludes : []) {
    if (typeof pattern === 'string' && pattern.trim() !== '') {
      args.push(`--exclude=${pattern.trim()}`)
    }
  }
  return args
}

/** How many findings `--exclude` dropped, read from the scanner's summary. */
function excludedCount(stdout) {
  const match = /^\s*(\d+) left out by --exclude\s*$/m.exec(typeof stdout === 'string' ? stdout : '')
  return match ? Number(match[1]) : 0
}

function parseReport(text) {
  let report
  try {
    report = JSON.parse(text)
  } catch {
    throw new ScanError('The scanner wrote a report that is not valid JSON.')
  }
  if (report === null || typeof report !== 'object' || !Array.isArray(report.findings)) {
    throw new ScanError('The scanner wrote a report in a form this extension does not understand.')
  }
  return report
}

/** `execFile` as a promise that never rejects: the caller reads the outcome. */
function execFile(file, args, options) {
  return new Promise((resolve) => {
    childProcess.execFile(file, args, options, (error, stdout, stderr) => {
      resolve({ error: error ?? null, stdout: String(stdout ?? ''), stderr: String(stderr ?? '') })
    })
  })
}

function lastLine(text) {
  const lines = text.split(/\r?\n/).filter((line) => line.trim() !== '')
  return lines.length > 0 ? lines[lines.length - 1].trim() : ''
}

function explain(error, stderr, { pythonPath, timeoutMs }) {
  if (error.code === 'ENOENT') {
    return new ScanError(
      `Python was not found at "${pythonPath}". Set sentinelforge.pythonPath in your user settings.`,
    )
  }
  if (error.killed === true || error.signal) {
    return new ScanError(
      `The scan was stopped after ${Math.round(timeoutMs / 1000)} seconds. ` +
        'Raise sentinelforge.timeoutSeconds, or exclude folders that do not need scanning.',
    )
  }
  if (/No module named '?app(\.cli)?'?/.test(stderr)) {
    return new ScanError(
      'The scanner was not found. Set sentinelforge.backendPath to the "backend" folder of SentinelForge.',
      stderr,
    )
  }
  if (/No module named/.test(stderr)) {
    return new ScanError(
      "That Python does not have the scanner's requirements installed. " +
        'Point sentinelforge.pythonPath at the interpreter in the backend\'s virtual environment.',
      stderr,
    )
  }
  const reason = lastLine(stderr).replace(/^error:\s*/, '')
  return new ScanError(reason ? `The scan could not be run: ${reason}` : 'The scan could not be run.', stderr)
}

/**
 * Scan one folder.
 *
 * @param {{ pythonPath: string, backendPath: string, folder: string,
 *           excludes?: string[], timeoutMs?: number, htmlPath?: string }} options
 * @param {{ execFile?: typeof execFile }} [dependencies] replaced in tests
 * @returns {Promise<{ report: object, excluded: number }>}
 */
async function scan(options, dependencies = {}) {
  const run = dependencies.execFile ?? execFile
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS

  if (!options.backendPath) {
    throw new ScanError(
      'Set sentinelforge.backendPath in your user settings to the "backend" folder of SentinelForge.',
    )
  }

  // The report is written to a private temporary folder, read, and removed.
  // Never into the workspace: a scan should not change what it scans.
  const scratch = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinelforge-'))
  try {
    const jsonPath = path.join(scratch, 'report.json')
    const { error, stdout, stderr } = await run(
      options.pythonPath || 'python',
      buildArguments({ folder: options.folder, jsonPath, htmlPath: options.htmlPath, excludes: options.excludes }),
      {
        cwd: options.backendPath,
        timeout: timeoutMs,
        maxBuffer: MAX_OUTPUT_BYTES,
        windowsHide: true,
        // Same text encoding on every platform, whatever the console is set to.
        env: { ...process.env, PYTHONIOENCODING: 'utf-8', PYTHONUTF8: '1' },
      },
    )
    if (error) throw explain(error, stderr, { pythonPath: options.pythonPath || 'python', timeoutMs })

    let text
    try {
      const { size } = await fs.stat(jsonPath)
      if (size > MAX_REPORT_BYTES) throw new ScanError('The report is too large to load.')
      text = await fs.readFile(jsonPath, 'utf8')
    } catch (cause) {
      if (cause instanceof ScanError) throw cause
      throw new ScanError('The scanner finished without writing a report.', stderr)
    }
    return { report: parseReport(text), excluded: excludedCount(stdout) }
  } finally {
    await fs.rm(scratch, { recursive: true, force: true })
  }
}

function buildFixArguments({ folder, fingerprint, mode, jsonPath, model = {} }) {
  const args = ['-m', 'app.cli', 'fix', folder, `--fingerprint=${fingerprint}`, `--mode=${mode}`, `--json=${jsonPath}`]
  if (mode === MODES.MODEL) {
    // One token each, like every other option: a setting that begins with
    // `--` stays a value.
    if (model.url) args.push(`--ollama-url=${model.url}`)
    if (model.name) args.push(`--model=${model.name}`)
    args.push(`--timeout=${model.timeoutSeconds ?? DEFAULT_MODEL_TIMEOUT_SECONDS}`)
    if (model.allowRemote === true) args.push('--allow-remote-model')
    if (model.retry === true) args.push('--retry')
  }
  return args
}

function explainFix(error, stderr, context) {
  const problem = explain(error, stderr, context)
  // Not found, not installed, timed out: the same causes as for a scan, and
  // the same advice. Anything else is the fix command saying why it stopped.
  const setup = error.code === 'ENOENT' || /No module named/.test(stderr)
  if (setup) return new FixError(problem.message, problem.detail, { setup: true })
  if (error.killed === true || error.signal) {
    return new FixError(
      `The fix was stopped after ${Math.round(context.timeoutMs / 1000)} seconds. ` +
        'A local model can take minutes on a CPU: raise sentinelforge.modelTimeoutSeconds.',
      stderr,
    )
  }
  const reason = lastLine(stderr).replace(/^error:\s*/, '')
  return new FixError(reason || 'The fix could not be worked out.', stderr)
}

/**
 * Ask the scanner for a fix for one finding, checked by a re-scan.
 *
 * Nothing in the workspace is written by this: the scanner works on a copy,
 * and the result says what would change. Applying it is the editor's job, and
 * the user's decision.
 *
 * @param {{ pythonPath: string, backendPath: string, folder: string,
 *           fingerprint: string, mode: string, timeoutMs?: number,
 *           model?: { url?: string, name?: string, timeoutSeconds?: number,
 *                     allowRemote?: boolean, retry?: boolean } }} options
 * @param {{ execFile?: typeof execFile }} [dependencies] replaced in tests
 * @returns {Promise<object>} the result, as `parseFixResult` returns it
 */
async function fix(options, dependencies = {}) {
  const run = dependencies.execFile ?? execFile
  if (!options.backendPath) {
    throw new FixError(
      'Set sentinelforge.backendPath in your user settings to the "backend" folder of SentinelForge.',
      '',
      { setup: true },
    )
  }
  if (!isFingerprint(options.fingerprint) || !isMode(options.mode)) {
    throw new FixError('That finding cannot be fixed from here. Scan again, then ask for the fix.')
  }
  const scanMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const modelSeconds = options.model?.timeoutSeconds ?? DEFAULT_MODEL_TIMEOUT_SECONDS
  // A fix scans twice; with the model it also waits for one generation.
  const timeoutMs = options.mode === MODES.MODEL ? scanMs * 2 + modelSeconds * 1000 : scanMs * 2

  const scratch = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinelforge-'))
  try {
    const jsonPath = path.join(scratch, 'fix.json')
    const pythonPath = options.pythonPath || 'python'
    const { error, stderr } = await run(
      pythonPath,
      buildFixArguments({ ...options, jsonPath, model: { ...options.model, timeoutSeconds: modelSeconds } }),
      {
        cwd: options.backendPath,
        timeout: timeoutMs,
        maxBuffer: MAX_OUTPUT_BYTES,
        windowsHide: true,
        env: { ...process.env, PYTHONIOENCODING: 'utf-8', PYTHONUTF8: '1' },
      },
    )
    if (error && error.code !== EXIT_NO_FIX) throw explainFix(error, stderr, { pythonPath, timeoutMs })

    let text
    try {
      const { size } = await fs.stat(jsonPath)
      if (size > MAX_REPORT_BYTES) throw new FixError('The result is too large to load.')
      text = await fs.readFile(jsonPath, 'utf8')
    } catch (cause) {
      if (cause instanceof FixError) throw cause
      throw new FixError('The scanner finished without writing a result.', stderr)
    }
    try {
      return parseFixResult(JSON.parse(text))
    } catch (cause) {
      if (cause instanceof FixResultError) throw new FixError(cause.message)
      throw new FixError('The scanner wrote a result that is not valid JSON.')
    }
  } finally {
    await fs.rm(scratch, { recursive: true, force: true })
  }
}

module.exports = {
  DEFAULT_MODEL_TIMEOUT_SECONDS,
  DEFAULT_TIMEOUT_MS,
  FixError,
  ScanError,
  buildArguments,
  buildFixArguments,
  explainFix,
  fix,
  excludedCount,
  execFile,
  explain,
  parseReport,
  scan,
}
