'use strict'

/**
 * Running the SentinelForge scanner and reading what it wrote.
 *
 * The extension contains no detection logic. It runs `python -m app.cli scan`
 * — the same command a build pipeline runs — and reads the JSON report. One
 * analyser means the editor, the pipeline and the web application cannot
 * disagree about what is a finding.
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

const DEFAULT_TIMEOUT_MS = 120_000
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

module.exports = {
  DEFAULT_TIMEOUT_MS,
  ScanError,
  buildArguments,
  excludedCount,
  execFile,
  explain,
  parseReport,
  scan,
}
