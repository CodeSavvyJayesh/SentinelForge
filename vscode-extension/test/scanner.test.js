'use strict'

const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { describe, it } = require('node:test')

const {
  DEFAULT_MODEL_TIMEOUT_SECONDS,
  FixError,
  ScanError,
  buildArguments,
  buildFixArguments,
  excludedCount,
  fix,
  parseReport,
  scan,
} = require('../src/scanner')

const REPORT = { open_count: 1, score: 40, grade: 'C', findings: [{ file_path: 'a.py', line_start: 1 }] }
const OPTIONS = { pythonPath: '/venv/bin/python', backendPath: '/sf/backend', folder: '/work/project' }

/** A stand-in for running Python: records the call, optionally writes a report. */
function fakeRun({ report = REPORT, raw, error = null, stdout = '', stderr = '' } = {}) {
  const calls = []
  const run = async (file, args, options) => {
    calls.push({ file, args, options })
    const jsonPath = args.find((arg) => arg.startsWith('--json=')).slice('--json='.length)
    calls.scratch = path.dirname(jsonPath)
    if (raw !== undefined) fs.writeFileSync(jsonPath, raw)
    else if (report !== null) fs.writeFileSync(jsonPath, JSON.stringify(report))
    return { error, stdout, stderr }
  }
  return { run, calls }
}

function failure(properties) {
  return Object.assign(new Error('failed'), properties)
}

describe('buildArguments', () => {
  it('runs the same command a pipeline runs, and never fails the editor', () => {
    assert.deepEqual(buildArguments({ folder: '/work/project', jsonPath: '/tmp/r.json' }), [
      '-m',
      'app.cli',
      'scan',
      '/work/project',
      '--fail-on=none',
      '--quiet',
      '--json=/tmp/r.json',
    ])
  })

  it('passes every option as one token, so a value cannot become an option', () => {
    const args = buildArguments({
      folder: '/work/project',
      jsonPath: '/tmp/r.json',
      htmlPath: '/tmp/r.html',
      excludes: ['tests', '--sarif=/tmp/stolen.sarif', '  *.min.js  ', '--html', '/etc/cron.d/x'],
    })

    assert.deepEqual(args.slice(7), [
      '--html=/tmp/r.html',
      '--exclude=tests',
      '--exclude=--sarif=/tmp/stolen.sarif',
      '--exclude=*.min.js',
      '--exclude=--html',
      '--exclude=/etc/cron.d/x',
    ])
    // Exactly one of each real option, however the patterns are spelled.
    assert.equal(args.filter((arg) => arg.startsWith('--html')).length, 1)
    assert.equal(args.filter((arg) => arg.startsWith('--sarif')).length, 0)
  })

  it('drops exclusions that are not text', () => {
    const args = buildArguments({
      folder: '/w',
      jsonPath: '/tmp/r.json',
      excludes: ['', '   ', null, 7, { a: 1 }, ['x'], 'docs'],
    })

    assert.deepEqual(args.slice(7), ['--exclude=docs'])
    assert.deepEqual(buildArguments({ folder: '/w', jsonPath: '/j', excludes: 'tests' }).slice(7), [])
  })
})

describe('excludedCount', () => {
  it('reads the number the scanner printed', () => {
    assert.equal(excludedCount('SentinelForge 0.1.0: p\n  3 findings\n  43 left out by --exclude\n\nPASSED\n'), 43)
    assert.equal(excludedCount('  1 left out by --exclude\r\n'), 1)
  })

  it('is zero when nothing was left out, or nothing was printed', () => {
    assert.equal(excludedCount('SentinelForge 0.1.0: p\n  3 findings\n'), 0)
    assert.equal(excludedCount(''), 0)
    assert.equal(excludedCount(undefined), 0)
  })

  it('is not fooled by a file name that contains the phrase', () => {
    assert.equal(excludedCount('  HIGH PY003 a/9 left out by --exclude.py:3  os.system()\n'), 0)
  })
})

describe('parseReport', () => {
  it('accepts a report', () => {
    assert.deepEqual(parseReport(JSON.stringify(REPORT)), REPORT)
  })

  for (const [name, text] of [
    ['not JSON', '{not json'],
    ['an array', '[]'],
    ['null', 'null'],
    ['a report with no findings list', '{"findings": "many"}'],
    ['nothing', ''],
  ]) {
    it(`refuses ${name}`, () => {
      assert.throws(() => parseReport(text), ScanError)
    })
  }
})

describe('scan', () => {
  it('runs Python from the scanner folder, never from the workspace', async () => {
    const { run, calls } = fakeRun()

    const result = await scan(OPTIONS, { execFile: run })

    assert.deepEqual(result, { report: REPORT, excluded: 0 })
    assert.equal(calls.length, 1)
    assert.equal(calls[0].file, '/venv/bin/python')
    assert.equal(calls[0].options.cwd, '/sf/backend')
    assert.notEqual(calls[0].options.cwd, OPTIONS.folder)
    assert.equal(calls[0].args[3], '/work/project')
  })

  it('never goes through a shell', async () => {
    const { run, calls } = fakeRun()

    await scan(OPTIONS, { execFile: run })

    assert.equal(calls[0].options.shell, undefined)
    assert.equal(calls[0].options.windowsHide, true)
    assert.ok(Array.isArray(calls[0].args))
  })

  it('gives the scan a time limit and one text encoding', async () => {
    const { run, calls } = fakeRun()

    await scan({ ...OPTIONS, timeoutMs: 5000 }, { execFile: run })

    assert.equal(calls[0].options.timeout, 5000)
    assert.equal(calls[0].options.env.PYTHONUTF8, '1')
    assert.equal(calls[0].options.env.PYTHONIOENCODING, 'utf-8')
  })

  it('writes the report outside the workspace and removes it afterwards', async () => {
    const { run, calls } = fakeRun()

    await scan(OPTIONS, { execFile: run })

    assert.ok(calls.scratch.startsWith(os.tmpdir()))
    assert.ok(!calls.scratch.startsWith(OPTIONS.folder))
    assert.equal(fs.existsSync(calls.scratch), false)
  })

  it('removes its scratch folder when the scan fails, too', async () => {
    const { run, calls } = fakeRun({ error: failure({ code: 2 }), stderr: 'error: not a folder: x\n' })

    await assert.rejects(scan(OPTIONS, { execFile: run }), ScanError)

    assert.equal(fs.existsSync(calls.scratch), false)
  })

  it('passes exclusions and the report path through, and reads how many were left out', async () => {
    const { run, calls } = fakeRun({ stdout: '  7 left out by --exclude\n' })

    const result = await scan({ ...OPTIONS, excludes: ['tests'], htmlPath: '/store/report.html' }, { execFile: run })

    assert.equal(result.excluded, 7)
    assert.ok(calls[0].args.includes('--exclude=tests'))
    assert.ok(calls[0].args.includes('--html=/store/report.html'))
  })

  it('uses "python" when no interpreter is configured', async () => {
    const { run, calls } = fakeRun()

    await scan({ ...OPTIONS, pythonPath: '' }, { execFile: run })

    assert.equal(calls[0].file, 'python')
  })

  it('does not run anything until it knows where the scanner is', async () => {
    const { run, calls } = fakeRun()

    await assert.rejects(scan({ ...OPTIONS, backendPath: '' }, { execFile: run }), /sentinelforge\.backendPath/)

    assert.equal(calls.length, 0)
  })

  const explanations = [
    ['a missing interpreter', { error: failure({ code: 'ENOENT' }) }, /Python was not found at "\/venv\/bin\/python"/],
    ['a scan that ran out of time', { error: failure({ killed: true, signal: 'SIGTERM' }) }, /stopped after 120 seconds/],
    [
      'a backend path with no scanner in it',
      { error: failure({ code: 1 }), stderr: "/venv/bin/python: No module named app.cli\n" },
      /scanner was not found/,
    ],
    [
      'a Python without the requirements',
      { error: failure({ code: 2 }), stderr: "error: the scan could not be run: ModuleNotFoundError: No module named 'pydantic'\n" },
      /does not have the scanner's requirements/,
    ],
    [
      "the scanner's own error",
      { error: failure({ code: 2 }), stderr: 'error: not a folder: /work/project\n' },
      /^The scan could not be run: not a folder: \/work\/project$/,
    ],
    ['a failure that said nothing', { error: failure({ code: 1 }) }, /^The scan could not be run\.$/],
    ['a scan that wrote no report', { report: null }, /without writing a report/],
    ['a report that is not JSON', { raw: '<html>' }, /not valid JSON/],
  ]
  for (const [name, outcome, expected] of explanations) {
    it(`explains ${name} in words`, async () => {
      const { run } = fakeRun({ report: null, ...outcome })

      await assert.rejects(scan(OPTIONS, { execFile: run }), (error) => {
        assert.ok(error instanceof ScanError)
        assert.match(error.message, expected)
        return true
      })
    })
  }

  it("keeps the scanner's own words for the output channel", async () => {
    const { run } = fakeRun({ report: null, error: failure({ code: 2 }), stderr: 'Traceback…\nerror: boom\n' })

    await assert.rejects(scan(OPTIONS, { execFile: run }), (error) => {
      assert.equal(error.message, 'The scan could not be run: boom')
      assert.match(error.detail, /Traceback/)
      return true
    })
  })
})

// --- fixes -------------------------------------------------------------------

const FINGERPRINT = 'b'.repeat(64)
const FIX_OPTIONS = { ...OPTIONS, fingerprint: FINGERPRINT, mode: 'builtin' }
const FIX_RESULT = {
  schema: 1,
  status: 'verified',
  source: 'builtin',
  title: 'Use SHA-256 instead of a broken hash',
  edits: [{ first_line: 5, last_line: 5, old: ['md5\n'], new: ['sha256\n'] }],
}

describe('buildFixArguments', () => {
  it('asks for one finding by fingerprint, with every option one token', () => {
    assert.deepEqual(
      buildFixArguments({ folder: '/work/project', fingerprint: FINGERPRINT, mode: 'builtin', jsonPath: '/tmp/f.json' }),
      ['-m', 'app.cli', 'fix', '/work/project', `--fingerprint=${FINGERPRINT}`, '--mode=builtin', '--json=/tmp/f.json'],
    )
  })

  it('never asks the scanner to write the change itself', () => {
    const args = buildFixArguments({ folder: '/w', fingerprint: FINGERPRINT, mode: 'model', jsonPath: '/tmp/f.json' })

    assert.equal(args.includes('--apply'), false)
  })

  it('passes the model settings only when the model is asked', () => {
    const model = { url: 'http://localhost:11434', name: '--apply', timeoutSeconds: 90, allowRemote: false, retry: true }

    assert.deepEqual(
      buildFixArguments({ folder: '/w', fingerprint: FINGERPRINT, mode: 'model', jsonPath: '/j', model }).slice(7),
      ['--ollama-url=http://localhost:11434', '--model=--apply', '--timeout=90', '--retry'],
    )
    assert.equal(
      buildFixArguments({ folder: '/w', fingerprint: FINGERPRINT, mode: 'builtin', jsonPath: '/j', model }).length,
      7,
    )
  })

  it('sends code to a model on another machine only when the user allowed it', () => {
    const args = buildFixArguments({
      folder: '/w',
      fingerprint: FINGERPRINT,
      mode: 'model',
      jsonPath: '/j',
      model: { allowRemote: true },
    })

    assert.ok(args.includes('--allow-remote-model'))
    assert.ok(args.includes(`--timeout=${DEFAULT_MODEL_TIMEOUT_SECONDS}`))
  })
})

describe('fix', () => {
  it('runs the fix command from the scanner folder and reads its result', async () => {
    const { run, calls } = fakeRun({ report: FIX_RESULT })

    const result = await fix(FIX_OPTIONS, { execFile: run })

    assert.equal(result.status, 'verified')
    assert.equal(result.edits[0].firstLine, 5)
    assert.equal(calls[0].file, '/venv/bin/python')
    assert.equal(calls[0].options.cwd, '/sf/backend')
    assert.deepEqual(calls[0].args.slice(0, 4), ['-m', 'app.cli', 'fix', '/work/project'])
  })

  it('reads the result of "no change to offer", which exits with 1', async () => {
    const { run } = fakeRun({ report: { schema: 1, status: 'no_fix', reason: 'No built-in fix.' }, error: failure({ code: 1 }) })

    const result = await fix(FIX_OPTIONS, { execFile: run })

    assert.equal(result.status, 'no_fix')
    assert.equal(result.reason, 'No built-in fix.')
  })

  it('removes its scratch folder afterwards', async () => {
    const { run, calls } = fakeRun({ report: FIX_RESULT })

    await fix(FIX_OPTIONS, { execFile: run })

    assert.equal(fs.existsSync(calls.scratch), false)
  })

  it('gives the model time to answer on top of two scans', async () => {
    const { run, calls } = fakeRun({ report: FIX_RESULT })

    await fix({ ...FIX_OPTIONS, mode: 'model', timeoutMs: 10_000, model: { timeoutSeconds: 60 } }, { execFile: run })

    assert.equal(calls[0].options.timeout, 10_000 * 2 + 60_000)
  })

  it('does not run anything for a request it cannot trust', async () => {
    const { run, calls } = fakeRun({ report: FIX_RESULT })

    await assert.rejects(fix({ ...FIX_OPTIONS, fingerprint: '--apply' }, { execFile: run }), FixError)
    await assert.rejects(fix({ ...FIX_OPTIONS, mode: 'shell' }, { execFile: run }), FixError)
    await assert.rejects(fix({ ...FIX_OPTIONS, backendPath: '' }, { execFile: run }), (error) => error.setup === true)

    assert.equal(calls.length, 0)
  })

  const failures = [
    ['a missing interpreter, as a setup problem', { error: failure({ code: 'ENOENT' }) }, /Python was not found/, true],
    [
      'a model that took too long',
      { error: failure({ killed: true, signal: 'SIGTERM' }) },
      /stopped after \d+ seconds\..*modelTimeoutSeconds/,
      false,
    ],
    [
      "the fix command's own reason",
      { error: failure({ code: 2 }), stderr: 'error: Could not reach Ollama at http://localhost:11434\n' },
      /^Could not reach Ollama at http:\/\/localhost:11434$/,
      false,
    ],
    ['a command that wrote no result', { report: null }, /without writing a result/, false],
    ['a result that is not JSON', { raw: '{' }, /not valid JSON/, false],
    ['a result in another shape', { report: { schema: 1, status: 'verified', edits: [] } }, /nothing to apply/, false],
  ]
  for (const [name, outcome, expected, setup] of failures) {
    it(`explains ${name}`, async () => {
      const { run } = fakeRun({ report: null, ...outcome })

      await assert.rejects(fix(FIX_OPTIONS, { execFile: run }), (error) => {
        assert.ok(error instanceof FixError)
        assert.match(error.message, expected)
        assert.equal(error.setup, setup)
        return true
      })
    })
  }
})
