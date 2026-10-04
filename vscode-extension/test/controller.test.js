'use strict'

const assert = require('node:assert/strict')
const path = require('node:path')
const { describe, it } = require('node:test')

const { IDLE_TEXT, createController, merge } = require('../src/controller')
const { ScanError } = require('../src/scanner')
const { createFakeVscode } = require('../support/fake-vscode')

function finding(overrides = {}) {
  return {
    rule_id: 'PY010',
    title: 'SQL query built by string formatting',
    message: 'A value formatted into SQL can change the statement.',
    severity: 'CRITICAL',
    cwe_id: 'CWE-89',
    file_path: 'app/users.py',
    line_start: 24,
    line_end: 24,
    ...overrides,
  }
}

function report(findings = [finding()], overrides = {}) {
  return {
    open_count: findings.length,
    score: 40,
    grade: 'C',
    counts_by_severity: { CRITICAL: findings.length, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
    scan: { truncated: false },
    rules: [{ rule_id: 'PY010', fix_note: 'Pass values as parameters.' }],
    findings,
    ...overrides,
  }
}

/** A scanner that returns what it is told to, and records what it was asked. */
function fakeScanner(...results) {
  const calls = []
  const queue = [...results]
  const scan = async (options) => {
    calls.push(options)
    const next = queue.length > 1 ? queue.shift() : queue[0]
    if (next instanceof Error) throw next
    return typeof next === 'function' ? next(options) : next
  }
  return { scan, calls }
}

function setup({ results = [{ report: report(), excluded: 0 }], ...options } = {}) {
  const fake = createFakeVscode(options)
  const scanner = fakeScanner(...results)
  const timers = []
  const controller = createController(fake.vscode, fake.context, {
    scan: scanner.scan,
    setTimeout: (callback, delay) => {
      const timer = { callback, delay, cleared: false }
      timers.push(timer)
      return timer
    },
    clearTimeout: (timer) => {
      timer.cleared = true
    },
  })
  return { ...fake, controller, scanner, timers }
}

describe('activation', () => {
  it('shows a status bar item that scans when clicked, and registers three commands', () => {
    const { state } = setup()

    assert.equal(state.status.shown, true)
    assert.equal(state.status.text, IDLE_TEXT)
    assert.equal(state.status.command, 'sentinelforge.scanWorkspace')
    assert.deepEqual([...state.commands.keys()].sort(), [
      'sentinelforge.clear',
      'sentinelforge.openReport',
      'sentinelforge.scanWorkspace',
    ])
  })

  it('scans nothing until it is asked to', () => {
    const { scanner } = setup()

    assert.equal(scanner.calls.length, 0)
  })

  it('hands everything it creates to the editor to dispose of', () => {
    const { context } = setup()

    assert.ok(context.subscriptions.length >= 7)
    for (const item of context.subscriptions) assert.equal(typeof item.dispose, 'function')
  })
})

describe('scanning', () => {
  it('puts each finding on its line, in its file, with its severity', async () => {
    const { controller, state, vscode } = setup({
      results: [
        {
          report: report([
            finding(),
            finding({ file_path: 'lib/hash.py', line_start: 3, line_end: 5, severity: 'MEDIUM', cwe_id: null }),
          ]),
          excluded: 0,
        },
      ],
    })

    assert.equal(await controller.scanWorkspace(), true)

    assert.deepEqual([...state.diagnostics.keys()], [
      path.join('/work/project', 'app', 'users.py'),
      path.join('/work/project', 'lib', 'hash.py'),
    ])
    const [sql] = state.diagnostics.get(path.join('/work/project', 'app', 'users.py'))
    assert.equal(sql.severity, vscode.DiagnosticSeverity.Error)
    assert.equal(sql.source, 'SentinelForge')
    assert.deepEqual(
      [sql.range.startLine, sql.range.startCharacter, sql.range.endLine],
      [23, 0, 23],
    )
    assert.ok(sql.range.endCharacter > 10_000)
    assert.match(sql.message, /^SQL query built by string formatting\n/)
    assert.match(sql.message, /Fix: Pass values as parameters\.$/)
    assert.equal(sql.code.value, 'PY010')
    assert.equal(sql.code.target.value, 'https://cwe.mitre.org/data/definitions/89.html')

    const [hash] = state.diagnostics.get(path.join('/work/project', 'lib', 'hash.py'))
    assert.equal(hash.severity, vscode.DiagnosticSeverity.Warning)
    assert.deepEqual([hash.range.startLine, hash.range.endLine], [2, 4])
    assert.equal(hash.code, 'PY010') // no CWE: a plain code, not a link
  })

  it('asks the scanner about the workspace folder, with the user settings', async () => {
    const { controller, scanner } = setup({
      configuration: { pythonPath: 'C:\\venv\\python.exe', backendPath: 'C:\\sf\\backend', exclude: ['tests'], timeoutSeconds: 30 },
    })

    await controller.scanWorkspace()

    assert.deepEqual(scanner.calls, [
      {
        pythonPath: 'C:\\venv\\python.exe',
        backendPath: 'C:\\sf\\backend',
        excludes: ['tests'],
        timeoutMs: 30_000,
        folder: '/work/project',
        htmlPath: undefined,
      },
    ])
  })

  it('falls back to two minutes when the timeout setting is unusable', async () => {
    for (const timeoutSeconds of [undefined, 'soon', 0, -5, 2]) {
      const { controller, scanner } = setup({ configuration: { timeoutSeconds } })
      await controller.scanWorkspace()
      assert.equal(scanner.calls[0].timeoutMs, 120_000)
    }
  })

  it('shows the grade and the count in the status bar', async () => {
    const { controller, state } = setup({ results: [{ report: report(), excluded: 4 }] })

    await controller.scanWorkspace()

    assert.equal(state.status.text, '$(shield) SentinelForge C · 1')
    assert.match(state.status.tooltip, /Risk 40\/100 \(grade C\), 1 open finding/)
    assert.match(state.status.tooltip, /4 findings left out by sentinelforge\.exclude/)
  })

  it('replaces the previous results rather than adding to them', async () => {
    const { controller, state } = setup({
      results: [
        { report: report([finding(), finding({ file_path: 'old.py' })]), excluded: 0 },
        { report: report([finding({ file_path: 'new.py' })]), excluded: 0 },
      ],
    })

    await controller.scanWorkspace()
    await controller.scanWorkspace()

    assert.deepEqual([...state.diagnostics.keys()], [path.join('/work/project', 'new.py')])
    assert.equal(state.clears, 2)
  })

  it('does not attach a finding to a file outside the workspace', async () => {
    const { controller, state } = setup({
      results: [{ report: report([finding({ file_path: '../../etc/passwd' }), finding()]), excluded: 0 }],
    })

    await controller.scanWorkspace()

    assert.deepEqual([...state.diagnostics.keys()], [path.join('/work/project', 'app', 'users.py')])
    assert.match(state.status.tooltip, /1 finding could not be placed in a file/)
  })

  it('has nothing to scan without a folder, and says so', async () => {
    const { controller, state, scanner } = setup({ folders: [] })

    assert.equal(await controller.scanWorkspace(), false)

    assert.equal(scanner.calls.length, 0)
    assert.deepEqual(state.infos, ['SentinelForge: open a folder to scan it.'])
  })

  it('scans every folder of a multi-root workspace and adds them up', async () => {
    const { controller, state, scanner } = setup({
      folders: ['/work/api', '/work/web'],
      configuration: { perFolder: { '/work/web': { exclude: ['dist'] } } },
      results: [
        (options) => ({
          report: report([finding()], options.folder === '/work/web' ? { grade: 'F', score: 90 } : {}),
          excluded: 0,
        }),
      ],
    })

    await controller.scanWorkspace()

    assert.deepEqual(scanner.calls.map((call) => call.folder), ['/work/api', '/work/web'])
    assert.deepEqual(scanner.calls.map((call) => call.excludes), [[], ['dist']])
    assert.equal(state.diagnostics.size, 2)
    assert.equal(state.status.text, '$(shield) SentinelForge F · 2')
    assert.equal(state.sets, 1) // shown together, once both are done
  })
})

describe('when a scan fails', () => {
  it('says why, keeps the old findings, and offers the settings', async () => {
    const { controller, state } = setup({
      results: [{ report: report(), excluded: 0 }, new ScanError('Python was not found at "python".', 'detail')],
    })
    await controller.scanWorkspace()

    assert.equal(await controller.scanWorkspace(), false)

    assert.deepEqual(state.errors, [{ message: 'Python was not found at "python".', actions: ['Open settings'] }])
    assert.equal(state.diagnostics.size, 1) // not cleared: a failed scan found nothing out
    assert.match(state.status.text, /\$\(warning\)/)
    assert.deepEqual(state.output.slice(-2), ['Python was not found at "python".', 'detail'])
    assert.deepEqual(state.executed, [])
  })

  it('opens the settings when asked to', async () => {
    const { controller, state } = setup({ results: [new ScanError('No scanner.')] })
    state.errorChoice = 'Open settings'

    await controller.scanWorkspace()

    assert.deepEqual(state.executed, [['workbench.action.openSettings', 'sentinelforge']])
  })

  it('can scan again afterwards', async () => {
    const { controller, state } = setup({
      results: [new ScanError('Once.'), { report: report(), excluded: 0 }],
    })

    assert.equal(await controller.scanWorkspace(), false)
    assert.equal(await controller.scanWorkspace(), true)
    assert.equal(state.status.text, '$(shield) SentinelForge C · 1')
  })

  it('survives an error that is not one of its own', async () => {
    const { controller, state } = setup({ results: [new TypeError('unexpected')] })

    assert.equal(await controller.scanWorkspace(), false)
    assert.match(state.errors[0].message, /unexpected/)
  })
})

describe('one scan at a time', () => {
  it('runs a second request after the first, once, however many were made', async () => {
    let release
    const gate = new Promise((resolve) => {
      release = resolve
    })
    let started = 0
    const { controller, scanner } = setup({
      results: [
        async () => {
          started += 1
          if (started === 1) await gate
          return { report: report(), excluded: 0 }
        },
      ],
    })

    const first = controller.scanWorkspace()
    await Promise.resolve()
    assert.equal(await controller.scanWorkspace(), false)
    assert.equal(await controller.scanWorkspace(), false)
    assert.equal(await controller.scanWorkspace(), false)
    assert.equal(scanner.calls.length, 1)
    release()
    await first

    assert.equal(scanner.calls.length, 2)
  })
})

describe('scan on save', () => {
  it('does nothing unless it is switched on', () => {
    const { state, timers } = setup()

    state.saveListeners[0]()

    assert.equal(timers.length, 0)
  })

  it('waits a moment, so that "save all" is one scan', async () => {
    const { state, timers, scanner } = setup({ configuration: { scanOnSave: true } })

    state.saveListeners[0]()
    state.saveListeners[0]()
    state.saveListeners[0]()

    assert.equal(timers.length, 3)
    assert.deepEqual(timers.map((timer) => timer.cleared), [true, true, false])
    assert.equal(timers[2].delay, 1000)
    assert.equal(scanner.calls.length, 0)
    timers[2].callback()
    await new Promise((resolve) => setImmediate(resolve))
    assert.equal(scanner.calls.length, 1)
  })
})

describe('the report', () => {
  it('is written to the extension storage and opened in the browser', async () => {
    const { controller, state, scanner } = setup()

    await controller.openReport()

    const expected = path.join('/storage/sentinelforge', 'report.html')
    assert.deepEqual(state.createdDirectories, ['/storage/sentinelforge'])
    assert.equal(scanner.calls[0].htmlPath, expected)
    assert.deepEqual(state.opened, [expected])
  })

  it('is not opened when the scan failed', async () => {
    const { controller, state } = setup({ results: [new ScanError('No scanner.')] })

    await controller.openReport()

    assert.deepEqual(state.opened, [])
  })

  it('is written once, for the first folder', async () => {
    const { controller, scanner } = setup({ folders: ['/work/api', '/work/web'] })

    await controller.openReport()

    assert.deepEqual(scanner.calls.map((call) => typeof call.htmlPath), ['string', 'undefined'])
  })
})

describe('clearing', () => {
  it('removes the findings and resets the status bar', async () => {
    const { controller, state } = setup()
    await controller.scanWorkspace()

    state.commands.get('sentinelforge.clear')()

    assert.equal(state.diagnostics.size, 0)
    assert.equal(state.status.text, IDLE_TEXT)
  })
})

describe('merge', () => {
  it('adds counts and keeps the worst grade and score', () => {
    const totals = { open_count: 0, score: 0, grade: 'A', counts_by_severity: {}, scan: {} }

    merge(totals, { open_count: 2, score: 30, grade: 'C', counts_by_severity: { HIGH: 2 } })
    merge(totals, { open_count: 1, score: 10, grade: 'B', counts_by_severity: { HIGH: 1, LOW: 'x' }, scan: { truncated: true } })

    assert.deepEqual(totals, {
      open_count: 3,
      score: 30,
      grade: 'C',
      counts_by_severity: { HIGH: 3 },
      scan: { truncated: true },
    })
  })
})
