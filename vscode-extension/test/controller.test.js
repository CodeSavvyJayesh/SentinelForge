'use strict'

const assert = require('node:assert/strict')
const path = require('node:path')
const { describe, it } = require('node:test')

const { ASK_MODEL_TITLE, BUTTONS, FIX_COMMAND, IDLE_TEXT, PROPOSAL_SCHEME, createController, merge } = require('../src/controller')
const { FixError, ScanError } = require('../src/scanner')
const { parseFixResult } = require('../src/fixes')
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

function setup({ results = [{ report: report(), excluded: 0 }], fixResults = [], ...options } = {}) {
  const fake = createFakeVscode(options)
  const scanner = fakeScanner(...results)
  const fixer = fakeScanner(...fixResults)
  const timers = []
  const controller = createController(fake.vscode, fake.context, {
    scan: scanner.scan,
    fix: fixer.scan,
    setTimeout: (callback, delay) => {
      const timer = { callback, delay, cleared: false }
      timers.push(timer)
      return timer
    },
    clearTimeout: (timer) => {
      timer.cleared = true
    },
  })
  return { ...fake, controller, scanner, fixer, timers }
}

describe('activation', () => {
  it('shows a status bar item that scans when clicked, and registers its four commands', () => {
    const { state } = setup()

    assert.equal(state.status.shown, true)
    assert.equal(state.status.text, IDLE_TEXT)
    assert.equal(state.status.command, 'sentinelforge.scanWorkspace')
    assert.deepEqual([...state.commands.keys()].sort(), [
      'sentinelforge.clear',
      'sentinelforge.fix',
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

// --- fixes -------------------------------------------------------------------

const FILE = path.join('/work/project', 'app', 'main.py')
const FIXABLE = 'f'.repeat(64)
const SOURCE = 'import hashlib\n\n\ndef digest(value):\n    return hashlib.md5(value).hexdigest()\n'
const HASH_FINDING = finding({
  rule_id: 'PY007',
  title: 'Weak hash algorithm (MD5 or SHA-1)',
  severity: 'MEDIUM',
  cwe_id: 'CWE-327',
  file_path: 'app/main.py',
  line_start: 5,
  line_end: 5,
  fingerprint: FIXABLE,
})
const FIXABLE_REPORT = report([HASH_FINDING], { quick_fixes: { PY007: 'Use SHA-256 instead of a broken hash' } })

function verified(overrides = {}) {
  return parseFixResult({
    schema: 1,
    status: 'verified',
    source: 'builtin',
    title: 'Use SHA-256 instead of a broken hash',
    rationale: 'MD5 is collision-broken.',
    caution: 'Old digests will not match.',
    edits: [
      {
        first_line: 5,
        last_line: 5,
        old: ['    return hashlib.md5(value).hexdigest()\n'],
        new: ['    return hashlib.sha256(value).hexdigest()\n'],
      },
    ],
    ...overrides,
  })
}

/** A workspace with one scanned, fixable finding, and the file open in the editor. */
async function scanned(options = {}) {
  const context = setup({ results: [{ report: FIXABLE_REPORT, excluded: 0 }], ...options })
  const document = context.addDocument(FILE, SOURCE, options.document)
  await context.controller.scanWorkspace()
  const diagnostic = context.state.diagnostics.get(FILE)[0]
  const actions = context.controller.provideCodeActions(document, diagnostic.range, { diagnostics: [diagnostic] })
  return { ...context, document, diagnostic, actions }
}

describe('quick fixes', () => {
  it('registers a quick-fix provider for files, and a read-only view for proposals', () => {
    const { state } = setup()

    assert.equal(state.codeActionProviders.length, 1)
    assert.deepEqual(state.codeActionProviders[0].selector, { scheme: 'file' })
    assert.deepEqual(state.codeActionProviders[0].metadata.providedCodeActionKinds, ['quickfix'])
    assert.ok(state.contentProviders.has(PROPOSAL_SCHEME))
  })

  it('offers the built-in fix first, and the local model as well', async () => {
    const { actions, diagnostic } = await scanned()

    assert.deepEqual(
      actions.map((action) => [action.title, action.isPreferred]),
      [
        ['SentinelForge: Use SHA-256 instead of a broken hash', true],
        [ASK_MODEL_TITLE, false],
      ],
    )
    assert.deepEqual(actions[0].diagnostics, [diagnostic])
    assert.equal(actions[0].command.command, FIX_COMMAND)
    assert.deepEqual(actions[0].command.arguments, [
      { folder: '/work/project', file: FILE, fingerprint: FIXABLE, mode: 'builtin' },
    ])
    assert.equal(actions[1].command.arguments[0].mode, 'model')
  })

  it('offers only the model for a rule without a built-in fix', async () => {
    const context = setup({ results: [{ report: report([{ ...HASH_FINDING, rule_id: 'PY010' }]), excluded: 0 }] })
    const document = context.addDocument(FILE, SOURCE)
    await context.controller.scanWorkspace()
    const diagnostic = context.state.diagnostics.get(FILE)[0]

    const actions = context.controller.provideCodeActions(document, diagnostic.range, { diagnostics: [diagnostic] })

    assert.deepEqual(actions.map((action) => action.title), [ASK_MODEL_TITLE])
  })

  it('offers nothing for a leaked credential, which is rotated rather than edited', async () => {
    const context = setup({
      results: [{ report: report([{ ...HASH_FINDING, is_credential: true }], { quick_fixes: FIXABLE_REPORT.quick_fixes }), excluded: 0 }],
    })
    const document = context.addDocument(FILE, SOURCE)
    await context.controller.scanWorkspace()
    const diagnostic = context.state.diagnostics.get(FILE)[0]

    assert.deepEqual(context.controller.provideCodeActions(document, diagnostic.range, { diagnostics: [diagnostic] }), [])
  })

  it("offers nothing for another extension's diagnostics, or after the findings are cleared", async () => {
    const { controller, document, diagnostic } = await scanned()

    const other = { ...diagnostic, source: 'eslint' }
    assert.deepEqual(controller.provideCodeActions(document, diagnostic.range, { diagnostics: [other] }), [])

    controller.clear()
    assert.deepEqual(controller.provideCodeActions(document, diagnostic.range, { diagnostics: [diagnostic] }), [])
  })
})

describe('applying a fix', () => {
  it('asks first, then makes the change, saves the file and scans again', async () => {
    const { controller, actions, state, document, fixer, scanner } = await scanned({ fixResults: [verified()] })
    state.infoChoices.push(BUTTONS.APPLY)

    const applied = await controller.fix(actions[0].command.arguments[0])

    assert.equal(applied, true)
    assert.equal(document.getText(), SOURCE.replace('md5', 'sha256'))
    assert.equal(document.saves, 1)
    assert.equal(scanner.calls.length, 2)
    assert.equal(fixer.calls[0].fingerprint, FIXABLE)
    assert.equal(fixer.calls[0].mode, 'builtin')
    assert.equal(fixer.calls[0].model, undefined)
    const question = state.infoCalls.find((call) => call.options?.modal)
    assert.equal(question.message, 'Use SHA-256 instead of a broken hash')
    assert.match(question.options.detail, /Before you accept it: Old digests will not match/)
    assert.match(question.options.detail, /does not say the program behaves the same/)
  })

  it('changes nothing when the user does not choose Apply', async () => {
    const { controller, actions, state, document, scanner } = await scanned({ fixResults: [verified()] })
    state.infoChoices.push(undefined)

    assert.equal(await controller.fix(actions[0].command.arguments[0]), false)

    assert.equal(document.getText(), SOURCE)
    assert.equal(state.applied.length, 0)
    assert.equal(scanner.calls.length, 1)
  })

  it('shows the change side by side before applying it, when asked', async () => {
    const { controller, actions, state, document } = await scanned({ fixResults: [verified()] })
    state.infoChoices.push(BUTTONS.SHOW, BUTTONS.APPLY)

    await controller.fix(actions[0].command.arguments[0])

    const diff = state.executed.find((call) => call[0] === 'vscode.diff')
    assert.equal(diff[1], document.uri)
    assert.equal(diff[2].scheme, PROPOSAL_SCHEME)
    const proposal = state.contentProviders.get(PROPOSAL_SCHEME).provideTextDocumentContent(diff[2])
    assert.equal(proposal, SOURCE.replace('md5', 'sha256'))
    assert.equal(document.getText(), SOURCE.replace('md5', 'sha256'))
  })

  it('refuses to fix a file with unsaved changes, without asking the scanner', async () => {
    const { controller, actions, state, fixer } = await scanned({ fixResults: [verified()], document: { dirty: true } })

    assert.equal(await controller.fix(actions[0].command.arguments[0]), false)

    assert.equal(fixer.calls.length, 0)
    assert.match(state.warnings[0].message, /Save the file first/)
  })

  it('applies nothing when the file changed while the fix was being checked', async () => {
    const { controller, actions, state, document } = await scanned({ fixResults: [verified()] })
    // Edited and saved by the user while the question was open.
    state.infoChoices.push(BUTTONS.SHOW)
    state.infoChoices.push(BUTTONS.APPLY)
    const originalExecute = state.executed.push.bind(state.executed)
    state.executed.push = (call) => {
      if (call[0] === 'vscode.diff') document.text = SOURCE.replace('md5(value)', 'md5(other)')
      return originalExecute(call)
    }

    assert.equal(await controller.fix(actions[0].command.arguments[0]), false)

    assert.equal(document.getText(), SOURCE.replace('md5(value)', 'md5(other)'))
    assert.equal(state.applied.length, 0)
    assert.match(state.warnings[0].message, /changed since this fix was checked/)
  })

  it('applies nothing when the file has unsaved edits by the time the user answers', async () => {
    const { controller, actions, state, document } = await scanned({ fixResults: [verified()] })
    state.infoChoices.push(BUTTONS.SHOW, BUTTONS.APPLY)
    const originalExecute = state.executed.push.bind(state.executed)
    state.executed.push = (call) => {
      // A different line is edited and not saved: the lines the fix replaces
      // still match, but saving would also save an edit nobody checked.
      if (call[0] === 'vscode.diff') {
        document.text = SOURCE.replace('import hashlib', 'import hashlib  # edited')
        document.isDirty = true
      }
      return originalExecute(call)
    }

    assert.equal(await controller.fix(actions[0].command.arguments[0]), false)

    assert.equal(state.applied.length, 0)
    assert.equal(document.saves, 0)
  })

  it('says so when the editor refuses the edit', async () => {
    const { controller, actions, state, document } = await scanned({ fixResults: [verified()] })
    state.infoChoices.push(BUTTONS.APPLY)
    state.applyResult = false

    assert.equal(await controller.fix(actions[0].command.arguments[0]), false)

    assert.equal(document.saves, 0)
    assert.match(state.errors[0].message, /did not accept the change/)
  })

  it('does not let its own save start a second scan', async () => {
    const { controller, actions, state, timers } = await scanned({
      fixResults: [verified()],
      configuration: { scanOnSave: true },
    })
    state.infoChoices.push(BUTTONS.APPLY)

    await controller.fix(actions[0].command.arguments[0])

    assert.equal(timers.length, 0)
  })

  it('works on one fix at a time', async () => {
    let release
    const pending = new Promise((resolve) => {
      release = resolve
    })
    const { controller, actions, state } = await scanned({ fixResults: [() => pending] })

    const first = controller.fix(actions[0].command.arguments[0])
    const second = await controller.fix(actions[0].command.arguments[0])
    release(verified({ status: 'no_fix', edits: [], reason: 'Nothing.' }))
    await first

    assert.equal(second, false)
    assert.ok(state.infos.includes('SentinelForge is already checking a fix. One at a time.'))
  })

  it('refuses a request that did not come from its own quick fix', async () => {
    const { controller, state, fixer } = await scanned()

    for (const request of [
      undefined,
      { folder: '/elsewhere', file: FILE, fingerprint: FIXABLE, mode: 'builtin' },
      { folder: '/work/project', file: FILE, fingerprint: 'x', mode: 'builtin' },
      { folder: '/work/project', file: FILE, fingerprint: FIXABLE, mode: 'shell' },
    ]) {
      assert.equal(await controller.fix(request), false)
    }

    assert.equal(fixer.calls.length, 0)
    assert.equal(state.errors.length, 4)
  })
})

describe('when there is no fix to apply', () => {
  it('explains a rejected change and can show it', async () => {
    const rejected = verified({ status: 'rejected', reason: 'The re-scan found a new problem.', diff: '-a\n+b\n' })
    const { controller, actions, state, document } = await scanned({ fixResults: [rejected] })
    state.warningChoices.push(BUTTONS.SHOW_REJECTED)

    assert.equal(await controller.fix(actions[0].command.arguments[0]), false)

    assert.match(state.warnings[0].message, /did not offer this change\. The re-scan found a new problem\./)
    assert.deepEqual(state.warnings[0].actions, [BUTTONS.SHOW_REJECTED])
    assert.equal(state.shown[0].document.getText(), '-a\n+b\n')
    assert.equal(document.getText(), SOURCE)
  })

  it('lets the user ask the model again after a rejected model fix', async () => {
    const rejected = verified({ status: 'rejected', source: 'model', reason: 'It deleted the function.' })
    const { controller, actions, state, fixer } = await scanned({ fixResults: [rejected, rejected] })
    state.warningChoices.push(BUTTONS.TRY_AGAIN, undefined)

    await controller.fix(actions[1].command.arguments[0])

    assert.equal(fixer.calls.length, 2)
    assert.equal(fixer.calls[0].model.retry, false)
    assert.equal(fixer.calls[1].model.retry, true)
  })

  it('offers the local model when there is no built-in fix', async () => {
    const none = verified({ status: 'no_fix', edits: [], reason: 'There is no built-in fix for PY010.' })
    const { controller, actions, state, fixer } = await scanned({ fixResults: [none, none] })
    state.infoChoices.push(BUTTONS.ASK_MODEL, undefined)

    await controller.fix(actions[0].command.arguments[0])

    assert.deepEqual(state.infoCalls[0].actions, [BUTTONS.ASK_MODEL])
    assert.equal(fixer.calls[1].mode, 'model')
  })

  it('sends the model settings from the user settings', async () => {
    const none = verified({ status: 'no_fix', edits: [], reason: 'Nothing.' })
    const { controller, actions, fixer } = await scanned({
      fixResults: [none],
      configuration: { ollamaUrl: 'http://localhost:11434', model: 'qwen2.5-coder:7b', modelTimeoutSeconds: 240 },
    })

    await controller.fix(actions[1].command.arguments[0])

    assert.deepEqual(fixer.calls[0].model, {
      url: 'http://localhost:11434',
      name: 'qwen2.5-coder:7b',
      timeoutSeconds: 240,
      allowRemote: false,
      retry: false,
    })
  })

  it('points at the settings when the fix cannot be run because of them', async () => {
    const { controller, actions, state } = await scanned({
      fixResults: [new FixError('Python was not found at "python".', '', { setup: true })],
    })
    state.errorChoice = BUTTONS.SETTINGS

    assert.equal(await controller.fix(actions[0].command.arguments[0]), false)

    assert.deepEqual(state.errors.at(-1), { message: 'Python was not found at "python".', actions: [BUTTONS.SETTINGS] })
    assert.deepEqual(state.executed.at(-1), ['workbench.action.openSettings', 'sentinelforge'])
  })

  it("passes the scanner's reason on when the model cannot be reached", async () => {
    const { controller, actions, state } = await scanned({
      fixResults: [new FixError('Could not reach Ollama at http://localhost:11434. Start it with: ollama serve')],
    })

    await controller.fix(actions[1].command.arguments[0])

    assert.match(state.errors.at(-1).message, /Could not reach Ollama/)
    assert.ok(state.output.some((line) => /Could not reach Ollama/.test(line)))
  })
})
