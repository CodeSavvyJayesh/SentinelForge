'use strict'

/**
 * Everything the extension does, with the VS Code API handed in.
 *
 * `extension.js` is four lines that pass the real `vscode` module here. Taking
 * it as an argument is what lets the tests drive this file with a stand-in and
 * check what would have been shown, without an editor running.
 */

const { SOURCE, toDiagnostics, statusFor } = require('./diagnostics')
const { MODES, STATUSES, isFingerprint, isMode, planEdits, proposedText, verifiedDetail } = require('./fixes')
const scanner = require('./scanner')
const setup = require('./setup')

const SAVE_DEBOUNCE_MS = 1000
const IDLE_TEXT = '$(shield) SentinelForge'
const FIX_COMMAND = 'sentinelforge.fix'
const SETUP_COMMAND = 'sentinelforge.setup'
const PROPOSAL_SCHEME = 'sentinelforge-fix'
// How many proposed versions of a file are kept for the side-by-side view.
const MAX_PROPOSALS = 8
const ASK_MODEL_TITLE = 'SentinelForge: Ask the local model for a fix'
const BUTTONS = Object.freeze({
  APPLY: 'Apply',
  SHOW: 'Show changes',
  DISCARD: 'Discard',
  SHOW_REJECTED: 'Show what was rejected',
  TRY_AGAIN: 'Try again',
  ASK_MODEL: 'Ask the local model',
  SCAN: 'Scan again',
  SETTINGS: 'Open settings',
  SET_UP: 'Set up the scanner',
  INSTALL: 'Install',
})

function createController(vscode, context, dependencies = {}) {
  const runScan = dependencies.scan ?? scanner.scan
  const runFix = dependencies.fix ?? scanner.fix
  const createEnvironment = dependencies.createEnvironment ?? setup.createEnvironment
  const runProcess = dependencies.execFile ?? scanner.execFile
  const setTimer = dependencies.setTimeout ?? setTimeout
  const clearTimer = dependencies.clearTimeout ?? clearTimeout

  const collection = vscode.languages.createDiagnosticCollection('sentinelforge')
  const output = vscode.window.createOutputChannel('SentinelForge')
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50)
  status.command = 'sentinelforge.scanWorkspace'
  status.text = IDLE_TEXT
  status.tooltip = 'Click to scan this workspace'
  status.show()

  let running = false
  let again = false
  let saveTimer = null
  let fixing = false
  let settingUp = false
  // Set while this extension saves a file it has just fixed: that save is
  // followed by a scan of its own, so scan-on-save must not start a second.
  let savingAFix = false
  // What each diagnostic can be offered, by where it is. An editor hands a
  // code action provider its own copies of the diagnostics, so nothing stored
  // on the objects themselves can be relied on to come back.
  let fixable = new Map()
  const proposals = new Map()
  let proposalCount = 0

  const levels = {
    error: vscode.DiagnosticSeverity.Error,
    warning: vscode.DiagnosticSeverity.Warning,
    information: vscode.DiagnosticSeverity.Information,
    hint: vscode.DiagnosticSeverity.Hint,
  }

  function located() {
    // Where the scanner is is a user-level question, never a folder's.
    return setup.locate(vscode.workspace.getConfiguration('sentinelforge'), {
      extensionPath: context.extensionPath,
      storagePath: context.globalStorageUri?.fsPath,
    })
  }

  function settings(folder) {
    // Scoped to the folder, so a multi-root workspace can exclude per folder.
    const configuration = vscode.workspace.getConfiguration('sentinelforge', folder?.uri)
    const seconds = Number(configuration.get('timeoutSeconds'))
    const { pythonPath, backendPath } = located()
    return {
      pythonPath: pythonPath || 'python',
      backendPath,
      excludes: configuration.get('exclude') ?? [],
      timeoutMs: (Number.isFinite(seconds) && seconds >= 5 ? seconds : 120) * 1000,
    }
  }

  /** True when the scanner can be run; otherwise offers its one-time setup. */
  async function ready() {
    if (!located().needsSetup) return true
    const message =
      'SentinelForge needs a one-time setup: its scanner runs on your Python, with a few packages installed ' +
      "into the extension's own folder."
    status.text = `${IDLE_TEXT} $(warning)`
    status.tooltip = message
    const choice = await vscode.window.showWarningMessage(message, BUTTONS.SET_UP)
    if (choice === BUTTONS.SET_UP) return setUp()
    return false
  }

  /**
   * Install the scanner's packages into a virtual environment of its own.
   * Returns true when the scanner is ready to run.
   */
  async function setUp() {
    const { backendPath } = located()
    if (!backendPath) {
      await vscode.window.showErrorMessage(
        'SentinelForge: this copy of the extension has no scanner in it. Set sentinelforge.backendPath.',
        BUTTONS.SETTINGS,
      )
      return false
    }
    if (settingUp) return false
    const choice = await vscode.window.showInformationMessage(
      'Set up the SentinelForge scanner?',
      {
        modal: true,
        detail:
          "This creates a Python environment in the extension's own storage folder and installs the scanner's " +
          'packages into it from the Python Package Index (about 50 MB, a minute or two). Nothing is installed ' +
          'into your own Python, and nothing in your workspace is run.',
      },
      BUTTONS.INSTALL,
    )
    if (choice !== BUTTONS.INSTALL) return false
    settingUp = true
    try {
      await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'SentinelForge: setting up the scanner…' },
        () =>
          createEnvironment({
            run: runProcess,
            configuration: vscode.workspace.getConfiguration('sentinelforge'),
            backendPath,
            storagePath: context.globalStorageUri.fsPath,
            log: (line) => line && output.appendLine(line),
          }),
      )
    } catch (error) {
      const message = error instanceof setup.SetupError ? error.message : `SentinelForge: ${error}`
      output.appendLine(message)
      if (error?.detail) output.appendLine(error.detail)
      status.text = `${IDLE_TEXT} $(warning)`
      status.tooltip = message
      await vscode.window.showErrorMessage(message)
      return false
    } finally {
      settingUp = false
    }
    output.appendLine('The scanner is set up.')
    await vscode.window.showInformationMessage('SentinelForge: the scanner is set up. Scanning now.')
    await scanWorkspace()
    return true
  }

  function modelSettings(folder) {
    const configuration = vscode.workspace.getConfiguration('sentinelforge', folder?.uri)
    const seconds = Number(configuration.get('modelTimeoutSeconds'))
    return {
      url: String(configuration.get('ollamaUrl') || ''),
      name: String(configuration.get('model') || ''),
      timeoutSeconds:
        Number.isFinite(seconds) && seconds >= 10 ? Math.round(seconds) : scanner.DEFAULT_MODEL_TIMEOUT_SECONDS,
      allowRemote: configuration.get('allowRemoteModel') === true,
    }
  }

  function fixKey(uri, line, code) {
    return `${uri.toString()}\n${line}\n${code}`
  }

  function codeOf(diagnostic) {
    const code = diagnostic.code
    return code !== null && typeof code === 'object' ? code.value : code
  }

  function show(folder, report) {
    const { files, skipped } = toDiagnostics(report)
    const entries = []
    const fixes = []
    for (const { segments, items } of files.values()) {
      const uri = vscode.Uri.joinPath(folder.uri, ...segments)
      entries.push([
        uri,
        items.map((item) => {
          if (item.fix) {
            fixes.push([fixKey(uri, item.line, item.code), { ...item.fix, folder: folder.uri.fsPath }])
          }
          // To the end of the line, whatever its length: the editor clips the
          // range to the text that is actually there.
          const range = new vscode.Range(item.line, 0, item.lastLine, Number.MAX_SAFE_INTEGER)
          const diagnostic = new vscode.Diagnostic(range, item.message, levels[item.level])
          diagnostic.source = item.source
          diagnostic.code = item.codeUrl
            ? { value: item.code, target: vscode.Uri.parse(item.codeUrl) }
            : item.code
          return diagnostic
        }),
      ])
    }
    return { entries, skipped, fixes }
  }

  async function explainFailure(error) {
    const message = error instanceof scanner.ScanError ? error.message : `SentinelForge: ${error}`
    output.appendLine(message)
    if (error instanceof scanner.ScanError && error.detail) output.appendLine(error.detail)
    status.text = `${IDLE_TEXT} $(warning)`
    status.tooltip = `${message}\nClick to try again`
    const choice = await vscode.window.showErrorMessage(message, 'Open settings')
    if (choice === 'Open settings') {
      await vscode.commands.executeCommand('workbench.action.openSettings', 'sentinelforge')
    }
  }

  /** Scan every workspace folder. Returns true if every scan completed. */
  async function scanWorkspace({ htmlPath } = {}) {
    const folders = vscode.workspace.workspaceFolders ?? []
    if (folders.length === 0) {
      vscode.window.showInformationMessage('SentinelForge: open a folder to scan it.')
      return false
    }
    if (running) {
      // One scan at a time. A request made while one is running is not lost:
      // the workspace is scanned once more when the current scan ends.
      again = true
      return false
    }

    if (!(await ready())) return false

    running = true
    status.text = `${IDLE_TEXT} $(sync~spin)`
    status.tooltip = 'Scanning…'
    let ok = true
    try {
      const all = []
      const offers = new Map()
      const totals = { open_count: 0, score: 0, grade: 'A', counts_by_severity: {}, scan: {} }
      let excluded = 0
      let skipped = 0
      for (const folder of folders) {
        const options = settings(folder)
        const result = await runScan({
          ...options,
          folder: folder.uri.fsPath,
          // One report file, so only the first folder's report is opened.
          htmlPath: folder === folders[0] ? htmlPath : undefined,
        })
        const shown = show(folder, result.report)
        all.push(...shown.entries)
        // Two findings of one rule on one line share a key. The first is kept:
        // either fingerprint names that line, and a fix rewrites the line.
        for (const [key, info] of shown.fixes) if (!offers.has(key)) offers.set(key, info)
        skipped += shown.skipped
        excluded += result.excluded
        merge(totals, result.report)
        output.appendLine(
          `${folder.name}: ${result.report.open_count} findings, risk ${result.report.score} ` +
            `(grade ${result.report.grade})`,
        )
      }
      // Replaced in one step, after every folder has been scanned, so the
      // Problems panel never shows half of an old result and half of a new one.
      collection.clear()
      collection.set(all)
      fixable = offers
      const summary = statusFor(totals, { excluded, skipped })
      status.text = summary.text
      status.tooltip = summary.tooltip
    } catch (error) {
      ok = false
      await explainFailure(error)
    } finally {
      running = false
    }
    if (again) {
      again = false
      return scanWorkspace()
    }
    return ok
  }

  async function openReport() {
    const directory = context.globalStorageUri
    await vscode.workspace.fs.createDirectory(directory)
    const file = vscode.Uri.joinPath(directory, 'report.html')
    if (await scanWorkspace({ htmlPath: file.fsPath })) {
      // Opened by the system's browser, not inside the editor: the report is a
      // self-contained page with no scripts, and a browser is where it prints.
      await vscode.env.openExternal(file)
    }
  }

  // --- fixes -----------------------------------------------------------------

  /** The quick fixes for the SentinelForge findings under the cursor. */
  function provideCodeActions(document, _range, actionContext) {
    const actions = []
    const offered = new Set()
    for (const diagnostic of actionContext?.diagnostics ?? []) {
      if (diagnostic.source !== SOURCE) continue
      const key = fixKey(document.uri, diagnostic.range.start.line, codeOf(diagnostic))
      const info = fixable.get(key)
      // Nothing for a credential: it is rotated, not edited.
      if (!info || info.credential || offered.has(key)) continue
      offered.add(key)
      const request = { folder: info.folder, file: document.uri.fsPath, fingerprint: info.fingerprint }
      const add = (title, mode, preferred) => {
        const action = new vscode.CodeAction(title, vscode.CodeActionKind.QuickFix)
        action.diagnostics = [diagnostic]
        action.isPreferred = preferred
        action.command = { command: FIX_COMMAND, title, arguments: [{ ...request, mode }] }
        actions.push(action)
      }
      if (info.builtinTitle) add(`SentinelForge: ${info.builtinTitle}`, MODES.BUILTIN, true)
      add(ASK_MODEL_TITLE, MODES.MODEL, false)
    }
    return actions
  }

  function folderFor(fsPath) {
    return (vscode.workspace.workspaceFolders ?? []).find((folder) => folder.uri.fsPath === fsPath)
  }

  function linesOf(document) {
    const lines = []
    for (let index = 0; index < document.lineCount; index += 1) lines.push(document.lineAt(index).text)
    return lines
  }

  async function explainFixFailure(error, request) {
    const known = error instanceof scanner.ScanError
    const message = known ? error.message : `SentinelForge: ${error}`
    output.appendLine(message)
    if (known && error.detail) output.appendLine(error.detail)
    const setup = error instanceof scanner.FixError && error.setup
    const choice = await vscode.window.showErrorMessage(message, setup ? BUTTONS.SETTINGS : BUTTONS.SCAN)
    if (choice === BUTTONS.SETTINGS) {
      await vscode.commands.executeCommand('workbench.action.openSettings', 'sentinelforge')
    } else if (choice === BUTTONS.SCAN) {
      await scanWorkspace()
    }
    return request
  }

  async function showProposal(document, text, title) {
    proposalCount += 1
    const id = String(proposalCount)
    proposals.set(id, text)
    while (proposals.size > MAX_PROPOSALS) proposals.delete(proposals.keys().next().value)
    const name = document.uri.fsPath.split(/[\\/]/).pop() || 'file'
    const proposed = vscode.Uri.parse(`${PROPOSAL_SCHEME}:${encodeURIComponent(name)}?${id}`)
    await vscode.commands.executeCommand('vscode.diff', document.uri, proposed, `${name}: ${title} (proposed)`)
  }

  async function showRejected(result) {
    const view = await vscode.workspace.openTextDocument({ content: result.diff, language: 'diff' })
    await vscode.window.showTextDocument(view, { preview: true })
  }

  /** Make the checked edits in the document, or say why they were not made. */
  async function apply(document, result) {
    // Asked again, at the last moment: the question was open for as long as
    // the user took to answer it, and the file may have been edited since.
    const plan = document.isDirty ? { ok: false } : planEdits(linesOf(document), result.edits)
    if (!plan.ok) {
      const choice = await vscode.window.showWarningMessage(
        'The file has changed since this fix was checked, so nothing was applied. Scan again, then ask for the fix.',
        BUTTONS.SCAN,
      )
      if (choice === BUTTONS.SCAN) await scanWorkspace()
      return false
    }
    const edit = new vscode.WorkspaceEdit()
    for (const { start, end, text } of plan.replacements) {
      edit.replace(document.uri, new vscode.Range(start.line, start.character, end.line, end.character), text)
    }
    if ((await vscode.workspace.applyEdit(edit)) !== true) {
      await vscode.window.showErrorMessage('SentinelForge: the editor did not accept the change. Nothing was applied.')
      return false
    }
    savingAFix = true
    try {
      await document.save()
    } finally {
      savingAFix = false
    }
    output.appendLine(`Applied: ${result.title} (${document.uri.fsPath})`)
    // The scanner reads files, so the findings are refreshed from what was
    // saved. This is also the user's own confirmation that the finding is gone.
    await scanWorkspace()
    return true
  }

  async function present(result, request, document) {
    if (result.status === STATUSES.VERIFIED) {
      // Checked now so that "Show changes" never opens on a file that is not
      // the one the change was worked out from.
      const text = proposedText(document.getText(), result.edits)
      if (text === null) return apply(document, result)
      let choice = await vscode.window.showInformationMessage(
        result.title,
        { modal: true, detail: verifiedDetail(result) },
        BUTTONS.APPLY,
        BUTTONS.SHOW,
      )
      if (choice === BUTTONS.SHOW) {
        await showProposal(document, text, result.title)
        choice = await vscode.window.showInformationMessage(
          `Apply "${result.title}" to this file?`,
          BUTTONS.APPLY,
          BUTTONS.DISCARD,
        )
      }
      return choice === BUTTONS.APPLY ? apply(document, result) : false
    }

    const model = request.mode === MODES.MODEL
    if (result.status === STATUSES.REJECTED) {
      const buttons = []
      if (result.diff) buttons.push(BUTTONS.SHOW_REJECTED)
      if (model) buttons.push(BUTTONS.TRY_AGAIN)
      const choice = await vscode.window.showWarningMessage(
        `SentinelForge did not offer this change. ${result.reason || 'It did not pass the checks.'}`,
        ...buttons,
      )
      if (choice === BUTTONS.SHOW_REJECTED) await showRejected(result)
      if (choice === BUTTONS.TRY_AGAIN) return fix({ ...request, retry: true })
      return false
    }

    const choice = await vscode.window.showInformationMessage(
      result.reason || 'SentinelForge has no change to offer for this finding.',
      ...(model ? [] : [BUTTONS.ASK_MODEL]),
    )
    if (choice === BUTTONS.ASK_MODEL) return fix({ ...request, mode: MODES.MODEL })
    return false
  }

  /**
   * Work out a fix for one finding, show it, and apply it if the user says so.
   * Returns true only when a change was applied.
   */
  async function fix(request) {
    const folder = folderFor(request?.folder)
    if (
      !folder ||
      typeof request.file !== 'string' ||
      !isFingerprint(request.fingerprint) ||
      !isMode(request.mode)
    ) {
      await vscode.window.showErrorMessage('SentinelForge: that finding cannot be fixed from here. Scan again first.')
      return false
    }
    if (fixing) {
      await vscode.window.showInformationMessage('SentinelForge is already checking a fix. One at a time.')
      return false
    }

    fixing = true
    let result
    let document
    try {
      if (!(await ready())) return false
      document = await vscode.workspace.openTextDocument(vscode.Uri.file(request.file))
      if (document.isDirty) {
        // The scanner reads the file on disk. A fix worked out from that would
        // be checked against one text and applied to another.
        await vscode.window.showWarningMessage('Save the file first: a fix is worked out from the file as it is saved.')
        return false
      }
      const model = request.mode === MODES.MODEL
      result = await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: model
            ? 'SentinelForge: asking the local model for a fix, then scanning it. This can take a minute…'
            : 'SentinelForge: working out the fix and scanning it…',
        },
        () =>
          runFix({
            ...settings(folder),
            folder: folder.uri.fsPath,
            fingerprint: request.fingerprint,
            mode: request.mode,
            model: model ? { ...modelSettings(folder), retry: request.retry === true } : undefined,
          }),
      )
    } catch (error) {
      await explainFixFailure(error, request)
      return false
    } finally {
      fixing = false
    }
    return present(result, request, document)
  }

  function clear() {
    collection.clear()
    fixable = new Map()
    status.text = IDLE_TEXT
    status.tooltip = 'Click to scan this workspace'
  }

  function onSave() {
    if (savingAFix) return
    if (vscode.workspace.getConfiguration('sentinelforge').get('scanOnSave') !== true) return
    // "Save all" saves many files at once; that is one scan, not many.
    if (saveTimer !== null) clearTimer(saveTimer)
    saveTimer = setTimer(() => {
      saveTimer = null
      void scanWorkspace()
    }, SAVE_DEBOUNCE_MS)
  }

  context.subscriptions.push(
    collection,
    output,
    status,
    vscode.commands.registerCommand('sentinelforge.scanWorkspace', () => scanWorkspace()),
    vscode.commands.registerCommand('sentinelforge.openReport', () => openReport()),
    vscode.commands.registerCommand('sentinelforge.clear', () => clear()),
    vscode.commands.registerCommand(FIX_COMMAND, (request) => fix(request)),
    vscode.commands.registerCommand(SETUP_COMMAND, () => setUp()),
    vscode.languages.registerCodeActionsProvider(
      { scheme: 'file' },
      { provideCodeActions },
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
    ),
    // The proposed version of a file, for the side-by-side view. Read-only,
    // held in memory, and never written anywhere.
    vscode.workspace.registerTextDocumentContentProvider(PROPOSAL_SCHEME, {
      provideTextDocumentContent: (uri) => proposals.get(uri.query) ?? '',
    }),
    vscode.workspace.onDidSaveTextDocument(() => onSave()),
    { dispose: () => saveTimer !== null && clearTimer(saveTimer) },
  )

  return { scanWorkspace, openReport, clear, onSave, fix, provideCodeActions, setUp }
}

const GRADES = ['A', 'B', 'C', 'D', 'F']

/** Combine folder reports for the status bar: counts add up, the worst grade wins. */
function merge(totals, report) {
  totals.open_count += Number.isInteger(report.open_count) ? report.open_count : 0
  if (typeof report.score === 'number' && report.score >= totals.score) {
    totals.score = report.score
  }
  if (GRADES.indexOf(report.grade) > GRADES.indexOf(totals.grade)) totals.grade = report.grade
  for (const [severity, count] of Object.entries(report.counts_by_severity ?? {})) {
    if (Number.isInteger(count)) {
      totals.counts_by_severity[severity] = (totals.counts_by_severity[severity] ?? 0) + count
    }
  }
  if (report.scan?.truncated === true) totals.scan.truncated = true
}

module.exports = {
  ASK_MODEL_TITLE,
  BUTTONS,
  FIX_COMMAND,
  IDLE_TEXT,
  PROPOSAL_SCHEME,
  SAVE_DEBOUNCE_MS,
  SETUP_COMMAND,
  createController,
  merge,
}
