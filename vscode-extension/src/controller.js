'use strict'

/**
 * Everything the extension does, with the VS Code API handed in.
 *
 * `extension.js` is four lines that pass the real `vscode` module here. Taking
 * it as an argument is what lets the tests drive this file with a stand-in and
 * check what would have been shown, without an editor running.
 */

const { toDiagnostics, statusFor } = require('./diagnostics')
const scanner = require('./scanner')

const SAVE_DEBOUNCE_MS = 1000
const IDLE_TEXT = '$(shield) SentinelForge'

function createController(vscode, context, dependencies = {}) {
  const runScan = dependencies.scan ?? scanner.scan
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

  const levels = {
    error: vscode.DiagnosticSeverity.Error,
    warning: vscode.DiagnosticSeverity.Warning,
    information: vscode.DiagnosticSeverity.Information,
    hint: vscode.DiagnosticSeverity.Hint,
  }

  function settings(folder) {
    // Scoped to the folder, so a multi-root workspace can exclude per folder.
    const configuration = vscode.workspace.getConfiguration('sentinelforge', folder?.uri)
    const seconds = Number(configuration.get('timeoutSeconds'))
    return {
      pythonPath: String(configuration.get('pythonPath') || 'python'),
      backendPath: String(configuration.get('backendPath') || ''),
      excludes: configuration.get('exclude') ?? [],
      timeoutMs: (Number.isFinite(seconds) && seconds >= 5 ? seconds : 120) * 1000,
    }
  }

  function show(folder, report) {
    const { files, skipped } = toDiagnostics(report)
    const entries = []
    for (const { segments, items } of files.values()) {
      const uri = vscode.Uri.joinPath(folder.uri, ...segments)
      entries.push([
        uri,
        items.map((item) => {
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
    return { entries, skipped }
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

    running = true
    status.text = `${IDLE_TEXT} $(sync~spin)`
    status.tooltip = 'Scanning…'
    let ok = true
    try {
      const all = []
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

  function clear() {
    collection.clear()
    status.text = IDLE_TEXT
    status.tooltip = 'Click to scan this workspace'
  }

  function onSave() {
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
    vscode.workspace.onDidSaveTextDocument(() => onSave()),
    { dispose: () => saveTimer !== null && clearTimer(saveTimer) },
  )

  return { scanWorkspace, openReport, clear, onSave }
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

module.exports = { IDLE_TEXT, SAVE_DEBOUNCE_MS, createController, merge }
