'use strict'

/**
 * A stand-in for the `vscode` module: the handful of things the extension
 * uses, recording what it was asked to do.
 *
 * It is a model of the API, not the API. It checks that the extension asks for
 * the right things; only running in a real editor checks that the editor does
 * what this file assumes.
 */

const path = require('node:path')

class Uri {
  constructor(scheme, value, query = '') {
    this.scheme = scheme
    this.value = value
    this.query = query
  }
  get fsPath() {
    return this.value
  }
  toString() {
    return `${this.scheme}:${this.value}`
  }
  static file(value) {
    return new Uri('file', value)
  }
  static parse(value) {
    // Web addresses are kept whole: the tests read them back as they were given.
    if (/^https?:/.test(value)) return new Uri('parsed', value)
    const colon = value.indexOf(':')
    const rest = colon === -1 ? value : value.slice(colon + 1)
    const question = rest.indexOf('?')
    return new Uri(
      colon === -1 ? 'parsed' : value.slice(0, colon),
      question === -1 ? rest : rest.slice(0, question),
      question === -1 ? '' : rest.slice(question + 1),
    )
  }
  static joinPath(base, ...segments) {
    return new Uri(base.scheme, path.join(base.value, ...segments))
  }
}

class Range {
  constructor(startLine, startCharacter, endLine, endCharacter) {
    Object.assign(this, { startLine, startCharacter, endLine, endCharacter })
  }
  // As the real API names them.
  get start() {
    return { line: this.startLine, character: this.startCharacter }
  }
  get end() {
    return { line: this.endLine, character: this.endCharacter }
  }
}

class Diagnostic {
  constructor(range, message, severity) {
    Object.assign(this, { range, message, severity })
  }
}

class CodeAction {
  constructor(title, kind) {
    Object.assign(this, { title, kind })
  }
}

/** Records replacements; `workspace.applyEdit` makes them in the fake documents. */
class WorkspaceEdit {
  constructor() {
    this.replacements = []
  }
  replace(uri, range, text) {
    this.replacements.push({ uri, range, text })
  }
}

/**
 * A text document as an editor holds it: lines without their endings, plus the
 * text with its endings, which is what `save()` writes back.
 */
class FakeDocument {
  constructor(uri, text, { dirty = false, onSave = () => {} } = {}) {
    this.uri = uri
    this.text = text
    this.isDirty = dirty
    this.saves = 0
    this.onSave = onSave
  }
  get pieces() {
    return this.text.match(/[^\r\n]*(?:\r\n|\n|\r)|[^\r\n]+$/g) ?? []
  }
  get lines() {
    const pieces = this.pieces.map((piece) => piece.replace(/(?:\r\n|\n|\r)$/, ''))
    return this.text === '' || /(?:\r\n|\n|\r)$/.test(this.text) ? [...pieces, ''] : pieces
  }
  get lineCount() {
    return this.lines.length
  }
  lineAt(index) {
    return { text: this.lines[index] }
  }
  getText() {
    return this.text
  }
  offsetAt(line, character) {
    const pieces = this.pieces
    let offset = 0
    for (let index = 0; index < line && index < pieces.length; index += 1) offset += pieces[index].length
    return offset + character
  }
  async save() {
    this.saves += 1
    this.isDirty = false
    await this.onSave(this)
    return true
  }
}

function createFakeVscode({ folders = ['/work/project'], configuration = {} } = {}) {
  const state = {
    diagnostics: new Map(),
    clears: 0,
    sets: 0,
    commands: new Map(),
    executed: [],
    errors: [],
    infos: [],
    opened: [],
    createdDirectories: [],
    output: [],
    saveListeners: [],
    errorChoice: undefined,
    // Answers to information and warning messages, used in order.
    infoChoices: [],
    warningChoices: [],
    infoCalls: [],
    warnings: [],
    documents: new Map(),
    applied: [],
    applyResult: true,
    codeActionProviders: [],
    contentProviders: new Map(),
    progress: [],
    shown: [],
    configuration: { pythonPath: 'python', backendPath: '/sf/backend', exclude: [], ...configuration },
    configurationScopes: [],
    status: { shown: false },
  }

  const vscode = {
    Uri,
    Range,
    Diagnostic,
    CodeAction,
    WorkspaceEdit,
    CodeActionKind: { QuickFix: 'quickfix' },
    ProgressLocation: { Notification: 15 },
    DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
    StatusBarAlignment: { Left: 1, Right: 2 },
    languages: {
      createDiagnosticCollection: () => ({
        clear: () => {
          state.clears += 1
          state.diagnostics.clear()
        },
        set: (entries) => {
          state.sets += 1
          for (const [uri, items] of entries) state.diagnostics.set(uri.fsPath, items)
        },
        dispose: () => {},
      }),
      registerCodeActionsProvider: (selector, provider, metadata) => {
        state.codeActionProviders.push({ selector, provider, metadata })
        return { dispose: () => {} }
      },
    },
    window: {
      createOutputChannel: () => ({
        appendLine: (line) => state.output.push(line),
        dispose: () => {},
      }),
      createStatusBarItem: () => {
        state.status.show = () => {
          state.status.shown = true
        }
        state.status.dispose = () => {}
        return state.status
      },
      showErrorMessage: async (message, ...actions) => {
        state.errors.push({ message, actions })
        return state.errorChoice
      },
      showInformationMessage: async (message, ...rest) => {
        state.infos.push(message)
        const options = rest.length && typeof rest[0] === 'object' ? rest.shift() : undefined
        state.infoCalls.push({ message, options, actions: rest })
        return state.infoChoices.shift()
      },
      showWarningMessage: async (message, ...actions) => {
        state.warnings.push({ message, actions })
        return state.warningChoices.shift()
      },
      showTextDocument: async (document, options) => {
        state.shown.push({ document, options })
      },
      withProgress: async (options, task) => {
        state.progress.push(options)
        return task({ report: () => {} })
      },
    },
    workspace: {
      workspaceFolders: folders.map((folder) => ({
        uri: Uri.file(folder),
        name: path.basename(folder),
      })),
      getConfiguration: (section, scope) => {
        state.configurationScopes.push(scope?.fsPath ?? null)
        return {
          get: (key) => {
            const perFolder = state.configuration.perFolder?.[scope?.fsPath]
            return perFolder && key in perFolder ? perFolder[key] : state.configuration[key]
          },
        }
      },
      openTextDocument: async (target) => {
        if (target instanceof Uri) {
          const document = state.documents.get(target.fsPath)
          if (!document) throw new Error(`no such file: ${target.fsPath}`)
          return document
        }
        return new FakeDocument(Uri.parse('untitled:view'), target.content)
      },
      applyEdit: async (edit) => {
        state.applied.push(edit)
        if (state.applyResult !== true) return state.applyResult
        // Last first, so earlier offsets stay right.
        const ordered = [...edit.replacements].sort(
          (a, b) => b.range.startLine - a.range.startLine || b.range.startCharacter - a.range.startCharacter,
        )
        for (const { uri, range, text } of ordered) {
          const document = state.documents.get(uri.fsPath)
          const start = document.offsetAt(range.startLine, range.startCharacter)
          const end = document.offsetAt(range.endLine, range.endCharacter)
          document.text = document.text.slice(0, start) + text + document.text.slice(end)
          document.isDirty = true
        }
        return true
      },
      registerTextDocumentContentProvider: (scheme, provider) => {
        state.contentProviders.set(scheme, provider)
        return { dispose: () => {} }
      },
      onDidSaveTextDocument: (listener) => {
        state.saveListeners.push(listener)
        return { dispose: () => {} }
      },
      fs: {
        createDirectory: async (uri) => {
          state.createdDirectories.push(uri.fsPath)
        },
      },
    },
    commands: {
      registerCommand: (name, handler) => {
        state.commands.set(name, handler)
        return { dispose: () => {} }
      },
      executeCommand: async (...args) => {
        state.executed.push(args)
      },
    },
    env: {
      openExternal: async (uri) => {
        state.opened.push(uri.fsPath)
      },
    },
  }

  const context = { subscriptions: [], globalStorageUri: Uri.file('/storage/sentinelforge') }

  /** Put a file "on disk and open in the editor". Saving it fires the save listeners. */
  function addDocument(fsPath, text, options = {}) {
    const document = new FakeDocument(Uri.file(fsPath), text, {
      ...options,
      onSave: async (saved) => {
        for (const listener of state.saveListeners) await listener(saved)
      },
    })
    state.documents.set(fsPath, document)
    return document
  }

  return { vscode, context, state, addDocument }
}

module.exports = { createFakeVscode, FakeDocument }
