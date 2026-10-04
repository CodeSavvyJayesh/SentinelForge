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
  constructor(scheme, value) {
    this.scheme = scheme
    this.value = value
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
    return new Uri('parsed', value)
  }
  static joinPath(base, ...segments) {
    return new Uri(base.scheme, path.join(base.value, ...segments))
  }
}

class Range {
  constructor(startLine, startCharacter, endLine, endCharacter) {
    Object.assign(this, { startLine, startCharacter, endLine, endCharacter })
  }
}

class Diagnostic {
  constructor(range, message, severity) {
    Object.assign(this, { range, message, severity })
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
    configuration: { pythonPath: 'python', backendPath: '/sf/backend', exclude: [], ...configuration },
    configurationScopes: [],
    status: { shown: false },
  }

  const vscode = {
    Uri,
    Range,
    Diagnostic,
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
      showInformationMessage: async (message) => {
        state.infos.push(message)
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
  return { vscode, context, state }
}

module.exports = { createFakeVscode }
