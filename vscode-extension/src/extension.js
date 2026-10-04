'use strict'

const vscode = require('vscode')

const { createController } = require('./controller')

function activate(context) {
  createController(vscode, context)
}

function deactivate() {}

module.exports = { activate, deactivate }
