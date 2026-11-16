'use strict'

/**
 * The manifest against the code: every setting the extension reads is
 * declared, and every setting that decides what runs, or where code is sent,
 * can only be set by the user — never by a workspace someone else wrote.
 */

const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const { describe, it } = require('node:test')

const ROOT = path.resolve(__dirname, '..')
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'))
const properties = manifest.contributes.configuration.properties
const source = fs
  .readdirSync(path.join(ROOT, 'src'))
  .map((name) => fs.readFileSync(path.join(ROOT, 'src', name), 'utf8'))
  .join('\n')

describe('the manifest', () => {
  it('declares every setting the extension reads', () => {
    const read = new Set([...source.matchAll(/\.get\('([A-Za-z]+)'\)/g)].map((match) => match[1]))

    assert.ok(read.size >= 8)
    for (const key of read) assert.ok(properties[`sentinelforge.${key}`], `sentinelforge.${key} is not declared`)
  })

  it('lets only the user decide what runs and where code is sent', () => {
    for (const key of ['backendPath', 'pythonPath', 'ollamaUrl', 'model', 'allowRemoteModel', 'modelTimeoutSeconds']) {
      assert.equal(properties[`sentinelforge.${key}`].scope, 'machine', key)
    }
    assert.equal(properties['sentinelforge.allowRemoteModel'].default, false)
  })

  it('declares every command it registers, and hides the one that needs a finding', () => {
    const registered = [...source.matchAll(/registerCommand\('([a-zA-Z.]+)'/g)].map((match) => match[1])
    const declared = manifest.contributes.commands.map((command) => command.command)

    for (const name of [...registered, 'sentinelforge.fix']) assert.ok(declared.includes(name), name)
    assert.deepEqual(manifest.contributes.menus.commandPalette, [{ command: 'sentinelforge.fix', when: 'false' }])
  })
})
