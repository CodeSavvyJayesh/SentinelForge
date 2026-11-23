'use strict'

const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const zlib = require('node:zlib')
const { describe, it } = require('node:test')

const { build } = require('../scripts/package')

/** Read a zip back: every entry's name and inflated bytes, checking each CRC. */
function unzip(buffer) {
  const end = buffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]))
  const count = buffer.readUInt16LE(end + 10)
  let offset = buffer.readUInt32LE(end + 16)
  const entries = new Map()
  for (let index = 0; index < count; index += 1) {
    assert.equal(buffer.readUInt32LE(offset), 0x02014b50)
    const crc = buffer.readUInt32LE(offset + 16)
    const size = buffer.readUInt32LE(offset + 20)
    const nameLength = buffer.readUInt16LE(offset + 28)
    const local = buffer.readUInt32LE(offset + 42)
    const name = buffer.toString('utf8', offset + 46, offset + 46 + nameLength)
    const localName = buffer.readUInt16LE(local + 26)
    const start = local + 30 + localName
    const data = zlib.inflateRawSync(buffer.subarray(start, start + size))
    assert.equal(zlib.crc32(data), crc, name)
    entries.set(name, data)
    offset += 46 + nameLength
  }
  return entries
}

describe('the package', () => {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-vsix-'))
  const { target } = build(folder)
  const entries = unzip(fs.readFileSync(target))
  const names = [...entries.keys()]
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'))

  it('is named after the extension and its version', () => {
    assert.equal(path.basename(target), `sentinelforge-${manifest.version}.vsix`)
  })

  it('has the files VS Code reads to install it', () => {
    for (const name of ['[Content_Types].xml', 'extension.vsixmanifest', 'extension/package.json']) {
      assert.ok(names.includes(name), name)
    }
    const vsix = entries.get('extension.vsixmanifest').toString('utf8')
    assert.match(vsix, new RegExp(`Id="sentinelforge" Version="${manifest.version}" Publisher="${manifest.publisher}"`))
    assert.match(vsix, /Microsoft\.VisualStudio\.Code\.Engine" Value="\^1\.80\.0"/)
  })

  it('carries the extension, its icon and licence, and the scanner with its requirements', () => {
    for (const name of [
      'extension/src/extension.js',
      'extension/src/setup.js',
      'extension/images/icon.png',
      'extension/LICENSE',
      'extension/scanner/requirements-scanner.txt',
      'extension/scanner/app/cli/__main__.py',
      'extension/scanner/app/analysis/engine.py',
      'extension/scanner/app/fixing/builtin.py',
    ]) {
      assert.ok(names.includes(name), name)
    }
    assert.ok(fs.existsSync(path.join(__dirname, '..', manifest.icon)))
  })

  it('carries no tests, no editor stand-in, no caches and nothing secret', () => {
    for (const name of names) {
      assert.doesNotMatch(name, /^extension\/(test|support|scripts)\//, name)
      assert.doesNotMatch(name, /__pycache__|\.pyc$|(^|\/)\.env$/, name)
    }
  })

  it('is the same file every time it is built from the same sources', () => {
    const again = build(fs.mkdtempSync(path.join(os.tmpdir(), 'sf-vsix-')))
    assert.deepEqual(fs.readFileSync(again.target), fs.readFileSync(target))
  })
})
