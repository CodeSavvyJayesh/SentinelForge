#!/usr/bin/env node
'use strict'

/**
 * Build the installable package: sentinelforge-<version>.vsix
 *
 *     node scripts/package.js            (from vscode-extension/)
 *     code --install-extension sentinelforge-0.2.0.vsix
 *
 * A .vsix is a zip file: the extension's own files under `extension/`, a
 * manifest describing them, and a list of content types. This writes one with
 * Node alone, so packaging needs nothing installed — no `vsce`, no npm.
 *
 * Unlike a development checkout, the package carries the scanner's source in
 * `extension/scanner/` (copied from ../backend), so it works on a machine that
 * has never seen this repository. The scanner's Python packages are not carried:
 * some are compiled for one platform. The extension installs them once, when
 * the user agrees, into its own storage folder (see src/setup.js).
 */

const fs = require('node:fs')
const path = require('node:path')
const zlib = require('node:zlib')

const ROOT = path.resolve(__dirname, '..')
const BACKEND = path.resolve(ROOT, '..', 'backend')

// The extension's own files. Tests, the editor stand-in and this script are not
// shipped.
const EXTENSION_FILES = ['package.json', 'README.md', 'LICENSE', 'images/icon.png']
const EXTENSION_FOLDERS = ['src']
// The scanner: the application package and the list of what it needs.
const SCANNER_FILES = ['requirements-scanner.txt']
const SCANNER_FOLDERS = ['app']
const SKIPPED = new Set(['__pycache__', '.pytest_cache', '.ruff_cache'])

function filesUnder(base, folder) {
  const found = []
  const walk = (relative) => {
    for (const entry of fs.readdirSync(path.join(base, relative), { withFileTypes: true })) {
      if (SKIPPED.has(entry.name) || entry.name.endsWith('.pyc')) continue
      const child = path.join(relative, entry.name)
      if (entry.isSymbolicLink()) continue
      if (entry.isDirectory()) walk(child)
      else if (entry.isFile()) found.push(child)
    }
  }
  walk(folder)
  return found.sort()
}

/** Every file in the package, as [path in the zip, path on disk]. */
function contents() {
  const entries = []
  for (const name of EXTENSION_FILES) entries.push([`extension/${name}`, path.join(ROOT, name)])
  for (const folder of EXTENSION_FOLDERS) {
    for (const file of filesUnder(ROOT, folder)) entries.push([`extension/${toZip(file)}`, path.join(ROOT, file)])
  }
  for (const name of SCANNER_FILES) entries.push([`extension/scanner/${name}`, path.join(BACKEND, name)])
  for (const folder of SCANNER_FOLDERS) {
    for (const file of filesUnder(BACKEND, folder)) {
      entries.push([`extension/scanner/${toZip(file)}`, path.join(BACKEND, file)])
    }
  }
  for (const [, source] of entries) {
    if (!fs.existsSync(source)) throw new Error(`missing: ${path.relative(ROOT, source)}`)
  }
  return entries
}

function toZip(relative) {
  return relative.split(path.sep).join('/')
}

function escapeXml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function vsixManifest(manifest) {
  const tags = [...(manifest.keywords ?? []), 'vscode'].join(',')
  return `<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Language="en-US" Id="${escapeXml(manifest.name)}" Version="${escapeXml(manifest.version)}" Publisher="${escapeXml(manifest.publisher)}" />
    <DisplayName>${escapeXml(manifest.displayName)}</DisplayName>
    <Description xml:space="preserve">${escapeXml(manifest.description)}</Description>
    <Tags>${escapeXml(tags)}</Tags>
    <Categories>${escapeXml((manifest.categories ?? []).join(','))}</Categories>
    <GalleryFlags>Public</GalleryFlags>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="${escapeXml(manifest.engines.vscode)}" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionPack" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="workspace" />
      <Property Id="Microsoft.VisualStudio.Services.Links.Source" Value="${escapeXml(manifest.repository.url)}" />
      <Property Id="Microsoft.VisualStudio.Services.GitHubFlavoredMarkdown" Value="true" />
      <Property Id="Microsoft.VisualStudio.Services.Content.Pricing" Value="Free" />
    </Properties>
    <License>extension/LICENSE</License>
    <Icon>extension/images/icon.png</Icon>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code" />
  </Installation>
  <Dependencies />
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true" />
    <Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/README.md" Addressable="true" />
    <Asset Type="Microsoft.VisualStudio.Services.Content.License" Path="extension/LICENSE" Addressable="true" />
    <Asset Type="Microsoft.VisualStudio.Services.Icons.Default" Path="extension/images/icon.png" Addressable="true" />
  </Assets>
</PackageManifest>
`
}

function contentTypes(names) {
  const known = {
    '.json': 'application/json',
    '.js': 'application/javascript',
    '.md': 'text/markdown',
    '.png': 'image/png',
    '.py': 'text/x-python',
    '.txt': 'text/plain',
    '.vsixmanifest': 'text/xml',
    '.xml': 'text/xml',
  }
  const extensions = new Set(names.map((name) => path.posix.extname(name)).filter(Boolean))
  const lines = [...extensions]
    .sort()
    .map((extension) => `  <Default Extension="${extension}" ContentType="${known[extension] ?? 'application/octet-stream'}" />`)
  // Files with no extension at all (LICENSE) need an override each.
  const overrides = names
    .filter((name) => !path.posix.extname(name))
    .map((name) => `  <Override PartName="/${escapeXml(name)}" ContentType="text/plain" />`)
  return `<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
${[...lines, ...overrides].join('\n')}
</Types>
`
}

/** A minimal zip writer: deflated entries, a central directory, no extras. */
function zip(entries) {
  const locals = []
  const centrals = []
  let offset = 0
  // A fixed timestamp, so the same sources always make the same package.
  const time = (12 << 11) | (0 << 5)
  const date = ((2026 - 1980) << 9) | (1 << 5) | 1
  for (const { name, data } of entries) {
    const nameBytes = Buffer.from(name, 'utf8')
    const compressed = zlib.deflateRawSync(data, { level: 9 })
    const crc = zlib.crc32(data)
    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt16LE(0x0800, 6) // names are UTF-8
    local.writeUInt16LE(8, 8) // deflate
    local.writeUInt16LE(time, 10)
    local.writeUInt16LE(date, 12)
    local.writeUInt32LE(crc, 14)
    local.writeUInt32LE(compressed.length, 18)
    local.writeUInt32LE(data.length, 22)
    local.writeUInt16LE(nameBytes.length, 26)
    local.writeUInt16LE(0, 28)
    locals.push(local, nameBytes, compressed)

    const central = Buffer.alloc(46)
    central.writeUInt32LE(0x02014b50, 0)
    central.writeUInt16LE(20, 4)
    central.writeUInt16LE(20, 6)
    central.writeUInt16LE(0x0800, 8)
    central.writeUInt16LE(8, 10)
    central.writeUInt16LE(time, 12)
    central.writeUInt16LE(date, 14)
    central.writeUInt32LE(crc, 16)
    central.writeUInt32LE(compressed.length, 20)
    central.writeUInt32LE(data.length, 24)
    central.writeUInt16LE(nameBytes.length, 28)
    central.writeUInt32LE(offset, 42)
    centrals.push(central, nameBytes)
    offset += local.length + nameBytes.length + compressed.length
  }
  const directory = Buffer.concat(centrals)
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0)
  end.writeUInt16LE(entries.length, 8)
  end.writeUInt16LE(entries.length, 10)
  end.writeUInt32LE(directory.length, 12)
  end.writeUInt32LE(offset, 16)
  return Buffer.concat([...locals, directory, end])
}

function build(outputFolder = ROOT) {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'))
  const files = contents().map(([name, source]) => ({ name, data: fs.readFileSync(source) }))
  const names = ['extension.vsixmanifest', ...files.map((file) => file.name)]
  const entries = [
    { name: '[Content_Types].xml', data: Buffer.from(contentTypes(names), 'utf8') },
    { name: 'extension.vsixmanifest', data: Buffer.from(vsixManifest(manifest), 'utf8') },
    ...files,
  ]
  const target = path.join(outputFolder, `${manifest.name}-${manifest.version}.vsix`)
  fs.writeFileSync(target, zip(entries))
  return { target, files: entries.length }
}

if (require.main === module) {
  const { target, files } = build(process.argv[2] ? path.resolve(process.argv[2]) : ROOT)
  const size = (fs.statSync(target).size / 1024).toFixed(0)
  console.log(`${path.basename(target)}: ${files} files, ${size} KB`)
  console.log(`Install it with:  code --install-extension ${path.basename(target)}`)
}

module.exports = { build, contents, contentTypes, vsixManifest, zip }
