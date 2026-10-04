'use strict'

/**
 * The extension against the real scanner.
 *
 * Every other test replaces Python with a stand-in. These run the actual
 * command and read the actual report, so they are what shows the two halves
 * fit together. They need an interpreter with the backend's requirements
 * installed, named by SENTINELFORGE_PYTHON; without it they are skipped, and
 * say so.
 */

const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { describe, it } = require('node:test')

const { toDiagnostics, statusFor } = require('../src/diagnostics')
const { ScanError, scan } = require('../src/scanner')

const PYTHON = process.env.SENTINELFORGE_PYTHON
const BACKEND = path.resolve(__dirname, '..', '..', 'backend')
const skip = PYTHON ? false : 'set SENTINELFORGE_PYTHON to a Python with the backend requirements'

const VULNERABLE = [
  'import os',
  'import hashlib',
  '',
  '',
  'def handle(command, cursor, user_id):',
  '    os.system(command)',
  '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
  '    return hashlib.md5(command.encode()).hexdigest()',
  '',
].join('\n')

function workspace(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-workspace-'))
  for (const [name, content] of Object.entries(files)) {
    const target = path.join(root, ...name.split('/'))
    fs.mkdirSync(path.dirname(target), { recursive: true })
    fs.writeFileSync(target, content)
  }
  return root
}

function options(folder, extra = {}) {
  return { pythonPath: PYTHON, backendPath: BACKEND, folder, timeoutMs: 120_000, ...extra }
}

describe('with the real scanner', { skip }, () => {
  it('finds what is in the code and puts it on the right lines', async () => {
    const root = workspace({ 'app/main.py': VULNERABLE, 'app/clean.py': 'def add(a, b):\n    return a + b\n' })

    const { report, excluded } = await scan(options(root))
    const { files, skipped } = toDiagnostics(report)

    assert.equal(excluded, 0)
    assert.equal(skipped, 0)
    assert.deepEqual([...files.keys()], ['app/main.py'])
    const byLine = new Map(files.get('app/main.py').items.map((item) => [item.line, item]))
    assert.deepEqual([...byLine.keys()].sort(), [5, 6, 7]) // lines 6, 7 and 8, counted from zero
    assert.equal(byLine.get(6).level, 'error')
    assert.match(byLine.get(6).message, /^SQL query built by string formatting\n/)
    assert.match(byLine.get(6).message, /\nFix: /)
    assert.equal(byLine.get(6).codeUrl, 'https://cwe.mitre.org/data/definitions/89.html')
    assert.equal(byLine.get(7).level, 'warning')
    assert.match(statusFor(report).text, /^\$\(shield\) SentinelForge [A-F] · 3$/)
  })

  it('reports a clean folder as clean', async () => {
    const { report } = await scan(options(workspace({ 'a.py': 'def add(a, b):\n    return a + b\n' })))

    assert.equal(report.open_count, 0)
    assert.equal(toDiagnostics(report).files.size, 0)
    assert.equal(statusFor(report).text, '$(shield) SentinelForge A · 0')
  })

  it('leaves out what it is told to, and says how many', async () => {
    const root = workspace({ 'app/main.py': VULNERABLE, 'legacy/old.py': VULNERABLE })

    const { report, excluded } = await scan(options(root, { excludes: ['legacy'] }))

    assert.equal(report.open_count, 3)
    assert.equal(excluded, 3)
    assert.deepEqual([...toDiagnostics(report).files.keys()], ['app/main.py'])
  })

  it('does not run code from the workspace, even code shaped like the scanner', async () => {
    // `python -m app.cli` imports `app.cli` from its working directory first.
    // A repository can contain a package with that name. Because the working
    // directory is the scanner's own folder, this one is read, not run.
    const marker = path.join(os.tmpdir(), `sf-executed-${process.pid}-${Date.now()}`)
    const payload = `open(${JSON.stringify(marker)}, "w").write("ran")\n`
    const root = workspace({
      'app/__init__.py': payload,
      'app/cli/__init__.py': payload,
      'app/cli/__main__.py': payload,
      'sitecustomize.py': payload,
      'setup.py': payload,
      'conftest.py': payload,
    })

    const { report } = await scan(options(root))

    assert.equal(fs.existsSync(marker), false)
    assert.ok(Array.isArray(report.findings))
  })

  it('writes nothing into the folder it scans', async () => {
    const root = workspace({ 'app/main.py': VULNERABLE })
    const before = fs.readdirSync(root, { recursive: true }).sort()

    await scan(options(root))

    assert.deepEqual(fs.readdirSync(root, { recursive: true }).sort(), before)
  })

  it('writes the HTML report where it is asked to', async () => {
    const htmlPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sf-report-')), 'report.html')

    await scan(options(workspace({ 'app/main.py': VULNERABLE }), { htmlPath }))

    const html = fs.readFileSync(htmlPath, 'utf8')
    assert.match(html, /<title>Security report: /)
    assert.doesNotMatch(html, /<script/i)
  })

  it('explains a backend path with no scanner in it', async () => {
    const elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-not-backend-'))

    await assert.rejects(
      scan(options(workspace({ 'a.py': 'x = 1\n' }), { backendPath: elsewhere })),
      (error) => error instanceof ScanError && /scanner was not found/.test(error.message),
    )
  })

  it('explains a folder that is not there', async () => {
    await assert.rejects(
      scan(options(path.join(os.tmpdir(), 'sf-missing-folder-that-does-not-exist'))),
      (error) => error instanceof ScanError && /not a folder/.test(error.message),
    )
  })

  it('explains an interpreter that is not there', async () => {
    await assert.rejects(
      scan(options(workspace({ 'a.py': 'x = 1\n' }), { pythonPath: path.join(os.tmpdir(), 'no-such-python') })),
      (error) => error instanceof ScanError && /Python was not found/.test(error.message),
    )
  })
})
