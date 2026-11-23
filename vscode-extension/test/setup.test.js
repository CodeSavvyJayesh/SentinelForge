'use strict'

const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { describe, it } = require('node:test')

const {
  ENVIRONMENT_FOLDER,
  SetupError,
  bundledScanner,
  candidates,
  createEnvironment,
  findPython,
  isRecentEnough,
  locate,
  parseVersion,
  pythonIn,
} = require('../src/setup')

function temporary() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sf-setup-'))
}

/** A folder that looks like the scanner: app/cli/__main__.py, and optionally a venv. */
function scannerAt(folder, { venv = false, requirements = true } = {}) {
  fs.mkdirSync(path.join(folder, 'app', 'cli'), { recursive: true })
  fs.writeFileSync(path.join(folder, 'app', 'cli', '__main__.py'), '')
  if (requirements) fs.writeFileSync(path.join(folder, 'requirements-scanner.txt'), 'pydantic==2.13.4\n')
  if (venv) {
    const python = pythonIn(path.join(folder, 'venv'))
    fs.mkdirSync(path.dirname(python), { recursive: true })
    fs.writeFileSync(python, '')
  }
  return folder
}

/** User settings, as `getConfiguration` returns them. */
function configuration(values = {}) {
  return { get: (key) => values[key], inspect: (key) => ({ globalValue: values[key] }) }
}

describe('locate', () => {
  it('uses what the user set, always', () => {
    const extension = temporary()
    scannerAt(path.join(extension, 'scanner'))

    const found = locate(configuration({ backendPath: '/mine/backend', pythonPath: '/mine/python' }), {
      extensionPath: extension,
      storagePath: temporary(),
    })

    assert.deepEqual([found.backendPath, found.pythonPath, found.needsSetup], ['/mine/backend', '/mine/python', false])
  })

  it('finds the scanner inside an installed package, and asks for setup until its Python exists', () => {
    const extension = temporary()
    const storage = temporary()
    scannerAt(path.join(extension, 'scanner'))

    const before = locate(configuration(), { extensionPath: extension, storagePath: storage })
    assert.equal(before.backendPath, path.join(extension, 'scanner'))
    assert.equal(before.needsSetup, true)

    const managed = pythonIn(path.join(storage, ENVIRONMENT_FOLDER))
    fs.mkdirSync(path.dirname(managed), { recursive: true })
    fs.writeFileSync(managed, '')
    const after = locate(configuration(), { extensionPath: extension, storagePath: storage })
    assert.equal(after.pythonPath, managed)
    assert.equal(after.needsSetup, false)
  })

  it('run from the repository, uses its backend and its venv', () => {
    const repository = temporary()
    const extension = path.join(repository, 'vscode-extension')
    fs.mkdirSync(extension)
    scannerAt(path.join(repository, 'backend'), { venv: true })

    const found = locate(configuration(), { extensionPath: extension, storagePath: temporary() })

    assert.equal(found.backendPath, path.join(repository, 'backend'))
    assert.equal(found.pythonPath, pythonIn(path.join(repository, 'backend', 'venv')))
    assert.equal(found.needsSetup, false)
  })

  it('keeps the old default for a user backend with no interpreter named', () => {
    const found = locate(configuration({ backendPath: '/mine/backend' }), { extensionPath: temporary() })

    assert.equal(found.pythonPath, 'python')
    assert.equal(found.needsSetup, false)
  })

  it('reports no scanner at all when there is none to find', () => {
    const found = locate(configuration(), { extensionPath: temporary(), storagePath: temporary() })

    assert.equal(found.backendPath, '')
    assert.equal(found.needsSetup, false)
  })

  it('ignores a value a workspace set: only the user level counts', () => {
    const settings = {
      get: (key) => ({ backendPath: '/workspace/evil', pythonPath: '/workspace/evil.exe' })[key],
      inspect: (key) => ({ globalValue: undefined, workspaceValue: `/workspace/${key}` }),
    }
    const extension = temporary()
    scannerAt(path.join(extension, 'scanner'))

    const found = locate(settings, { extensionPath: extension, storagePath: temporary() })

    assert.equal(found.backendPath, path.join(extension, 'scanner'))
    assert.notEqual(found.pythonPath, '/workspace/evil.exe')
  })

  it('finds nothing when the extension folder is not known', () => {
    assert.equal(bundledScanner(undefined), null)
  })
})

describe('choosing a Python', () => {
  it('tries the launcher first on Windows and python3 elsewhere, unless the user named one', () => {
    assert.deepEqual(candidates(configuration(), 'win32'), [['py', '-3'], ['python'], ['python3']])
    assert.deepEqual(candidates(configuration(), 'linux'), [['python3'], ['python']])
    assert.deepEqual(candidates(configuration({ pythonPath: 'C:\\Python313\\python.exe' }), 'win32'), [
      ['C:\\Python313\\python.exe'],
    ])
  })

  it('needs Python 3.12 or newer', () => {
    assert.deepEqual(parseVersion('3.13\n'), [3, 13])
    assert.equal(parseVersion('Python'), null)
    assert.equal(isRecentEnough([3, 12]), true)
    assert.equal(isRecentEnough([3, 11]), false)
    assert.equal(isRecentEnough([4, 0]), true)
    assert.equal(isRecentEnough(null), false)
  })

  it('takes the first that runs and is new enough', async () => {
    const versions = { python3: '3.11\n', python: '3.13\n' }
    const run = async (file) => (versions[file] ? { error: null, stdout: versions[file] } : { error: new Error('ENOENT') })

    const found = await findPython(run, configuration(), 'linux')

    assert.deepEqual([found.file, found.version], ['python', [3, 13]])
  })

  it('says which it tried when none will do', async () => {
    const run = async () => ({ error: null, stdout: '3.10\n' })

    await assert.rejects(findPython(run, configuration(), 'linux'), (error) => {
      assert.ok(error instanceof SetupError)
      assert.match(error.message, /Python 3\.12 or newer/)
      assert.match(error.detail, /python3: 3\.10/)
      return true
    })
  })
})

describe('createEnvironment', () => {
  function fakeRun({ failPip = false } = {}) {
    const calls = []
    const run = async (file, args, options) => {
      calls.push({ file, args, options })
      if (args.includes('-c')) return { error: null, stdout: '3.13\n', stderr: '' }
      if (args.includes('venv')) {
        const python = pythonIn(args.at(-1))
        fs.mkdirSync(path.dirname(python), { recursive: true })
        fs.writeFileSync(python, '')
        return { error: null, stdout: '', stderr: '' }
      }
      return failPip
        ? { error: new Error('pip failed'), stdout: '', stderr: 'Could not find a version' }
        : { error: null, stdout: 'Successfully installed pydantic', stderr: '' }
    }
    return { run, calls }
  }

  it("creates the environment in the extension's storage and installs the pinned packages into it", async () => {
    const backend = scannerAt(temporary())
    const storage = temporary()
    const { run, calls } = fakeRun()
    const log = []

    const python = await createEnvironment({
      run,
      configuration: configuration(),
      backendPath: backend,
      storagePath: storage,
      platform: 'linux',
      log: (line) => log.push(line),
    })

    assert.equal(python, pythonIn(path.join(storage, ENVIRONMENT_FOLDER), 'linux'))
    const pip = calls.at(-1)
    assert.equal(pip.file, python)
    assert.deepEqual(pip.args, [
      '-m',
      'pip',
      'install',
      '--disable-pip-version-check',
      '--no-input',
      '--requirement',
      path.join(backend, 'requirements-scanner.txt'),
    ])
    assert.ok(calls.every((call) => !('shell' in call.options)))
    assert.match(log.join('\n'), /Using Python 3\.13/)
  })

  it('removes a half-made environment when the packages cannot be installed', async () => {
    const backend = scannerAt(temporary())
    const storage = temporary()
    const { run } = fakeRun({ failPip: true })

    await assert.rejects(
      createEnvironment({ run, configuration: configuration(), backendPath: backend, storagePath: storage, platform: 'linux', log: () => {} }),
      (error) => error instanceof SetupError && /internet connection/.test(error.message) && /Could not find/.test(error.detail),
    )

    assert.equal(fs.existsSync(path.join(storage, ENVIRONMENT_FOLDER)), false)
  })

  it('refuses a scanner with no list of packages', async () => {
    const backend = scannerAt(temporary(), { requirements: false })

    await assert.rejects(
      createEnvironment({ run: fakeRun().run, configuration: configuration(), backendPath: backend, storagePath: temporary(), log: () => {} }),
      SetupError,
    )
  })
})
