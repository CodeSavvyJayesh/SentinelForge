'use strict'

/**
 * Where the scanner is, which Python runs it, and setting that Python up.
 *
 * Three ways of running the extension, found in this order:
 *
 * 1. **The user said.** `sentinelforge.backendPath` and `sentinelforge.pythonPath`
 *    in user settings always win. That is how a developer points it at a
 *    checkout of their own.
 * 2. **Installed from a .vsix.** The package carries the scanner's source in
 *    `scanner/`. Its Python packages are not carried — some of them are
 *    compiled per platform — so they are installed once, on request, into a
 *    virtual environment in the extension's own storage folder.
 * 3. **Run from the repository** (`F5`, or `--extensionDevelopmentPath`). The
 *    scanner is the repository's `backend` folder, and its `venv` is used if
 *    there is one.
 *
 * Nothing here is read from a workspace: every path comes from the extension's
 * own folder, its own storage, or user settings that a workspace cannot set.
 */

const fs = require('node:fs')
const path = require('node:path')

const MINIMUM_PYTHON = [3, 12]
const ENVIRONMENT_FOLDER = 'scanner-env'
const REQUIREMENTS = 'requirements-scanner.txt'
const SETUP_TIMEOUT_MS = 15 * 60 * 1000
const CHECK_TIMEOUT_MS = 30_000

class SetupError extends Error {
  constructor(message, detail = '') {
    super(message)
    this.name = 'SetupError'
    this.detail = detail
  }
}

function isScanner(folder) {
  return Boolean(folder) && fs.existsSync(path.join(folder, 'app', 'cli', '__main__.py'))
}

function pythonIn(environment, platform = process.platform) {
  return platform === 'win32'
    ? path.join(environment, 'Scripts', 'python.exe')
    : path.join(environment, 'bin', 'python')
}

/** The scanner folders this extension can find without being told. */
function bundledScanner(extensionPath) {
  if (!extensionPath) return null
  const packaged = path.join(extensionPath, 'scanner')
  if (isScanner(packaged)) return { folder: packaged, kind: 'packaged' }
  const repository = path.join(extensionPath, '..', 'backend')
  if (isScanner(repository)) return { folder: path.resolve(repository), kind: 'repository' }
  return null
}

/** A setting's value only if the user set it themselves. */
function userValue(configuration, key) {
  const inspected = typeof configuration.inspect === 'function' ? configuration.inspect(key) : undefined
  const value = inspected ? inspected.globalValue : configuration.get(key)
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : ''
}

/**
 * Where the scanner is and which Python runs it.
 *
 * Returns `{ backendPath, pythonPath, needsSetup, managed }`. `needsSetup` is
 * true when nothing tells us which Python has the scanner's packages: the
 * packaged scanner before its one-time setup.
 */
function locate(configuration, { extensionPath, storagePath, platform = process.platform }) {
  const userBackend = userValue(configuration, 'backendPath')
  const userPython = userValue(configuration, 'pythonPath')
  const found = userBackend ? null : bundledScanner(extensionPath)
  const backendPath = userBackend || found?.folder || ''
  const managed = storagePath ? pythonIn(path.join(storagePath, ENVIRONMENT_FOLDER), platform) : ''

  if (userPython) return { backendPath, pythonPath: userPython, needsSetup: false, managed }
  if (managed && fs.existsSync(managed)) return { backendPath, pythonPath: managed, needsSetup: false, managed }
  if (found?.kind === 'repository') {
    const venv = pythonIn(path.join(found.folder, 'venv'), platform)
    if (fs.existsSync(venv)) return { backendPath, pythonPath: venv, needsSetup: false, managed }
  }
  // The user's own backend with no interpreter named: the old default.
  if (userBackend) return { backendPath, pythonPath: 'python', needsSetup: false, managed }
  return { backendPath, pythonPath: '', needsSetup: Boolean(backendPath), managed }
}

/** The interpreters worth trying to create the environment with, best first. */
function candidates(configuration, platform = process.platform) {
  const userPython = userValue(configuration, 'pythonPath')
  if (userPython) return [[userPython]]
  return platform === 'win32' ? [['py', '-3'], ['python'], ['python3']] : [['python3'], ['python']]
}

function parseVersion(text) {
  const match = /^(\d+)\.(\d+)/.exec(String(text).trim())
  return match ? [Number(match[1]), Number(match[2])] : null
}

function isRecentEnough(version) {
  return (
    version !== null &&
    (version[0] > MINIMUM_PYTHON[0] || (version[0] === MINIMUM_PYTHON[0] && version[1] >= MINIMUM_PYTHON[1]))
  )
}

/** The first interpreter that runs and is new enough, or a SetupError saying why none is. */
async function findPython(run, configuration, platform = process.platform) {
  const tried = []
  for (const [file, ...prefix] of candidates(configuration, platform)) {
    const { error, stdout } = await run(
      file,
      [...prefix, '-c', 'import sys; print("%d.%d" % sys.version_info[:2])'],
      { timeout: CHECK_TIMEOUT_MS, windowsHide: true },
    )
    const version = error ? null : parseVersion(stdout)
    tried.push(`${[file, ...prefix].join(' ')}: ${version ? version.join('.') : 'not found'}`)
    if (isRecentEnough(version)) return { file, prefix, version }
  }
  throw new SetupError(
    `SentinelForge needs Python ${MINIMUM_PYTHON.join('.')} or newer, and none was found. ` +
      'Install it from python.org, then run "SentinelForge: Set up the scanner" again.',
    tried.join('\n'),
  )
}

/**
 * Create the scanner's virtual environment and install its packages.
 *
 * The environment lives in the extension's own storage folder, so nothing is
 * installed into the user's Python, and removing the extension removes it.
 * The packages and their versions are the ones pinned in the scanner's
 * requirements file, which is part of the package.
 */
async function createEnvironment({ run, configuration, backendPath, storagePath, platform = process.platform, log }) {
  const requirements = path.join(backendPath, REQUIREMENTS)
  if (!fs.existsSync(requirements)) {
    throw new SetupError('This copy of the scanner has no list of packages to install.')
  }
  const python = await findPython(run, configuration, platform)
  log(`Using Python ${python.version.join('.')} (${[python.file, ...python.prefix].join(' ')}).`)

  const environment = path.join(storagePath, ENVIRONMENT_FOLDER)
  fs.mkdirSync(storagePath, { recursive: true })
  // A half-made environment from an interrupted attempt is started again.
  fs.rmSync(environment, { recursive: true, force: true })
  const options = { timeout: SETUP_TIMEOUT_MS, windowsHide: true, maxBuffer: 20 * 1024 * 1024 }

  let step = await run(python.file, [...python.prefix, '-m', 'venv', environment], options)
  if (step.error) {
    throw new SetupError('Python could not create a virtual environment for the scanner.', step.stderr)
  }
  const managed = pythonIn(environment, platform)
  step = await run(
    managed,
    ['-m', 'pip', 'install', '--disable-pip-version-check', '--no-input', '--requirement', requirements],
    options,
  )
  log(step.stdout)
  if (step.error) {
    fs.rmSync(environment, { recursive: true, force: true })
    throw new SetupError(
      "The scanner's packages could not be installed. Check your internet connection and try again.",
      step.stderr,
    )
  }
  return managed
}

module.exports = {
  ENVIRONMENT_FOLDER,
  MINIMUM_PYTHON,
  REQUIREMENTS,
  SetupError,
  bundledScanner,
  candidates,
  createEnvironment,
  findPython,
  isRecentEnough,
  locate,
  parseVersion,
  pythonIn,
}
