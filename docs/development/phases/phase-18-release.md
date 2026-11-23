# Phase 18 — Release readiness

**Status:** complete
**Branch:** `phase-18-release`

Until now the VS Code extension worked on one machine: the one with this
repository, a virtual environment, and two paths typed into the settings. This
phase makes it something anyone can install, and turns the classifier's data
collection into one command.

## The extension, installable by anyone

### A package that carries the scanner

`node scripts/package.js` (in `vscode-extension/`) builds
`sentinelforge-0.2.0.vsix`: the extension, its icon and licence, **and the
scanner's source** under `scanner/` — `backend/app` and a new
`backend/requirements-scanner.txt`. About 400 KB.

The script is plain Node — no `vsce`, no npm packages — because packaging should
not need a download, and because nothing here could reach the npm registry. It
writes the zip itself: deflated entries, the `extension.vsixmanifest`, and the
content-type list VS Code reads. It is deterministic: the same sources always
make the same file, byte for byte, which a test checks.

### A one-time setup instead of a manual one

The scanner's Python packages are **not** in the package: `pydantic` is compiled
separately for every platform, so a package carrying it would work on one kind
of machine. Instead, the first scan offers a one-time setup. With the user's
agreement it:

1. finds a Python 3.12 or newer (the `py` launcher on Windows, `python3`
   elsewhere, or the one the user named);
2. creates a virtual environment in the extension's own storage folder;
3. installs exactly the pinned packages in `requirements-scanner.txt`.

Nothing is installed into the user's own Python, and uninstalling the extension
removes it all. If a step fails, the half-made environment is removed and the
message says what to do.

### Where the scanner is, found in order

| | Scanner | Python |
| --- | --- | --- |
| The user set `backendPath` / `pythonPath` | theirs | theirs |
| Installed from the package | `scanner/` inside it | the environment made by the setup |
| Run from the repository (`F5`) | `../backend` | `backend/venv`, if there is one |

Running from the repository therefore needs no settings at all any more.
Only the user's own settings are read for this: a value set in a workspace's
`.vscode/settings.json` is ignored, and a test checks exactly that.

### `requirements-scanner.txt`

Six packages, at the same versions as `requirements.txt` — no server, no
database driver, no migration tool. Two tests keep it honest: every pin must
match the backend's, and a real scan and fix, run in a separate interpreter,
must not import `uvicorn`, `alembic`, `psycopg` or `jwt`. If the scanner ever
came to need a package that is not listed, the extension would install and then
fail on every machine but the developer's; that test is what stops it.

### Licence and publishing

The repository now has an MIT licence in the names of the four team members,
and the extension a 128-pixel icon. Publishing to the Marketplace needs the
team's own Microsoft account; [publishing.md](../../devsecops/publishing.md) is
the step by step.

## The classifier, in one command

```powershell
.\scripts\train-classifier.ps1
```

With the backend and Ollama running, this asks for fixes and checks a few at a
time, prints the counts as they move, stops when there are 60 judged fixes with
15 of each outcome, and trains. `python scripts/collect_patch_outcomes.py auto`
is the same loop on its own.

It decides each step from the counts alone: check what is waiting first (a
proposal waiting for a check is an example nearly made, and costs no model time),
ask for new fixes only when the model is idle, and ask again where a fix was
rejected once every finding has one. It stops, and says why, when nothing more
qualifies (scan more code), when nothing has moved for fifteen minutes with
work outstanding (the backend or Ollama is not running), or after twelve hours.

## Tests

| | |
| --- | --- |
| Extension | 195 tests (24 new): finding the scanner, choosing a Python, the setup and its failures, the setup flow in the editor, the package's contents, its validity as a zip and its reproducibility |
| Backend | 9 new: the collection loop against a real database (enough at once, checks before fixes, batches, a stalled backend, nothing qualifying, asking again, bad settings), and the scanner's requirements |

## Not verified

- **Installing the `.vsix` in a real VS Code.** There is no VS Code here. The
  package is a valid zip with the files VS Code reads, checked by a test that
  unpacks it; installing it is the first real check.
- **The one-time setup against PyPI.** Packages could not be downloaded here.
  The setup's steps are tested with a stand-in for Python and pip; the first
  real install happens on your machine.
- **The collection loop against a real model**, for the same reason as every
  model step: there is no Ollama here.
- **Docker.** There is no Docker daemon here, so `docker compose up --build` has
  still never been run. Run it once on your PC.

## Using it

```powershell
# build the extension package
cd C:\SentinelForge\vscode-extension
node scripts\package.js
code --install-extension sentinelforge-0.2.0.vsix

# train the classifier (backend and Ollama running, a repository scanned)
cd C:\SentinelForge
.\scripts\train-classifier.ps1
```
