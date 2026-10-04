# SentinelForge for VS Code

Shows SentinelForge's security findings on the lines they are on.

- **Scan workspace** — underlines each finding in the editor and lists it in
  the Problems panel, with the rule, why it matters and how to fix it.
- **Status bar** — the workspace's risk grade and how many findings are open.
  Click it to scan again.
- **Open report** — the full report as a page in your browser, ready to print.
- **Scan on save** — optional.

The extension contains no detection logic of its own. It runs the same scanner
as the web application and the build pipeline (`python -m app.cli scan`) and
shows what it reports, so the three cannot disagree.

Nothing is sent anywhere. The scanner runs on your machine and opens no network
connection, and nothing in the workspace is executed.

## Setting it up

The extension needs to know two things, both in your **user** settings
(`Ctrl+,`, search for "SentinelForge"):

| Setting | Example |
| --- | --- |
| `sentinelforge.backendPath` | `C:\SentinelForge\backend` |
| `sentinelforge.pythonPath` | `C:\SentinelForge\backend\venv\Scripts\python.exe` |

or in `settings.json`:

```json
{
  "sentinelforge.backendPath": "C:\\SentinelForge\\backend",
  "sentinelforge.pythonPath": "C:\\SentinelForge\\backend\\venv\\Scripts\\python.exe"
}
```

These two can only be set in user settings. A workspace cannot set them — see
"Opening code you do not trust" below.

## Running it

**While developing** — open the `vscode-extension` folder in VS Code and press
`F5`. A second window opens with the extension loaded; open any folder in it.

**From a terminal**, without opening the extension's folder:

```
code --extensionDevelopmentPath=C:\SentinelForge\vscode-extension C:\path\to\some\project
```

**As an installed extension** — package it once, then install the file:

```
cd vscode-extension
npx @vscode/vsce package
code --install-extension sentinelforge-0.1.0.vsix
```

Then run **SentinelForge: Scan workspace** from the Command Palette
(`Ctrl+Shift+P`).

## Settings

| Setting | Default | |
| --- | --- | --- |
| `sentinelforge.backendPath` | — | SentinelForge's `backend` folder. User setting only |
| `sentinelforge.pythonPath` | `python` | An interpreter with the backend's requirements. User setting only |
| `sentinelforge.scanOnSave` | `false` | Scan again when a file is saved |
| `sentinelforge.exclude` | `[]` | Paths or globs to leave out, e.g. `tests`, `*.min.js`. The number left out is shown in the status bar's tooltip |
| `sentinelforge.timeoutSeconds` | `120` | Give up on a scan after this long |

## Opening code you do not trust

A security scanner is exactly the tool somebody runs on a repository they do
not trust, so the extension is built for that case.

- **Nothing in the workspace is executed** — no build, no test, no script.
- **A workspace cannot choose what is run.** The interpreter and the scanner's
  location are *machine-scoped* settings: VS Code ignores them in a workspace's
  `.vscode/settings.json`. If a repository could set `sentinelforge.pythonPath`,
  opening it and scanning would run whatever it pointed at.
- **The scanner is never loaded from the workspace.** Python is started in the
  scanner's own folder. Started in the workspace, a repository containing its
  own `app/cli` package would be run in place of the scanner. A test builds
  exactly that repository and checks it is not.
- **No shell is involved.** The command is a program and a list of arguments;
  a path or a setting is never interpreted as shell syntax, and every option is
  a single token, so an exclusion pattern cannot turn into another option.
- **A finding cannot be attached to a file outside the workspace.** Paths in
  the report are checked before they are used.
- **The report is written to a temporary folder**, read, and deleted. A scan
  does not change the folder it scans.

A workspace *can* set `sentinelforge.exclude`, and so could hide its own
findings from you. That is why the number left out is always shown.

## Tests

```
cd vscode-extension
node --test
```

No packages to install. To also run the tests that use the real scanner:

```
set SENTINELFORGE_PYTHON=C:\SentinelForge\backend\venv\Scripts\python.exe
node --test
```

## Limitations

- Findings are refreshed by scanning; they do not follow your edits as you type.
  After editing, a finding may sit a line or two away until the next scan.
- The whole workspace is scanned each time. There is no single-file scan.
- A finding underlines its whole line, not the exact expression.
- It shows what the analyser finds. Explanations and proposed fixes from the
  local model are in the web application, not here.
