# SentinelForge for VS Code

Shows SentinelForge's security findings on the lines they are on, and fixes
them.

- **Scan workspace** — underlines each finding in the editor and lists it in
  the Problems panel, with the rule, why it matters and how to fix it.
- **Status bar** — the workspace's risk grade and how many findings are open.
  Click it to scan again.
- **Open report** — the full report as a page in your browser, ready to print.
- **Quick fixes** — click the lightbulb on a finding: a built-in fix where
  one exists, or ask your local model. Every fix is checked by scanning a copy
  before you are asked whether to apply it.
- **Scan on save** — optional.

The extension contains no detection logic of its own. It runs the same scanner
as the web application and the build pipeline (`python -m app.cli scan`) and
shows what it reports, so the three cannot disagree.

Nothing is sent anywhere. The scanner runs on your machine, a scan opens no
network connection, and nothing in the workspace is executed. Asking the local
model for a fix sends the code around that finding to Ollama on your own
machine, and nowhere else unless you allow it (see below).

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

**From a terminal** — the simplest way, and it needs nothing set up:

```
code --extensionDevelopmentPath=C:\SentinelForge\vscode-extension C:\path\to\some\project
```

A window opens on that project with the extension loaded.

**While developing** — open the `vscode-extension` folder itself in VS Code (not
the repository root) and press `F5`. A second window opens with the extension
loaded; open any folder in it.

**As an installed extension** — package it once, then install the file:

```
cd vscode-extension
npx @vscode/vsce package
code --install-extension sentinelforge-0.2.0.vsix
```

Then run **SentinelForge: Scan workspace** from the Command Palette
(`Ctrl+Shift+P`).

## Fixing a finding

Put the cursor on an underlined line and press `Ctrl+.` (or click the
lightbulb). SentinelForge offers up to two fixes:

| Quick fix | What it does |
| --- | --- |
| **SentinelForge: *what the fix does*** | A built-in fix. No model, instant, the same change every time. Offered for the 12 rules where there is exactly one right rewrite: weak hashes, `yaml.load` without a safe loader, certificate checks turned off, Flask's `debug=True`, `random` used for secrets and insecure cookies — in Python, and the Java and JavaScript equivalents. |
| **SentinelForge: Ask the local model for a fix** | Asks your local Ollama model (`qwen2.5-coder:7b` by default) for a change. Offered for every finding except leaked credentials. Takes up to a minute on a CPU. |

Whichever you choose, the same thing happens next:

1. The scanner works out the change and applies it to a **throwaway copy** of
   the folder.
2. It **scans the copy again**. The change is offered only if the finding is
   gone, nothing new appeared, the change replaces code with code rather than
   deleting it, and (for Python) the file still parses.
3. You are shown what the change does and what to watch for, and asked
   whether to apply it. **Show changes** opens it side by side first.
4. If you apply it, the edit is made in the editor, the file is saved and the
   workspace is scanned again.

Your file is never touched until you choose **Apply**, and not even then if it
has changed since the fix was checked — you are asked to scan again instead.
A file with unsaved changes has to be saved before a fix is worked out, because
the scanner reads the file on disk.

A leaked password or key is never "fixed": editing the line does not un-leak
it. Rotate it and load the new one from the environment.

"Checked by re-scan" means the scanner no longer detects the problem. It does
not mean the program still behaves the same — nothing in the workspace is run,
not even its tests. Read the change before you apply it.

For the model fix, Ollama must be running with the model pulled:

```
ollama pull qwen2.5-coder:7b
```

## Settings

| Setting | Default | |
| --- | --- | --- |
| `sentinelforge.backendPath` | — | SentinelForge's `backend` folder. User setting only |
| `sentinelforge.pythonPath` | `python` | An interpreter with the backend's requirements. User setting only |
| `sentinelforge.scanOnSave` | `false` | Scan again when a file is saved |
| `sentinelforge.exclude` | `[]` | Paths or globs to leave out, e.g. `tests`, `*.min.js`. The number left out is shown in the status bar's tooltip |
| `sentinelforge.timeoutSeconds` | `120` | Give up on a scan after this long |
| `sentinelforge.ollamaUrl` | `http://localhost:11434` | Your local Ollama, for model fixes. User setting only |
| `sentinelforge.model` | `qwen2.5-coder:7b` | The model that proposes fixes. User setting only |
| `sentinelforge.modelTimeoutSeconds` | `300` | Give up on the model after this long. User setting only |
| `sentinelforge.allowRemoteModel` | `false` | Allow `ollamaUrl` to be another machine. Off: the code around a finding would be sent there. User setting only |

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

- **A workspace cannot choose where your code is sent.** The model's address
  is a user setting too, and a model on another machine is refused unless you
  turn on `sentinelforge.allowRemoteModel` yourself.
- **A fix is data, not a command.** The scanner returns the change as line
  edits; the extension checks each one is well formed and that every line it
  replaces still reads exactly as it did when the change was checked, before
  making it. The scanner itself never writes to the workspace.

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
- Built-in fixes exist for 12 rules. For the rest, the model is asked, and a
  7B model on a CPU takes up to a minute and is not always right — which is why
  every proposal is re-scanned and you are asked before anything changes.
- A model fix from the editor is grounded in this project's own fix note for
  the rule. The web application also gives the model the CWE and OWASP
  passages from its knowledge base, which needs its database.
- One fix at a time. The workspace is scanned again after each one.
