# Phase 15 — VS Code extension

**Status:** complete
**Branch:** `phase-15-vscode`

A finding in a web page is something a developer goes and looks at. A finding
underlined in the file they are editing is something they see. This phase puts
SentinelForge's findings in the editor: on the line, in the Problems panel, and
as a grade in the status bar.

## What it does

| | |
| --- | --- |
| **SentinelForge: Scan workspace** | scans every folder in the workspace and shows the findings |
| On each finding | the title, why it matters, and this project's fix note for the rule; the rule id links to the CWE page |
| Status bar | `SentinelForge D · 43` — the grade and the number open; the breakdown on hover; click to scan |
| **SentinelForge: Open report** | the HTML report from Phase 13, opened in the browser |
| **SentinelForge: Clear findings** | removes them |
| `sentinelforge.scanOnSave` | scan again when a file is saved (off by default) |

## A thin layer, on purpose

The extension has no detection logic. It runs `python -m app.cli scan` — the
Phase 14 command — and reads the JSON report. The editor, the pipeline and the
web application therefore run one analyser and build one report, and cannot
disagree about what is a finding.

It is also plain JavaScript with **no dependencies and no build step**. There
is nothing to compile and nothing to install; the tests run with Node's built-in
test runner.

| File | What it is |
| --- | --- |
| `vscode-extension/package.json` | the manifest: commands, settings, what an untrusted workspace may do |
| `src/extension.js` | four lines: hands the real `vscode` module to the controller |
| `src/controller.js` | everything the extension does, with the editor's API passed in |
| `src/scanner.js` | runs the scanner, reads the report, explains failures |
| `src/diagnostics.js` | turns a report into what an editor shows; pure functions |
| `test/` | 97 tests, 9 of them against the real scanner |
| `support/fake-vscode.js` | the stand-in for the editor's API that the tests use |

## The design question that mattered: what can a repository make this run?

A security scanner is the tool somebody runs on code they do **not** trust. An
editor extension that runs a program, in a workspace that can carry its own
settings, is a well-known way to turn "open this repository" into "run this
code". Five decisions close that off.

**A workspace cannot choose the interpreter or the scanner.**
`sentinelforge.pythonPath` and `sentinelforge.backendPath` are declared
`machine`-scoped, so VS Code ignores them in a workspace's
`.vscode/settings.json`. Without that, a repository could point `pythonPath` at
a script it ships.

**The scanner's location is never guessed from the workspace.** It would have
been convenient to look for a `backend/` folder in the open workspace and use
it. That is exactly the convenience that runs a stranger's code, so the path
has to be set once, by hand, in user settings.

**Python starts in the scanner's folder, not the workspace.** `python -m`
puts the working directory first on the import path. Started in the workspace,
a repository containing its own `app/cli` package would be run *instead of* the
scanner. A test builds that repository and checks that nothing in it ran.

**No shell, and every option is one token.** The command is a program and a
list of arguments. Exclusion patterns are passed as `--exclude=PATTERN`, never
as `--exclude` followed by the pattern, so a pattern of `--html` or
`--sarif=/somewhere` stays a pattern. Exclusions are the one setting a workspace
*can* supply, which is why this matters.

**A finding cannot be placed outside the workspace.** Paths in the report are
checked — no `..`, no absolute path, no drive letter — before they are joined
onto the workspace folder.

The extension declares itself safe for untrusted workspaces, and says why in
the manifest.

What a workspace *can* still do is set `sentinelforge.exclude` and hide its own
findings. The number left out is therefore always shown in the status bar's
tooltip.

## How it was tested without an editor

VS Code cannot be started where this was written, so the extension is built to
be testable without it:

- **`diagnostics.js` and `scanner.js` do not touch the editor's API.** They are
  tested directly: 36 tests on the mapping, 29 on running the scanner with a
  stand-in for Python.
- **`controller.js` takes the `vscode` module as an argument.** The tests pass
  a stand-in that records what it was asked to do — which diagnostics were set
  on which files, what the status bar says, which message was shown — and
  drive the commands through it. 23 tests.
- **Nine tests run the real scanner.** A real Python, the real command, a real
  folder on disk: the right lines, a clean folder, exclusions, a missing
  interpreter, a wrong backend path, the hostile repository above, and that a
  scan writes nothing into the folder it scans.

The stand-in is a model of the API, not the API. It shows the extension asks
for the right things; it cannot show that VS Code does what the stand-in
assumes. That gap is stated below rather than papered over.

## Mutation testing: 56 claims, 56 covered

One survived the first pass, and it was the same kind as in earlier phases: an
explicit "refuse an absolute path" check that could be deleted without any test
failing, because the rule beside it (no empty path segment) already refused
every absolute path. It was removed, and the comment now says what covers it.

## Verification

| Check | Result |
| --- | --- |
| Extension tests | 97 passed (88 without the real scanner) |
| Mutation pass | 56 / 56 |
| Backend tests | 1088 passed (unchanged: no backend code changed) |
| The CI scan step on a clean copy, extension included | exit 0 |
| `package.json`, `launch.json` | parse |

The extension's tests are a new job in the CI workflow and a new step in
`scripts/verify.ps1`.

## What the first F5 found

Pressing `F5` asked for "an extension for debugging JSON". The launch
configuration that tells VS Code how to start the extension had never been
committed: the repository ignores every `.vscode/` folder, and the file was in
one. It existed where the extension was written, so nothing there noticed; the
commit simply did not contain it.

The ignore rule now has an exception for `vscode-extension/.vscode/`. The
README also gives a way to start the extension that needs no configuration file
at all, which is the more robust instruction anyway.

## Run in VS Code, on Windows

After the launch configuration was fixed, the extension was started with `F5`
on the development machine (Windows, VS Code with an Extension Development
Host) and used on two folders:

- a React project with nothing to find: the status bar read
  `SentinelForge A · 0`;
- the same folder with a three-line vulnerable Python file added: the status
  bar read `SentinelForge D · 3`, the Problems counter read 2 errors and
  1 warning, and lines 6, 7 and 8 were underlined — two in red, one in yellow —
  each with its title, its reason and its fix.

That is the editor doing what the stand-in assumed it would, for the main path:
activation, the status bar, running the scanner through a Windows virtual
environment, and placing diagnostics. The **Open report** command, scan on
save, multi-root workspaces and the failure messages were not exercised by
hand; they rest on the tests.

## Not verified

- **`vsce package` was not run.** Packaging needs the npm registry, which is
  not reachable here. The manifest has no `LICENSE` file beside it, which
  `vsce` warns about.
- **JavaScript type-checking was not run** on the extension. There is no
  TypeScript and no linter for this folder.

## Limitations

- Findings follow a scan, not your typing. After an edit a finding can sit a
  line or two off until the next scan.
- The whole workspace is scanned every time.
- A finding underlines its whole line.
- No explanations or proposed fixes from the local model; those stay in the web
  application, behind their warnings.
- No quick-fix actions. A code action that rewrote code would be an unvalidated
  patch, which is the thing Phases 10 and 11 exist to prevent.
- Not published to the Marketplace; that needs a publisher account.

## What this unlocks

Every surface a developer meets — the editor, the pull request, the dashboard —
now shows the same findings from the same analyser. What is left is to measure
how good those findings are: Phase 16.
