# Phase 17 — Fixes where the developer is

**Status:** complete
**Branch:** `phase-17-vscode-fixes`

Phases 10 and 11 could propose a fix and check it — in the web application,
through a queue, a database and a worker. A developer in an editor or at a
terminal had the findings and nothing else. This phase brings the fix to them:
a `fix` command on the scanner, and quick fixes on every finding in VS Code.

The rule from Phase 11 carries over unchanged: **nothing is called a fix until
a re-scan of a copy supports it.** That applies to a fix written by the model
and to one written by this project's own code alike.

## What it does

| Where | What |
| --- | --- |
| Command line | `python -m app.cli fix PATH --at FILE:LINE [--mode builtin|model] [--json FILE] [--apply]` |
| VS Code | the lightbulb on a finding offers **SentinelForge: *the built-in fix*** and **Ask the local model for a fix** |

In both, the same steps run in the same order:

1. **Scan the folder as it is now** and find the finding by its fingerprint. A
   finding remembered from an earlier scan may have moved; a fix worked out
   from a remembered line number would edit whatever is on that line today.
2. **Refuse a leaked credential.** Editing the line does not un-leak it.
3. **Get a change** — from a built-in rewrite, or from the local model, asked
   with the same prompt and held to the same output contract as in the web
   application.
4. **Check it is worth testing**: it changes something, it is not a deletion,
   it is not a rewrite of the whole region, and a Python file still parses.
5. **Apply it to a throwaway copy and scan the copy.** Verified only if the
   finding is gone and nothing new appeared.

The scanner never writes to the folder unless `--apply` is given, and then only
a verified change, and only if the file has not changed since it was read. The
editor does not use `--apply` at all: it receives the change as line edits and
makes them itself, after asking.

## Built-in fixes

Twelve rules have exactly one right rewrite, so they are fixed without a model —
instantly, offline, the same way every time:

| Rule | Fix |
| --- | --- |
| PY007, JS005, JV003 | weak hash → SHA-256 |
| PY004 | `yaml.load` → the safe loader |
| PY008, JS006 | certificate verification turned back on |
| PY014 | an unverified SSL context → a verifying one |
| PY009 | Flask `debug=True` → `False` |
| PY011 | `random` for a secret → the `secrets` module (with the import) |
| JV005 | `java.util.Random` → `SecureRandom` |
| PY023, JV006 | cookie marked `Secure` |

A rule gets a built-in fix only when there is one right answer, it fits on the
finding's lines, and what else it changes fits in one sentence — which every fix
carries as a `caution`, shown before the user accepts it ("values hashed before
this change will not match values hashed after it").

SQL injection is the instructive absence. A parameterised query is the right
fix, but the placeholder is `%s` for one driver and `?` for another, and the
wrong one produces code that looks fixed and fails at runtime. That is a
decision, not a rewrite, so it goes to the model or to a person.

Python rewrites are made through the syntax tree, never by searching the line
for text: `verify=False` inside a string, a comment, or a different call on the
same line is not what the analyser reported. Every edit also names the words it
expects to replace and refuses if something else is there.

## In VS Code

- The quick fixes come from the report: it carries each finding's fingerprint
  and the scanner's own list of rules with a built-in fix, so the extension
  keeps no list of its own to fall out of date.
- Nothing for a credential, nothing for another extension's diagnostics.
- The file must be saved first: the scanner reads the file on disk, and a fix
  worked out from that must not be applied to different text in the editor.
- A verified fix is shown with what it does, the caution, and what the check
  does not prove, and the user chooses **Apply** or **Show changes** (a side by
  side view of the proposed file, held in memory and never written).
- At the moment of applying, every line the edit replaces must still read
  exactly as it did when it was checked, and the file must have no unsaved
  edits. Otherwise nothing is applied and the user is asked to scan again.
- After applying, the file is saved and the workspace scanned again — which is
  also the user's own confirmation that the finding is gone.
- A rejected fix can be shown; a rejected model fix can be tried again (at a
  slightly higher temperature, because at 0 the same question returns the same
  answer). "No built-in fix" offers the model.
- One fix at a time; the extension's own save does not trigger scan-on-save.

### What a workspace cannot do

The model's address, the model and its time limit are user settings, like the
interpreter: a repository's `.vscode/settings.json` cannot point them anywhere.
A model that is not on this machine is refused unless the user turns on
`sentinelforge.allowRemoteModel`, because asking for a fix sends the code around
the finding to it. A test checks every setting the code reads is declared, and
that the ones deciding what runs or where code goes are machine-scoped.

## A bug in Phase 11 that this phase found

A built-in fix on a line with two findings was refused. On a line like
`hashlib.md5(os.popen(cmd).read())`, fixing the hash rewrites the line, and the
command-injection finding on it comes back with a new identity, because a
finding's identity includes the text of its line. The validator called that a
new weakness and rejected a correct fix.

The comparison now asks two different questions. For the finding's own rule:
does it still fire in that file? For every other rule: does the file now have
*more* findings of that rule than before? The same command injection on a
reworded line is carried over; a genuinely new one is still caught. This change
is shared with the web application, which had the same problem.

## Tests

| | |
| --- | --- |
| Backend | 243 tests for the fix code, the command and the shared patching code, including every built-in fix applied and re-scanned on a real file |
| Whole backend suite | 1,763 tests; 1,761 pass here. The other two need to resolve a host name, which this build environment cannot do; they failed in the same way before this phase |
| Lint | `ruff check` and `ruff format --check` clean |
| Extension | 171 tests (74 new): the result format, placing edits, the quick fixes, every way a fix can end, the manifest, and the real scanner end to end |
| Mutation | 18 safety checks broken one at a time; two survived the first pass and each got a test (below) |

The two survivors:

- **"The words are where the tree says"** passed with the check removed. A test
  needed a file whose lines the parser and the line list count differently —
  a form feed ends a line for `str.splitlines` but not for Python — so the
  tree's line 3 is the list's line 4. Without the check, the fix would edit the
  wrong line.
- **"No unsaved edits at the moment of applying"** passed too, because every
  test that changed the file also changed the lines being replaced. The new
  test edits a *different* line: the replaced lines still match, but saving
  would also save an edit nobody checked.

## Not verified

- **Not run inside VS Code.** The extension's tests use a stand-in for the
  editor API. The lightbulb, the modal question and the side-by-side view are
  what the stand-in assumes VS Code does; the first run in a real editor is
  their test.
- **The model path was not run against a real model.** There is no Ollama
  here. Its tests use a stand-in for the model. That the full path reports
  "Could not reach Ollama" correctly was checked against a real closed port.
- **Windows.** Run `.\scripts\verify.ps1`.

## Limitations

- Built-in fixes for 12 rules; the model for the rest, which on a CPU takes up
  to a minute and is not always right.
- A model fix from the editor is grounded in this project's fix note for the
  rule. The web application also gives the model CWE and OWASP passages from
  its knowledge base, which needs its database.
- The re-scan shows the scanner no longer detects the problem. It does not show
  the program behaves the same: nothing in the workspace is run.

## Using it

```powershell
# from backend, venv active
python -m app.cli fix C:\path\to\project --at app\main.py:12
python -m app.cli fix C:\path\to\project --at app\main.py:12 --mode model
```

In VS Code: start the extension as before, scan, put the cursor on an
underlined line and press `Ctrl+.`. For model fixes, Ollama must be running
with `qwen2.5-coder:7b` pulled.
