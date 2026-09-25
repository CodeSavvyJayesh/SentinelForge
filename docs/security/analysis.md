# Analysing untrusted code

Phase 4 got other people's code onto disk without trusting it. Phase 5 reads
it. The rule carries over unchanged:

> **Code that arrives here is data, never something to run.**

Python is parsed with `ast.parse`, which builds a syntax tree and imports,
calls and evaluates nothing. Every other language is matched as text. No build
step, no dependency install, no test run, no plugin loaded from the repository.

## Why an AST for Python and regular expressions for the rest

These three lines are identical to a regular expression and completely
different to a parser:

```python
eval(config)          # a finding
# eval(config)        # a comment
"eval(config)"        # a string in a docstring about not using eval
```

So Python — the language the project targets first — gets a real parser. It
also gives the analyser things a regex cannot have: that `shell=True` is a
keyword argument to *this* call, that `ElementTree` came from `xml.etree` and
not `defusedxml`, and that a query string was *built* rather than parameterised.

JavaScript, Java, PHP and Go get carefully written regular expressions, and the
cost is admitted rather than hidden:

- Line comments are stripped before matching, so "do not use `eval(input)`
  here" is not a finding.
- Rules require the dangerous **shape**, not just the function name:
  `exec("ls")` is not reported, ``exec(`ls ${dir}`)`` is.
- Those rules are capped at MEDIUM confidence unless the pattern cannot mean
  anything else (`rejectUnauthorized: false`).

A parser per language is a project of its own. Until then, the honest position
is a lower confidence score and this paragraph.

## Severity and confidence are two different questions

| | |
| --- | --- |
| **Severity** | how bad it is *if the finding is real* |
| **Confidence** | how sure the analyser is that it found what it thinks it found |

A hardcoded AWS key is CRITICAL/HIGH. A string concatenated into something that
*looks like* SQL is CRITICAL/MEDIUM — serious if real, and we are guessing that
it is a query. Collapsing the two into one number is how scanners end up crying
wolf, and a scanner people ignore finds nothing at all.

## Every rule has a counterexample

For each rule there are two tests: code that must trigger it, and realistic
code that must **not**. The second is the one that keeps the tool usable:

| Rule | Must fire on | Must stay quiet on |
| --- | --- | --- |
| `eval` | `eval(payload)` | `eval("2 + 2")`, `model.evaluate(data)`, the word in a comment |
| SQL injection | `execute(f"SELECT … {user_id}")` | `execute("SELECT … %s", (user_id,))`, `runner.execute(f"job-{id}")` |
| Weak randomness | `session_token = random.choice(…)` | `colour = random.choice(["red", "green"])` |
| Hardcoded secret | `DB_PASSWORD = "sup3r-s3cret…"` | `os.environ["DB_PASSWORD"]`, `"changeme"`, `"${DB_PASSWORD}"` |
| Weak hash | `hashlib.md5(...)` | `hashlib.sha256(...)` |
| XML | `xml.etree.ElementTree.parse` | `defusedxml.ElementTree.parse` |

`backend/.env.example` is the nastiest test case in the repository: a file that
exists to *document* credentials. A scanner that reports it is a scanner that
gets muted. There is a test asserting it produces nothing.

## A finding about a leaked secret never leaks it again

The single most important rule in this phase. A credential finding stores the
file, the line and the *shape* of the value:

```
DB_PASSWORD = <redacted 27-character value>
AWS_ACCESS_KEY_ID=AKIA…<redacted 20 chars>
```

The value itself never reaches the database, the API, the audit log, the UI or
a report — all of which are read by more people, and kept for longer, than the
source file it came from. Three tests enforce it, including a browser check
that the planted secret appears nowhere in the rendered page or its HTML.

## Fingerprints, and why they ignore line numbers

Each finding's identity is `sha256(rule, file, normalised code, occurrence)`.

- **Not the line number**, so adding an import at the top of a file does not
  turn every finding below it into a "new" one.
- **Plus an occurrence counter**, so `os.system(cmd)` on line 10 and line 200
  of the same file are two findings rather than one. Without it the second one
  silently disappears — which is how a scanner quietly under-reports.

Re-analysing replaces the previous findings rather than appending: the findings
describe the code as it is now, so a fixed vulnerability disappears instead of
lingering as a false accusation. History belongs to scans, in Phase 6.

## Bounds

| Limit | Why |
| --- | --- |
| `ANALYSIS_MAX_FILE_BYTES` (1 MB) | a generated bundle is not source code; parsing it costs seconds and finds nothing |
| `ANALYSIS_MAX_FINDINGS` (2000) | past this the repository has a systemic problem a longer list will not help with; the response says `truncated: true` rather than pretending to be complete |
| Binary sniff (null byte) | a `.dat` file full of bytes is not text, whatever its extension says |
| Ignored directories | `node_modules`, `.git`, `dist`, `venv` — inherited from Phase 4 |

An analysis that never finishes is an outage, so every one of these is a real
limit rather than a suggestion.

## What this phase deliberately does not claim

- **"No findings" is not "secure."** It means these rules did not match. The
  empty state in the UI says exactly that, in those words.
- **No data-flow analysis.** The rules are local: they see a dangerous call,
  not a path from user input to it. Real taint tracking needs a call graph,
  and inventing one badly produces confident nonsense.
- **No third-party scanner adapters yet** (Semgrep, Bandit, SonarQube). The
  normalised `Finding` shape exists so they can be added as another analyser
  without changing the database or the UI.
- **Nothing is auto-fixed.** Patch generation is Phases 10–11, and it comes
  with re-analysis before anything is called secure.
