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
- **Data flow is followed for Python only, and only inside one file.** See the
  next section. For every other language the rules are still local: they see
  a dangerous shape, not a path from user input to it.
- **No third-party scanner adapters yet** (Semgrep, Bandit, SonarQube). The
  normalised `Finding` shape exists so they can be added as another analyser
  without changing the database or the UI.
- **Nothing is auto-fixed.** Patch generation is Phases 10–11, and it comes
  with re-analysis before anything is called secure.


## Following request data through Python (Phase 16)

Phase 5 said: no data-flow analysis, because inventing one badly produces
confident nonsense. Phase 16 measured what that cost — on a benchmark with
known answers the Python rules scored +8 out of 100 — and built one for Python,
with the limits below. How much it helped, and where it still fails, is in
[the evaluation](../evaluation/README.md).

The code is still never run. Each function is walked statement by statement,
and every value is described as one of three things:

| | Meaning | Example |
| --- | --- | --- |
| **request data** | it was read from the request, on a known line | `request.args.get("name")` |
| **clean** | it was built only from literals in this file | `"ls -l " + "/tmp"` |
| **not known** | anything else | what a function in another file returned |

The third one is the important one. An analyser with only "tainted" and
"safe" has to put the unknown in one of them, and both are lies.

### What the rules do with that

Two kinds of rule use it differently, and the difference is deliberate.

- **Calls that are dangerous by nature** — `eval`, `os.system`,
  `subprocess` with a shell, `pickle.loads`, a query built by formatting. These
  were reported before and still are, **unless the argument is shown to be
  clean**. *Not known* is still reported: a value the analyser lost track of is
  not a safe value.
- **Calls that are ordinary until request data reaches them** — opening a
  file, redirecting, writing to the session, building an XPath or LDAP filter,
  returning HTML. Nobody wants every `open()` reported. These are reported
  **only when request data is shown to reach them**, and the finding says
  which line it was read on.

| Rule | Reports request data reaching | Weakness |
| --- | --- | --- |
| PY016 | a command given as a list that still starts a shell (`["sh", "-c", value]`) | CWE-78 |
| PY017 | a file path (`open`, `pathlib`, `send_file`, …) | CWE-22 |
| PY018 | an XPath expression | CWE-643 |
| PY019 | an LDAP filter | CWE-90 |
| PY020 | a redirect | CWE-601 |
| PY021 | an HTML response | CWE-79 |
| PY022 | the session | CWE-501 |

PY023 (a cookie set with `secure=False`, CWE-614) and three Java rules — a
weak cipher (JV004), `java.util.Random` or `Math.random()` near a secret
(JV005) and `setSecure(false)` (JV006) — were added in the same phase and do
not need the walk.

### What the walk understands

- **Where request data comes from**: the request objects of Flask, Django and
  similar frameworks, and route parameters. A route parameter with a numeric
  converter (`<int:id>`) is a number, not text an attacker chose.
- **What makes it safe, and for what.** `html.escape` makes a value safe to
  put in HTML and does nothing for a file path. Each sanitiser is recorded
  against the kind of sink it protects, so escaping for one does not excuse
  another.
- **Checks**: `if name not in ALLOWED: abort(400)` makes `name` one of a known
  set afterwards. The fact is attached to the variable that was checked, not
  to where its value came from — two fields read from the same request body
  are two values, and checking one says nothing about the other.
- **Constants**: branches whose condition is known are not walked, so
  `if False:` hides nothing and a value chosen between two literals is known
  to be one of the two.
- **Lists, dictionaries and sets** element by element while they are small,
  and as one value once they are passed to something that could change them.
- **Functions in the same file**, three calls deep.
- **Loops** are walked until nothing changes, at most six times, and then
  everything assigned in the loop is treated as not known.

### Where it stops

Each of these is a decision to be less clever rather than wrong.

- **One file.** What a function in another module returns is *not known*, even
  when it was handed the request. Treating it as request data was tried, and
  withdrawn after it reported ordinary Django views.
- **Names that more than one function can change** — globals, `nonlocal`,
  module-level containers that are mutated — are never called clean.
- **Two names for one object** are tracked while the analyser can see both;
  past that, both are not known.
- **`try` blocks**: a handler may run after any statement of the block, so it
  sees every state the block passed through.
- **Dynamic features** — `getattr` by computed name, `exec`, decorators that
  replace a function, metaclasses — are not modelled. Values that pass through
  them come out as not known.
- **Frameworks it has no model of** contribute no request data, so the
  "only when request data reaches it" rules say nothing about them.
- **It is bounded**: 200,000 steps per file, 8 alternative values per
  variable, call depth 3. Past a bound, values become not known; they never
  become clean.
- **It cannot crash a scan.** If the walk fails on a file for any reason, the
  file is analysed as it was before Phase 16, by the local rules alone.

Analysing Python now takes about three times as long as it did. On Django
(5,661 files) a whole scan went from 17 to 30 seconds.

### Java, and the others

Still patterns. Two things changed: a Java statement wrapped over several
lines is now read as one (up to twelve lines), and the rule for SQL built by
concatenation was rewritten to find a literal that starts like a statement and
is joined to a value. The evaluation shows precisely what that is worth
without data flow: it finds 90 % of the injectable queries in the Java
benchmark and reports 89 % of the safe ones as well. It also still mistakes
`"<select id='" + name` in JavaScript for SQL. Both are recorded in the
evaluation rather than hidden.
