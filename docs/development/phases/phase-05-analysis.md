# Phase 5 — Static analysis: report

**Goal:** read the ingested code and say what is wrong with it. This is the
first phase that produces the thing the project is named after: real findings,
about real code, with real CWE references.

**Scope rule followed:** no LLM, no risk scoring, no patches. Analysis runs on
request, per repository. Scheduled and background scans are Phase 6, and the
project page says so rather than showing an empty scan history.

---

## 1. Summary

| | |
| --- | --- |
| Backend | 10 files added, 8 changed |
| Database | 1 migration (`a7be837ea618`): `findings`, plus `repositories.analyzed_at` |
| Rules | 32 across Python AST, patterns and secrets |
| Endpoints | analyse, list findings, get finding |
| Backend tests | 120 new (348 total) |
| Frontend | findings panel per repository; 5 new tests (56 total) |
| Docs | this report, `security/analysis.md`, API conventions, architecture, README |

```
app/analysis/
├── findings.py    what a finding is, and its fingerprint
├── rules.py       the catalogue: severity, confidence, CWE, OWASP — one place
├── python_ast.py  15 rules over a real syntax tree
├── patterns.py    12 rules for JS/TS, Java, PHP, Go, and SQL in any of them
├── secrets.py     5 rules, every one redacting before it stores
└── engine.py      walk, choose analysers, bound, collapse, number, sort
```

---

## 2. The one rule, continued

Phase 4's rule was "code is data, never something to run". Analysis keeps it:
`ast.parse` builds a syntax tree and imports, calls and evaluates nothing;
everything else is matched as text. No build, no dependency install, no test
run. That is why analysing a hostile repository in-process is safe.

---

## 3. Why an AST for Python

These are the same three lines to a regular expression:

```python
eval(config)          # a finding
# eval(config)        # a comment
"eval(config)"        # a string in a docstring warning against eval
```

A parser also knows what a regex cannot: that `shell=True` is a keyword
argument to *this* call; that `ElementTree` came from `xml.etree` and not
`defusedxml` (the analyser tracks imports for exactly this); and that a query
string was **built** rather than parameterised.

The other languages get regular expressions, with the cost admitted rather than
hidden: comments are stripped before matching, rules require the dangerous
*shape* rather than the function name alone, and they are capped at MEDIUM
confidence unless the pattern cannot mean anything else.

---

## 4. Severity and confidence are different questions

**Severity** is how bad it is if the finding is real. **Confidence** is how sure
we are that it is. A hardcoded AWS key is CRITICAL/HIGH; a string concatenated
into something that looks like SQL is CRITICAL/MEDIUM — serious if real, and we
are inferring that it is a query.

Collapsing them into one number is how scanners cry wolf, and a scanner people
mute finds nothing at all.

---

## 5. Every rule has a counterexample

Each rule has two tests: code that must trigger it, and realistic code that
must **not**. The second half is the one that keeps the tool usable.

| Rule | Fires on | Stays quiet on |
| --- | --- | --- |
| `eval` | `eval(payload)` | `eval("2 + 2")`, `model.evaluate(data)`, the word in a comment |
| SQL injection | `execute(f"SELECT … {user_id}")` | `execute("SELECT … %s", (user_id,))`, `runner.execute(f"job-{id}")` |
| Weak randomness | `session_token = random.choice(…)` | `colour = random.choice(["red", "green"])` |
| Hardcoded secret | `DB_PASSWORD = "sup3r-s3cret…"` | `os.environ[...]`, `"changeme"`, `"${DB_PASSWORD}"` |
| `innerHTML` | `el.innerHTML = comment` | `el.innerHTML = '<b>Loading…</b>'`, `el.textContent = comment` |
| XML | `xml.etree…parse` | `defusedxml…parse` |

The nastiest test case is **`backend/.env.example`** — a file whose whole job is
to document credentials. A scanner that reports it is a scanner that gets
muted, so there is a test asserting it produces nothing.

---

## 6. A finding about a leaked secret never leaks it again

The most important rule in the phase. A credential finding stores the file, the
line, and the *shape* of the value:

```
DB_PASSWORD = <redacted 27-character value>
AWS_ACCESS_KEY_ID=AKIA…<redacted 20 chars>
```

The value never reaches the database, the API, the audit log, the UI or a
report — all read by more people, and kept longer, than the file it came from.
Three tests enforce it, including a browser check that the planted secret
appears nowhere in the rendered page **or its HTML**.

---

## 7. Two engine bugs the tests caught

Both were found by tests that failed for the right reason, and both would have
been quiet, serious defects.

**Identical lines collapsed into one finding.** The fingerprint deliberately
excludes line numbers, so that adding an import at the top of a file does not
turn every finding below it into a "new" one. But that made `os.system(cmd)` on
line 10 and line 200 of the same file share an identity — the second one
silently vanished. Findings now carry an **occurrence counter**: stable under
code movement, still distinct per repeat.

**The same issue reported twice.** A hardcoded credential is found by the
Python AST rule *and* by the generic secret rule: same file, same line, same
CWE, two entries with different ids. The engine now collapses findings that
share (file, line, CWE) and keeps the stronger claim — higher severity, then
higher confidence. Different CWEs on one line are left alone, because a line
can genuinely be both an injection and a weak hash.

There was also a third, in my own regex: a negative lookahead defeated by
`\s*` matching zero characters, so `eval( "literal" )` was reported while
`eval("literal")` was not. That is why the pattern analyser now has a small
`refine` hook — the regex finds candidates, a function decides — instead of
growing more lookaheads.

---

## 8. Data model

`findings`, one row per claim:

| Column | Notes |
| --- | --- |
| `repository_id` | → `repositories.id`, `ON DELETE CASCADE`, indexed |
| `rule_id`, `analyzer` | which rule, and which analyser found it |
| `severity`, `confidence` | the two separate questions |
| `cwe_id`, `owasp_category` | CWE links out to MITRE in the UI |
| `file_path`, `line_start`, `line_end` | path is always relative to the repository |
| `snippet` | already redacted; stored as data, never interpreted |
| `fingerprint` | unique per repository (`uq_findings_repository_fingerprint`) |

Index `ix_findings_repository_severity` serves the only question the UI asks:
this repository's findings, worst first.

The migration needed the **same hand-edit as Phase 4** — `drop_table` does not
drop a PostgreSQL enum type, so the generated downgrade would have left
`finding_severity` behind and broken the next upgrade. Autogenerate is a
starting point, not an answer; the round-trip test is what catches it.

---

## 9. Frontend

Each READY repository gains a **Security findings** panel: an Analyse button,
a one-line run summary, severity filter chips with counts, and a list of
collapsible findings showing rule, confidence, CWE (linked to MITRE) and the
redacted snippet.

Three deliberate choices:

- **"Not analysed yet" and "no issues found" are different states**, and the UI
  never shows the second when it means the first.
- The empty state says *"These rules found nothing in this code. That is not a
  guarantee of security — it means these checks did not match."*
- Severity is carried by the **label text** as well as colour, and the filter
  counts always describe the whole repository, so filtering cannot make the
  numbers beside it lie.

---

## 10. Verification

| Check | Result |
| --- | --- |
| `pytest` — 348 tests (120 new) against real PostgreSQL | ✅ pass |
| `ruff check` / `ruff format --check` | ✅ pass |
| `alembic upgrade` → `check` → `downgrade` → `upgrade` | ✅ pass |
| Frontend type-check (strict), ESLint (React Compiler rules), 56 tests | ✅ pass |
| Browser run against the real API — 17 checks | ✅ pass |

### Do the controls bite?

Every one was deliberately broken, the suite re-run, and the control restored:

| Control removed | Tests that fail |
| --- | --- |
| Secret redaction (AST rule) | 2 |
| Secret redaction (secret scanner) | 2 |
| Placeholder filtering for secrets | 2 |
| `eval` literal check (Python) | 1 |
| `eval` literal check (patterns) | 1 |
| SQL keyword check before reporting injection | 1 |
| Comment stripping before pattern matching | 1 |
| Environment-reference check for secrets | 1 |
| Language scoping of pattern rules | 1 |
| Binary file skip | 1 |
| File size cap | 1 |
| Finding cap | 1 |
| Occurrence numbering for repeated lines | 2 |
| Collapsing one issue found by two analysers | 2 |
| Symlink skip while walking | 1 |
| Unparsable files counted, not guessed at | 2 |
| Ownership join on findings | 1 |
| Re-analysis replacing instead of appending | 1 |
| Refusing to analyse a repository with no code | 1 |
| Refusing to analyse a missing workspace | 1 |

Twenty for twenty on the first pass this time — Phase 4's exercise found three
untested controls, and writing the counterexample tests first is what changed.

### The browser run (17 checks)

| Step | Result |
| --- | --- |
| Panel before any analysis | ✅ "This code has not been analysed yet." |
| Analyse a deliberately vulnerable repository | ✅ 6 findings, "Scanned 3 files" |
| Planted SQL injection | ✅ reported at `app/main.py:10` |
| Command injection, `shell=True`, weak hash, `innerHTML` | ✅ all reported |
| Ordering | ✅ CRITICAL first |
| Finding detail | ✅ rule, confidence, CWE-89 linked to MITRE |
| **The planted secret** | ✅ appears nowhere in the page text or its HTML |
| Severity filter | ✅ narrows the list; counts stay whole-repository |
| Re-analyse | ✅ 6 → 6, no duplicates |
| A clean repository | ✅ "No issues found", with the honest caveat |
| Phone width (390px) | ✅ no horizontal overflow |
| JavaScript console | ✅ no errors |

One stale line of copy was caught by reading the screenshot: the project page
still said "nothing is analysed yet", which stopped being true this phase.

---

## 11. Status

- **COMPLETED:** analysis package (AST, patterns, secrets), 32 rules with CWE
  and OWASP mapping, redaction, fingerprints with occurrence numbering,
  bounded engine, `findings` table, analyse/list/get endpoints, findings panel,
  documentation.
- **REMAINING (yours):** `alembic upgrade head`, then `scripts\verify.ps1`;
  commit and push.
- **Deferred on purpose:** data-flow (taint) analysis — the rules are local and
  say "this call is dangerous", not "user input reaches it"; third-party
  scanner adapters (Semgrep, Bandit, SonarQube), which the normalised `Finding`
  shape is designed to accept later; suppressions and baselines, which belong
  with scan history in Phase 6.

## 12. Next milestone — Phase 6: Scan orchestration

- A `scans` table: history, status, and what changed since the last run
- Background execution, so a large repository does not hold a request open
- Findings linked to the scan that produced them, with first-seen / fixed state
- Progress in the UI, and a scan history you can compare

## 13. Study checklist

1. Why does Python get a parser while JavaScript gets regular expressions, and what does that cost?
2. What is the difference between severity and confidence, and why keep them separate?
3. Why does every rule need a test for code it must *not* report?
4. Why is `backend/.env.example` the most important test case in the suite?
5. What exactly is stored when the analyser finds a hardcoded password, and what is not?
6. Why does the fingerprint exclude line numbers — and what broke when it did only that?
7. When two analysers report the same line, which one survives and why?
8. Why is "0 findings" refused for a repository whose workspace is missing?
9. Why does the severity filter not change the counts shown on the filter chips?
10. Which twenty controls were broken to check the tests, and why is a passing security test with the control removed worthless?
