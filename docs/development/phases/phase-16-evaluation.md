# Phase 16 — Research evaluation

**Status:** complete
**Branch:** `phase-16-evaluation`

Fifteen phases built a tool and tested that it does what it was written to do.
None of them answered the question a reader of the project report will ask
first: **is it any good at finding vulnerabilities?** This phase measures that,
on code whose answers are published — and then, because the first measurement
was poor, improves the analyser and measures again on test cases it was not
allowed to look at.

| OWASP Benchmark | Before | After (held-out half) |
| --- | ---: | ---: |
| Python 0.1 | +8.1 | **+88.0** |
| Java 1.2 | +1.7 | **+33.5** |

Score is recall minus false positive rate, averaged over categories: +100 is
perfect, 0 is what guessing scores. The full tables, the method and the limits
are in [docs/evaluation](../../evaluation/README.md). This document is about
what was built and what went wrong on the way.

## Part one: a measuring tool, and a bad first number

`python -m app.cli evaluate PATH` reads a benchmark's answer key, runs the
ordinary analyser over the benchmark, and marks each test case.

| Module (`backend/app/evaluation/`) | What it is |
| --- | --- |
| `benchmark.py` | reads the answer key; assigns each test case to a fixed half by a hash of its name |
| `mapping.py` | the one table saying which rule answers which benchmark category |
| `runner.py` | runs the analyser and marks each case; refuses if a case could not be read or parsed |
| `metrics.py` | recall, false positive rate, precision, F1, the score, Wilson and Newcombe intervals, exact McNemar test — standard library only |
| `compare.py` | this run against an earlier one, case by case |
| `render.py` | the results as JSON, a Markdown table and a per-case CSV, with no timestamps in them |

The first result: **Java +2.0, Python +8.6** over all test cases. The analyser
found weak hashes and little else; on Python command and code injection it
reported the safe cases as often as the vulnerable ones, which scores zero or
below. That was committed as the baseline before anything was changed.

### The first Python number was wrong, and looked fine

The very first run reported Python at **+0.8**. It was produced under Python
3.11; the benchmark uses 3.12 syntax; 470 of 1,230 files failed to parse, were
skipped without a word, and were marked "nothing found". Nothing looked
broken: there was a table, and the table had numbers in it.

Three changes came out of it: the engine now records which files it could not
parse, the evaluation refuses to mark a test case whose file was one of them,
and every results file records the Python version. A measuring tool that
silently measures something else is worse than none.

## Part two: why the score was low, and what was built

Reading the development half's misses gave one answer over and over: the
benchmark's question is *does request data reach this call*, and the analyser
could not ask it. A safe test case and a vulnerable one differ by where a
value came from, several lines above the call the rule looks at.

So Python got a flow analysis (`python_values.py`, `python_models.py`,
`python_flow.py`; about 2,500 lines). It walks each function without running
it and describes every value as **request data**, **clean** (built only from
literals) or **not known**. The existing rules for dangerous calls now stay
quiet when the argument is shown clean; eight new rules (PY016–PY023) cover
path traversal, XPath and LDAP injection, open redirect, reflected XSS, trust
boundary, shell-in-a-list and insecure cookies. What it models and where it
stops is in [the analysis document](../../security/analysis.md).

Java stayed pattern-based. It gained three rules (weak cipher, weak randomness
near a secret, `setSecure(false)`), reads statements wrapped over several
lines, and its SQL rule was rewritten.

### "Wrong clean" is the bug that matters

An analysis like this fails in two directions. Reporting something harmless is
a nuisance. Calling request data *clean* silences a rule that used to fire —
the new analyser would then be worse than the old one, invisibly. Most of the
work in this part was hunting that second kind, and each one found is pinned
by a test:

| What was wrong | What it would have hidden |
| --- | --- |
| A loop was walked once | a value that becomes request data on the second pass |
| A check on one field cleared every value read from the same request body | the unchecked field |
| Two names for one list were tracked separately | request data appended through the other name |
| A list passed to an unknown function was still "all literals" | whatever the function put in it |
| A module-level list mutated by another function was "clean" inside a closure | the mutation |
| `global` and `nonlocal` names kept their last local value | assignments made elsewhere |
| An exception handler saw only the state at the end of the `try` block | a value that was request data when the exception was raised |

The rule that came out of it: past any limit, and in any case the analysis is
not sure of, a value becomes *not known* — never *clean*.

### Real code changed the design

Before the held-out measurement, the old and new analysers were run over
WebGoat, Juice Shop, PyGoat, Vulnerable-Flask-App, Flask and Django, and every
finding that appeared or disappeared was read. That found:

- **A crash.** A function that never returns broke the walk. The walk is now
  wrapped so that any failure costs one file its flow analysis, not the scan.
- **An eight-fold slowdown**, brought down to about three by caching what
  following a function produced.
- **A pattern that took minutes on WebGoat** (catastrophic backtracking in the
  rewritten SQL rule). Rewritten as two bounded steps; three seconds.
- **False alarms on Django** from treating everything derived from the request
  object as request data. That assumption was withdrawn, which **lowered the
  development score from +95.9 to +86.9**; later work on other things brought
  it to +94.1. A rule that is right on a benchmark and wrong on Django is
  wrong.
- **False alarms on test code** that has a parameter named `request` (a pytest
  fixture). A `request` parameter is now a source only in a file that imports
  a web framework.

## Part three: the held-out measurement

The analyser was committed, its source hash recorded, and the held-out half
marked **once**. Nothing in `backend/app/analysis/` has changed since.

Python went from +8.1 to +88.0: 178 test cases judged correctly that had been
wrong, none the other way. Java went from +1.7 to +33.5: 345 fixed and 100
broken, all 100 in SQL injection, where the rewritten rule reports the safe
cases along with the vulnerable ones.

The Java result is the more instructive. Three categories are at +100 because
they are questions a pattern can answer — which algorithm, which class, which
flag. The rest are at or near zero because they are questions about where a
value came from. That is the same wall Python was at before this phase, and
the Python result is the measure of what is on the other side of it.

## Part four: the classifier

The project's own trained model: given a proposed fix, predict whether the
re-scan will support it. `backend/app/learning/` holds the features, a
logistic regression written in plain Python, grouped and repeated
cross-validation, two baselines and a report writer; two scripts collect data
and train. It is described in [classifier.md](../../evaluation/classifier.md).

**It has not been trained on real data and has no result.** That needs fixes
proposed and checked by the user's own installation, and the command refuses
to train on fewer than 60. The development database here held fixes written by
a stand-in for the language model; those are not outcomes of anything and
appear nowhere.

Two bugs were found by the tests while building it: gradient descent diverged
to `NaN` under a strong penalty (replaced by Newton's method with step
halving), and the AUC of a constant predictor came out as 0.494 instead of 0.5
when folds were pooled (now averaged per fold).

## Mutation testing: 239 claims, 239 covered

Two harnesses change one thing in the code at a time and require that some
test fails: 183 changes across the evaluation and the flow analysis, 56 across
the pattern rules. Every survivor was either given a test or turned out to be
code that did nothing, and that code was deleted — an interval clamp that
could never apply, a flag that was never read, several conditions that could
not be false.

## Verification

| Check | Result |
| --- | --- |
| Backend tests | 1,603 passed, three times: as is, with Windows path behaviour simulated, and with the database in another time zone |
| `ruff check`, `ruff format --check` | clean |
| `alembic check` | no schema change in this phase, none detected |
| Extension tests | 97 passed |
| The CI gate, exactly as the workflow runs it, on a clean copy | passed; the same single MEDIUM finding as before this phase |
| Recorded results | all six reproduced from freshly downloaded benchmarks with `--check` |
| Benchmark files with Windows line endings | development-half results unchanged |
| Analyser tests under Python 3.13 | 482 passed (see below) |

## Not verified

- **`scripts\evaluate.ps1` has not been run.** There was no PowerShell where
  it was written. Its git commands and its six comparisons were run by hand
  and reproduced; the script around them is untested until it runs on Windows.
- **The full test suite was not run under Python 3.13**, the version the
  project targets. It ran under 3.11; under 3.13 only the analyser's tests
  could be run there (482 pass; one could not start for want of a compiled
  dependency in that environment, not because of the code). The recorded
  results themselves were all produced with 3.13.
- **The classifier on real data** — see above.
- **No other analyser was run** on either benchmark, so nothing here says how
  SentinelForge compares with one.

## Limitations

- The held-out half comes from the same generator as the development half. It
  shows the rules were not fitted to individual test cases, not that they
  carry over to arbitrary code.
- The flow analysis is one file deep, Python only, and knows Flask's and
  Django's request objects.
- Java has no rule for five of eleven benchmark categories and cannot separate
  safe from vulnerable SQL.
- The SQL rule mistakes a JavaScript string that begins with `<select` or the
  word "select" for a statement. Found on Django's admin scripts after the
  held-out measurement, and left as it is rather than measure twice.
- Six test cases were read before the split was made; three are in the
  held-out half. They are listed in the evaluation.
- Python analysis is about three times slower than before.
- Findings change for repositories already scanned. After this phase a new
  scan of the same code will report some findings as fixed (the rule now sees
  the argument is a literal) and some as new. That is the rules changing, not
  the code.

## After merging

```powershell
.\scripts\verify.ps1                         # everything still passes
cd backend
python scripts\build_knowledge.py            # index the notes for the eleven new rules
cd ..
.\scripts\evaluate.ps1                       # optional: reproduce the recorded results
```

## What this unlocks

- A number to put in the project report, with its method and its limits, that
  anyone can reproduce with one command.
- A way to know whether the next rule change helps: `--compare` says how many
  test cases moved and whether that is more than chance.
- The obvious next piece of work, with its expected value already measured:
  data flow for Java.
- A classifier result, as soon as there are sixty checked fixes to train on.
