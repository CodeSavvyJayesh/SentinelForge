# Evaluation: how often is the analyser right?

Everything before Phase 16 was checked by asking "does the code do what it was
written to do". This document asks the question an examiner asks: **on code
whose answers are already known, how often is the analyser right, and how
often does it cry wolf?**

The short version, in the benchmark's own score (recall minus false positive
rate, from −100 to +100; reporting everything, reporting nothing and tossing a
coin all score 0), averaged over categories:

| Benchmark | Before | After, on test cases never looked at |
| --- | ---: | ---: |
| OWASP Benchmark for Python 0.1 | **+8.1** | **+88.0** |
| OWASP Benchmark for Java 1.2 | **+1.7** | **+33.5** |

"Before" is the analyser as it stood at the end of Phase 15, measured first and
changed afterwards. The rest of this document is how those four numbers were
obtained, what they do not show, and how to obtain them again.

## What was measured

Two public benchmarks from the OWASP Benchmark project. Each is a web
application made of small test cases; every test case contains exactly one
weakness of a named kind, or code that looks like it and is not; and an answer
key says which.

| | Java | Python |
| --- | --- | --- |
| Benchmark | OWASP Benchmark for Java, version 1.2 | OWASP Benchmark for Python, version 0.1 |
| Commit | `8b67a88d73b2594570fc21150705283de884620b` | `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` |
| Test cases | 2,740 (1,415 vulnerable, 1,325 safe) | 1,230 (452 vulnerable, 778 safe) |
| Categories | 11 | 14 |

Nothing in either benchmark is built or run. The test cases are read as text by
the same engine a scan uses, with no evaluation-only switch.

### How one test case is marked

This is the benchmark's own convention, not one invented here.

- A test case asks one question: *is there a weakness of this category in this
  file?* It is **reported** when the analyser produced at least one finding, in
  that test case's own source file, from a rule assigned to that category.
- Vulnerable and reported is a true positive; vulnerable and silent is a miss;
  safe and reported is a false alarm; safe and silent is correct.
- A finding of another kind in the file is not an answer to the question. It is
  counted and published beside the results and is in no figure.

Which rule answers which category is one table, `backend/app/evaluation/mapping.py`.
It was written before the first measurement, from the weakness each rule
already declared; rules added since were entered the same way.

### The figures

For each category: recall (share of vulnerable cases reported), false positive
rate (share of safe cases reported), precision, F1, and the **score** — recall
minus false positive rate. The score is the headline because it is the only one
that cannot be raised by reporting more: a scanner that flags every file has
100 % recall and a score of zero.

Every score is given with a 95 % interval (Wilson intervals for the two rates,
combined by Newcombe's method). When the interval contains zero the table says
the result is *not distinguishable from guessing*, whatever the number is.

A ratio with nothing underneath it is shown as a dash, never as zero: a scanner
that reported nothing has no precision, not a precision of 0 %.

The overall figure is the average over categories, each counting once. That is
the benchmark's convention, and it includes the categories the analyser has no
rule for, which score zero. A second figure leaves those out; it describes how
good the existing rules are and is not a substitute for the first.

## The procedure, and why it has this shape

A benchmark with the answers in the same repository is easy to score well on
dishonestly: change a rule, look at which test cases flipped, change it again.
After enough rounds the rules describe the benchmark rather than the weakness.
Four things were done to prevent that.

1. **Measured first, changed second.** The analyser was scored exactly as
   Phase 15 left it, and those results were committed before any rule changed
   (`results/baseline/`).
2. **Half the test cases were never looked at.** Each test case belongs to the
   *development* half or the *held-out* half according to a hash of its name —
   not its position, category or answer. Rules were studied and changed using
   the development half only. The split is pinned by a test.
3. **The held-out half was measured once**, after the analyser's source was
   committed, and nothing in the analyser has changed since. The results record
   a hash of the analyser's source (`79a0731a…`), so a later change is visible.
4. **Every change needed a reason that is not the benchmark's answer.** A rule
   was changed when it was wrong about what the code does — and each change was
   then checked on real projects that are not the benchmark (below).

## Results on the held-out half

### Python — 622 test cases (220 vulnerable, 402 safe)

| Category | Cases | Before: recall / false positives / score | After: recall / false positives / score | 95 % interval of the score |
| --- | ---: | --- | --- | --- |
| Command injection | 10 | 50.0 % / 100.0 % / −50.0 | 66.7 % / 25.0 % / +41.7 | −16.3 to +72.9 |
| Code injection | 27 | 100.0 % / 100.0 % / 0.0 | 100.0 % / 0.0 % / +100.0 | +66.7 to +100.0 |
| Deserialisation | 27 | 100.0 % / 36.8 % / +63.2 | 100.0 % / 10.5 % / +89.5 | +50.9 to +97.1 |
| Weak hash | 72 | 100.0 % / 0.0 % / +100.0 | 100.0 % / 0.0 % / +100.0 | +85.5 to +100.0 |
| LDAP injection | 16 | no rule | 87.5 % / 0.0 % / +87.5 | +40.1 to +97.8 |
| Path traversal | 69 | no rule | 93.3 % / 0.0 % / +93.3 | +76.2 to +98.2 |
| Open redirect | 19 | no rule | 100.0 % / 0.0 % / +100.0 | +57.1 to +100.0 |
| Insecure cookie | 18 | no rule | 100.0 % / 0.0 % / +100.0 | +54.0 to +100.0 |
| SQL injection | 12 | 0.0 % / 0.0 % / 0.0 | 100.0 % / 0.0 % / +100.0 | +41.2 to +100.0 |
| Trust boundary | 20 | no rule | 54.5 % / 0.0 % / +54.5 | +14.6 to +78.7 |
| Weak randomness | 176 | 0.0 % / 0.0 % / 0.0 | 100.0 % / 0.0 % / +100.0 | +92.2 to +100.0 |
| XPath injection | 95 | no rule | 76.9 % / 0.0 % / +76.9 | +57.2 to +89.0 |
| Cross-site scripting | 44 | no rule | 88.9 % / 0.0 % / +88.9 | +63.7 to +96.9 |
| XML external entities | 17 | 0.0 % / 0.0 % / 0.0 | 100.0 % / 0.0 % / +100.0 | +39.9 to +100.0 |
| **Average over categories** | | 25.0 % / 16.9 % / **+8.1** | 90.6 % / 2.5 % / **+88.0** | |

Counting every test case once: 202 true positives, 18 misses, 3 false alarms,
399 correct silences — recall 91.8 %, false positive rate 0.7 %, precision
98.5 %, F1 95.1 %.

Against the earlier analyser on the same 622 cases: 178 judged correctly that
were wrong before, none judged wrongly that were right before (exact McNemar
test, p = 5 × 10⁻⁵⁴).

Command injection has ten test cases in this half. Its interval runs from −16
to +73: with ten cases, +41.7 cannot be told apart from guessing, and the table
says so rather than claiming it.

### Java — 1,389 test cases (705 vulnerable, 684 safe)

| Category | Cases | Before: recall / false positives / score | After: recall / false positives / score | 95 % interval of the score |
| --- | ---: | --- | --- | --- |
| Command injection | 132 | 0.0 % / 0.0 % / 0.0 | 0.0 % / 0.0 % / 0.0 | −4.9 to +6.2 |
| Weak cipher | 122 | no rule | 100.0 % / 0.0 % / +100.0 | +91.6 to +100.0 |
| Weak hash | 131 | 18.7 % / 0.0 % / +18.7 | 68.0 % / 0.0 % / +68.0 | +55.1 to +77.5 |
| LDAP injection | 24 | no rule | no rule | |
| Path traversal | 144 | no rule | no rule | |
| Insecure cookie | 32 | no rule | 100.0 % / 0.0 % / +100.0 | +72.5 to +100.0 |
| SQL injection | 255 | 0.0 % / 0.0 % / 0.0 | 90.2 % / 89.3 % / +0.9 | −6.5 to +9.0 |
| Trust boundary | 69 | no rule | no rule | |
| Weak randomness | 239 | no rule | 100.0 % / 0.0 % / +100.0 | +95.5 to +100.0 |
| XPath injection | 13 | no rule | no rule | |
| Cross-site scripting | 228 | no rule | no rule | |
| **Average over categories** | | 1.7 % / 0.0 % / **+1.7** | 41.7 % / 8.1 % / **+33.5** | |

Counting every test case once: 359 true positives, 346 misses, 100 false
alarms, 584 correct silences — recall 50.9 %, false positive rate 14.6 %,
precision 78.2 %, F1 61.7 %. Against the earlier analyser: 345 fixed, 100
broken (p = 1 × 10⁻³²). Averaged over only the six categories that have a
rule, the score is +61.5.

Two rows in that table are the important ones.

**SQL injection: 90 % recall, 89 % false positives, score +0.9.** The rule now
finds a query built by concatenation — and it finds it in the safe test cases
too, because in those the query is built the same way from a value that
happens to be harmless. Telling the two apart needs to know where the value
came from, and for Java the analyser cannot. All 100 "broken" test cases in
the comparison are these. The rule is still right to report a concatenated
query; what the benchmark shows is that, for Java, it cannot say which ones
matter.

**Five categories have no rule and four of the rest are at zero for the same
reason.** Command injection, path traversal, LDAP, XPath, trust boundary and
cross-site scripting are all "does request data reach this call". Java is read
with patterns, and a pattern cannot follow a value. The Python figures above
are what following the value is worth.

### The development half, for comparison

The half the rules were studied on scores higher for Python, as it should: it
is the half they were fitted to.

| | Development | Held-out |
| --- | ---: | ---: |
| Python, average over categories | +94.1 | +88.0 |
| Java, average over categories | +33.5 | +33.5 |

The held-out column is the result. The development column is here so the gap
between them can be seen.

## What changed in the analyser

Described fully in `docs/security/analysis.md`. In one paragraph: Python files
are now walked statement by statement, and every argument of every call is
described as *request data*, *built only from literals*, or *not known*. Rules
for calls that are dangerous by nature stay silent when the argument is shown
to be literal; eight new rules report only when request data is shown to reach
the call. Java gained three pattern rules, reads statements that were wrapped
over several lines, and the rule for SQL built by concatenation was rewritten.

## Checked on code that is not the benchmark

A rule that only works on generated test cases is not a rule. Before the
held-out measurement, the old and the new analyser were both run over six real
projects and every finding that appeared or disappeared was read. There is no
answer key for these, so this is a reading, not a score.

| Project (commit) | Findings before → after | What changed |
| --- | --- | --- |
| WebGoat (`3284a8e466df`), Java, deliberately vulnerable | 43 → 64 | SQL injection 1 → 12: ten are the SQL-injection lessons themselves and `Servers.java`, one is a test payload. Ten weak-randomness findings, among them the password-reset link and the session id. |
| Juice Shop (`1618a611b173`), TypeScript, deliberately vulnerable | 222 → 227 | SQL injection 9 → 14: the product search in `routes/search.ts`, four copies of it kept as teaching material, and a test payload. One earlier false alarm, on a log message containing the word "update", went away. |
| PyGoat (`19d17cc88748`), Django, deliberately vulnerable | 20 → 28 | Two raw SQL queries built from the request, a parser with external entities enabled given the request body, a file opened by a name from the request, a three-digit OTP from `random`, three cookies with `secure=False`. |
| Vulnerable-Flask-App (`b6a4f97afd46`) | 15 → 17 | A query built from the request, and request data in a template string. |
| Flask (`d73fa1cdcbd8`), not vulnerable | 13 → 39 | All 26 new findings are in its tests: views written to echo a parameter back. Correct by the rule's definition, and not vulnerabilities in Flask. |
| Django (`a461af8ce487`), 5,661 files, not vulnerable | 235 → 270 | 32 of the new findings are in its tests. Outside them: a query handed to the Oracle cursor, a session write in the CSRF middleware, and **four false alarms** — two redirects in `views/i18n.py` that Django validates in a way the analyser cannot follow, and two lines of JavaScript where the word `select` is an HTML tag, not SQL. Three earlier findings went away, each correctly: a `git` command made only of literals, and two calls in tests that the earlier rule mistook for `eval`. |

The same reading found two things no test had: a version of the SQL pattern
that took **minutes** on WebGoat (rewritten; the whole project now takes about
three seconds), and a crash in the flow walk on a function that never returns
(fixed; the walk now cannot take a scan down with it). The analyser then ran
over about 5,600 Python files — the standard library, Django, Flask and PyGoat
— without an error.

Two of the false alarms above are the SQL rule's and are still there. It
reports a string that starts like a statement and is joined to a value, and
`"<select id='" + name` starts like one. Django's bundled admin scripts hold
four such lines; the earlier rule reported two of them and this one reports
all four. This was found after the held-out measurement, so it is recorded
rather than fixed: changing the rule now would mean measuring the held-out
half a second time.

## What these numbers do not show

- **The held-out half is not independent of the development half.** Both were
  written by the same generator from the same templates. The split shows the
  rules were not fitted to individual test cases; it does not show they work
  on code the generator would never write. The real-project reading above is
  the only evidence for that, and it has no answer key.
- **The benchmark is half vulnerable.** Precision of 98.5 % on a set where 35 %
  of files are vulnerable says little about precision on a repository where
  one file in a thousand is. The false positive rate is the figure that
  carries over; precision is not.
- **The Python benchmark is one framework.** Every test case is a Flask view.
  The analyser's idea of "request data" is Flask's and Django's request
  objects and route parameters; a framework it does not know contributes
  nothing it can follow.
- **The flow walk stays inside one file.** Some test cases read the request
  through a helper class in another file. The analyser treats what that helper
  returns as *not known*. That choice was made deliberately after reading
  Django, where assuming "anything given the request returns request data"
  reported views that were fine — and it costs recall on this benchmark: on
  the development half, most of the misses are these. (The held-out misses
  have not been read, and will not be.)
- **No other tool was run.** The OWASP project publishes scorecards for other
  analysers. None was reproduced here, so this document makes no comparison.
- **Nothing here measures the fixes.** Whether a proposed fix is correct is a
  different question; see `classifier.md` for the part of it that is measured.

## Things that went wrong, kept on the record

- **The first Python measurement was wrong.** The Python benchmark uses syntax
  from Python 3.12. Run under Python 3.11, the analyser could not parse 470 of
  its 1,230 files, skipped them silently, and reported a score of +0.8 as if it
  had read them. The command now refuses to mark a test case whose file could
  not be parsed, and every results file records the Python version. All
  Python figures here were produced with Python 3.13.
- **Six test cases were read before the split existed**, while working out the
  answer key's format: Java 00003, 00005, 00006, 00008, 00023 and Python
  00001. Three of them (Java 00003, 00005, 00008) fell in the held-out half.
  What was seen — a hash algorithm read from a properties file, a DES cipher,
  a stored-procedure call — is also in many development cases.
- **A choice was made that lowered the score.** With "anything derived from
  the request object is request data", the development half scored +95.9.
  That rule was withdrawn because of what it did on Django, which cost about
  nine points before other work recovered some of them.
- **Java's weak-hash rule still misses a third.** Those test cases read the
  algorithm's name from a properties file. The name is not in the Java file,
  and the analyser does not read one file to understand another.

## Reproducing it

On Windows, from the repository root, with the backend's virtual environment
active:

```powershell
.\scripts\evaluate.ps1
```

That downloads the two benchmarks at the commits above into a folder **next
to** the repository (`..\sentinelforge-benchmarks`; they are about 250 MB, and
they are kept outside so that a scan of this repository does not find several
thousand deliberately vulnerable files). Nothing in them is built or run. It
then marks the analyser against both — held-out half, development half, and
everything — and compares each of the six results with the one recorded here.
Every line ends in `REPRODUCED` or `DIFFERENT`.

By hand, for one result:

```powershell
git clone -c core.autocrlf=false https://github.com/OWASP-Benchmark/BenchmarkPython ..\sentinelforge-benchmarks\BenchmarkPython
git -C ..\sentinelforge-benchmarks\BenchmarkPython checkout f1291485808b66e20ddb6b01b10dc71b3df8c8ba
cd backend
python -m app.cli evaluate ..\..\sentinelforge-benchmarks\BenchmarkPython `
    --split held-out `
    --check ..\docs\evaluation\results\improved\owasp-python-held-out.json
```

`core.autocrlf=false` matters on Windows: the answer key is identified by its
hash, and git rewriting its line endings makes it a different file. (The test
cases themselves give the same results with either line ending; that was
checked.)

`--check` exits 0 when the run matches the record and 1 when it does not.
`--json`, `--markdown` and `--cases` write a new record; `--compare` takes the
`--cases` file of an earlier run and says how many test cases changed and
whether that is more than chance. Python 3.12 or newer is needed for the
Python benchmark. The command is described in
[the command-line document](../devsecops/command-line.md).

The script was written on Linux, where PowerShell was not available: its git
steps and its six comparisons were run there by hand, from an empty folder, and
all six reproduced. **The script itself has not been run.** Its first run on
Windows is its test.

## The recorded results

| Folder | What it is |
| --- | --- |
| `results/baseline/` | The analyser as Phase 15 left it, on every test case. Analyser source `4fb2833c…`. |
| `results/improved/` | The analyser as it is now: held-out half, development half, and all. Analyser source `79a0731a…`. |
| `results/classifier/` | Created by `scripts/train_patch_classifier.py` when it has been run. It does not exist yet: see [classifier.md](classifier.md). |

Each result is three files: `.json` (the counts, for `--check`), `.md` (the
table, for reading) and `-cases.csv` (every test case and how it was judged,
so any figure can be recounted without trusting the code that produced it).
None contains a time, so a results file that changes in version control means
a result changed.
