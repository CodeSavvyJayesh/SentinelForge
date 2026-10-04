# The command-line scanner and the quality gate

The web application needs a database, an account and somebody to click. A build
pipeline has none of those. `python -m app.cli` runs the same analyser over a
folder, builds the same report, and turns the result into an exit code.

It needs **no database and no configuration**, opens no network connection, and
never executes anything in the folder it scans.

## Running it

From the `backend` folder, with the backend's dependencies installed
(`pip install -r requirements.txt`):

```bash
python -m app.cli scan PATH
```

```text
SentinelForge 0.1.0: payments
  42 files analysed, 3 findings, risk 54.5/100 (grade D)
  1 critical, 1 high, 1 medium, 0 low, 0 info

  CRITICAL PY010   app/main.py:7  SQL query built by string formatting
  HIGH     PY003   app/main.py:6  os.system() or os.popen()
  MEDIUM   PY007   app/main.py:8  Weak hash algorithm (MD5 or SHA-1)

FAILED
  2 findings at HIGH severity or above.
    CRITICAL PY010 app/main.py:7
    HIGH PY003 app/main.py:6
```

## Exit codes

There are three, and they never mean two things.

| Code | Meaning | Whose problem |
| --- | --- | --- |
| `0` | the scan ran and the gate passed | — |
| `1` | the scan ran and the gate failed | the code |
| `2` | the scan could not be run as asked | the invocation |

A missing folder, an unreadable baseline, a report that cannot be written, a
bad argument and a crash inside the scanner are all `2`. That distinction is
the point: a pipeline that cannot tell 1 from 2 either blocks a merge because of
a typo in its own configuration, or lets one through because the scanner fell
over.

## The gate

| Option | Effect |
| --- | --- |
| `--fail-on SEVERITY` | fail when a finding at this severity or worse is present. `critical`, `high` (the default), `medium`, `low`, `info`, or `none` |
| `--max-score N` | also fail when the repository's risk score (0–100) is above `N` |
| `--baseline FILE.sarif` | only findings that are **not** in this earlier SARIF can fail the build |
| `--exclude PATTERN` | leave out findings under a path or glob. Repeatable |

Every reason for failing is printed as a sentence, followed by the findings
that caused it.

### Adopting it on a repository that already has findings

A gate that fails on everything is switched off within a week. The baseline is
how to avoid that:

```bash
# once, on the main branch: record what is already there
python -m app.cli scan . --fail-on none --sarif baseline.sarif

# on every change: fail only on what the change added
python -m app.cli scan . --baseline baseline.sarif --sarif current.sarif
```

The build now asks "did this change make things worse?", which a team can keep
green, instead of "is this repository perfect?", which it cannot.

Findings are matched by fingerprint — the rule, the file and the code, not the
line number — so adding an import at the top of a file does not turn everything
below it into a new finding. In the SARIF, every result carries
`baselineState: new` or `unchanged`.

A baseline that cannot be read is an error (exit 2). It is never treated as
empty, which would make every existing finding "new", and never as complete,
which would wave everything through.

### Exclusions are printed

`--exclude tests` drops findings under `tests/`; `--exclude "*.min.js"` drops
them by glob. The number left out is printed in every run:

```text
  43 left out by --exclude
```

An exclusion nobody can see is how a gate is quietly emptied. This one cannot
be: excluding everything still passes, and still says so.

## Reports

`--sarif`, `--markdown`, `--html` and `--json` each take a file and can be
combined; all four are written from the one scan. They are the same documents
the web application produces (see [reports](../security/reports.md)).

On GitHub Actions, `--markdown "$GITHUB_STEP_SUMMARY"` puts the report on the
run's summary page.

## What a scanned repository cannot do

The folder being scanned is untrusted. The scanner reads it; it does not trust
it.

- **Nothing is executed.** No build, no test, no hook, no script. A test puts
  six kinds of auto-run file in a folder and checks none of them ran.
- **Links out of the folder are not followed.**
- **File names cannot write to the log.** A file can be named with a terminal
  escape sequence in it, or with a line break followed by `::` — which a GitHub
  Actions runner reads as a command. Every control and formatting character,
  line breaks included, is replaced with `?` before anything is printed.
- **Git is not asked anything.** The branch and commit come from the
  environment variables GitHub Actions sets. Asking git would mean running a
  program inside a folder this tool was told not to trust.
- **Secrets are redacted before they are printed or written**, exactly as in
  the web application.

## In GitHub Actions

`.github/workflows/ci.yml` has three jobs: the backend checks, the frontend
checks, and a scan of this repository by itself. The scan job:

```yaml
- name: Scan this repository
  working-directory: backend
  run: >-
    python -m app.cli scan ..
    --fail-on high
    --exclude backend/tests
    --exclude docs
    --sarif ../sentinelforge.sarif
    --markdown "$GITHUB_STEP_SUMMARY"

- name: Upload findings to code scanning
  if: always() && hashFiles('sentinelforge.sarif') != ''
  continue-on-error: true
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sentinelforge.sarif
    category: sentinelforge
```

`backend/tests` and `docs` are excluded on purpose: the tests are full of
deliberately vulnerable code and invented credentials, because that is what the
analyser is tested on.

The upload runs even when the gate failed — a failed build is exactly when the
findings need to be visible — and is allowed to fail on its own, because code
scanning is not available for every repository.

## Marking the analyser against a benchmark

A second command answers a different question: not "what is in this code" but
"how often is the analyser right". It needs a benchmark — a folder of test
cases with a published answer key — and nothing else.

```bash
python -m app.cli evaluate PATH [--split all|development|held-out]
```

```text
SentinelForge 0.1.0 against OWASP Benchmark for Python 0.1
  622 test cases (held-out): 220 vulnerable, 402 safe; 2535 files analysed in 3.2 s

  category         cases   TP   FN   FP   TN   recall  FP rate precision       F1  score  reading
  cmdi                10    4    2    1    3   66.7 %   25.0 %    80.0 %   72.7 %  +41.7  not distinguishable from guessing
  codeinj             27   10    0    0   17  100.0 %    0.0 %   100.0 %  100.0 % +100.0  better than guessing
  ...
```

| Option | What it does |
| --- | --- |
| `--expected CSV` | the answer key, when it is not the `expectedresults-*.csv` in the folder |
| `--split` | mark every test case, or one fixed half of them |
| `--json FILE`, `--markdown FILE`, `--cases FILE` | record the result: the counts, the table, and every test case with its verdict |
| `--compare CSV` | a `--cases` file from an earlier run: how many test cases changed, and whether that is more than chance |
| `--check JSON` | a `--json` file from an earlier run: exit 1 unless this run reproduces it |

Exit codes follow the same rule as the scanner's: `0` the benchmark was marked
(and, with `--check`, matches the record), `1` `--check` found a different
result, `2` it could not be marked.

It refuses rather than guesses. A test case whose file is missing, cannot be
read, or **cannot be parsed by this Python** stops the run with exit code 2: a
skipped file would be counted as "nothing found" and be indistinguishable from
a correct silence. The Python benchmark needs Python 3.12 or newer for that
reason.

Like the scanner, it reads the folder and executes nothing in it. The method,
the recorded results and what they do not show are in
[the evaluation](../evaluation/README.md).

## Limitations

- **No per-finding suppression.** There is no "ignore this line" comment. The
  ways to leave something out are a path exclusion and a baseline.
- **A scan that hit the finding limit still gets a verdict.** It is announced
  as incomplete; it does not fail by itself.
- **It installs with the whole backend's dependencies.** There is no separate,
  smaller package for the scanner yet.
