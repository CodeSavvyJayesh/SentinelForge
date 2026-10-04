# Phase 14 — DevSecOps integration

**Status:** complete
**Branch:** `phase-14-devsecops`

Until now SentinelForge scanned code when somebody clicked a button. This phase
makes it part of the build: a scanner that runs in a pipeline, a gate that can
fail it, a workflow that does so on every push, and a way to start the whole
project with one command.

It began with something else, though. A gate that fails builds makes false
positives expensive — a wrong CRITICAL now blocks someone's work — so the first
job was to find out how many there were.

## Part one: what a real project showed

OWASP WebGoat was cloned and scanned, and every credential finding was read.

| | Before | After |
| --- | --- | --- |
| Findings | 119 | 43 |
| Credential findings | 79 | 13 |
| "SQL injection" findings | 7 | 1 |
| Risk score | 99.5 (as the web application showed it) | 61.4 |

Seventy-six findings were wrong, in six distinct ways. Each got a fix and a test
that quotes the real case.

| What was reported | What it was | Fix |
| --- | --- | --- |
| 60 credentials in one file | `token: "keyword.operator"` — a syntax highlighter's token types | under the bare name `token`, a value with no digit and no uppercase letter is a word, not a secret |
| 6 SQL injections in jQuery | the word `select` and a `+` thirty thousand characters apart on one minified line | line patterns do not read lines over 1,000 characters |
| 2 private keys | `pem.replace("-----BEGIN PRIVATE KEY-----", "")` — code that *strips* the header | a key needs a base64 body after its header |
| 3 passwords | `password=Wachtwoord` — the Dutch label for a login field | message bundles skip the generic guess; known key formats still apply |
| 1 token | `append("Token: ").append(…)` — the quote ends a string, and code follows | a name inside an open string literal is not an assignment |
| bundled libraries ranked as the project's worst code | `libs/`, `*.min.js`, `wysihtml5-0.3.0.js` | recognised as vendored and discounted (risk policy v2) |

Scanning SentinelForge itself found four more in its own code — an error code
named `UNAUTHORIZED`, an event named `auth.token_refreshed`, a message constant,
a regex constant — and one thing that had been missed entirely:
`spring.datasource.password=…` did not match, because the name has dots in it.
That is how a Java application's database password is usually committed.

The thirteen credential findings left in WebGoat are real hard-coded values. It
is a deliberately vulnerable application; they are meant to be there.

These heuristics only ever *remove guesses*. The known-format rules — a GitHub
token, an AWS key, a private key block — do not consult them, and a test checks
that a real token in a message bundle or on a minified line is still found.

**The risk policy is now version 2.** The version is stored on every scan, so a
score from before this phase is visibly not comparable to one after it.

**One consequence to expect:** on the next scan of an existing repository, the
findings that were false positives will be recorded as *fixed*. The system
cannot tell "the rule changed" from "the code changed".

## Part two: the command-line scanner

`python -m app.cli scan PATH`. See
[the command-line scanner](../../devsecops/command-line.md) for how to use it.

| File | What it is |
| --- | --- |
| `backend/app/cli/main.py` | arguments, the printed summary, exit codes |
| `backend/app/cli/scan.py` | runs the analyser on a folder and builds a report with no database |
| `backend/app/cli/gate.py` | pass or fail, with reasons |
| `backend/app/cli/baseline.py` | reads fingerprints out of an earlier SARIF |
| `backend/app/analysis/credential_names.py` | the name heuristics, shared by both credential rules |
| `backend/tests/unit/test_cli.py` | 76 tests |

### One report builder

The scanner wraps the analyser's findings in the same model objects the web
application stores — never added to a session — and hands them to the Phase 13
report builder. A pipeline's report and the web application's report of the
same code are produced by the same function.

### Three exit codes

`0` passed, `1` the gate failed, `2` the scan could not be run. The third is
what makes the first two trustworthy, and it took a crash to get right — see
below.

### A baseline, so the gate can be adopted

Given the SARIF from an earlier run, only findings that are not in it can fail
the build. Without this, the only honest setting for a repository with existing
findings would be "off".

### What the scanned folder cannot do

It is untrusted input. Nothing in it is executed; links are not followed; git is
never invoked; and file names are sanitised before printing, because a file can
be *named* with a terminal escape sequence, or with a line break followed by
`::`, which a GitHub Actions runner reads as a command.

## A crash that only a clean checkout could show

Every test of the scanner passed, including one written specifically to prove
it never builds the application's settings. Then the CI step was run exactly as
written on a clean copy of the repository — no `.env`, no environment — and it
crashed on its first import.

`app/core/config.py` ended with `settings = get_settings()`. Importing anything
from that module, the `Settings` *class* included, built the settings, which
need a database URL and a signing key. The scanner imports the class.

Two things had hidden it:

- the in-process test ran after the module was already imported, so the import
  never happened again;
- every manual run was on a machine with a `.env` file, which the settings read
  by absolute path whatever the environment says.

And the crash exited **1** — the code for "the gate failed". In a pipeline it
would have looked like the scanner had found something.

Three changes:

1. `settings` is now built when first asked for, not when the module is loaded.
   The application still fails at startup if it is misconfigured.
2. `python -m app.cli` catches everything, imports included, and exits 2.
3. A test copies the application to a temporary folder and runs the real command
   in a fresh process with an empty environment. That is the test that would
   have caught it, and it now fails if the first change is reverted.

This is the same lesson as Phases 10, 11 and 12, one more time: the suite checks
that the design holds, and only running it where it will actually run checks
that the design is right.

## Part three: the workflow

`.github/workflows/ci.yml`, three jobs on every push to `main` and every pull
request:

- **Backend** — lint, format check, migrations, model/migration drift, tests,
  against a PostgreSQL service container.
- **Frontend** — ESLint, tests, type-check and build.
- **SentinelForge scan** — scans this repository with itself, fails on HIGH or
  worse, writes the report to the run summary, and uploads SARIF to code
  scanning.

No credential is written in the file. The throwaway database's password is
derived from the run number, and the signing key is generated in a step.

The workflow has `contents: read` only; the scan job alone adds
`security-events: write`.

The scan of this repository, as the workflow runs it, finds one thing: a MEDIUM
in the project's own code (`PY015`, the CWE catalogue is parsed with the
standard XML parser). It is left in, and reported. A security tool whose own
report is empty by construction would be less believable, not more.

## Part four: Docker Compose

`docker-compose.yml`, `backend/Dockerfile`, `frontend/Dockerfile`. See
[running with Docker](../../devsecops/docker.md).

- No default password or signing key: compose stops and names the missing one.
- Ports are published on `127.0.0.1` only; the database is not published.
- Both application containers run as non-root.
- `.env` files are excluded from both build contexts.

## Mutation testing: 67 claims, 67 covered

Five survived the first pass. Two were patterns the harness got wrong. Of the
three real ones:

| Survivor | What it showed | What changed |
| --- | --- | --- |
| code after a key header is not a body | no test had code *between* a header and something base64-shaped | a case that does |
| a long blocking list is cut short | the test checked for "and 4 more", not that only ten were listed | it counts them |
| an empty exclusion pattern excludes nothing | the check was unreachable: an empty pattern already matched nothing | the check was removed |

## Verification

| Check | Result |
| --- | --- |
| Backend tests | 1088 passed |
| Backend tests with Windows line endings simulated | 1088 passed |
| Backend tests with the database in `Asia/Kolkata` | 1088 passed |
| Ruff lint and format | clean |
| `alembic check` | no schema change |
| Mutation pass | 67 / 67 |
| The CI scan step, run as written on a clean copy | exit 0; 1 MEDIUM; 43 left out by `--exclude` |
| `docker compose config` | valid; refuses to start without the two secrets |
| Backend settings loaded with the compose environment | accepted; `production` without TLS refused, as designed |
| Browser run, Phase 12 | 31 / 31 |
| Browser run, Phase 13 | 35 / 35 on the second run; the first timed out on one step |

No frontend code changed in this phase.

## Not verified

Said plainly, because each of these is a claim somebody could reasonably assume
was checked:

- **No Docker image was built.** There is no Docker daemon where this was
  written. The Dockerfiles and the nginx configuration are untested.
- **The workflow has never run.** Its YAML parses and its scan step was executed
  by hand; the service container, the caches and the actions themselves were
  not.
- **SARIF has never been uploaded to GitHub.** The first workflow run is the
  first time GitHub's own parser sees it. The upload step is allowed to fail
  without failing the build.
- **Actions are pinned by major version** (`@v4`), not by commit hash. Pinning
  by hash is the stricter practice.
- **The Phase 13 browser run failed once** before passing. The failing step
  waits for an error message after a full page load on a server that had just
  started; it passed when repeated and nothing in that path changed in this
  phase. It is recorded rather than explained away.

## Limitations

- No per-finding suppression; see the command-line page.
- The name heuristics can hide a real credential: `token = "lowercaseonly"` is
  no longer reported. That is the trade this phase made, on the evidence of
  sixty wrong findings to none right, and it is a trade.
- Vendored code is discounted, not ignored: a CRITICAL in a bundled library is
  still CRITICAL, and still fails a `--fail-on high` gate unless excluded.
- The scanner installs with the whole backend's dependencies.

## What this unlocks

The scanner now runs anywhere a command can run. An editor extension (Phase 15)
is a thin layer over the same command and the same SARIF.
