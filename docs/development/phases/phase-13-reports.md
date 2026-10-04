# Phase 13 — Reports

**Status:** complete
**Branch:** `phase-13-reports`

The dashboard answers "how are my repositories doing" for the person signed in.
A report answers it for someone who is not: a reviewer, a team lead, a CI job.
This phase turns one repository's state into a document that can be saved,
printed, pasted into an issue, or read by another tool.

## What a report contains

| Section | Source |
| --- | --- |
| Repository, branch, commit, last scan | the repository and its latest completed scan |
| Risk grade and score | the Phase 9 scoring, computed at request time |
| Open findings by severity | `findings`, fixed ones excluded |
| What to fix, by rule | this project's own per-rule notes (`app/knowledge/rule_notes.py`) |
| Each open finding | location, rule, CWE, OWASP, confidence, redacted snippet, the score's arithmetic, and where its fix stands |
| Fixed findings | findings gone from the last scan |
| What this report does not claim | fixed text, in every format |

It contains no model output. See [security/reports.md](../../security/reports.md)
for why.

## Four formats, one report

| Format | For |
| --- | --- |
| HTML | reading, printing, saving as PDF from the browser |
| Markdown | pasting into an issue, a pull request or a README |
| SARIF 2.1.0 | GitHub code scanning and other static-analysis consumers |
| JSON | the same report as data |

`app/reports/model.py` builds one frozen `Report`. Each renderer is a pure
function from that object to a string. Nothing is computed twice, so the formats
cannot disagree about a count or a score — a test renders all four from one
object and compares them.

## What was built

| File | What it is |
| --- | --- |
| `backend/app/reports/model.py` | the report as data; fix states; the fixed limitations text |
| `backend/app/reports/markdown.py` | Markdown, with prose and code escaped differently |
| `backend/app/reports/html.py` | one self-contained, script-free, printable page |
| `backend/app/reports/sarif.py` | SARIF 2.1.0 |
| `backend/app/repositories/report_repository.py` | each finding's latest patch and its latest check |
| `backend/app/services/report_service.py` | ownership, building, exporting, the audit record, the filename |
| `backend/app/api/v1/reports.py`, `schemas/report.py` | three endpoints |
| `backend/tests/unit/test_reports.py` | 80 tests, mostly hostile input |
| `backend/tests/api/test_reports.py` | 25 tests |
| `frontend/src/pages/ReportPage.tsx` | preview and downloads |
| `frontend/src/services/reportService.ts`, `types/report.ts`, `utils/download.ts` | the request, the formats, saving a file |
| `docs/security/reports.md` | what a report can do to its reader, and what it claims |

No migration: the audit action is a new value in a text column.

## Decisions

### An unscanned repository has no report

The endpoint answers 409 rather than a report with zero findings. The dashboard
made the same choice for the same reason, and it matters more here: this
document is forwarded to people who cannot see that no scan ever ran.

### Reports are not stored

A report is generated on request from the current rows. Storing one would create
a second version of the truth that is out of date after the next scan. What is
stored is the fact that one was taken.

### The fix state follows the latest check of the latest patch

Nine states, from `none` to `not_judged`. The same rule as the patch page and
the dashboard, so the three cannot disagree. `passed` is worded as "passed the
re-scan on a throwaway copy. It has not been applied to the code", and a check
that could not run is never called a rejection. A credential is always "rotate",
whatever rows exist. A fixed finding carries no advice about fixing it.

### SARIF's two conventions are named as conventions

SARIF has three levels and this project has five severities, so CRITICAL and
HIGH are both `error`. And `security-severity` — the number GitHub uses to sort
results — is on CVSS's scale, so it looks like a CVSS score and is not one. Each
value is simply a number inside the band that reproduces this project's own
severity on GitHub's side. The module says so at the top.

Only open findings are SARIF results. A fixed finding is not a result of the
current code.

### PDF is the browser's job

A PDF library would be a new dependency whose only job is to redraw a page the
browser already draws. The HTML report has print styles, and "Save as PDF" in
the print dialog is the PDF export. The browser run prints one to check.

### An export is audited; a read is not

`GET …/report/export` writes one audit row and commits it — a GET that writes,
which is unusual enough that a test asserts the commit. `GET …/report` (the data)
is an ordinary read, like the findings list.

## A bug this phase found in Phase 6

The browser run's last step went back from the report to the project page, and
the repository that had just been scanned said **"This code has not been scanned
yet"**.

The scan service has always stored `analyzed_at` on the repository. The API's
repository response never included it. The page reads that field to decide
whether there are findings to load, so within one visit everything worked — the
page sets it itself when a scan finishes — and on every later visit a scanned
repository looked unscanned until it was scanned again.

One line in `RepositoryRead`, and a test that reads the field through the API
before and after a scan. The existing test checked the database row, which was
always right.

It was found by a check written for something else, on the way back from the
feature being tested. No unit test was ever going to: each layer was correct on
its own terms.

## Mutation testing: 80 claims, 80 covered

Seven survived the first pass. Each was a test passing for a reason other than
the code it was named after:

| Survivor | Why it survived | What changed |
| --- | --- | --- |
| findings sorted by risk | severity order gave the same answer | a CRITICAL in test code now ranks below a HIGH in application code |
| ties fall back to file and line | id order gave the same answer | ids no longer follow the expected order |
| a rule's worst severity | the first member was also the worst | a group whose highest-scoring member is not its most severe |
| message escaped for line start | no message began with a list marker | one that begins `1.` |
| quotes escaped in HTML | nothing untrusted is in an attribute | the escape function is tested directly |
| a fixed finding's path escaped | pattern mismatch in the harness | harness corrected |
| patches scoped to the repository | unobservable through the API | the query is tested directly |

Two of those are worth a sentence. Quote-escaping is unobservable today because
no untrusted value is written into an attribute — it is kept, and tested, so
that the day one is, it is already safe. And the repository scope on the patch
query cannot leak anything even when removed, because patches are looked up by
this repository's own findings; the filter is about not reading other people's
rows into memory, which only a direct test can see.

## Checked by running it

A browser run against the real API, a real scan and the real validation worker
(35 checks). The uploaded code contains a credential and a line with
`<script>` in a comment; the project is named `Report <b>Demo</b>`.

- no Report link before a scan; one after;
- the preview frame has an empty `sandbox`;
- the project name and the `<script>` line appear as text, no `<b>` or
  `<script>` element exists, and nothing ran in the frame or the page;
- the score equals the repository page's; every open finding is listed;
- one fix reads as passed and not applied, one as rejected, one as could not be
  checked; the credential is told to rotate;
- all four formats download with the expected names; the SARIF has one result
  per open finding; none of the files contains the secret;
- the saved HTML file opens from disk, makes zero network requests, and prints
  to a PDF;
- another account gets "Repository not found";
- back on the project page — and after a full reload — the repository still
  shows its findings (the bug above).

The Phase 12 browser run was repeated afterwards and still passes.

## Verification

| Check | Result |
| --- | --- |
| Backend tests | 905 passed |
| Backend tests with Windows line endings simulated | 905 passed |
| Backend tests with the database in `Asia/Kolkata` | 905 passed |
| Ruff lint and format | clean |
| `alembic check` | no schema change |
| Frontend type-check (strict) | clean |
| Frontend tests | 131 passed |
| Mutation pass | 80 / 80 |
| Browser run (Phase 13) | 35 / 35 |
| Browser run (Phase 12, repeated) | 31 / 31 |

ESLint could not be run in the build environment; `scripts/verify.ps1` runs it
on the development machine.

## Limitations, stated plainly

- **The SARIF has not been validated against the official schema file**, and has
  not been uploaded to GitHub code scanning. Its structure is asserted by tests
  written from the specification. Uploading one is the first thing the CI phase
  does, and that is the real test.
- **No PDF file is produced by the server.** Print the HTML report.
- **Reports are per repository.** There is no project-level or account-level
  report.
- **A report describes the last completed scan and the current findings.** There
  is no report "as of" an earlier scan.
- **Timestamps are UTC**, and say so. They are not localised.
- **A very large repository gives a very long report.** Nothing is paginated or
  summarised away; a scan stopped at the finding limit is announced at the top.
- **The remediation notes are this project's own**, one per rule. They are
  reviewed like code and are not a standard.

## What this unlocks

SARIF is the format CI systems read. Phase 14 can run a scan in a pipeline and
hand its result to GitHub code scanning without inventing anything new.
