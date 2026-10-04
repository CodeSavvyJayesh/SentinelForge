# Phase 12 — Dashboard

**Status:** complete
**Branch:** `phase-12-dashboard`

Until now every screen was about one project. To answer "which of my
repositories is in the worst state" a user had to open each one and remember
the numbers. This phase adds the page that answers it: one screen across
everything the signed-in user has scanned.

It adds no table, no migration, no worker and no dependency. Everything on the
page is counted from rows the first eleven phases already write. That is the
point of doing it now rather than earlier — there was nothing real to show.

## What is on the page

| Section | What it shows | Where the number comes from |
| --- | --- | --- |
| Headline tiles | open findings, fixed findings, repositories, completed scans, projects | counts of the user's own rows |
| Open findings by severity | all five severities, zeros included | `findings.severity`, fixed ones excluded |
| Most common weaknesses | the six commonest CWEs among open findings | `findings.cwe_id` |
| Repositories, highest risk first | grade and score, open and fixed counts, one bar per scan, last scan | live risk aggregate + the score each scan recorded |
| Highest-risk findings | the eight worst findings across every repository, with the arithmetic | the Phase 9 scoring function |
| Proposed fixes | what happened to every fix that was asked for | `patches` and each patch's latest `patch_validations` row |

## What was built

| File | What it is |
| --- | --- |
| `backend/app/repositories/dashboard_repository.py` | five owner-scoped queries, whatever the number of repositories |
| `backend/app/services/dashboard_service.py` | turns those rows into the page: scoring, ranking, grouping, counting |
| `backend/app/schemas/dashboard.py`, `backend/app/api/v1/dashboard.py` | `GET /api/v1/dashboard` |
| `backend/tests/api/test_dashboard.py` | 16 tests |
| `frontend/src/types/dashboard.ts` | the response type, and the pure functions that turn it into rows |
| `frontend/src/services/dashboardService.ts` (+ test) | the request; 22 tests with the helpers |
| `frontend/src/pages/DashboardPage.tsx` | the page |
| `frontend/src/App.tsx`, `layouts/AppLayout.tsx` | the `/dashboard` route and its nav link |

Signing in still lands on Projects, and `/` still redirects there. The
dashboard is a new link, not a new front door: an account with nothing in it
would otherwise open on an empty page.

## Decisions

### Never scanned is not the same as clean

A repository with no completed scan has `score: null` and `grade: null`, and
the table says "Not scanned". It would have been less code to let it fall
through as `0 / A` — the aggregate of zero findings *is* zero — and it would
have made the page reward not scanning. A scanned repository with nothing in it
is a real `0 / A`, and sorts above one that was never looked at.

### The endpoint takes no id

This is the first read that crosses projects, so it is the first place one
forgotten join would show a user somebody else's findings. `GET /dashboard` has
no parameters: the only input is who is asking. Every query starts from
`projects.owner_id`, and the repository class has no method that accepts a list
of ids from its caller.

The patch query originally had two ownership filters, one on patches and one on
their validations. Mutation testing showed the second could be deleted without
any test noticing — correctly, because a validation was only ever looked up by a
patch that had already passed the first. A security check that cannot fail is
not a check, so the two queries became one join with one filter, and that one
is covered.

### The current score is live; the bars are history

Same split as the repository page. A finding's score rises with age, so the
current number is computed when the page is opened, and it equals what the
repository page shows — a test compares the two endpoints. The per-scan bars are
the score each scan stored when it finished. Scans that carry no score are
skipped rather than drawn at zero.

The bars share a fixed 0–100 scale rather than each row stretching to its own
tallest bar. In a table, the reader compares rows: a row of short bars has to
mean lower risk than a row of tall ones.

### A patch is counted once, by its latest check

A proposal that was rejected, then re-checked and passed, is one passed
proposal. Counting validation rows instead would report it as one of each, and
the number of "labelled examples" would exceed the number of patches. The
ordering is the one the patch endpoint uses, so the dashboard cannot say passed
while the patch's own page says rejected.

`labelled` is `passed + rejected`. A check that **could not run** — the stored
code had moved — is counted on its own and is never a label. It says nothing
about the change, and a classifier trained on it would be learning from noise.
This is the number the planned patch-outcome classifier is waiting on.

### One colour, with the number beside every bar

The app already has a severity colour scale, and red and green for pass and
fail. Both were checked with a colour-vision validator before being used as
chart fills, and both failed: LOW and INFO are too close to tell apart side by
side, and the red/green pair collapses for a deuteranopic reader. So every bar
is the same colour, the label says which row it is, and the count is printed at
the end. Nothing depends on colour or on hovering.

### Totals are sums of the rows beneath them

A repository's open count is computed as "not fixed", not taken from the risk
aggregate (which counts findings that score above zero). A test asserts that
the tile, the severity bars and the repository rows all add up to the same
number, because a dashboard whose total disagrees with its own table is not
believed again.

## Mutation testing: 33 claims, 33 covered

Each line was broken in turn and the suite run. Two survived the first pass:

| Survivor | What it showed | What changed |
| --- | --- | --- |
| ownership filter on validations | the filter was unreachable — see above | two queries became one |
| unscanned repositories sort last | the fixture's unscanned repository happened to sort last anyway | the fixture now has a scanned repository with score 0 created *after* it |

The second is the usual one: a test that passes for a reason other than the code
it is named after.

## Checked by running it

A browser run against the real API, real scans and the real validation worker
(31 checks):

- a new account sees an empty state and no numbers;
- a project with no code shows zero and says no scan has completed;
- an uploaded, unscanned repository reads "Not scanned";
- after a scan, open findings equals the number of findings on the project
  page, the five severity bars add up to it, and the risk score matches the
  repository page;
- after three proposals — one that passes, one that is rejected, one whose file
  then changes — the page reads 1 passed, 1 rejected, 1 could not be checked,
  "2 proposals have a verdict", and open findings has **not** moved;
- after the code is really fixed and re-scanned: one fewer open, one fixed, two
  bars, the second shorter;
- a second account sees none of it;
- no horizontal scroll at 1280 px or 390 px, no bar past its track, no console
  errors, and the secret in the scanned `.env` is nowhere in the page.

The first screenshot showed weakness labels cut off beside a wide, mostly empty
bar. No check had caught it. Long labels now sit on their own line above the
bar.

## Verification

| Check | Result |
| --- | --- |
| Backend tests | 799 passed |
| Backend tests with Windows line endings simulated | 799 passed |
| Ruff lint and format | clean |
| `alembic check` | no schema change |
| Frontend type-check (strict) | clean |
| Frontend tests | 120 passed |
| Mutation pass | 33 / 33 |
| Browser run | 31 / 31 |

ESLint could not be run in the build environment; `scripts/verify.ps1` runs it
on the development machine.

## Limitations, stated plainly

- **It reads every finding the user owns on each request** and scores them in
  memory. That keeps one scoring policy in one language and is exact; it is also
  linear in the number of findings. Fine for thousands, wrong for hundreds of
  thousands, where it would become SQL aggregation or a cache.
- **No date filter and no account-wide trend.** The only history is each
  repository's score per scan.
- **A finding links to its project, not to itself.** The project page has no
  per-finding address yet.
- **Weakness titles are the commonest finding title in the group**, not the
  CWE's official name; the knowledge base is not consulted for a count.
- **Nothing here is a measure of accuracy.** The pass rate is "of the proposals
  a re-scan could judge, how many it accepted" — on this user's code, with these
  rules. Precision and recall belong to the evaluation phase.

## What this unlocks

Reports (Phase 13) are this page, per project, in a form that can be handed to
someone. And `fixes.labelled` is now visible: once it reaches a hundred or so,
there is enough to train the patch-outcome classifier on.
