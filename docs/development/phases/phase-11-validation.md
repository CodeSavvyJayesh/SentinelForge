# Phase 11 — Patch validation

**Status:** complete
**Branch:** `phase-11-validation`

Since the first page, this project has said it re-validates every generated
patch before calling it anything. This is the phase where that sentence becomes
code: every proposal is applied to a throwaway copy of the repository and the
analyser is run again.

The short version of what was learned building it: **"the finding went away" is
the easiest thing in the world to achieve, and almost none of the ways of
achieving it are fixing the code.**

## What a verdict is

A proposal is checked automatically the moment it is generated. The check
produces one of three outcomes, and they are kept apart on purpose:

| Outcome | Means | Shown as |
| --- | --- | --- |
| `PASSED` | the re-scan supports the change | "Checked by re-scan" |
| `REJECTED` | the re-scan contradicts the change | "Rejected by re-scan" |
| `FAILED` | the check could not be made | "Could not be checked" |

`PASSED` requires all of:

1. **the target finding is gone**;
2. **nothing new is detected**;
3. **the change is not a deletion** — by size, and by substance;
4. **the patched file still parses** (Python; reported as *skipped* elsewhere).

Each check is stored with its outcome and a sentence of detail, and the
interface lists them under the verdict. A verdict never travels without its
evidence.

## What was built

| File | What it is |
| --- | --- |
| `app/patching/apply.py` | a strict unified-diff applier: no fuzz, no offset, one file |
| `app/patching/validation.py` | copy → scan → apply → scan → judge; no database |
| `app/models/patch_validation.py` | the `patch_validations` table, also a job queue |
| `app/repositories/patch_validation_repository.py` | claim / requeue / ownership-scoped reads |
| `app/services/patch_validation_service.py` | request (API) and run (worker) |
| `app/workers/validation_worker.py` | the fourth `JobWorker`, and the only one with no model |
| `app/api/v1/patches.py` | `POST /patches/{id}/validation`; `validated` now derived |
| `app/patching/diffing.py` | `check_substance`: refuses code replaced by a no-op |
| `src/components/FindingPatch.tsx` | the verdict, its checks, and "Check again" |

**A table, not two more enum values.** Phase 10's notes said this phase would
add `VALIDATED` and `REJECTED` to `patch_status`. It does not, and the reason is
what a verdict has to carry. A status column holds one word. A validation holds
every check that was made, the finding counts before and after, and what
appeared that was not there — and a patch can be validated more than once.
`validated` on the API is derived on every read from the latest validation, so
there is no stored flag to set by hand or to go stale.

## Four ways to make a finding disappear

Each of these makes the original finding vanish from the re-scan. Each has a
test where the finding is gone **and the verdict is still no**.

**Delete the code.** Caught by size in Phase 10 already.

**Replace it with `pass`, or a comment.** One line out, one line in: the size
check sees a net change of zero. This was a hole in Phase 10 — a model could
"fix" any one-line finding by commenting it out, and it would have been shown
to a developer as a one-line fix. `check_substance` now refuses a change whose
added lines contain nothing that runs, both before a proposal is shown and
again at validation, recounted from the diff itself.

**Break the syntax.** The instructive one. A Python file that does not parse
produces no AST findings at all — so a patch with a typo in it "resolves" the
finding it was written for and every other finding in the file. The re-scan
comes back *cleaner than a real fix would make it*. The test for this asserts
zero findings after the patch and a rejection anyway.

**Reword the weakness.** MD5 becomes SHA-1. The original finding's text no
longer exists, so it is gone; the same rule fires on the new text. Phase 10
cannot see this — the change is small, is not a deletion, and parses. It is the
first failure in this project that *only* a re-scan can catch, and it is the
reason the phase exists.

## The occurrence-number trap

A fingerprint includes an occurrence number so that two identical vulnerable
lines are two findings. Fix the first, and the second is renumbered into the
first's fingerprint. Compare fingerprints, and the fixed finding is "still
there" — a correct patch reported as having done nothing.

So the comparison counts findings by rule, file and code, and requires the
target's count to fall. This was caught at design time by asking what the
fingerprint was actually made of, and it has a test with two identical lines.

## A bug this phase found in Phase 5

While looking for a realistic rejected example, I rewrote an f-string SQL query
as `"SELECT … {}".format(user_id)` and expected the SQL rule to fire on it. It
did not. The analyser reported nothing.

The rule's own docstring listed `.format()` as covered. The implementation asked
whether the call's dotted name ended in `.format` — and a call on a string
literal has no dotted name, so the commonest way `.format()` is written had
never matched. The existing tests covered f-strings, `+` and `%`; nobody had
written the fourth.

It matters here more than it would have in Phase 5. A model asked to fix SQL
injection could return that exact rewrite, the re-scan would find nothing, and
the patch would be **validated** — still injectable, with a green banner above
it. The rule is fixed and tested, and the general point goes in the limitations
in plain words: *a re-scan is only as good as the rules it re-runs.*

## Could-not-check is not a rejection

If the stored code has moved since the proposal, the diff no longer applies.
That says nothing about the patch. It is recorded as `FAILED`, with an empty
check list and the reason, and the interface says "This says nothing about the
change itself."

The same goes for a validation interrupted by a crash, a file that is not
UTF-8, and an analysis that hit its findings limit (two partial lists cannot be
compared). The distinction is for the developer first, and for Phase 16 second:
a measurement of how often a model's fixes hold up is wrong the moment "could
not test it" is counted as "it failed".

## What validation never does

- **Execute anything.** It is the Phase 5 analyser, twice. A test plants
  `conftest.py`, `setup.py` and a test file that each write a marker when run,
  and asserts the marker never appears.
- **Write to the stored workspace.** The copy is patched; a test compares every
  byte of the original.
- **Leave the copy behind.** Including when it raises.
- **Touch the finding.** After a PASSED validation the finding is still open,
  still at its severity, and the risk score has not moved. The real code has not
  changed — only a copy did, and the copy is gone.

## Mutation testing: 46 controls, 46 killed

Three survived the first run:

| Survivor | Why |
| --- | --- |
| refusing a truncated *baseline* scan | the fixture truncated both scans, so the second check masked the first |
| knowing `//` is not a comment in Python | the fixture was `x = a // b`, which does not *start* with `//`, so the per-language rule was never exercised |
| reading the validation "fresh" (`populate_existing`) | **nothing needed it** |

The first two are the same mistake as last phase — a fixture that does not sit
on the boundary — and were rewritten. The third is different and I removed the
code rather than write a test for it: I had added a query option to guard
against a stale read I *expected*, with a comment asserting it was necessary,
and no test could tell whether it was there. A control nobody can show is
needed is a comment with side effects.

The Phase 10 pass was re-run afterwards: 51 of 53, the two absentees being
lines this phase deliberately replaced, each with a successor above.

## Checked by running it

The lesson of Phase 10 was that a green suite verifies the design, not that the
design is right. So before writing this report the application was run for
real, twice:

- **Against the live API and worker thread:** a real upload, a real scan, then
  four proposals through `POST /patches/{id}/validation` — a real fix (PASSED),
  MD5→SHA-1 (REJECTED: reworded), a parameterised query (PASSED), `pass`
  (REJECTED: nothing that runs). Workspace bytes unchanged, no temporary
  directories left, the finding still `NEW`.
- **In a browser:** three findings, three different verdicts on screen —
  "Checked by re-scan", "Rejected by re-scan", "Could not be checked" — 16 of 16
  assertions, including that the verdict sits above the diff, that no Apply
  button exists, and that no finding changed state.

The language model is not available in the build environment, so those
proposals were stored by a script standing in for it, through the same region,
re-indent, splice and diff code the patch service uses. The validation path —
the subject of this phase — was entirely real. What that run could **not**
exercise is a real model's output arriving at validation; that is the first
thing to try on the development machine.

The browser run also showed that every line of a diff had a box drawn round it
(the global `<code>` style applied to each line). Fixed.

## Verification

| Check | Result |
| --- | --- |
| `ruff format` + `ruff check` | clean |
| Backend tests | **766 passed** (94 new) |
| `alembic upgrade` → `check` → `downgrade` → `upgrade` | clean; no drift |
| Mutation pass | **46/46 controls killed** |
| Live API + worker run | 4 verdicts as expected, workspace untouched |
| Browser run | 16/16 |
| `tsc` | clean |
| Frontend tests | **96 passed** (13 new) |

## Limitations, stated plainly

- A passed validation inherits every blind spot of the analyser.
- It says nothing about behaviour; the project's tests are never run.
- Only Python is parsed. Elsewhere the syntax check is *skipped*, and shown so.
- "Nothing that runs" recognises blank lines, comments and bare no-ops — not
  `return None` where a function body used to be.
- A file that is not UTF-8 cannot be validated at all.

## What this unlocks

Every validation is a labelled example: a proposal, its features, and a verdict
that came from a re-scan rather than from anybody's opinion. `PASSED` and
`REJECTED` are labels; `FAILED` is deliberately not one. That is the dataset the
patch-outcome classifier needs, and it now accumulates on its own.
