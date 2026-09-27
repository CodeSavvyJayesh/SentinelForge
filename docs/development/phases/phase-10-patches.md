# Phase 10 — Patch generation

**Status:** complete
**Branch:** `phase-10-patches`

The model now writes code. This is the phase where "do not trust the LLM alone"
stops being a slogan about paragraphs and starts being a claim about a diff
somebody might apply to their repository.

The short version: a patch is a **proposal**. It is generated, checked, stored
and shown. It is never applied, the finding it addresses does not change, the
risk score does not move, and the word "fixed" does not appear. Phase 11 earns
that word by applying the diff to a throwaway copy and re-scanning it.

## The decision the phase turns on

**The model never produces the diff.**

The obvious design is to ask for a unified diff and store what comes back. It
does not survive contact with a 7B model, and the reason is arithmetic: a diff
requires computing `@@ -12,7 +12,8 @@` from line counts. Models are bad at that,
and worse at it under a format constraint.

What makes it dangerous rather than merely annoying is the failure mode. A
malformed diff is caught by `git apply` and thrown away. A hunk header that is
off by one **applies cleanly to the wrong place**.

So the work is split by who is good at what:

| Step | Who does it |
| --- | --- |
| "rewrite this code so it isn't vulnerable" | the model |
| knowing which lines those were | `region.py` |
| assembling the patched file | `region.splice()` |
| computing the diff | `difflib.unified_diff` |

The diff is correct by construction, because nothing wrote a hunk header by
hand. The end-to-end test runs the result through `git apply --check` against
the real workspace files — the claim being tested is "a diff the developer's own
tools accept", not "a diff was produced".

## What was built

| File | What it is |
| --- | --- |
| `app/patching/region.py` | reads the finding's lines plus context, splices a replacement back in |
| `app/patching/diffing.py` | builds the diff; refuses proposals not worth showing |
| `app/llm/patch_prompt.py` | the prompt: a finding, a numbered region, passages, an explanation |
| `app/llm/patch_contract.py` | what a reply may be; strips fences, gutters and preambles |
| `app/models/patch.py` | the `patches` table, which is also the job queue |
| `app/repositories/patch_repository.py` | claim / requeue / ownership-scoped reads |
| `app/services/patch_service.py` | request (API) and run (worker) |
| `app/workers/patch_worker.py` | the third background worker |
| `app/workers/job_worker.py` | **the loop all three now share** — see below |
| `app/api/v1/patches.py`, `app/schemas/patch.py` | 202-and-poll, `validated: false` |
| `src/types/patch.ts`, `src/services/patchService.ts` | client mirror, diff classification |
| `src/components/FindingPatch.tsx` | the diff, the notice, and no Apply button |

## The rule of three came due

Phases 6 and 8 each wrote out a worker loop in full — claim, commit the claim,
run, commit, sleep — with a comment saying the duplication was deliberate until
a third case arrived and the shape was known rather than predicted.

This is the third case, so `JobWorker` now holds the loop and the three workers
are subclasses that say only what differs: which repository claims a row, which
service runs it, and what the log lines are called. `ScanWorker` and
`ExplanationWorker` kept their public API exactly (`recover_stale_scans()`,
`recover_stale_explanations()`, `build_llm_client()`, `wait_for()`), and their
57 existing tests passed unchanged after the rewrite — which is the only reason
to believe the extraction was behaviour-preserving.

The repositories stayed separate. What they share is a four-line SQL shape;
what differs is the model, the status enum and the give-up message. A base class
abstracting three lines of SQL behind two type parameters would be harder to
read than the duplication it removed.

## Refusing to patch code that has moved

The most dangerous outcome available in this phase is not a bad patch. It is a
patch that applies cleanly to the **wrong lines** — which is exactly what
happens if the file has been edited since the finding was recorded, because the
diff is generated against the file as it is now while the line numbers came from
a row written earlier.

So before the model is called, the finding's stored snippet is checked against
the region actually read. If it is not there, the job fails with *"the code has
changed since this finding was recorded, so a proposed change would edit the
wrong lines. Scan again first."* A test asserts that the model is **not called**
in that case, not merely that the job failed.

## Which proposals are thrown away

A model asked to fix SQL injection will sometimes delete the function, sometimes
rewrite the file's indentation, and sometimes return the code unchanged with a
comment saying it fixed it. All three look plausible in a JSON field.

- **Nothing changed** → refused. Showing somebody a fix that fixes nothing is
  worse than showing them a failure.
- **A rewrite** → refused above a size budget relative to what it replaced.
- **A net deletion** → refused. This is the important one: removing the
  vulnerable code makes the finding disappear on the next scan, so **Phase 11,
  whose whole method is re-scanning, would certify it as a success**. From the
  scanner's point of view a deletion and a repair are indistinguishable, so it
  has to be caught here. A *small* net removal is still allowed, because
  deleting `shell=True` is the correct fix for that finding.
- **Broken syntax** → refused, for Python, via `ast.parse` (which builds a tree
  and evaluates nothing — the same property Phase 5 relies on). For other
  languages this check does not run, and that is stated in the limitations
  rather than hidden.

## Two bugs the tests found

**The CRLF bug, found by a test written to document behaviour that did not
exist.** `splice()` carefully preserved the file's dominant line ending, with a
comment explaining that a model answering with `\n` must not convert a whole
CRLF file. The test for it failed. `Path.read_text()` performs universal-newline
translation, so by the time `splice` saw the file every `\r\n` was already `\n`
— the preservation logic was dead code, and the generated diff was against
content that did not match the bytes on disk. `git apply` would have rejected it
on exactly the Windows checkouts this project is developed on. Fixed by reading
with `newline=""`.

**Test fixtures that were wrong in an instructive way.** The first version of
the API tests had the fake model return only the two changed lines. Six tests
failed — correctly. The region shown to the model is the finding's line plus six
lines of context either side, so for a short file that is the whole file, and
replacing it with two lines is proposing to delete everything else. The deletion
check caught it. The fixtures were wrong; the code was right.

## Mutation testing: 40 controls, 40 killed

The usual pass — break each control, confirm a test fails, restore. Five
survived the first run, and four of the five were tests that could not fail:

| Survivor | Why it could not fail |
| --- | --- |
| "a small net removal is still allowed" | the fixture removed one line and added one, so it passed with the allowance set to **zero** |
| "gutters are only stripped when every line has one" | the fixture had *no* lines matching the gutter pattern, so `all` and `any` behaved identically |
| "refusing to propose without sources" | the mutation hit the wrong `raise` in a file with five |
| "never promoting past PROPOSED" | the mutation was a no-op I had written carelessly |

The first two are the interesting ones, and they are the same mistake made twice:
**a test that exercises the extreme case does not test the boundary.** A fixture
with no gutters proves nothing about a rule that says "only when *all* lines have
one"; it needs a fixture where *some* do. Both were rewritten with partial
fixtures, and both now die.

Replacing the no-op mutation produced two better ones, and they are the two that
matter most in this phase: adding `APPLIED` to the status enum (a test asserts
the vocabulary cannot express it), and making the service write the patched file
to disk (a test reads the file's bytes before and after). Both are killed.

That is now four phases in a row where mutation testing found something the
green suite could not. It keeps being worth the hour.

## Verification

| Check | Result |
| --- | --- |
| `ruff format` + `ruff check` | clean |
| Backend tests | **652 passed** (63 new) |
| `alembic upgrade` → `check` → `downgrade` → `upgrade` | clean; no drift |
| Mutation pass | **40/40 controls killed** |
| `git apply --check` on a generated diff | applies |
| `tsc --noEmit` | clean |
| Frontend tests | **83 passed** |

## What Phase 11 has to add

- apply the patch to a **copy**, never the workspace;
- re-scan the copy and compare findings before and after;
- treat "the finding disappeared" as necessary but **not sufficient** — the
  deletion check above is the reason;
- add `VALIDATED` / `REJECTED` to the status enum and let the API's `validated`
  field finally be read from data rather than hard-coded false.
