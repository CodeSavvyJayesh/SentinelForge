# Phase 9 — Risk engine: report

**Goal:** turn eighteen findings into one number a reviewer can act on — and,
more importantly, argue with.

**Scope rule followed:** no model. This phase is arithmetic, deliberately, and
§2 is the argument for why.

---

## 1. Summary

| | |
| --- | --- |
| Backend | 5 files added, 5 changed |
| Database | 1 migration (`a6c5ed2d3245`): three nullable columns on `scans` |
| Endpoints | the current score with its working; risk over time |
| Backend tests | 37 new (589 total) |
| Frontend | a risk band above the findings list, with a *Show working* panel; 5 new tests (77 total) |
| New dependency | **none** |
| Docs | this report, README, API conventions |

---

## 2. Why this is not a model

Phase 8 put a local LLM behind every finding, and the obvious next move is to
ask it "how risky is this repository?". That would be a mistake, for three
reasons that are worth stating in order of how much they matter.

**A risk score has to be arguable.** Its entire job is to make somebody act on
one finding before another. A reviewer who disagrees with the ordering needs to
be able to point at *why* — "you're discounting test files too heavily" is a
conversation that improves the tool. "The model said 52" is not a conversation.

**It has to be reproducible.** The same findings must give the same score today
and next month, or the trend line is measuring the sampler rather than the code.

**It has to be stable across machines.** A score that depends on which model
somebody pulled is not a score, it is a local opinion.

So: a small file of constants, applied by pure functions, with every score
returned alongside the factors that produced it.

---

## 3. The policy is opinions, and it says so

Everything numeric lives in `app/risk/policy.py`, in one reviewable file,
because **these constants are a policy rather than a measurement**. Nothing here
was derived from incident data — this project has none. They encode defensible
opinions, gathered in one place precisely so that a disagreement is a
disagreement about numbers rather than about code.

| Input | Effect | Reasoning |
| --- | --- | --- |
| Severity | base 40 / 25 / 12 / 4 / 1 | Deliberately not linear: the gap between CRITICAL and HIGH is the gap between "stop" and "schedule it". |
| Confidence | × 1.0 / 0.8 / 0.6 | Risk is impact × likelihood, and confidence is the only honest proxy for likelihood this project has. |
| Path | × 0.4 test, 0.5 vendored, 0.6 example | Without taint analysis there is no reachability, so the heuristic uses the one signal available — and reduces rather than dismisses. |
| Age | up to × 1.25, capped at 90 days | An old open finding has survived review. Capped so a stale LOW never outranks a fresh CRITICAL. |
| Regression | × 1.15 | Phase 6 can tell a returning finding from a new one. A reverted fix says something a first sighting does not. |

The scale is 0–100 and is **not CVSS**. It is not derived from CVSS and does not
map onto it; calling it a CVSS score would be borrowing rigour this project has
not done the work for.

**Credentials are the exception to the path rule.** A hard-coded key in a test
fixture is a real key — it is exposed to everyone who can read the repository
and stays in git history after the line is deleted. The path heuristic asks "is
this code reachable", and that question does not apply, so `SEC*` findings get
no discount anywhere.

---

## 4. Aggregation: neither a sum nor a maximum

Findings are ranked worst-first and combined with geometric decay — the first
counts fully, the second at 0.6, the third at 0.36.

A **plain sum** would let a hundred INFO findings outrank one CRITICAL, which is
exactly how a scoring system teaches people to ignore it. Taking only the
**maximum** would say a repository with thirty CRITICALs is identical to one
with a single one. Both are wrong in ways a reviewer notices within a day of
using the tool, and the decay sits between them.

A pleasant accident falls out of the constants: with a CRITICAL base of 40 and a
decay of 0.6, an unlimited number of identical fresh findings converges to
exactly 40 / (1 − 0.6) = **100**. The scale is self-bounding for fresh findings,
and the explicit cap only bites once the age and regression factors push
individual scores above their base. §7 covers how that nearly went untested.

Grades exist because two digits invite false precision — 34 and 37 are not
meaningfully different, and a reader will treat them as if they were. The letter
belongs in a summary; the number is for ordering.

---

## 5. Two different claims, stored two different ways

**The live score is computed on demand.** A finding's score depends on how long
it has been open, so a stored value starts drifting the moment it is written,
and a nightly refresh job would be a scheduled way of being slightly wrong. The
arithmetic is microseconds over a few thousand rows.

**The scan snapshot is frozen.** When a scan completes it records the score,
grade and policy version it produced. That is a different claim — a historical
record of what one run concluded — and it has to be frozen precisely because the
live number moves. Phase 6's scan history becomes a risk trend for free.

`risk_policy_version` travels with every snapshot so a chart cannot silently mix
two scoring policies. Two scores from different policies are not two points on
the same line.

**There is no backfill.** Existing scans have no score and keep none. Computing
one now from today's findings would be a fabrication wearing a historical
timestamp; the chart starts where the scoring does, and scans without a score
are skipped rather than plotted as zero — which would invent an improvement
that never happened.

---

## 6. Frontend

A band above the findings list: the grade as a large letter, the score out of
100, what the grade means in words, the open-finding count, and the change since
the last scan (down is green — falling risk is the improvement).

Under it, a bar per scan, oldest on the left. **Deliberately bars, not a line**:
with a handful of scans at irregular intervals, a line implies a rate of change
between points that the data does not support.

*Show working* expands the arithmetic for the top five findings —
`40 base × 0.8 confidence × 0.4 test path × 1.06 age = 13.6` — with the reason
each factor applied. That panel is the phase.

---

## 7. Verification

| Check | Result |
| --- | --- |
| `pytest` — 589 tests (37 new) against real PostgreSQL | ✅ pass |
| `ruff check` / `ruff format --check` | ✅ pass |
| `alembic upgrade` → `check` → `downgrade` → `upgrade` | ✅ pass |
| Frontend type-check (strict), ESLint, 77 tests | ✅ pass |

### Do the controls bite?

Twenty-eight controls were broken one at a time. Twenty-five failed a test
immediately; three survived, and two of those were real gaps worth recording.

**The bound was untestable as written.** `test_the_score_is_bounded` threw 500
CRITICAL findings at the aggregate and asserted the result was ≤ 100. It passed
with the cap removed — because 500 fresh CRITICALs sum to *exactly* 100, as §4
explains. The test could not have failed. It now uses aged, regressed findings,
whose individual scores exceed their base and whose series genuinely overshoots,
so the cap is reached and removing it fails.

**Aggregation order was never exercised.** Every aggregation test built its
findings worst-first already, so deleting the sort changed nothing — while in
production, findings arrive in whatever order the database returns them, and an
unsorted aggregate would apply full weight to whichever finding happened to come
first. The new test hands them over worst-*last* and pins the exact total.

(The third survivor was a stale pattern in the mutation harness, not a gap.)

Both real survivors are the same mistake in different clothes: a test that
asserted the right property against an input that could not distinguish a
working control from a missing one. That is now three phases running, which is
less a coincidence than a warning about how mutation testing earns its keep.

---

## 8. Status

- **COMPLETED:** the policy file, scoring with per-factor explanations, path and
  age and regression handling, the credential exception, rank-decay aggregation,
  grades, the scan snapshot and migration, two endpoints, the UI band with its
  working and trend, documentation.
- **REMAINING (yours):** `alembic upgrade head`, `scripts\verify.ps1`, then open
  a repository and press *Show working*.
- **Deferred on purpose:** reachability analysis (that is taint tracking, a
  phase of its own and arguably a project of its own), per-project and
  per-account rollups (Phase 12's dashboard, where there is a screen to put them
  on), and suppressions or accepted-risk markers (they need a policy about who
  may accept what, not just a column).

## 9. Next milestone — Phase 10: patch generation

- The local model proposes a change for a finding, grounded in the Phase 7
  passages and the Phase 8 explanation
- Output is a **diff**, never a rewritten file, so the change is reviewable
- Nothing is applied. A generated patch is a proposal until Phase 11 re-scans
  and proves the finding is gone and nothing new appeared
- Which is the point the whole project has been building towards: this is where
  "never mark a patch secure without re-analysis" stops being a rule in a README
  and becomes a code path

## 10. Study checklist

1. Why is the risk score arithmetic rather than a model, given Phase 8 exists?
2. What does the policy file's existence as a *separate file* buy?
3. Why is the score neither a sum nor a maximum of its findings?
4. Why does a hard-coded credential get no path discount when a `yaml.load` does?
5. Why is the age factor capped?
6. Why is the live score computed on demand while the scan score is frozen?
7. What would go wrong if `risk_policy_version` were not stored?
8. Why are pre-Phase-9 scans skipped in the trend rather than plotted as zero?
9. Why bars rather than a line chart?
10. Two mutation survivors were tests that asserted the right property and still could not fail. What was wrong with each input?
