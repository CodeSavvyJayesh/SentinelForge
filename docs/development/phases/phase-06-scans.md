# Phase 6 — Scan orchestration: report

**Goal:** stop analysis happening inside an HTTP request, and start keeping
history — so the question "what changed since last time?" has an answer.

**Scope rule followed:** no LLM, no risk scoring, no scheduling. A scan is
triggered by a person; cron and CI belong to the DevSecOps phase.

---

## 1. Summary

| | |
| --- | --- |
| Backend | 5 files added, 12 changed |
| Database | 1 migration (`a149a73f0c60`): `scans`, plus the finding lifecycle — **with a backfill** |
| Endpoints | queue a scan, scan history, poll one scan; findings gain a status filter |
| Backend tests | 43 new (392 total) |
| Frontend | scan history, live polling, NEW/OPEN/FIXED states; 3 new tests (59 total) |
| Docs | this report, API conventions, architecture, README, `.env.example` |

---

## 2. What was wrong with Phase 5

Two things, and they were the same thing twice:

1. **Analysis ran inside the request.** Click *Analyse*, the browser waits.
   A large repository held a connection open for the whole run.
2. **There was no record that a run happened.** Findings were deleted and
   re-inserted on every analysis, so a vulnerability you *fixed* simply
   vanished. "You fixed two things" was unsayable, and so was "this appeared
   yesterday".

---

## 3. The queue is the database

```sql
SELECT ... FROM scans
WHERE status = 'QUEUED' AND attempts < :max
ORDER BY created_at
FOR UPDATE SKIP LOCKED
LIMIT 1
```

`FOR UPDATE` locks the row so nobody else can take it. **`SKIP LOCKED`** is
what makes it a queue rather than a traffic jam: a second worker asking at the
same moment steps over the locked row instead of blocking behind it.

**Why not Celery and Redis.** Celery is the textbook answer and it needs a
broker — a second service to install, run, and keep alive on a laptop, in a
demo, and in a viva. PostgreSQL has had `SKIP LOCKED` since 9.5, the work is
already in a database we already run, and a queue in the same transaction as
the data cannot disagree with it. What this does *not* give is workers on other
machines; that is where Celery earns its keep, and it is written down as the
scale-out path rather than pretended away.

**The worker is a thread started with the app**, and `SCAN_WORKER_ENABLED=false`
turns it off so scans can be run from a separate process. The tests always run
with it off and drive the worker directly — a background thread racing the
assertions is how a suite becomes flaky.

### Crash safety

Each scan is one session and one transaction: claim → run → commit. A process
that dies mid-scan rolls back to `QUEUED`. At startup the worker sweeps for
scans left `RUNNING` by a dead process and requeues them, up to
`SCAN_MAX_ATTEMPTS`, after which the scan is marked `FAILED` rather than
retried forever.

Without that sweep, one power cut leaves a row that says `RUNNING` for eternity
and a repository that can never be scanned again — because the "already
running" check keeps refusing.

---

## 4. The finding lifecycle

A finding row now **survives across scans**, and the scan changes its status:

| Status | Meaning |
| --- | --- |
| `NEW` | the last scan is the first that saw it |
| `OPEN` | it was there before and is still there |
| `FIXED` | it was there before and this scan could not find it |

Three decisions inside that:

- **Fixed findings are kept, not deleted.** They are the evidence that work was
  done. They are excluded from the severity counts, though — a CRITICAL you
  fixed last week is not still a CRITICAL.
- **A finding that comes back counts as NEW again.** A reverted fix is a
  regression, and quietly calling it `OPEN` would hide that.
- **A failed scan changes nothing.** "We could not look" is not "the problem is
  gone" — marking everything `FIXED` because the workspace vanished would be
  the most dangerous bug in the phase. There is a test.

---

## 5. The migration keeps your data

Anyone who ran Phase 5 already has findings that belong to no scan. Deleting
them would have been the easy answer and the wrong one, so the migration mints
one `COMPLETED` scan per already-analysed repository — dated from
`repositories.analyzed_at` — and points those findings at it as `OPEN`.

Their history starts there rather than nowhere. `files_scanned` stays 0 on that
backfilled row because we genuinely do not know it, and inventing a number is
worse than admitting one.

(And, for the third phase running, the enum types needed hand-editing:
`drop_table` and `drop_column` leave a PostgreSQL enum behind, so the generated
downgrade broke the next upgrade. The round-trip test is what catches it.)

---

## 6. Two bugs found along the way

**A zip containing only `src/` lost its prefix.** Phase 4 unwraps a single
top-level directory, because GitHub's "Download ZIP" wraps everything in
`repo-main/`. But a project whose archive root contains only `app/` was being
unwrapped too, so every finding was reported at `main.py` — a path that does
not exist in the repository the developer is looking at. Common source
directory names are now left alone.

**The `.env` secret gap** (fixed as this phase's first commit). The generic
credential rule required the value to be *quoted*, which is how code is written
and not how `.env` files are written — and `.env` is where secrets actually
leak. `JWT_SECRET=<the real secret>` went undetected. The unquoted form is now
matched in configuration files only, because applying it to source code would
make `token = getToken()` a finding and every scan noise.

---

## 7. Frontend

The findings panel gains:

- **Scan / Scan again**, which returns immediately and then shows
  *"Waiting for a worker to pick this up…"* → *"The worker is analysing your
  code…"* → the result. The page polls; it does not sit on a request.
- **State chips** — New / Open / Fixed, with counts — alongside the severity
  chips.
- **Fixed findings struck through and dimmed**, still listed.
- **Scan history**: every run with its status, findings, new, fixed and
  duration. Each row keeps the numbers it found, not today's.

---

## 8. Verification

| Check | Result |
| --- | --- |
| `pytest` — 392 tests (43 new) against real PostgreSQL | ✅ pass |
| `ruff check` / `ruff format --check` | ✅ pass |
| `alembic upgrade` → `check` → `downgrade` → `upgrade` | ✅ pass |
| Frontend type-check (strict), ESLint (React Compiler rules), 59 tests | ✅ pass |
| Browser run against the real API, worker running for real — 16 checks | ✅ pass |

### Do the controls bite?

All nineteen were broken, the suite re-run, and each restored:

| Control removed | Tests that fail |
| --- | --- |
| `SKIP LOCKED` on the queue claim | 1 |
| Attempt limit on claiming | 1 |
| Oldest-first ordering | 1 |
| Stale scan recovery | 3 |
| Giving up after too many attempts | 1 |
| Refusing a second concurrent scan | 1 |
| Refusing to scan a repository with no code | 1 |
| Marking disappeared findings as fixed | 4 |
| A returning finding counting as new again | 1 |
| New findings counted on first sight | 2 |
| Fixed findings excluded from severity counts | 1 |
| Ownership join on scans | 1 |
| A crashed scan caught, not propagated | 1 |
| A crash message carrying no internal detail | 1 |
| A failed scan leaving findings untouched | 10 |
| Unquoted secrets only in env-style files | 3 |
| Placeholder prefixes for secrets | 4 |
| Commented-out lines not treated as secrets | 2 |
| A source directory not mistaken for a wrapper | 1 |

**Two of these passed with the control removed on the first attempt**, and both
are worth knowing about:

- The `SKIP LOCKED` test used the shared test transaction, so the queued row
  was never visible to the second connection — it returned `None` because there
  was nothing to see, not because it skipped a lock. It now uses two real
  connections with real commits, holds the lock open, and sets
  `lock_timeout = 2s` so that *blocking* fails the test instead of passing it
  slowly.
- The commented-out-secret test used an `.env` line, which the unquoted rule
  never matches anyway. It now includes `# password = "…"` in a `.py` file,
  which the quoted rule *would* match without the guard.

### The browser run (16 checks)

| Step | Result |
| --- | --- |
| Before any scan | ✅ "This code has not been scanned yet." |
| Queue a scan | ✅ returned in **77 ms**, button read "Queued…" |
| Worker finishes it | ✅ page updated on its own: "3 new, 0 fixed" |
| First scan | ✅ all three findings NEW |
| Scan again, code unchanged | ✅ "0 new, 0 fixed", chips read "Open 3" |
| Fix two issues on disk, scan again | ✅ "0 new, **2 fixed**" |
| Severity counts | ✅ CRITICAL disappears once fixed |
| Fixed findings | ✅ still listed, struck through, not deleted |
| Scan history | ✅ 3 rows, newest first, each keeping its own numbers |
| Phone width (390px) | ✅ no horizontal overflow |
| Console | ✅ no errors |

Reading the screenshot caught stale copy again — the project page still
promised that background scans "arrive in Phase 6".

The harness itself had two bugs worth recording, because both would have made a
green run meaningless: it used fixed `waitForTimeout` sleeps against a worker
running in another thread (a race dressed up as a test, now replaced by waiting
for the actual text), and it picked the *oldest* matching workspace on disk, so
it was editing a repository from a previous run.

---

## 9. Status

- **COMPLETED:** `scans` table doubling as the job queue, `SKIP LOCKED`
  claiming, background worker with crash recovery and attempt limits, the
  NEW/OPEN/FIXED lifecycle, scan history API and UI, live polling, the `.env`
  secret fix, the wrapper-directory fix, documentation.
- **REMAINING (yours):** `alembic upgrade head`, then `scripts\verify.ps1`;
  commit and push.
- **Deferred on purpose:** scheduled scans and CI triggers (DevSecOps phase),
  workers on other machines (needs Celery/Redis — documented, not pretended),
  per-finding suppression and baselines (they need a policy, not just a
  column), and cancelling a running scan (the analyser has no interrupt point
  yet, and a cancel button that does nothing is worse than none).

## 10. Next milestone — Phase 7: RAG (security knowledge)

- A local vector store of security knowledge: CWE descriptions, OWASP guidance,
  remediation patterns
- Retrieval keyed by a finding's rule and CWE, so the context handed to Phase
  8's model is *about the finding in front of it*
- Everything local — no knowledge base call leaves the machine

## 11. Study checklist

1. What does `SKIP LOCKED` do, and what would happen to a second worker without it?
2. Why is the queue a database table here instead of Redis — and when would that answer change?
3. What happens to a scan if the process dies half way through it?
4. Why is a scan limited to `SCAN_MAX_ATTEMPTS` rather than retried until it succeeds?
5. Why are fixed findings kept instead of deleted, and why are they excluded from the severity counts?
6. Why does a finding that reappears count as NEW rather than OPEN?
7. What must a *failed* scan never do to the existing findings, and why is that the most dangerous bug in this phase?
8. What did the Phase 5 migration leave behind, and how does this migration deal with it?
9. Why does queueing return 202 instead of 200?
10. Two controls passed with the protection removed — what was wrong with each test, and what does that tell you about testing concurrency?
