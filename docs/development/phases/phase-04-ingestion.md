# Phase 4 — Repository ingestion: report

**Goal:** get real source code into SentinelForge — by upload or by Git clone —
without ever trusting it.

This is the first phase where the input is *code written by someone else*. A
project name is a string; an archive is a program's worth of structure, and
some archives are written specifically to attack the thing that opens them.

**Scope rule followed:** no analysis, no scanning, no vulnerability data. The
project page now says scanning arrives in Phase 6 and shows nothing simulated.

---

## 1. Summary

| | |
| --- | --- |
| Backend | 9 files added, 7 changed |
| Database | 1 migration (`def97007d9c9`): `repositories` |
| Endpoints | upload, git connect, list, get, delete |
| Backend tests | 121 new (228 total) |
| Frontend | repository panel on the project page; 14 new tests (51 total) |
| Docs | this report, `security/ingestion.md`, API conventions, architecture, `.env.example` |

New backend layout:

```
app/ingestion/
├── limits.py      the limits, and one error class per way input can be wrong
├── workspace.py   one isolated directory per repository, and nothing outside the root
├── archive.py     safe zip extraction
├── git_clone.py   URL validation (SSRF, schemes, argument injection) and a bounded clone
└── language.py    what is in the tree, by bytes
```

---

## 2. The one rule

> **Code that arrives here is data, never something to run.**

Nothing is executed. No build step, no `npm install`, no hooks, no submodules,
and every extracted file lands as `0644` — no execute bit, whatever the archive
claimed. That single sentence is what most of the code below is defending.

---

## 3. What an attacker can send

Full table in [security/ingestion.md](../../security/ingestion.md). The four
worth understanding properly:

### Zip slip

A zip entry is just a *name*, and nothing stops that name being
`../../etc/cron.d/backdoor`. `zipfile.extractall` will happily write it.
So entries are extracted one by one: separators are normalised, absolute paths
and Windows drive paths are refused, any `..` part is refused, and the resolved
path must still be inside the destination. Six shapes of this attack are tested,
and the test also asserts nothing appeared outside the folder.

### Zip bombs

42 KB can expand to petabytes. Two checks before writing (total declared size,
and compression ratio against the real file size on disk) **and** a byte counter
during writing — because the declared size comes from the archive, which is the
attacker's. The header is checked because it is cheap; the counter is there
because the header is a claim.

### SSRF

`https://169.254.169.254/latest/meta-data` is the cloud metadata service. A
server that clones any URL it is given is a server that will happily fetch its
own credentials for you. So the host is resolved and every address it maps to
must be public — private, loopback, link-local, reserved, multicast and
unspecified are all refused. `ALLOW_PRIVATE_GIT_HOSTS` exists for an internal
Git server, and defaults to off.

### git as an execution vector

`ext::sh -c 'id'` is a valid git URL that runs a command. A URL or branch
beginning with `-` is read by git as an *option*, and `--upload-pack=` names a
program to run. So: scheme allow-list, `protocol.ext.allow=never`,
`protocol.file.allow=never`, a leading-`-` guard on both URL and branch, `--`
before the operands, hooks disabled, submodules off, system and global config
ignored, and an environment containing almost nothing.

---

## 4. Design decisions worth defending

**Bytes, not file counts, decide the language.** Forty tiny JSON fixtures say
less about a codebase than one large Python module. And YAML, JSON, Markdown,
HTML and CSS are reported in the breakdown but can never be the *primary*
language — a repository is not "a YAML project" because its CI config is long.
A tree with no recognised source files reports `None`. Nothing is guessed,
because Phase 5 picks analysers from this value.

**A failure leaves a record.** A rejected archive leaves a `FAILED` row with a
message safe to show the owner, plus an audit entry holding the error *code* —
never the submitted bytes or URL. The workspace is deleted. The commit is
deliberate: the request ends in an error response, which would otherwise roll
the row back and make the attempt vanish.

**Relative workspace paths.** The database stores `project-7/repo-12-9f3a1c02`,
not `/srv/sentinelforge/workspaces/...`. The root is deployment configuration;
moving the disk should not require a data migration. `workspace_path` is never
returned by the API either — telling a client where uploads land is free
reconnaissance.

**Delete the row before the files.** If removing the directory fails, the user
is not left with a repository they cannot delete. An orphaned directory is a
cleanup problem; an undeletable row is a bug they have to live with.

**The wrapper folder is unwrapped.** GitHub's "Download ZIP" gives you
`flask-main/...`; without unwrapping, every analysed path in later phases would
carry a meaningless prefix.

**`.git`, `node_modules`, `venv`, `dist`, `build`, `target` and friends are
skipped**, so the file budget is spent on real code rather than a vendored
universe.

---

## 5. Data model

`repositories`, one row per ingested codebase:

| Column | Notes |
| --- | --- |
| `project_id` | → `projects.id`, `ON DELETE CASCADE`, indexed |
| `source` | `UPLOAD` or `GIT` |
| `status` | `PENDING` / `INGESTING` / `READY` / `FAILED` |
| `origin` | the Git URL, or the sanitised upload filename |
| `branch`, `commit_hash` | recorded so a scan can be reproduced |
| `workspace_path` | **relative** to `WORKSPACE_ROOT`; `NULL` after a failure |
| `file_count`, `total_bytes` | what was actually stored |
| `primary_language`, `language_breakdown` | bytes per language, biggest first |
| `error_message`, `ingested_at` | set on failure / success |

`PENDING` and `INGESTING` are unused today (ingestion is synchronous) but exist
now so Phase 6 can move this to a background worker without a migration.

The autogenerated migration needed **one hand-edit**: `drop_table` does not drop
a PostgreSQL enum type, so the generated downgrade left `repository_source`
behind and `upgrade → downgrade → upgrade` failed with "type already exists".
The two types are now created with `checkfirst` and dropped in the downgrade.
This is the same class of bug as Phase 2's enum column — autogenerate is a
starting point, not an answer.

---

## 6. Frontend

The project page gains a **Code** panel: two tabs (upload a zip / Git URL), and
a card per repository showing status, file count, size, detected language, a
language bar, branch and commit.

- A **failed** repository is shown as a card with its reason, not hidden. You
  can see that your upload was refused and why.
- The upload size is checked in the browser too — as a courtesy, because the
  server enforces it anyway and the browser cannot be trusted.
- Ingestion gets a 3-minute client timeout; reading and indexing a repository
  is not a 10-second request.
- The language bar is `aria-hidden` and the legend underneath carries the same
  information as text, so a screen reader hears it once, not twice.

---

## 7. Verification

| Check | Result |
| --- | --- |
| `pytest` — 228 tests (121 new) against real PostgreSQL | ✅ pass |
| `ruff check` / `ruff format --check` | ✅ pass |
| `alembic upgrade` → `check` → `downgrade` → `upgrade` | ✅ pass |
| Frontend type-check (strict), ESLint with your exact config, 51 tests | ✅ pass |
| Browser run against the real API — 19 checks | ✅ pass |

Two of the new tests run a **real git clone over HTTP** against git's own
`git-http-backend` started inside the test, so the command, the flags, the
sanitised environment and the shallow fetch are exercised for real rather than
mocked. One test starts a socket that accepts the connection and never answers,
and asserts the clone is killed at the timeout.

### Do the security tests bite?

Every control was deliberately broken, the suite re-run, and the control
restored:

| Control removed | Tests that fail |
| --- | --- |
| Zip-slip path check | 5 |
| Symlink refusal in archives | 1 |
| Zip-bomb ratio and size checks | 2 |
| File-count limit | 1 |
| Permission reset on extracted files | 1 |
| SSRF host check | 12 |
| Clone URL scheme allow-list | 2 |
| Argument-injection guard on the URL | 3 |
| Branch name validation | 7 |
| `core.symlinks=false` on clone | 1 |
| Workspace root containment | 4 |
| Ownership join on repositories | 2 |
| Upload size limit | 1 |
| Workspace cleanup after a failure | 1 |
| Symlinks not followed while summarising | 1 |

The first run of this exercise found **three controls that no test actually
covered** — the permission reset, the leading-dash guard and the symlink skip
during the walk all passed with the code removed, because the tests were hitting
a different check first. Those three tests were rewritten until they failed for
the right reason. A security test that passes with the protection removed is
decoration.

### The browser run (19 checks)

| Step | Result |
| --- | --- |
| Empty state before anything is connected | ✅ "No code connected yet" |
| Upload a zip with `node_modules` inside | ✅ Ready, 3 files, Python 81% / JavaScript 19% / Markdown 1% |
| `node_modules` excluded from the count | ✅ |
| Upload a **zip-slip** archive | ✅ "The archive contains a path that escapes the target folder" |
| Nothing escaped onto disk | ✅ |
| Upload a corrupt file | ✅ "The file is not a valid zip archive" |
| Clone `https://169.254.169.254/latest/meta-data` | ✅ "That host is on a private or local network and cannot be cloned" |
| Clone `file:///etc/passwd` | ✅ "Only https:// URLs can be cloned…" |
| Reload the page | ✅ repositories persist; failed attempts still listed |
| Phone width (390px) | ✅ no horizontal overflow |
| Remove a repository | ✅ row and workspace gone |
| A second account opens the same project URL | ✅ "This project does not exist, or it is not yours" |
| JavaScript console | ✅ no errors |

**Two bugs were found by the browser run and fixed**, neither of which any unit
test would have caught:

1. **A successful upload showed "An unexpected client error occurred."** The
   form called `event.currentTarget.reset()` *after* awaiting the upload, and by
   then React has detached the event, so `currentTarget` is `null`. The card
   appeared and an error appeared with it. Fixed by capturing the form element
   before the await.
2. **Signing in from `/login` landed on "Page not found."** The auth screen
   renders at any path while you are signed out, and after signing in the path
   stays — but `/login` is not a route once you are authenticated. This has been
   there since Phase 2 and was only visible because this run started at
   `/login`. Fixed with redirects for `/login` and `/register`.

---

## 8. Status

- **COMPLETED:** `repositories` table, zip upload with full archive hardening,
  git clone with URL validation and a sandboxed command, isolated workspaces,
  language detection, repository/service/API layers, failure recording and
  auditing, the Code panel, documentation.
- **REMAINING (yours):** `alembic upgrade head`, `pip install -r
  requirements.txt` (python-multipart is new), then `scripts\verify.ps1`;
  commit and push.
- **Deferred on purpose:** background ingestion (Phase 6 has the worker),
  `tar.gz` support (a second archive format is a second set of edge cases for
  no benefit), private repositories (needs stored credentials — belongs with
  the DevSecOps phase), re-ingesting a repository in place (delete and add
  is honest, and cheap, until scans reference a repository).

## 9. Next milestone — Phase 5: Static analysis engine

- Language-specific analysers chosen from the detected language
- An AST/rule pass over the ingested workspace, in a sandbox, with no execution
- Findings normalised into one shape (rule id, file, line, severity, evidence)
- CWE mapping, and the first real vulnerability records in the database

## 10. Study checklist

1. Why is `zipfile.extractall` unsafe, and what exactly does `safe_member_path` refuse?
2. Why is the expanded size checked twice — before and during extraction?
3. What is at `169.254.169.254`, and what would happen without the host check?
4. What does `ext::sh -c 'id'` do as a git URL, and which two things stop it?
5. Why do the URL and branch validators both reject a leading `-`?
6. Why does the language breakdown count bytes instead of files, and why can YAML never be primary?
7. Why is the workspace path stored relative, and never returned by the API?
8. Why does a failed ingest commit the transaction itself?
9. Which three controls turned out to be untested, and how were the tests fixed?
10. Why is the repository row deleted before its files, and not the other way round?
