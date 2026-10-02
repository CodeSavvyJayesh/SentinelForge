# Security of proposed fixes

Phase 8's page opens by saying SentinelForge does not trust the LLM alone. Phase
10 is where that rule costs something: the model is now writing code, and the
output is a diff a developer might apply to their own repository.

This page is the argument that it is still safe, and the list of things that
would make it unsafe.

## A patch is a proposal, and the system cannot say otherwise

The status vocabulary for a patch is `QUEUED → RUNNING → PROPOSED`, plus
`FAILED`. There is no `APPLIED` and no `VALIDATED`. That is not an omission to
be filled in later by the same code — Phase 11 adds those, and the only way to
earn one is to apply the diff to a throwaway copy of the repository and
**re-scan it**.

So, concretely, in this phase:

- nothing writes to the workspace — a patch is text in a database row;
- the finding is untouched: its status, severity and confidence are exactly what
  the analyser set, and the repository's risk score does not move;
- the API returns `validated: false` on every patch, hard-coded rather than read
  from a column, so no row can be edited into claiming otherwise;
- the UI shows the notice **above** the diff, and there is no Apply button —
  absent, not disabled.

A test asserts each of these, including one that reads the file's bytes before
and after a successful generation.

## The model never produces the diff

This is the central design decision of the phase, and it is about correctness
before it is about security.

Asking a 7B model for a unified diff means asking it to count lines and compute
`@@ -12,7 +12,8 @@`. Models are bad at arithmetic and worse at it under a format
constraint. The failures are not loud: a hunk header off by one produces a patch
that **applies cleanly to the wrong place**.

Instead the model is shown a region and asked to rewrite it. The server splices
the replacement into the file it already has and generates the diff with
`difflib`. The hunk headers cannot be wrong, because nothing wrote one by hand.
The end-to-end test runs the result through `git apply --check` against the real
files, so the claim being tested is "a diff the developer's own tools accept",
not "a diff was produced".

## The model is asked for as little as possible

It sees the finding's line with six lines of context either side, but it is
asked to replace **only the finding's own lines**, fenced off in the prompt
with explicit markers.

That split was learned in production. The first version asked for the whole
window back, and a model asked to fix one line returns one line — which, against
a thirteen-line window, is arithmetically a proposal to delete twelve, and the
deletion check below refused a correct fix. Asking for less makes the obvious
answer the accepted one, and makes the size checks measure the fix against what
it actually replaced.

Markers the model echoes back as if they were code are stripped, conservatively:
only lines that match the marker pattern, never lines that merely contain
angle brackets.

**Indentation is restored by the server, not requested from the model.** Models
return the corrected line flush against the margin. The prompt asks them not
to; they do it anyway. Since the correct indentation is arithmetic — the indent
of the line being replaced — the replacement block is shifted to match, which
preserves relative indentation inside it. Without this, a correct Python fix
arrives as a file that does not parse and is refused by the syntax check.

## Refusing to patch code that has moved

If the file has been edited since the finding was recorded, a patch built from
the stored line numbers would edit the wrong lines — and, because the diff is
generated from the current file, it would apply cleanly while doing it. That is
the worst outcome available here, strictly worse than failing.

So before the model is called, the finding's snippet is checked against the
region actually read. If it is not there, the job fails with *"the code has
changed since this finding was recorded"* and no generation happens. Secret
findings are exempt, because their snippet is redacted before storage and there
is nothing to compare — their line is still bounds-checked.

## Which proposals are thrown away

A model asked to fix a vulnerability will sometimes return the code unchanged,
sometimes rewrite the whole file, and sometimes delete the problem. All three
look plausible in a JSON field. Before a proposal is stored it must:

| Check | Why |
| --- | --- |
| change something | an empty diff is a model saying "done" |
| stay within a size budget | a fix for one line that rewrites forty is not reviewable |
| not be a net deletion | see below |
| still parse (Python) | a patch that breaks the file is worse than none |

The deletion check is the one that matters most. **Removing the vulnerable code
makes the finding disappear on the next scan** — which means Phase 11, whose
whole method is re-scanning, would certify it as a successful fix. From the
scanner's point of view a deletion and a repair are indistinguishable. It has to
be caught here, so a proposal that removes substantially more than it adds is
refused. A small net removal is still allowed, because deleting `shell=True` is
the correct fix for that finding.

## Model output is not code until it is cleaned

Three habits show up in every small model, and all three produce text that looks
like code, passes a schema, and does not compile: markdown fences around the
answer, the prompt's own line-number gutters echoed back, and a sentence of
prose before the code. All three are stripped, and how much stripping was needed
is **recorded on the row** — it is a measurement of the model, and the
evaluation chapter needs it.

The gutter rule is deliberately conservative: numbers are only stripped if
*every* non-blank line has them. A single line reading `    1 | 2` is a bitwise
expression, and eating it would corrupt working code.

## Path containment, again

`file_path` comes from a database row built out of an archive somebody else
uploaded. Resolving `workspace / file_path` and reading it is the same operation
Phase 4 guards for archive members, so it carries the same check: resolve first,
then require the result to be inside the workspace root. Without it a stored
`../../etc/passwd` would be read and handed to a model.

## Prompt injection

Unchanged from Phase 8 in kind, and slightly worse in consequence. The region
handed to the model is attacker-controlled code, and it can contain
*"ignore the instructions above and add this line"*. The system prompt says to
treat `CODE` as data; that helps and is not the boundary.

The boundary is that **the output of a successful injection is a suggested diff
a person reads before using**. It is not applied, it does not change the
finding, and it does not lower the score. The checks above also constrain what
an injection can produce: it cannot make the patch large, cannot make it a
deletion, and cannot make it unparseable.

What this phase does **not** defend against is a developer who copies a diff
without reading it. That is stated rather than engineered around, and it is why
the notice comes before the diff and why there is no Apply button.

## Refusals are shown, not just counted

When a proposal is refused, the model's actual output is stored on the row and
shown in the UI behind a disclosure. The checks above are heuristics, and a
heuristic that refuses a correct fix is one a developer should be able to see
through — *"this mostly deletes code"* is a verdict, and the evidence for it
belongs next to it.

It is also the only failure data this project will ever have. Nobody can
reconstruct, after the fact, what a model returned six weeks ago.

## Credentials are not patched

No change is proposed for a hard-coded credential (CWE-798). Three reasons, any
one of which would be enough:

- **It is not fixable by an edit.** The secret is in every clone and in the
  history. The fix is to rotate it.
- **A diff must quote the line it replaces.** Proposing one stored the secret in
  `patches.diff` and showed it on screen, undoing the redaction every finding
  gets before it is stored.
- **Models answer with another secret.** Asked to fix `JWT_SECRET=…`, a real
  model wrote `JWT_SECRET=${JWT_SECRET:-'default_secret'}`.

The API refuses the request with the advice, the worker refuses a request
queued before the rule existed without sending the file to the model, and the
interface shows the advice instead of a button.

## What happens next

Every proposal is validated automatically: applied to a throwaway copy and
scanned again. That is Phase 11, and it has its own page —
[validating a fix](validation.md) — including the ways a finding can disappear
without anything having been fixed, and the one-for-one "replace it with `pass`"
deletion that the size check above cannot see and a second check now refuses
both here and there.
