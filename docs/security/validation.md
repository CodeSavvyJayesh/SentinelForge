# Validating a proposed fix

Phase 10 produces a diff and calls it PROPOSED. This page is about the only
thing that can say more than that: **applying the diff to a throwaway copy of
the code and running the analyser again.**

It is also about why "the finding went away" is not the verdict.

## What a passed validation claims

Exactly this, and no more:

1. the finding the change was written for is no longer detected;
2. nothing is detected that was not there before;
3. the change replaces code with code — it is not a deletion;
4. the patched file still parses, where that can be known.

It does **not** claim the program still behaves the same. The convincing way to
establish that is to run the project's own tests, and that is ruled out on
purpose: those tests are code somebody uploaded, and this project has refused
to execute uploaded code since Phase 4. Validation is the analyser from Phase 5
run twice. Nothing is built, installed, imported or run.

The interface says "Checked by re-scan", never "fixed" or "safe", and repeats
the limit beside the verdict.

## A passed validation fixes nothing

The copy was patched. The repository was not. So after a PASSED validation the
file on disk is byte-for-byte the same, the finding is still open at the same
severity, and the risk score has not moved. Only a scan of the real code closes
a finding. A test asserts all three.

## Four ways a finding disappears without being fixed

A validator that asks only "is the original finding still there?" certifies
every one of these as a success.

| What the change does | Why the finding vanishes | What catches it |
| --- | --- | --- |
| Deletes the vulnerable code | there is nothing left to flag | `not_a_deletion` — net lines removed |
| Replaces it with `pass` or a comment | same, but one line out and one in, so a size check sees nothing | `not_a_deletion` — the added lines contain nothing that runs |
| Breaks the file's syntax | a Python file that does not parse yields **no AST findings at all**, so a typo "resolves" every finding in the file | `still_parses` |
| Rewords the weakness (MD5 → SHA-1) | the old text is gone; the same rule fires on the new text | `no_new_findings` |

The third is worth dwelling on, because it inverts intuition: the more broken
the patch, the cleaner the re-scan looks. The test for it asserts that the
re-scan reports **zero findings** and that the verdict is still a rejection.

## Comparing what a finding is, not its fingerprint

A stored fingerprint includes an occurrence number, so that two identical
vulnerable lines in one file are two findings rather than one. That is right for
storage and wrong for comparison: fix the first of the two and the second is
renumbered into the first's fingerprint. A fingerprint comparison then reports
the fixed finding as still present — a correct patch judged to have done
nothing.

The comparison therefore counts findings by rule, file and code, and requires
the count for the target to go down. Nothing else's count may go up.

## REJECTED and FAILED are different words

`REJECTED` is a verdict: the re-scan contradicts the change.

`FAILED` is not a verdict: the check could not be made. The code moved after
the proposal, the finding is no longer in the stored code, the file is not
UTF-8, the analysis hit its findings limit and a comparison would be partial.
None of these says anything about the patch, and the interface says so: *"Could
not be checked… This says nothing about the change itself."*

Keeping them apart matters twice over. A developer should not be told a patch
is bad because their workspace is stale. And the evaluation in Phase 16 will
count how often a model's fixes hold up — a count that is wrong the moment
"could not test it" is filed under "it failed".

## Applying a diff with no fuzz

`git apply` and `patch` are helpful. Given a hunk whose context no longer
matches, they search nearby for somewhere it fits. A hunk that has been slid is
a patch applied to code nobody reviewed.

The applier here has **no fuzz and no offset**: every context line and every
removed line must be exactly where the hunk header says, or the whole patch is
refused. It also:

- accepts a diff for **one file only**, and only the file the finding is in —
  whatever the diff's own header says;
- reads hunks by the line counts in their header rather than by sniffing
  prefixes, because a removed SQL comment `-- x` is the diff line `--- x`, which
  looks exactly like a file header;
- takes line endings and the final-newline convention from the file, not the
  diff, so a CRLF file stays CRLF.

It is written here rather than delegated to a `git` binary so that validation
does not depend on what is installed on the worker's PATH.

## The copy

- Made in the system temporary directory and removed when validation ends,
  including when it ends in an exception. A test checks the directory is gone.
- Contains exactly the files the analyser would read. Dependency folders,
  binaries and files over the analysis size limit cannot change a verdict,
  because no analysis opens them.
- Never follows a symbolic link, for the reason Phase 4 never extracts one.
- The stored workspace is only ever read. A test snapshots every file's bytes
  before and after.

## What this does not defend against

- **The analyser's blind spots.** A re-scan is only as good as the rules it
  re-runs. A change that rewrites a weakness into a form no rule recognises
  passes. This is not hypothetical: while building this phase, rewriting an
  f-string SQL query as `"…".format(user_id)` turned out to produce no finding
  at all, so that "fix" would have been validated. The rule meant to catch
  `.format()` had never matched a call on a literal. It is fixed and has a
  test; the lesson stands.
- **Behaviour.** A patch can pass every check and break the feature.
- **Languages without a parser here.** Only Python is parsed. For the rest,
  `still_parses` is reported as *skipped* — shown as "Not checked", never as
  passed.
- **A no-op that looks like code.** The "nothing that runs" check recognises
  blank lines, comments and bare no-ops. `return None` in place of a function
  body is code as far as it can tell.

Which is why, even after all of this, the patch is still not applied for you.
