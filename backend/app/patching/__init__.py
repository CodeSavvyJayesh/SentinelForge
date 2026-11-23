"""Proposing code changes, without ever writing one.

Phase 8 explained a finding. This phase proposes a fix for it — as a diff a
person reads, not as an edit to their files. Nothing here writes to a
workspace, and a proposal's status says `PROPOSED` until Phase 11 applies it to
a throwaway copy, re-scans, and proves the finding is gone and nothing new
appeared.

The design decision worth knowing is in :mod:`app.patching.region`: the model
is never asked to produce a diff. It is asked to rewrite a region of code, and
the diff is computed from before and after — so hunk headers cannot be wrong,
because nothing wrote one by hand.
"""

# Said wherever a fix is refused for a credential: by the web application, by
# the command line and by the editor. One wording, because it is one fact.
CREDENTIAL_MESSAGE = (
    "A leaked credential cannot be fixed by editing the file: it is already in every copy "
    "of the repository and in its history. Rotate it, remove it from the code, and load the "
    "new one from the environment or a secret manager."
)

# Temperature for a second attempt. The first runs at the configured default
# (0), because a reproducible answer is worth having. But at 0 the model is
# deterministic, so retrying a failure returns the identical failure — and a
# "Try again" button that cannot produce anything new is a lie told by the
# interface. A retry therefore asks a slightly different question.
RETRY_TEMPERATURE = 0.3

__all__ = ["CREDENTIAL_MESSAGE", "RETRY_TEMPERATURE"]
