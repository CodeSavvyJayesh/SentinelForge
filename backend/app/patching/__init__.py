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
