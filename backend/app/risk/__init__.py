"""Deterministic risk scoring.

Phase 8 put a language model behind every finding. This phase deliberately does
not: a risk score has to be reproducible between runs, explainable to somebody
who disagrees with it, and stable enough to plot over time. A model gives none
of those, and a number nobody can argue with is a number nobody should act on.

So this is arithmetic — a small, reviewable policy of constants in
:mod:`app.risk.policy`, applied by pure functions in :mod:`app.risk.scoring`,
with every score returned alongside the factors that produced it.
"""
