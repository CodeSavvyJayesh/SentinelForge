"""Fixing a finding where the developer is: at a terminal or in an editor.

The web application proposes a fix through a queue, a database row and a
worker (Phases 10 and 11). None of that exists when somebody runs the scanner
on their own folder, so this package does the same work without it:

* :mod:`app.fixing.builtin` — fixes that need no model at all. A handful of
  rules have exactly one sensible rewrite (``verify=False`` becomes
  ``verify=True``), and asking a language model to make it would be slower,
  need a model, and could get it wrong.
* :mod:`app.fixing.local` — one finding in, one judged proposal out. It finds
  the finding by scanning, asks either the built-in rewriter or the local
  model for a change, and then does what this project has promised since its
  first page: applies the change to a throwaway copy and scans again.

A built-in fix is **not** exempt from that re-scan. "Mechanical" describes how
the change was produced, not whether it worked, and the only thing here allowed
to say a finding is gone is the analyser that found it.
"""
