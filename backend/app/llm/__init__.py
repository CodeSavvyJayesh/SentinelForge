"""The local language model, and the rules it is held to.

Phase 7 gave every finding real reference material. This package puts a model
behind that material so a developer gets an explanation of *their* code rather
than a rule description — while keeping the project's first principle intact:
**do not trust the LLM alone.**

Concretely, that principle is three design decisions rather than a slogan:

* the model is never asked for a verdict, only for an explanation of a verdict
  the analyser already reached;
* everything it returns is validated against a narrow contract, and its
  citations are checked against the passages it was actually given;
* when it is unavailable, the failure is reported rather than papered over.

Nothing here leaves the machine. Ollama runs locally and is reached over
loopback.
"""
