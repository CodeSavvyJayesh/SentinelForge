"""A model trained on this project's own data: will a proposed fix pass its check?

Every other model in the project was trained by someone else. This one is
trained here, on rows this application wrote: each fix the language model
proposed, and whether re-scanning the patched code supported it (PASSED) or
contradicted it (REJECTED). A fix that could not be judged is not an example
of either and is left out.

The package is small on purpose, and has no dependency the project did not
already have:

* :mod:`features` — what is known about a proposal before it is checked.
* :mod:`logistic` — logistic regression, written out in plain Python.
* :mod:`crossval` — how well it predicts fixes it was not trained on, next to
  two baselines it has to beat for the result to mean anything.
* :mod:`dataset` — reading the examples from the database.
* :mod:`store` — the trained model and its report, as files.

Nothing here invents data. With too few judged fixes the training command
refuses and says how many more are needed.
"""
