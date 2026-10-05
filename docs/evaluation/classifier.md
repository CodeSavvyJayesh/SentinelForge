# The patch-outcome classifier

SentinelForge asks a language model for a fix (Phase 10) and then checks the
fix by applying it to a copy and scanning again (Phase 11). Every checked fix
is a labelled example: these were the circumstances, and this is how it came
out. This is a small model trained on those examples to answer one question:

> **Before the re-scan is run, how likely is this proposed fix to pass it?**

It is the project's own trained model, on the project's own data — not a
downloaded one, and not the language model.

## There is no result yet

**No figure in this document comes from a trained model, because none has been
trained.** Training needs fixes that were really proposed by the model and
really checked on this installation. The pipeline below is built and tested;
its numbers will exist when it has been run against a database that holds
enough of them, and they will be written to `results/classifier/report.md` by
the command itself, not typed in here.

The tests train on invented examples to prove the arithmetic is right. Invented
examples say nothing about real fixes and none of their scores is reported
anywhere.

## What it learns from

One example per checked fix. The label is the validation's verdict:

| Verdict | Used as |
| --- | --- |
| `PASSED` | the fix was supported by the re-scan |
| `REJECTED` | it was not |
| `FAILED` | **left out** — the check itself could not be run, which says nothing about the fix |

The inputs are only things known when the proposal was created: the rule,
its severity and confidence, the file type, how many lines were added and
removed, how large the region the model was allowed to change was, the length
of the diff and of the rationale, whether the reply had to be cleaned up (code
fences, line-number gutters, re-indentation), which attempt it was, whether an
explanation and reference passages were available, and the generation's token
counts, duration and temperature.

Nothing recorded by the re-scan is an input. The findings before and after are
the answer; using them to predict the answer would give a perfect score that
means nothing.

## How it is trained

A regularised logistic regression, written in plain Python (about 150 lines,
`backend/app/learning/logistic.py`) and fitted by Newton's method. There is no
machine-learning library in the project and this did not add one: with a few
hundred examples and a few dozen inputs the fit takes milliseconds, and a
model this small can be read. The saved model is a JSON file of named weights.

A logistic regression was chosen over anything larger on purpose. With this
little data a flexible model memorises; and the first thing worth knowing is
whether there is any signal at all, which a simple model answers.

## How it is judged

The model is never scored on examples it was trained on.

- **Cross-validation, five folds, repeated ten times** with different splits.
  The figure reported is the average, with the spread across repeats.
- **Fixes for the same finding stay together.** A second attempt at the same
  finding is nearly a copy of the first. If one were in the training part and
  the other in the test part, the model would be marked on something it had
  seen. Splits are made by finding, not by fix.
- **Everything fitted is fitted inside the fold**: which rules are common
  enough to get their own input, and the scaling of each number, are decided
  from the training part only.
- **Two baselines, and the second is the one that matters.**
  1. *Base rate*: predict the overall pass rate for every fix.
  2. *By rule*: predict the pass rate of that rule's earlier fixes. "Fixes for
     weak hashes usually pass, fixes for SQL injection usually do not" needs no
     model. The classifier is only worth having if it knows something beyond
     which rule it is looking at.
- **Figures**: area under the ROC curve (0.5 is guessing), Brier score (how far
  the stated probabilities are from what happened), accuracy, and precision and
  recall for "will pass".

The report ends with one of three conclusions, and the bar for the first is
deliberately high:

| Conclusion | Requires |
| --- | --- |
| *Better than knowing the rule* | a higher average AUC by more than 0.02, **and** no overlap between the two spreads, **and** a paired test on the individual predictions with p < 0.05 |
| *Unclear* | higher on average, but not all of the above |
| *No better* | not higher by more than 0.02 |

"No better" is a result, and the report says it in those words. It would mean
the outcome of a fix depends on the rule and on little else that is recorded —
which is worth knowing, and is what a small dataset will most likely show.

## It refuses to train on too little

Fewer than **60** judged fixes, or fewer than **15** of either outcome, and the
command stops, says how many there are, and exits with code 1. Below that, a
five-fold split leaves a handful of the rarer outcome in each test part and
every figure is noise with a decimal point.

## Running it

From `backend`, with the virtual environment active and the database running:

```powershell
python scripts\train_patch_classifier.py --status      # how much data is there?
```

To gather more, with the backend and Ollama running (these ask the application
to do what the buttons in the interface do, for findings that have no fix yet):

```powershell
python scripts\collect_patch_outcomes.py fixes --limit 25    # propose fixes
python scripts\collect_patch_outcomes.py checks              # check the proposed ones
python scripts\collect_patch_outcomes.py status
```

Each fix is a model generation, so twenty-five take a while on a CPU. Then:

```powershell
python scripts\train_patch_classifier.py
```

That writes `backend\models\patch_outcome.json` (the model) and
`docs\evaluation\results\classifier\report.md` (the cross-validated figures,
the baselines, the conclusion and the largest weights). Commit the report; it
is the result.

## What it cannot show, even with data

- **The label is "passed the re-scan", not "is correct".** Phase 11's check is
  narrow by its own description: the finding is gone, nothing new appeared, and
  the change is not a deletion. A fix that breaks the program passes. The
  classifier predicts the check, and inherits everything the check cannot see.
- **One installation, one language model.** The examples come from whichever
  repositories were scanned here and whichever model Ollama was running. A
  different model would produce different fixes, and the weights would not
  carry over.
- **Collected, not sampled.** `collect_patch_outcomes.py` asks for fixes in
  the order findings come out of the database. The examples are whatever those
  were, not a designed sample of weaknesses.
- **It is not used to decide anything.** The application does not consult the
  model: no fix is hidden, ranked or approved by it. A fix is still only
  "checked" when the re-scan has run. Wiring a prediction into the interface
  is a decision for after there is a result that justifies it.
