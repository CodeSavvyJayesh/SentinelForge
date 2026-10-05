"""Logistic regression, written out.

    probability = 1 / (1 + exp(-(bias + weights · features)))

fitted by Newton's method on the log loss with an L2 penalty on the weights
(not on the bias). A page of arithmetic is easier to defend in a viva than an
import, and the data this will ever see — a few hundred rows, a few dozen
columns — does not need more.

Why Newton's method and not gradient descent: the first version used gradient
descent with a fixed step, and with a strong penalty on a small data set the
step overshot and the weights became ``nan``. A fixed step is a number that
has to be right for every data set. Newton's method works its step out from
the curvature, and the version here also halves any step that fails to lower
the loss, so each iteration can only make the fit better.

Deterministic: weights start at zero and there is no random step, so the same
examples give the same model on every machine.
"""

import math
from dataclasses import dataclass

DEFAULT_L2 = 1.0
MAX_ITERATIONS = 50
# Stop when a full step changes no parameter by more than this.
TOLERANCE = 1e-8
MAX_HALVINGS = 30
# Keeps the system solvable when a column is constant; far too small to move a fit.
JITTER = 1e-9


@dataclass(frozen=True)
class Model:
    weights: tuple[float, ...]
    bias: float
    iterations: int = 0

    def probability(self, row: list[float]) -> float:
        if len(row) != len(self.weights):
            raise ValueError("the row has a different number of features from the model")
        return sigmoid(self.bias + sum(w * x for w, x in zip(self.weights, row, strict=True)))


def sigmoid(value: float) -> float:
    """1 / (1 + e^-x), written so that neither large sign overflows."""
    if value >= 0:
        return 1.0 / (1.0 + math.exp(-value))
    raised = math.exp(value)
    return raised / (1.0 + raised)


def _log_one_plus_exp(value: float) -> float:
    """log(1 + e^x) without overflowing for large x."""
    return value + math.log1p(math.exp(-value)) if value > 0 else math.log1p(math.exp(value))


def _loss(
    rows: list[list[float]], targets: list[float], parameters: list[float], l2: float
) -> float:
    """Log loss plus the penalty. ``parameters`` is the weights, then the bias."""
    total = 0.0
    for row, target in zip(rows, targets, strict=True):
        score = parameters[-1] + sum(w * x for w, x in zip(parameters, row, strict=False))
        total += _log_one_plus_exp(score) - target * score
    return total + 0.5 * l2 * sum(weight * weight for weight in parameters[:-1])


def _solve(matrix: list[list[float]], vector: list[float]) -> list[float]:
    """Solve a symmetric positive-definite system by Cholesky factorisation."""
    size = len(vector)
    lower = [[0.0] * size for _ in range(size)]
    for i in range(size):
        for j in range(i + 1):
            total = matrix[i][j] - sum(lower[i][k] * lower[j][k] for k in range(j))
            if i == j:
                if total <= 0:
                    raise ArithmeticError("the curvature is not positive")
                lower[i][j] = math.sqrt(total)
            else:
                lower[i][j] = total / lower[j][j]
    forward = [0.0] * size
    for i in range(size):
        forward[i] = (vector[i] - sum(lower[i][k] * forward[k] for k in range(i))) / lower[i][i]
    solution = [0.0] * size
    for i in reversed(range(size)):
        solution[i] = (
            forward[i] - sum(lower[k][i] * solution[k] for k in range(i + 1, size))
        ) / lower[i][i]
    return solution


def train(
    rows: list[list[float]],
    labels: list[bool],
    *,
    l2: float = DEFAULT_L2,
    max_iterations: int = MAX_ITERATIONS,
) -> Model:
    if not rows or len(rows) != len(labels):
        raise ValueError("training needs one label for every row, and at least one row")
    if l2 < 0:
        raise ValueError("the penalty cannot be negative")
    width = len(rows[0])
    if any(len(row) != width for row in rows):
        raise ValueError("every row must have the same number of features")

    count = len(rows)
    targets = [1.0 if label else 0.0 for label in labels]
    size = width + 1  # the bias is the last parameter
    # Start the bias at the base rate: with every weight at zero the model
    # already predicts the share of positives, and the weights only have to
    # explain departures from it. (Half a count is added to each side so that
    # a data set with one outcome only does not ask for the logarithm of zero.)
    positives = sum(targets)
    parameters = [0.0] * width + [math.log((positives + 0.5) / (count - positives + 0.5))]
    loss = _loss(rows, targets, parameters, l2)

    iterations = 0
    for iterations in range(1, max_iterations + 1):  # noqa: B007 - reported in the model
        gradient = [0.0] * size
        curvature = [[0.0] * size for _ in range(size)]
        for row, target in zip(rows, targets, strict=True):
            probability = sigmoid(
                parameters[-1] + sum(w * x for w, x in zip(parameters, row, strict=False))
            )
            error = probability - target
            spread = probability * (1.0 - probability)
            extended = [*row, 1.0]
            for i in range(size):
                if extended[i] == 0.0:
                    continue
                gradient[i] += error * extended[i]
                scaled = spread * extended[i]
                line = curvature[i]
                for j in range(i + 1):
                    line[j] += scaled * extended[j]
        for i in range(width):
            gradient[i] += l2 * parameters[i]
            curvature[i][i] += l2
        for i in range(size):
            curvature[i][i] += JITTER
            for j in range(i):
                curvature[j][i] = curvature[i][j]

        step = _solve(curvature, gradient)
        # Take the full step if it lowers the loss; otherwise halve it until
        # it does. The loss therefore never goes up from one iteration to the next.
        scale = 1.0
        for _ in range(MAX_HALVINGS):
            candidate = [p - scale * s for p, s in zip(parameters, step, strict=True)]
            candidate_loss = _loss(rows, targets, candidate, l2)
            if candidate_loss <= loss:
                break
            scale /= 2
        else:
            break  # no step helps: this is as good as it gets
        moved = max(abs(scale * s) for s in step)
        parameters, loss = candidate, candidate_loss
        if moved < TOLERANCE:
            break
    return Model(tuple(parameters[:-1]), parameters[-1], iterations)


__all__ = ["DEFAULT_L2", "Model", "sigmoid", "train"]
