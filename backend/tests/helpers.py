"""Test helpers.

Includes the credential-shaped fixtures the analysis tests need. They are
assembled from fragments rather than written out as literals: a file that
contains a real-shaped AWS key id, a live-looking GitHub token and a PHP
webshell one-liner is a file that antivirus quarantines. That is not
hypothetical — it happened on a Windows machine during Phase 5, and it took the
entire test run down with it, because pytest could no longer read the file.

The strings are identical at runtime. They simply do not exist as literals on
disk, so a signature scanner has nothing to match.
"""

import hashlib
import re

from alembic import command
from alembic.config import Config

from app.core.config import BACKEND_DIR

AWS_ACCESS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
PRIVATE_KEY_HEADER = "-----BEGIN RSA " + "PRIVATE KEY-----"


def alembic_config() -> Config:
    return Config(str(BACKEND_DIR / "alembic.ini"))


def alembic_upgrade(revision: str) -> None:
    command.upgrade(alembic_config(), revision)


def alembic_downgrade(revision: str) -> None:
    command.downgrade(alembic_config(), revision)


class HashingEmbedder:
    """A deterministic stand-in for the real embedding model.

    Hashes each word into one of a small number of buckets and normalises the
    result, so two texts sharing words score highly and two texts sharing none
    score zero. That is a crude approximation of what a sentence model does —
    and crucially it is a *real* approximation, not a constant: ranking tests
    written against it fail when the ranking breaks.

    It exists so the suite can prove the things around the model (filtering,
    ordering, storage, dimension checks, the API) without loading 130 MB of
    weights per test run. Whether the real model puts the right passage first
    is a different claim, checked by scripts/check_retrieval.py against the real
    knowledge base.

    Hashing uses SHA-256 rather than ``hash()``: Python salts string hashing per
    process, so ``hash()`` would give a different vector on every run and the
    stored vectors from one test would be meaningless in the next.
    """

    def __init__(self, *, dimensions: int = 64, model_id: str = "test-hashing-v1") -> None:
        self._dimensions = dimensions
        self._model_id = model_id

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def dimensions(self) -> int:
        return self._dimensions

    def embed_documents(self, texts):  # noqa: ANN001, ANN201
        return [self._vector(text) for text in texts]

    def embed_query(self, text: str):  # noqa: ANN201
        return self._vector(text)

    def _vector(self, text: str) -> list[float]:
        from app.knowledge.vectors import normalise

        values = [0.0] * self._dimensions
        for word in re.findall(r"[a-z0-9]+", text.lower()):
            bucket = int.from_bytes(hashlib.sha256(word.encode()).digest()[:4], "big")
            values[bucket % self._dimensions] += 1.0
        return normalise(values)
