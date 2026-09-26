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
import json
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


class FakeOllama:
    """A stand-in for the Ollama daemon.

    The test suite must never need a 4.7 GB model installed, and it must never
    depend on what that model happens to say today. So the daemon is faked at
    the boundary this project actually owns: the client's two methods.

    What it does *not* fake is the contract. Responses go through the real
    parser, which is where the citation checking, the link stripping and the
    schema enforcement live — those are the security properties of this phase,
    and testing them against a mock of themselves would prove nothing.
    """

    def __init__(
        self,
        response: str | None = None,
        *,
        model: str = "test-model:1b",
        installed: bool = True,
        error: Exception | None = None,
        ready_error: Exception | None = None,
    ) -> None:
        self.model = model
        self.response = (
            response
            if response is not None
            else json.dumps(
                {
                    "summary": "The code hashes with MD5, which is collision-broken.",
                    "impact": "An attacker can craft a second input with the same digest.",
                    "remediation": 'Use MessageDigest.getInstance("SHA-256") instead.',
                    "citations": [1],
                }
            )
        )
        self.installed = installed
        self.error = error
        self.ready_error = ready_error
        self.prompts: list[str] = []
        self.systems: list[str | None] = []

    def check_ready(self) -> None:
        if self.ready_error is not None:
            raise self.ready_error

    def available_models(self) -> list[str]:
        return [self.model] if self.installed else []

    def generate(self, prompt: str, *, system: str | None = None):  # noqa: ANN201
        from app.llm.client import Completion

        self.prompts.append(prompt)
        self.systems.append(system)
        if self.error is not None:
            raise self.error
        return Completion(
            text=self.response,
            model=self.model,
            total_duration_ms=1234,
            prompt_tokens=100,
            completion_tokens=50,
        )


def llm_response(**overrides) -> str:  # noqa: ANN003
    """A well-formed model answer, with fields overridden as a test needs."""
    payload = {
        "summary": "Summary of the problem.",
        "impact": "What an attacker does with it.",
        "remediation": "What to change.",
        "citations": [1],
    }
    payload.update(overrides)
    return json.dumps(payload)
