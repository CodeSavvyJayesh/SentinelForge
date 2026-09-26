"""Turning text into vectors, locally.

The interface is a protocol with exactly one real implementation and one test
double. That is not over-engineering — it is what keeps the test suite honest.
The plumbing around embeddings (chunking, storage, filtering, ranking, the API)
is ordinary code and deserves ordinary tests; loading a 130 MB neural network to
prove that a database filter works would make the suite slow *and* would hide
which of the two actually broke when something failed.

So: the stub proves the plumbing, and the model is verified separately by
``scripts/check_retrieval.py``, which asks real questions of the real model and
prints what comes back. Two different claims, checked two different ways.

**There is no automatic fallback.** If the model cannot be loaded, every call
raises. An embedder that quietly degraded to random vectors when its dependency
was missing would produce a knowledge base that looks full, answers every query,
and is wrong — and nothing in the UI would say so.
"""

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from app.core.logging import get_logger
from app.knowledge.vectors import normalise

logger = get_logger("sentinelforge.knowledge")


class EmbeddingBackendUnavailableError(RuntimeError):
    """The embedding model is not installed or could not be loaded.

    The message is aimed at whoever is running the project, because that is the
    only person who can fix it.
    """

    def __init__(self, detail: str) -> None:
        super().__init__(
            f"{detail}\n"
            "The knowledge base needs a local embedding model. Install it with:\n"
            "    python -m pip install fastembed\n"
            "The model itself is downloaded once, on first use, and cached on disk."
        )


@runtime_checkable
class Embedder(Protocol):
    """Anything that can turn text into unit-length vectors."""

    @property
    def model_id(self) -> str:
        """Recorded on every chunk, so a mixed-model knowledge base is detectable."""

    @property
    def dimensions(self) -> int: ...

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        """Embed passages that will be stored and searched."""

    def embed_query(self, text: str) -> list[float]:
        """Embed a question. Deliberately separate from :meth:`embed_documents`:
        retrieval models are trained asymmetrically, and BGE in particular
        expects a short instruction prefix on the query side only. Using the
        passage encoder for queries silently costs accuracy."""


class FastEmbedEmbedder:
    """Sentence embeddings via fastembed, which runs ONNX on the CPU.

    Chosen over ``sentence-transformers`` because that pulls PyTorch — about
    2.5 GB — for a model that is 130 MB and never trained here. Same vectors,
    a fraction of the install.

    The import is deferred to first use so that the rest of the application,
    its tests and its migrations all run on a machine where the model is not
    installed. Only the knowledge base needs it.
    """

    def __init__(self, model_id: str, *, dimensions: int, cache_dir: str | None = None) -> None:
        self._model_id = model_id
        self._dimensions = dimensions
        self._cache_dir = cache_dir
        self._model = None

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def dimensions(self) -> int:
        return self._dimensions

    def _load(self):  # noqa: ANN202 - fastembed.TextEmbedding, imported lazily
        if self._model is not None:
            return self._model
        try:
            from fastembed import TextEmbedding
        except ImportError as exc:
            raise EmbeddingBackendUnavailableError("fastembed is not installed.") from exc
        try:
            self._model = TextEmbedding(model_name=self._model_id, cache_dir=self._cache_dir)
        except Exception as exc:  # noqa: BLE001 - a bad model name, no disk, no network
            raise EmbeddingBackendUnavailableError(
                f"Could not load the embedding model {self._model_id!r}: {exc}"
            ) from exc
        logger.info(
            "embedding_model_loaded",
            extra={"model_id": self._model_id, "dimensions": self._dimensions},
        )
        return self._model

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []
        model = self._load()
        return [self._check(list(vector)) for vector in model.embed(list(texts))]

    def embed_query(self, text: str) -> list[float]:
        model = self._load()
        # query_embed applies the model's own query-side prefix.
        vectors = list(model.query_embed([text]))
        if not vectors:
            raise EmbeddingBackendUnavailableError("The embedding model returned no vector.")
        return self._check(list(vectors[0]))

    def _check(self, vector: list[float]) -> list[float]:
        """Refuse a vector of unexpected width, then normalise it.

        The configured dimension count decides how stored vectors are decoded.
        A model that returns a different width would write rows that decode into
        nonsense, so this fails at write time instead.
        """
        if len(vector) != self._dimensions:
            raise EmbeddingBackendUnavailableError(
                f"The model {self._model_id!r} returned {len(vector)} dimensions, "
                f"but KNOWLEDGE_EMBEDDING_DIMENSIONS is {self._dimensions}."
            )
        return normalise(vector)


def build_embedder(settings) -> FastEmbedEmbedder:  # noqa: ANN001 - app.core.config.Settings
    return FastEmbedEmbedder(
        settings.KNOWLEDGE_EMBEDDING_MODEL,
        dimensions=settings.KNOWLEDGE_EMBEDDING_DIMENSIONS,
        cache_dir=settings.KNOWLEDGE_MODEL_CACHE_DIR or None,
    )


__all__ = [
    "Embedder",
    "EmbeddingBackendUnavailableError",
    "FastEmbedEmbedder",
    "build_embedder",
]
