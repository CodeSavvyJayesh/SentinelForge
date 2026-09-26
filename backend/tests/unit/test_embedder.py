"""The embedding backend.

The model itself is not loaded here — that is the point of the stub. What is
tested is the behaviour *around* it, and in particular the two ways a knowledge
base can be built out of nonsense without anybody noticing: a missing backend
that quietly returns something, and a model whose output is the wrong width.
"""

import builtins
import math
import sys

import pytest

from app.core.config import get_settings
from app.knowledge.embedder import (
    EmbeddingBackendUnavailableError,
    FastEmbedEmbedder,
    build_embedder,
)


def test_build_embedder_uses_the_configured_model() -> None:
    """The production wiring, asserted without downloading anything."""
    settings = get_settings()
    embedder = build_embedder(settings)
    assert isinstance(embedder, FastEmbedEmbedder)
    assert embedder.model_id == settings.KNOWLEDGE_EMBEDDING_MODEL
    assert embedder.dimensions == settings.KNOWLEDGE_EMBEDDING_DIMENSIONS


def test_a_missing_backend_raises_rather_than_returning_anything(monkeypatch) -> None:  # noqa: ANN001
    """There is no fallback, deliberately.

    An embedder that degraded to random or constant vectors when fastembed was
    absent would build a knowledge base that looks complete, answers every
    query, and is wrong — with nothing in the UI to say so.
    """
    monkeypatch.setitem(sys.modules, "fastembed", None)
    real_import = builtins.__import__

    def refuse(name, *args, **kwargs):  # noqa: ANN001, ANN202
        if name == "fastembed":
            raise ImportError("No module named 'fastembed'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse)

    embedder = FastEmbedEmbedder("any/model", dimensions=8)
    with pytest.raises(EmbeddingBackendUnavailableError, match="pip install fastembed"):
        embedder.embed_query("anything")


def test_a_wrong_width_vector_is_refused_at_write_time() -> None:
    """A model returning 768 dimensions where 384 is configured would write rows
    that decode into nonsense. Failing here means the knowledge base never
    contains them."""
    embedder = FastEmbedEmbedder("any/model", dimensions=4)
    with pytest.raises(EmbeddingBackendUnavailableError, match="returned 3 dimensions"):
        embedder._check([1.0, 2.0, 3.0])


def test_vectors_are_normalised_before_they_are_stored() -> None:
    """Normalising at index time is what makes query-time similarity a plain dot
    product instead of a division and two square roots per comparison."""
    embedder = FastEmbedEmbedder("any/model", dimensions=2)
    vector = embedder._check([3.0, 4.0])
    assert math.isclose(math.sqrt(sum(value * value for value in vector)), 1.0, rel_tol=1e-6)


def test_embedding_no_documents_does_not_load_the_model() -> None:
    """A rebuild where nothing changed should not pay for a model load."""
    embedder = FastEmbedEmbedder("model/that/does/not/exist", dimensions=8)
    assert embedder.embed_documents([]) == []


def test_the_stub_ranks_related_text_above_unrelated_text(stub_embedder) -> None:  # noqa: ANN001
    """The stub is only useful if it discriminates; a constant embedder would
    make every ranking test pass whatever the code did."""
    from app.knowledge.vectors import similarity

    query = stub_embedder.embed_query("weak hash algorithm MD5 in Java")
    related, unrelated = stub_embedder.embed_documents(
        [
            "MD5 and SHA-1 are weak hash algorithms; use SHA-256 in Java",
            "Broken access control lets a user reach another user's records",
        ]
    )
    assert similarity(query, related) > similarity(query, unrelated)
