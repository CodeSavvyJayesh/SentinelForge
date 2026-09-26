"""Vector storage and comparison.

The point of these tests is that a *wrong* vector fails loudly. A silently
truncated or mis-decoded embedding still produces a number between -1 and 1,
and every layer above would treat that number as a similarity score.
"""

import math
import struct

import pytest

from app.knowledge.vectors import (
    VectorFormatError,
    decode,
    encode,
    normalise,
    similarity,
)


def test_normalise_gives_unit_length() -> None:
    vector = normalise([3.0, 4.0])
    assert math.isclose(math.sqrt(sum(value * value for value in vector)), 1.0, rel_tol=1e-6)
    assert math.isclose(vector[0], 0.6, rel_tol=1e-6)


def test_normalise_leaves_a_zero_vector_alone() -> None:
    """A zero vector has no direction. Dividing by its length would raise, and
    inventing a direction would make it match something."""
    assert normalise([0.0, 0.0, 0.0]) == [0.0, 0.0, 0.0]


def test_encode_decode_round_trip() -> None:
    original = normalise([0.1, -0.5, 0.9, 0.2])
    restored = decode(encode(original), dimensions=4)
    assert len(restored) == 4
    for left, right in zip(original, restored, strict=True):
        assert math.isclose(left, right, rel_tol=1e-6)


def test_encoding_is_little_endian_float32() -> None:
    """Pinned so a database written on one machine reads correctly on another."""
    assert encode([1.0, 2.0]) == struct.pack("<2f", 1.0, 2.0)


def test_normalised_dot_product_equals_cosine() -> None:
    left = normalise([1.0, 2.0, 3.0])
    right = normalise([2.0, 4.0, 6.0])  # same direction, different magnitude
    assert math.isclose(similarity(left, right), 1.0, rel_tol=1e-6)


def test_orthogonal_vectors_score_zero() -> None:
    assert math.isclose(similarity(normalise([1.0, 0.0]), normalise([0.0, 1.0])), 0.0, abs_tol=1e-6)


def test_decode_rejects_a_truncated_vector() -> None:
    """Three bytes is not a whole float. Returning a shorter vector here would
    produce a plausible score for a comparison that never happened."""
    with pytest.raises(VectorFormatError):
        decode(b"\x00\x00\x00")


def test_decode_rejects_the_wrong_dimension_count() -> None:
    with pytest.raises(VectorFormatError, match="expected 4"):
        decode(encode([1.0, 2.0]), dimensions=4)


def test_similarity_rejects_mismatched_lengths() -> None:
    """zip() would silently stop at the shorter vector and return a confident
    number. This is the control that stops that."""
    with pytest.raises(VectorFormatError):
        similarity([1.0, 0.0, 0.0], [1.0, 0.0])
