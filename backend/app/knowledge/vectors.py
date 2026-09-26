"""Storing and comparing embedding vectors without a vector database.

Three decisions live in this file, and all three are deliberate.

**Vectors are stored as bytes, not as a JSON array.** A 384-dimension vector is
1536 bytes as little-endian float32 and roughly 8 KB as JSON text. At a few
thousand chunks that is the difference between a table that fits in memory and
one that does not, and decoding 1536 bytes is a memory copy rather than a parse.

**Vectors are normalised on the way in.** Cosine similarity is
``dot(a, b) / (|a| * |b|)``. If both vectors already have length 1, the divisor
is 1 and cosine *is* the dot product — so the square roots are paid once at
index time instead of on every comparison of every query.

**Similarity is computed in Python, exactly, over every candidate.** No numpy,
no approximate index. The corpus here is a few thousand chunks; a brute-force
pass is a few milliseconds, and it returns the true nearest neighbours rather
than probably-the-nearest. An ANN index trades accuracy for speed at a scale we
are nowhere near, and pgvector would mean a PostgreSQL extension to install on
every machine this project is ever run on. The honest scale-out path is written
down in the phase report rather than pretended away.
"""

import math
from array import array
from collections.abc import Sequence
from operator import mul
from sys import byteorder

# float32: four bytes per dimension. Chosen over float64 because the model's own
# output is float32 — storing it as float64 would be inventing precision.
BYTES_PER_DIMENSION = 4
_LITTLE_ENDIAN = byteorder == "little"


class VectorFormatError(ValueError):
    """A stored vector is not the shape the caller expects.

    Raised rather than returning a shorter vector: a truncated embedding
    compared against a full one produces a plausible-looking number, and a
    silently wrong similarity score is worse than a failed request.
    """


def normalise(vector: Sequence[float]) -> list[float]:
    """Scale a vector to unit length so that dot product == cosine similarity.

    A zero vector cannot be normalised — it has no direction — and is returned
    unchanged. It will score 0 against everything, which is the correct answer
    for "this text carried no signal".
    """
    length = math.sqrt(sum(value * value for value in vector))
    if length == 0.0:
        return [float(value) for value in vector]
    return [float(value) / length for value in vector]


def encode(vector: Sequence[float]) -> bytes:
    """Pack a vector into little-endian float32 bytes for the database.

    The endianness is pinned so that a database written on one machine can be
    read on another. Without this, a dump restored on a big-endian host would
    decode to plausible nonsense rather than failing.
    """
    packed = array("f", (float(value) for value in vector))
    if not _LITTLE_ENDIAN:  # pragma: no cover - x86 and ARM are little-endian
        packed.byteswap()
    return packed.tobytes()


def decode(blob: bytes, *, dimensions: int | None = None) -> array:
    """Unpack stored bytes back into a float array.

    Returns an ``array('f')`` rather than a list: it holds the same numbers in a
    quarter of the memory, and :func:`similarity` iterates it just as fast.
    """
    if len(blob) % BYTES_PER_DIMENSION != 0:
        raise VectorFormatError(
            f"stored vector is {len(blob)} bytes, not a whole number of float32 values"
        )
    if dimensions is not None and len(blob) != dimensions * BYTES_PER_DIMENSION:
        raise VectorFormatError(
            f"stored vector has {len(blob) // BYTES_PER_DIMENSION} dimensions, "
            f"expected {dimensions}"
        )
    values = array("f")
    values.frombytes(blob)
    if not _LITTLE_ENDIAN:  # pragma: no cover - x86 and ARM are little-endian
        values.byteswap()
    return values


def similarity(left: Sequence[float], right: Sequence[float]) -> float:
    """Cosine similarity of two **already normalised** vectors.

    Mismatched dimensions are an error, not something to zip away quietly:
    ``zip`` would stop at the shorter vector and return a confident score for a
    comparison that never happened.
    """
    if len(left) != len(right):
        raise VectorFormatError(
            f"cannot compare a {len(left)}-dimension vector with a {len(right)}-dimension one"
        )
    return float(sum(map(mul, left, right)))


__all__ = [
    "BYTES_PER_DIMENSION",
    "VectorFormatError",
    "decode",
    "encode",
    "normalise",
    "similarity",
]
