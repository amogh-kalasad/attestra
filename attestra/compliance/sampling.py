"""Shared audit sampling helpers for ISO 9.2 and SOC 2 Type II.

Sample sizes follow SAMPLE_SIZE_TABLE (documented Type II practice). Seeds normalize
to int for random.Random; missing seeds derive from a context string via sha256.
"""
# @lat: [[compliance#Shared audit sampling]]

from __future__ import annotations

import hashlib

# (max population size inclusive, sample size). None means sample the whole population.
SAMPLE_SIZE_TABLE: tuple[tuple[int, int | None], ...] = (
    (2, None),  # tiny populations: test every item
    (4, 2),  # quarterly-type frequency
    (12, 2),  # monthly-type frequency
    (52, 5),  # weekly-type frequency
    (250, 25),  # daily-type frequency
    (10**12, 40),  # many times per day
)


def sample_size_for(population_size: int) -> int:
    """Documented sample size for a population of this size (see SAMPLE_SIZE_TABLE)."""
    if population_size <= 0:
        return 0
    for limit, size in SAMPLE_SIZE_TABLE:
        if population_size <= limit:
            return population_size if size is None else min(size, population_size)
    return population_size


def seed_from_context(context: str) -> int:
    """Deterministic int seed from a context string (sha256, first 12 hex digits)."""
    return int(hashlib.sha256(context.encode()).hexdigest()[:12], 16)


def seed_to_int(seed: int | str) -> int:
    """Normalize a provided seed to int for random.Random.

    Integers pass through. Decimal integer strings parse as int; other strings
    hash the same way as [[seed_from_context]].
    """
    if isinstance(seed, int):
        return seed
    s = str(seed).strip()
    try:
        return int(s, 10)
    except ValueError:
        return seed_from_context(s)


def resolve_seed(seed: int | str | None, *, context: str) -> int:
    """Int seed for RNG: use seed when given, else hash context."""
    if seed is None or (isinstance(seed, str) and not str(seed).strip()):
        return seed_from_context(context)
    return seed_to_int(seed)
