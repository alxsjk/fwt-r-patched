"""Reference-only model of a possible Alex boss-selection policy.

It is not connected to the game: the runtime hook, object identity, monster
classification and cell validity still require independent verification.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

_BOSS_TYPES = frozenset((80, 90, 100))


@dataclass(frozen=True)
class Candidate:
    """Synthetic combatant; ``key`` must be stable and unique within battle."""

    key: int
    y: int
    z: int
    x: int
    monster_type: int
    alive: bool
    enemy: bool


def choose_boss(origin: tuple[int, int, int], candidates: Iterable[Candidate]) -> Candidate | None:
    """Choose closest alive opposing boss; resolve ties by tile then stable key."""
    eligible = (candidate for candidate in candidates
                if candidate.alive and candidate.enemy and candidate.monster_type in _BOSS_TYPES)

    def rank(candidate: Candidate) -> tuple[int, int, int, int, int]:
        distance = (abs(origin[0] - candidate.y) + abs(origin[1] - candidate.z)
                    + abs(origin[2] - candidate.x))
        return distance, candidate.y, candidate.z, candidate.x, candidate.key

    return min(eligible, key=rank, default=None)
