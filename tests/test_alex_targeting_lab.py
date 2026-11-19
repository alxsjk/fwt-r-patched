"""Design tests for the standalone targeting model, not game integration."""

from itertools import permutations

from tools.lab_alex_targeting import Candidate, choose_boss


def test_nearest_eligible_boss_is_independent_of_enumeration_order() -> None:
    candidates = [
        Candidate(4, 0, 2, 0, 100, True, True),
        Candidate(1, 0, 0, 2, 90, True, True),
        Candidate(3, 0, 0, 1, 80, False, True),
        Candidate(2, 0, 0, 0, 100, True, False),
        Candidate(5, 0, 0, 0, 1, True, True),
    ]
    for ordering in permutations(candidates):
        assert choose_boss((0, 0, 0), ordering) == candidates[1]


def test_height_contributes_to_distance_and_no_boss_is_unavailable() -> None:
    high = Candidate(1, 4, 0, 0, 100, True, True)
    near = Candidate(2, 0, 2, 0, 80, True, True)
    assert choose_boss((0, 0, 0), [high, near]) == near
    assert choose_boss((0, 0, 0), [Candidate(3, 0, 0, 0, 100, False, True)]) is None


def test_same_tile_tie_uses_stable_key() -> None:
    first = Candidate(7, 1, 2, 3, 100, True, True)
    second = Candidate(3, 1, 2, 3, 100, True, True)
    assert choose_boss((0, 0, 0), [first, second]) == second
    assert choose_boss((0, 0, 0), [second, first]) == second
