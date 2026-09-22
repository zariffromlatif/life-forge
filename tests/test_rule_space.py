import numpy as np
import pytest

from lifeforge.rules import (
    ConwayRule,
    OuterTotalisticRule,
    random_outer_totalistic_rule,
)


def test_conway_notation():
    rule = ConwayRule()

    assert rule.notation == "B3/S23"


def test_custom_rule_notation():
    rule = OuterTotalisticRule(
        birth=frozenset({3, 6}),
        survival=frozenset({2, 3}),
    )

    assert rule.notation == "B36/S23"


def test_random_rule_is_reproducible():
    rule_a = random_outer_totalistic_rule(seed=42)
    rule_b = random_outer_totalistic_rule(seed=42)

    assert rule_a.birth == rule_b.birth
    assert rule_a.survival == rule_b.survival
    assert rule_a.notation == rule_b.notation


def test_random_rules_can_differ():
    rule_a = random_outer_totalistic_rule(seed=1)
    rule_b = random_outer_totalistic_rule(seed=2)

    assert (
        rule_a.birth != rule_b.birth
        or rule_a.survival != rule_b.survival
    )


def test_invalid_birth_count():
    with pytest.raises(ValueError):
        OuterTotalisticRule(
            birth=frozenset({9}),
            survival=frozenset({2, 3}),
        )


def test_invalid_survival_count():
    with pytest.raises(ValueError):
        OuterTotalisticRule(
            birth=frozenset({3}),
            survival=frozenset({-1}),
        )



def test_conway_matches_expected_transition():
    rule = ConwayRule()

    state = np.array(
        [
            [0, 0, 0, 0, 0],
            [0, 0, 1, 0, 0],
            [0, 0, 1, 0, 0],
            [0, 0, 1, 0, 0],
            [0, 0, 0, 0, 0],
        ],
        dtype=np.uint8,
    )

    from lifeforge.world import World

    world = World(
        width=5,
        height=5,
        state=state,
    )

    next_world = rule.apply(world)

    expected = np.array(
        [
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 1, 1, 1, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ],
        dtype=np.uint8,
    )

    assert np.array_equal(next_world.state, expected)

def test_rule_id_is_reproducible():
    rule_a = OuterTotalisticRule(
        birth=frozenset({3}),
        survival=frozenset({2, 3}),
    )

    rule_b = OuterTotalisticRule(
        birth=frozenset({3}),
        survival=frozenset({2, 3}),
    )

    assert rule_a.rule_id == rule_b.rule_id


def test_rule_id_changes_when_rule_changes():
    rule_a = OuterTotalisticRule(
        birth=frozenset({3}),
        survival=frozenset({2, 3}),
    )

    rule_b = OuterTotalisticRule(
        birth=frozenset({3, 6}),
        survival=frozenset({2, 3}),
    )

    assert rule_a.rule_id != rule_b.rule_id