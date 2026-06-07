"""Tests for tier-mapping and calibration utilities."""

from __future__ import annotations

from sharesift.tier import (
    DEFAULT_THRESHOLDS,
    TierThresholds,
    probability_to_tier,
)


def test_default_thresholds_ordered():
    """Black > Red > Yellow — invariant. Reordering them would silently
    invert tier severity."""
    assert DEFAULT_THRESHOLDS.black > DEFAULT_THRESHOLDS.red
    assert DEFAULT_THRESHOLDS.red > DEFAULT_THRESHOLDS.yellow
    assert DEFAULT_THRESHOLDS.yellow > 0


def test_probability_to_tier_default_thresholds():
    assert probability_to_tier(0.99) == "Black"
    assert probability_to_tier(0.95) == "Black"  # boundary inclusive
    assert probability_to_tier(0.94) == "Red"
    assert probability_to_tier(0.80) == "Red"  # boundary inclusive
    assert probability_to_tier(0.79) == "Yellow"
    assert probability_to_tier(0.50) == "Yellow"  # boundary inclusive
    assert probability_to_tier(0.49) is None
    assert probability_to_tier(0.00) is None


def test_probability_to_tier_custom_thresholds():
    """Custom thresholds must work and not leak into the default."""
    custom = TierThresholds(black=0.99, red=0.90, yellow=0.70)
    assert probability_to_tier(0.95, custom) == "Red"
    assert probability_to_tier(0.95) == "Black"  # default unchanged


def test_probability_to_tier_boundary_zero():
    """A probability of exactly 0.0 is not flagged — strict ``>=`` at
    yellow but yellow is 0.5 by default."""
    assert probability_to_tier(0.0) is None
