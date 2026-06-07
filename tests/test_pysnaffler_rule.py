"""Tests for the pysnaffler integration rule.

The rule construction loads the real path classifier (Windows + Linux
models from ``models/``). When those artifacts are absent — fresh
clone, no training run yet — the tests are skipped instead of erroring
so CI on a fresh checkout doesn't fail spuriously. The deeper
canonical-tier asserts test the rule's contract (tier mapping,
``determine_action`` shape), not the model's calibration.
"""

from __future__ import annotations

import warnings
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

_WINDOWS_MODEL = REPO_ROOT / "models" / "path_classifier_v0_windows" / "calibrated.joblib"
_LINUX_MODEL = REPO_ROOT / "models" / "path_classifier_v0_linux" / "calibrated.joblib"

SKIP_NO_PATH_MODEL = pytest.mark.skipif(
    not (_WINDOWS_MODEL.exists() and _LINUX_MODEL.exists()),
    reason="Both per-shape path-classifier models must be trained.",
)

# Silence the LightGBM "X does not have valid feature names" UserWarning
# that fires during predict_proba; the warning is benign but noisy in
# test output.
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")


class _FakeSMBFile:
    """Duck-typed stand-in for aiosmb's SMBFile — only the three
    attributes our rule reads."""

    def __init__(self, fullpath: str, name: str = "f", size: int = 1024) -> None:
        self.fullpath = fullpath
        self.name = name
        self.size = size


@SKIP_NO_PATH_MODEL
def test_rule_imports():
    from sharesift.pysnaffler_rule import ShareSiftPathRule  # noqa: F401


@SKIP_NO_PATH_MODEL
def test_rule_construction_default():
    from sharesift.pysnaffler_rule import ShareSiftPathRule

    rule = ShareSiftPathRule()
    assert rule.ruleName == "ShareSiftPathClassifier"


@SKIP_NO_PATH_MODEL
def test_rule_skips_unsupported_path_shapes_cleanly():
    """``determine_action`` with neither smbfile nor fullpath returns
    ``(None, None)`` rather than raising."""
    from sharesift.pysnaffler_rule import ShareSiftPathRule

    rule = ShareSiftPathRule()
    action, triage = rule.determine_action(smbfile=None, fullpath=None)
    assert action is None
    assert triage is None


@SKIP_NO_PATH_MODEL
def test_rule_matches_canonical_juicy_linux():
    """``/etc/shadow`` and ``~/.ssh/id_rsa`` must Snaffle at Black."""
    from pysnaffler.rules.constants import MatchAction, Triage

    from sharesift.pysnaffler_rule import ShareSiftPathRule

    rule = ShareSiftPathRule()

    for path in ("/etc/shadow", "~/.ssh/id_rsa"):
        action, triage = rule.determine_action(smbfile=None, fullpath=path)
        assert action == MatchAction.Snaffle, f"{path}: expected Snaffle, got {action}"
        assert triage == Triage.Black, f"{path}: expected Black, got {triage}"


@SKIP_NO_PATH_MODEL
def test_rule_skips_canonical_benign():
    """``/etc/timezone`` and a benign UNC share readme must NOT match."""
    from sharesift.pysnaffler_rule import ShareSiftPathRule

    rule = ShareSiftPathRule()

    for path in ("/etc/timezone", r"\\fs01\share\public\readme.txt"):
        action, triage = rule.determine_action(smbfile=None, fullpath=path)
        assert action is None, f"{path}: expected no action, got {action}"
        assert triage is None


@SKIP_NO_PATH_MODEL
def test_rule_reads_path_from_smbfile_attr():
    """When the caller passes a populated smbfile, ``fullpath`` is
    taken from ``smbfile.fullpath`` (not the kwarg)."""
    from pysnaffler.rules.constants import MatchAction

    from sharesift.pysnaffler_rule import ShareSiftPathRule

    rule = ShareSiftPathRule()
    smbfile = _FakeSMBFile(fullpath="/etc/shadow", name="shadow", size=1024)
    action, triage = rule.determine_action(smbfile=smbfile)
    assert action == MatchAction.Snaffle
    assert triage is not None


@SKIP_NO_PATH_MODEL
def test_ruleset_integration_enum_file():
    """A ``SnafflerRuleSet`` loaded with only the Truffler rule must
    route ``enum_file()`` to Snaffle juicy paths and skip benign ones."""
    from pysnaffler.ruleset import SnafflerRuleSet

    from sharesift.pysnaffler_rule import ShareSiftPathRule

    ruleset = SnafflerRuleSet()
    ruleset.load_rule(ShareSiftPathRule())

    # Juicy path → enum_file returns (True, [matching_rule])
    juicy = _FakeSMBFile(fullpath="/etc/shadow", name="shadow", size=1024)
    to_dl, rules = ruleset.enum_file(juicy)
    assert to_dl is True
    assert len(rules) == 1
    assert rules[0].ruleName == "ShareSiftPathClassifier"

    # Benign path → no matching rules → enum_file returns (False, None)
    benign = _FakeSMBFile(fullpath="/etc/timezone", name="timezone", size=16)
    to_dl, rules = ruleset.enum_file(benign)
    assert to_dl is False


@SKIP_NO_PATH_MODEL
def test_rule_accepts_injected_classifier():
    """A pre-built ``PathClassifier`` can be passed in — important for
    test fixtures that want to mock the model layer."""
    from sharesift.path import PathClassifier
    from sharesift.pysnaffler_rule import ShareSiftPathRule

    clf = PathClassifier()
    rule = ShareSiftPathRule(classifier=clf)
    action, _ = rule.determine_action(smbfile=None, fullpath="/etc/shadow")
    # We don't assert exact tier here — just that the injected
    # classifier wired through (returned a tier, hence Snaffle).
    from pysnaffler.rules.constants import MatchAction

    assert action == MatchAction.Snaffle
