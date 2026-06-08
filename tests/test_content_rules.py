"""v0.20 Phase 1: ContentRuleEngine — execute the vendored Snaffler
rules against file content."""

from __future__ import annotations

import pytest

from sharesift.content_rules import (
    ContentRuleEngine,
    RuleMatch,
    RuleVerdict,
    get_default_engine,
)


def test_engine_loads_with_meaningful_rule_count():
    """The bundled 88 base rules minus Discard/ShareName classes
    should leave a substantial executable set."""
    engine = ContentRuleEngine()
    # ~7 Discard + ~3 ShareName get filtered out; ~78 remain.
    assert len(engine) > 50, f"only {len(engine)} rules compiled"


def test_engine_fires_on_obvious_credential_filename():
    """A file named ``id_rsa`` should fire at least one rule."""
    engine = ContentRuleEngine()
    verdict = engine.evaluate("/share/admin/id_rsa", content=None)
    assert verdict.has_any()
    assert verdict.tier in ("Black", "Red")


def test_engine_fires_on_password_keyword_in_name():
    """``passw`` is in the Green-tier KeepNameContains list."""
    engine = ContentRuleEngine()
    verdict = engine.evaluate(
        "/share/dev/database_password_2026.txt", content=None
    )
    assert verdict.has_any()
    # At least one match should reference the FileName rule.
    assert any(m.match_location == "FileName" for m in verdict.matches)


def test_engine_silent_on_benign_filename_with_no_content():
    """``intake_form.csv`` shouldn't fire any rule when content is
    absent — this is exactly the v0.19 content-ood case Stage 1
    can't catch on path alone."""
    engine = ContentRuleEngine()
    verdict = engine.evaluate(
        "/share/healthcare/intake_form_0058.csv", content=None
    )
    # We may match the .csv extension rule (Yellow-tier database-ish)
    # but the FileName/FilePath rules shouldn't see anything juicy.
    name_matches = [m for m in verdict.matches if m.match_location == "FileName"]
    assert name_matches == [], (
        f"unexpected FileName rule hit on benign file: {name_matches}"
    )


def test_engine_fires_on_credential_content():
    """A benign-named file with credentials INSIDE should fire a
    FileContentAsString rule. This is the v0.19 content-ood fix."""
    engine = ContentRuleEngine()
    # csharp connection string is in the bundled rules.
    content = (
        "# innocuous header\n"
        "// later in file\n"
        '  conn = "Data Source=db01.corp.local;Integrated Security=SSPI"\n'
        "more lines\n"
    )
    verdict = engine.evaluate("/share/finance/Q4_report.docx", content=content)
    content_matches = [m for m in verdict.matches if m.match_location == "FileContentAsString"]
    assert content_matches, (
        f"expected a FileContentAsString hit; got {verdict.matches}"
    )


def test_verdict_tier_returns_highest():
    """If multiple rules at different tiers fire, ``tier`` is the
    highest one. Tier ordering: Black > Red > Yellow > Green."""
    m1 = RuleMatch(
        rule_name="r1", tier="Yellow", action="Snaffle",
        match_location="FileName", matched_pattern="passw", matched_span="password",
    )
    m2 = RuleMatch(
        rule_name="r2", tier="Black", action="Snaffle",
        match_location="FileName", matched_pattern="id_rsa", matched_span="id_rsa",
    )
    m3 = RuleMatch(
        rule_name="r3", tier="Green", action="Snaffle",
        match_location="FileExtension", matched_pattern=r"\\.txt", matched_span=".txt",
    )
    verdict = RuleVerdict(matches=[m1, m2, m3])
    assert verdict.tier == "Black"


def test_engine_handles_missing_content_gracefully():
    """``content=None`` should not crash — content-side rules just skip."""
    engine = ContentRuleEngine()
    verdict = engine.evaluate("/path/to/binary.bin", content=None)
    # Whatever the verdict is, we shouldn't have raised.
    assert isinstance(verdict, RuleVerdict)


def test_singleton_returns_same_instance():
    a = get_default_engine()
    b = get_default_engine()
    assert a is b
    assert len(a) > 0
