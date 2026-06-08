"""v0.20 Phase 2: ContentDeterminer cascade."""

from __future__ import annotations

from sharesift.content_determiner import ContentDeterminer, ContentVerdict


class _FakeRuleVerdict:
    def __init__(self, matches):
        self.matches = matches
    @property
    def tier(self):
        if not self.matches:
            return None
        rank = {"Black": 4, "Red": 3, "Yellow": 2, "Green": 1}
        return max(self.matches, key=lambda m: rank[m.tier]).tier
    def has_any(self):
        return bool(self.matches)


class _FakeRuleMatch:
    def __init__(self, tier="Red"):
        self.rule_name = "fake_rule"
        self.tier = tier
        self.action = "Snaffle"
        self.match_location = "FileContentAsString"
        self.matched_pattern = "fake_pattern"
        self.matched_span = "matched_value"


class _FakeRuleEngine:
    def __init__(self, will_fire=False, tier="Red"):
        self._fire = will_fire
        self._tier = tier
    def evaluate(self, path, content):
        if not self._fire:
            return _FakeRuleVerdict([])
        return _FakeRuleVerdict([_FakeRuleMatch(tier=self._tier)])


def _no_parsers(path, content):
    return []


def _no_extractor(excerpt):
    return []


def test_silent_cascade_returns_no_tier_verdict():
    """Nothing fires → tier=None, source=none."""
    det = ContentDeterminer(
        rule_engine=_FakeRuleEngine(will_fire=False),
        run_parsers_fn=_no_parsers,
        extractor_fn=_no_extractor,
    )
    v = det.evaluate("/share/innocuous/file.txt", "plain content")
    assert v.tier is None
    assert v.source == "none"
    assert v.matches == []


def test_rule_engine_fires_short_circuits_extractor():
    """When rules fire, extractor isn't called — cascade ordering
    means rules take precedence."""
    extractor_call_count = {"n": 0}
    def counting_extractor(excerpt):
        extractor_call_count["n"] += 1
        return []
    det = ContentDeterminer(
        rule_engine=_FakeRuleEngine(will_fire=True, tier="Black"),
        run_parsers_fn=_no_parsers,
        extractor_fn=counting_extractor,
    )
    v = det.evaluate("/share/admin/id_rsa", "content")
    assert v.source == "rules"
    assert v.tier == "Black"
    assert extractor_call_count["n"] == 0


def test_parsers_take_precedence_over_rules():
    """Tier 1 (parsers) beats Tier 2 (rules) when both would fire."""
    rule_called = {"yes": False}
    class _SpyEngine(_FakeRuleEngine):
        def evaluate(self, path, content):
            rule_called["yes"] = True
            return super().evaluate(path, content)
    fields = [{"field_name": "password", "value": "x", "confidence": 0.85}]
    det = ContentDeterminer(
        rule_engine=_SpyEngine(will_fire=True),
        run_parsers_fn=lambda p, c: fields,
        extractor_fn=_no_extractor,
    )
    v = det.evaluate("/share/conf/db.yaml", "irrelevant")
    assert v.source == "parsers"
    assert v.tier == "Red"
    assert rule_called["yes"] is False  # rules never consulted


def test_extractor_fires_when_rules_silent():
    """If rules don't fire but extractor finds a credential format,
    promote the extractor verdict."""
    class _FakeCred:
        credential_type = "github_pat_classic"
        value = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        context = None
    det = ContentDeterminer(
        rule_engine=_FakeRuleEngine(will_fire=False),
        run_parsers_fn=_no_parsers,
        extractor_fn=lambda c: [_FakeCred()],
    )
    v = det.evaluate("/share/notes.md", "GITHUB_TOKEN=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")
    assert v.source == "extractor"
    assert v.tier == "Red"
    assert len(v.matches) == 1


def test_classifier_runs_only_when_opted_in():
    """``use_classifier=False`` (default) skips the LoRA stage."""
    classifier_called = {"yes": False}
    class _StubClassifier:
        def score(self, content):
            classifier_called["yes"] = True
            class _R: contains_secret = True
            return _R()
    det = ContentDeterminer(
        rule_engine=_FakeRuleEngine(will_fire=False),
        run_parsers_fn=_no_parsers,
        extractor_fn=_no_extractor,
        classifier=_StubClassifier(),
    )
    v = det.evaluate("/share/doc.txt", "content")
    assert v.source == "none"
    assert classifier_called["yes"] is False
    # Re-run with use_classifier=True; classifier should fire.
    classifier_called["yes"] = False
    v = det.evaluate("/share/doc.txt", "content", use_classifier=True)
    assert classifier_called["yes"] is True
    assert v.source == "classifier"
    assert v.tier == "Yellow"


def test_verdict_round_trips_to_dict():
    v = ContentVerdict(tier="Black", source="rules", matches=[{"k": 1}], confidence=0.95)
    d = v.to_dict()
    assert d == {"tier": "Black", "source": "rules", "matches": [{"k": 1}], "confidence": 0.95}
