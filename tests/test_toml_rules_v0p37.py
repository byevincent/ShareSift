"""v0.37 step 1 — Snaffler TOML rule format support.

Operators write Snaffler rules in TOML. ShareSift now accepts both
its native JSON format AND Snaffler's ``[[ClassifierRules]]`` TOML
schema, so a pentester can drop a Snaffler-formatted rule file into
the rules directory without conversion.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sharesift.content_rules import (
    ContentRuleEngine,
    _load_rule_records,
    _snaffler_toml_to_record,
    get_default_engine,
)


def _write_toml(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


# --- _snaffler_toml_to_record pure conversion ----------------------


class TestSnafflerTomlToRecord:
    def test_pascalcase_keys_mapped_to_snake(self):
        block = {
            "RuleName": "KeepFoo",
            "Triage": "Black",
            "MatchAction": "Snaffle",
            "MatchLocation": "FileExtension",
            "WordListType": "Exact",
            "WordList": ["\\.foo"],
            "Description": "Foo files are dangerous",
            "EnumerationScope": "FileEnumeration",
        }
        rec = _snaffler_toml_to_record(block)
        assert rec == {
            "rule_name": "KeepFoo",
            "triage": "Black",
            "match_action": "Snaffle",
            "match_location": "FileExtension",
            "wordlist_type": "Exact",
            "wordlist": ["\\.foo"],
            "description": "Foo files are dangerous",
            "enumeration_scope": "FileEnumeration",
            "source_file": "",
        }

    def test_missing_optional_fields_default_safely(self):
        block = {"RuleName": "Minimal", "Triage": "Yellow",
                 "MatchAction": "Snaffle", "MatchLocation": "FileName",
                 "WordList": ["foo"]}
        rec = _snaffler_toml_to_record(block)
        assert rec["wordlist_type"] == "Exact"  # default
        assert rec["description"] == ""

    def test_matchlength_field_is_ignored(self):
        """``MatchLength`` is Snaffler-specific context sizing — we
        don't model it. It shouldn't end up in the record."""
        block = {
            "RuleName": "X", "Triage": "Red",
            "MatchAction": "Snaffle", "MatchLocation": "FileExtension",
            "WordListType": "Exact", "WordList": ["\\.x"],
            "MatchLength": 256,
        }
        rec = _snaffler_toml_to_record(block)
        assert "MatchLength" not in rec
        assert "match_length" not in rec


# --- _load_rule_records dispatch -----------------------------------


class TestLoadRuleRecords:
    def test_loads_json_rule_file(self, tmp_path):
        f = tmp_path / "rules.json"
        f.write_text(
            '{"rules": [{"rule_name": "X", "triage": "Red", '
            '"match_action": "Snaffle", "match_location": "FileExtension", '
            '"wordlist_type": "Exact", "wordlist": ["\\\\.x"]}]}'
        )
        records = _load_rule_records(f)
        assert len(records) == 1
        assert records[0]["rule_name"] == "X"

    def test_loads_single_rule_toml(self, tmp_path):
        f = _write_toml(tmp_path / "single.toml", """
[[ClassifierRules]]
RuleName = "TomlOne"
Triage = "Black"
MatchAction = "Snaffle"
MatchLocation = "FileExtension"
WordListType = "Exact"
WordList = ["\\\\.toml1"]
Description = "single-rule TOML"
""")
        records = _load_rule_records(f)
        assert len(records) == 1
        assert records[0]["rule_name"] == "TomlOne"
        assert records[0]["triage"] == "Black"

    def test_loads_multi_rule_toml(self, tmp_path):
        f = _write_toml(tmp_path / "multi.toml", """
[[ClassifierRules]]
RuleName = "TomlA"
Triage = "Black"
MatchAction = "Snaffle"
MatchLocation = "FileExtension"
WordListType = "Exact"
WordList = ["\\\\.a"]

[[ClassifierRules]]
RuleName = "TomlB"
Triage = "Yellow"
MatchAction = "Snaffle"
MatchLocation = "FileExtension"
WordListType = "Exact"
WordList = ["\\\\.b"]
""")
        records = _load_rule_records(f)
        assert len(records) == 2
        names = {r["rule_name"] for r in records}
        assert names == {"TomlA", "TomlB"}

    def test_empty_toml_returns_empty_list(self, tmp_path):
        f = _write_toml(tmp_path / "empty.toml", "")
        assert _load_rule_records(f) == []

    def test_unsupported_extension_raises(self, tmp_path):
        f = tmp_path / "rules.yaml"
        f.write_text("rules: []")
        with pytest.raises(ValueError, match="unsupported rule file extension"):
            _load_rule_records(f)


# --- End-to-end engine integration ---------------------------------


class TestEngineLoadsToml:
    def test_engine_loads_toml_and_fires_on_match(self, tmp_path):
        f = _write_toml(tmp_path / "rules.toml", """
[[ClassifierRules]]
RuleName = "KeepKdbx"
Triage = "Black"
MatchAction = "Snaffle"
MatchLocation = "FileExtension"
WordListType = "Exact"
WordList = ["\\\\.kdbx"]
""")
        engine = ContentRuleEngine(rules_json_paths=[f])
        v = engine.evaluate("/share/secrets.kdbx", content=None)
        hits = [m for m in v.matches if m.rule_name == "KeepKdbx"]
        assert len(hits) == 1
        assert hits[0].tier == "Black"

    def test_engine_loads_snaffler_upstream_file_unchanged(self, tmp_path):
        """A pentester's existing Snaffler rule TOML drops straight in
        without modification."""
        upstream = Path(
            "/tmp/snaffler_upstream/Snaffler/SnaffRules/DefaultRules/"
            "FileRules/Keep/UserFiles/PassMgrs/KeepPassMgrsByExtension.toml"
        )
        if not upstream.exists():
            pytest.skip("upstream Snaffler clone not available")
        engine = ContentRuleEngine(rules_json_paths=[upstream])
        v = engine.evaluate("/home/alice/secrets.kdbx", content=None)
        assert any(m.rule_name == "KeepPassMgrsByExtension" for m in v.matches)

    def test_engine_loads_json_and_toml_in_same_construction(self, tmp_path):
        json_rules = tmp_path / "json.json"
        json_rules.write_text(
            '{"rules": [{"rule_name": "JsonRule", "triage": "Red", '
            '"match_action": "Snaffle", "match_location": "FileExtension", '
            '"wordlist_type": "Exact", "wordlist": ["\\\\.j"]}]}'
        )
        toml_rules = _write_toml(tmp_path / "toml.toml", """
[[ClassifierRules]]
RuleName = "TomlRule"
Triage = "Yellow"
MatchAction = "Snaffle"
MatchLocation = "FileExtension"
WordListType = "Exact"
WordList = ["\\\\.t"]
""")
        engine = ContentRuleEngine(rules_json_paths=[json_rules, toml_rules])
        names = {r.rule_name for r in engine._compiled}
        assert "JsonRule" in names
        assert "TomlRule" in names


class TestDefaultEngineUnchanged:
    """Production engine still loads the 144 rules from
    snaffler_default.json + extra_rules.json — TOML support is purely
    additive and doesn't change the default rule set."""

    def test_default_engine_rule_count_holds(self):
        # Clear the lru_cache to force a fresh load
        get_default_engine.cache_clear()
        engine = get_default_engine()
        # 88 ported Snaffler rules - 13 Discard rules = 75 active
        # (Discard rules are filtered during compilation). + 56 extras
        # net of filtered. Don't assert exact number — Discard
        # filtering + future additions move it. Just assert > 100.
        assert len(engine) > 100
