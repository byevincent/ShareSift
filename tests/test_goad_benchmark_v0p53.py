"""v0.53: smoke tests for the GOAD benchmark harness.

The harness orchestrates ShareSift + Snaffler against a live AD
lab, which we can't exercise in CI. These tests focus on the
pure-function pieces (UNC normalization, category mapping, TSV
parsing, scorecard computation) that determine whether the
harness produces a defensible scorecard once the lab is up.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


_HAS_HARNESS = importlib.util.find_spec("tools.goad_benchmark") is not None or (
    Path(__file__).parent.parent / "tools" / "goad_benchmark.py"
).exists()


@pytest.fixture(autouse=True)
def _add_tools_to_path():
    import sys
    tools = str(Path(__file__).parent.parent / "tools")
    if tools not in sys.path:
        sys.path.insert(0, tools)
    yield


def _harness():
    import goad_benchmark  # type: ignore[import-not-found]
    return goad_benchmark


class TestNormalizeUnc:
    def test_lowercases_host_and_share(self):
        h = _harness()
        assert h.normalize_unc(r"\\DC01\Public\file.txt") == r"\\dc01\public\file.txt"

    def test_preserves_case_in_subpath(self):
        h = _harness()
        norm = h.normalize_unc(r"\\fs01\Share\FOO\Bar.TXT")
        assert norm == r"\\fs01\share\FOO\Bar.TXT"

    def test_converts_forward_slashes(self):
        h = _harness()
        assert h.normalize_unc("//fs01/share/file.txt") == r"\\fs01\share\file.txt"

    def test_strips_whitespace(self):
        h = _harness()
        assert h.normalize_unc("  \\\\fs01\\share\\file.txt  ") == r"\\fs01\share\file.txt"


class TestCategorize:
    def test_gpp_cpassword(self):
        h = _harness()
        assert h.categorize("KeepGppPassword") == "gpp_cpassword"
        assert h.categorize("ShareSiftKeepGroupsXmlCpassword") == "gpp_cpassword"

    def test_keepass(self):
        h = _harness()
        assert h.categorize("KeepKeePassDatabase") == "keepass_db"

    def test_aws(self):
        h = _harness()
        assert h.categorize("KeepAwsCredentials") == "aws_credentials"
        # Snippet-based detection
        assert h.categorize("unknown", "AKIA1234567890ABCDEF") == "aws_credentials"

    def test_browser(self):
        h = _harness()
        assert h.categorize("KeepChromeLoginData") == "browser_password_store"
        assert h.categorize("KeepFirefoxLogins") == "browser_password_store"

    def test_sccm_naa(self):
        h = _harness()
        assert h.categorize("KeepSccmNaa") == "sccm_naa"

    def test_putty_ppk(self):
        h = _harness()
        assert h.categorize("KeepPuttyPpk") == "putty_ppk"

    def test_unknown_falls_to_generic_or_unsorted(self):
        h = _harness()
        assert h.categorize("KeepSomeRandomPasswordFile") == "generic_password_file"
        assert h.categorize("WhateverRule") == "unsorted_other"


class TestParseSnafflerTsv:
    def test_headerless_tsv(self, tmp_path):
        h = _harness()
        tsv = tmp_path / "snaffler.tsv"
        tsv.write_text(
            "Red\tKeepGppPassword\t\\\\dc01\\sysvol\\Policies\\Groups.xml\t"
            "2023-01-01\t1024\tcpassword=ABCDEF\n"
            "Yellow\tKeepBackupFile\t\\\\fs01\\share\\backup.zip\t"
            "2023-01-01\t10485760\t\n",
            encoding="utf-8",
        )
        hits = h.parse_snaffler_tsv(tsv)
        assert len(hits) == 2
        assert hits[0].category == "gpp_cpassword"
        assert hits[0].tier == "Red"
        assert hits[1].category == "backup_archive"

    def test_header_tsv(self, tmp_path):
        h = _harness()
        tsv = tmp_path / "snaffler.tsv"
        tsv.write_text(
            "severity\trule\tunc\tmodified\tsize\tsnippet\n"
            "Black\tKeepKeePassDatabase\t\\\\fs01\\share\\creds.kdbx\t"
            "2023-01-01\t2048\tkdbx header\n",
            encoding="utf-8",
        )
        hits = h.parse_snaffler_tsv(tsv)
        assert len(hits) == 1
        assert hits[0].category == "keepass_db"
        assert hits[0].tier == "Black"


class TestComputeScorecard:
    def test_overlap_and_unique_counts(self):
        h = _harness()
        ss_hits = [
            h.Hit(unc_path=r"\\fs01\share\a.txt", tier="Red",
                  rule_id="r1", category="gpp_cpassword"),
            h.Hit(unc_path=r"\\fs01\share\b.txt", tier="Yellow",
                  rule_id="r2", category="aws_credentials"),
        ]
        sn_hits = [
            h.Hit(unc_path=r"\\fs01\share\a.txt", tier="Red",
                  rule_id="r1", category="gpp_cpassword",
                  raw_source="snaffler"),
            h.Hit(unc_path=r"\\fs01\share\c.txt", tier="Yellow",
                  rule_id="r3", category="keepass_db",
                  raw_source="snaffler"),
        ]
        card = h.compute_scorecard(ss_hits, sn_hits)
        assert card.sharesift_total == 2
        assert card.snaffler_total == 2
        assert card.overlap == 1
        assert card.sharesift_only == 1
        assert card.snaffler_only == 1

    def test_per_category_breakdown(self):
        h = _harness()
        ss_hits = [
            h.Hit(unc_path=r"\\fs01\a.txt", tier="Red",
                  rule_id="r1", category="gpp_cpassword"),
            h.Hit(unc_path=r"\\fs01\b.txt", tier="Yellow",
                  rule_id="r2", category="gpp_cpassword"),
        ]
        sn_hits = [
            h.Hit(unc_path=r"\\fs01\a.txt", tier="Red",
                  rule_id="r1", category="gpp_cpassword",
                  raw_source="snaffler"),
        ]
        card = h.compute_scorecard(ss_hits, sn_hits)
        row = card.by_category["gpp_cpassword"]
        assert row["sharesift"] == 2
        assert row["snaffler"] == 1
        assert row["overlap"] == 1
        assert row["sharesift_only"] == 1


class TestRenderScorecardMd:
    def test_renders_overall_table(self):
        h = _harness()
        card = h.compute_scorecard([], [])
        md = h.render_scorecard_md(card, [], [])
        assert "## Overall" in md
        assert "ShareSift" in md
        assert "Snaffler" in md

    def test_includes_elapsed_when_set(self):
        h = _harness()
        ss_hits = [
            h.Hit(unc_path=r"\\fs01\a.txt", tier="Red",
                  rule_id="r1", category="gpp_cpassword"),
        ]
        card = h.compute_scorecard(
            ss_hits, [], sharesift_elapsed_s=42.5,
        )
        md = h.render_scorecard_md(card, ss_hits, [])
        assert "42.5" in md


class TestRenderScorecardJson:
    def test_emits_parseable_json(self):
        h = _harness()
        card = h.compute_scorecard([], [])
        text = h.render_scorecard_json(card)
        data = json.loads(text)
        assert data["sharesift_total"] == 0
        assert data["snaffler_total"] == 0
        assert "by_category" in data
