"""v0.45 — verifier-first sort tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sharesift.ranking import live_marker, sort_verifier_first


class TestSortVerifierFirst:
    def test_passed_beats_failed_beats_inconclusive(self):
        records = [
            {"path": "/skipped", "verification_status": "skipped"},
            {"path": "/passed",  "verification_status": "passed"},
            {"path": "/failed",  "verification_status": "failed"},
            {"path": "/inconclusive", "verification_status": "inconclusive"},
        ]
        ranked = sort_verifier_first(records)
        assert [r["path"] for r in ranked] == [
            "/passed", "/failed", "/inconclusive", "/skipped",
        ]

    def test_verified_beats_higher_tier_without_verification(self):
        """A verified-passed Yellow beats an unverified Black —
        verification is a stronger signal than tier."""
        records = [
            {"path": "/unverified-black", "content_tier": "Black"},
            {"path": "/verified-yellow",
             "content_tier": "Yellow", "verification_status": "passed"},
        ]
        ranked = sort_verifier_first(records)
        assert ranked[0]["path"] == "/verified-yellow"

    def test_within_same_verification_sort_by_tier(self):
        records = [
            {"path": "/yellow", "content_tier": "Yellow",
             "verification_status": "passed"},
            {"path": "/black",  "content_tier": "Black",
             "verification_status": "passed"},
            {"path": "/red",    "content_tier": "Red",
             "verification_status": "passed"},
        ]
        ranked = sort_verifier_first(records)
        assert [r["path"] for r in ranked] == ["/black", "/red", "/yellow"]

    def test_within_same_tier_sort_by_rank_score(self):
        records = [
            {"path": "/low",  "content_tier": "Red", "rank_score": 0.3},
            {"path": "/high", "content_tier": "Red", "rank_score": 0.9},
            {"path": "/mid",  "content_tier": "Red", "rank_score": 0.6},
        ]
        ranked = sort_verifier_first(records)
        assert [r["path"] for r in ranked] == ["/high", "/mid", "/low"]

    def test_falls_back_to_probability_when_no_rank_score(self):
        records = [
            {"path": "/a", "probability": 0.3},
            {"path": "/b", "probability": 0.9},
        ]
        ranked = sort_verifier_first(records)
        assert ranked[0]["path"] == "/b"

    def test_path_tier_used_when_content_tier_missing(self):
        """A Stage-1-only record (no content stage) ranks by
        path_tier instead of content_tier."""
        records = [
            {"path": "/a", "path_tier": "Black"},
            {"path": "/b", "path_tier": "Yellow"},
        ]
        ranked = sort_verifier_first(records)
        assert ranked[0]["path"] == "/a"

    def test_mixed_verified_unverified_works(self):
        """Verified records surface first; unverified land below
        sorted by tier + rank among themselves."""
        records = [
            {"path": "/unv-black", "content_tier": "Black"},
            {"path": "/passed-yellow", "content_tier": "Yellow",
             "verification_status": "passed"},
            {"path": "/unv-red", "content_tier": "Red"},
            {"path": "/failed-red", "content_tier": "Red",
             "verification_status": "failed"},
        ]
        ranked = sort_verifier_first(records)
        assert [r["path"] for r in ranked] == [
            "/passed-yellow",  # passed
            "/failed-red",     # failed
            "/unv-black",      # no verification but Black
            "/unv-red",        # no verification, Red
        ]


class TestLiveMarker:
    def test_passed_yields_LIVE(self):
        assert live_marker({"verification_status": "passed"}) == "[LIVE]"

    def test_failed_yields_FAIL(self):
        assert live_marker({"verification_status": "failed"}) == "[FAIL]"

    def test_inconclusive_yields_empty(self):
        assert live_marker({"verification_status": "inconclusive"}) == ""

    def test_skipped_yields_empty(self):
        assert live_marker({"verification_status": "skipped"}) == ""

    def test_missing_yields_empty(self):
        assert live_marker({}) == ""


class TestSortCliSubcommand:
    """v0.45: ``sharesift sort`` re-sorts a JSONL file by the
    verifier-first key."""

    def _write_jsonl(self, path: Path, records: list[dict]) -> Path:
        with path.open("w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        return path

    def test_sort_subcommand_reorders_records(self, tmp_path):
        from sharesift.cli import main

        src = self._write_jsonl(tmp_path / "hits.jsonl", [
            {"path": "/skipped", "verification_status": "skipped",
             "content_tier": "Black"},
            {"path": "/passed", "verification_status": "passed",
             "content_tier": "Yellow"},
            {"path": "/failed", "verification_status": "failed",
             "content_tier": "Red"},
        ])
        out_path = tmp_path / "sorted.jsonl"
        rc = main(["sort", "--input", str(src), "--output", str(out_path)])
        assert rc == 0

        sorted_records = [
            json.loads(line)
            for line in out_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert [r["path"] for r in sorted_records] == [
            "/passed", "/failed", "/skipped",
        ]

    def test_sort_subcommand_via_stdin(self, tmp_path, capsys, monkeypatch):
        import io
        from sharesift.cli import main

        payload = (
            json.dumps({"path": "/a", "verification_status": "skipped"}) + "\n"
            + json.dumps({"path": "/b", "verification_status": "passed"}) + "\n"
        )
        monkeypatch.setattr("sys.stdin", io.StringIO(payload))

        rc = main(["sort", "--stdin"])
        assert rc == 0

        out = capsys.readouterr().out
        first_path = json.loads(out.splitlines()[0])["path"]
        assert first_path == "/b"


class TestToSnafflerTsvSortIntegration:
    """``sharesift to-snaffler-tsv`` applies verifier-first sort by
    default; ``--no-sort`` preserves input order."""

    def _hits(self, path: Path, records: list[dict]) -> Path:
        with path.open("w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        return path

    def test_default_sorts_verified_first(self, tmp_path):
        from sharesift.cli import main

        src = self._hits(tmp_path / "hits.jsonl", [
            {"path": "/x.cfg", "path_tier": "Black"},
            {"path": "/y.cfg", "path_tier": "Red",
             "verification_status": "passed"},
        ])
        out_path = tmp_path / "out.tsv"
        rc = main([
            "to-snaffler-tsv",
            "--input", str(src),
            "--output", str(out_path),
        ])
        assert rc == 0
        lines = [l for l in out_path.read_text().splitlines() if l]
        # Verified-passed record appears first
        assert "/y.cfg" in lines[0]
        assert "/x.cfg" in lines[1]

    def test_no_sort_preserves_input_order(self, tmp_path):
        from sharesift.cli import main

        src = self._hits(tmp_path / "hits.jsonl", [
            {"path": "/x.cfg", "path_tier": "Black"},
            {"path": "/y.cfg", "path_tier": "Red",
             "verification_status": "passed"},
        ])
        out_path = tmp_path / "out.tsv"
        rc = main([
            "to-snaffler-tsv",
            "--input", str(src),
            "--output", str(out_path),
            "--no-sort",
        ])
        assert rc == 0
        lines = [l for l in out_path.read_text().splitlines() if l]
        # Input order preserved
        assert "/x.cfg" in lines[0]
        assert "/y.cfg" in lines[1]
