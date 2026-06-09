"""v0.44 — filename-frequency dedup penalty tests.

Lifted from the v0.22 eval_harness logic into a shared
``sharesift.ranking`` module so production CLI applies the same
penalty operators were getting from the harness.
"""

from __future__ import annotations

import math

import pytest

from sharesift.ranking import (
    _TIER_PSEUDO_P,
    apply_dedup_penalty,
    basename,
    sort_by_rank,
)


class TestBasename:
    def test_posix_path(self):
        assert basename("/etc/passwd") == "passwd"

    def test_windows_path(self):
        assert basename(r"C:\Windows\System32\kernel32.dll") == "kernel32.dll"

    def test_unc_path(self):
        assert basename(r"\\10.0.0.5\Finance\secrets.kdbx") == "secrets.kdbx"

    def test_mixed_separators(self):
        assert basename(r"C:/Windows\Panther/unattend.xml") == "unattend.xml"

    def test_empty_string(self):
        assert basename("") == ""

    def test_no_separator(self):
        assert basename("loose-file.txt") == "loose-file.txt"


class TestDedupPenaltyMath:
    def test_single_occurrence_unchanged(self):
        records = [{"path": "/etc/passwd", "probability": 0.9, "tier": None}]
        apply_dedup_penalty(records)
        # divisor = sqrt(1) = 1; rank == probability
        assert records[0]["rank_score"] == pytest.approx(0.9)
        assert records[0]["filename_frequency"] == 1

    def test_four_occurrences_halved(self):
        """sqrt(4) = 2 → divisor 2 → 0.9 / 2 = 0.45."""
        records = [
            {"path": f"/dir{i}/foo.ps1", "probability": 0.9, "tier": None}
            for i in range(4)
        ]
        apply_dedup_penalty(records)
        for r in records:
            assert r["rank_score"] == pytest.approx(0.45)
            assert r["filename_frequency"] == 4

    def test_16_occurrences_quartered(self):
        records = [
            {"path": f"/dir{i}/dup.exe", "probability": 1.0, "tier": None}
            for i in range(16)
        ]
        apply_dedup_penalty(records)
        for r in records:
            assert r["rank_score"] == pytest.approx(0.25)

    def test_green_tier_does_not_contribute(self):
        """Green tier matches are informational. v0.21 MSF3 finding:
        Relay rules fire on every .ps1 / every .config — Green
        weight drowned credentials. Green stays at 0.0."""
        records = [
            {"path": "/share/relay-green.ps1",
             "probability": 0.0, "tier": "Green"},
        ]
        apply_dedup_penalty(records)
        assert records[0]["rank_score"] == 0.0

    def test_green_cascade_tier_zeros_out_high_probability(self):
        """v0.44 step 2 — the critical fix. When cascade_tier=Green
        (only Relay rules fired — RelayPsByExtension etc.) the path
        classifier's high probability should NOT win. Pre-v0.44
        step 2 the ``max()`` let path_probability=1.0 dominate
        cascade_tier=Green=0.0; this defeated the v0.21 lesson.

        Without this fix, MSF3 top-10 stays at 0.2 (Boxstarter
        Relay-matched .ps1 files flood). With it, top-10 jumps to
        0.8."""
        records = [
            {"path": "/share/installer.ps1",
             "probability": 1.0, "tier": "Black", "cascade_tier": "Green"},
        ]
        apply_dedup_penalty(records)
        # Green cascade → evidence is 0 regardless of probability
        assert records[0]["rank_score"] == 0.0

    def test_non_green_cascade_tier_still_max_of_signals(self):
        """The Green-zero short-circuit only fires for Green
        specifically. Yellow/Red/Black still use max-of-signals."""
        records = [
            {"path": "/a", "probability": 0.5, "cascade_tier": "Yellow"},
        ]
        apply_dedup_penalty(records)
        # Yellow pseudo (0.65) > probability (0.5) → max = 0.65
        assert records[0]["rank_score"] == pytest.approx(0.65)

    def test_tier_pseudo_p_used_when_probability_missing(self):
        """When probability isn't available (e.g. score-paths skipped),
        cascade tier acts as the per-file evidence signal."""
        records = [
            {"path": "/a", "probability": None, "cascade_tier": "Black"},
        ]
        apply_dedup_penalty(records)
        assert records[0]["rank_score"] == pytest.approx(_TIER_PSEUDO_P["Black"])

    def test_max_of_signals_used(self):
        """When probability AND tier disagree, the stronger signal
        wins (so high-confidence rules can boost a low-probability
        classifier signal)."""
        records = [
            {"path": "/a", "probability": 0.1, "tier": "Black"},
        ]
        apply_dedup_penalty(records)
        # Black tier pseudo-prob (0.99) > 0.1 → 0.99 / sqrt(1) = 0.99
        assert records[0]["rank_score"] == pytest.approx(0.99)

    def test_no_evidence_yields_zero(self):
        records = [{"path": "/a", "probability": None, "tier": None}]
        apply_dedup_penalty(records)
        assert records[0]["rank_score"] == 0.0


class TestBoxstarterReproduction:
    """Reproduce the failure mode that prompted v0.44: duplicate
    installer-script names dominating the top of the ranking.
    With the dedup penalty applied, unique credential filenames
    rise above the duplicates."""

    def test_unique_filename_beats_16x_duplicate(self):
        records = [
            # 16 Boxstarter installer copies — saturated classifier output
            {"path": f"/path{i}/Install-BoxstarterPackage.ps1",
             "probability": 1.0, "tier": "Black"}
            for i in range(16)
        ]
        # One real credential — moderate classifier score
        records.append({
            "path": "/share/admin/server.kdbx",
            "probability": 0.7, "tier": None,
        })

        apply_dedup_penalty(records)
        ranked = sort_by_rank(records)

        # The unique kdbx beats the duplicated installer:
        # installer rank ≈ 0.99 / sqrt(16) = 0.2475
        # kdbx rank      = 0.7  / sqrt(1)  = 0.7
        assert ranked[0]["path"] == "/share/admin/server.kdbx"


class TestSortByRank:
    def test_sorts_by_rank_score_descending(self):
        records = [
            {"path": "/a", "rank_score": 0.5},
            {"path": "/b", "rank_score": 0.9},
            {"path": "/c", "rank_score": 0.2},
        ]
        ranked = sort_by_rank(records)
        assert [r["path"] for r in ranked] == ["/b", "/a", "/c"]

    def test_falls_back_to_probability(self):
        """If rank_score wasn't computed, sort by probability."""
        records = [
            {"path": "/a", "probability": 0.5},
            {"path": "/b", "probability": 0.9},
        ]
        ranked = sort_by_rank(records)
        assert ranked[0]["path"] == "/b"

    def test_stable_on_tie(self):
        """Same rank_score → sort by path for determinism."""
        records = [
            {"path": "/c", "rank_score": 0.5},
            {"path": "/a", "rank_score": 0.5},
            {"path": "/b", "rank_score": 0.5},
        ]
        ranked = sort_by_rank(records)
        assert [r["path"] for r in ranked] == ["/a", "/b", "/c"]


class TestCmdScorePathsIntegration:
    """End-to-end: ``sharesift score-paths`` emits records with the
    v0.44 fields."""

    def test_score_paths_output_has_rank_fields(self, tmp_path, capsys):
        import io
        from sharesift.cli import main

        paths_in = (
            r"\\10.0.0.5\C$\test\unique.kdbx" + "\n"
            r"\\10.0.0.5\C$\foo\dup.ps1" + "\n"
            r"\\10.0.0.5\C$\bar\dup.ps1" + "\n"
            r"\\10.0.0.5\C$\baz\dup.ps1" + "\n"
        )
        input_file = tmp_path / "paths.txt"
        input_file.write_text(paths_in, encoding="utf-8")
        out_file = tmp_path / "scored.jsonl"

        rc = main([
            "score-paths",
            "--input", str(input_file),
            "--output", str(out_file),
        ])
        assert rc == 0

        import json
        records = [json.loads(l) for l in out_file.read_text().splitlines() if l.strip()]
        # Every record has the new fields
        for r in records:
            assert "rank_score" in r
            assert "filename_frequency" in r
        # The duplicate dup.ps1 paths have frequency 3
        dups = [r for r in records if r["path"].endswith("dup.ps1")]
        assert all(r["filename_frequency"] == 3 for r in dups)
        # The unique kdbx has frequency 1
        unique = [r for r in records if r["path"].endswith("unique.kdbx")]
        assert unique[0]["filename_frequency"] == 1
