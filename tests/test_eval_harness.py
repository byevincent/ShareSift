"""v0.22 eval harness — declarative scoring helpers."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


def test_basename_extracts_unc_path():
    import eval_harness as eh
    assert eh._basename(r"\\fileserver\share\Folder\Secret.txt") == "secret.txt"


def test_basename_extracts_windows_path():
    import eval_harness as eh
    assert eh._basename(r"C:\Users\admin\notes.md") == "notes.md"


def test_basename_extracts_unix_path():
    import eval_harness as eh
    assert eh._basename("/home/dev/.env") == ".env"


def test_dedup_penalty_demotes_repeated_filenames():
    """Files whose basename appears 9 times should rank ~3x lower
    than unique files at the same per-file evidence (sqrt(9)=3)."""
    import eval_harness as eh

    records = [
        {"path": "/share/unique_secret.txt",
         "path_probability": 0.8, "cascade_tier": None},
    ] + [
        {"path": f"/share/dir{i}/Install-Pkg.ps1",
         "path_probability": 0.8, "cascade_tier": None}
        for i in range(9)
    ]
    scores = eh._score_with_dedup_penalty(records)
    # Unique file: score = 0.8 / sqrt(1) = 0.8
    # Repeated: score = 0.8 / sqrt(9) = 0.267
    assert abs(scores[0] - 0.8) < 0.001
    assert abs(scores[1] - (0.8 / 3.0)) < 0.001
    # Unique file ranks above any of the repeated copies.
    assert scores[0] > max(scores[1:])


def test_green_tier_scores_zero():
    """v0.22: Green cascade tier should NOT contribute to ranking —
    it's informational, not a credential signal."""
    import eval_harness as eh

    records = [
        {"path": "/share/relay-green.ps1",
         "path_probability": 0.0, "cascade_tier": "Green"},
        {"path": "/share/yellow-tier.config",
         "path_probability": 0.0, "cascade_tier": "Yellow"},
    ]
    scores = eh._score_with_dedup_penalty(records)
    assert scores[0] == 0.0  # Green = 0
    assert scores[1] > 0.5   # Yellow = 0.65


def test_score_uses_max_of_path_and_cascade():
    """Per-file evidence is max(path_prob, cascade_pseudo_p)."""
    import eval_harness as eh
    records = [
        # High path prob, no cascade
        {"path": "/share/a.txt", "path_probability": 0.95, "cascade_tier": None},
        # Low path prob, Black cascade
        {"path": "/share/b.txt", "path_probability": 0.10, "cascade_tier": "Black"},
    ]
    scores = eh._score_with_dedup_penalty(records)
    # a's score = 0.95 / 1 = 0.95
    # b's score = 0.99 / 1 = 0.99
    assert scores[0] == pytest.approx(0.95, abs=0.001)
    assert scores[1] == pytest.approx(0.99, abs=0.001)
