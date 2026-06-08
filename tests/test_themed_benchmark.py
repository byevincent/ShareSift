"""v0.19 themed-benchmark tooling — builder + scorer + taxonomy."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from src.eval.themed_taxonomy import FailureLabel, TriagedMiss, all_labels


# --- taxonomy ---------------------------------------------------------------


def test_failure_label_vocabulary_is_fixed():
    """The 6 labels in the plan are the entire vocabulary."""
    assert set(all_labels()) == {
        "naming-ood",
        "content-ood",
        "template-mismatch",
        "extraction-missing",
        "calibration-drift",
        "parser-gap",
    }


def test_triaged_miss_serializes_to_dict():
    m = TriagedMiss(
        path="/share/finance/payroll_keys_0001.xlsx",
        label=FailureLabel.NAMING_OOD,
        note="filename token not in training data",
        salted_credential_type="swift_iban",
        path_probability=0.04,
        path_tier=None,
    )
    d = m.to_dict()
    assert d["label"] == "naming-ood"
    assert d["path_probability"] == 0.04


# --- builder ----------------------------------------------------------------


def _minimal_theme_config() -> dict:
    return {
        "theme": "smoke",
        "n_files": 8,
        "salt_density": 0.5,  # half salted for predictability
        "seed": 7,
        "file_naming": {
            "juicy_tokens": ["secret_key", "admin_password"],
            "benign_tokens": ["meeting_notes", "agenda"],
        },
        "extensions": {
            "documents": [".docx", ".pdf"],
            "configs": [".env", ".yaml"],
        },
        "directories": ["d1", "d2"],
        "credential_types": {
            "api_key": 0.6,
            "db_password": 0.4,
        },
    }


def test_build_share_emits_expected_structure(tmp_path):
    import build_themed_share as bts

    records = bts.build_share(_minimal_theme_config(), tmp_path)

    assert len(records) == 8
    for r in records:
        assert Path(r["local_path"]).exists(), f"missing file: {r['local_path']}"
        assert r["source_box"] == "smoke"
        # Salted ↔ tier_label/cred type assignment is consistent.
        if r["salted"]:
            assert r["salted_credential_type"] is not None
            assert r["tier_label"] is not None
        else:
            assert r["salted_credential_type"] is None
            assert r["tier_label"] is None


def test_build_share_is_deterministic_with_seed(tmp_path):
    import build_themed_share as bts

    cfg = _minimal_theme_config()
    r1 = bts.build_share(cfg, tmp_path / "a")
    r2 = bts.build_share(cfg, tmp_path / "b")
    assert [(x["filename_token"], x["salted"]) for x in r1] == [
        (y["filename_token"], y["salted"]) for y in r2
    ]


def test_build_share_writes_credentials_into_salted_files(tmp_path):
    import build_themed_share as bts

    records = bts.build_share(_minimal_theme_config(), tmp_path)
    salted = [r for r in records if r["salted"]]
    for r in salted:
        content = Path(r["local_path"]).read_text(encoding="utf-8")
        ct = r["salted_credential_type"]
        # Stub credential includes the theme name in its token.
        assert "smoke" in content, (
            f"salted file {r['local_path']} ({ct}) missing theme marker"
        )


# --- scorer -----------------------------------------------------------------


def test_score_emits_card_with_required_fields(tmp_path):
    import build_themed_share as bts
    import score_themed_run as scorer

    cfg = _minimal_theme_config()
    records = bts.build_share(cfg, tmp_path)
    manifest_path = tmp_path / "manifest.jsonl"
    with manifest_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    # Synthesize a fake `score-paths` output: flag the salted files,
    # miss the unsalted ones. Simulates a perfect classifier so the
    # metrics card has all fields populated.
    scores = []
    for r in records:
        scores.append({
            "path": r["local_path"],
            "probability": 0.95 if r["salted"] else 0.05,
            "tier": "Red" if r["salted"] else None,
        })
    scores_path = tmp_path / "scores.jsonl"
    with scores_path.open("w", encoding="utf-8") as f:
        for s in scores:
            f.write(json.dumps(s) + "\n")

    card = scorer.score("smoke", manifest_path, scores_path)
    assert card["theme"] == "smoke"
    assert card["n_files"] == 8
    assert card["recall_on_salted_overall"] == 1.0  # perfect synthetic
    assert "top_10" in card["top_k_precision"]
    assert "tier_distribution" in card
    assert "bottom_misses" in card
    assert card["bottom_misses"] == []  # nothing missed


def test_score_surfaces_bottom_misses(tmp_path):
    import build_themed_share as bts
    import score_themed_run as scorer

    cfg = _minimal_theme_config()
    records = bts.build_share(cfg, tmp_path)
    manifest_path = tmp_path / "manifest.jsonl"
    with manifest_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    # Now MISS every salted file (worst-case classifier).
    scores = []
    for r in records:
        scores.append({
            "path": r["local_path"],
            "probability": 0.0,
            "tier": None,
        })
    scores_path = tmp_path / "scores.jsonl"
    with scores_path.open("w", encoding="utf-8") as f:
        for s in scores:
            f.write(json.dumps(s) + "\n")

    card = scorer.score("smoke", manifest_path, scores_path)
    assert card["recall_on_salted_overall"] == 0.0
    assert len(card["bottom_misses"]) <= 5
    n_salted = sum(1 for r in records if r["salted"])
    assert len(card["bottom_misses"]) == min(5, n_salted)
