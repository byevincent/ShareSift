"""Tests for the Phase-2 path-classifier code.

Coverage:
* featurization shape + invariants + hand-feature correctness
* ``is_juicy`` adapter handles both label conventions
* training smoke test on a tiny synthetic fixture (verifies the
  pipeline runs end-to-end and produces a working model)
* save/load round-trip preserves predictions
* evaluation metrics computed correctly on a deterministic fixture
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from src.eval.model.evaluate import evaluate
from sharesift.features import (
    HAND_FEATURE_NAMES,
    N_HAND_FEATURES,
    N_HASH_FEATURES,
    featurize,
    hand_features,
    is_juicy,
)
from src.eval.model.train import (
    TrainConfig,
    load_records,
    save_model,
    train_model,
)


# --- featurization ----------------------------------------------------------


def test_featurize_combined_shape():
    """Char-ngram hash matrix + hand-features stacked horizontally."""
    paths = [r"\\fs\share\foo.txt", "/etc/shadow", r"\\dc\NETLOGON\map.bat"]
    X = featurize(paths)
    assert X.shape == (3, N_HASH_FEATURES + N_HAND_FEATURES)
    # Non-negative — LightGBM requirement.
    assert X.min() >= 0


def test_hand_features_unc_path():
    p = r"\\HQFS1\Shared\Finance\report.xlsx"
    feats = hand_features(p)
    assert feats.shape == (N_HAND_FEATURES,)
    fdict = dict(zip(HAND_FEATURE_NAMES, feats))
    assert fdict["is_unc_path"] == 1.0
    assert fdict["is_linux_path"] == 0.0
    assert fdict["has_extension"] == 1.0
    assert fdict["extension_length"] == 4.0  # "xlsx"
    assert fdict["num_dots_in_basename"] == 1.0
    assert fdict["path_length"] == float(len(p))


def test_hand_features_linux_path():
    p = "/home/jsmith/.ssh/id_rsa"
    feats = hand_features(p)
    fdict = dict(zip(HAND_FEATURE_NAMES, feats))
    assert fdict["is_unc_path"] == 0.0
    assert fdict["is_linux_path"] == 1.0
    assert fdict["has_extension"] == 0.0
    assert fdict["extension_length"] == 0.0
    assert fdict["path_depth"] == 4.0  # 4 forward slashes


def test_hand_features_extensionless_basename():
    """Files without an extension (NTDS.dit, SAM, etc.) should report
    has_extension correctly."""
    # SAM hive — extensionless registry hive basename.
    feats = hand_features(r"\\dc\C$\Windows\System32\config\SAM")
    fdict = dict(zip(HAND_FEATURE_NAMES, feats))
    assert fdict["has_extension"] == 0.0
    # NTDS.dit — extensioned, dot present.
    feats2 = hand_features(r"\\dc\C$\Windows\NTDS\NTDS.dit")
    fdict2 = dict(zip(HAND_FEATURE_NAMES, feats2))
    assert fdict2["has_extension"] == 1.0
    assert fdict2["extension_length"] == 3.0


def test_hand_features_dot_prefix_basename():
    """Linux dotfiles like .env — the leading dot is NOT an extension
    separator (no chars after, or the whole name starts with dot)."""
    feats = hand_features("/home/user/.env")
    fdict = dict(zip(HAND_FEATURE_NAMES, feats))
    # basename is ".env", rfind('.')=0 → dot_idx=0, has_ext=(0>0)=False.
    # This is the desired behavior for dotfiles.
    assert fdict["has_extension"] == 0.0


# --- is_juicy adapter -------------------------------------------------------


def test_is_juicy_synthetic_convention():
    """Synthetic uses boolean 'juicy' field."""
    assert is_juicy({"juicy": True}) is True
    assert is_juicy({"juicy": False}) is False


def test_is_juicy_eval_convention():
    """Eval uses string 'label' field."""
    assert is_juicy({"label": "juicy"}) is True
    assert is_juicy({"label": "not_juicy"}) is False


def test_is_juicy_missing_field_raises():
    with pytest.raises(ValueError):
        is_juicy({"path": "x"})


# --- training + evaluation end-to-end --------------------------------------


def _toy_records():
    """A small but discriminable fixture: id_rsa-family paths are juicy,
    /var/log/*.log paths are not. LightGBM should easily separate."""
    juicy_paths = [
        r"\\fs\Users\alice\.ssh\id_rsa",
        r"\\fs\Users\bob\.ssh\id_ed25519",
        r"\\fs\Users\carol\.ssh\id_ecdsa",
        "/home/dpark/.ssh/id_rsa",
        "/home/elin/.ssh/id_dsa",
        "/root/.ssh/id_rsa",
        r"\\dc\NETLOGON\map.bat",
        r"\\dc\SYSVOL\corp\Policies\Groups.xml",
        "/etc/shadow",
        "/etc/ssl/private/server.pem",
    ]
    not_juicy_paths = [
        "/var/log/syslog",
        "/var/log/auth.log",
        "/var/log/messages",
        "/var/log/dmesg",
        r"\\fs\Public\Photos\team_lunch.jpg",
        r"\\fs\Public\Marketing\logo.png",
        r"\\fs\Public\Reports\Q4.pdf",
        r"\\fs\Public\Wallpapers\nature.jpg",
        "/usr/share/fonts/Inter-Regular.ttf",
        "/usr/share/icons/hicolor/64x64/apps/firefox.png",
    ]
    records = []
    for p in juicy_paths:
        records.append({"path": p, "juicy": True, "why": "x"})
    for p in not_juicy_paths:
        records.append({"path": p, "juicy": False, "why": "x"})
    return records


def test_training_smoke():
    """End-to-end: featurize → fit → predict on the toy fixture.
    LightGBM should achieve perfect separation on this trivial set.

    ``min_child_samples=2`` lets the tree split this tiny dataset; the
    default ``min_child_samples=20`` would refuse to split a 20-record
    fixture and produce a constant predictor (PR-AUC == 0.5).
    """
    records = _toy_records()
    model = train_model(
        records, TrainConfig(n_estimators=50, min_child_samples=2)
    )
    report = evaluate(model, records)
    # On a separable training set, the model should fit it perfectly.
    assert report.pr_auc > 0.95, f"got PR-AUC={report.pr_auc:.3f}"
    assert report.best_f1 > 0.95, f"got F1={report.best_f1:.3f}"


def test_save_load_round_trip_preserves_predictions(tmp_path: Path):
    """Save + reload should reproduce the same prediction probabilities."""
    import joblib
    records = _toy_records()
    model = train_model(
        records, TrainConfig(n_estimators=20, min_child_samples=2)
    )

    save_model(
        model,
        tmp_path / "model_dir",
        records,
        TrainConfig(n_estimators=20, min_child_samples=2),
        Path("toy"),
    )
    reloaded = joblib.load(tmp_path / "model_dir" / "model.joblib")

    # Same predictions before and after.
    X = featurize([r["path"] for r in records])
    original_probs = model.predict_proba(X)[:, 1]
    reloaded_probs = reloaded.predict_proba(X)[:, 1]
    np.testing.assert_array_almost_equal(original_probs, reloaded_probs)

    # Metadata should exist and be parseable.
    meta = json.loads((tmp_path / "model_dir" / "metadata.json").read_text())
    assert meta["train_record_count"] == len(records)
    assert "config" in meta
    assert "features" in meta


def test_load_records_jsonl(tmp_path: Path):
    p = tmp_path / "x.jsonl"
    p.write_text(
        '{"path": "/a", "juicy": true, "why": "x"}\n'
        '{"path": "/b", "juicy": false, "why": "y"}\n'
        "\n",  # blank line tolerated
        encoding="utf-8",
    )
    recs = load_records(p)
    assert len(recs) == 2
    assert recs[0]["path"] == "/a"


# --- evaluation metrics ----------------------------------------------------


def test_evaluate_per_category_breakdown():
    """Per-category recall should aggregate over juicy records only."""
    records = _toy_records()
    # Mock categories in for the eval pathway.
    for r in records[:5]:
        r["category"] = "ssh_credentials"
    for r in records[5:10]:
        r["category"] = "windows_credential_artifacts"

    model = train_model(
        records, TrainConfig(n_estimators=50, min_child_samples=2)
    )
    report = evaluate(model, records)
    # Both juicy categories should appear.
    assert "ssh_credentials" in report.per_category_recall
    assert "windows_credential_artifacts" in report.per_category_recall
    # not_juicy records should NOT appear in per_category_recall.
    correct, total = report.per_category_recall["ssh_credentials"]
    assert total == 5
