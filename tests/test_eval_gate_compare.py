"""Eval-gate comparison: regression detection."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


def _write_baseline(path: Path, top10: float, recall: float) -> None:
    path.write_text(json.dumps({
        "headline": {
            "min_top_10_precision_across_primary": top10,
            "min_recall_across_primary": recall,
        }
    }), encoding="utf-8")


def test_compare_passes_on_equal_metrics(tmp_path, capsys):
    import eval_gate_compare as egc
    prev = tmp_path / "prev.json"
    curr = tmp_path / "curr.json"
    _write_baseline(prev, 0.2, 0.9)
    _write_baseline(curr, 0.2, 0.9)
    rc = egc.compare(prev, curr)
    assert rc == 0
    assert "::error::" not in capsys.readouterr().out


def test_compare_passes_on_improvement(tmp_path, capsys):
    import eval_gate_compare as egc
    prev = tmp_path / "prev.json"
    curr = tmp_path / "curr.json"
    _write_baseline(prev, 0.2, 0.9)
    _write_baseline(curr, 0.5, 0.95)
    assert egc.compare(prev, curr) == 0


def test_compare_fails_on_top10_regression(tmp_path, capsys):
    import eval_gate_compare as egc
    prev = tmp_path / "prev.json"
    curr = tmp_path / "curr.json"
    _write_baseline(prev, 0.2, 0.9)
    _write_baseline(curr, 0.1, 0.9)
    assert egc.compare(prev, curr) == 1
    captured = capsys.readouterr().out
    assert "::error::MIN top-10 precision regressed" in captured


def test_compare_fails_on_recall_regression(tmp_path, capsys):
    import eval_gate_compare as egc
    prev = tmp_path / "prev.json"
    curr = tmp_path / "curr.json"
    _write_baseline(prev, 0.2, 0.9)
    _write_baseline(curr, 0.2, 0.5)
    assert egc.compare(prev, curr) == 1
    captured = capsys.readouterr().out
    assert "::error::MIN recall regressed" in captured


def test_compare_passes_when_previous_baseline_empty(tmp_path):
    import eval_gate_compare as egc
    prev = tmp_path / "prev.json"
    curr = tmp_path / "curr.json"
    prev.write_text("{}", encoding="utf-8")
    _write_baseline(curr, 0.2, 0.9)
    # Empty baseline = floors of 0; current is non-zero, so no regression.
    assert egc.compare(prev, curr) == 0
