"""v0.25 plot_harness_history — text-mode chart of harness MIN trajectory."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


def test_bar_at_zero_is_all_empty():
    import plot_harness_history as plh
    assert plh._bar(0.0) == plh._BAR_EMPTY * plh._BAR_WIDTH


def test_bar_at_one_is_all_filled():
    import plot_harness_history as plh
    assert plh._bar(1.0) == plh._BAR_FILL * plh._BAR_WIDTH


def test_bar_at_half_is_split():
    import plot_harness_history as plh
    bar = plh._bar(0.5)
    assert bar.count(plh._BAR_FILL) == 5
    assert bar.count(plh._BAR_EMPTY) == 5


def test_render_handles_empty_history():
    import plot_harness_history as plh
    out = plh.render([])
    assert "no harness history" in out


def test_render_includes_each_release():
    import plot_harness_history as plh
    rows = [
        {"version": "v0.22.0", "min_top_10_precision_across_primary": 0.20,
         "min_recall_across_primary": 0.90},
        {"version": "v0.24.0", "min_top_10_precision_across_primary": 0.30,
         "min_recall_across_primary": 0.95},
    ]
    out = plh.render(rows)
    assert "v0.22.0" in out
    assert "v0.24.0" in out
    assert "0.20" in out
    assert "0.30" in out
    assert "0.90" in out
    assert "0.95" in out


def test_render_visualises_regression(tmp_path):
    """A drop between releases should show fewer filled cells."""
    import plot_harness_history as plh
    rows = [
        {"version": "good", "min_top_10_precision_across_primary": 0.80,
         "min_recall_across_primary": 0.90},
        {"version": "bad",  "min_top_10_precision_across_primary": 0.20,
         "min_recall_across_primary": 0.90},
    ]
    out = plh.render(rows)
    # Count filled cells per row — the second row should have fewer.
    lines = out.splitlines()
    good = next(l for l in lines if l.startswith("good"))
    bad = next(l for l in lines if l.startswith("bad"))
    assert good.count(plh._BAR_FILL) > bad.count(plh._BAR_FILL)
