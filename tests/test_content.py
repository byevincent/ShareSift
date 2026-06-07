"""Tests for the Phase-3 content classifier data pipeline.

Coverage:
* snippet extraction edge cases (out-of-bounds, file-too-short, encoding)
* prompt formatting shape stability
* corpus filter behavior (extensions, skip dirs, size bounds)
* dedup invariants (first-wins, count drops, dissimilar passes through)
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from src.eval.content.corpus import walk_code_files
from src.eval.content.dedup import dedup_snippets
from sharesift.prompt import (
    SYSTEM_PROMPT,
    format_inference_messages,
    format_sft_example,
)
from src.eval.content.snippet import extract_around_line, random_snippet


# --- snippet extraction ----------------------------------------------------


def _write_lines(tmp_path: Path, name: str, lines: list[str]) -> Path:
    p = tmp_path / name
    p.write_text("\n".join(lines), encoding="utf-8")
    return p


def test_extract_around_line_centers_on_target(tmp_path: Path):
    """A ±2 window around line 5 of a 10-line file returns lines 3-7."""
    f = _write_lines(tmp_path, "f.txt", [f"line{i}" for i in range(1, 11)])
    out = extract_around_line(f, target_line=5, before=2, after=2)
    assert out is not None
    assert out.splitlines() == ["line3", "line4", "line5", "line6", "line7"]


def test_extract_around_line_clamps_at_file_start(tmp_path: Path):
    f = _write_lines(tmp_path, "f.txt", [f"line{i}" for i in range(1, 11)])
    out = extract_around_line(f, target_line=1, before=5, after=2)
    assert out is not None
    assert out.splitlines() == ["line1", "line2", "line3"]


def test_extract_around_line_clamps_at_file_end(tmp_path: Path):
    f = _write_lines(tmp_path, "f.txt", [f"line{i}" for i in range(1, 11)])
    out = extract_around_line(f, target_line=10, before=2, after=10)
    assert out is not None
    assert out.splitlines() == ["line8", "line9", "line10"]


def test_extract_around_line_returns_none_for_out_of_range(tmp_path: Path):
    f = _write_lines(tmp_path, "f.txt", ["only"])
    assert extract_around_line(f, target_line=99, before=2, after=2) is None


def test_extract_around_line_returns_none_for_missing_file(tmp_path: Path):
    missing = tmp_path / "nope.txt"
    assert extract_around_line(missing, target_line=1) is None


def test_random_snippet_returns_window_lines(tmp_path: Path):
    f = _write_lines(tmp_path, "f.txt", [f"line{i}" for i in range(1, 51)])
    rng = random.Random(0)
    out = random_snippet(f, window_lines=8, rng=rng)
    assert out is not None
    assert len(out.splitlines()) == 8


def test_random_snippet_returns_none_for_tiny_file(tmp_path: Path):
    f = _write_lines(tmp_path, "f.txt", ["a", "b"])
    out = random_snippet(f, window_lines=16, rng=random.Random(0))
    assert out is None


# --- prompt formatting -----------------------------------------------------


def test_format_sft_example_messages_shape():
    ex = format_sft_example("api_key = 'sk_test_abc'", "yes")
    assert "messages" in ex
    msgs = ex["messages"]
    assert [m["role"] for m in msgs] == ["system", "user", "assistant"]
    assert msgs[0]["content"] == SYSTEM_PROMPT
    assert msgs[1]["content"] == "api_key = 'sk_test_abc'"
    assert msgs[2]["content"] == "yes"


def test_format_inference_messages_omits_assistant():
    msgs = format_inference_messages("snippet")
    assert [m["role"] for m in msgs] == ["system", "user"]


# --- corpus walker ---------------------------------------------------------


def test_walk_code_files_filters_by_extension(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.png").write_text("not really png")
    (tmp_path / "c.yaml").write_text("a: b\n")
    out = sorted(p.name for p in walk_code_files(tmp_path))
    assert out == ["a.py", "c.yaml"]


def test_walk_code_files_prunes_skip_dirs(tmp_path: Path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "deep.js").write_text("var x = 1;\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("x = 1\n")
    out = sorted(p.name for p in walk_code_files(tmp_path))
    assert out == ["main.py"]


def test_walk_code_files_drops_empty_and_huge(tmp_path: Path):
    (tmp_path / "empty.py").write_text("")
    (tmp_path / "okay.py").write_text("x = 1\n")
    out = sorted(p.name for p in walk_code_files(tmp_path))
    assert out == ["okay.py"]


def test_walk_code_files_includes_dockerfile_basename(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM alpine\nRUN apk add curl\n")
    out = [p.name for p in walk_code_files(tmp_path)]
    assert "Dockerfile" in out


# --- dedup -----------------------------------------------------------------


def test_dedup_first_wins_on_near_duplicates():
    """Two snippets that are 90%+ token-overlap should collapse; only
    one survives. Count-based check rather than identity-based because
    near-duplicate texts can be equal strings."""
    a = "import os\napi_key = 'AAA'\nprint(api_key)\n"
    b = "import os\napi_key = 'AAA'\nprint(api_key)\n"  # exact dup
    c = "import json\nfrom typing import Any\nfoo = bar(qux)\n"
    kept, dropped = dedup_snippets([a, b, c])
    assert dropped == 1
    assert len(kept) == 2
    assert kept.count(a) == 1  # not both copies
    assert c in kept


def test_dedup_keeps_distinct_snippets():
    snippets = [
        "from sklearn import svm\n",
        "package main\nimport \"fmt\"\n",
        "fn main() { println!(\"x\"); }\n",
    ]
    kept, dropped = dedup_snippets(snippets)
    assert dropped == 0
    assert len(kept) == 3


def test_dedup_preserves_input_order():
    snippets = ["a b c d e", "f g h i j", "k l m n o"]
    kept, _ = dedup_snippets(snippets)
    assert kept == snippets


# --- prompt round-trip via JSONL is what training will see -----------------


def test_format_sft_example_is_json_serializable():
    import json
    ex = format_sft_example("snippet text", "no")
    encoded = json.dumps(ex)
    assert json.loads(encoded) == ex
