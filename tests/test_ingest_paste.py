"""Tests for the paste-dump ingester.

The bug this module exists to prevent (passes 1-5 silently wrote 893
broken paths) is canary-pinned: feed valid JSON ``\\\\HQFS1\\Shared``
through the parser and the output JSONL must decode to the canonical
2-leading-backslash UNC, NOT 4-leading. If a future "simplification"
of the parser regresses to the regex-only behavior, this test breaks
loudly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.eval.generator.ingest_paste import (
    ingest_pass,
    normalize_path,
    parse_line,
)


# -- escape-style round-trip (the parser-bug canary) -------------------------


def test_qwen_style_valid_json_round_trips_to_canonical_unc():
    """Qwen/DeepSeek emit proper JSON; the parsed path value must be
    the canonical 2-leading-backslash UNC, not the over-escaped form
    that bit passes 1-5."""
    line = (
        r'{"path": "\\\\HQFS1\\Shared\\Finance\\file.txt",'
        r' "juicy": false, "why": "x"}'
    )
    rec = parse_line(line)
    assert rec is not None
    assert rec["path"] == r"\\HQFS1\Shared\Finance\file.txt"


def test_chatgpt_style_invalid_json_recovers_via_regex():
    """ChatGPT emits invalid JSON (lone ``\\S``); the regex fallback
    captures raw chars so json.dumps in write_jsonl produces valid
    JSON that decodes to the same canonical UNC."""
    line = (
        r'{"path":"\\HQFS1\Shared\Finance\file.txt",'
        r'"juicy":false,"why":"x"}'
    )
    rec = parse_line(line)
    assert rec is not None
    assert rec["path"] == r"\\HQFS1\Shared\Finance\file.txt"


def test_normalize_path_halves_over_escaped_unc():
    """Existing over-escaped raw files (from the pass 1-5 era) get
    auto-fixed when re-ingested. 4-leading-backslash signature is the
    detection key."""
    over = "\\\\\\\\HQFS1\\\\Shared\\\\file.txt"
    assert normalize_path(over) == r"\\HQFS1\Shared\file.txt"


def test_normalize_path_no_op_on_canonical_unc():
    canonical = r"\\HQFS1\Shared\file.txt"
    assert normalize_path(canonical) == canonical


def test_normalize_path_no_op_on_linux_path():
    linux = "/home/jsmith/.ssh/id_rsa"
    assert normalize_path(linux) == linux


# -- line-level edge cases ---------------------------------------------------


def test_parse_line_skips_batch_marker_comment():
    assert parse_line("// BATCH 1") is None
    assert parse_line("  // BATCH 2  ") is None


def test_parse_line_skips_blank():
    assert parse_line("") is None
    assert parse_line("   \n") is None


def test_parse_line_preserves_empty_why():
    """Empty whys are kept here; schema validation in the post-processor
    is the boundary that drops them. Preserving them keeps generator
    regressions (like ChatGPT's pass-6 empty-why batch) countable."""
    line = (
        r'{"path": "\\\\srv\\share\\file.txt",'
        r' "juicy": true, "why": ""}'
    )
    rec = parse_line(line)
    assert rec is not None
    assert rec["why"] == ""


def test_parse_line_linux_path_preserved():
    line = (
        r'{"path": "/home/jsmith/.ssh/id_rsa",'
        r' "juicy": true, "why": "private key"}'
    )
    rec = parse_line(line)
    assert rec is not None
    assert rec["path"] == "/home/jsmith/.ssh/id_rsa"


def test_parse_line_returns_none_for_junk():
    assert parse_line("not a json line") is None
    assert parse_line('{"unrelated": "object"}') is None


# -- end-to-end ingest -------------------------------------------------------


def test_ingest_pass_writes_per_model_jsonl(tmp_path: Path):
    paste = tmp_path / "paste"
    raw = tmp_path / "raw"
    paste.mkdir()

    (paste / "chatgpt7.txt").write_text(
        '// BATCH 1\n'
        r'{"path":"\\HQFS1\Shared\file.txt","juicy":false,"why":"x"}'
        "\n"
    )
    (paste / "deepseek7.txt").write_text(
        '// BATCH 1\n'
        r'{"path": "\\\\HQFS1\\Shared\\file.txt", "juicy": true, "why": "y"}'
        "\n"
    )
    # No qwen file; should skip gracefully.

    counts = ingest_pass(7, paste, raw)
    assert counts == {"chatgpt": 1, "deepseek": 1, "qwen": 0}

    cg = [json.loads(l) for l in (raw / "chatgpt_pass7.jsonl").read_text().splitlines()]
    ds = [json.loads(l) for l in (raw / "deepseek_pass7.jsonl").read_text().splitlines()]
    assert cg[0]["path"] == r"\\HQFS1\Shared\file.txt"
    assert ds[0]["path"] == r"\\HQFS1\Shared\file.txt"
    assert not (raw / "qwen_pass7.jsonl").exists()


def test_ingest_pass_creates_raw_dir_if_missing(tmp_path: Path):
    paste = tmp_path / "paste"
    raw = tmp_path / "nested" / "raw"
    paste.mkdir()
    (paste / "chatgpt1.txt").write_text(
        r'{"path":"\\srv\share\f.txt","juicy":false,"why":"x"}'
        "\n"
    )
    ingest_pass(1, paste, raw)
    assert (raw / "chatgpt_pass1.jsonl").exists()
