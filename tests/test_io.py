"""Tests for the atomic write/append primitives."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

import pytest

from src.eval._io import atomic_append_jsonl, atomic_write_jsonl


# A minimal JSON-serializable stand-in for QueueRecord / EvalRecord so the
# primitive tests don't depend on the Pydantic models.
@dataclass
class _Record:
    payload: dict

    def model_dump_json(self) -> str:
        return json.dumps(self.payload)


def _r(**fields) -> _Record:
    return _Record(payload=fields)


# ---------------------------------------------------------------------------
# atomic_write_jsonl
# ---------------------------------------------------------------------------


def test_write_creates_file_and_writes_each_record_on_its_own_line(tmp_path):
    out = tmp_path / "out.jsonl"
    atomic_write_jsonl(out, [_r(a=1), _r(b=2)])
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines == ['{"a": 1}', '{"b": 2}']


def test_write_creates_parent_directories(tmp_path):
    out = tmp_path / "nested" / "deep" / "out.jsonl"
    atomic_write_jsonl(out, [_r(a=1)])
    assert out.exists()


def test_write_leaves_no_tmp_file_on_success(tmp_path):
    out = tmp_path / "out.jsonl"
    atomic_write_jsonl(out, [_r(a=1)])
    assert not out.with_suffix(out.suffix + ".tmp").exists()


def test_write_cleans_tmp_on_failure(tmp_path):
    out = tmp_path / "out.jsonl"

    def boom():
        yield _r(a=1)
        raise RuntimeError("simulated mid-write failure")

    with pytest.raises(RuntimeError, match="simulated mid-write failure"):
        atomic_write_jsonl(out, boom())
    assert not out.exists()
    assert not out.with_suffix(out.suffix + ".tmp").exists()


def test_write_preserves_existing_file_on_failure(tmp_path):
    out = tmp_path / "out.jsonl"
    out.write_text("original content\n", encoding="utf-8")

    def boom():
        raise RuntimeError("nope")
        yield  # pragma: no cover  -- make this a generator

    with pytest.raises(RuntimeError):
        atomic_write_jsonl(out, boom())
    assert out.read_text(encoding="utf-8") == "original content\n"


def test_write_empty_records_produces_empty_file(tmp_path):
    out = tmp_path / "out.jsonl"
    atomic_write_jsonl(out, [])
    assert out.exists()
    assert out.read_text(encoding="utf-8") == ""


def test_write_calls_fsync(tmp_path, monkeypatch):
    out = tmp_path / "out.jsonl"
    calls: list[int] = []
    original_fsync = os.fsync

    def spy_fsync(fd):
        calls.append(fd)
        return original_fsync(fd)

    monkeypatch.setattr(os, "fsync", spy_fsync)
    atomic_write_jsonl(out, [_r(a=1)])
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# atomic_append_jsonl
# ---------------------------------------------------------------------------


def test_append_creates_file_when_missing(tmp_path):
    out = tmp_path / "out.jsonl"
    atomic_append_jsonl(out, _r(a=1))
    assert out.read_text(encoding="utf-8") == '{"a": 1}\n'


def test_append_creates_parent_directories(tmp_path):
    out = tmp_path / "nested" / "out.jsonl"
    atomic_append_jsonl(out, _r(a=1))
    assert out.exists()


def test_append_adds_to_existing_file(tmp_path):
    out = tmp_path / "out.jsonl"
    atomic_append_jsonl(out, _r(a=1))
    atomic_append_jsonl(out, _r(b=2))
    atomic_append_jsonl(out, _r(c=3))
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines == ['{"a": 1}', '{"b": 2}', '{"c": 3}']


def test_append_preserves_existing_non_jsonl_content(tmp_path):
    # If for some reason the file has prior content, append shouldn't
    # truncate it — the durability contract is "this line is added,"
    # not "this file now contains only this line."
    out = tmp_path / "out.jsonl"
    out.write_text('{"existing": true}\n', encoding="utf-8")
    atomic_append_jsonl(out, _r(new=1))
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines == ['{"existing": true}', '{"new": 1}']


def test_append_calls_fsync(tmp_path, monkeypatch):
    out = tmp_path / "out.jsonl"
    calls: list[int] = []
    original_fsync = os.fsync

    def spy_fsync(fd):
        calls.append(fd)
        return original_fsync(fd)

    monkeypatch.setattr(os, "fsync", spy_fsync)
    atomic_append_jsonl(out, _r(a=1))
    atomic_append_jsonl(out, _r(b=2))
    assert len(calls) == 2


def test_append_writes_trailing_newline(tmp_path):
    out = tmp_path / "out.jsonl"
    atomic_append_jsonl(out, _r(a=1))
    content = out.read_text(encoding="utf-8")
    assert content.endswith("\n"), (
        "every appended record must end with a newline so subsequent "
        "appends start on a fresh line — JSONL convention"
    )


def test_round_trip_write_then_append(tmp_path):
    out = tmp_path / "out.jsonl"
    atomic_write_jsonl(out, [_r(a=1), _r(b=2)])
    atomic_append_jsonl(out, _r(c=3))
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines == ['{"a": 1}', '{"b": 2}', '{"c": 3}']
