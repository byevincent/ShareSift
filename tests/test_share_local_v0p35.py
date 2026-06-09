"""v0.35 Sprint 1 — LocalShare unit tests.

Confirms the refactored share-walking abstraction preserves the
pre-v0.35 behavior in cmd_scan: recursive enumeration, files-only,
sorted, absolute-path strings, size metadata.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sharesift.share import LocalShare, Share, ShareEntry


def test_walk_yields_files_in_subdirs(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("alpha")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("beta")
    (tmp_path / "sub" / "nested").mkdir()
    (tmp_path / "sub" / "nested" / "c.txt").write_text("gamma")

    paths = [e.path for e in LocalShare(tmp_path).walk()]

    assert str(tmp_path / "a.txt") in paths
    assert str(tmp_path / "sub" / "b.txt") in paths
    assert str(tmp_path / "sub" / "nested" / "c.txt") in paths
    assert len(paths) == 3


def test_walk_excludes_directories(tmp_path: Path) -> None:
    (tmp_path / "f.txt").write_text("file")
    (tmp_path / "empty_dir").mkdir()
    (tmp_path / "non_empty_dir").mkdir()
    (tmp_path / "non_empty_dir" / "inside.txt").write_text("x")

    paths = [e.path for e in LocalShare(tmp_path).walk()]

    assert str(tmp_path / "empty_dir") not in paths
    assert str(tmp_path / "non_empty_dir") not in paths
    assert str(tmp_path / "f.txt") in paths
    assert str(tmp_path / "non_empty_dir" / "inside.txt") in paths


def test_walk_yields_size_metadata(tmp_path: Path) -> None:
    (tmp_path / "small.txt").write_bytes(b"abc")
    (tmp_path / "larger.txt").write_bytes(b"0123456789")

    by_name = {Path(e.path).name: e for e in LocalShare(tmp_path).walk()}

    assert by_name["small.txt"].size == 3
    assert by_name["larger.txt"].size == 10


def test_walk_on_empty_share_yields_nothing(tmp_path: Path) -> None:
    assert list(LocalShare(tmp_path).walk()) == []


def test_walk_is_deterministic_sorted(tmp_path: Path) -> None:
    for name in ("z.txt", "a.txt", "m.txt", "b.txt"):
        (tmp_path / name).write_text(name)

    run1 = [e.path for e in LocalShare(tmp_path).walk()]
    run2 = [e.path for e in LocalShare(tmp_path).walk()]

    assert run1 == run2
    assert run1 == sorted(run1)


def test_walk_returns_iterator(tmp_path: Path) -> None:
    """``walk()`` is lazy — Sprint 2's SmbShare streams entries; the
    contract is iterator semantics, not a list."""
    (tmp_path / "x.txt").write_text("x")
    walker = LocalShare(tmp_path).walk()
    assert iter(walker) is walker  # iterator protocol


def test_root_property_returns_input_path(tmp_path: Path) -> None:
    share = LocalShare(tmp_path)
    assert share.root == str(tmp_path)


def test_root_accepts_string_input(tmp_path: Path) -> None:
    share = LocalShare(str(tmp_path))
    assert share.root == str(tmp_path)


def test_local_share_satisfies_share_protocol(tmp_path: Path) -> None:
    """Runtime-checkable protocol membership — guards against
    accidental signature drift between LocalShare and the protocol."""
    assert isinstance(LocalShare(tmp_path), Share)


def test_share_entry_is_frozen() -> None:
    entry = ShareEntry(path="/tmp/x", size=42)
    with pytest.raises(Exception):  # FrozenInstanceError
        entry.path = "/tmp/y"  # type: ignore[misc]
