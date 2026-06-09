"""v0.38 step 1 — parallel SMB content reads via thread pool.

Lab confirmed smbprotocol handles concurrent Open + read on one
Connection up to 8 workers; sweet spot is 4 (diminishing returns
above, credit-flow control issues at 16+). v0.38 wires a thread
pool into cmd_scan_files when the active share is an SmbShare.

These tests verify the wiring with mocked shares — they don't
re-test smbprotocol thread safety (the lab did that).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def _files_list(tmp_path: Path, paths: list[str]) -> Path:
    files = tmp_path / "files.txt"
    files.write_text("\n".join(paths) + "\n", encoding="utf-8")
    return files


def _scan_files_ns(input_path: Path, output_path: Path, **kwargs):
    defaults = {
        "input": input_path,
        "stdin": False,
        "output": output_path,
        "windows_model_dir": None,
        "linux_model_dir": None,
        "content_model_dir": None,
        "device": None,
        "max_snippet_bytes": 4096,
        "force_content": False,
        "read_threads": 4,
        "debug": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class TestParallelReadDispatch:
    """Verify cmd_scan_files routes to the thread pool when share is
    set and read_threads > 1."""

    def test_single_thread_uses_sequential_path(self, tmp_path):
        from sharesift.cli import cmd_scan_files

        files = _files_list(tmp_path, ["/a", "/b", "/c"])
        out_path = tmp_path / "hits.jsonl"

        share = MagicMock()
        share.read_bytes.return_value = b"content"

        ns = _scan_files_ns(files, out_path, read_threads=1, _share=share)
        # Patch Scanner so we just check read_bytes call count
        with patch("sharesift.cli.Scanner") as MockScanner:
            MockScanner.return_value.scan_batch.return_value = []
            cmd_scan_files(ns)

        # All 3 paths read sequentially through the share
        assert share.read_bytes.call_count == 3

    def test_multi_thread_uses_thread_pool(self, tmp_path):
        """When share is set and read_threads > 1 with multiple paths,
        a ThreadPoolExecutor is constructed with the requested worker
        count."""
        from sharesift.cli import cmd_scan_files

        files = _files_list(tmp_path, ["/a", "/b", "/c", "/d", "/e"])
        out_path = tmp_path / "hits.jsonl"

        share = MagicMock()
        share.read_bytes.return_value = b"content"

        ns = _scan_files_ns(files, out_path, read_threads=4, _share=share)
        with patch("sharesift.cli.Scanner") as MockScanner:
            MockScanner.return_value.scan_batch.return_value = []
            with patch("concurrent.futures.ThreadPoolExecutor") as MockPool:
                # Make .map call the function so reads still happen
                MockPool.return_value.__enter__.return_value.map.side_effect = (
                    lambda fn, iterable: [fn(x) for x in iterable]
                )
                cmd_scan_files(ns)
                MockPool.assert_called_once_with(max_workers=4)

        # All 5 reads happened through the share
        assert share.read_bytes.call_count == 5

    def test_thread_pool_preserves_path_order(self, tmp_path):
        """ThreadPoolExecutor.map returns results in input order even
        though they were computed concurrently — Scanner.scan_batch
        relies on this for deterministic JSONL output."""
        from sharesift.cli import cmd_scan_files

        paths = [f"/path_{i}" for i in range(10)]
        files = _files_list(tmp_path, paths)
        out_path = tmp_path / "hits.jsonl"

        share = MagicMock()
        share.read_bytes.side_effect = lambda p, max_bytes=None: f"content-{p}".encode()

        ns = _scan_files_ns(files, out_path, read_threads=4, _share=share)

        captured_items = None

        def capture_batch(items, **kwargs):
            nonlocal captured_items
            captured_items = list(items)
            return []

        with patch("sharesift.cli.Scanner") as MockScanner:
            MockScanner.return_value.scan_batch.side_effect = capture_batch
            cmd_scan_files(ns)

        # items is [(path, content)] in input order
        captured_paths = [p for p, _ in captured_items]
        assert captured_paths == paths

    def test_local_path_skips_threading(self, tmp_path):
        """Local FS reads are sub-millisecond — threading adds overhead
        without benefit. cmd_scan_files uses the path-based loader
        directly when no share is provided."""
        from sharesift.cli import cmd_scan_files

        # Plant real files so load_content can read them
        (tmp_path / "a.txt").write_text("a")
        (tmp_path / "b.txt").write_text("b")
        files = _files_list(tmp_path, [str(tmp_path / "a.txt"), str(tmp_path / "b.txt")])
        out_path = tmp_path / "hits.jsonl"

        # NO _share attribute → falls through to load_content path
        ns = _scan_files_ns(files, out_path, read_threads=4)

        with patch("sharesift.cli.Scanner") as MockScanner:
            MockScanner.return_value.scan_batch.return_value = []
            with patch("concurrent.futures.ThreadPoolExecutor") as MockPool:
                cmd_scan_files(ns)
                # ThreadPoolExecutor never constructed for local FS
                MockPool.assert_not_called()

    def test_single_path_skips_threading(self, tmp_path):
        """Pool overhead exceeds benefit for one file — sequential."""
        from sharesift.cli import cmd_scan_files

        files = _files_list(tmp_path, ["/only_one"])
        out_path = tmp_path / "hits.jsonl"

        share = MagicMock()
        share.read_bytes.return_value = b"content"

        ns = _scan_files_ns(files, out_path, read_threads=4, _share=share)
        with patch("sharesift.cli.Scanner") as MockScanner:
            MockScanner.return_value.scan_batch.return_value = []
            with patch("concurrent.futures.ThreadPoolExecutor") as MockPool:
                cmd_scan_files(ns)
                MockPool.assert_not_called()


class TestReadThreadsFlag:
    """The CLI flag --read-threads is wired through scan + scan-files +
    batch subcommands."""

    def test_scan_files_help_mentions_flag(self):
        import io
        import contextlib
        from sharesift.cli import main

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with pytest.raises(SystemExit):
                main(["scan-files", "--help"])
        out = buf.getvalue()
        assert "--read-threads" in out

    def test_scan_help_mentions_flag(self):
        import io
        import contextlib
        from sharesift.cli import main

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with pytest.raises(SystemExit):
                main(["scan", "--help"])
        out = buf.getvalue()
        assert "--read-threads" in out

    def test_batch_help_mentions_flag(self):
        import io
        import contextlib
        from sharesift.cli import main

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with pytest.raises(SystemExit):
                main(["batch", "--help"])
        out = buf.getvalue()
        assert "--read-threads" in out
