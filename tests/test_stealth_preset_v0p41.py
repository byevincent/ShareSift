"""v0.41 — ``--stealth`` preset wiring tests."""

from __future__ import annotations

import argparse
from unittest.mock import patch

import pytest


def _scan_ns(**kwargs):
    defaults = {
        "target": None, "share": None, "output_dir": None,
        "user": None, "password": None, "hash": None,
        "kerberos": False, "use_kcache": False,
        "domain": None, "anonymous": False,
        "encrypt": True, "check": False,
        "skip_verify": False, "skip_report": False,
        "windows_model_dir": None, "linux_model_dir": None,
        "content_model_dir": None, "device": None,
        "max_snippet_bytes": 4096, "force_content": False,
        "read_threads": 4,
        "exclude_glob": None, "no_default_excludes": False,
        "max_file_size": None, "stealth": False,
        "target_file": None, "rate_limit": 1.0, "timeout": 10.0,
        "dry_run": False, "title": None,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def test_stealth_caps_read_size_at_256K(tmp_path):
    from sharesift.cli import cmd_scan
    (tmp_path / "f.txt").write_text("content")
    ns = _scan_ns(
        target=str(tmp_path), output_dir=tmp_path / "out",
        stealth=True, skip_verify=True, skip_report=True,
    )
    with (
        patch("sharesift.cli.cmd_score_paths", return_value=0),
        patch("sharesift.cli.cmd_scan_files", return_value=0),
    ):
        cmd_scan(ns)
    # --stealth set max_file_size = "256K" since it wasn't set
    assert ns.max_file_size == "256K"


def test_stealth_drops_read_threads_to_1(tmp_path):
    from sharesift.cli import cmd_scan
    (tmp_path / "f.txt").write_text("content")
    ns = _scan_ns(
        target=str(tmp_path), output_dir=tmp_path / "out",
        stealth=True, skip_verify=True, skip_report=True,
    )
    with (
        patch("sharesift.cli.cmd_score_paths", return_value=0),
        patch("sharesift.cli.cmd_scan_files", return_value=0),
    ):
        cmd_scan(ns)
    assert ns.read_threads == 1


def test_stealth_does_not_override_explicit_max_file_size(tmp_path):
    """If operator passes both --stealth and --max-file-size, the
    explicit value wins."""
    from sharesift.cli import cmd_scan
    (tmp_path / "f.txt").write_text("content")
    ns = _scan_ns(
        target=str(tmp_path), output_dir=tmp_path / "out",
        stealth=True, max_file_size="1M",
        skip_verify=True, skip_report=True,
    )
    with (
        patch("sharesift.cli.cmd_score_paths", return_value=0),
        patch("sharesift.cli.cmd_scan_files", return_value=0),
    ):
        cmd_scan(ns)
    assert ns.max_file_size == "1M"


def test_stealth_does_not_override_explicit_read_threads(tmp_path):
    """If operator passes --read-threads 8 with --stealth, the
    explicit value wins. (read_threads != 4 means operator set it.)"""
    from sharesift.cli import cmd_scan
    (tmp_path / "f.txt").write_text("content")
    ns = _scan_ns(
        target=str(tmp_path), output_dir=tmp_path / "out",
        stealth=True, read_threads=8,
        skip_verify=True, skip_report=True,
    )
    with (
        patch("sharesift.cli.cmd_score_paths", return_value=0),
        patch("sharesift.cli.cmd_scan_files", return_value=0),
    ):
        cmd_scan(ns)
    assert ns.read_threads == 8


def test_no_stealth_leaves_defaults(tmp_path):
    from sharesift.cli import cmd_scan
    (tmp_path / "f.txt").write_text("content")
    ns = _scan_ns(
        target=str(tmp_path), output_dir=tmp_path / "out",
        stealth=False, skip_verify=True, skip_report=True,
    )
    with (
        patch("sharesift.cli.cmd_score_paths", return_value=0),
        patch("sharesift.cli.cmd_scan_files", return_value=0),
    ):
        cmd_scan(ns)
    assert ns.max_file_size is None
    assert ns.read_threads == 4
