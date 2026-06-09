"""v0.43 — resume after crash tests."""

from __future__ import annotations

import argparse
from pathlib import Path
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
        "db": None, "resume": False,
        "target_file": None, "rate_limit": 1.0, "timeout": 10.0,
        "dry_run": False, "title": None,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _local_share_with_files(tmp_path, names):
    target = tmp_path / "share"
    target.mkdir()
    for n in names:
        (target / n).write_text(f"content of {n}")
    return target


class TestSeenFiles:
    def test_returns_empty_set_for_new_share(self, tmp_path):
        from sharesift.engagement import EngagementDB
        db = EngagementDB(tmp_path / "e.db")
        try:
            assert db.seen_files("10.0.0.5", "Finance") == set()
        finally:
            db.close()

    def test_returns_recorded_rel_paths(self, tmp_path):
        from sharesift.engagement import EngagementDB
        db = EngagementDB(tmp_path / "e.db")
        try:
            db.record_file("10.0.0.5", "Finance", "secrets.cfg")
            db.record_file("10.0.0.5", "Finance", "sub/nested.txt")
            seen = db.seen_files("10.0.0.5", "Finance")
            assert seen == {"secrets.cfg", "sub/nested.txt"}
        finally:
            db.close()

    def test_scoped_to_host_and_share(self, tmp_path):
        from sharesift.engagement import EngagementDB
        db = EngagementDB(tmp_path / "e.db")
        try:
            db.record_file("10.0.0.5", "A", "x")
            db.record_file("10.0.0.5", "B", "y")
            db.record_file("10.0.0.6", "A", "z")
            assert db.seen_files("10.0.0.5", "A") == {"x"}
            assert db.seen_files("10.0.0.5", "B") == {"y"}
            assert db.seen_files("10.0.0.6", "A") == {"z"}
        finally:
            db.close()


class TestBulkRecord:
    def test_bulk_insert_returns_count_of_new_rows(self, tmp_path):
        from sharesift.engagement import EngagementDB
        db = EngagementDB(tmp_path / "e.db")
        try:
            n = db.record_files_bulk(
                "h", "s", [("a", 10), ("b", 20), ("c", None)],
            )
            assert n == 3
        finally:
            db.close()

    def test_bulk_insert_skips_already_seen(self, tmp_path):
        from sharesift.engagement import EngagementDB
        db = EngagementDB(tmp_path / "e.db")
        try:
            db.record_file("h", "s", "a")
            n = db.record_files_bulk("h", "s", [("a", 10), ("b", 20)])
            assert n == 1  # only "b" is new
            assert db.seen_files("h", "s") == {"a", "b"}
        finally:
            db.close()

    def test_bulk_insert_empty_returns_zero(self, tmp_path):
        from sharesift.engagement import EngagementDB
        db = EngagementDB(tmp_path / "e.db")
        try:
            assert db.record_files_bulk("h", "s", []) == 0
        finally:
            db.close()


class TestResumeIntegration:
    def test_resume_without_db_errors(self, tmp_path):
        from sharesift.cli import cmd_scan
        share = _local_share_with_files(tmp_path, ["a.txt", "b.txt"])
        ns = _scan_ns(
            target=str(share),
            output_dir=tmp_path / "out",
            resume=True,
            skip_verify=True, skip_report=True,
        )
        with pytest.raises(SystemExit, match="--resume requires --db"):
            cmd_scan(ns)

    def test_first_scan_records_files_in_db(self, tmp_path):
        from sharesift.cli import cmd_scan
        from sharesift.engagement import EngagementDB

        share = _local_share_with_files(tmp_path, ["a.txt", "b.txt", "c.txt"])
        db_path = tmp_path / "e.db"
        ns = _scan_ns(
            target=str(share),
            output_dir=tmp_path / "out",
            db=db_path,
            skip_verify=True, skip_report=True,
        )
        with (
            patch("sharesift.cli.cmd_score_paths", return_value=0),
            patch("sharesift.cli.cmd_scan_files", return_value=0),
        ):
            cmd_scan(ns)

        with EngagementDB(db_path) as db:
            seen = db.seen_files("local", "share")
        assert seen == {"a.txt", "b.txt", "c.txt"}

    def test_resume_skips_already_recorded_files(self, tmp_path):
        from sharesift.cli import cmd_scan
        from sharesift.engagement import EngagementDB

        share = _local_share_with_files(tmp_path, ["a.txt", "b.txt", "c.txt"])
        db_path = tmp_path / "e.db"

        # Pre-populate DB as if a previous run had processed a.txt + b.txt
        with EngagementDB(db_path) as db:
            db.record_file("local", "share", "a.txt")
            db.record_file("local", "share", "b.txt")

        files_path_capture = []

        def capture_score_paths(ns):
            # The score-paths input file is what cmd_scan wrote
            files_path_capture.append(
                Path(ns.input).read_text(encoding="utf-8").splitlines()
            )
            return 0

        ns = _scan_ns(
            target=str(share),
            output_dir=tmp_path / "out",
            db=db_path,
            resume=True,
            skip_verify=True, skip_report=True,
        )
        with (
            patch("sharesift.cli.cmd_score_paths", side_effect=capture_score_paths),
            patch("sharesift.cli.cmd_scan_files", return_value=0),
        ):
            cmd_scan(ns)

        # Only c.txt should remain after --resume filtering
        kept = [p for p in files_path_capture[0] if p.strip()]
        assert len(kept) == 1
        assert kept[0].endswith("c.txt")
