"""v0.37 step 3 — ``sharesift batch`` multi-target scan tests."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from sharesift.cli import main


def _write_targets(path: Path, lines: list[str]) -> Path:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_batch_iterates_each_target(tmp_path):
    """Each non-empty / non-comment line in the targets file becomes
    one cmd_scan invocation."""
    targets = _write_targets(tmp_path / "t.txt", [
        "# comment line — ignored",
        "/mnt/share-a",
        "",
        "/mnt/share-b",
    ])
    output = tmp_path / "out"

    with patch("sharesift.cli.cmd_scan", return_value=0) as mock_scan:
        rc = main([
            "batch",
            "--targets", str(targets),
            "--output-dir", str(output),
        ])
        assert rc == 0
        assert mock_scan.call_count == 2
        # Verify the targets passed through correctly
        called_targets = [c.args[0].target for c in mock_scan.call_args_list]
        assert called_targets == ["/mnt/share-a", "/mnt/share-b"]


def test_batch_writes_summary_per_target(tmp_path):
    targets = _write_targets(tmp_path / "t.txt", [
        "/mnt/a",
        "/mnt/b",
    ])
    output = tmp_path / "out"

    with patch("sharesift.cli.cmd_scan", return_value=0):
        main([
            "batch",
            "--targets", str(targets),
            "--output-dir", str(output),
        ])

    summary = (output / "batch_summary.jsonl").read_text(encoding="utf-8")
    records = [json.loads(line) for line in summary.splitlines() if line]
    assert len(records) == 2
    assert all(r["ok"] for r in records)
    assert records[0]["target"] == "/mnt/a"
    assert records[1]["target"] == "/mnt/b"


def test_batch_continues_after_per_target_failure(tmp_path):
    """If one target's cmd_scan raises (e.g. auth fails), batch
    records the failure and continues with the rest. Exit code is
    1 when any target failed."""
    targets = _write_targets(tmp_path / "t.txt", [
        "/mnt/good",
        "//bad-host/share",  # auth will fail
        "/mnt/also-good",
    ])
    output = tmp_path / "out"

    call_results = [0, SystemExit("auth fail"), 0]

    def fake_scan(args):
        result = call_results.pop(0)
        if isinstance(result, SystemExit):
            raise result
        return result

    with patch("sharesift.cli.cmd_scan", side_effect=fake_scan):
        rc = main([
            "batch",
            "--targets", str(targets),
            "--output-dir", str(output),
        ])
        assert rc == 1  # at least one failure

    records = [
        json.loads(line)
        for line in (output / "batch_summary.jsonl").read_text().splitlines()
        if line
    ]
    assert len(records) == 3
    assert [r["ok"] for r in records] == [True, False, True]


def test_batch_smb_target_subdir_name_uses_host_and_share(tmp_path):
    targets = _write_targets(tmp_path / "t.txt", [
        "//10.0.0.5/Finance",
    ])
    output = tmp_path / "out"

    with patch("sharesift.cli.cmd_scan", return_value=0) as mock_scan:
        main([
            "batch",
            "--targets", str(targets),
            "--output-dir", str(output),
            "-u", "u", "-p", "p",
        ])

    # The output subdir passed through to cmd_scan
    ns = mock_scan.call_args.args[0]
    assert str(ns.output_dir).endswith("sharesift-10.0.0.5-Finance")


def test_batch_empty_targets_file_errors(tmp_path):
    targets = _write_targets(tmp_path / "t.txt", [
        "# only comments",
        "",
    ])
    output = tmp_path / "out"

    with pytest.raises(SystemExit, match="no targets"):
        main([
            "batch",
            "--targets", str(targets),
            "--output-dir", str(output),
        ])


def test_batch_propagates_auth_flags(tmp_path):
    """The auth flags passed to ``batch`` propagate to each
    per-target cmd_scan call."""
    targets = _write_targets(tmp_path / "t.txt", [
        "//host/share",
    ])
    output = tmp_path / "out"

    with patch("sharesift.cli.cmd_scan", return_value=0) as mock_scan:
        main([
            "batch",
            "--targets", str(targets),
            "--output-dir", str(output),
            "-u", "alice", "-p", "pw", "-d", "CORP",
        ])

    ns = mock_scan.call_args.args[0]
    assert ns.user == "alice"
    assert ns.password == "pw"
    assert ns.domain == "CORP"
