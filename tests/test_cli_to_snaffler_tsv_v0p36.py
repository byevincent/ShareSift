"""v0.36 step 4 — ``sharesift to-snaffler-tsv`` CLI integration tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sharesift.cli import main


def _hits(path: Path, records: list[dict]) -> Path:
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    return path


def test_to_snaffler_tsv_writes_file(tmp_path):
    src = _hits(tmp_path / "hits.jsonl", [
        {"path": "/share/secrets.cfg", "path_tier": "Red"},
        {"path": "/share/keys/id_rsa", "path_tier": "Black"},
    ])
    out = tmp_path / "out.tsv"
    rc = main(["to-snaffler-tsv", "--input", str(src), "--output", str(out)])
    assert rc == 0
    # Don't .strip() — would eat trailing empty fields (tabs) on the
    # last line and break the 12-field count assertion.
    lines = out.read_text(encoding="utf-8").splitlines()
    # Drop trailing blank line if present
    lines = [ln for ln in lines if ln]
    assert len(lines) == 2
    # v0.45: default verifier-first sort. With no verification on
    # either record, sort is by tier — Black > Red.
    assert "Black" in lines[0]
    assert "Red" in lines[1]
    # 12 fields per line (tab-separated)
    assert all(len(line.split("\t")) == 12 for line in lines)


def test_to_snaffler_tsv_via_stdin(tmp_path, capsys, monkeypatch):
    import io
    payload = (
        json.dumps({"path": "/share/x", "path_tier": "Yellow"}) + "\n"
        + json.dumps({"path": "/share/y", "path_tier": "Green"}) + "\n"
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))

    rc = main(["to-snaffler-tsv", "--stdin"])
    assert rc == 0
    captured = capsys.readouterr()
    lines = [ln for ln in captured.out.splitlines() if ln]
    assert len(lines) == 2
    assert "Yellow" in lines[0]
    assert "Green" in lines[1]


def test_to_snaffler_tsv_preserves_unc_paths(tmp_path):
    src = _hits(tmp_path / "hits.jsonl", [
        {
            "path": r"\\10.0.0.5\Finance\creds.kdbx",
            "path_tier": "Black",
            "content_matches": [
                {"rule_name": "KeepPassMgrsByExtension", "tier": "Black",
                 "match_context": "binary-kdbx-content"}
            ],
        }
    ])
    out = tmp_path / "out.tsv"
    rc = main(["to-snaffler-tsv", "--input", str(src), "--output", str(out)])
    assert rc == 0
    # Don't .strip() — see field-count test above for rationale.
    line = next(ln for ln in out.read_text(encoding="utf-8").splitlines() if ln)
    fields = line.split("\t")
    assert fields[1] == "Black"
    assert fields[2] == "KeepPassMgrsByExtension"
    assert fields[9] == r"\\10.0.0.5\Finance\creds.kdbx"
    # UNC → size + modified empty
    assert fields[7] == ""
    assert fields[8] == ""
