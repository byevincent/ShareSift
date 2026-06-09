"""v0.46 step 1 — engagement exporter tests."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from sharesift.engagement import (
    EngagementDB,
    to_ghostwriter_csv,
    to_markdown,
    to_sysreptor_json,
)


def _populated_db(tmp_path: Path) -> Path:
    """Build a DB with realistic findings for exporter tests."""
    db_path = tmp_path / "engagement.db"
    with EngagementDB(db_path) as db:
        db.record_host("10.0.0.5", alive=True, port=445)
        db.record_share("10.0.0.5", "Finance", type_="disk",
                        can_read=True, can_write=True)
        db.record_share("10.0.0.5", "Public", type_="disk",
                        can_read=True, can_write=False)
        db.record_file("10.0.0.5", "Finance", "secrets.cfg", size=128)
        db.record_file("10.0.0.5", "Finance", "logs/old.log", size=4096)
        db.record_hit(
            "10.0.0.5", "Finance", "secrets.cfg",
            "ShareSiftKeepVaultToken",
            tier="Black", snippet="hvs.AbCdEf...",
        )
        db.record_hit(
            "10.0.0.5", "Finance", "logs/old.log",
            "ShareSiftKeepEditorBackupConfig",
            tier="Red", snippet="password=hunter2",
        )
        db.record_hit(
            "10.0.0.5", "Public", "readme.txt",
            "DummyRule", tier="Yellow",
        )
    return db_path


class TestMarkdownExport:
    def test_emits_header_and_summary(self, tmp_path):
        with EngagementDB(_populated_db(tmp_path)) as db:
            text = to_markdown(db)
        assert "# ShareSift Engagement Findings" in text
        assert "## Summary" in text
        assert "Hits: **3**" in text

    def test_custom_title(self, tmp_path):
        with EngagementDB(_populated_db(tmp_path)) as db:
            text = to_markdown(db, title="Acme 2026 Q3 Internal")
        assert "# Acme 2026 Q3 Internal" in text

    def test_findings_sorted_by_tier(self, tmp_path):
        """Black first, then Red, then Yellow — verify per-finding
        section ordering."""
        with EngagementDB(_populated_db(tmp_path)) as db:
            text = to_markdown(db)
        black_pos = text.index("ShareSiftKeepVaultToken")
        red_pos = text.index("ShareSiftKeepEditorBackupConfig")
        yellow_pos = text.index("DummyRule")
        assert black_pos < red_pos < yellow_pos

    def test_includes_paths_and_snippets(self, tmp_path):
        with EngagementDB(_populated_db(tmp_path)) as db:
            text = to_markdown(db)
        assert r"\\10.0.0.5\Finance\secrets.cfg" in text
        assert "hvs.AbCdEf..." in text

    def test_writable_share_marked_RW(self, tmp_path):
        with EngagementDB(_populated_db(tmp_path)) as db:
            text = to_markdown(db)
        assert "RW" in text  # Finance is writable

    def test_empty_db_handled(self, tmp_path):
        with EngagementDB(tmp_path / "empty.db") as db:
            text = to_markdown(db)
        assert "# ShareSift Engagement Findings" in text
        assert "No hits recorded" in text


class TestGhostwriterCsv:
    def test_emits_valid_csv(self, tmp_path):
        with EngagementDB(_populated_db(tmp_path)) as db:
            text = to_ghostwriter_csv(db)
        rows = list(csv.reader(io.StringIO(text)))
        assert rows[0] == [
            "title", "severity", "description", "recommendation",
            "references", "finding_type", "cvss_score", "cvss_vector",
        ]
        assert len(rows) == 4  # header + 3 findings

    def test_severity_mapping(self, tmp_path):
        with EngagementDB(_populated_db(tmp_path)) as db:
            text = to_ghostwriter_csv(db)
        rows = list(csv.reader(io.StringIO(text)))
        severities = [r[1] for r in rows[1:]]
        assert "Critical" in severities  # Black
        assert "High" in severities       # Red
        assert "Medium" in severities    # Yellow

    def test_finding_type_set(self, tmp_path):
        with EngagementDB(_populated_db(tmp_path)) as db:
            text = to_ghostwriter_csv(db)
        rows = list(csv.reader(io.StringIO(text)))
        for r in rows[1:]:
            assert r[5] == "Credential Exposure"

    def test_recommendation_present(self, tmp_path):
        with EngagementDB(_populated_db(tmp_path)) as db:
            text = to_ghostwriter_csv(db)
        rows = list(csv.reader(io.StringIO(text)))
        for r in rows[1:]:
            assert "Rotate" in r[3]

    def test_empty_db_yields_header_only(self, tmp_path):
        with EngagementDB(tmp_path / "empty.db") as db:
            text = to_ghostwriter_csv(db)
        rows = list(csv.reader(io.StringIO(text)))
        assert len(rows) == 1  # just the header


class TestSysreptorJson:
    def test_emits_valid_json(self, tmp_path):
        with EngagementDB(_populated_db(tmp_path)) as db:
            text = to_sysreptor_json(db)
        payload = json.loads(text)
        assert payload["format"] == "projects/v1"
        assert "findings" in payload
        assert len(payload["findings"]) == 3

    def test_severity_lowercased(self, tmp_path):
        """SysReptor expects lowercase severity (critical/high/medium)."""
        with EngagementDB(_populated_db(tmp_path)) as db:
            payload = json.loads(to_sysreptor_json(db))
        for f in payload["findings"]:
            assert f["severity"] in ("critical", "high", "medium", "low", "info")

    def test_metadata_preserved(self, tmp_path):
        with EngagementDB(_populated_db(tmp_path)) as db:
            payload = json.loads(to_sysreptor_json(db))
        for f in payload["findings"]:
            assert "metadata" in f
            assert "sharesift_rule" in f["metadata"]

    def test_project_name_used(self, tmp_path):
        with EngagementDB(_populated_db(tmp_path)) as db:
            payload = json.loads(to_sysreptor_json(db, project_name="ACME Q3"))
        assert payload["name"] == "ACME Q3"


class TestCliExportSubcommand:
    def test_markdown_format(self, tmp_path):
        from sharesift.cli import main

        db_path = _populated_db(tmp_path)
        out_path = tmp_path / "findings.md"
        rc = main([
            "export",
            "--db", str(db_path),
            "--format", "markdown",
            "--output", str(out_path),
            "--title", "Test Engagement",
        ])
        assert rc == 0
        text = out_path.read_text(encoding="utf-8")
        assert "# Test Engagement" in text
        assert "ShareSiftKeepVaultToken" in text

    def test_ghostwriter_format(self, tmp_path):
        from sharesift.cli import main

        db_path = _populated_db(tmp_path)
        out_path = tmp_path / "findings.csv"
        rc = main([
            "export", "--db", str(db_path),
            "--format", "ghostwriter",
            "--output", str(out_path),
        ])
        assert rc == 0
        rows = list(csv.reader(io.StringIO(out_path.read_text())))
        assert len(rows) >= 2

    def test_sysreptor_format(self, tmp_path):
        from sharesift.cli import main

        db_path = _populated_db(tmp_path)
        out_path = tmp_path / "findings.json"
        rc = main([
            "export", "--db", str(db_path),
            "--format", "sysreptor",
            "--output", str(out_path),
        ])
        assert rc == 0
        payload = json.loads(out_path.read_text())
        assert payload["format"] == "projects/v1"

    def test_invalid_format_rejected(self, tmp_path):
        from sharesift.cli import main

        db_path = _populated_db(tmp_path)
        with pytest.raises(SystemExit):
            main([
                "export", "--db", str(db_path),
                "--format", "powerpoint",  # not a choice
                "--output", str(tmp_path / "out"),
            ])
