"""v0.40 step 3 — SQLite engagement datastore tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from sharesift.engagement import EngagementDB


# --- Schema ------------------------------------------------------


class TestSchema:
    def test_creates_db_file(self, tmp_path):
        p = tmp_path / "sub" / "engagement.db"
        db = EngagementDB(p)
        try:
            assert p.exists()
        finally:
            db.close()

    def test_creates_required_tables(self, tmp_path):
        p = tmp_path / "engagement.db"
        with EngagementDB(p) as db:
            tables = {
                row["name"]
                for row in db.query(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            assert tables == {"meta", "hosts", "shares", "files", "hits"}

    def test_stamps_schema_version_and_created_at(self, tmp_path):
        p = tmp_path / "engagement.db"
        with EngagementDB(p) as db:
            rows = db.query("SELECT key, value FROM meta")
            meta = {r["key"]: r["value"] for r in rows}
        assert meta["schema_version"] == "1"
        assert "created_at" in meta

    def test_reopen_preserves_data(self, tmp_path):
        p = tmp_path / "engagement.db"
        with EngagementDB(p) as db:
            db.record_host("10.0.0.5")
        with EngagementDB(p) as db:
            rows = db.query("SELECT host FROM hosts")
        assert [r["host"] for r in rows] == ["10.0.0.5"]


# --- record_host -------------------------------------------------


class TestRecordHost:
    def test_inserts_new_host(self, tmp_path):
        with EngagementDB(tmp_path / "e.db") as db:
            db.record_host("10.0.0.5", alive=True, port=445)
            rows = db.query("SELECT host, alive, port FROM hosts")
        assert len(rows) == 1
        assert rows[0]["host"] == "10.0.0.5"
        assert rows[0]["alive"] == 1
        assert rows[0]["port"] == 445

    def test_upsert_preserves_first_seen(self, tmp_path):
        with EngagementDB(tmp_path / "e.db") as db:
            db.record_host("10.0.0.5", alive=False)
            first = db.query("SELECT first_seen FROM hosts")[0]["first_seen"]
            db.record_host("10.0.0.5", alive=True)
            row = db.query(
                "SELECT first_seen, last_seen, alive FROM hosts"
            )[0]
        assert row["first_seen"] == first
        assert row["alive"] == 1


# --- record_share -------------------------------------------------


class TestRecordShare:
    def test_inserts_share_with_metadata(self, tmp_path):
        with EngagementDB(tmp_path / "e.db") as db:
            db.record_host("10.0.0.5")
            db.record_share(
                "10.0.0.5", "Finance",
                type_="disk", comment="Quarterly reports",
                can_read=True, can_write=False,
            )
            rows = db.query("SELECT * FROM shares")
        assert len(rows) == 1
        r = rows[0]
        assert r["share"] == "Finance"
        assert r["type"] == "disk"
        assert r["comment"] == "Quarterly reports"
        assert r["can_read"] == 1
        assert r["can_write"] == 0

    def test_upsert_share_keeps_first_seen(self, tmp_path):
        with EngagementDB(tmp_path / "e.db") as db:
            db.record_host("10.0.0.5")
            db.record_share("10.0.0.5", "F", type_="disk")
            first = db.query("SELECT first_seen FROM shares")[0]["first_seen"]
            db.record_share("10.0.0.5", "F", can_write=True)
            r = db.query("SELECT first_seen, can_write FROM shares")[0]
        assert r["first_seen"] == first
        assert r["can_write"] == 1


# --- record_file -------------------------------------------------


class TestRecordFile:
    def test_new_file_returns_True(self, tmp_path):
        with EngagementDB(tmp_path / "e.db") as db:
            assert db.record_file(
                "10.0.0.5", "Finance", "secrets.cfg",
                size=42, content_hash="abc",
            ) is True

    def test_seen_file_returns_False(self, tmp_path):
        with EngagementDB(tmp_path / "e.db") as db:
            db.record_file("h", "s", "a")
            assert db.record_file("h", "s", "a") is False

    def test_updates_hash_on_re_record(self, tmp_path):
        with EngagementDB(tmp_path / "e.db") as db:
            db.record_file("h", "s", "a", content_hash="aaa")
            db.record_file("h", "s", "a", content_hash="bbb")
            row = db.query("SELECT content_hash FROM files")[0]
        assert row["content_hash"] == "bbb"


# --- record_hit --------------------------------------------------


class TestRecordHit:
    def test_inserts_hit_with_tier_and_snippet(self, tmp_path):
        with EngagementDB(tmp_path / "e.db") as db:
            db.record_hit(
                "10.0.0.5", "Finance", "secrets.cfg", "ShareSiftKeepVaultToken",
                tier="Black", snippet="hvs.AbCdEf...",
            )
            row = db.query("SELECT host, share, rel_path, rule, tier, snippet FROM hits")[0]
        assert row["tier"] == "Black"
        assert row["rule"] == "ShareSiftKeepVaultToken"
        assert "hvs" in row["snippet"]

    def test_same_path_rule_replaces(self, tmp_path):
        with EngagementDB(tmp_path / "e.db") as db:
            db.record_hit("h", "s", "p", "R", tier="Yellow")
            db.record_hit("h", "s", "p", "R", tier="Black")
            rows = db.query("SELECT tier FROM hits")
        assert len(rows) == 1
        assert rows[0]["tier"] == "Black"


# --- summary -----------------------------------------------------


class TestSummary:
    def test_empty_db_summary(self, tmp_path):
        with EngagementDB(tmp_path / "e.db") as db:
            s = db.summary()
        assert s["hosts_total"] == 0
        assert s["hits_total"] == 0

    def test_populated_summary(self, tmp_path):
        with EngagementDB(tmp_path / "e.db") as db:
            db.record_host("10.0.0.5", alive=True)
            db.record_host("10.0.0.6", alive=False)
            db.record_share("10.0.0.5", "F", can_write=True)
            db.record_share("10.0.0.5", "P", can_write=False)
            db.record_hit("10.0.0.5", "F", "s.cfg", "R1", tier="Black")
            db.record_hit("10.0.0.5", "F", "s.cfg", "R2", tier="Red")
            db.record_hit("10.0.0.5", "F", "other.txt", "R3", tier="Yellow")
            s = db.summary()
        assert s == {
            "hosts_total": 2,
            "hosts_alive": 1,
            "shares_total": 2,
            "shares_writable": 1,
            "files_total": 0,
            "hits_total": 3,
            "hits_black": 1,
            "hits_red": 1,
            "hits_yellow": 1,
        }


# --- query safety ------------------------------------------------


class TestQuery:
    def test_select_works(self, tmp_path):
        with EngagementDB(tmp_path / "e.db") as db:
            db.record_host("10.0.0.5")
            rows = db.query("SELECT host FROM hosts")
        assert len(rows) == 1
        assert rows[0]["host"] == "10.0.0.5"

    def test_select_with_params_works(self, tmp_path):
        with EngagementDB(tmp_path / "e.db") as db:
            db.record_host("10.0.0.5")
            db.record_host("10.0.0.6")
            rows = db.query("SELECT host FROM hosts WHERE host = ?", ("10.0.0.5",))
        assert len(rows) == 1

    def test_non_select_rejected(self, tmp_path):
        with EngagementDB(tmp_path / "e.db") as db:
            with pytest.raises(ValueError, match="read-only"):
                db.query("INSERT INTO hosts(host, alive, port, first_seen, last_seen) VALUES('x', 1, 445, '', '')")

    def test_drop_table_rejected(self, tmp_path):
        with EngagementDB(tmp_path / "e.db") as db:
            with pytest.raises(ValueError, match="read-only"):
                db.query("DROP TABLE hosts")


# --- CLI integration ---------------------------------------------


class TestCliQuery:
    def _populated_db(self, tmp_path):
        db_path = tmp_path / "e.db"
        with EngagementDB(db_path) as db:
            db.record_host("10.0.0.5")
            db.record_share("10.0.0.5", "Finance", can_write=True)
            db.record_hit("10.0.0.5", "Finance", "secret.cfg", "R", tier="Black")
        return db_path

    def test_summary_flag(self, tmp_path, capsys):
        db_path = self._populated_db(tmp_path)
        from sharesift.cli import main
        rc = main(["query", "--db", str(db_path), "--summary"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "hits_total" in out
        assert "1" in out

    def test_preset_live_creds(self, tmp_path, capsys):
        db_path = self._populated_db(tmp_path)
        from sharesift.cli import main
        rc = main(["query", "--db", str(db_path), "--preset", "live-creds"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Black" in out
        assert "Finance" in out

    def test_unknown_preset_errors(self, tmp_path):
        db_path = self._populated_db(tmp_path)
        from sharesift.cli import main
        # argparse rejects invalid preset choice
        with pytest.raises(SystemExit):
            main(["query", "--db", str(db_path), "--preset", "nope"])

    def test_raw_sql(self, tmp_path, capsys):
        db_path = self._populated_db(tmp_path)
        from sharesift.cli import main
        rc = main(["query", "--db", str(db_path), "SELECT host FROM hosts"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "10.0.0.5" in out

    def test_json_output(self, tmp_path, capsys):
        db_path = self._populated_db(tmp_path)
        from sharesift.cli import main
        rc = main([
            "query", "--db", str(db_path),
            "--json", "SELECT host FROM hosts",
        ])
        assert rc == 0
        import json as _json
        lines = capsys.readouterr().out.strip().splitlines()
        records = [_json.loads(line) for line in lines]
        assert records == [{"host": "10.0.0.5"}]

    def test_no_args_errors(self, tmp_path):
        db_path = self._populated_db(tmp_path)
        from sharesift.cli import main
        with pytest.raises(SystemExit, match="--summary|--preset|positional"):
            main(["query", "--db", str(db_path)])
