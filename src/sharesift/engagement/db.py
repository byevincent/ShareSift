"""SQLite engagement datastore (v0.40).

Schema (created on first ``EngagementDB(path)`` open):

  meta(key TEXT PRIMARY KEY, value TEXT)
  hosts(host TEXT PRIMARY KEY, alive INTEGER, port INTEGER,
        first_seen TEXT, last_seen TEXT)
  shares(host TEXT, share TEXT, type TEXT, comment TEXT,
         can_read INTEGER, can_write INTEGER,
         first_seen TEXT, last_seen TEXT,
         PRIMARY KEY(host, share))
  files(host TEXT, share TEXT, rel_path TEXT, size INTEGER,
        content_hash TEXT, first_seen TEXT, last_seen TEXT,
        PRIMARY KEY(host, share, rel_path))
  hits(host TEXT, share TEXT, rel_path TEXT, rule TEXT,
       tier TEXT, snippet TEXT, ts TEXT,
       PRIMARY KEY(host, share, rel_path, rule))

The schema is intentionally flat — operators query it with plain
SQL. Each tier (host / share / file / hit) carries first_seen +
last_seen for incremental-crawl resume semantics in v0.41+.
"""

from __future__ import annotations

import datetime as _dt
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator, Optional


_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS hosts (
        host TEXT PRIMARY KEY,
        alive INTEGER NOT NULL DEFAULT 0,
        port INTEGER NOT NULL DEFAULT 445,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS shares (
        host TEXT NOT NULL,
        share TEXT NOT NULL,
        type TEXT,
        comment TEXT,
        can_read INTEGER,
        can_write INTEGER,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        PRIMARY KEY(host, share),
        FOREIGN KEY(host) REFERENCES hosts(host)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS files (
        host TEXT NOT NULL,
        share TEXT NOT NULL,
        rel_path TEXT NOT NULL,
        size INTEGER,
        content_hash TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        PRIMARY KEY(host, share, rel_path)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS hits (
        host TEXT NOT NULL,
        share TEXT NOT NULL,
        rel_path TEXT NOT NULL,
        rule TEXT NOT NULL,
        tier TEXT,
        snippet TEXT,
        ts TEXT NOT NULL,
        PRIMARY KEY(host, share, rel_path, rule)
    )
    """,
    # Indexes for the common query shapes
    "CREATE INDEX IF NOT EXISTS idx_hits_tier ON hits(tier)",
    "CREATE INDEX IF NOT EXISTS idx_hits_rule ON hits(rule)",
    "CREATE INDEX IF NOT EXISTS idx_files_hash ON files(content_hash)",
]


def _now() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class EngagementDB:
    """Open or create a SQLite engagement datastore.

    Thread-safe for read; writes serialize through one connection.
    Operator queries via ``query()`` get the same connection (no
    cross-thread reads here — keep it simple).
    """

    SCHEMA_VERSION = "1"

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._init_schema()

    def _init_schema(self) -> None:
        for stmt in _SCHEMA:
            self._conn.execute(stmt)
        # Stamp schema version + creation time if first-time
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'"
        ).fetchone()
        if row is None:
            now = _now()
            self._conn.executemany(
                "INSERT INTO meta(key, value) VALUES(?, ?)",
                [
                    ("schema_version", self.SCHEMA_VERSION),
                    ("created_at", now),
                ],
            )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Recording: each upsert preserves first_seen and bumps last_seen.
    # ------------------------------------------------------------------

    def record_host(
        self, host: str, *, alive: bool = True, port: int = 445
    ) -> None:
        now = _now()
        self._conn.execute(
            """
            INSERT INTO hosts(host, alive, port, first_seen, last_seen)
            VALUES(?, ?, ?, ?, ?)
            ON CONFLICT(host) DO UPDATE SET
                alive = excluded.alive,
                port = excluded.port,
                last_seen = excluded.last_seen
            """,
            (host, int(alive), port, now, now),
        )
        self._conn.commit()

    def record_share(
        self,
        host: str,
        share: str,
        *,
        type_: str | None = None,
        comment: str | None = None,
        can_read: bool | None = None,
        can_write: bool | None = None,
    ) -> None:
        now = _now()
        self._conn.execute(
            """
            INSERT INTO shares(host, share, type, comment, can_read,
                               can_write, first_seen, last_seen)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(host, share) DO UPDATE SET
                type = COALESCE(excluded.type, shares.type),
                comment = COALESCE(excluded.comment, shares.comment),
                can_read = COALESCE(excluded.can_read, shares.can_read),
                can_write = COALESCE(excluded.can_write, shares.can_write),
                last_seen = excluded.last_seen
            """,
            (
                host, share, type_, comment,
                None if can_read is None else int(can_read),
                None if can_write is None else int(can_write),
                now, now,
            ),
        )
        self._conn.commit()

    def record_file(
        self,
        host: str,
        share: str,
        rel_path: str,
        *,
        size: int | None = None,
        content_hash: str | None = None,
    ) -> bool:
        """Insert or update a file row. Returns True if this is a
        new (host, share, rel_path); False if previously seen.
        v0.41+'s resume uses this for incremental-crawl skip."""
        now = _now()
        existed = self._conn.execute(
            "SELECT 1 FROM files WHERE host = ? AND share = ? AND rel_path = ?",
            (host, share, rel_path),
        ).fetchone() is not None
        self._conn.execute(
            """
            INSERT INTO files(host, share, rel_path, size, content_hash,
                              first_seen, last_seen)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(host, share, rel_path) DO UPDATE SET
                size = COALESCE(excluded.size, files.size),
                content_hash = COALESCE(excluded.content_hash, files.content_hash),
                last_seen = excluded.last_seen
            """,
            (host, share, rel_path, size, content_hash, now, now),
        )
        self._conn.commit()
        return not existed

    def record_hit(
        self,
        host: str,
        share: str,
        rel_path: str,
        rule: str,
        *,
        tier: str | None = None,
        snippet: str | None = None,
    ) -> None:
        now = _now()
        self._conn.execute(
            """
            INSERT OR REPLACE INTO hits(host, share, rel_path, rule,
                                        tier, snippet, ts)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (host, share, rel_path, rule, tier, snippet, now),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        """Run an operator-supplied SELECT. Returns Row objects (dict-
        accessible). Mutations should go through the typed record_*
        methods — this is for ad-hoc inspection."""
        if not sql.strip().lower().startswith("select"):
            raise ValueError(
                "EngagementDB.query() is read-only; use record_* for writes"
            )
        return list(self._conn.execute(sql, params))

    def summary(self) -> dict:
        """High-level stats for end-of-scan reporting."""
        def _scalar(sql: str) -> int:
            return self._conn.execute(sql).fetchone()[0]

        return {
            "hosts_total": _scalar("SELECT COUNT(*) FROM hosts"),
            "hosts_alive": _scalar("SELECT COUNT(*) FROM hosts WHERE alive = 1"),
            "shares_total": _scalar("SELECT COUNT(*) FROM shares"),
            "shares_writable": _scalar(
                "SELECT COUNT(*) FROM shares WHERE can_write = 1"
            ),
            "files_total": _scalar("SELECT COUNT(*) FROM files"),
            "hits_total": _scalar("SELECT COUNT(*) FROM hits"),
            "hits_black": _scalar(
                "SELECT COUNT(*) FROM hits WHERE tier = 'Black'"
            ),
            "hits_red": _scalar(
                "SELECT COUNT(*) FROM hits WHERE tier = 'Red'"
            ),
            "hits_yellow": _scalar(
                "SELECT COUNT(*) FROM hits WHERE tier = 'Yellow'"
            ),
        }

    @property
    def path(self) -> Path:
        return self._path

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass

    def __enter__(self) -> "EngagementDB":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
