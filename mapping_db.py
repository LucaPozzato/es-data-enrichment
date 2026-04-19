import sqlite3
import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent / "domain_mappings.db"


class MappingDB:
    """
    SQLite store for parent→child domain relationships discovered during
    redirect analysis. Enables fast context lookup on future alerts:
      e.g. real-website.com → tracking-pixel.com
    So when tracking-pixel.com triggers an alert, we already know the source.
    """

    def __init__(self, path: Path = DB_PATH):
        self.path = str(path)
        self._init()

    def _connect(self):
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA journal_mode=MEMORY")  # no journal files on disk — required with read_only container FS
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS domain_mappings (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    parent_domain TEXT    NOT NULL,
                    child_domain  TEXT    NOT NULL,
                    first_seen    TEXT    NOT NULL,
                    last_seen     TEXT    NOT NULL,
                    count         INTEGER DEFAULT 1,
                    UNIQUE(parent_domain, child_domain)
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_child ON domain_mappings(child_domain)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_parent ON domain_mappings(parent_domain)"
            )

    def lookup_parents(self, child_domain: str) -> list[dict]:
        """Return known parent domains for a child, ordered by frequency."""
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM domain_mappings WHERE child_domain = ? ORDER BY count DESC",
                (child_domain,),
            ).fetchall()
            return [dict(r) for r in rows]

    def record(self, parent_domain: str, child_domain: str) -> None:
        """Insert or increment a parent→child mapping."""
        if parent_domain == child_domain:
            return
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO domain_mappings
                    (parent_domain, child_domain, first_seen, last_seen, count)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(parent_domain, child_domain) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    count     = count + 1
                """,
                (parent_domain, child_domain, now, now),
            )
        log.debug("Mapping recorded: %s -> %s", parent_domain, child_domain)

    def all_mappings(self) -> list[dict]:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(
                "SELECT * FROM domain_mappings ORDER BY count DESC"
            ).fetchall()]
