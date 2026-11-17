"""SQLite archive of every article seen, so repeated runs can report only what's new."""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import Article


def _utc_iso(dt: datetime | None) -> str | None:
    """Store every timestamp in UTC so text order matches time order."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()

SCHEMA = """
CREATE TABLE IF NOT EXISTS articles (
    url        TEXT PRIMARY KEY,
    title      TEXT NOT NULL,
    source     TEXT NOT NULL,
    published  TEXT,
    summary    TEXT,
    author     TEXT,
    cves       TEXT,
    tags       TEXT,
    first_seen TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_articles_published ON articles(published);
"""


class Store:
    def __init__(self, path: str | Path):
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def add_new(self, articles: list[Article]) -> list[Article]:
        """Insert articles not seen before; return only those that were new."""
        new = []
        with self.conn:
            for a in articles:
                cur = self.conn.execute(
                    """INSERT OR IGNORE INTO articles
                       (url, title, source, published, summary, author, cves, tags)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (a.url, a.title, a.source, _utc_iso(a.published),
                     a.summary, a.author, json.dumps(a.cves), json.dumps(a.tags)),
                )
                if cur.rowcount:
                    new.append(a)
        return new

    def search(self, term: str, limit: int = 50) -> list[Article]:
        like = f"%{term}%"
        rows = self.conn.execute(
            """SELECT * FROM articles WHERE title LIKE ? OR summary LIKE ? OR cves LIKE ?
               ORDER BY julianday(published) DESC LIMIT ?""",
            (like, like, like, limit),
        ).fetchall()
        return [self._row_to_article(r) for r in rows]

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]

    @staticmethod
    def _row_to_article(r: sqlite3.Row) -> Article:
        return Article(
            title=r["title"], url=r["url"], source=r["source"],
            published=datetime.fromisoformat(r["published"]) if r["published"] else None,
            summary=r["summary"] or "", author=r["author"] or "",
            cves=json.loads(r["cves"] or "[]"), tags=json.loads(r["tags"] or "[]"),
        )
