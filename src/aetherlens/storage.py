"""SQLite-backed scan history. Each scan is one atomic transaction."""

from pathlib import Path
import sqlite3

from .model import AccessPoint, Snapshot

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    collected_at TEXT NOT NULL,
    source TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS access_points (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    bssid TEXT NOT NULL,
    ssid TEXT NOT NULL,
    frequency_mhz INTEGER NOT NULL,
    signal_dbm REAL NOT NULL,
    security TEXT NOT NULL,
    fingerprint TEXT,
    PRIMARY KEY (scan_id, bssid)
);
CREATE INDEX IF NOT EXISTS ap_history ON access_points(bssid, scan_id);
"""


class ScanStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(_SCHEMA)
        columns = {row[1] for row in self.conn.execute("PRAGMA table_info(access_points)")}
        if "fingerprint" not in columns:
            self.conn.execute("ALTER TABLE access_points ADD COLUMN fingerprint TEXT")

    def __enter__(self) -> "ScanStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self.conn.close()

    def record(self, snapshot: Snapshot) -> int:
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO scans(collected_at, source) VALUES (?, ?)",
                (snapshot.collected_at, snapshot.source),
            )
            scan_id = cursor.lastrowid
            self.conn.executemany(
                """INSERT INTO access_points
                (scan_id, bssid, ssid, frequency_mhz, signal_dbm, security, fingerprint)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    (scan_id, ap.bssid, ap.ssid, ap.frequency_mhz, ap.signal_dbm, ap.security, ap.fingerprint)
                    for ap in snapshot.access_points
                ),
            )
        return scan_id

    def latest(self, count: int = 2) -> list[Snapshot]:
        rows = self.conn.execute(
            "SELECT id, collected_at, source FROM scans ORDER BY id DESC LIMIT ?", (count,)
        ).fetchall()
        snapshots = []
        for scan_id, collected_at, source in rows:
            points = [
                AccessPoint(*row) for row in self.conn.execute(
                    """SELECT bssid, ssid, frequency_mhz, signal_dbm, security, fingerprint
                    FROM access_points WHERE scan_id = ? ORDER BY signal_dbm DESC, bssid""",
                    (scan_id,),
                )
            ]
            snapshots.append(Snapshot.create(points, source, collected_at))
        return snapshots

    def history(self, bssid: str, limit: int = 100) -> list[tuple[str, float, str]]:
        return self.conn.execute(
            """SELECT s.collected_at, a.signal_dbm, a.security
            FROM access_points a JOIN scans s ON a.scan_id=s.id
            WHERE a.bssid=? ORDER BY a.scan_id DESC LIMIT ?""",
            (bssid.lower(), limit),
        ).fetchall()
