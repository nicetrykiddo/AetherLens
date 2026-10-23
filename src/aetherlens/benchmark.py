"""Deterministic local-storage benchmark; results never stand in for radio measurements."""

from pathlib import Path
import math
import statistics
import tempfile
from time import perf_counter

from .model import AccessPoint, Snapshot
from .storage import ScanStore


def _dataset(count: int) -> Snapshot:
    points = [
        AccessPoint(f"02:00:{i >> 24 & 255:02x}:{i >> 16 & 255:02x}:{i >> 8 & 255:02x}:{i & 255:02x}",
                    f"AP-{i % 64}", 2412 + (i % 11) * 5, -30 - i % 65, "WPA2")
        for i in range(count)
    ]
    return Snapshot.create(points, "synthetic:storage-benchmark", "2026-01-01T00:00:00+00:00")


def _individual_commits(store: ScanStore, snap: Snapshot) -> None:
    """Baseline: durable commit for every observation rather than every scan."""
    with store.conn:
        scan_id = store.conn.execute(
            "INSERT INTO scans(collected_at, source) VALUES (?, ?)",
            (snap.collected_at, snap.source),
        ).lastrowid
    for ap in snap.access_points:
        with store.conn:
            store.conn.execute(
                """INSERT INTO access_points
                (scan_id, bssid, ssid, frequency_mhz, signal_dbm, security)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (scan_id, ap.bssid, ap.ssid, ap.frequency_mhz, ap.signal_dbm, ap.security),
            )


def _percentile(values: list[float], percent: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percent * len(ordered)) - 1)]


def run(access_points: int = 1000, repeats: int = 3) -> dict:
    if not 1 <= access_points <= 200_000:
        raise ValueError("--aps must be between 1 and 200000")
    if not 1 <= repeats <= 20:
        raise ValueError("--repeats must be between 1 and 20")
    snap = _dataset(access_points)
    individual_times: list[float] = []
    batch_times: list[float] = []
    query_times: list[float] = []
    with tempfile.TemporaryDirectory(prefix="aetherlens-bench-") as temporary:
        root = Path(temporary)
        for attempt in range(repeats):
            with ScanStore(root / f"individual-{attempt}.sqlite") as store:
                start = perf_counter()
                _individual_commits(store, snap)
                individual_times.append((perf_counter() - start) * 1000)
            with ScanStore(root / f"batched-{attempt}.sqlite") as store:
                start = perf_counter()
                store.record(snap)
                batch_times.append((perf_counter() - start) * 1000)
                for _ in range(30):
                    start = perf_counter()
                    latest = store.latest(1)
                    query_times.append((perf_counter() - start) * 1000)
                    assert len(latest[0].access_points) == access_points
    individual = statistics.median(individual_times)
    batch = statistics.median(batch_times)
    return {
        "workload": "synthetic_sqlite_storage",
        "access_points": access_points,
        "repeats": repeats,
        "individual_commits_ms": round(individual, 3),
        "batch_ms": round(batch, 3),
        "batch_speedup": round(individual / batch, 3) if batch else 0,
        "batch_observations_per_second": round(access_points / (batch / 1000)) if batch else 0,
        "query_p50_ms": round(_percentile(query_times, 0.5), 3),
        "query_p95_ms": round(_percentile(query_times, 0.95), 3),
        "method": "Separate SQLite files per repeat; per-row durable transaction vs one transaction per scan; query all APs in latest scan",
    }
