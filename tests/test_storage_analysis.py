import tempfile
import unittest
from pathlib import Path

from aetherlens.analysis import compare
from aetherlens.model import AccessPoint, Snapshot
from aetherlens.storage import ScanStore


def point(mac: int, ssid: str = "Campus", security: str = "WPA2") -> AccessPoint:
    return AccessPoint(f"02:00:00:00:00:{mac:02x}", ssid, 2412, -50, security)


class StorageAndAnalysisTests(unittest.TestCase):
    def test_history_persists_and_orders_scans(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "scans.sqlite"
            first = Snapshot.create([point(1)], "test", "2026-10-01T00:00:00Z")
            second = Snapshot.create([point(1, security="OPEN"), point(2)], "test", "2026-10-01T00:01:00Z")
            with ScanStore(path) as store:
                store.record(first)
                store.record(second)
                recent, previous = store.latest()
                self.assertEqual(recent.access_points[0].security, "OPEN")
                self.assertEqual(len(store.history(point(1).bssid)), 2)
                findings = compare(previous, recent)
                self.assertIn("security_downgrade", [f.kind for f in findings])
            with ScanStore(path) as store:
                self.assertEqual(len(store.latest()), 2)

    def test_open_replica_is_evidence_not_certainty(self):
        previous = Snapshot.create([point(1)], "test")
        current = Snapshot.create([point(1), point(2, security="OPEN")], "test")
        findings = compare(previous, current)
        self.assertEqual([f.kind for f in findings], ["possible_open_replica"])
        self.assertIn("not proof", findings[0].detail)

    def test_legitimate_same_ssid_not_high_risk(self):
        previous = Snapshot.create([point(1)], "test")
        current = Snapshot.create([point(1), point(2)], "test")
        self.assertEqual(compare(previous, current)[0].severity, "info")

    def test_missed_scan_is_not_decommissioned(self):
        previous = Snapshot.create([point(1)], "test")
        current = Snapshot.create([], "test")
        finding = compare(previous, current)[0]
        self.assertEqual(finding.kind, "not_seen")
        self.assertIn("may still be nearby", finding.detail)


if __name__ == "__main__":
    unittest.main()
