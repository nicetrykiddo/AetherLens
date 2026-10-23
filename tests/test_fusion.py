"""A/B sensor evidence and false-positive controls for offline fusion."""

from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from aetherlens.fusion import Capture, fuse, read_capture, write_capture
from aetherlens.model import AccessPoint, Snapshot


FPA = "ie1:" + "a" * 64
FPB = "ie1:" + "b" * 64
FPC = "iw1:" + "b" * 64


def sample(sensor: str, site: str, security: str = "WPA2",
           fingerprint: str | None = None, bssid: str = "02:00:00:00:00:01",
           when: str = "2026-10-23T11:00:00Z", ssid: str = "Campus") -> Capture:
    return Capture(sensor, site, Snapshot.create([
        AccessPoint(bssid, ssid, 2412, -50, security, fingerprint)
    ], f"test:{sensor}", when))


class FusionTests(unittest.TestCase):
    def test_simultaneous_security_conflict(self):
        result = fuse([sample("one", "library"), sample("two", "lab", "OPEN")])
        self.assertEqual([f["kind"] for f in result["findings"]],
                         ["simultaneous_security_conflict"])
        self.assertEqual(result["compared_pairs"], 1)

    def test_signature_conflict_is_comparable_only_within_family(self):
        a = sample("one", "lab", fingerprint=FPA)
        b = sample("two", "hall", fingerprint=FPB)
        result = fuse([a, b])
        self.assertEqual([f["kind"] for f in result["findings"]],
                         ["simultaneous_radio_identity_conflict"])
        self.assertEqual(fuse([a, replace(b, snapshot=Snapshot.create([
            AccessPoint("02:00:00:00:00:01", "Campus", 2412, -50, "WPA2", FPC)
        ], "test:two", "2026-10-23T11:00:00Z"))])["findings"], [])

    def test_stale_observations_are_not_compared(self):
        a = sample("one", "hall")
        b = sample("two", "library", "OPEN", when="2026-10-23T11:05:00Z")
        result = fuse([a, b])
        self.assertEqual(result["compared_pairs"], 0)
        self.assertEqual(result["findings"], [])

    def test_shared_ssid_different_bssid_is_normal(self):
        a = sample("one", "hall")
        b = sample("two", "library", "OPEN", bssid="02:00:00:00:00:02")
        self.assertEqual(fuse([a, b])["findings"], [])

    def test_one_sensor_cannot_fake_independent_consensus(self):
        with self.assertRaises(ValueError):
            fuse([sample("one", "hall"), sample("one", "library")])

    def test_checksum_round_trip_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "capture.json"
            cap = sample("one", "hall", fingerprint=FPA)
            write_capture(path, cap)
            self.assertEqual(read_capture(path), cap)
            path.write_text(path.read_text().replace("Campus", "Campus-1"))
            with self.assertRaises(ValueError):
                read_capture(path)

    def test_needs_two_sensors_and_reasonable_skew(self):
        with self.assertRaises(ValueError):
            fuse([sample("one", "hall")])
        with self.assertRaises(ValueError):
            fuse([sample("one", "hall"), sample("two", "hall")], -1)


if __name__ == "__main__":
    unittest.main()
