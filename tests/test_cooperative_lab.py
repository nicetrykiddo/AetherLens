"""Cooperative receiver tests, including adversarial clock offset."""

import unittest

from aetherlens.model import AccessPoint
from aetherlens.pcap import Beacon, Trace
from aetherlens.pcap_experiment import run_cooperative_lab


def timeline(offset: float, bssid: str = "02:aa:bb:cc:dd:ee") -> Trace:
    """A single legitimate WPA2->WPA3 configuration transition per receiver."""
    frames = []
    for n, security in enumerate(("WPA2",) * 3 + ("WPA3",) * 3):
        ap = AccessPoint(bssid, "University", 2412, -45, security)
        frames.append(Beacon(offset + n * 0.1, ap))
    return Trace(tuple(frames), len(frames), 0)


class CooperativeLabTests(unittest.TestCase):
    def test_merge_of_uncalibrated_clocks_can_invent_attack(self):
        first = timeline(0)
        second = timeline(0.25)
        self.assertEqual(first.contradictions(), [])
        self.assertEqual(second.contradictions(), [])
        unsafe_merge = Trace(first.frames + second.frames, 12, 0)
        self.assertTrue(unsafe_merge.contradictions())  # demonstrates the bug
        self.assertFalse(any(bool(x.contradictions()) for x in (first, second)))

    def test_conservative_any_sensor_baseline(self):
        result = run_cooperative_lab(seeds=4, sensors=3, loss_rates=(0.0, 0.5))
        self.assertEqual(result["sensor_count"], 3)
        for row in result["results"]:
            self.assertGreaterEqual(
                row["cooperative"]["true_positives"] if "true_positives" in row["cooperative"]
                else row["cooperative"]["tp"],
                row["single_sensor"]["tp"],
            )
            self.assertEqual(row["cooperative"]["fp"], 0)  # benign suite has no A-B-A
            self.assertGreaterEqual(row["missed_attacks_recovered"], 0)


if __name__ == "__main__":
    unittest.main()
