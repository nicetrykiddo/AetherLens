import unittest

from aetherlens.fusion import Capture
from aetherlens.model import AccessPoint, Snapshot
from aetherlens.planning import plan_sites


def survey(site: str, ids: set[int]) -> Capture:
    aps = [
        AccessPoint(f"02:00:00:00:{i >> 8 & 255:02x}:{i & 255:02x}",
                    f"AP-{i}", 2412, -50, "WPA2")
        for i in sorted(ids)
    ]
    return Capture(site, site, Snapshot.create(aps, f"test:{site}"))


class PlanningTests(unittest.TestCase):
    def test_greedy_is_measured_against_exact_optimum(self):
        captures = [
            survey("A", {1, 2, 3, 4}),
            survey("B", {1, 2, 5}),
            survey("C", {3, 4, 6}),
        ]
        result = plan_sites(captures, budget=2)
        self.assertEqual(result["selected_sites"], ["A", "B"])
        self.assertEqual(result["score"], 5)
        self.assertEqual(result["exact_optimum_score"], 6)
        self.assertAlmostEqual(result["greedy_to_optimum_percent"], 83.33, places=1)

    def test_more_sensors_in_same_room_do_not_fake_more_sites(self):
        captures = [survey("Lab", {1, 2}), survey("Lab", {3}),
                    survey("Hall", {1, 2})]
        result = plan_sites(captures, budget=2, witnesses=2)
        self.assertEqual(result["candidate_sites"], 2)
        self.assertEqual(result["unique_bssids_found"], 3)
        self.assertEqual(result["bssids_with_multiple_witnesses"], 2)

    def test_empty_captures_and_invalid_budgets(self):
        with self.assertRaises(ValueError):
            plan_sites([], budget=2)
        with self.assertRaises(ValueError):
            plan_sites([survey("Lab", {1})], budget=0)

    def test_rssi_threshold_restricts_observed_coverage(self):
        cap = survey("Lab", {1, 2})
        weak = AccessPoint("02:00:00:00:00:02", "AP-2", 2412, -100, "WPA2")
        cap = Capture(cap.sensor_id, cap.site_id,
                      Snapshot.create([cap.snapshot.access_points[0], weak], "test"))
        result = plan_sites([cap], 1)
        self.assertEqual(result["unique_bssids_found"], 1)


if __name__ == "__main__":
    unittest.main()
