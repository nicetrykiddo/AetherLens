import unittest
from aetherlens.evaluation import LabeledPair, evaluate
from aetherlens.model import AccessPoint, Snapshot


def ap(i: int, sec: str):
    return AccessPoint(f"02:00:00:00:00:{i:02x}", "Campus", 2412, -50, sec)


class EvaluationTests(unittest.TestCase):
    def test_fp_and_fn_are_counted(self):
        before = Snapshot.create([ap(1, "WPA2")], "test")
        after = Snapshot.create([ap(1, "WPA2"), ap(2, "OPEN"), ap(3, "WPA2")], "test")
        pair = LabeledPair(before, after, frozenset({ap(3, "WPA2").bssid}), "test")
        result = evaluate([pair])
        self.assertEqual(result["false_positives"], 1)
        self.assertEqual(result["false_negatives"], 1)
        self.assertEqual(result["true_negatives"], 1)

    def test_rejects_unobserved_labels(self):
        pair = LabeledPair(Snapshot.create([], "test"), Snapshot.create([], "test"), frozenset({ap(1, "OPEN").bssid}), "bad")
        with self.assertRaises(ValueError):
            evaluate([pair])


if __name__ == "__main__":
    unittest.main()
