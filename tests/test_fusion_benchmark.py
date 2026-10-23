import unittest

from aetherlens.fusion_benchmark import benchmark_fusion


class FusionBenchmarkTests(unittest.TestCase):
    def test_reports_nonzero_correlations_and_detects_injected_conflict(self):
        result = benchmark_fusion(access_points=30, sensors=3, repeats=2)
        self.assertEqual(result["workload"], "synthetic_multisensor_correlation")
        self.assertGreater(result["comparable_pairs"], 0)
        self.assertEqual(result["injected_security_conflicts_found"], 2)

    def test_rejects_invalid_benchmark_parameters(self):
        for kwargs in (
            {"access_points": 0},
            {"sensors": 1},
            {"repeats": 0},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                benchmark_fusion(**kwargs)


if __name__ == "__main__":
    unittest.main()
