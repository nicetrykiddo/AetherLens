import contextlib
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest

from aetherlens.benchmark import run
from aetherlens.cli import main


class CLITests(unittest.TestCase):
    def test_replay_and_json_report(self):
        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory) / "test.sqlite")
            sample = Path(__file__).resolve().parents[1] / "examples" / "sample_scans.json"
            with contextlib.redirect_stdout(StringIO()):
                self.assertEqual(main(["--db", db, "import", str(sample)]), 0)
            output = StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["--db", db, "report", "--output", "json"]), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(len(report["scan"]["access_points"]), 2)
            self.assertIn("possible_open_replica", [f["kind"] for f in report["findings"]])

    def test_benchmark_rejects_bad_inputs(self):
        with self.assertRaises(ValueError):
            run(0, 1)

    def test_benchmark_reports_metrics(self):
        metrics = run(10, 1)
        self.assertGreater(metrics["batch_observations_per_second"], 0)
        self.assertEqual(metrics["workload"], "synthetic_sqlite_storage")


if __name__ == "__main__":
    unittest.main()
