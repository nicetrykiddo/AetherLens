import contextlib
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from aetherlens.cli import main
from aetherlens.pcap_experiment import run_lab


class PacketLabTests(unittest.TestCase):
    def test_unmodified_detector_has_known_false_positive_and_false_negative(self):
        result = run_lab(seeds=1, loss_rates=(0.0,))
        row = result["results"][0]
        self.assertEqual(row["cases"], 8)
        self.assertEqual((row["tp"], row["fp"], row["fn"], row["tn"]),
                         (2, 1, 1, 4))
        self.assertEqual(row["precision"], 0.6667)
        self.assertEqual(row["recall"], 0.6667)
        self.assertEqual(len(row["first_seed_examples"]), 8)

    def test_packet_loss_sweep_is_reproducible(self):
        one = run_lab(seeds=3, loss_rates=(0.0, 0.35, 0.65))
        two = run_lab(seeds=3, loss_rates=(0.0, 0.35, 0.65))
        for left, right in zip(one["results"], two["results"]):
            self.assertEqual({k: v for k, v in left.items()
                              if k != "decode_and_detection_median_ms"},
                             {k: v for k, v in right.items()
                              if k != "decode_and_detection_median_ms"})

    def test_evidence_files_and_cli_replay(self):
        with TemporaryDirectory() as directory:
            result = run_lab(seeds=1, loss_rates=(0.0,), output_directory=directory)
            example = next(row for row in result["results"][0]["first_seed_examples"]
                           if row["name"] == "open_clone")
            path = Path(example["pcap_file"])
            self.assertTrue(path.is_file())
            output = StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["replay-pcap", str(path), "--output", "json"]), 0)
            report = json.loads(output.getvalue())
            self.assertGreater(report["supported_beacons"], 0)
            self.assertIn("intra_capture_security_conflict",
                          [f["kind"] for f in report["findings"]])

    def test_rejects_invalid_parameters(self):
        with self.assertRaises(ValueError):
            run_lab(seeds=0)
        with self.assertRaises(ValueError):
            run_lab(seeds=1, loss_rates=(1.1,))


if __name__ == "__main__":
    unittest.main()
