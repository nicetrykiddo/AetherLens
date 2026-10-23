import contextlib
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest

from aetherlens.cli import main
from aetherlens.fusion import read_capture


class OfflineWorkflowTests(unittest.TestCase):
    def test_two_offline_laptops_can_export_and_fuse(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            captures = []
            for sensor in ("lab-laptop", "library-laptop"):
                db = base / f"{sensor}.sqlite"
                capture = base / f"{sensor}.json"
                scan = [{
                    "collected_at": "2026-10-23T12:00:00Z",
                    "source": sensor,
                    "access_points": [{
                        "bssid": "02:00:00:00:00:42",
                        "ssid": "Campus", "frequency_mhz": 2412,
                        "signal_dbm": -49,
                        "security": "WPA2" if sensor == "lab-laptop" else "OPEN",
                    }],
                }]
                fixture = base / f"{sensor}-input.json"
                fixture.write_text(json.dumps(scan), encoding="utf-8")
                with contextlib.redirect_stdout(StringIO()):
                    self.assertEqual(main(["--db", str(db), "import", str(fixture)]), 0)
                    self.assertEqual(main(["--db", str(db), "export", str(capture),
                                           "--sensor", sensor, "--site", sensor]), 0)
                self.assertEqual(read_capture(capture).sensor_id, sensor)
                captures.append(capture)
            output = StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["fuse", *map(str, captures), "--output", "json"]), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["observed_bssids"], 1)
            self.assertEqual(report["findings"][0]["kind"], "simultaneous_security_conflict")


if __name__ == "__main__":
    unittest.main()
