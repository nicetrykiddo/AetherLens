from pathlib import Path
import tempfile
import unittest

from aetherlens.fusion import fuse
from aetherlens.model import AccessPoint, Snapshot
from aetherlens.fusion import Capture
from aetherlens.reporting import render_fusion, save_fusion


class ReportTests(unittest.TestCase):
    def test_html_escapes_untrusted_site_and_sensor_names(self):
        one = Capture('<script>alert(1)</script>', 'Lab & Lobby',
                      Snapshot.create([AccessPoint("02:00:00:00:00:01", "Office",
                                                   2412, -45, "WPA2")],
                                      "test", "2026-10-23T11:00:00Z"))
        two = Capture('second', 'library',
                      Snapshot.create([AccessPoint("02:00:00:00:00:01", "Office",
                                                   2412, -45, "OPEN")],
                                      "test", "2026-10-23T11:00:02Z"))
        report = fuse([one, two])
        html = render_fusion(report)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("simultaneous security conflict", html)
        self.assertIn("Lab &amp; Lobby", html)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.html"
            save_fusion(path, report)
            self.assertTrue(path.read_text(encoding="utf-8").startswith("<!doctype html>"))


if __name__ == "__main__":
    unittest.main()
