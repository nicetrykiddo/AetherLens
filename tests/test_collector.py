import sys
import unittest
from aetherlens.collector import parse_iw_scan
from aetherlens.model import AccessPoint, Snapshot

SCAN = """BSS AA:BB:CC:DD:EE:01(on wlan0)
\tfreq: 2412
\tsignal: -43.00 dBm
\tSSID: Campus
\tcapability: ESS Privacy
\tRSN:
\t\t* Authentication suites: PSK
BSS aa:bb:cc:dd:ee:02(on wlan0)
\tfreq: 5180
\tsignal: -67.50 dBm
\tSSID: Campus
\tcapability: ESS Privacy
\tRSN:
\t\t* Authentication suites: SAE
BSS aa:bb:cc:dd:ee:03(on wlan0)
\tfreq: 2437
\tsignal: -81.00 dBm
\tSSID:
\tcapability: ESS
BSS aa:bb:cc:dd:ee:04(on wlan0)
\tfreq: 2462
\tSSID: Incomplete
"""


class CollectorTests(unittest.TestCase):
    def test_security_and_hidden_ssid(self):
        aps = parse_iw_scan(SCAN)
        self.assertEqual(len(aps), 3)
        self.assertEqual([p.security for p in aps], ["WPA2", "WPA3", "OPEN"])
        self.assertEqual(aps[-1].ssid, "")

    def test_invalid_and_duplicate_bssid(self):
        with self.assertRaises(ValueError):
            AccessPoint("bad", "SSID", 2412, -50, "WPA2")
        ap = parse_iw_scan(SCAN)[0]
        with self.assertRaises(ValueError):
            Snapshot.create([ap, ap], source="test")

    @unittest.skipUnless(sys.platform == "linux", "Linux iw interface validation")
    def test_no_shell_or_command_injection(self):
        from aetherlens.collector import scan
        with self.assertRaises(ValueError):
            scan("wlan0;echo hi")


if __name__ == "__main__":
    unittest.main()
