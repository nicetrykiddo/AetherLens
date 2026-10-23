import unittest

from aetherlens.fingerprint import (
    ie_capabilities, ie_fingerprint, iw_fingerprint,
)


def element(tag: int, data: bytes) -> bytes:
    return bytes([tag, len(data)]) + data


class FingerprintTests(unittest.TestCase):
    def test_dynamic_fields_do_not_change_signature(self):
        fixed = element(1, bytes([2, 4, 11])) + element(45, bytes([0x6e, 0x01]))
        beacon_a = element(0, b"Campus") + element(3, b"\x01") + fixed
        beacon_b = element(0, b"New SSID") + element(3, b"\x0b") + fixed
        self.assertEqual(ie_fingerprint(beacon_a), ie_fingerprint(beacon_b))
        self.assertTrue(ie_fingerprint(beacon_a).startswith("ie1:"))

    def test_radio_capability_change_is_visible(self):
        first = element(1, b"\x02\x04") + element(45, b"\x01\x02")
        second = element(1, b"\x02\x04") + element(45, b"\x01\x03")
        self.assertNotEqual(ie_fingerprint(first), ie_fingerprint(second))

    def test_malformed_and_insufficient_ies_are_not_fingerprinted(self):
        self.assertIsNone(ie_fingerprint(element(1, b"\x02")))
        self.assertEqual(ie_capabilities(b"\x2d\xff\x01"), ())
        self.assertIsNone(ie_fingerprint(b"\x01\x02\x01"))

    def test_vendor_dynamic_bytes_are_ignored(self):
        base = element(1, b"\x02\x04")
        vendor_a = element(221, b"\x00\x11\x22\x01HELLO")
        vendor_b = element(221, b"\x00\x11\x22\x01WORLD")
        self.assertEqual(ie_fingerprint(base + vendor_a), ie_fingerprint(base + vendor_b))

    def test_linux_fingerprint_is_separate_scheme(self):
        data = [
            "Supported rates: 6.0* 9.0 12.0*",
            "HT capabilities: 0x6e",
            "Vendor specific: OUI 00:11:22, data 01 23 45",
        ]
        self.assertTrue(iw_fingerprint(data).startswith("iw1:"))
        self.assertEqual(iw_fingerprint(data),
                         iw_fingerprint([data[0], data[1], "Vendor specific: OUI 00:11:22, data aa bb"]))


if __name__ == "__main__":
    unittest.main()
