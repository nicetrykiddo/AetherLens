import ctypes
import sys
import unittest
from unittest.mock import patch

from aetherlens import collector
from aetherlens.model import Snapshot
from aetherlens.windows import (
    _BssEntry, _Guid, _InterfaceInfo, _akm_suites, _pick, _security,
)


def rsn(*types: int) -> bytes:
    oui = b"\x00\x0f\xac"
    payload = (
        b"\x01\x00" + oui + b"\x04" +
        b"\x01\x00" + oui + b"\x04" +
        len(types).to_bytes(2, "little") +
        b"".join(oui + bytes([kind]) for kind in types)
    )
    return bytes([48, len(payload)]) + payload


class WindowsParserTests(unittest.TestCase):
    def test_security_from_rsn_information_elements(self):
        self.assertEqual(_security(0x10, rsn(2)), "WPA2")
        self.assertEqual(_security(0x10, rsn(8)), "WPA3")
        self.assertEqual(_security(0x10, rsn(2, 8)), "WPA2/WPA3")
        self.assertEqual(_security(0x10, rsn(18)), "OWE")
        self.assertEqual(_security(0x00, b""), "OPEN")
        self.assertEqual(_security(0x10, b""), "WEP")

    def test_malformed_rsn_does_not_crash(self):
        malformed = bytes([48, 5]) + b"\x01\x00\x00\x0f\xac"
        self.assertEqual(_security(0x10, malformed), "WPA2")
        self.assertEqual(_akm_suites(b"\x01\x00"), set())

    def test_vendor_wpa(self):
        self.assertEqual(_security(0x10, b"\xdd\x04\x00\x50\xf2\x01"), "WPA")

    def test_choose_unique_adapter(self):
        devices = [
            (_Guid(1, 2, 3, (ctypes.c_ubyte * 8)()), "Intel Wi-Fi"),
            (_Guid(4, 5, 6, (ctypes.c_ubyte * 8)()), "USB Wi-Fi"),
        ]
        self.assertEqual(_pick(devices, "Intel")[1], "Intel Wi-Fi")
        with self.assertRaises(ValueError):
            _pick(devices, "Wi-Fi")
        self.assertEqual(_pick(devices, None)[1], "Intel Wi-Fi")

    def test_windows_structure_sizes(self):
        if sys.platform != "win32":
            self.skipTest("Windows ABI check")
        self.assertEqual(ctypes.sizeof(_Guid), 16)
        self.assertEqual(ctypes.sizeof(_InterfaceInfo), 532)
        self.assertEqual(ctypes.sizeof(_BssEntry), 360)

    def test_collector_dispatches_to_windows(self):
        expected = Snapshot.create([], "test")
        with patch.object(collector.sys, "platform", "win32"):
            with patch("aetherlens.windows.scan", return_value=expected) as native:
                self.assertEqual(collector.scan(), expected)
                native.assert_called_once_with(None, timeout=12)


if __name__ == "__main__":
    unittest.main()
