"""Packet parser tests use genuine 802.11 frame fields, not mock scan records."""

from dataclasses import replace
from pathlib import Path
import random
import struct
import tempfile
import unittest

from aetherlens.pcap import _beacon, read_pcap
from aetherlens.pcap_lab import Network, beacon_bytes, scenarios, write_pcap


class PcapTests(unittest.TestCase):
    def test_replay_decodes_radio_security_and_fingerprints(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "frames.pcap"
            count = write_pcap(path, (
                Network("02:11:22:33:44:10", "Campus", "WPA2", 2412, -53),
                Network("02:11:22:33:44:10", "Campus", "OPEN", 2412, -37),
            ), frame_repeats=2)
            trace = read_pcap(path)
            self.assertEqual(len(trace.frames), count)
            self.assertEqual({f.ap.security for f in trace.frames}, {"WPA2", "OPEN"})
            self.assertEqual({f.ap.signal_dbm for f in trace.frames}, {-53, -37})
            self.assertTrue(all(f.ap.fingerprint.startswith("ie1:") for f in trace.frames))
            self.assertIn("intra_capture_security_conflict",
                          {f["kind"] for f in trace.contradictions()})
            self.assertEqual(len(trace.snapshot("test").access_points), 1)

    def test_full_scenarios_contain_negative_cases_and_known_misses(self):
        results = {}
        with tempfile.TemporaryDirectory() as directory:
            for scenario in scenarios():
                path = Path(directory) / (scenario.name + ".pcap")
                write_pcap(path, scenario.frames, frame_repeats=3, schedule=scenario.schedule)
                trace = read_pcap(path)
                results[scenario.name] = bool(trace.contradictions())
        self.assertTrue(results["open_clone"])
        self.assertTrue(results["radio_identity_conflict"])
        self.assertFalse(results["normal_enterprise"])
        self.assertFalse(results["channel_switch"])
        self.assertFalse(results["hidden_ssid"])
        self.assertFalse(results["independent_guest"])
        self.assertFalse(results["firmware_security_migration"])  # one-way migration
        self.assertFalse(results["same_security_clone"])  # known false negative

    def test_padding_in_radiotap_before_channel(self):
        base = beacon_bytes(Network("02:11:22:33:44:10", "Campus"), 1, 123)
        custom = struct.pack("<BBHIQHHb", 0, 0, 21, 0x29, 12345, 2412, 0xa0, -51)
        frame = _beacon(custom + base[13:], 1000.0)
        self.assertIsNotNone(frame)
        self.assertEqual(frame.ap.signal_dbm, -51)

    def test_bad_packet_metadata_does_not_generate_fake_results(self):
        packet = beacon_bytes(Network("02:11:22:33:44:10", "Campus"), 0, 0)
        self.assertIsNone(_beacon(packet[:5], 0))
        self.assertIsNone(_beacon(packet[:13] + b"\x08\x00" + packet[15:], 0))
        self.assertIsNone(_beacon(packet[:13] + b"\x80\x00" + packet[15:30], 0))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.pcap"
            path.write_bytes(b"not a real pcap file")
            with self.assertRaisesRegex(ValueError, "classic PCAP"):
                read_pcap(path)
            path.write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            with self.assertRaisesRegex(ValueError, "link type"):
                read_pcap(path)

    def test_packet_loss_and_packet_count_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "loss.pcap"
            frames = write_pcap(path, (Network("02:11:22:33:44:10", "test"),),
                                packet_loss=1.0, frame_repeats=5)
            self.assertEqual(frames, 0)
            with self.assertRaisesRegex(ValueError, "no supported"):
                read_pcap(path).snapshot("test")
            write_pcap(path, (Network("02:11:22:33:44:10", "test"),),
                       packet_loss=0.0, frame_repeats=5)
            with self.assertRaisesRegex(ValueError, "packet limit"):
                read_pcap(path, limit=2)

    def test_fuzzed_input_never_becomes_a_valid_beacon_by_accident(self):
        rng = random.Random(2309)
        for _ in range(200):
            payload = rng.randbytes(rng.randint(0, 180))
            self.assertIsNone(_beacon(payload, 0))


if __name__ == "__main__":
    unittest.main()
