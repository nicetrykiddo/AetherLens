"""Reproducible, offline 802.11 management-frame test scenarios.

Frames are emitted into PCAP files, never transmitted over the air. Real packet
decoders must parse them before the detector sees any labels. Ground truth
lives outside the PCAP and is never available to the detection function.
"""

from dataclasses import dataclass
from pathlib import Path
import random
import struct


@dataclass(frozen=True, slots=True)
class Network:
    bssid: str
    ssid: str
    security: str = "WPA2"
    frequency_mhz: int = 2412
    signal_dbm: int = -55
    radio_variant: int = 1


@dataclass(frozen=True, slots=True)
class Scenario:
    name: str
    malicious: bool
    explanation: str
    frames: tuple[Network, ...]


def _ie(tag: int, value: bytes) -> bytes:
    if len(value) > 255:
        raise ValueError("information element exceeds 255 bytes")
    return bytes((tag, len(value))) + value


def beacon_bytes(network: Network, sequence: int, microseconds: int) -> bytes:
    """Construct real 802.11 beacon layout plus Radiotap channel/RSSI metadata."""
    mac = bytes.fromhex(network.bssid.replace(":", ""))
    if len(mac) != 6:
        raise ValueError("BSSID must have six octets")
    if network.security not in ("OPEN", "WPA2", "WPA3", "WPA2/WPA3"):
        raise ValueError("unsupported synthetic security mode")
    if not -120 <= network.signal_dbm <= 0:
        raise ValueError("RSSI must be valid")
    radiotap = struct.pack(
        "<BBHIHHb", 0, 0, 13, 0x28, network.frequency_mhz, 0x00a0,
        network.signal_dbm,
    )
    header = struct.pack(
        "<HH6s6s6sH", 0x0080, 0, b"\xff" * 6, mac, mac, (sequence % 4096) << 4,
    )
    capabilities = 0x0001 | (0x0010 if network.security != "OPEN" else 0)
    fixed = struct.pack("<QHH", microseconds, 100, capabilities)
    elements = (
        _ie(0, network.ssid.encode("utf-8"))
        + _ie(1, b"\x82\x84\x8b\x96")
        + _ie(45, bytes((network.radio_variant, 0x11)))
    )
    if network.security != "OPEN":
        suite = b"\x00\x0f\xac"
        akms = (2, 8) if network.security == "WPA2/WPA3" else (
            (8,) if network.security == "WPA3" else (2,)
        )
        rsn = (
            b"\x01\x00" + suite + b"\x04"
            + b"\x01\x00" + suite + b"\x04"
            + len(akms).to_bytes(2, "little")
            + b"".join(suite + bytes([akm]) for akm in akms)
            + b"\x00\x00"
        )
        elements += _ie(48, rsn)
    return radiotap + header + fixed + elements


def scenarios() -> tuple[Scenario, ...]:
    campus = Network("02:11:22:33:44:10", "University")
    guest = Network("02:11:22:33:44:11", "University")
    return (
        Scenario(
            "open_clone", True, "A cloned BSSID advertises OPEN and WPA2 security almost simultaneously.",
            (campus, Network(campus.bssid, campus.ssid, "OPEN", signal_dbm=-43)),
        ),
        Scenario(
            "normal_enterprise", False, "Legitimate APs share SSID but have distinct BSSIDs.",
            (campus, guest),
        ),
        Scenario(
            "firmware_security_migration", False, "A legitimate AP changes to WPA3 during configuration.",
            (campus, Network(campus.bssid, campus.ssid, "WPA3")),
        ),
        Scenario(
            "same_security_clone", True, "An indistinguishable clone advertises exactly the same fields.",
            (campus, Network(campus.bssid, campus.ssid, "WPA2", signal_dbm=-44)),
        ),
        Scenario(
            "radio_identity_conflict", True, "Same BSSID and security, incompatible radio capabilities.",
            (campus, Network(campus.bssid, campus.ssid, "WPA2", radio_variant=8)),
        ),
        Scenario(
            "channel_switch", False, "A legitimate AP moves to another channel.",
            (campus, Network(campus.bssid, campus.ssid, "WPA2", frequency_mhz=2437)),
        ),
        Scenario(
            "hidden_ssid", False, "Hidden SSID beacons do not indicate an attack.",
            (Network("02:11:22:33:44:20", "", "WPA2"),),
        ),
        Scenario(
            "independent_guest", False, "Open guest and secured employee SSIDs coexist.",
            (campus, Network("02:11:22:33:44:30", "Guest", "OPEN")),
        ),
    )


def write_pcap(path: str | Path, networks: tuple[Network, ...],
               seed: int = 0, frame_repeats: int = 3,
               packet_loss: float = 0.0) -> int:
    if not 1 <= frame_repeats <= 100:
        raise ValueError("frame_repeats must be in 1..100")
    if not 0 <= packet_loss <= 1:
        raise ValueError("packet_loss must be between 0 and 1")
    rng = random.Random(seed)
    count = 0
    # The same base time is used across captures so comparisons are reproducible.
    with Path(path).open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 127))
        for repetition in range(frame_repeats):
            for i, network in enumerate(networks):
                if rng.random() < packet_loss:
                    continue
                usec = (repetition * len(networks) + i) * 100_000
                frame = beacon_bytes(network, repetition * len(networks) + i, usec)
                output.write(struct.pack("<IIII", 1_782_000_000 + usec // 1_000_000,
                                         usec % 1_000_000, len(frame), len(frame)))
                output.write(frame)
                count += 1
    return count
