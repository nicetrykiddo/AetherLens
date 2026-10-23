"""Bounded replay of classic PCAP files carrying 802.11 Radiotap beacons.

Accepts DLT_IEEE802_11_RADIO (127), not Ethernet frames or pcapng. Parses
actual beacon/probe-response management frames; never fabricates RSSI,
frequencies, or encryption for packets whose metadata is missing.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
import struct

from .fingerprint import ie_fingerprint
from .model import AccessPoint, Snapshot
from .windows import _security

_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_RADIOTAP_FIELDS = (
    (8, 8),  # TSFT
    (1, 1),  # flags
    (1, 1),  # rate
    (2, 4),  # channel (MHz, flags)
    (2, 2),  # FHSS
    (1, 1),  # RSSI dBm
)


@dataclass(frozen=True, slots=True)
class Beacon:
    timestamp: float
    ap: AccessPoint


@dataclass(frozen=True, slots=True)
class Trace:
    frames: tuple[Beacon, ...]
    packets_read: int
    packets_skipped: int

    def snapshot(self, source: str) -> Snapshot:
        if not self.frames:
            raise ValueError("capture contains no supported beacon/probe-response observations")
        strongest: dict[str, AccessPoint] = {}
        for beacon in self.frames:
            old = strongest.get(beacon.ap.bssid)
            if old is None or beacon.ap.signal_dbm > old.signal_dbm:
                strongest[beacon.ap.bssid] = beacon.ap
        observed_at = datetime.fromtimestamp(
            max(frame.timestamp for frame in self.frames), timezone.utc
        ).isoformat()
        return Snapshot.create(list(strongest.values()), source, observed_at)

    def contradictions(self, max_gap_seconds: float = 3.0) -> list[dict]:
        """Correlate mutually inconsistent same-BSSID frames, within one capture.

        Several changes can be legitimate; this reports evidence, not attribution.
        """
        if max_gap_seconds < 0:
            raise ValueError("max_gap_seconds cannot be negative")
        per_bssid: dict[str, list[Beacon]] = {}
        for item in self.frames:
            per_bssid.setdefault(item.ap.bssid, []).append(item)
        findings = []
        for bssid, observed in per_bssid.items():
            last: Beacon | None = None
            for item in sorted(observed, key=lambda frame: frame.timestamp):
                if last is not None and item.timestamp - last.timestamp <= max_gap_seconds:
                    difference: dict | None = None
                    if last.ap.security != item.ap.security:
                        difference = {
                            "kind": "intra_capture_security_conflict",
                            "first_security": last.ap.security,
                            "second_security": item.ap.security,
                        }
                    elif (
                        last.ap.fingerprint and item.ap.fingerprint
                        and last.ap.fingerprint.split(":", 1)[0]
                            == item.ap.fingerprint.split(":", 1)[0]
                        and last.ap.fingerprint != item.ap.fingerprint
                    ):
                        difference = {
                            "kind": "intra_capture_radio_signature_conflict",
                            "first_fingerprint": last.ap.fingerprint,
                            "second_fingerprint": item.ap.fingerprint,
                        }
                    if difference is not None:
                        findings.append({
                            "bssid": bssid,
                            **difference,
                            "delta_ms": round((item.timestamp - last.timestamp) * 1000, 3),
                            "timestamp": item.timestamp,
                        })
                last = item
        return findings


def _radiotap(packet: bytes) -> tuple[int, int, int] | None:
    if len(packet) < 8 or packet[0] != 0:
        return None
    length = struct.unpack_from("<H", packet, 2)[0]
    if not 8 <= length <= len(packet):
        return None
    words = []
    offset = 4
    while True:
        if offset + 4 > length or len(words) >= 8:
            return None
        word = struct.unpack_from("<I", packet, offset)[0]
        words.append(word)
        offset += 4
        if not word & (1 << 31):
            break
    present = words[0]
    frequency = signal = None
    for bit, (alignment, size) in enumerate(_RADIOTAP_FIELDS):
        if not (present & (1 << bit)):
            continue
        offset = (offset + alignment - 1) & ~(alignment - 1)
        if offset + size > length:
            return None
        if bit == 3:
            frequency = struct.unpack_from("<H", packet, offset)[0]
        elif bit == 5:
            signal = struct.unpack_from("<b", packet, offset)[0]
        offset += size
    if frequency is None or signal is None:
        return None
    return length, frequency, signal


def _beacon(packet: bytes, timestamp: float) -> Beacon | None:
    radio = _radiotap(packet)
    if radio is None:
        return None
    offset, frequency, rssi = radio
    data = packet[offset:]
    if len(data) < 36:
        return None
    control = struct.unpack_from("<H", data, 0)[0]
    if control & 0x000c != 0 or control & 0x00f0 not in (0x0080, 0x0050):
        return None
    if data[10:16] != data[16:22]:
        return None  # source MAC must identify the advertising BSSID
    bssid = ":".join(f"{part:02x}" for part in data[16:22])
    capabilities = struct.unpack_from("<H", data, 34)[0]
    elements = data[36:]
    ssid = None
    pos = 0
    while pos + 2 <= len(elements):
        tag, size = elements[pos:pos + 2]
        pos += 2
        if pos + size > len(elements):
            return None
        if tag == 0 and ssid is None:
            try:
                ssid = elements[pos:pos + size].decode("utf-8")
            except UnicodeDecodeError:
                return None
        pos += size
    if pos != len(elements) or ssid is None:
        return None
    try:
        ap = AccessPoint(
            bssid, ssid, frequency, float(rssi),
            _security(capabilities, elements),
            ie_fingerprint(elements),
        )
    except ValueError:
        return None
    return Beacon(timestamp, ap)


def read_pcap(path: str | Path, limit: int = 200_000) -> Trace:
    """Read classic PCAP as a stream, with explicit packet and length limits."""
    if not 1 <= limit <= 2_000_000:
        raise ValueError("limit must be between 1 and 2,000,000 packets")
    observations: list[Beacon] = []
    total = skipped = 0
    with Path(path).open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] not in _MAGIC:
            raise ValueError("not a supported classic PCAP file (pcapng not supported)")
        endian, divisor = _MAGIC[header[:4]]
        _, _, _, _, snaplen, linktype = struct.unpack_from(endian + "HHIIII", header, 4)
        if linktype != 127:
            raise ValueError(f"unsupported link type {linktype}; expected Radiotap (127)")
        if not 1 <= snaplen <= 1_048_576:
            raise ValueError("invalid capture snaplen")
        while True:
            record = stream.read(16)
            if not record:
                break
            if len(record) != 16:
                raise ValueError("truncated PCAP packet header")
            sec, fraction, length, original = struct.unpack(endian + "IIII", record)
            if length > snaplen or length > original:
                raise ValueError("invalid captured packet length")
            total += 1
            if total > limit:
                raise ValueError(f"PCAP exceeds packet limit ({limit})")
            packet = stream.read(length)
            if len(packet) != length:
                raise ValueError("truncated PCAP packet body")
            frame = _beacon(packet, sec + fraction / divisor)
            if frame is None:
                skipped += 1
            else:
                observations.append(frame)
    return Trace(tuple(observations), total, skipped)
