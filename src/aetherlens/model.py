"""Validated observations shared by collectors, storage, and analysis."""

from dataclasses import dataclass
from datetime import datetime, timezone
import re

_FINGERPRINT = re.compile(r"(?:ie1|iw1):[0-9a-f]{64}\Z")
_MAC = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z")


@dataclass(frozen=True, slots=True)
class AccessPoint:
    bssid: str
    ssid: str
    frequency_mhz: int
    signal_dbm: float
    security: str
    fingerprint: str | None = None

    def __post_init__(self) -> None:
        if not _MAC.fullmatch(self.bssid):
            raise ValueError(f"invalid BSSID: {self.bssid!r}")
        object.__setattr__(self, "bssid", self.bssid.lower())
        if len(self.ssid.encode("utf-8")) > 32:
            raise ValueError("SSID exceeds 32 UTF-8 bytes")
        if not 2300 <= self.frequency_mhz <= 7125:
            raise ValueError("frequency is outside supported Wi-Fi bands")
        if not -120 <= self.signal_dbm <= 0:
            raise ValueError("signal strength must be between -120 and 0 dBm")
        if self.security not in {"OPEN", "WEP", "WPA", "WPA2", "WPA3", "WPA2/WPA3", "OWE"}:
            raise ValueError(f"unknown security type: {self.security}")
        if self.fingerprint is not None and not _FINGERPRINT.fullmatch(self.fingerprint):
            raise ValueError("invalid radio fingerprint")


@dataclass(frozen=True, slots=True)
class Snapshot:
    collected_at: str
    access_points: tuple[AccessPoint, ...]
    source: str

    @classmethod
    def create(cls, points: list[AccessPoint], source: str, collected_at: str | None = None) -> "Snapshot":
        timestamp = collected_at or datetime.now(timezone.utc).isoformat()
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("collected_at must include a timezone")
        if not source.strip():
            raise ValueError("source must not be empty")
        if len({p.bssid for p in points}) != len(points):
            raise ValueError("duplicate BSSID in a snapshot")
        return cls(timestamp, tuple(points), source)
