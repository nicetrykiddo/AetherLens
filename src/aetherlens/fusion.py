"""Offline cooperation between independent Wi-Fi observers.

Captures contain no client payloads or credentials. A checksum detects file
corruption but does not authenticate the contributor. Signal strength is not
compared across adapters because RSSI is hardware-dependent.
"""

from dataclasses import asdict, dataclass
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path

from .model import AccessPoint, Snapshot


@dataclass(frozen=True, slots=True)
class Capture:
    sensor_id: str
    site_id: str
    snapshot: Snapshot


@dataclass(frozen=True, slots=True)
class Conflict:
    kind: str
    severity: str
    bssid: str
    sensors: tuple[str, str]
    evidence: tuple[str, ...]


def _payload(capture: Capture) -> dict:
    return {
        "format": 1,
        "sensor_id": capture.sensor_id,
        "site_id": capture.site_id,
        "snapshot": {
            "collected_at": capture.snapshot.collected_at,
            "source": capture.snapshot.source,
            "access_points": [asdict(ap) for ap in capture.snapshot.access_points],
        },
    }


def _digest(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(encoded.encode("utf-8")).hexdigest()


def write_capture(path: str | Path, capture: Capture) -> None:
    if not capture.sensor_id.strip() or not capture.site_id.strip():
        raise ValueError("sensor and site IDs are required")
    payload = _payload(capture)
    payload["sha256"] = _digest(payload)
    Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def read_capture(path: str | Path) -> Capture:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    checksum = data.pop("sha256", None)
    if data.get("format") != 1 or not isinstance(checksum, str) or checksum != _digest(data):
        raise ValueError(f"{path}: invalid capture checksum or format")
    sensor = data["sensor_id"]
    site = data["site_id"]
    if not isinstance(sensor, str) or not sensor.strip() or not isinstance(site, str) or not site.strip():
        raise ValueError(f"{path}: sensor and site IDs must be nonempty strings")
    saved = data["snapshot"]
    snapshot = Snapshot.create(
        [AccessPoint(**ap) for ap in saved["access_points"]],
        saved["source"], saved["collected_at"],
    )
    return Capture(sensor, site, snapshot)


def _timestamp(snapshot: Snapshot) -> datetime:
    return datetime.fromisoformat(snapshot.collected_at.replace("Z", "+00:00"))


def fuse(captures: list[Capture], max_skew_seconds: float = 30) -> dict:
    """Compare independently observed AP identities within a bounded time window.

    Missing fingerprints remain unknown. Linux iw and Windows IE signatures are
    incomparable and must never be treated as contradictory.
    """
    if not 0 <= max_skew_seconds <= 3600:
        raise ValueError("max skew must be between 0 and 3600 seconds")
    if len(captures) < 2:
        raise ValueError("at least two captures are required")
    seen_ids = [cap.sensor_id for cap in captures]
    if len(set(seen_ids)) != len(seen_ids):
        raise ValueError("each capture needs a distinct sensor_id")

    groups: dict[str, list[tuple[Capture, AccessPoint]]] = {}
    for capture in captures:
        for ap in capture.snapshot.access_points:
            groups.setdefault(ap.bssid, []).append((capture, ap))

    findings: list[Conflict] = []
    compared_pairs = 0
    for bssid, entries in groups.items():
        for i, (left, first) in enumerate(entries):
            for right, second in entries[i + 1:]:
                skew = abs((_timestamp(left.snapshot) - _timestamp(right.snapshot)).total_seconds())
                if skew > max_skew_seconds:
                    continue
                compared_pairs += 1
                sensors = (left.sensor_id, right.sensor_id)
                if first.security != second.security:
                    findings.append(Conflict(
                        "simultaneous_security_conflict", "high", bssid, sensors,
                        (f"{left.sensor_id}: {first.security}",
                         f"{right.sensor_id}: {second.security}",
                         f"Observed {skew:g}s apart"),
                    ))
                if (first.fingerprint and second.fingerprint
                        and first.fingerprint.split(":", 1)[0] ==
                            second.fingerprint.split(":", 1)[0]
                        and first.fingerprint != second.fingerprint):
                    findings.append(Conflict(
                        "simultaneous_radio_identity_conflict", "medium", bssid, sensors,
                        ("Same BSSID advertises incompatible radio capability signatures",
                         f"Fingerprint family: {first.fingerprint.split(':')[0]}",
                         f"Observed {skew:g}s apart"),
                    ))
                if first.ssid != second.ssid:
                    findings.append(Conflict(
                        "simultaneous_ssid_conflict", "medium", bssid, sensors,
                        (f"{left.sensor_id}: {first.ssid!r}",
                         f"{right.sensor_id}: {second.ssid!r}",
                         f"Observed {skew:g}s apart"),
                    ))
    ordered = sorted(findings, key=lambda f: (f.bssid, f.kind, f.sensors))
    return {
        "sensor_count": len(captures),
        "observed_bssids": len(groups),
        "shared_bssids": sum(len(entries) > 1 for entries in groups.values()),
        "compared_pairs": compared_pairs,
        "max_skew_seconds": max_skew_seconds,
        "sensors": [{"id": c.sensor_id, "site": c.site_id,
                     "timestamp": c.snapshot.collected_at,
                     "observations": len(c.snapshot.access_points)} for c in captures],
        "findings": [asdict(f) for f in ordered],
        "note": "Conflicts are forensic leads, not proof of impersonation. "
                "Checksums do not authenticate sensors. No trilateration is inferred.",
    }
