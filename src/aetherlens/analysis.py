"""Explainable changes between scans; indicators are not attack attribution."""

from dataclasses import dataclass
from .model import Snapshot

_STRENGTH = {"OPEN": 0, "WEP": 1, "WPA": 2, "OWE": 2, "WPA2": 3, "WPA2/WPA3": 4, "WPA3": 5}


@dataclass(frozen=True, slots=True)
class Finding:
    severity: str
    kind: str
    bssid: str
    detail: str


def compare(previous: Snapshot, current: Snapshot) -> list[Finding]:
    prior = {ap.bssid: ap for ap in previous.access_points}
    now = {ap.bssid: ap for ap in current.access_points}
    known_ssids: dict[str, list] = {}
    for ap in prior.values():
        if ap.ssid:
            known_ssids.setdefault(ap.ssid, []).append(ap)

    findings: list[Finding] = []
    for bssid, ap in now.items():
        old = prior.get(bssid)
        if old:
            if _STRENGTH[ap.security] < _STRENGTH[old.security]:
                findings.append(Finding(
                    "high", "security_downgrade", bssid,
                    f"{old.ssid or '<hidden>'}: {old.security} -> {ap.security} on the same BSSID",
                ))
            if (old.fingerprint and ap.fingerprint
                    and old.fingerprint.split(":", 1)[0] == ap.fingerprint.split(":", 1)[0]
                    and old.fingerprint != ap.fingerprint):
                findings.append(Finding(
                    "medium", "radio_signature_changed", bssid,
                    "Advertised radio capabilities changed for a known BSSID. "
                    "Possible hardware replacement, firmware update, or identity conflict; "
                    "requires verification.",
                ))
            if ap.ssid != old.ssid:
                findings.append(Finding(
                    "medium", "ssid_changed", bssid,
                    f"SSID changed from {old.ssid!r} to {ap.ssid!r}",
                ))
            continue

        similar = known_ssids.get(ap.ssid, [])
        if similar and ap.security in {"OPEN", "WEP"} and any(
            _STRENGTH[p.security] >= _STRENGTH["WPA2"] for p in similar
        ):
            findings.append(Finding(
                "high", "possible_open_replica", bssid,
                f"New {ap.security} transmitter advertises {ap.ssid!r}, previously observed with WPA2/WPA3. Verify ownership; this is not proof of an evil twin.",
            ))
        else:
            findings.append(Finding("info", "new_bssid", bssid, f"New transmitter: {ap.ssid or '<hidden>'} ({ap.security})"))
    for bssid in prior.keys() - now.keys():
        findings.append(Finding("info", "not_seen", bssid, "Previously observed transmitter absent from this scan; it may still be nearby"))
    return sorted(findings, key=lambda f: ({"high": 0, "medium": 1, "info": 2}[f.severity], f.bssid, f.kind))
