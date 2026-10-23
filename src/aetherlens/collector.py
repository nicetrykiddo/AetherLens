"""Collect Wi-Fi beacon/probe-response observations using Linux iw."""

import re
import subprocess
import sys

from .model import AccessPoint, Snapshot
from .fingerprint import iw_fingerprint

_BSS = re.compile(r"^BSS\s+([0-9a-f:]{17})\b", re.IGNORECASE)
_FREQ = re.compile(r"^freq:\s*(\d+)")
_SIGNAL = re.compile(r"^signal:\s*(-?\d+(?:\.\d+)?)\s*dBm")


def _security(block: list[str]) -> str:
    text = "\n".join(block)
    rsn = "RSN:" in text
    wpa = any(line.strip() == "WPA:" for line in block)
    if rsn:
        sae = "SAE" in text
        psk = "PSK" in text
        if sae and psk:
            return "WPA2/WPA3"
        if sae:
            return "WPA3"
        if "OWE" in text:
            return "OWE"
        return "WPA2"
    if wpa:
        return "WPA"
    if any("capability:" in line and "Privacy" in line for line in block):
        return "WEP"
    return "OPEN"


def parse_iw_scan(raw: str) -> list[AccessPoint]:
    """Parse `iw dev IFACE scan` output. Skip incomplete BSS records."""
    blocks: list[tuple[str, list[str]]] = []
    bssid: str | None = None
    lines: list[str] = []
    for line in raw.splitlines():
        match = _BSS.match(line)
        if match:
            if bssid is not None:
                blocks.append((bssid, lines))
            bssid, lines = match.group(1), []
        elif bssid is not None:
            lines.append(line.strip())
    if bssid is not None:
        blocks.append((bssid, lines))

    points: dict[str, AccessPoint] = {}
    for bssid, block in blocks:
        freq = next((m.group(1) for line in block if (m := _FREQ.match(line))), None)
        signal = next((m.group(1) for line in block if (m := _SIGNAL.match(line))), None)
        ssid_line = next((line for line in block if line.startswith("SSID:")), None)
        if freq is None or signal is None or ssid_line is None:
            continue
        try:
            point = AccessPoint(bssid, ssid_line.removeprefix("SSID:").strip(), int(freq), float(signal), _security(block), iw_fingerprint(block))
        except ValueError:
            continue
        old = points.get(point.bssid)
        if old is None or point.signal_dbm > old.signal_dbm:
            points[point.bssid] = point
    return sorted(points.values(), key=lambda p: (-p.signal_dbm, p.bssid))


def interfaces() -> list[str]:
    if sys.platform == "win32":
        from .windows import interfaces as windows_interfaces
        return windows_interfaces()
    if sys.platform != "linux":
        raise RuntimeError(f"Wi-Fi scanning is not supported on {sys.platform}")
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True,
                                timeout=10, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Unable to enumerate Wi-Fi adapters with iw") from exc
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "iw dev failed")
    return re.findall(r"^\s+Interface\s+(\S+)", result.stdout, re.MULTILINE)


def scan(interface: str | None = None, timeout: int = 45) -> Snapshot:
    if sys.platform == "win32":
        from .windows import scan as windows_scan
        return windows_scan(interface, timeout=min(timeout, 12))
    if sys.platform != "linux":
        raise RuntimeError(f"Wi-Fi scanning is not supported on {sys.platform}")
    if interface is None:
        raise ValueError("Linux needs --interface; run 'aetherlens interfaces' to list adapters")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", interface):
        raise ValueError("invalid network interface name")
    try:
        result = subprocess.run(
            ["iw", "dev", interface, "scan"], capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("iw is not installed (install wireless-regdb and iw for your distro)") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"scan timed out after {timeout}s") from exc
    if result.returncode:
        reason = result.stderr.strip() or f"iw exited with code {result.returncode}"
        raise RuntimeError(f"wireless scan failed: {reason}")
    return Snapshot.create(parse_iw_scan(result.stdout), source=f"iw:{interface}")
