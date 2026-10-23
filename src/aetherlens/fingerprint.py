"""Stable management-frame capabilities used to flag transmitter identity drift.

Only attributes unlikely to change within a deployment are included; SSID,
channel, BSSID, RSSI, timestamps, and traffic counters are deliberately
excluded. Signatures from different collector formats are never compared.
"""

from hashlib import sha256
import json
import re

# Stable capabilities and supported rates. HE/EHT extension IEs are not
# included yet: extensions can encode variable-length, driver-specific data.
_STABLE_IES = {1: "rates", 50: "extended_rates", 45: "ht", 191: "vht", 127: "extended"}
_HEX = re.compile(r"0x[0-9a-fA-F]+")
_VENDOR = re.compile(r"Vendor specific:\s*OUI\s+([0-9a-fA-F:]{8})(?:,\s*(.*))?", re.I)


def _hash(features: tuple[str, ...], scheme: str) -> str | None:
    if len(features) < 2:
        return None
    data = json.dumps(features, separators=(",", ":"), ensure_ascii=True).encode()
    return f"{scheme}:{sha256(data).hexdigest()}"


def ie_capabilities(raw: bytes) -> tuple[str, ...]:
    """Fingerprint stable parts of 802.11 IEs, excluding volatile fields.

    Malformed trailing elements invalidate the fingerprint rather than
    producing partial evidence. Ignore the vendor payload, which can carry
    counters and configurable data. OUI + subtype only is retained.
    """
    offset = 0
    features: list[str] = []
    while offset + 2 <= len(raw):
        tag, length = raw[offset:offset + 2]
        offset += 2
        if offset + length > len(raw):
            return ()
        value = raw[offset:offset + length]
        offset += length
        if tag in _STABLE_IES and value:
            features.append(f"{_STABLE_IES[tag]}:{value.hex()}")
        elif tag == 221 and len(value) >= 4:
            features.append(f"vendor:{value[:4].hex()}")
    if offset != len(raw):
        return ()
    return tuple(sorted(set(features)))


def ie_fingerprint(raw: bytes) -> str | None:
    features = ie_capabilities(raw)
    if not any(feature.startswith(("rates:", "extended_rates:")) for feature in features):
        return None
    return _hash(features, "ie1")


def iw_capabilities(block: list[str]) -> tuple[str, ...]:
    """Use explicitly reported Linux iw rates, HT/VHT, and vendor hints.

    This is a separate signature family from raw Windows IEs because iw
    omits or reformats some management-frame attributes.
    """
    features: list[str] = []
    for line in block:
        line = line.strip()
        if line.startswith(("Supported rates:", "Extended supported rates:")):
            label, value = line.split(":", 1)
            rates = " ".join(value.split())
            if rates:
                features.append(f"{label.lower().replace(' ', '_')}:{rates}")
        elif line.startswith(("HT capabilities:", "VHT capabilities:")):
            key, value = line.split(":", 1)
            hexcode = _HEX.search(value)
            if hexcode:
                features.append(f"{key.lower().replace(' ', '_')}:{hexcode.group().lower()}")
        elif match := _VENDOR.search(line):
            features.append(f"vendor:{match.group(1).lower()}")
    return tuple(sorted(set(features)))


def iw_fingerprint(block: list[str]) -> str | None:
    features = iw_capabilities(block)
    if not any("supported_rates:" in f for f in features):
        return None
    return _hash(features, "iw1")
