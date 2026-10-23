"""Native Windows Wi-Fi collection using the WLAN API, without external packages.

The BSS API exposes driver-reported RSSI in dBm and per-transmitter IEs.
A scan is awaited before reading the results; cached lists are not silently
presented as a completed fresh scan.
"""

import ctypes
from ctypes import wintypes
from contextlib import contextmanager
import sys
from threading import Event
from uuid import UUID

from .model import AccessPoint, Snapshot
from .fingerprint import ie_fingerprint


class _Guid(ctypes.Structure):
    _fields_ = [
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    ]


class _InterfaceInfo(ctypes.Structure):
    _fields_ = [
        ("guid", _Guid),
        ("description", ctypes.c_wchar * 256),
        ("state", ctypes.c_int32),
    ]


class _Ssid(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint32),
        ("bytes", ctypes.c_ubyte * 32),
    ]


class _RateSet(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint32),
        ("rates", ctypes.c_uint16 * 126),
    ]


class _BssEntry(ctypes.Structure):
    _fields_ = [
        ("ssid", _Ssid),
        ("phy_id", ctypes.c_uint32),
        ("bssid", ctypes.c_ubyte * 6),
        ("bss_type", ctypes.c_int32),
        ("phy_type", ctypes.c_int32),
        ("rssi", ctypes.c_int32),
        ("quality", ctypes.c_uint32),
        ("in_reg_domain", ctypes.c_ubyte),
        ("beacon_period", ctypes.c_uint16),
        ("timestamp", ctypes.c_uint64),
        ("host_timestamp", ctypes.c_uint64),
        ("capabilities", ctypes.c_uint16),
        ("frequency_khz", ctypes.c_uint32),
        ("rates", _RateSet),
        ("ie_offset", ctypes.c_uint32),
        ("ie_size", ctypes.c_uint32),
    ]


class _Notification(ctypes.Structure):
    _fields_ = [
        ("source", ctypes.c_uint32),
        ("code", ctypes.c_uint32),
        ("guid", _Guid),
        ("data_size", ctypes.c_uint32),
        ("data", ctypes.c_void_p),
    ]


def _check(code: int, operation: str) -> None:
    if code == 5:
        raise RuntimeError(
            f"{operation} denied by Windows (error 5). Enable Location and "
            "desktop-app location access under Settings > Privacy & security > "
            "Location, and check the WLAN AutoConfig service."
        )
    if code:
        raise OSError(code, f"{operation} failed (Windows error {code})")


def _api():
    if sys.platform != "win32":
        raise RuntimeError("Native WLAN collection requires Windows")
    api = ctypes.WinDLL("wlanapi.dll")
    handle = ctypes.c_void_p
    pointer = ctypes.POINTER
    dword = ctypes.c_uint32
    api.WlanOpenHandle.argtypes = [dword, ctypes.c_void_p, pointer(dword), pointer(handle)]
    api.WlanOpenHandle.restype = dword
    api.WlanCloseHandle.argtypes = [handle, ctypes.c_void_p]
    api.WlanCloseHandle.restype = dword
    api.WlanEnumInterfaces.argtypes = [handle, ctypes.c_void_p, pointer(handle)]
    api.WlanEnumInterfaces.restype = dword
    api.WlanGetNetworkBssList.argtypes = [
        handle, pointer(_Guid), ctypes.c_void_p, ctypes.c_int32,
        ctypes.c_int32, ctypes.c_void_p, pointer(handle),
    ]
    api.WlanGetNetworkBssList.restype = dword
    api.WlanScan.argtypes = [
        handle, pointer(_Guid), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]
    api.WlanScan.restype = dword
    callback = ctypes.WINFUNCTYPE(None, pointer(_Notification), ctypes.c_void_p)
    api.WlanRegisterNotification.argtypes = [
        handle, dword, ctypes.c_int32, callback, ctypes.c_void_p,
        ctypes.c_void_p, pointer(dword),
    ]
    api.WlanRegisterNotification.restype = dword
    api.WlanFreeMemory.argtypes = [ctypes.c_void_p]
    api.WlanFreeMemory.restype = None
    return api, callback


@contextmanager
def _session():
    api, callback_type = _api()
    negotiated = ctypes.c_uint32()
    handle = ctypes.c_void_p()
    _check(api.WlanOpenHandle(2, None, ctypes.byref(negotiated), ctypes.byref(handle)),
           "WlanOpenHandle")
    try:
        yield api, handle, callback_type
    finally:
        api.WlanCloseHandle(handle, None)


def _interfaces(api, handle) -> list[tuple[_Guid, str]]:
    ptr = ctypes.c_void_p()
    _check(api.WlanEnumInterfaces(handle, None, ctypes.byref(ptr)), "WlanEnumInterfaces")
    try:
        if not ptr.value:
            raise RuntimeError("WLAN interface enumeration returned no data")
        count = ctypes.c_uint32.from_address(ptr.value).value
        if count > 64:
            raise RuntimeError("WLAN interface count is invalid")
        base = ptr.value + 8  # DWORD item count + DWORD selected index
        return [
            (
                _Guid.from_buffer_copy(ctypes.string_at(base + i * ctypes.sizeof(_InterfaceInfo), 16)),
                _InterfaceInfo.from_buffer_copy(
                    ctypes.string_at(base + i * ctypes.sizeof(_InterfaceInfo),
                                     ctypes.sizeof(_InterfaceInfo))
                ).description,
            )
            for i in range(count)
        ]
    finally:
        if ptr.value:
            api.WlanFreeMemory(ptr)


def interfaces() -> list[str]:
    with _session() as (api, handle, _):
        return [name for _, name in _interfaces(api, handle)]


def _pick(available: list[tuple[_Guid, str]], interface: str | None) -> tuple[_Guid, str]:
    if not available:
        raise RuntimeError("No Windows Wi-Fi adapters found")
    if interface is None:
        return available[0]
    matches = [
        item for item in available
        if interface.casefold() in item[1].casefold()
        or interface.casefold() == str(UUID(bytes_le=bytes(item[0]))).casefold()
    ]
    if len(matches) != 1:
        raise ValueError(
            f"Wi-Fi adapter {interface!r} not uniquely found. "
            f"Available: {', '.join(name for _, name in available)}"
        )
    return matches[0]


def _akm_suites(rsn: bytes) -> set[bytes]:
    """Return authentication suites from an RSN information element."""
    if len(rsn) < 8:
        return set()
    cursor = 6  # version (2) + group cipher (4)
    count = int.from_bytes(rsn[cursor:cursor + 2], "little")
    cursor += 2 + count * 4
    if cursor + 2 > len(rsn):
        return set()
    count = int.from_bytes(rsn[cursor:cursor + 2], "little")
    cursor += 2
    if count > (len(rsn) - cursor) // 4:
        return set()
    return {rsn[cursor + i * 4:cursor + (i + 1) * 4] for i in range(count)}


def _security(capabilities: int, information_elements: bytes) -> str:
    rsn: bytes | None = None
    wpa = False
    offset = 0
    while offset + 2 <= len(information_elements):
        identifier = information_elements[offset]
        length = information_elements[offset + 1]
        offset += 2
        if offset + length > len(information_elements):
            break  # malformed, untrusted frame data
        payload = information_elements[offset:offset + length]
        offset += length
        if identifier == 48:
            rsn = payload
        elif identifier == 221 and payload.startswith(b"\x00\x50\xf2\x01"):
            wpa = True
    if rsn is not None:
        suites = _akm_suites(rsn)
        sae = b"\x00\x0f\xac\x08" in suites
        psk = b"\x00\x0f\xac\x02" in suites
        if b"\x00\x0f\xac\x12" in suites:
            return "OWE"
        if sae and psk:
            return "WPA2/WPA3"
        if sae or b"\x00\x0f\xac\x0c" in suites:
            return "WPA3"
        return "WPA2"
    if wpa:
        return "WPA"
    return "WEP" if capabilities & 0x10 else "OPEN"


def _read_bss(api, handle, guid: _Guid) -> list[AccessPoint]:
    ptr = ctypes.c_void_p()
    _check(api.WlanGetNetworkBssList(
        handle, ctypes.byref(guid), None, 1, 0, None, ctypes.byref(ptr)
    ), "WlanGetNetworkBssList")
    try:
        if not ptr.value:
            raise RuntimeError("WLAN returned a null scan result")
        total, count = (ctypes.c_uint32 * 2).from_address(ptr.value)
        entry_size = ctypes.sizeof(_BssEntry)
        if total < 8 or count > (total - 8) // entry_size:
            raise RuntimeError("WLAN returned an invalid BSS buffer")
        points: dict[str, AccessPoint] = {}
        for i in range(count):
            entry_offset = 8 + i * entry_size
            entry = _BssEntry.from_buffer_copy(
                ctypes.string_at(ptr.value + entry_offset, entry_size)
            )
            if entry.ssid.length > 32 or entry.ie_size > 2324:
                continue
            if entry.ie_size:
                ie_start = entry_offset + entry.ie_offset
                if (entry.ie_offset < entry_size or ie_start + entry.ie_size > total):
                    continue
                information_elements = ctypes.string_at(
                    ptr.value + ie_start, entry.ie_size
                )
            else:
                information_elements = b""
            try:
                ssid = bytes(entry.ssid.bytes[:entry.ssid.length]).decode("utf-8")
                ap = AccessPoint(
                    ":".join(f"{byte:02x}" for byte in entry.bssid),
                    ssid, int(entry.frequency_khz // 1000), float(entry.rssi),
                    _security(entry.capabilities, information_elements),
                    ie_fingerprint(information_elements),
                )
            except (UnicodeError, ValueError):
                continue
            existing = points.get(ap.bssid)
            if existing is None or ap.signal_dbm > existing.signal_dbm:
                points[ap.bssid] = ap
        return sorted(points.values(), key=lambda ap: (-ap.signal_dbm, ap.bssid))
    finally:
        if ptr.value:
            api.WlanFreeMemory(ptr)


def scan(interface: str | None = None, timeout: float = 6) -> Snapshot:
    """Request and await a Windows WLAN scan before reading BSS observations."""
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    with _session() as (api, handle, callback_type):
        guid, name = _pick(_interfaces(api, handle), interface)
        completed = Event()
        result: list[int] = []
        target_guid = bytes(guid)

        @callback_type
        def on_notification(data, _context):
            if not data:
                return
            event = data.contents
            if (event.source == 8 and event.code in (7, 8)
                    and bytes(event.guid) == target_guid):
                result.append(event.code)
                completed.set()

        previous_source = ctypes.c_uint32()
        _check(api.WlanRegisterNotification(
            handle, 8, False, on_notification, None, None,
            ctypes.byref(previous_source),
        ), "WlanRegisterNotification")
        try:
            _check(api.WlanScan(handle, ctypes.byref(guid), None, None, None),
                   "WlanScan")
            if not completed.wait(timeout):
                raise RuntimeError(f"Wi-Fi scan did not complete within {timeout:g}s")
            if result[-1] == 8:
                raise RuntimeError("Wi-Fi scan failed (reported by Windows WLAN service)")
        finally:
            api.WlanRegisterNotification(
                handle, 0, False, on_notification, None, None, None
            )
        return Snapshot.create(_read_bss(api, handle, guid), source=f"windows-wlan:{name}")
