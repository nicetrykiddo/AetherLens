#!/usr/bin/env bash
# Local mac80211_hwsim experiment. Operates only on newly created virtual radios.
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run with sudo; mac80211_hwsim and virtual interfaces require root." >&2
  exit 2
fi
for command in iw ip hostapd modprobe python3 grep sort comm; do
  command -v "$command" >/dev/null || { echo "Missing dependency: $command" >&2; exit 2; }
done
if lsmod | grep -q '^mac80211_hwsim '; then
  echo "mac80211_hwsim is already loaded; refusing to modify existing virtual radios." >&2
  exit 2
fi
# Use the calling shell's installed Python package or editable repo installation.
python3 -c 'import aetherlens' || {
  echo "Install the package first: python -m pip install -e ." >&2
  exit 2
}

output="${1:-./hwsim-evidence}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
before="$(mktemp)"
after="$(mktemp)"
iw phy | awk '/^Wiphy / {print $2}' | sort > "$before"

ap_secure="alapsecure"
ap_open="alapopen"
station="alstation"
secure_pid=""
open_pid=""
created=0
cleanup() {
  [[ -n "$open_pid" ]] && kill "$open_pid" 2>/dev/null || true
  [[ -n "$secure_pid" ]] && kill "$secure_pid" 2>/dev/null || true
  if (( created )); then
    iw dev "$ap_secure" del 2>/dev/null || true
    iw dev "$ap_open" del 2>/dev/null || true
    iw dev "$station" del 2>/dev/null || true
    modprobe -r mac80211_hwsim 2>/dev/null || true
  fi
  rm -f "$before" "$after"
}
trap cleanup EXIT

modprobe mac80211_hwsim radios=3
created=1
iw phy | awk '/^Wiphy / {print $2}' | sort > "$after"
mapfile -t radios < <(comm -13 "$before" "$after")
if (( ${#radios[@]} != 3 )); then
  echo "Expected three newly created hwsim radios, got ${#radios[@]}" >&2
  exit 1
fi
iw phy "${radios[0]}" interface add "$ap_secure" type __ap
iw phy "${radios[1]}" interface add "$station" type managed
iw phy "${radios[2]}" interface add "$ap_open" type __ap

cat > "$output/secure.conf" <<CONF
interface=$ap_secure
driver=nl80211
ssid=AetherLens-Lab
hw_mode=g
channel=6
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=AetherLensVirtualOnly2026
rsn_pairwise=CCMP
CONF
cat > "$output/open.conf" <<CONF
interface=$ap_open
driver=nl80211
ssid=AetherLens-Lab
hw_mode=g
channel=6
auth_algs=1
CONF

ip link set "$ap_secure" up
ip link set "$station" up
ip link set "$ap_open" up
hostapd -B -P "$output/secure.pid" -f "$output/secure.log" "$output/secure.conf"
secure_pid="$(cat "$output/secure.pid")"

scan_into() {
  local attempt=0
  while (( attempt < 10 )); do
    if python3 -m aetherlens --db "$output/survey.sqlite" scan --interface "$station" > "$output/scan-$1.log" 2>&1; then
      if grep -q 'AetherLens-Lab' "$output/scan-$1.log"; then
        return 0
      fi
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  cat "$output/scan-$1.log" >&2
  return 1
}

scan_into baseline

hostapd -B -P "$output/open.pid" -f "$output/open.log" "$output/open.conf"
open_pid="$(cat "$output/open.pid")"
scan_into replica

python3 -m aetherlens --db "$output/survey.sqlite" report --output json > "$output/result.json"
python3 - "$output/result.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    report = json.load(source)
alerts = [finding for finding in report["findings"]
          if finding["kind"] == "possible_open_replica"]
if not alerts:
    raise SystemExit("FAILED: injected open AP was not flagged. Inspect captured scans.")
print(f"PASS: detected {len(alerts)} possible replica(s) in Linux virtual 802.11 radio test.")
print("This is a virtual-radio test, not over-the-air RF validation.")
PY
echo "Evidence saved in $output"
