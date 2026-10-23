# AetherLens

Wi-Fi access-point discovery, historical inventory, and explainable change detection for networks you own or are authorized to assess.

AetherLens collects access-point observations using the Linux `iw` utility, saves each scan atomically to SQLite, and highlights observable changes such as security downgrades and newly seen open transmitters advertising an existing secured SSID. Such findings are **indicators**, not proof of an attack.

## Quick start

Requires Python 3.11+. Live scanning uses Linux `iw` or the native Windows WLAN API. Run from the repository root:

```bash
python -m pip install -e .
aetherlens --db demo.sqlite import examples/sample_scans.json
aetherlens --db demo.sqlite report --output json
```

To collect from your own wireless adapter (replace `wlan0`; scanning may require elevated privileges):

```bash
iw dev
aetherlens --db live.sqlite scan --interface wlan0
aetherlens --db live.sqlite report
```

Some adapters and drivers cannot scan while connected. AetherLens does not perform packet injection, deauthentication, or network association.

### Windows 10/11 (PowerShell)

```powershell
git clone https://github.com/nicetrykiddo/AetherLens.git
cd AetherLens
py -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
python -m pip install -e .
aetherlens interfaces
aetherlens --db wifi.sqlite scan
aetherlens --db wifi.sqlite report
```

Windows selects the first wireless adapter automatically. If multiple adapters are present, run `aetherlens interfaces` and provide a unique part of the adapter description using `aetherlens scan --interface "Intel"`. Both platforms share the same SQLite database format, JSON reports, benchmark command, and labeled evaluation.

Live Windows scanning uses the **WLAN API**, not `netsh`, and requests a fresh scan before collecting BSSID, frequency, RSSI, SSID, and security information. Windows Location and desktop-app location access may need to be enabled under Settings > Privacy & security > Location. The **WLAN AutoConfig** service and a compatible Wi-Fi adapter are required. Windows drivers can limit the visibility and freshness of scan results; a completed scan does not imply that every nearby network was detected. Native radio scanning must be verified on physical hardware; automated Windows tests cover API layouts, parser logic and the platform-independent commands without relying on a CI runner's Wi-Fi hardware.

## Reproducible performance benchmark

```bash
aetherlens benchmark --aps 1000 --repeats 5
aetherlens benchmark --aps 1000 --repeats 5 --output json
python -m unittest discover -s tests -v
```

The synthetic benchmark measures SQLite storage operations on the machine where it runs: per-observation commits versus one transaction per scan, plus latest-scan query p50/p95. It **does not** measure over-the-air discovery time or attack-detection accuracy. Results vary with disk, filesystem, cache, hardware, and SQLite settings.

## Detection evaluation

Run the independently labeled scan-pair evaluator:

```bash
aetherlens evaluate examples/labeled_cases.json
aetherlens evaluate examples/labeled_cases.json --output json
```

The included three **simulated** scenarios deliberately contain a true positive, false positive, and false negative. They exercise precision, recall, F1, and false-positive reporting; their scores are not real-world validation. For research-grade results, replace these examples with independently established ground truth from separate capture sites and sessions. In particular, avoid training on the same handcrafted heuristics used to derive your labels.

## Data model

Every imported snapshot supplies `collected_at` (timezone-aware ISO 8601), `source`, and an `access_points` array. Each observation contains `bssid`, `ssid`, `frequency_mhz`, `signal_dbm`, and `security`. A real example is in [examples/sample_scans.json](examples/sample_scans.json).

## Team development

The independent modules are in `src/aetherlens/`: `collector.py` parses device observations, `model.py` validates them, `storage.py` records their history, `analysis.py` explains changes, and `benchmark.py` measures performance. Changes to the observation schema should preserve existing import and CLI tests.

## Research direction

A fair detection study needs *labeled* real-world captures, device/site-separated evaluation, precision, recall, F1, false-positive rate, and inference latency. Synthetic storage measurements cannot substitute for that study.

Relevant published work: [Banakh et al., *Data Mining Approach for Evil Twin Attack Identification in Wi-Fi Networks* (2024)](https://doi.org/10.3390/data9100119). The [IEEE 802.11 Beacon Frame Dataset for Rogue Access Point Detection in Urban Environments (2026)](https://doi.org/10.17632/mc83zc5768.4) is a candidate for independently evaluated beacon-level extensions; its features are richer than `iw` scan summaries, so comparison would first require compatible capture support.

This release is a functioning access-point discovery and rule-based change-detection baseline, **not yet** a validated ML intrusion detector.
