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

## Cooperating sensors: detect wireless identity conflicts

Two laptops can compare observations without a server or specialized monitor-mode hardware. Each collects an access-point scan, exports an offline evidence file, and transfers it by any file-sharing method you already trust.

On a Linux observer:

```bash
aetherlens --db hallway.sqlite scan --interface wlan0
aetherlens --db hallway.sqlite export hallway.json --sensor laptop-a --site hallway
```

On a Windows observer (PowerShell):

```powershell
aetherlens --db lab.sqlite scan
aetherlens --db lab.sqlite export lab.json --sensor laptop-b --site lab
```

Copy both JSON files to one computer, then compare the time-aligned observations:

```bash
aetherlens fuse hallway.json lab.json --skew 30
aetherlens fuse hallway.json lab.json --output html --save investigation.html
aetherlens fuse hallway.json lab.json --output json --save investigation.json
```

Open `investigation.html` locally. AetherLens correlates the same BSSID across independent sensors and reports conflicting security settings, incompatible radio signatures, or SSIDs observed within the selected time tolerance. Normal infrastructure can have the same SSID on many *different* BSSIDs; that is not, by itself, a conflict.

Each export has a SHA-256 integrity checksum, **not a cryptographic signature or proof that a sensor is trustworthy**. Dates need synchronized device clocks. Fingerprints from Windows raw beacon information elements (`ie1`) and Linux `iw` textual capabilities (`iw1`) cannot be compared directly. RSSI is not cross-device calibrated, and neither physical positioning nor definitive evil-twin attribution is implied.

The feature is designed for low-overhead, authorized wireless surveys; raw scan summaries alone cannot observe client attacks, deauthentication traffic, or all nearby networks.

## Pick the most useful observation sites

After collecting several pilot captures from different locations, choose the locations that expose the most **observed** unique transmitters within a site budget:

```bash
aetherlens plan hallway.json lab.json library.json --budget 2
aetherlens plan hallway.json lab.json library.json --budget 2 --witnesses 2 --output json
```

The planner solves a budgeted maximum-coverage problem with a greedy algorithm, then compares against exhaustive optimal selection whenever the candidate search space has at most 50,000 combinations. The `--witnesses` option awards additional coverage credit when a transmitter is observed from more than one site. Signal-strength filtering is available with `--min-rssi`.

These results **cannot predict coverage in unvisited areas**. Repeated measurements at the same site are treated as one possible station. A coverage score is not an RF propagation model or a positioning estimate.

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

Every imported snapshot supplies `collected_at` (timezone-aware ISO 8601), `source`, and an `access_points` array. Each observation contains `bssid`, `ssid`, `frequency_mhz`, `signal_dbm`, and `security` (plus optional `fingerprint`). A recorded sample is in [examples/sample_scans.json](examples/sample_scans.json).

## Team development

The independent modules are in `src/aetherlens/`: `collector.py` parses device observations, `model.py` validates them, `storage.py` records their history, `analysis.py` explains changes, and `benchmark.py` measures performance. Changes to the observation schema should preserve existing import and CLI tests.

## Research direction

A fair detection study needs *labeled* real-world captures, device/site-separated evaluation, precision, recall, F1, false-positive rate, and inference latency. Synthetic storage measurements cannot substitute for that study.

Relevant published work: [Banakh et al., *Data Mining Approach for Evil Twin Attack Identification in Wi-Fi Networks* (2024)](https://doi.org/10.3390/data9100119). The [IEEE 802.11 Beacon Frame Dataset for Rogue Access Point Detection in Urban Environments (2026)](https://doi.org/10.17632/mc83zc5768.4) is a candidate for independently evaluated beacon-level extensions; its features are richer than `iw` scan summaries, so comparison would first require compatible capture support.

This release is a functioning access-point discovery and rule-based change-detection baseline, **not yet** a validated ML intrusion detector.
