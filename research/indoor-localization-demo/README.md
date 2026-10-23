# AetherLens Research Extension: Indoor Localization Demo

This folder contains an **experimental, standalone Streamlit app** exploring whether Wi-Fi received signal strength (RSSI) can help classify an indoor room. It is intentionally separate from the AetherLens scanner and core CLI.

## What it does

- Loads the UCI Wireless Indoor Localization dataset (ID 422) or explicitly labelled synthetic demo data.
- Trains a Decision Tree classifier to estimate one of four room labels from seven RSSI features.
- Reports accuracy, macro precision/recall/F1, a confusion matrix, and feature importance.
- Ranks candidate rooms by model output and offers CSV exports.
- Demonstrates Linear Regression for estimating one RSSI feature from the others.
- Includes unit tests for the reusable data and model helpers.

Dataset: https://archive.ics.uci.edu/dataset/422/wireless+indoor+localization

## Important boundaries

This is **not integrated with live AetherLens scans**. The UCI dataset uses a fixed set of seven RSSI features and known room labels; AetherLens currently collects access-point observations identified by BSSID/SSID, frequency, signal strength, and security. A future integration would need a deliberate feature-mapping strategy and location-labelled scans collected in the intended environment.

The dataset has no target-present/absent, distance, or search-time labels. The demo therefore does not detect physical targets or estimate distance/search time. A room ranking is decision support, not evidence of a target's presence. The displayed Decision Tree scores are not guaranteed to be calibrated probabilities.

Synthetic data exists only to keep the interface demonstrable when the remote dataset cannot be downloaded. **Never present synthetic-data metrics as real-world evaluation results.** The app is a research prototype, not a validated localization or security system.

## Run on Linux

From this directory:

~~~bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run app.py
~~~

On Windows, activate the environment using the PowerShell activation script at .venv\Scripts\Activate.ps1, then run the same pip and Streamlit commands.

Internet access is required to fetch the UCI dataset. If that fails, the app clearly labels its synthetic-data fallback.

## Tests

~~~bash
python -m unittest discover -s tests -v
~~~

The tests target the reusable helpers in modeling.py; they do not validate live Wi-Fi collection or production localization accuracy.

## Integration direction

Keep this dependency set optional and separate from AetherLens core. Before attempting integration, collect representative, consented, location-labelled observations, define a stable feature schema, evaluate on held-out devices/sites where possible, and report per-room precision/recall, macro F1, confusion matrices, and latency. Compare against simple baselines before claiming an ML improvement.
