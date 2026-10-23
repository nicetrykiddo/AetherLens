# AetherLens

Wireless environment discovery and change detection from Wi-Fi scan observations.

AetherLens collects nearby access-point observations, keeps a queryable history, and measures discovery and detection quality against reproducible baselines. It is intended for networks you own or are authorized to assess.

## Scope

- **Software engineering:** collection, validated data models, durable storage, command-line workflows, automated tests.
- **Machine learning:** experimentally evaluated anomaly detection with explicit baselines, once representative labeled data is available.
- **AI:** evidence-based interpretation of observations and changes, without inventing threats or certainty.

Python 3.11+ is required. See the CLI and benchmark commands as they are introduced below.

## Development

The application is developed as independent components so collection, analysis, and user experience work can happen on separate branches.
