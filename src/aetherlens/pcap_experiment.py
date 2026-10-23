"""End-to-end challenge suite: raw 802.11 frames -> PCAP decoder -> alerts.

Labels are generated from scenario definitions, NEVER passed to the detector.
Runs include benign hard negatives and an intentionally undetectable clone.
No generated result is presented as field-measured intrusion accuracy.
"""

from pathlib import Path
from statistics import median
from tempfile import TemporaryDirectory
from time import perf_counter

from .pcap import read_pcap
from .pcap_lab import scenarios, write_pcap


def _metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4)
        if precision + recall else 0.0,
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
    }


def run_lab(seeds: int = 10, loss_rates: tuple[float, ...] = (0.0, 0.2, 0.5),
            output_directory: str | Path | None = None) -> dict:
    if not 1 <= seeds <= 1000:
        raise ValueError("seeds must be between 1 and 1000")
    if not 1 <= len(loss_rates) <= 10 or any(not 0 <= loss <= 1 for loss in loss_rates):
        raise ValueError("provide 1..10 packet loss rates between 0 and 1")
    if output_directory is not None:
        Path(output_directory).mkdir(parents=True, exist_ok=True)

    def run_at(root: Path) -> dict:
        results = []
        for loss in loss_rates:
            tp = fp = fn = tn = packets = 0
            runtimes = []
            scenario_results = []
            for trial in range(seeds):
                for scenario in scenarios():
                    name = f"{scenario.name}-seed{trial}-loss{round(loss * 1000):04d}.pcap"
                    path = root / name
                    frame_count = write_pcap(
                        path, scenario.frames, seed=trial * 7919 + 31,
                        packet_loss=loss, frame_repeats=3, schedule=scenario.schedule,
                    )
                    packets += frame_count
                    start = perf_counter()
                    predicted = bool(read_pcap(path).contradictions())
                    runtimes.append((perf_counter() - start) * 1000)
                    if scenario.malicious:
                        if predicted:
                            tp += 1
                        else:
                            fn += 1
                    elif predicted:
                        fp += 1
                    else:
                        tn += 1
                    if trial == 0:
                        scenario_results.append({
                            "name": scenario.name,
                            "truth_malicious": scenario.malicious,
                            "detected": predicted,
                            "pcap_file": str(path) if output_directory is not None else None,
                        })
                    if output_directory is None:
                        path.unlink()  # keep only requested evidence files
            results.append({
                "loss_rate": loss,
                "cases": seeds * len(scenarios()),
                "packets_decoded": packets,
                "decode_and_detection_median_ms": round(median(runtimes), 4),
                **_metrics(tp, fp, fn, tn),
                "first_seed_examples": scenario_results,
            })
        return {
            "workload": "synthetic_80211_radiotap_packet_replay",
            "scenario_count": len(scenarios()),
            "seeds": seeds,
            "loss_rates": list(loss_rates),
            "results": results,
            "limitations": [
                "Simulated beacon frames and independent synthetic labels, not real RF measurements",
                "Packet loss is random per frame; no calibrated propagation or interference model",
                "Identical same-security clones can be observationally indistinguishable",
                "Legitimate security migrations produce false-positive identity alerts",
            ],
        }

    if output_directory is not None:
        return run_at(Path(output_directory))
    with TemporaryDirectory(prefix="aetherlens-pcap-lab-") as temporary:
        return run_at(Path(temporary))

def run_cooperative_lab(seeds: int = 20, sensors: int = 3,
                        loss_rates: tuple[float, ...] = (0.2, 0.5)) -> dict:
    """Compare one observer with an any-sensor alert baseline.

    Each detector evaluates its own frame timeline independently. A receiver
    reports an alert if any observer has sufficient A-B-A evidence. Combining
    raw timestamps without verified clock synchronization creates false
    temporal contradictions and is deliberately forbidden here.

    Packet loss remains independent and uncalibrated in this benchmark.
    """

    if not 1 <= seeds <= 1000:
        raise ValueError("seeds must be between 1 and 1000")
    if not 2 <= sensors <= 8:
        raise ValueError("sensors must be in 2..8")
    if not 1 <= len(loss_rates) <= 10 or any(not 0 <= x <= 1 for x in loss_rates):
        raise ValueError("provide 1..10 loss rates in 0..1")
    rows = []
    with TemporaryDirectory(prefix="aetherlens-coop-lab-") as temporary:
        for loss in loss_rates:
            tp = fp = fn = tn = 0
            ctp = cfp = cfn = ctn = 0
            for seed in range(seeds):
                for scenario in scenarios():
                    streams = []
                    for sensor in range(sensors):
                        path = Path(temporary) / f"capture-{sensor}.pcap"
                        write_pcap(
                            path, scenario.frames,
                            seed=seed * 7919 + sensor * 65537 + 31,
                            packet_loss=loss, frame_repeats=3,
                            schedule=scenario.schedule,
                        )
                        streams.append(read_pcap(path))
                    sensor_alerts = [bool(stream.contradictions()) for stream in streams]
                    single = sensor_alerts[0]
                    fused = any(sensor_alerts)

                    if scenario.malicious:
                        if single:
                            tp += 1
                        else:
                            fn += 1
                        if fused:
                            ctp += 1
                        else:
                            cfn += 1
                    else:
                        if single:
                            fp += 1
                        else:
                            tn += 1
                        if fused:
                            cfp += 1
                        else:
                            ctn += 1
            first = _metrics(tp, fp, fn, tn)
            combined = _metrics(ctp, cfp, cfn, ctn)
            rows.append({
                "loss_rate": loss,
                "cases": seeds * len(scenarios()),
                "single_sensor": first,
                "cooperative": combined,
                "absolute_recall_gain": round(combined["recall"] - first["recall"], 4),
                "missed_attacks_recovered": ctp - tp,
            })
    return {
        "workload": "synthetic_independent_packet_loss_capture_diversity",
        "seeds": seeds,
        "sensor_count": sensors,
        "results": rows,
        "limitations": [
            "Uncalibrated independent random frame drops; real sensors may have correlated losses",
            "Idealized identical transmitted frames; sensors compare only their own clocks",
            "An any-sensor alert can increase false positives as more receivers participate",
            "A synthetic corpus cannot validate field threat detection or prove physical localization",
        ],
    }
