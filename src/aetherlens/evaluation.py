"""Measure alert quality against independently labeled scan pairs."""

from dataclasses import dataclass
from .analysis import compare
from .model import Snapshot


@dataclass(frozen=True, slots=True)
class LabeledPair:
    previous: Snapshot
    current: Snapshot
    suspicious_bssids: frozenset[str]
    scenario: str


def evaluate(pairs: list[LabeledPair]) -> dict:
    if not pairs:
        raise ValueError("evaluation requires at least one labeled scan pair")
    tp = fp = tn = fn = 0
    results = []
    for pair in pairs:
        current_bssids = {ap.bssid for ap in pair.current.access_points}
        if not pair.suspicious_bssids <= current_bssids:
            raise ValueError(f"labels include BSSIDs absent from scenario {pair.scenario}")
        predicted = {
            f.bssid for f in compare(pair.previous, pair.current)
            if f.severity == "high" and f.bssid in current_bssids
        }
        actual = pair.suspicious_bssids
        counts = {
            "tp": len(actual & predicted),
            "fp": len(predicted - actual),
            "fn": len(actual - predicted),
            "tn": len(current_bssids - (actual | predicted)),
        }
        tp += counts["tp"]
        fp += counts["fp"]
        fn += counts["fn"]
        tn += counts["tn"]
        results.append({"scenario": pair.scenario, **counts})
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "cases": len(pairs), "true_positives": tp, "false_positives": fp,
        "true_negatives": tn, "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
        "scenarios": results,
    }
