"""Reproducible compute benchmark for offline multi-sensor correlation."""

from math import ceil
from statistics import median
from time import perf_counter

from .fusion import Capture, fuse
from .model import AccessPoint, Snapshot


def _percentile(samples: list[float], ratio: float) -> float:
    samples = sorted(samples)
    return samples[max(0, ceil(ratio * len(samples)) - 1)]


def benchmark_fusion(access_points: int = 1000, sensors: int = 3,
                     repeats: int = 7) -> dict:
    if not 1 <= access_points <= 20_000:
        raise ValueError("access_points must be 1..20000")
    if not 2 <= sensors <= 8:
        raise ValueError("sensors must be 2..8")
    if not 1 <= repeats <= 50:
        raise ValueError("repeats must be 1..50")

    captures: list[Capture] = []
    for sensor in range(sensors):
        observations = []
        for i in range(access_points):
            # Two thirds of BSSIDs appear at a sensor. The first is injected
            # into every scan so ground-truth contradiction stays testable.
            if i > 0 and (i + sensor) % 3 == 0:
                continue
            bssid = (f"02:{(i >> 24) & 255:02x}:{(i >> 16) & 255:02x}:"
                     f"{(i >> 8) & 255:02x}:{i & 255:02x}:01")
            security = "OPEN" if i == 0 and sensor == sensors - 1 else "WPA2"
            observations.append(AccessPoint(
                bssid, f"AP-{i % 128}", 2412, -45 - (i % 45),
                security,
            ))
        captures.append(Capture(
            f"synthetic-sensor-{sensor}", f"sample-site-{sensor}",
            Snapshot.create(observations, "synthetic:fusion-benchmark",
                            "2026-10-23T00:00:00Z"),
        ))

    timings: list[float] = []
    result = None
    for _ in range(repeats):
        start = perf_counter()
        result = fuse(captures)
        timings.append((perf_counter() - start) * 1000)
    assert result is not None
    total_observations = sum(len(cap.snapshot.access_points) for cap in captures)
    conflicts = [
        finding for finding in result["findings"]
        if finding["kind"] == "simultaneous_security_conflict"
    ]
    # Each of the other sensors must disagree with the injected OPEN reading.
    assert len(conflicts) == sensors - 1
    return {
        "workload": "synthetic_multisensor_correlation",
        "unique_bssids": access_points,
        "sensors": sensors,
        "total_observations": total_observations,
        "comparable_pairs": result["compared_pairs"],
        "repeats": repeats,
        "runtime_p50_ms": round(median(timings), 3),
        "runtime_p95_ms": round(_percentile(timings, 0.95), 3),
        "correlations_per_second": round(
            result["compared_pairs"] / (median(timings) / 1000)
        ) if median(timings) else 0,
        "injected_security_conflicts_found": len(conflicts),
        "note": "Measures offline correlation on synthetic Wi-Fi observations; "
                "not RF collection time, field detection accuracy, or an ML benchmark.",
    }
