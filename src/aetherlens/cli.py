"""Entry point for collection, replay, inspection, and benchmarks."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

from .analysis import compare
from .collector import scan
from .model import AccessPoint, Snapshot
from .storage import ScanStore


def _table(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> str:
    widths = [max(len(str(row[i])) for row in [headers, *rows]) for i in range(len(headers))]
    return "\n".join([
        "  ".join(f"{cell:<{widths[i]}}" for i, cell in enumerate(headers)),
        "  ".join("-" * width for width in widths),
        *("  ".join(f"{cell:<{widths[i]}}" for i, cell in enumerate(row)) for row in rows),
    ])


def _load(path: Path) -> list[Snapshot]:
    content = json.loads(path.read_text(encoding="utf-8"))
    items = content if isinstance(content, list) else [content]
    snapshots = []
    for entry in items:
        points = [AccessPoint(**ap) for ap in entry["access_points"]]
        snapshots.append(Snapshot.create(points, entry["source"], entry["collected_at"]))
    return snapshots


def _display(store: ScanStore, output: str) -> int:
    latest = store.latest()
    if not latest:
        print("No scans recorded. Try 'aetherlens scan' or 'aetherlens import'.")
        return 0
    current = latest[0]
    findings = compare(latest[1], current) if len(latest) > 1 else []
    if output == "json":
        print(json.dumps({
            "scan": {"collected_at": current.collected_at, "source": current.source,
                     "access_points": [asdict(ap) for ap in current.access_points]},
            "findings": [asdict(f) for f in findings],
        }, indent=2))
        return 0
    print(f"AetherLens | {current.collected_at} | {current.source} | {len(current.access_points)} APs")
    print(_table(
        ("BSSID", "SSID", "FREQ", "RSSI", "SECURITY"),
        [(p.bssid, p.ssid or "<hidden>", str(p.frequency_mhz), f"{p.signal_dbm:g}", p.security)
         for p in current.access_points],
    ))
    if len(latest) < 2:
        print("\nChange detection needs a second scan.")
    elif findings:
        print(f"\nChanges since previous scan ({len(findings)}):")
        for f in findings:
            print(f"  [{f.severity.upper():6}] {f.kind}: {f.bssid} | {f.detail}")
    else:
        print("\nNo changes since previous scan.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aetherlens", description="Wireless AP discovery and change detection")
    parser.add_argument("--db", default="aetherlens.sqlite", help="SQLite database path")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_cmd = commands.add_parser("scan", help="Collect access points using Linux iw")
    scan_cmd.add_argument("--interface", "-i", required=True, help="Wi-Fi interface (e.g. wlan0)")
    import_cmd = commands.add_parser("import", help="Import one or more recorded JSON snapshots")
    import_cmd.add_argument("path", type=Path)
    report_cmd = commands.add_parser("report", help="Show the most recent scan and changes")
    report_cmd.add_argument("--output", choices=("table", "json"), default="table")
    bench_cmd = commands.add_parser("benchmark", help="Measure ingestion and query costs on synthetic observations")
    bench_cmd.add_argument("--aps", type=int, default=1000, help="Distinct APs per run")
    bench_cmd.add_argument("--repeats", type=int, default=3)
    bench_cmd.add_argument("--output", choices=("table", "json"), default="table")
    eval_cmd = commands.add_parser("evaluate", help="Score high-severity alerts on labeled scan pairs")
    eval_cmd.add_argument("path", type=Path)
    eval_cmd.add_argument("--output", choices=("table", "json"), default="table")
    args = parser.parse_args(argv)
    try:
        if args.command == "evaluate":
            from .evaluation import LabeledPair, evaluate
            raw = json.loads(args.path.read_text(encoding="utf-8"))
            pairs = []
            for item in raw:
                def restore(entry):
                    return Snapshot.create(
                        [AccessPoint(**ap) for ap in entry["access_points"]],
                        entry["source"], entry["collected_at"],
                    )
                pairs.append(LabeledPair(
                    restore(item["previous"]), restore(item["current"]),
                    frozenset(mac.lower() for mac in item["suspicious_bssids"]),
                    item["scenario"],
                ))
            metrics = evaluate(pairs)
            if args.output == "json":
                print(json.dumps(metrics, indent=2))
            else:
                print(f"Detection evaluation | {metrics['cases']} labeled scenarios")
                print(f"  TP={metrics['true_positives']} FP={metrics['false_positives']} "
                      f"FN={metrics['false_negatives']} TN={metrics['true_negatives']}")
                print(f"  Precision={metrics['precision']:.3f} Recall={metrics['recall']:.3f} "
                      f"F1={metrics['f1']:.3f} FPR={metrics['false_positive_rate']:.3f}")
                print("  Scores describe only the provided labels; sample cases are simulated, not field validation.")
            return 0
        if args.command == "benchmark":
            from .benchmark import run
            metrics = run(args.aps, args.repeats)
            if args.output == "json":
                print(json.dumps(metrics, indent=2))
            else:
                print(f"AetherLens synthetic benchmark | {metrics['access_points']} APs | {metrics['repeats']} repeats")
                print(f"  One commit per observation: {metrics['individual_commits_ms']:.2f} ms")
                print(f"  One transaction per scan:   {metrics['batch_ms']:.2f} ms")
                print(f"  Batch speedup:              {metrics['batch_speedup']:.2f}x")
                print(f"  Batch ingest:               {metrics['batch_observations_per_second']:,.0f} observations/s")
                print(f"  Latest-scan query p50/p95: {metrics['query_p50_ms']:.2f}/{metrics['query_p95_ms']:.2f} ms")
                print("  Synthetic local-storage workload; not wireless scan time or detection accuracy.")
            return 0
        with ScanStore(args.db) as store:
            if args.command == "scan":
                snap = scan(args.interface)
                store.record(snap)
                return _display(store, "table")
            if args.command == "import":
                samples = _load(args.path)
                for sample in samples:
                    store.record(sample)
                print(f"Imported {len(samples)} snapshot(s) into {args.db}")
                return _display(store, "table")
            if args.command == "report":
                return _display(store, args.output)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"aetherlens: {error}", file=sys.stderr)
        return 1
    return 0
