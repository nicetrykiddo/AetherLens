"""Budgeted observer placement over previously measured candidate sites.

This is maximum coverage (or capped multi-witness coverage), not a prediction
of signals in unmeasured rooms. Greedy results are compared with exact
enumeration when the candidate set is small enough.
"""

from itertools import combinations
from math import comb

from .fusion import Capture


def _score(chosen: tuple[str, ...], sites: dict[str, set[str]], witnesses: int) -> int:
    counts: dict[str, int] = {}
    for site in chosen:
        for bssid in sites[site]:
            counts[bssid] = counts.get(bssid, 0) + 1
    return sum(min(count, witnesses) for count in counts.values())


def plan_sites(captures: list[Capture], budget: int, witnesses: int = 1,
               min_rssi: float = -85) -> dict:
    if budget < 1:
        raise ValueError("budget must be at least one site")
    if witnesses not in (1, 2, 3):
        raise ValueError("witnesses must be 1, 2, or 3")
    if not -120 <= min_rssi <= 0:
        raise ValueError("minimum RSSI must be between -120 and 0")
    sites: dict[str, set[str]] = {}
    for cap in captures:
        sites.setdefault(cap.site_id, set()).update(
            ap.bssid for ap in cap.snapshot.access_points
            if ap.signal_dbm >= min_rssi
        )
    if not sites:
        raise ValueError("survey planning needs at least one captured site")

    count = min(budget, len(sites))
    chosen: tuple[str, ...] = ()
    remaining = set(sites)
    for _ in range(count):
        options = sorted(remaining)
        winner = max(options, key=lambda site: (
            _score(chosen + (site,), sites, witnesses),
            len(sites[site] - set().union(*(sites[x] for x in chosen))),
            -options.index(site),
        ))
        chosen += (winner,)
        remaining.remove(winner)

    selected_aps = set().union(*(sites[site] for site in chosen))
    total_aps = set().union(*sites.values())
    witness_counts = {
        ap: sum(ap in sites[site] for site in chosen) for ap in selected_aps
    }
    value = _score(chosen, sites, witnesses)
    candidates = len(sites)
    possible = comb(candidates, count)
    optimum: int | None = None
    optimal_sites: tuple[str, ...] | None = None
    # Bound enumeration by combination count rather than an arbitrary site count.
    if possible <= 50_000:
        for site_list in combinations(sorted(sites), count):
            result = _score(site_list, sites, witnesses)
            if optimum is None or result > optimum:
                optimum, optimal_sites = result, site_list

    return {
        "budget": budget,
        "selected_sites": list(chosen),
        "candidate_sites": candidates,
        "unique_bssids_found": len(selected_aps),
        "unique_bssids_available": len(total_aps),
        "coverage_percent": round(100 * len(selected_aps) / len(total_aps), 2) if total_aps else 0,
        "bssids_with_multiple_witnesses": sum(v >= 2 for v in witness_counts.values()),
        "witness_target": witnesses,
        "score": value,
        "all_sites_score": _score(tuple(sites), sites, witnesses),
        "exact_optimum_score": optimum,
        "exact_optimum_sites": list(optimal_sites) if optimal_sites is not None else None,
        "greedy_to_optimum_percent": round(100 * value / optimum, 2) if optimum else None,
        "note": "Optimization covers only observed candidate sites; it cannot predict unvisited rooms or replace an RF site survey.",
    }
