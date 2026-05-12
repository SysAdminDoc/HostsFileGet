#!/usr/bin/env python3
"""Deterministic large-file benchmarks for HostsFileGet parser/cleaner paths."""

from __future__ import annotations

import argparse
import json
import pathlib
import statistics
import sys
import time
from collections.abc import Callable
from typing import Any

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from hosts_editor import (  # noqa: E402
    _get_canonical_cleaned_output_and_stats,
    categorize_entries_by_domain_hint,
    extract_blocking_domains_from_lines,
    normalize_line_to_hosts_entries,
)


def generate_large_hosts_fixture(entry_count: int) -> dict[str, Any]:
    """Build a deterministic mixed hosts corpus for repeatable benchmarks."""
    entry_count = max(1, int(entry_count))
    lines: list[str] = []
    whitelist: set[str] = set()
    pinned_domains: set[str] = set()

    for index in range(entry_count):
        base_domain = f"ads-{index:06d}.example"
        if index % 97 == 0:
            lines.append(f"# section marker {index}")
        elif index % 89 == 0:
            lines.append("")
        elif index % 53 == 0:
            lines.append(f"0.0.0.0 ads-{index - 1:06d}.example")
        elif index % 41 == 0:
            lines.append(f"192.168.1.10 lan-{index:06d}")
        elif index % 37 == 0:
            lines.append(f"address=/telemetry-{index:06d}.example/0.0.0.0")
        elif index % 31 == 0:
            lines.append(f"||filter-{index:06d}.example^$third-party")
        elif index % 29 == 0:
            lines.append(f"https://tracker-{index:06d}.example/pixel.gif?id={index}")
        else:
            lines.append(f"0.0.0.0 {base_domain}")

        if index % 113 == 0:
            whitelist.add(base_domain)
        if index % 211 == 0:
            pinned_domains.add(f"pinned-{index:06d}.example")

    return {
        "lines": lines,
        "whitelist": whitelist,
        "pinned_domains": pinned_domains,
    }


def _time_operation(repeats: int, operation: Callable[[], Any]) -> tuple[dict[str, float], Any]:
    durations: list[float] = []
    result: Any = None
    for _ in range(max(1, int(repeats))):
        start = time.perf_counter()
        result = operation()
        durations.append(time.perf_counter() - start)
    return {
        "min_seconds": min(durations),
        "mean_seconds": statistics.fmean(durations),
        "max_seconds": max(durations),
    }, result


def run_large_file_benchmark(entry_count: int = 50_000, repeats: int = 3) -> dict[str, Any]:
    fixture = generate_large_hosts_fixture(entry_count)
    lines = fixture["lines"]
    whitelist = fixture["whitelist"]
    pinned_domains = fixture["pinned_domains"]

    normalize_metrics, normalized = _time_operation(
        repeats,
        lambda: [normalize_line_to_hosts_entries(line) for line in lines],
    )
    clean_metrics, clean_result = _time_operation(
        repeats,
        lambda: _get_canonical_cleaned_output_and_stats(lines, whitelist, pinned_domains),
    )
    cleaned_lines, clean_stats = clean_result
    extract_metrics, extracted_domains = _time_operation(
        repeats,
        lambda: extract_blocking_domains_from_lines(cleaned_lines),
    )
    categorize_metrics, category_counts = _time_operation(
        repeats,
        lambda: categorize_entries_by_domain_hint(cleaned_lines),
    )

    return {
        "entry_count": len(lines),
        "repeats": max(1, int(repeats)),
        "fixture": {
            "whitelist_count": len(whitelist),
            "pinned_count": len(pinned_domains),
        },
        "operations": {
            "normalize_all_lines": normalize_metrics,
            "clean": clean_metrics,
            "extract_blocking_domains": extract_metrics,
            "categorize_cleaned_entries": categorize_metrics,
        },
        "clean_stats": clean_stats,
        "normalized_line_count": len(normalized),
        "extracted_domain_count": len(extracted_domains),
        "category_counts": category_counts,
    }


def format_benchmark_report(report: dict[str, Any]) -> str:
    lines = [
        "Large-file benchmark",
        f"Input lines: {report['entry_count']:,}",
        f"Repeats: {report['repeats']}",
        "",
        "Operations:",
    ]
    for name, metrics in report["operations"].items():
        lines.append(
            f"  {name:<28} min={metrics['min_seconds']:.4f}s "
            f"mean={metrics['mean_seconds']:.4f}s max={metrics['max_seconds']:.4f}s"
        )
    clean_stats = report["clean_stats"]
    lines.extend([
        "",
        "Clean stats:",
        f"  final_active={clean_stats['final_active']:,}",
        f"  total_discarded={clean_stats['total_discarded']:,}",
        f"  transformed={clean_stats['transformed']:,}",
        f"  pinned_preserved={clean_stats['pinned_preserved']:,}",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entries", type=int, default=50_000, help="Synthetic input line count.")
    parser.add_argument("--repeats", type=int, default=3, help="Operation repeats used for min/mean/max timing.")
    parser.add_argument("--json-output", help="Optional path for a JSON benchmark report.")
    parser.add_argument("--max-clean-seconds", type=float, help="Optional failure budget for the best clean pass.")
    parser.add_argument("--quiet", action="store_true", help="Suppress human-readable stdout.")
    args = parser.parse_args(argv)

    report = run_large_file_benchmark(args.entries, args.repeats)
    if args.json_output:
        output_path = pathlib.Path(args.json_output)
        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if not args.quiet:
        print(format_benchmark_report(report))

    if args.max_clean_seconds is not None:
        clean_min = report["operations"]["clean"]["min_seconds"]
        if clean_min > args.max_clean_seconds:
            print(
                f"Clean benchmark exceeded budget: {clean_min:.4f}s > {args.max_clean_seconds:.4f}s",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
