"""Command line interface for the Truth Grind."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional, Sequence

from .bench import benchmark_orderings, format_report
from .engine import TruthGrind
from .legacy import KNOWN_LIMITATIONS, compare_engines
from .models import GrindReport, Verdict

#: Shell exit codes, so the grind is usable in a pipeline.
EXIT_PASS = 0
EXIT_BLOCKED = 1
EXIT_DEGRADED = 2
EXIT_USAGE = 64

_EXIT_FOR = {
    Verdict.PASS: EXIT_PASS,
    Verdict.BLOCKED: EXIT_BLOCKED,
    Verdict.DEGRADED: EXIT_DEGRADED,
}


def _load_subject(path: Optional[str]) -> Dict[str, Any]:
    raw = sys.stdin.read() if path in (None, "-") else open(path).read()
    subject = json.loads(raw)
    if not isinstance(subject, dict):
        raise ValueError("subject must be a JSON object")
    return subject


def _render_human(report: GrindReport) -> str:
    lines = [
        f"verdict          {report.verdict.value}",
        f"parity           {report.parity:.4f}",
        f"utility density  {report.utility_density:.2f} distinct findings / 1000 evals",
        f"evaluations      {report.evaluations}",
        f"elapsed          {report.elapsed_ms:.2f} ms",
        f"subject          {report.subject_digest[:16]}",
        "",
    ]

    hist = report.severity_histogram()
    lines.append(
        "findings         "
        + ", ".join(f"{k}={v}" for k, v in hist.items())
    )

    distinct: Dict[tuple, int] = {}
    for f in report.findings:
        distinct[(f.layer, f.code, f.severity.label, f.detail)] = (
            distinct.get((f.layer, f.code, f.severity.label, f.detail), 0) + 1
        )
    if distinct:
        lines += ["", "distinct findings:"]
        for (layer, code, sev, detail), count in sorted(
            distinct.items(), key=lambda kv: -kv[1]
        ):
            lines.append(f"  [{sev:<7}] {layer}/{code} (x{count})")
            lines.append(f"            {detail}")

    if report.notes:
        lines += ["", "notes:"]
        lines += [f"  - {n}" for n in report.notes]
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="http-grind",
        description="Hyper Truth Testing Protocol -- 7x70 adversarial validation.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_grind = sub.add_parser("grind", help="run a 7x70 grind over a JSON subject")
    p_grind.add_argument("subject", nargs="?", default="-", help="JSON file, or - for stdin")
    p_grind.add_argument("--simulations", type=int, default=70)
    p_grind.add_argument("--seed", type=int, default=0)
    p_grind.add_argument("--parity-floor", type=float, default=1.0)
    p_grind.add_argument("--json", action="store_true", help="emit the full report as JSON")
    p_grind.add_argument(
        "--no-halt",
        action="store_true",
        help="run every layer even after a mandate finding",
    )

    p_bench = sub.add_parser("bench", help="benchmark the ZTS gate orderings")
    p_bench.add_argument("--size", type=int, default=400)
    p_bench.add_argument("--reject-rate", type=float, default=0.5)
    p_bench.add_argument("--seed", type=int, default=0)
    p_bench.add_argument("--repeats", type=int, default=3)

    p_cmp = sub.add_parser("compare", help="contrast the v1.0 and v2.0 engines")
    p_cmp.add_argument("subject", nargs="?", default="-")

    sub.add_parser("limitations", help="list the documented v1.0 defects")

    args = parser.parse_args(argv)

    if args.command == "bench":
        print(
            format_report(
                benchmark_orderings(
                    size=args.size,
                    reject_rate=args.reject_rate,
                    seed=args.seed,
                    repeats=args.repeats,
                )
            )
        )
        return EXIT_PASS

    if args.command == "limitations":
        print("Documented defects in the archival HTTP v1.0 engine:\n")
        for i, item in enumerate(KNOWN_LIMITATIONS, 1):
            print(f"{i:2}. {item}")
        return EXIT_PASS

    try:
        subject = _load_subject(args.subject)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.command == "compare":
        print(json.dumps(compare_engines(subject), indent=2))
        return EXIT_PASS

    report = TruthGrind(
        simulations=args.simulations,
        seed=args.seed,
        parity_floor=args.parity_floor,
        halt_on_mandate=not args.no_halt,
    ).grind(subject)

    print(report.to_json() if args.json else _render_human(report))
    return _EXIT_FOR[report.verdict]


if __name__ == "__main__":
    raise SystemExit(main())
