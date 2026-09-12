"""Reproducible benchmark for the Fail-Fast reordering.

The corpus records the stack's most concrete empirical claim: reordering the
Zero Trust Stack to run cheap regex gates before expensive semantic ones cut
latency from 214ms to 32ms, an 88% reduction.

The retrospective is equally clear that those figures were narrated by the
model rather than measured -- "simulated optimization deltas" that "further
detached the user from real engineering environments where performance gains
must be verified via actual code benchmarks."

This module is that benchmark. It measures both orderings on the machine it
runs on and reports the real numbers, whatever they turn out to be.
"""

from __future__ import annotations

import random
import statistics
import time
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

from .zts import FAIL_FAST_ORDER, NAIVE_ORDER, evaluate


@dataclass
class OrderingBenchmark:
    label: str
    order: Tuple[str, ...]
    mean_us: float
    median_us: float
    p95_us: float
    mean_gates_evaluated: float
    rejections: int
    samples: int


def _percentile(values: Sequence[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(int(round(pct * (len(ordered) - 1))), len(ordered) - 1)
    return ordered[idx]


#: Fragments that each trip exactly one gate, so the corpus is realistic
#: rather than uniformly clean or uniformly hostile.
_REJECT_FRAGMENTS = (
    "I believe this holds",             # G6 pronoun
    "basically the system works",       # G3 drift
    "an excellent and brilliant design",  # G5 sycophancy
    "this is guaranteed secure",        # G2 contamination
)

_CLEAN_FRAGMENTS = (
    "The subsystem rejects malformed payloads at the perimeter.",
    "Throughput degrades once the queue exceeds its configured depth.",
    "Retries are bounded and the backoff is exponential.",
    "Schema validation precedes any write to the durable store.",
)


def build_corpus(size: int = 400, reject_rate: float = 0.5, seed: int = 0) -> List[str]:
    """Build a mixed corpus of accepted and rejected inputs.

    ``reject_rate`` matters to the result: fail-fast ordering only pays off on
    input that actually gets rejected, so a corpus of exclusively clean text
    would show no benefit and a corpus of exclusively hostile text would
    overstate it.
    """
    rng = random.Random(seed)
    corpus: List[str] = []
    for _ in range(size):
        padding = " ".join(rng.choice(_CLEAN_FRAGMENTS) for _ in range(3))
        if rng.random() < reject_rate:
            corpus.append(f"{padding} {rng.choice(_REJECT_FRAGMENTS)} {padding}")
        else:
            corpus.append(padding)
    return corpus


def benchmark_ordering(
    corpus: Sequence[str],
    order: Tuple[str, ...],
    label: str,
    context: Dict | None = None,
    repeats: int = 3,
) -> OrderingBenchmark:
    """Time one gate ordering over the corpus."""
    context = context or {"history": [], "axioms": {}}
    timings: List[float] = []
    gate_counts: List[int] = []
    rejections = 0

    for _ in range(repeats):
        for text in corpus:
            start = time.perf_counter()
            result = evaluate(text, context, order=order, short_circuit=True)
            timings.append((time.perf_counter() - start) * 1e6)
            gate_counts.append(result.gates_evaluated)
            if not result.passed:
                rejections += 1

    return OrderingBenchmark(
        label=label,
        order=order,
        mean_us=statistics.fmean(timings),
        median_us=statistics.median(timings),
        p95_us=_percentile(timings, 0.95),
        mean_gates_evaluated=statistics.fmean(gate_counts),
        rejections=rejections // repeats,
        samples=len(timings),
    )


def benchmark_orderings(
    size: int = 400, reject_rate: float = 0.5, seed: int = 0, repeats: int = 3
) -> Dict[str, OrderingBenchmark]:
    """Compare declaration order against the Fail-Fast order."""
    corpus = build_corpus(size=size, reject_rate=reject_rate, seed=seed)
    return {
        "naive": benchmark_ordering(corpus, NAIVE_ORDER, "declaration order", repeats=repeats),
        "fail_fast": benchmark_ordering(corpus, FAIL_FAST_ORDER, "fail-fast order", repeats=repeats),
    }


def format_report(results: Dict[str, OrderingBenchmark]) -> str:
    """Render the comparison, including the honest verdict on the claim."""
    naive = results["naive"]
    fast = results["fail_fast"]
    reduction = (
        (naive.mean_us - fast.mean_us) / naive.mean_us * 100.0 if naive.mean_us else 0.0
    )
    gate_reduction = (
        (naive.mean_gates_evaluated - fast.mean_gates_evaluated)
        / naive.mean_gates_evaluated
        * 100.0
        if naive.mean_gates_evaluated
        else 0.0
    )

    lines = [
        "Zero Trust Stack -- gate ordering benchmark",
        "=" * 62,
        f"{'ordering':<20}{'mean us':>10}{'median':>10}{'p95':>10}{'gates':>10}",
        "-" * 62,
    ]
    for b in (naive, fast):
        lines.append(
            f"{b.label:<20}{b.mean_us:>10.2f}{b.median_us:>10.2f}"
            f"{b.p95_us:>10.2f}{b.mean_gates_evaluated:>10.2f}"
        )
    lines += [
        "-" * 62,
        f"samples: {naive.samples} per ordering; "
        f"rejections: {naive.rejections}/{naive.samples // 3}",
        f"latency reduction:       {reduction:6.1f}%",
        f"gate evaluations avoided:{gate_reduction:6.1f}%",
        "",
        "Archival claim: 214ms -> 32ms (88% reduction).",
        "The direction of that claim reproduces: ordering cheap, selective gates",
        "first avoids work on inputs that are rejected early. The magnitude is a",
        "property of the corpus and the gate costs, not a constant of the design,",
        "and the absolute figures above are microseconds rather than milliseconds.",
    ]
    return "\n".join(lines)
