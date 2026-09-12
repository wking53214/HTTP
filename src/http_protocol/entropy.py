"""Variable-entropy mutation for the 70 micro-simulations.

The archival spec called for "70 variable-entropy micro-simulations", but the
v1.0 engine looped ``for sim_id in range(1, 71)`` over an unchanged payload.
Seventy identical evaluations of an identical subject return an identical
answer seventy times; the loop cost 70x the compute and produced one bit of
information.

The reconstruction makes the entropy real. Simulation *i* perturbs the subject
at an entropy level that rises across the run, and the grind then asks whether
the verdict *holds* under perturbation. That is metamorphic testing: the
mutations are semantics-preserving with respect to the safety question, so a
verdict that changes under them is unstable and the instability is the finding.

Mutations are seeded and therefore reproducible: the same subject and seed
produce the same 70 subjects on every run.
"""

from __future__ import annotations

import copy
import random
from typing import Any, Callable, Dict, List, Tuple

#: Number of micro-simulations per grind. Recovered from the 7x70 spec.
DEFAULT_SIMULATIONS = 70

#: Entropy ramps linearly across the run, from a near-identity probe to heavy
#: perturbation, so early simulations catch obvious defects cheaply.
MIN_ENTROPY = 0.0
MAX_ENTROPY = 1.0

#: Only whitespace that JSON encodes as a short escape. Vertical tab and form
#: feed encode as \u000b / \u000c, which the filtration layer correctly reads
#: as unicode-escaped content -- so padding with them would inject the very
#: finding the mutation is supposed to leave untouched.
_WHITESPACE = ("\t", "\n", "\r", " ")
#: Only the method is case-insensitive. Paths are case-sensitive, so
#: flipping their case changes meaning and is not an equivalence mutation.
_CASE_TARGETS = ("method",)


def _mutate_whitespace(subject: Dict[str, Any], rng: random.Random) -> str:
    """Pad a non-empty body. Must not change any verdict.

    Only non-empty bodies are padded: padding an empty body would make a GET
    request carry content, which legitimately changes the answer and would
    therefore be a defect in the mutator rather than in the filter.
    """
    body = subject.get("body")
    if isinstance(body, str) and body:
        pad = "".join(rng.choice(_WHITESPACE) for _ in range(rng.randint(1, 4)))
        subject["body"] = pad + body + pad
        return "whitespace-pad"
    return "noop"


def _mutate_case(subject: Dict[str, Any], rng: random.Random) -> str:
    """Flip case on a case-insensitive field. Must not change any verdict."""
    field = rng.choice(_CASE_TARGETS)
    value = subject.get(field)
    if isinstance(value, str) and value:
        subject[field] = "".join(
            ch.upper() if rng.random() < 0.5 else ch.lower() for ch in value
        )
        return f"case-flip:{field}"
    return "noop"


def _mutate_header_order(subject: Dict[str, Any], rng: random.Random) -> str:
    """Reorder headers. Header order is not semantic, so verdicts must hold."""
    headers = subject.get("headers")
    if isinstance(headers, dict) and len(headers) > 1:
        items = list(headers.items())
        rng.shuffle(items)
        subject["headers"] = dict(items)
        return "header-reorder"
    return "noop"


def _mutate_benign_header(subject: Dict[str, Any], rng: random.Random) -> str:
    """Add an inert header. Must not change any verdict."""
    headers = subject.get("headers")
    if isinstance(headers, dict):
        headers[f"X-Probe-{rng.randint(1000, 9999)}"] = "grind"
        return "benign-header"
    return "noop"


def _mutate_unicode_confusable(subject: Dict[str, Any], rng: random.Random) -> str:
    """Swap ASCII for visually identical Unicode in the path.

    A filter that matches on raw bytes will miss this; one that normalises
    first will not. Either behaviour is informative.
    """
    path = subject.get("path")
    confusables = {"a": "а", "e": "е", "o": "о", "c": "с"}
    if isinstance(path, str):
        out = []
        changed = False
        for ch in path:
            low = ch.lower()
            if low in confusables and rng.random() < 0.5:
                out.append(confusables[low])
                changed = True
            else:
                out.append(ch)
        if changed:
            subject["path"] = "".join(out)
            return "unicode-confusable"
    return "noop"


def _mutate_nesting(subject: Dict[str, Any], rng: random.Random) -> str:
    """Wrap metadata in extra structure, exercising the filtration layer."""
    depth = rng.randint(2, 6)
    nested: Any = {"probe": True}
    for _ in range(depth):
        nested = {"wrap": nested}
    subject.setdefault("metadata", {})
    if isinstance(subject["metadata"], dict):
        subject["metadata"]["nest"] = nested
        return f"nest-depth:{depth}"
    return "noop"


#: Mutation classes.
#:
#: This distinction is what makes parity meaningful. EQUIVALENCE mutations are
#: guaranteed not to change the safety answer, so if the verdict moves under
#: one, the filter is unstable and that is a real defect. PROBE mutations may
#: legitimately change the answer -- they test whether the filter normalises
#: input before matching -- so counting them as parity violations would report
#: correct behaviour as a fault.
EQUIVALENCE = "equivalence"
PROBE = "probe"

#: (mutator, minimum entropy at which it becomes eligible, class).
MUTATORS: Tuple[Tuple[Callable[[Dict[str, Any], random.Random], str], float, str], ...] = (
    (_mutate_whitespace, 0.00, EQUIVALENCE),
    (_mutate_case, 0.10, EQUIVALENCE),
    (_mutate_header_order, 0.20, EQUIVALENCE),
    (_mutate_benign_header, 0.30, EQUIVALENCE),
    (_mutate_nesting, 0.55, PROBE),
    (_mutate_unicode_confusable, 0.70, PROBE),
)


def entropy_for(index: int, total: int) -> float:
    """Entropy level for simulation ``index`` of ``total`` (1-based)."""
    if total <= 1:
        return MIN_ENTROPY
    span = MAX_ENTROPY - MIN_ENTROPY
    return MIN_ENTROPY + span * ((index - 1) / (total - 1))


def mutate(
    subject: Dict[str, Any], entropy: float, rng: random.Random
) -> Tuple[Dict[str, Any], str, str]:
    """Return a perturbed copy of ``subject``, a label, and its mutation class.

    The number of mutators applied scales with entropy, so simulation 70 is a
    meaningfully harder probe than simulation 2. A simulation is classed PROBE
    if any applied mutator was a probe, since one probe mutation is enough to
    make the result unsafe to score for parity.
    """
    mutated = copy.deepcopy(subject)
    eligible = [(m, cls) for m, floor, cls in MUTATORS if entropy >= floor]
    if not eligible:
        return mutated, "identity", EQUIVALENCE

    rounds = 1 + int(entropy * (len(eligible) - 1))
    applied: List[str] = []
    classes: List[str] = []
    for _ in range(rounds):
        mutator, cls = rng.choice(eligible)
        label = mutator(mutated, rng)
        applied.append(label)
        if label != "noop":
            classes.append(cls)

    meaningful = [a for a in applied if a != "noop"]
    kind = PROBE if PROBE in classes else EQUIVALENCE
    return mutated, ",".join(meaningful) if meaningful else "identity", kind


def simulation_plan(
    subject: Dict[str, Any], count: int = DEFAULT_SIMULATIONS, seed: int = 0
) -> List[Tuple[int, float, Dict[str, Any], str, str]]:
    """Build the full reproducible plan of ``count`` micro-simulations.

    Returns ``(sim_id, entropy, subject, mutation_label, mutation_class)``.
    Simulation 1 is always the unmutated baseline, so the grind has a fixed
    reference verdict to measure parity against.
    """
    plan: List[Tuple[int, float, Dict[str, Any], str, str]] = [
        (1, MIN_ENTROPY, copy.deepcopy(subject), "baseline", EQUIVALENCE)
    ]
    for i in range(2, count + 1):
        # Per-simulation seed keeps each mutation independent yet reproducible.
        rng = random.Random(f"{seed}:{i}")
        level = entropy_for(i, count)
        mutated, label, kind = mutate(subject, level, rng)
        plan.append((i, level, mutated, label, kind))
    return plan
