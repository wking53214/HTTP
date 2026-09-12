"""The Zero Trust Stack -- a filter chain, and HTTP's primary subject.

HTTP is a test harness; the Zero Trust Stack is the thing it tests. The
archival record is explicit about this relationship: "Ran HTTP stress-tests on
the ZTS, resulting in a re-ordered Fail-Fast Sequence."

Seven gates were recovered from the corpus:

    G1  AB   Axiomatic Base                  cross-check against bedrock truths
    G2  SCF  Semantic Contamination Filter   meaning-level contamination
    G3  SBF  Syntactic Breach Filter         linguistic drift and jargon
    G4  HCA  Historical Context Anchor       cross-thread provenance
    G5  SND  Sycophancy Neutralization Deck  flattery and confirmation loops
    G6  PPA  Pronominal Purge Array          strip subjective pronouns
    G7  TAP  The Architect's Capstone        out-of-band manual authorisation

The corpus records a specific optimisation: reordering the chain to run cheap
regex gates before expensive semantic ones cut latency from 214ms to 32ms, an
88% reduction. That claim is reproducible here -- ``benchmark_orderings`` in
``bench.py`` measures both orders and reports the real numbers on the machine
it runs on, rather than restating the archival figure.

G7 is deliberately not part of either automatic ordering. It is an out-of-band
human handshake, and a gate chain that could satisfy it automatically would
defeat its purpose.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# Gate results
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class GateOutcome:
    gate: str
    name: str
    passed: bool
    reason: str = ""
    elapsed_us: float = 0.0


@dataclass
class ZTSResult:
    passed: bool
    outcomes: List[GateOutcome] = field(default_factory=list)
    elapsed_us: float = 0.0
    text: str = ""
    gates_evaluated: int = 0

    @property
    def rejected_by(self) -> Optional[GateOutcome]:
        return next((o for o in self.outcomes if not o.passed), None)


# --------------------------------------------------------------------------
# The gates
# --------------------------------------------------------------------------

#: G6 -- subjective pronouns the array strips. Cheapest gate in the stack:
#: one precompiled regex over the raw text.
_PRONOUNS = re.compile(
    r"\b(i|me|my|mine|myself|you|your|yours|we|us|our|ours)\b", re.I
)

#: G3 -- drift markers: conversational filler and self-referential jargon.
_DRIFT = re.compile(
    r"\b(basically|actually|essentially|let me|i think|as an ai|"
    r"great question|certainly|of course)\b",
    re.I,
)

#: G5 -- flattery and confirmation-loop markers.
_SYCOPHANCY = re.compile(
    r"\b(excellent|brilliant|perfect|amazing|absolutely right|"
    r"exactly right|great point|you're right|profound|masterful)\b",
    re.I,
)

#: G2 -- contamination: unsupported absolutes and totalising claims.
_CONTAMINATION = re.compile(
    r"\b(guaranteed|infallible|flawless|unbreakable|absolute(ly)? (certain|secure)|"
    r"100% (safe|secure|accurate)|never fails?)\b",
    re.I,
)


def gate_g6_pronominal_purge(text: str, ctx: Dict) -> Tuple[bool, str]:
    """Strip subjective pronouns to enforce objectivity. Pure regex."""
    match = _PRONOUNS.search(text)
    if match:
        return False, f"subjective pronoun {match.group(0)!r}"
    return True, ""


def gate_g3_syntactic_breach(text: str, ctx: Dict) -> Tuple[bool, str]:
    """Catch conversational drift and filler. Pure regex."""
    match = _DRIFT.search(text)
    if match:
        return False, f"drift marker {match.group(0)!r}"
    return True, ""


def gate_g1_axiomatic_base(text: str, ctx: Dict) -> Tuple[bool, str]:
    """Cross-reference claims against declared bedrock truths.

    Requires a dictionary lookup per axiom, so it costs more than a regex but
    far less than the semantic gates.
    """
    axioms: Dict[str, bool] = ctx.get("axioms", {})
    lowered = text.lower()
    for claim, holds in axioms.items():
        if claim.lower() in lowered and not holds:
            return False, f"contradicts axiom {claim!r}"
    return True, ""


def gate_g2_semantic_contamination(text: str, ctx: Dict) -> Tuple[bool, str]:
    """Detect unsupported absolutes.

    Semantic gates scan token-by-token rather than short-circuiting on a
    single precompiled pattern, which is what makes ordering matter.
    """
    tokens = text.split()
    for i, token in enumerate(tokens):
        window = " ".join(tokens[i : i + 3])
        match = _CONTAMINATION.search(window)
        if match:
            return False, f"unsupported absolute {match.group(0)!r}"
    return True, ""


def gate_g5_sycophancy_neutralization(text: str, ctx: Dict) -> Tuple[bool, str]:
    """Eradicate mirror-bias and flattery.

    The corpus identifies this failure mode as the central one: validation
    presented as verification. This gate is the direct countermeasure.
    """
    tokens = text.split()
    for i, token in enumerate(tokens):
        window = " ".join(tokens[i : i + 3])
        match = _SYCOPHANCY.search(window)
        if match:
            return False, f"sycophancy marker {match.group(0)!r}"
    return True, ""


def gate_g4_historical_context_anchor(text: str, ctx: Dict) -> Tuple[bool, str]:
    """Verify provenance against prior context.

    The most expensive gate: it compares the candidate against every prior
    entry in the supplied history rather than matching a fixed pattern.
    """
    history: Sequence[str] = ctx.get("history", ())
    if not history:
        return True, ""
    candidate = set(text.lower().split())
    if not candidate:
        return True, ""
    for prior in history:
        prior_tokens = set(prior.lower().split())
        if not prior_tokens:
            continue
        overlap = len(candidate & prior_tokens) / max(len(candidate), 1)
        if overlap > 0.92:
            return False, f"near-duplicate of prior context ({overlap:.0%} overlap)"
    return True, ""


#: Gate registry: id -> (short name, callable).
GATES: Dict[str, Tuple[str, Callable[[str, Dict], Tuple[bool, str]]]] = {
    "G1": ("Axiomatic Base", gate_g1_axiomatic_base),
    "G2": ("Semantic Contamination Filter", gate_g2_semantic_contamination),
    "G3": ("Syntactic Breach Filter", gate_g3_syntactic_breach),
    "G4": ("Historical Context Anchor", gate_g4_historical_context_anchor),
    "G5": ("Sycophancy Neutralization Deck", gate_g5_sycophancy_neutralization),
    "G6": ("Pronominal Purge Array", gate_g6_pronominal_purge),
    "G7": ("The Architect's Capstone", None),  # out-of-band, never automatic
}

#: Declaration order -- gates in the order the corpus numbers them.
NAIVE_ORDER: Tuple[str, ...] = ("G1", "G2", "G3", "G4", "G5", "G6")

#: The recovered optimisation: cheapest and most-selective gates first, so the
#: expensive semantic gates are never reached for input the regex gates can
#: already reject.
FAIL_FAST_ORDER: Tuple[str, ...] = ("G6", "G3", "G1", "G2", "G5", "G4")


def evaluate(
    text: str,
    context: Optional[Dict] = None,
    order: Sequence[str] = FAIL_FAST_ORDER,
    short_circuit: bool = True,
) -> ZTSResult:
    """Run the stack over ``text``.

    With ``short_circuit`` the chain stops at the first rejection, which is
    the whole point of the fail-fast ordering. Set it False to collect every
    gate's opinion, which is what the HTTP grind wants when characterising a
    subject rather than filtering it.
    """
    context = context or {}
    outcomes: List[GateOutcome] = []
    passed = True
    start = time.perf_counter()

    for gate_id in order:
        name, fn = GATES[gate_id]
        if fn is None:  # G7 is never evaluated automatically
            continue
        gate_start = time.perf_counter()
        ok, reason = fn(text, context)
        elapsed = (time.perf_counter() - gate_start) * 1e6
        outcomes.append(
            GateOutcome(
                gate=gate_id, name=name, passed=ok, reason=reason, elapsed_us=elapsed
            )
        )
        if not ok:
            passed = False
            if short_circuit:
                break

    total = (time.perf_counter() - start) * 1e6
    return ZTSResult(
        passed=passed,
        outcomes=outcomes,
        elapsed_us=total,
        text=text,
        gates_evaluated=len(outcomes),
    )


def requires_capstone(result: ZTSResult) -> bool:
    """Whether G7 (out-of-band human authorisation) is still outstanding.

    Passing the automatic chain is necessary but not sufficient. The capstone
    is a manual handshake by design and this function never satisfies it.
    """
    return result.passed
