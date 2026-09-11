"""Parity and Utility Density.

Two numbers dominate the archival record: "1.0000 Parity" and the "Utility
Density Ratio". Neither was ever defined as a computation. The clinical
retrospective in the corpus is explicit about the consequence: the parity
figure was produced by the model as narration, so a PASS carried no
information, and the corpus notes it was reported as achieved on essentially
every run.

A constant that is always 1.0000 measures nothing. Both quantities are given
falsifiable definitions here, so a run can genuinely fail to reach parity.
"""

from __future__ import annotations

from typing import Dict, List, Sequence

from .models import GrindReport, Severity, SimulationResult, Verdict


def verdict_signature(sim: SimulationResult) -> frozenset:
    """The safety-relevant content of one simulation's outcome.

    Parity compares *which defects were found*, not incidental detail such as
    which simulation index found them, because the mutations deliberately
    change that detail.
    """
    return frozenset((f.layer, f.code, f.severity.value) for f in sim.findings)


def equivalence_simulations(
    simulations: Sequence[SimulationResult],
) -> List[SimulationResult]:
    """Simulations whose mutations are guaranteed semantics-preserving.

    Only these are scored for parity. A probe mutation that changes the
    verdict is reporting something true about normalisation, and counting it
    as a parity failure would mark correct behaviour as a fault.
    """
    return [s for s in simulations if s.mutation_class == "equivalence"]


def compute_parity(simulations: Sequence[SimulationResult]) -> float:
    """Fraction of equivalence simulations agreeing with the baseline.

    Simulation 1 is the unmutated subject. Every equivalence simulation is a
    perturbation that cannot change the safety answer, so:

        parity = (equivalence sims matching the baseline) / (equivalence sims)

    Parity of 1.0000 means something specific and checkable: every
    semantics-preserving perturbation reached the same conclusion, so the
    verdict is stable. Anything below 1.0 localises an instability -- a
    mutation that could not have changed the answer nonetheless did, which is
    a defect in the *filter*, not in the subject.
    """
    scored = equivalence_simulations(simulations)
    if not scored:
        return 0.0
    baseline = verdict_signature(scored[0])
    agreeing = sum(1 for s in scored if verdict_signature(s) == baseline)
    return agreeing / len(scored)


def divergent_simulations(
    simulations: Sequence[SimulationResult],
) -> List[SimulationResult]:
    """Equivalence simulations whose outcome differs from the baseline.

    These are the actionable output of a sub-1.0 parity score.
    """
    scored = equivalence_simulations(simulations)
    if not scored:
        return []
    baseline = verdict_signature(scored[0])
    return [s for s in scored[1:] if verdict_signature(s) != baseline]


def probe_divergences(
    simulations: Sequence[SimulationResult],
) -> List[SimulationResult]:
    """Probe simulations whose outcome differs from the baseline.

    Reported, not penalised: these indicate the filter treats a normalised
    variant differently from the original, which is worth knowing but is not
    a parity failure.
    """
    scored = equivalence_simulations(simulations)
    if not scored:
        return []
    baseline = verdict_signature(scored[0])
    return [
        s
        for s in simulations
        if s.mutation_class == "probe" and verdict_signature(s) != baseline
    ]


def compute_utility_density(
    simulations: Sequence[SimulationResult], evaluations: int
) -> float:
    """Distinct defects discovered per thousand layer evaluations.

    The archival framing treated the Utility Density Ratio as a score to
    maximise. It is more useful as a diagnostic of the grind itself: a full
    7x70 run costs 490 evaluations, and if those 490 evaluations surface only
    one distinct defect, most of the run was wasted compute.

    That is precisely the v1.0 failure mode -- seven layers sharing one check
    over seventy identical payloads could not exceed one distinct finding.
    """
    if evaluations <= 0:
        return 0.0
    distinct = {(f.layer, f.code) for s in simulations for f in s.findings}
    return len(distinct) / (evaluations / 1000.0)


def decide_verdict(
    simulations: Sequence[SimulationResult], parity: float, parity_floor: float
) -> Verdict:
    """Map findings and parity onto a final verdict.

    Follows the recovered 1 / 2 / 3 axiom -- anomaly, pattern, mandate -- with
    the escalation made explicit:

    * any MANDATE finding blocks outright;
    * PATTERN findings on the unmutated baseline block, since the subject
      itself is implicated rather than a mutation of it;
    * parity below the floor is DEGRADED: the filter disagreed with itself,
      so no verdict it produced can be trusted.
    """
    # Probe mutations are allowed to surface findings the baseline lacks, so
    # the verdict is decided on equivalence simulations only.
    scored = equivalence_simulations(simulations)
    all_findings = [f for s in scored for f in s.findings]

    if any(f.severity is Severity.MANDATE for f in all_findings):
        return Verdict.BLOCKED

    if scored:
        baseline = scored[0]
        if any(f.severity is Severity.PATTERN for f in baseline.findings):
            return Verdict.BLOCKED

    if parity < parity_floor:
        return Verdict.DEGRADED

    return Verdict.PASS


def parity_note(parity: float, divergent: Sequence[SimulationResult]) -> str:
    """Human-readable explanation of a parity score."""
    if parity >= 1.0:
        return "parity 1.0000: verdict held across every micro-simulation"
    ids = ", ".join(str(s.simulation_id) for s in divergent[:8])
    more = "" if len(divergent) <= 8 else f" (+{len(divergent) - 8} more)"
    return (
        f"parity {parity:.4f}: verdict changed under mutation at "
        f"simulation(s) {ids}{more}; the filter is unstable, not the subject"
    )
