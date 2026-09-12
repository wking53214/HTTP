"""The Hyper Truth Testing Protocol engine -- the 7x70 Truth Grind.

Orchestrates seven distinct layers across seventy variable-entropy
micro-simulations (490 evaluations) and reports a verdict with the evidence
that produced it.

Differences from the archival v1.0 engine, all of which follow from the
retrospective's own criticism of it:

* Seven layers do seven different things rather than sharing one substring
  check, so the 490 evaluations can surface more than one distinct defect.
* The seventy simulations mutate the subject, so they test verdict stability
  instead of recomputing an identical answer seventy times.
* Parity is measured from those mutations rather than asserted as a constant,
  so a run can fail to reach it.
* Findings carry a layer, a code, a severity and the evidence that triggered
  them, so a BLOCKED verdict is auditable.
* Layer exceptions are contained: a crash in a layer becomes a MANDATE
  finding rather than taking the grind down.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Sequence

from .layers import CANONICAL_ORDER, HistoryWindow, build_layers, run_layer
from .models import GrindReport, Severity, SimulationResult, Verdict
from .entropy import DEFAULT_SIMULATIONS, simulation_plan
from .parity import (
    compute_parity,
    compute_utility_density,
    decide_verdict,
    divergent_simulations,
    parity_note,
    probe_divergences,
)

#: Seven layers. Recovered from the v1.0 ``self.layers`` declaration.
LAYER_COUNT = 7

#: Parity below this is DEGRADED -- the filter contradicted itself under
#: perturbation, so its verdict cannot be relied on.
DEFAULT_PARITY_FLOOR = 1.0


class TruthGrind:
    """A configured 7x70 grind.

    Reusable across subjects: the history window persists between calls so
    layer 4 can recognise replay across a session, which is the only way that
    layer can do its job.
    """

    def __init__(
        self,
        simulations: int = DEFAULT_SIMULATIONS,
        seed: int = 0,
        parity_floor: float = DEFAULT_PARITY_FLOOR,
        halt_on_mandate: bool = True,
        history: Optional[HistoryWindow] = None,
    ) -> None:
        if simulations < 1:
            raise ValueError("simulations must be at least 1")
        if not 0.0 <= parity_floor <= 1.0:
            raise ValueError("parity_floor must be within [0.0, 1.0]")

        self.simulations = simulations
        self.seed = seed
        self.parity_floor = parity_floor
        self.halt_on_mandate = halt_on_mandate
        self.history = history if history is not None else HistoryWindow()
        self._layers = build_layers(self.history)

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _digest(subject: Dict[str, Any]) -> str:
        return hashlib.sha256(
            json.dumps(subject, sort_keys=True, default=str).encode()
        ).hexdigest()

    def _run_simulation(
        self,
        sim_id: int,
        entropy: float,
        subject: Dict[str, Any],
        mutation: str,
        mutation_class: str,
    ) -> SimulationResult:
        result = SimulationResult(
            simulation_id=sim_id,
            entropy=entropy,
            mutation=mutation,
            mutation_class=mutation_class,
        )
        for name, fn in self._layers:
            layer_result = run_layer(name, fn, subject, sim_id)
            result.layer_results.append(layer_result)
            if self.halt_on_mandate and layer_result.worst is Severity.MANDATE:
                # Deeper layers presume the subject survived the shallower
                # ones; running them past a mandate yields noise, not evidence.
                layer_result.short_circuited = True
                break
        return result

    # -- public API --------------------------------------------------------

    def grind(self, subject: Dict[str, Any]) -> GrindReport:
        """Run the full 7x70 grind over ``subject``."""
        if not isinstance(subject, dict):
            raise TypeError("subject must be a dict")

        start = time.perf_counter()
        digest = self._digest(subject)
        plan = simulation_plan(subject, count=self.simulations, seed=self.seed)

        results: List[SimulationResult] = []
        evaluations = 0
        halted_at: Optional[int] = None

        for sim_id, entropy, mutated, mutation, mutation_class in plan:
            sim = self._run_simulation(
                sim_id, entropy, mutated, mutation, mutation_class
            )
            evaluations += len(sim.layer_results)
            results.append(sim)

            # A mandate on the unmutated baseline settles the question: the
            # subject itself is hostile, and mutating it further adds nothing.
            if sim_id == 1 and sim.worst is Severity.MANDATE and self.halt_on_mandate:
                halted_at = sim_id
                break

        parity = compute_parity(results)
        divergent = divergent_simulations(results)
        probes = probe_divergences(results)
        utility = compute_utility_density(results, evaluations)
        verdict = decide_verdict(results, parity, self.parity_floor)
        elapsed = (time.perf_counter() - start) * 1000.0

        # Layer 4 only sees the subject after the grind, so a subject is never
        # judged a replay of itself.
        self.history.observe(str(subject.get("path", "")), digest)

        notes = [parity_note(parity, divergent)]
        if probes:
            notes.append(
                f"{len(probes)} probe simulation(s) diverged from the baseline: "
                f"the filter treats normalised variants differently. Reported, "
                f"not scored against parity."
            )
        if halted_at is not None:
            notes.append(
                f"halted at simulation {halted_at}: mandate on the unmutated baseline"
            )
        if utility < 2.0 and evaluations > 100:
            notes.append(
                f"utility density {utility:.2f} distinct findings per 1000 "
                f"evaluations: most of this run's compute found nothing new"
            )

        return GrindReport(
            verdict=verdict,
            parity=parity,
            utility_density=utility,
            simulations=results,
            layers_run=list(CANONICAL_ORDER),
            subject_digest=digest,
            evaluations=evaluations,
            elapsed_ms=elapsed,
            halted_at=halted_at,
            probe_divergences=[s.simulation_id for s in probes],
            notes=notes,
        )

    def grind_many(self, subjects: Sequence[Dict[str, Any]]) -> List[GrindReport]:
        """Grind a sequence of subjects against one shared history window."""
        return [self.grind(s) for s in subjects]


def grind(subject: Dict[str, Any], **kwargs: Any) -> GrindReport:
    """One-shot convenience wrapper around :class:`TruthGrind`."""
    return TruthGrind(**kwargs).grind(subject)
