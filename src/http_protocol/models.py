"""Core data models for the Hyper Truth Testing Protocol.

The archival HTTP v1.0 engine returned a bare ``{"status": ..., "reason": ...}``
dict. Everything below exists so that a grind produces a *defensible record*:
which layer fired, on which micro-simulation, against which mutated payload,
and with what severity. Without that, a PASS is an assertion rather than
evidence.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    """The archival 1 / 2 / 3 axiom: ``1=Anomaly, 2=Pattern, 3=Mandate``.

    The original engine incremented a single counter and compared it to the
    literals 1, 2 and 3. Making the scale explicit lets a layer say how bad a
    finding is instead of every finding weighing the same.
    """

    CLEAN = 0
    ANOMALY = 1
    PATTERN = 2
    MANDATE = 3

    @property
    def label(self) -> str:
        return {0: "clean", 1: "anomaly", 2: "pattern", 3: "mandate"}[self.value]


class Verdict(Enum):
    PASS = "PASS"
    BLOCKED = "BLOCKED"
    DEGRADED = "DEGRADED"


@dataclass(frozen=True)
class Finding:
    """One concrete defect located by one layer on one micro-simulation."""

    layer: str
    gate: Optional[str]
    severity: Severity
    code: str
    detail: str
    simulation_id: int = 0
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d


@dataclass
class LayerResult:
    """Outcome of a single layer over a single micro-simulation."""

    layer: str
    simulation_id: int
    findings: List[Finding] = field(default_factory=list)
    elapsed_us: float = 0.0
    short_circuited: bool = False

    @property
    def worst(self) -> Severity:
        if not self.findings:
            return Severity.CLEAN
        return max((f.severity for f in self.findings), key=lambda s: s.value)

    @property
    def clean(self) -> bool:
        return not self.findings


@dataclass
class SimulationResult:
    """Outcome of all seven layers over one variable-entropy mutation."""

    simulation_id: int
    entropy: float
    mutation: str
    #: "equivalence" (must not change the verdict, so it is scored for parity)
    #: or "probe" (may legitimately change it, so it is reported separately).
    mutation_class: str = "equivalence"
    layer_results: List[LayerResult] = field(default_factory=list)

    @property
    def findings(self) -> List[Finding]:
        return [f for lr in self.layer_results for f in lr.findings]

    @property
    def worst(self) -> Severity:
        if not self.findings:
            return Severity.CLEAN
        return max((f.severity for f in self.findings), key=lambda s: s.value)

    @property
    def clean(self) -> bool:
        return not self.findings


@dataclass
class GrindReport:
    """The full 7x70 record.

    ``parity`` is the reproducibility ratio defined in ``parity.py``. It is a
    measured quantity, not the fixed 1.0000 constant the archival material
    asserted.
    """

    verdict: Verdict
    parity: float
    utility_density: float
    simulations: List[SimulationResult] = field(default_factory=list)
    layers_run: List[str] = field(default_factory=list)
    subject_digest: str = ""
    evaluations: int = 0
    elapsed_ms: float = 0.0
    halted_at: Optional[int] = None
    #: Probe simulations whose verdict diverged from the baseline. These are
    #: normalisation observations, not parity failures.
    probe_divergences: List[int] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def findings(self) -> List[Finding]:
        return [f for s in self.simulations for f in s.findings]

    @property
    def mandates(self) -> List[Finding]:
        return [f for f in self.findings if f.severity is Severity.MANDATE]

    @property
    def clean_simulations(self) -> int:
        return sum(1 for s in self.simulations if s.clean)

    def severity_histogram(self) -> Dict[str, int]:
        hist = {s.label: 0 for s in Severity if s is not Severity.CLEAN}
        for f in self.findings:
            hist[f.severity.label] += 1
        return hist

    def findings_by_layer(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.layer] = out.get(f.layer, 0) + 1
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "parity": round(self.parity, 4),
            "utility_density": round(self.utility_density, 4),
            "subject_digest": self.subject_digest,
            "evaluations": self.evaluations,
            "simulations_run": len(self.simulations),
            "clean_simulations": self.clean_simulations,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "halted_at": self.halted_at,
            "probe_divergences": self.probe_divergences,
            "layers_run": self.layers_run,
            "severity_histogram": self.severity_histogram(),
            "findings_by_layer": self.findings_by_layer(),
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def digest(self) -> str:
        """Stable hash of the report's substantive content.

        Excludes timings so two runs of the same subject compare equal.
        """
        payload = self.to_dict()
        payload.pop("elapsed_ms", None)
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()
