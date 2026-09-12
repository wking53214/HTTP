"""HTTP -- the Hyper Truth Testing Protocol.

A 7x70 adversarial validation harness: seven distinct inspection layers run
across seventy variable-entropy micro-simulations, producing a verdict, a
measured parity score, and the findings that justify both.

See PROVENANCE.md for what was recovered from the archives and what was
reconstructed.
"""

from .engine import TruthGrind, grind
from .models import Finding, GrindReport, LayerResult, Severity, SimulationResult, Verdict
from .layers import CANONICAL_ORDER, HistoryWindow
from .parity import compute_parity, compute_utility_density
from . import zts

__version__ = "2.0.0"

__all__ = [
    "TruthGrind",
    "grind",
    "Finding",
    "GrindReport",
    "LayerResult",
    "Severity",
    "SimulationResult",
    "Verdict",
    "CANONICAL_ORDER",
    "HistoryWindow",
    "compute_parity",
    "compute_utility_density",
    "zts",
    "__version__",
]
