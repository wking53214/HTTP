"""The archival HTTP v1.0 engine, preserved verbatim.

Recovered from Claude_History transcript 8cdf517a-32af-40ff-b754-2658d7c52847,
message dated 2026-05-30T00:26:14Z. The corpus flagged the existence of
functional Python from "Chats 50-60" as "the single critical priority" and
"the only confirmed executable outputs in the entire corpus"; this is that
code.

It is kept unchanged, bugs included, for three reasons: it is the historical
artifact, it is the baseline the v2 engine is measured against, and
``compare_engines`` below demonstrates concretely what the v1 design could and
could not detect.

Do not import this for real work. Use :mod:`http_protocol.engine`.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List

# ==========================================================================
# BEGIN VERBATIM ARCHIVAL SOURCE -- do not modify
# ==========================================================================


class HTTP7x70IntegrityEngine:
    """
    7x70 Red Team Testing Structure
    Core: Recursive Filtration & Deterministic Truth Verification
    """

    def __init__(self):
        self.layers = [
            "Foundational Axioms",   # Layer 1: Schema & Ground Truth
            "Recursive Filtration",  # Layer 2: Noise Reduction
            "Lexicographical Scrub", # Layer 3: Syntactic Purity
            "Historical Context",    # Layer 4: Pattern Recognition (2=Pattern)
            "Guardrail Enforcement", # Layer 5: Boundary Isolation
            "Recovery Audit",        # Layer 6: Failure Mode Simulation
            "Command Execution"      # Layer 7: Final Mandate (3=Mandate)
        ]
        self.anomalies = 0

    def syntactic_scrub(self, data):
        """Perform brutal syntactic scrubbing to isolate linguistic drift."""
        # Clinical normalization of the HTTP payload
        return str(data).strip().lower()

    def recursive_filter(self, payload, depth=3):
        """Recursive filtration to ensure data integrity at depth."""
        if depth == 0:
            return payload
        # Simulation of deep-packet inspection and filtration
        filtered = hashlib.sha256(payload.encode()).hexdigest()
        return self.recursive_filter(filtered, depth - 1)

    def verify_truth(self, layer, simulation_id, payload):
        """Verify deterministic integrity across 7 layers of truth."""
        # Simulated logic gates for each layer
        if "eval" in payload or "script" in payload:
            self.anomalies += 1
            return False
        return True

    def process_request(self, http_request, verbose: bool = True):
        if verbose:
            print(
                f"--- [START] 7x70 Clinical Audit: "
                f"{http_request['method']} {http_request['path']} ---"
            )
        self.anomalies = 0
        payload = json.dumps(http_request)

        # 70 Micro-simulations across the 7-layer stack
        for sim_id in range(1, 71):
            for i, layer_name in enumerate(self.layers):
                scrubbed_data = self.syntactic_scrub(payload)
                verified = self.verify_truth(layer_name, sim_id, scrubbed_data)

                # Axiom: 1=Anomaly, 2=Pattern, 3=Mandate
                if self.anomalies >= 3:
                    if verbose:
                        print(
                            f"![MANDATE] Critical Integrity Failure at Sim "
                            f"{sim_id}, Layer {i+1} ({layer_name})"
                        )
                    return {
                        "status": "BLOCKED",
                        "reason": "Deterministic Integrity Violation",
                    }

                if self.anomalies == 2:
                    # Logic: Pattern detected, escalating filtration
                    payload = self.recursive_filter(payload)
        # Final Operational Parity Check
        if verbose:
            print(
                f"--- [PASS] Operational Parity Achieved. "
                f"Total Anomalies: {self.anomalies} ---"
            )
        return {"status": "SUCCESS", "integrity_hash": self.recursive_filter(payload)}


# ==========================================================================
# END VERBATIM ARCHIVAL SOURCE
# ==========================================================================


#: Defects in the v1.0 design, each verifiable by running it.
#:
#: These are not stylistic complaints. Each one bounds what the engine is
#: capable of detecting, and together they explain why 490 evaluations could
#: only ever return one bit of information.
KNOWN_LIMITATIONS = (
    "All seven layers call the same verify_truth, so the layer list is "
    "decorative: seven names, one behaviour.",
    "verify_truth matches the substrings 'eval' and 'script' only. SQL "
    "injection, path traversal, shell chaining and JNDI lookups pass.",
    "'script' matches inside ordinary words such as 'description' and "
    "'subscription', so benign payloads are reported as attacks.",
    "The 70 simulations never mutate the payload, so simulations 2 through 70 "
    "recompute an identical answer at 70x the cost.",
    "syntactic_scrub lowercases and strips; neither defeats any attack.",
    "recursive_filter SHA-256 hashes the payload, which destroys it rather "
    "than filtering it -- and once hashed, no later layer can inspect it.",
    "The anomaly counter is never reset between layers, so three benign "
    "matches anywhere in the run block the request.",
    "Parity is printed unconditionally on the success path; it is a literal, "
    "never a measurement.",
    "A finding reports no layer, no severity and no evidence, so a BLOCKED "
    "verdict cannot be audited.",
)


def compare_engines(subject: Dict[str, Any]) -> Dict[str, Any]:
    """Run v1.0 and v2.0 over the same subject and contrast the outcomes.

    Used by the test suite to hold the documented limitations honest: each
    claim in ``KNOWN_LIMITATIONS`` is checkable by running both engines.
    """
    from .engine import grind

    legacy_result = HTTP7x70IntegrityEngine().process_request(
        dict(subject), verbose=False
    )
    report = grind(subject)

    return {
        "subject_digest": report.subject_digest,
        "v1": {
            "status": legacy_result["status"],
            "reason": legacy_result.get("reason", ""),
            "distinct_findings": 0,  # v1 cannot name a finding
            "evidence": None,
        },
        "v2": {
            "status": report.verdict.value,
            "parity": round(report.parity, 4),
            "distinct_findings": len({(f.layer, f.code) for f in report.findings}),
            "evidence": [f.code for f in report.findings[:5]],
            "evaluations": report.evaluations,
        },
    }
