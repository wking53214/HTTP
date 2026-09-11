"""The seven optimization layers of the Truth Grind.

The archival v1.0 engine declared seven layer names and then routed all seven
through one ``verify_truth`` method that searched for the substrings ``eval``
and ``script``. The layer list was therefore decorative: seven names, one
behaviour, and a run of 490 evaluations that could only ever discover the same
single defect.

Each layer here does distinct work and can only raise the finding codes it
owns, so a report identifies *which kind* of defect was found.
"""

from __future__ import annotations

import json
import math
import re
import time
from typing import Any, Callable, Dict, List, Optional, Sequence

from .models import Finding, LayerResult, Severity

# --------------------------------------------------------------------------
# Layer 1 -- Foundational Axioms (schema and ground truth)
# --------------------------------------------------------------------------

#: Structural requirements a subject must satisfy before deeper layers can
#: draw any conclusion from it.
REQUIRED_KEYS: Sequence[str] = ("method", "path")

SAFE_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"}
)


def layer_foundational_axioms(subject: Dict[str, Any], sim_id: int) -> List[Finding]:
    """Verify the subject is well formed before anything else reasons about it.

    A malformed subject makes every downstream verdict meaningless, so this
    layer runs first and reports at MANDATE severity.
    """
    findings: List[Finding] = []
    for key in REQUIRED_KEYS:
        if key not in subject:
            findings.append(
                Finding(
                    layer="foundational_axioms",
                    gate="L1",
                    severity=Severity.MANDATE,
                    code="AXIOM_MISSING_KEY",
                    detail=f"subject omits required key {key!r}",
                    simulation_id=sim_id,
                )
            )

    method = subject.get("method")
    if method is not None and str(method).upper() not in SAFE_METHODS:
        findings.append(
            Finding(
                layer="foundational_axioms",
                gate="L1",
                severity=Severity.PATTERN,
                code="AXIOM_UNKNOWN_METHOD",
                detail=f"method {method!r} is outside the known verb set",
                simulation_id=sim_id,
                evidence=str(method)[:120],
            )
        )

    path = subject.get("path")
    if isinstance(path, str) and not path.startswith("/"):
        findings.append(
            Finding(
                layer="foundational_axioms",
                gate="L1",
                severity=Severity.ANOMALY,
                code="AXIOM_RELATIVE_PATH",
                detail="path is not rooted at '/'",
                simulation_id=sim_id,
                evidence=path[:120],
            )
        )
    return findings


# --------------------------------------------------------------------------
# Layer 2 -- Recursive Filtration (noise reduction)
# --------------------------------------------------------------------------

#: Nesting past this depth is a denial-of-service shape rather than a payload.
MAX_NESTING_DEPTH = 12

#: Encoding applied more than twice is obfuscation, not transport.
MAX_ENCODING_ROUNDS = 2

_ENCODING_MARKERS = (
    (re.compile(r"%[0-9a-fA-F]{2}"), "percent"),
    (re.compile(r"\\u[0-9a-fA-F]{4}"), "unicode-escape"),
    (re.compile(r"&#x?[0-9a-fA-F]+;"), "html-entity"),
    (re.compile(r"base64_decode|atob\(|b64decode"), "base64-call"),
)


def _depth(value: Any, level: int = 0) -> int:
    if level > 64:  # guard against self-referential structures
        return level
    if isinstance(value, dict):
        return max((_depth(v, level + 1) for v in value.values()), default=level)
    if isinstance(value, (list, tuple)):
        return max((_depth(v, level + 1) for v in value), default=level)
    return level


def layer_recursive_filtration(subject: Dict[str, Any], sim_id: int) -> List[Finding]:
    """Strip structural noise and report what the noise was hiding.

    The v1.0 ``recursive_filter`` hashed the payload three times with SHA-256
    and called the digest "filtered". Hashing is one-way: it removed the
    payload rather than the noise, and nothing downstream could inspect the
    result. This layer instead *measures* the obfuscation.
    """
    findings: List[Finding] = []

    depth = _depth(subject)
    if depth > MAX_NESTING_DEPTH:
        findings.append(
            Finding(
                layer="recursive_filtration",
                gate="L2",
                severity=Severity.PATTERN,
                code="FILTER_EXCESSIVE_NESTING",
                detail=f"nesting depth {depth} exceeds limit {MAX_NESTING_DEPTH}",
                simulation_id=sim_id,
            )
        )

    blob = json.dumps(subject, default=str)
    layered = [name for rx, name in _ENCODING_MARKERS if rx.search(blob)]
    if len(layered) > MAX_ENCODING_ROUNDS:
        findings.append(
            Finding(
                layer="recursive_filtration",
                gate="L2",
                severity=Severity.MANDATE,
                code="FILTER_LAYERED_ENCODING",
                detail=(
                    f"{len(layered)} concurrent encoding schemes "
                    f"({', '.join(layered)}) indicate deliberate obfuscation"
                ),
                simulation_id=sim_id,
            )
        )
    elif layered:
        findings.append(
            Finding(
                layer="recursive_filtration",
                gate="L2",
                severity=Severity.ANOMALY,
                code="FILTER_ENCODED_CONTENT",
                detail=f"encoded content present ({', '.join(layered)})",
                simulation_id=sim_id,
            )
        )
    return findings


# --------------------------------------------------------------------------
# Layer 3 -- Lexicographical Scrub (syntactic purity)
# --------------------------------------------------------------------------

#: Injection shapes. The archival engine checked two substrings; these are the
#: patterns that substring check was standing in for.
INJECTION_PATTERNS: Sequence[tuple] = (
    (re.compile(r"\beval\s*\(", re.I), "code evaluation call"),
    (re.compile(r"<\s*script\b", re.I), "inline script element"),
    (re.compile(r"\b(union\s+select|drop\s+table|or\s+1\s*=\s*1)\b", re.I), "SQL injection"),
    (re.compile(r"(\.\./){2,}"), "path traversal"),
    (re.compile(r"[;|&`]\s*(rm|curl|wget|nc|sh|bash)\b", re.I), "shell command chain"),
    (re.compile(r"\b__(import|class|globals|subclasses)__\b"), "python introspection escape"),
    (re.compile(r"\$\{\s*jndi\s*:", re.I), "JNDI lookup"),
)

#: Shannon entropy above this, over a long enough run, reads as packed payload.
ENTROPY_CEILING = 4.7
ENTROPY_MIN_LENGTH = 48


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character."""
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def layer_lexicographical_scrub(subject: Dict[str, Any], sim_id: int) -> List[Finding]:
    """Search the *decoded* surface for injection grammar.

    The v1.0 ``syntactic_scrub`` lowercased and stripped the payload, which
    defeats nothing: an attack survives ``.lower()`` intact. Normalisation is
    only useful as a preliminary to matching, which is what happens here.
    """
    findings: List[Finding] = []
    blob = json.dumps(subject, default=str)
    normalized = blob.lower()

    for rx, description in INJECTION_PATTERNS:
        match = rx.search(normalized)
        if match:
            findings.append(
                Finding(
                    layer="lexicographical_scrub",
                    gate="L3",
                    severity=Severity.MANDATE,
                    code="SCRUB_INJECTION",
                    detail=f"{description} detected",
                    simulation_id=sim_id,
                    evidence=match.group(0)[:120],
                )
            )

    body = subject.get("body")
    if isinstance(body, str) and len(body) >= ENTROPY_MIN_LENGTH:
        bits = shannon_entropy(body)
        if bits > ENTROPY_CEILING:
            findings.append(
                Finding(
                    layer="lexicographical_scrub",
                    gate="L3",
                    severity=Severity.PATTERN,
                    code="SCRUB_HIGH_ENTROPY",
                    detail=f"body entropy {bits:.2f} bits/char exceeds {ENTROPY_CEILING}",
                    simulation_id=sim_id,
                )
            )
    return findings


# --------------------------------------------------------------------------
# Layer 4 -- Historical Context (pattern recognition)
# --------------------------------------------------------------------------


class HistoryWindow:
    """Rolling memory of prior subjects, so layer 4 has a history to consult.

    The archival engine had no cross-request state, which left "Historical
    Context / Pattern Recognition" with nothing to recognise a pattern against.
    """

    def __init__(self, capacity: int = 256) -> None:
        self.capacity = capacity
        self._paths: List[str] = []
        self._digests: List[str] = []

    def observe(self, path: str, digest: str) -> None:
        self._paths.append(path)
        self._digests.append(digest)
        if len(self._paths) > self.capacity:
            self._paths.pop(0)
            self._digests.pop(0)

    def path_count(self, path: str) -> int:
        return self._paths.count(path)

    def digest_count(self, digest: str) -> int:
        return self._digests.count(digest)

    def clear(self) -> None:
        self._paths.clear()
        self._digests.clear()


#: Identical subject seen this many times in the window reads as replay.
REPLAY_THRESHOLD = 3


def make_historical_context_layer(
    history: HistoryWindow,
) -> Callable[[Dict[str, Any], int], List[Finding]]:
    """Bind layer 4 to a history window."""

    def layer_historical_context(subject: Dict[str, Any], sim_id: int) -> List[Finding]:
        findings: List[Finding] = []
        path = str(subject.get("path", ""))
        import hashlib

        digest = hashlib.sha256(
            json.dumps(subject, sort_keys=True, default=str).encode()
        ).hexdigest()

        repeats = history.digest_count(digest)
        if repeats >= REPLAY_THRESHOLD:
            findings.append(
                Finding(
                    layer="historical_context",
                    gate="L4",
                    severity=Severity.PATTERN,
                    code="HISTORY_REPLAY",
                    detail=f"identical subject seen {repeats} times in window",
                    simulation_id=sim_id,
                    evidence=digest[:16],
                )
            )
        return findings

    return layer_historical_context


# --------------------------------------------------------------------------
# Layer 5 -- Guardrail Enforcement (boundary isolation)
# --------------------------------------------------------------------------

#: Boundary constants recovered from the archival gate description.
MAX_SUBJECT_CHARS = 500
MAX_HEADER_COUNT = 40

SENSITIVE_PATH_PATTERNS = (
    re.compile(r"^/(admin|internal|\.git|\.env)\b", re.I),
    re.compile(r"/etc/(passwd|shadow)\b", re.I),
)


def layer_guardrail_enforcement(subject: Dict[str, Any], sim_id: int) -> List[Finding]:
    """Enforce the declared capability boundary.

    Size and scope limits, which the v1.0 engine never checked at all.
    """
    findings: List[Finding] = []
    blob = json.dumps(subject, default=str)

    if len(blob) > MAX_SUBJECT_CHARS:
        findings.append(
            Finding(
                layer="guardrail_enforcement",
                gate="L5",
                severity=Severity.ANOMALY,
                code="GUARD_OVERSIZE",
                detail=f"subject is {len(blob)} chars, limit {MAX_SUBJECT_CHARS}",
                simulation_id=sim_id,
            )
        )

    headers = subject.get("headers")
    if isinstance(headers, dict) and len(headers) > MAX_HEADER_COUNT:
        findings.append(
            Finding(
                layer="guardrail_enforcement",
                gate="L5",
                severity=Severity.ANOMALY,
                code="GUARD_HEADER_FLOOD",
                detail=f"{len(headers)} headers exceed limit {MAX_HEADER_COUNT}",
                simulation_id=sim_id,
            )
        )

    path = str(subject.get("path", ""))
    for rx in SENSITIVE_PATH_PATTERNS:
        if rx.search(path):
            findings.append(
                Finding(
                    layer="guardrail_enforcement",
                    gate="L5",
                    severity=Severity.MANDATE,
                    code="GUARD_RESTRICTED_PATH",
                    detail="path targets a restricted region",
                    simulation_id=sim_id,
                    evidence=path[:120],
                )
            )
            break
    return findings


# --------------------------------------------------------------------------
# Layer 6 -- Recovery Audit (failure mode simulation)
# --------------------------------------------------------------------------


def layer_recovery_audit(subject: Dict[str, Any], sim_id: int) -> List[Finding]:
    """Confirm the subject survives serialisation intact.

    A subject that cannot be round-tripped cannot be logged, replayed, or
    reasoned about after the fact, which makes the audit trail unreliable
    regardless of the verdict.
    """
    findings: List[Finding] = []
    try:
        restored = json.loads(json.dumps(subject, default=str))
    except (TypeError, ValueError) as exc:
        findings.append(
            Finding(
                layer="recovery_audit",
                gate="L6",
                severity=Severity.MANDATE,
                code="RECOVERY_UNSERIALIZABLE",
                detail=f"subject cannot be serialised: {exc}",
                simulation_id=sim_id,
            )
        )
        return findings

    if restored != json.loads(json.dumps(subject, default=str)):
        findings.append(
            Finding(
                layer="recovery_audit",
                gate="L6",
                severity=Severity.PATTERN,
                code="RECOVERY_UNSTABLE",
                detail="serialisation is not idempotent",
                simulation_id=sim_id,
            )
        )
    return findings


# --------------------------------------------------------------------------
# Layer 7 -- Command Execution (final mandate)
# --------------------------------------------------------------------------


def layer_command_execution(subject: Dict[str, Any], sim_id: int) -> List[Finding]:
    """Final consistency check on the declared action.

    Runs last because it presumes the subject is already known to be well
    formed and non-hostile.
    """
    findings: List[Finding] = []
    method = str(subject.get("method", "")).upper()
    body = subject.get("body")

    if method in {"GET", "HEAD"} and body:
        findings.append(
            Finding(
                layer="command_execution",
                gate="L7",
                severity=Severity.ANOMALY,
                code="COMMAND_BODY_ON_SAFE_METHOD",
                detail=f"{method} carries a body of {len(str(body))} chars",
                simulation_id=sim_id,
            )
        )

    headers = subject.get("headers") or {}
    if isinstance(headers, dict):
        declared = {k.lower(): v for k, v in headers.items()}
        if "content-length" in declared and body is not None:
            try:
                stated = int(declared["content-length"])
            except (TypeError, ValueError):
                stated = -1
            actual = len(str(body))
            if stated >= 0 and stated != actual:
                findings.append(
                    Finding(
                        layer="command_execution",
                        gate="L7",
                        severity=Severity.PATTERN,
                        code="COMMAND_LENGTH_MISMATCH",
                        detail=f"content-length {stated} but body is {actual}",
                        simulation_id=sim_id,
                    )
                )
    return findings


# --------------------------------------------------------------------------
# Layer registry
# --------------------------------------------------------------------------

#: Canonical declaration order, recovered from the v1.0 ``self.layers`` list.
CANONICAL_ORDER: Sequence[str] = (
    "foundational_axioms",
    "recursive_filtration",
    "lexicographical_scrub",
    "historical_context",
    "guardrail_enforcement",
    "recovery_audit",
    "command_execution",
)


def build_layers(history: Optional[HistoryWindow] = None) -> List[tuple]:
    """Return ``(name, callable)`` pairs in canonical declaration order."""
    history = history if history is not None else HistoryWindow()
    return [
        ("foundational_axioms", layer_foundational_axioms),
        ("recursive_filtration", layer_recursive_filtration),
        ("lexicographical_scrub", layer_lexicographical_scrub),
        ("historical_context", make_historical_context_layer(history)),
        ("guardrail_enforcement", layer_guardrail_enforcement),
        ("recovery_audit", layer_recovery_audit),
        ("command_execution", layer_command_execution),
    ]


def run_layer(
    name: str,
    fn: Callable[[Dict[str, Any], int], List[Finding]],
    subject: Dict[str, Any],
    sim_id: int,
) -> LayerResult:
    """Execute one layer, timing it and containing its failures.

    A layer that raises must not take the grind down with it; an engine that
    crashes on hostile input has failed the test it was running.
    """
    start = time.perf_counter()
    try:
        findings = fn(subject, sim_id)
    except Exception as exc:  # a layer fault is itself a MANDATE finding
        findings = [
            Finding(
                layer=name,
                gate=None,
                severity=Severity.MANDATE,
                code="LAYER_FAULT",
                detail=f"{type(exc).__name__}: {exc}",
                simulation_id=sim_id,
            )
        ]
    elapsed = (time.perf_counter() - start) * 1e6
    return LayerResult(
        layer=name, simulation_id=sim_id, findings=findings, elapsed_us=elapsed
    )
