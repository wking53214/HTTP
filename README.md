# HTTP — the Hyper Truth Testing Protocol

A 7×70 adversarial validation harness. Seven distinct inspection layers run
across seventy variable-entropy micro-simulations — 490 evaluations — and
return a verdict, a measured parity score, and the findings that justify both.

Reconstructed from conversation archives. See [PROVENANCE.md](PROVENANCE.md)
for what was recovered verbatim, what was rebuilt, and why.

```
                    subject
                       │
        ┌──────────────▼───────────────┐
        │  70 seeded mutations         │   entropy ramps 0.0 → 1.0
        │  sim 1 = unmutated baseline  │   equivalence │ probe
        └──────────────┬───────────────┘
                       │
        ┌──────────────▼───────────────┐
        │  L1  foundational axioms     │  schema and ground truth
        │  L2  recursive filtration    │  obfuscation and nesting
        │  L3  lexicographical scrub   │  injection grammar, entropy
        │  L4  historical context      │  replay across a session
        │  L5  guardrail enforcement   │  size, scope, restricted paths
        │  L6  recovery audit          │  serialisation integrity
        │  L7  command execution       │  method and length consistency
        └──────────────┬───────────────┘
                       │
              verdict · parity · findings
```

## Install

```bash
pip install -e ".[dev]"
```

No runtime dependencies; the standard library only.

## Use

```bash
echo '{"method":"POST","path":"/login","headers":{},
       "body":"{\"cmd\":\"eval(base64_decode(x))\"}"}' | http-grind grind -
```

```
verdict          BLOCKED
parity           1.0000
utility density  666.67 distinct findings / 1000 evals
evaluations      3

distinct findings:
  [mandate] lexicographical_scrub/SCRUB_INJECTION (x1)
            code evaluation call detected
  [anomaly] recursive_filtration/FILTER_ENCODED_CONTENT (x1)
            encoded content present (base64-call)
```

Exit codes: `0` pass, `1` blocked, `2` degraded, `64` bad input — so a grind
drops into a pipeline.

```python
from http_protocol import TruthGrind

grinder = TruthGrind(seed=1)          # history persists across subjects
report = grinder.grind(subject)

report.verdict          # Verdict.PASS | BLOCKED | DEGRADED
report.parity           # measured, not asserted
report.findings         # layer, code, severity, evidence
report.to_json()
```

## The three verdicts

**PASS** — no mandate, and the verdict held across every semantics-preserving
mutation.

**BLOCKED** — a mandate finding, or a pattern finding on the unmutated
subject. The subject is implicated.

**DEGRADED** — parity fell below the floor. A mutation that *could not* have
changed the answer nonetheless did, so the filter contradicted itself and no
verdict it produced can be trusted. **The filter is implicated, not the
subject.** This is the verdict the archival engine had no way to express.

## Parity is measured here

The archives assert "1.0000 Parity" throughout and never define it as a
computation. The corpus's own retrospective is blunt about the consequence:
the figure was narrated by the model, and it was reported as achieved on
essentially every run. A constant that is always 1.0000 measures nothing.

Here it is a ratio over the seventy mutations:

```
parity = equivalence mutations agreeing with the baseline
         ─────────────────────────────────────────────────
                  equivalence mutations run
```

Mutations are split into two classes, and the split is what makes the number
mean something:

- **Equivalence** — padding whitespace, flipping method case, reordering
  headers, adding an inert header. These *cannot* change the safety answer.
  If the verdict moves, the filter is unstable, and that is a real defect.
- **Probe** — Unicode confusables, deep nesting. These *may* legitimately
  change the answer; they test whether the filter normalises before matching.
  Counting them against parity would report correct behaviour as a fault, so
  they are reported separately.

## The archival engine is preserved, and it is broken

`src/http_protocol/legacy.py` holds the recovered v1.0 engine verbatim. It is
kept because it is the historical artifact and the baseline this one is
measured against.

```bash
http-grind limitations        # the documented defects
http-grind compare subject.json
```

Running it surfaced a defect not previously recorded anywhere in the corpus:

> **The BLOCKED path is structurally unreachable.** On the second anomaly the
> engine replaces the payload with a SHA-256 digest. The digest contains
> neither `eval` nor `script`, so a third anomaly can never be found, the
> counter freezes at 2, and the `anomalies >= 3` branch never fires.

The engine therefore returns `SUCCESS` on its own hostile demonstration
request, and on a body consisting of nothing but the word `script` repeated.
Every documented defect is pinned by a regression test in
`tests/test_legacy.py`.

## The Zero Trust Stack

HTTP is the harness; the ZTS is its primary subject. Seven gates, recovered
from the corpus:

| | Gate | Cost |
|---|---|---|
| G1 | Axiomatic Base | dict lookup |
| G2 | Semantic Contamination Filter | token scan |
| G3 | Syntactic Breach Filter | regex |
| G4 | Historical Context Anchor | set overlap per prior entry |
| G5 | Sycophancy Neutralization Deck | token scan |
| G6 | Pronominal Purge Array | regex |
| G7 | The Architect's Capstone | **out-of-band, human** |

G7 is never evaluated automatically. The archives describe it as a manual
authorisation handshake, and a gate a program can satisfy on its own is not
one.

The recovered Fail-Fast ordering — `G6 → G3 → G1 → G2 → G5 → G4` — puts the
cheap, selective regex gates first:

```bash
http-grind bench
```

The archival claim was 214ms → 32ms, an 88% reduction. Measured here, the
direction reproduces (~20% latency, ~10% fewer gate evaluations) and the
magnitude does not. The mechanism is real; the figure was narrated. The test
suite asserts the mechanism rather than a wall-clock threshold, because
timing on a shared runner is noise.

## Tests

```bash
python -m pytest          # 102 tests
```

The suite enforces three properties the v1.0 engine violated: no two layers
may share a finding code, mutations must actually change the subject, and a
layer that raises becomes a MANDATE finding rather than a crash.

## Scope

This is a validation harness for structured request-like objects. It is not a
WAF, not a compliance instrument, and not a substitute for one. The archives
contain claims that these components were "independently marketable" and
constituted "the sole prerequisite tool for EU AI Act compliance"; the same
archives classify those claims as inflation with "Evidence Level: Low", and
no such claim is made here.
