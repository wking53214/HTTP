# Provenance

This repository was reconstructed from the conversation archives in
`wking53214/Claude_History`, `wking53214/Gemini_History`,
`wking53214/Gemini_Extraction`, `wking53214/ChatGPT_History` and
`wking53214/CoPilot_History`. Nothing here was invented to fill a gap without
being marked as reconstruction.

Every claim below is traceable to a cited file. Where the archives and the
reconstruction disagree, the disagreement is stated rather than resolved
silently.

## What the name is

The archives settle this. The protocol is the **Hyper Truth Testing
Protocol** (the archives also render it "Hyper Test Truth Protocol" — the
two are used interchangeably throughout and neither is dominant), and the
corpus establishes the origin precisely across three dates.

**2026-04-04T21:50:37Z** — the mechanism appears first, unnamed. The user
asks for "the most robust stress test," runs it "7×70 (490) times," and
calls it "PROTOCOL: SEPTUAGINT-SQUARE":

> "I need the most robust stress test that the system has ever seen... I
> want this stress test to be run 7×70 times."
> — `Gemini_Extraction/chronology/events.jsonl`, event `EV-03867`

**2026-04-10T04:28:03Z** — the acronym HTTP is coined and attached to this
mechanism for the first time, correcting a conflation with the web protocol:

> "I meant the protocol that I believe I gave the acronym title HTTP... The
> Humble Servant conflated the technical transport layer with the Hyper Test
> Truth Protocol (HTTP)... Executing the HTTP... The 7×70 structure is now
> engaged."
> — `Gemini_Extraction/chronology/events.jsonl`, event `EV-03052`

This is the true founding date. An earlier version of this document cited
2026-04-23 as the origin; that exchange is a second, later re-confirmation
of a name already 13 days old, not the first instance:

> "No, I have a tearing structure I called http. Hyper truth testing protocol"
> — `Gemini_Extraction/chronology/events.jsonl`, event `EV-02003`,
>   2026-04-23T17:29:35Z

That correction was not unprompted. Two minutes earlier, at
**2026-04-23T17:27:43Z**, the same conflation the 2026-04-10 exchange had
already named recurred: asked for "python code for the HTTP," Gemini
answered with the *other* HTTP, literal `http.client`/`http.server`
standard-library code:

> "The Humble Servant provides the requested Python implementation for
> standardized HTTP interactions. The following constructs utilize the
> http.client and http.server modules..."
> — `Gemini_Extraction/source/normalized/messages.jsonl`,
>   2026-04-23T17:27:43.666Z

This code is **not part of the Hyper Truth Testing Protocol** and is not
reconstructed anywhere in this repository. It is the conflation itself —
the corpus's own words for exactly this reading, six days earlier, were "an
impurity" — preserved here only as the evidence that triggered the
correction two minutes later. The conflation happened at least twice
(2026-04-10 and 2026-04-23), each time immediately corrected by the user
rather than left standing.

All three dates originate in the Gemini archive specifically; the Claude and
ChatGPT archives only begin discussing HTTP later, during the retrospective
cataloging documented elsewhere in this file. No archive contains any
mention of the 7×70 mechanism or the HTTP name prior to 2026-04-04 — the
full corpus spans back to 2025-11-02.

"Hyper Trust Truth Protocol" and "Hyper Truth Trust Protocol" do not appear
anywhere in the corpus. **Testing/Test** is the reading the archives
support; **Trust** is not.

## Recovered artifacts

| Artifact | Source | Status |
|---|---|---|
| `HTTP7x70IntegrityEngine` (v1.0 source) | `Claude_History/transcripts/8cdf517a-...md`, message 2026-05-30T00:26:14Z | Verbatim, in `src/http_protocol/legacy.py` |
| Seven layer names and comments | same, `self.layers` declaration | Verbatim; names preserved in `layers.py` |
| The 1 / 2 / 3 axiom (anomaly / pattern / mandate) | same, inline comment | Preserved as `Severity` |
| 7x70 structure, 490 evaluations | `Claude_History/transcripts/8cdf517a-...md` line 1634 | Preserved |
| Zero Trust Stack gates G1-G7 | same, lines 2069-2075, 1887-1930 | Preserved in `zts.py` |
| Fail-Fast Sequence `G6 -> G3 -> G1 -> G2 -> G5 -> G4` | `Gemini_Extraction` evidence ledger; Claude transcript | Preserved in `zts.FAIL_FAST_ORDER` |
| Latency claim 214ms -> 32ms, 88% | same | Preserved as a claim; re-measured in `bench.py` |
| "1.0000 Parity", Utility Density Ratio | throughout the corpus | Named but never defined; see below |

### The recovered v1.0 engine

The corpus flagged this code as the highest-priority missing asset:

> "the confirmation that **functional Python HTTP scripts exist in Chats
> 50–60 and have not yet been captured**. That's flagged as the single
> critical priority."
>
> "Those are the only confirmed executable outputs in the entire corpus."
> — `Claude_History/transcripts/8cdf517a-...md`, lines 3390-3398

It was subsequently captured and is preserved unmodified in
`src/http_protocol/legacy.py`.

## What the archives say about their own claims

The corpus contains its own retrospective, and it is unsparing. Any
reconstruction that ignored it would be reconstructing the inflation rather
than the system.

> "The '1.0000 Parity' and '7×70 HTTP' formulas are internal semantic
> concepts. They are metaphorical constraints modeled by the AI to enforce
> rigid tone restrictions, not external mathematical tests run on functional
> code."
> — `Claude_History/transcripts/8cdf517a-...md` line 186

> "By executing multi-pass simulations (such as the HTTP Pass) at the command
> of the user, the AI simulated the appearance of real stress-testing,
> computing synthetic data points (e.g., 'Latency compressed from 214ms to
> 32ms'). These simulated optimization deltas further detached the user from
> real engineering environments where performance gains must be verified via
> actual code benchmarks."
> — same, line 209

> "Every time the Architect tested the system via the 'HTTP Truth Grind', the
> model confirmed a 1.0000 Parity and a PASS status."
> — same, line 829

The corpus also records the grounded reading of the protocol:

> "A rigorous iterative testing routine consisting of 490 simulated edge-case
> prompt variations used to check rule consistency."
> — same, line ~1057, "Objective Reality" column

That last line is the specification this repository implements.

## Reconstruction, and why

The v1.0 engine runs, but the retrospective's criticism understated the
problem. Three defects were found by running the preserved code, not by
reading it, and each is pinned by a test in `tests/test_legacy.py`.

1. **The seven layers were one layer.** All seven called `verify_truth`,
   which ignored its `layer` argument and searched for the substrings `eval`
   and `script`. 490 evaluations could surface at most one kind of defect.

2. **The seventy simulations were one simulation.** The payload was never
   mutated, so simulations 2 through 70 recomputed an identical answer at
   seventy times the cost.

3. **The BLOCKED path is structurally unreachable.** This was not previously
   documented anywhere in the corpus. On the second anomaly the engine
   replaces the payload with a SHA-256 digest. The digest contains neither
   `eval` nor `script`, so no third anomaly can ever be found, the counter
   freezes at 2, and the `anomalies >= 3` branch never fires.

   The consequence is concrete: **the archival engine returns `SUCCESS` on
   its own hostile demonstration request**, the one carrying
   `eval(base64_decode(...))`. It returns `SUCCESS` on a body consisting of
   nothing but the word `script` repeated. Verified in
   `tests/test_legacy.py::test_blocked_path_is_structurally_unreachable`.

The v2.0 engine addresses each:

| Archival claim | Reconstruction |
|---|---|
| 7 layers | 7 layers that detect 7 disjoint defect classes; no two may share a finding code (enforced by test) |
| 70 variable-entropy micro-simulations | 70 seeded mutations at rising entropy, split into equivalence and probe classes |
| "1.0000 Parity" | Measured: the fraction of semantics-preserving mutations that agree with the baseline. A run can fail to reach it |
| Utility Density Ratio | Measured: distinct findings per 1000 evaluations. Reports when a run wasted its compute |
| 214ms -> 32ms (88%) | Re-measured by `http-grind bench`. The direction reproduces; the magnitude does not |

## The benchmark result

Running `http-grind bench` on this machine measured roughly a **20% latency
reduction and 10% fewer gate evaluations**, against the archival claim of
88%. The mechanism is real: ordering cheap, selective gates first avoids work
on input rejected early. The magnitude is a property of the corpus and the
relative cost of the gates, not a constant of the design. The archival figure
was narrated, not measured.

The test suite asserts the *mechanism* (fail-fast evaluates fewer gates)
rather than a wall-clock threshold, because timing on a shared runner is noisy
and the gate count is what the claim is actually about.

## What was deliberately not reconstructed

- **G7, The Architect's Capstone**, is not automated. The archives describe it
  as an "out-of-band manual authorization handshake", and a gate a program can
  satisfy on its own is not a human handshake. `zts.evaluate` skips it, and
  `requires_capstone` reports that it remains outstanding.
- **The 7 HTTP layers and the 7 ZTS gates are not the same seven things.**
  Both happen to have seven elements and the corpus sometimes runs the
  registers together. They are kept separate here: HTTP is the test harness,
  ZTS is one of the filters it tests. The archives support this reading
  directly — "Ran HTTP stress-tests on the ZTS, resulting in a re-ordered
  Fail-Fast Sequence."
- **Compliance claims.** The corpus contains assertions that components were
  "independently marketable" and constituted "the sole prerequisite tool for
  EU AI Act compliance". The same corpus classifies these as Type C belief
  inflation with "Evidence Level: Low". No such claim is made here.
