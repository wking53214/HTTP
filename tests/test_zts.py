"""Zero Trust Stack gates, fail-fast ordering, and the benchmark."""

import pytest

from http_protocol.bench import benchmark_orderings, build_corpus, format_report
from http_protocol.zts import (
    FAIL_FAST_ORDER,
    GATES,
    NAIVE_ORDER,
    evaluate,
    requires_capstone,
)

CLEAN = "The subsystem rejects malformed payloads at the perimeter."


class TestGates:
    def test_clean_text_passes_every_gate(self):
        result = evaluate(CLEAN)
        assert result.passed
        assert result.gates_evaluated == len(FAIL_FAST_ORDER)

    @pytest.mark.parametrize(
        "text,gate",
        [
            ("I think this holds", "G6"),
            ("basically the system works", "G3"),
            ("an excellent design", "G5"),
            ("this is guaranteed secure", "G2"),
        ],
    )
    def test_each_gate_catches_its_own_class(self, text, gate):
        result = evaluate(text, order=(gate,), short_circuit=True)
        assert not result.passed
        assert result.rejected_by.gate == gate

    def test_axiomatic_base_consults_supplied_axioms(self):
        ctx = {"axioms": {"the cache is durable": False}}
        result = evaluate("the cache is durable", ctx, order=("G1",))
        assert not result.passed

    def test_historical_anchor_detects_near_duplicates(self):
        ctx = {"history": [CLEAN]}
        assert not evaluate(CLEAN, ctx, order=("G4",)).passed

    def test_capstone_is_never_evaluated_automatically(self):
        """G7 is an out-of-band human handshake by design."""
        assert GATES["G7"][1] is None
        result = evaluate(CLEAN, order=("G1", "G7"))
        assert all(o.gate != "G7" for o in result.outcomes)

    def test_passing_the_chain_still_requires_the_capstone(self):
        assert requires_capstone(evaluate(CLEAN)) is True


class TestOrdering:
    def test_both_orderings_contain_the_same_six_gates(self):
        assert set(NAIVE_ORDER) == set(FAIL_FAST_ORDER)
        assert len(NAIVE_ORDER) == len(FAIL_FAST_ORDER) == 6

    def test_neither_ordering_includes_the_capstone(self):
        assert "G7" not in NAIVE_ORDER and "G7" not in FAIL_FAST_ORDER

    def test_ordering_does_not_change_the_accept_decision(self):
        """Reordering is an optimisation; it must not change outcomes."""
        corpus = build_corpus(size=120, seed=7)
        for text in corpus:
            a = evaluate(text, order=NAIVE_ORDER)
            b = evaluate(text, order=FAIL_FAST_ORDER)
            assert a.passed == b.passed, text

    def test_fail_fast_short_circuits_earlier(self):
        text = "I think this is an excellent and guaranteed secure design"
        fast = evaluate(text, order=FAIL_FAST_ORDER)
        naive = evaluate(text, order=NAIVE_ORDER)
        assert not fast.passed and not naive.passed
        assert fast.gates_evaluated <= naive.gates_evaluated

    def test_short_circuit_disabled_evaluates_every_gate(self):
        result = evaluate("I think so", order=FAIL_FAST_ORDER, short_circuit=False)
        assert result.gates_evaluated == len(FAIL_FAST_ORDER)
        assert not result.passed


class TestBenchmark:
    def test_benchmark_reports_both_orderings(self):
        results = benchmark_orderings(size=60, seed=1, repeats=1)
        assert set(results) == {"naive", "fail_fast"}
        for b in results.values():
            assert b.samples == 60
            assert b.mean_us > 0

    def test_fail_fast_evaluates_fewer_gates_on_average(self):
        """The mechanism behind the archival latency claim.

        Gate-count is asserted rather than wall-clock, because timing on a
        shared runner is noisy and the mechanism is what the claim is about.
        """
        results = benchmark_orderings(size=400, reject_rate=0.5, seed=2, repeats=1)
        assert (
            results["fail_fast"].mean_gates_evaluated
            < results["naive"].mean_gates_evaluated
        )

    def test_report_states_the_archival_claim_and_the_measurement(self):
        text = format_report(benchmark_orderings(size=60, seed=1, repeats=1))
        assert "214ms" in text and "88%" in text
        assert "latency reduction" in text

    def test_corpus_reject_rate_is_respected(self):
        clean_only = build_corpus(size=100, reject_rate=0.0, seed=1)
        assert all(evaluate(t).passed for t in clean_only)
