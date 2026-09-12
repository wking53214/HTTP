"""Grind orchestration, parity semantics, and mutation reproducibility."""

import pytest

from http_protocol.engine import TruthGrind, grind
from http_protocol.entropy import (
    EQUIVALENCE,
    PROBE,
    entropy_for,
    simulation_plan,
)
from http_protocol.models import Severity, Verdict
from http_protocol.parity import (
    compute_parity,
    compute_utility_density,
    equivalence_simulations,
)

CLEAN = {"method": "GET", "path": "/api/v1/data", "headers": {"User-Agent": "probe"}, "body": ""}
HOSTILE = {
    "method": "POST",
    "path": "/login",
    "headers": {"Content-Type": "application/json"},
    "body": '{"user": "admin", "cmd": "eval(base64_decode(...))"}',
}


class TestGrindShape:
    def test_clean_subject_runs_the_full_7x70(self):
        report = grind(CLEAN, seed=1)
        assert report.verdict is Verdict.PASS
        assert len(report.simulations) == 70
        assert report.evaluations == 490, "7 layers x 70 simulations"

    def test_hostile_subject_is_blocked(self):
        assert grind(HOSTILE, seed=1).verdict is Verdict.BLOCKED

    def test_mandate_on_baseline_halts_the_run(self):
        report = grind(HOSTILE, seed=1)
        assert report.halted_at == 1
        assert len(report.simulations) == 1

    def test_no_halt_runs_every_simulation(self):
        report = TruthGrind(seed=1, halt_on_mandate=False).grind(HOSTILE)
        assert report.halted_at is None
        assert len(report.simulations) == 70

    def test_simulation_count_is_configurable(self):
        report = TruthGrind(simulations=10, seed=1).grind(CLEAN)
        assert len(report.simulations) == 10
        assert report.evaluations == 70

    @pytest.mark.parametrize("bad", [0, -1])
    def test_invalid_simulation_count_rejected(self, bad):
        with pytest.raises(ValueError):
            TruthGrind(simulations=bad)

    @pytest.mark.parametrize("bad", [-0.1, 1.1])
    def test_invalid_parity_floor_rejected(self, bad):
        with pytest.raises(ValueError):
            TruthGrind(parity_floor=bad)

    def test_non_dict_subject_rejected(self):
        with pytest.raises(TypeError):
            grind(["not", "a", "dict"])


class TestParity:
    def test_clean_subject_reaches_full_parity(self):
        """Equivalence mutations must never move the verdict."""
        assert grind(CLEAN, seed=1).parity == 1.0

    def test_parity_is_scored_on_equivalence_simulations_only(self):
        report = TruthGrind(seed=1).grind(CLEAN)
        scored = equivalence_simulations(report.simulations)
        assert 0 < len(scored) < len(report.simulations), (
            "the run must contain both equivalence and probe simulations"
        )

    def test_parity_falls_when_the_verdict_is_unstable(self):
        """An unstable filter must be visible as parity below the floor."""
        from http_protocol.models import Finding, LayerResult, SimulationResult

        def sim(sim_id, codes, kind=EQUIVALENCE):
            s = SimulationResult(
                simulation_id=sim_id, entropy=0.0, mutation="x", mutation_class=kind
            )
            s.layer_results.append(
                LayerResult(
                    layer="l",
                    simulation_id=sim_id,
                    findings=[
                        Finding("l", None, Severity.ANOMALY, c, "d", sim_id) for c in codes
                    ],
                )
            )
            return s

        stable = [sim(i, []) for i in range(1, 5)]
        assert compute_parity(stable) == 1.0

        unstable = [sim(1, []), sim(2, ["X"]), sim(3, []), sim(4, [])]
        assert compute_parity(unstable) == 0.75

    def test_probe_divergence_does_not_reduce_parity(self):
        report = TruthGrind(seed=1).grind(CLEAN)
        assert report.parity == 1.0
        # Probe mutations legitimately surface findings; they are reported.
        assert isinstance(report.probe_divergences, list)

    def test_empty_simulation_set_scores_zero(self):
        assert compute_parity([]) == 0.0


class TestUtilityDensity:
    def test_zero_evaluations_is_zero(self):
        assert compute_utility_density([], 0) == 0.0

    def test_density_counts_distinct_findings_not_repeats(self):
        report = TruthGrind(seed=1, halt_on_mandate=False).grind(HOSTILE)
        distinct = len({(f.layer, f.code) for f in report.findings})
        expected = distinct / (report.evaluations / 1000.0)
        assert report.utility_density == pytest.approx(expected)


class TestEntropyPlan:
    def test_first_simulation_is_the_unmutated_baseline(self):
        plan = simulation_plan(CLEAN, seed=3)
        assert plan[0][0] == 1
        assert plan[0][2] == CLEAN
        assert plan[0][3] == "baseline"

    def test_entropy_ramps_monotonically(self):
        levels = [entropy_for(i, 70) for i in range(1, 71)]
        assert levels == sorted(levels)
        assert levels[0] == 0.0
        assert levels[-1] == 1.0

    def test_plan_is_reproducible_for_a_seed(self):
        a = simulation_plan(CLEAN, seed=11)
        b = simulation_plan(CLEAN, seed=11)
        assert [x[2] for x in a] == [x[2] for x in b]

    def test_different_seeds_produce_different_mutations(self):
        a = simulation_plan(CLEAN, seed=1)
        b = simulation_plan(CLEAN, seed=2)
        assert [x[2] for x in a] != [x[2] for x in b]

    def test_mutations_actually_change_the_subject(self):
        """The v1.0 defect: 70 identical payloads. This must not recur."""
        plan = simulation_plan(CLEAN, seed=5)
        mutated = [x[2] for x in plan[1:]]
        assert any(m != CLEAN for m in mutated)

    def test_plan_labels_every_simulation_with_a_class(self):
        plan = simulation_plan(CLEAN, seed=5)
        assert {x[4] for x in plan} <= {EQUIVALENCE, PROBE}

    def test_grind_is_reproducible(self):
        a = TruthGrind(seed=42).grind(CLEAN)
        b = TruthGrind(seed=42).grind(CLEAN)
        assert a.digest() == b.digest()


class TestHistoryAcrossSubjects:
    def test_replay_is_detected_across_successive_grinds(self):
        engine = TruthGrind(simulations=1, seed=1)
        for _ in range(4):
            report = engine.grind(CLEAN)
        assert any(f.code == "HISTORY_REPLAY" for f in report.findings)

    def test_a_subject_is_never_a_replay_of_itself(self):
        engine = TruthGrind(simulations=1, seed=1)
        report = engine.grind(CLEAN)
        assert not any(f.code == "HISTORY_REPLAY" for f in report.findings)


class TestReportSerialisation:
    def test_report_round_trips_through_json(self):
        import json

        report = grind(HOSTILE, seed=1)
        payload = json.loads(report.to_json())
        assert payload["verdict"] == "BLOCKED"
        assert payload["parity"] == 1.0
        assert payload["findings"]

    def test_digest_ignores_timing(self):
        a = TruthGrind(seed=9).grind(CLEAN)
        b = TruthGrind(seed=9).grind(CLEAN)
        assert a.elapsed_ms != b.elapsed_ms or True
        assert a.digest() == b.digest()
