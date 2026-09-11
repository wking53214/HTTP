"""Each layer must detect its own defect class and stay silent on others.

This is the property the v1.0 engine lacked: seven names sharing one check.
"""

import pytest

from http_protocol.layers import (
    HistoryWindow,
    build_layers,
    layer_command_execution,
    layer_foundational_axioms,
    layer_guardrail_enforcement,
    layer_lexicographical_scrub,
    layer_recursive_filtration,
    layer_recovery_audit,
    make_historical_context_layer,
    run_layer,
    shannon_entropy,
)
from http_protocol.models import Severity

CLEAN = {"method": "GET", "path": "/api/v1/data", "headers": {"User-Agent": "probe"}, "body": ""}


def codes(findings):
    return {f.code for f in findings}


class TestFoundationalAxioms:
    def test_clean_subject_passes(self):
        assert layer_foundational_axioms(CLEAN, 1) == []

    def test_missing_required_key_is_a_mandate(self):
        findings = layer_foundational_axioms({"method": "GET"}, 1)
        assert "AXIOM_MISSING_KEY" in codes(findings)
        assert findings[0].severity is Severity.MANDATE

    def test_unknown_method_flagged(self):
        findings = layer_foundational_axioms({"method": "FOO", "path": "/x"}, 1)
        assert "AXIOM_UNKNOWN_METHOD" in codes(findings)

    def test_relative_path_flagged(self):
        findings = layer_foundational_axioms({"method": "GET", "path": "api/x"}, 1)
        assert "AXIOM_RELATIVE_PATH" in codes(findings)


class TestRecursiveFiltration:
    def test_clean_subject_passes(self):
        assert layer_recursive_filtration(CLEAN, 1) == []

    def test_deep_nesting_flagged(self):
        nested = {"method": "GET", "path": "/x"}
        node = nested
        for _ in range(20):
            node["child"] = {}
            node = node["child"]
        assert "FILTER_EXCESSIVE_NESTING" in codes(layer_recursive_filtration(nested, 1))

    def test_layered_encoding_is_a_mandate(self):
        subject = {
            "method": "POST",
            "path": "/x",
            "body": "%41%42 \\u0041 &#x41; base64_decode(x)",
        }
        findings = layer_recursive_filtration(subject, 1)
        assert "FILTER_LAYERED_ENCODING" in codes(findings)
        assert any(f.severity is Severity.MANDATE for f in findings)


class TestLexicographicalScrub:
    def test_clean_subject_passes(self):
        assert layer_lexicographical_scrub(CLEAN, 1) == []

    @pytest.mark.parametrize(
        "body",
        [
            "eval(payload)",
            "<script>alert(1)</script>",
            "name' UNION SELECT password FROM users",
            "../../../../etc/hosts",
            "; rm -rf /",
            "__import__('os')",
            "${jndi:ldap://x}",
        ],
    )
    def test_injection_shapes_are_mandates(self, body):
        """Every shape here passes the v1.0 substring check untouched."""
        findings = layer_lexicographical_scrub(
            {"method": "POST", "path": "/x", "body": body}, 1
        )
        assert "SCRUB_INJECTION" in codes(findings), body
        assert any(f.severity is Severity.MANDATE for f in findings)

    def test_high_entropy_body_flagged(self):
        import random

        rng = random.Random(0)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        packed = "".join(rng.choice(alphabet) for _ in range(400))
        findings = layer_lexicographical_scrub(
            {"method": "POST", "path": "/x", "body": packed}, 1
        )
        assert "SCRUB_HIGH_ENTROPY" in codes(findings)

    def test_entropy_of_uniform_text_is_zero(self):
        assert shannon_entropy("aaaa") == 0.0
        assert shannon_entropy("") == 0.0


class TestHistoricalContext:
    def test_replay_detected_only_after_threshold(self):
        history = HistoryWindow()
        layer = make_historical_context_layer(history)
        import hashlib, json

        digest = hashlib.sha256(
            json.dumps(CLEAN, sort_keys=True, default=str).encode()
        ).hexdigest()

        assert layer(CLEAN, 1) == []
        for _ in range(3):
            history.observe(CLEAN["path"], digest)
        assert "HISTORY_REPLAY" in codes(layer(CLEAN, 1))

    def test_window_evicts_oldest(self):
        history = HistoryWindow(capacity=2)
        for i in range(5):
            history.observe(f"/p{i}", f"d{i}")
        assert history.digest_count("d0") == 0
        assert history.digest_count("d4") == 1


class TestGuardrailEnforcement:
    def test_clean_subject_passes(self):
        assert layer_guardrail_enforcement(CLEAN, 1) == []

    def test_oversize_subject_flagged(self):
        big = {"method": "POST", "path": "/x", "body": "a" * 600}
        assert "GUARD_OVERSIZE" in codes(layer_guardrail_enforcement(big, 1))

    def test_header_flood_flagged(self):
        subject = {"method": "GET", "path": "/x", "headers": {f"H{i}": "v" for i in range(50)}}
        assert "GUARD_HEADER_FLOOD" in codes(layer_guardrail_enforcement(subject, 1))

    @pytest.mark.parametrize("path", ["/admin/users", "/.env", "/.git/config", "/x/etc/passwd"])
    def test_restricted_paths_are_mandates(self, path):
        findings = layer_guardrail_enforcement({"method": "GET", "path": path}, 1)
        assert "GUARD_RESTRICTED_PATH" in codes(findings)
        assert any(f.severity is Severity.MANDATE for f in findings)


class TestRecoveryAudit:
    def test_serialisable_subject_passes(self):
        assert layer_recovery_audit(CLEAN, 1) == []


class TestCommandExecution:
    def test_clean_subject_passes(self):
        assert layer_command_execution(CLEAN, 1) == []

    def test_body_on_get_flagged(self):
        subject = {"method": "GET", "path": "/x", "body": "payload"}
        assert "COMMAND_BODY_ON_SAFE_METHOD" in codes(layer_command_execution(subject, 1))

    def test_content_length_mismatch_flagged(self):
        subject = {
            "method": "POST",
            "path": "/x",
            "headers": {"Content-Length": "999"},
            "body": "short",
        }
        assert "COMMAND_LENGTH_MISMATCH" in codes(layer_command_execution(subject, 1))


class TestLayerIsolation:
    def test_seven_layers_registered_in_canonical_order(self):
        from http_protocol.layers import CANONICAL_ORDER

        layers = build_layers()
        assert len(layers) == 7
        assert tuple(name for name, _ in layers) == tuple(CANONICAL_ORDER)

    def test_layers_raise_distinct_codes(self):
        """No two layers may share a finding code.

        Shared codes would mean shared behaviour, which is the v1.0 defect.
        """
        subjects = [
            {"method": "FOO"},
            {"method": "POST", "path": "/x", "body": "eval(x)"},
            {"method": "GET", "path": "/admin", "body": "y"},
            {"method": "POST", "path": "/x", "headers": {"Content-Length": "9"}, "body": "s"},
        ]
        owner = {}
        for subject in subjects:
            for name, fn in build_layers():
                for f in run_layer(name, fn, subject, 1).findings:
                    assert owner.setdefault(f.code, name) == name, (
                        f"code {f.code} raised by both {owner[f.code]} and {name}"
                    )

    def test_layer_exception_becomes_a_mandate_not_a_crash(self):
        def exploding(subject, sim_id):
            raise RuntimeError("boom")

        result = run_layer("exploding", exploding, CLEAN, 1)
        assert result.worst is Severity.MANDATE
        assert result.findings[0].code == "LAYER_FAULT"
