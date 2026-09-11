"""Regression tests pinning the documented defects of the archival v1.0 engine.

Every claim in ``KNOWN_LIMITATIONS`` is asserted here against the preserved
source, so the documentation cannot drift away from the artifact it describes.
"""

import pytest

from http_protocol.engine import grind
from http_protocol.legacy import (
    KNOWN_LIMITATIONS,
    HTTP7x70IntegrityEngine,
    compare_engines,
)
from http_protocol.models import Verdict

ARCHIVAL_CLEAN = {
    "method": "GET",
    "path": "/api/v1/data",
    "headers": {"User-Agent": "RedTeam-7x70-Probe"},
    "body": "",
}

ARCHIVAL_HOSTILE = {
    "method": "POST",
    "path": "/login",
    "headers": {"Content-Type": "application/json"},
    "body": '{"user": "admin", "cmd": "eval(base64_decode(...))"}',
}


class TestArchivalBehaviourPreserved:
    def test_clean_request_succeeds(self):
        result = HTTP7x70IntegrityEngine().process_request(
            dict(ARCHIVAL_CLEAN), verbose=False
        )
        assert result["status"] == "SUCCESS"

    def test_blocked_path_is_structurally_unreachable(self):
        """The decisive v1.0 defect.

        On the second anomaly the engine replaces the payload with a SHA-256
        digest, destroying the evidence. A third anomaly can then never be
        found, so the counter freezes at 2 and the BLOCKED branch -- which
        requires 3 -- is unreachable for any input whose second anomaly
        triggers the hash.

        The consequence is that the engine returns SUCCESS on its own
        hostile demonstration request.
        """
        engine = HTTP7x70IntegrityEngine()
        result = engine.process_request(dict(ARCHIVAL_HOSTILE), verbose=False)
        assert result["status"] == "SUCCESS"
        assert engine.anomalies == 2

    def test_engine_is_blinded_by_its_own_filter(self):
        """Even a payload that is nothing but attack strings passes."""
        engine = HTTP7x70IntegrityEngine()
        result = engine.process_request(
            {"method": "POST", "path": "/x", "headers": {}, "body": "script script script"},
            verbose=False,
        )
        assert result["status"] == "SUCCESS"
        assert engine.anomalies == 2


class TestDocumentedLimitations:
    @pytest.mark.parametrize(
        "body",
        [
            "name' UNION SELECT password FROM users--",
            "../../../../etc/passwd",
            "; rm -rf /",
            "${jndi:ldap://attacker/x}",
            "__import__('os').system('id')",
        ],
    )
    def test_v1_misses_attacks_that_v2_blocks(self, body):
        subject = {"method": "POST", "path": "/x", "headers": {}, "body": body}
        assert (
            HTTP7x70IntegrityEngine().process_request(dict(subject), verbose=False)[
                "status"
            ]
            == "SUCCESS"
        )
        assert grind(subject).verdict is Verdict.BLOCKED

    def test_script_matches_inside_ordinary_words(self):
        """'subscription' and 'description' both contain 'script'."""
        engine = HTTP7x70IntegrityEngine()
        engine.process_request(
            {
                "method": "POST",
                "path": "/items",
                "headers": {},
                "body": '{"description": "a subscription"}',
            },
            verbose=False,
        )
        assert engine.anomalies > 0, "benign words counted as attacks"

    def test_all_layers_share_one_check(self):
        """Seven layer names, one behaviour: the layer argument is ignored."""
        engine = HTTP7x70IntegrityEngine()
        verdicts = {
            engine.verify_truth(layer, 1, "clean payload") for layer in engine.layers
        }
        assert verdicts == {True}, "all seven layers agree because all seven are one"

    def test_recursive_filter_destroys_rather_than_filters(self):
        engine = HTTP7x70IntegrityEngine()
        filtered = engine.recursive_filter("payload with eval( inside")
        assert "eval" not in filtered
        assert len(filtered) == 64, "output is a SHA-256 digest, not a payload"

    def test_syntactic_scrub_defeats_nothing(self):
        engine = HTTP7x70IntegrityEngine()
        assert "eval(" in engine.syntactic_scrub("  EVAL( x ) ")

    def test_limitations_list_is_populated(self):
        assert len(KNOWN_LIMITATIONS) >= 9
        assert all(isinstance(item, str) and item for item in KNOWN_LIMITATIONS)


class TestComparison:
    def test_compare_reports_both_engines(self):
        result = compare_engines(ARCHIVAL_HOSTILE)
        assert result["v1"]["status"] == "SUCCESS"
        assert result["v2"]["status"] == "BLOCKED"
        assert result["v2"]["distinct_findings"] >= 1
        assert result["v1"]["distinct_findings"] == 0

    def test_v2_finds_more_than_one_distinct_defect_across_a_corpus(self):
        """The 490 evaluations must be capable of more than one bit."""
        subjects = [
            {"method": "GET", "path": "/admin/users", "headers": {}, "body": ""},
            {"method": "POST", "path": "/x", "headers": {}, "body": "eval(1)"},
            {"method": "FOO", "path": "rel/path", "headers": {}, "body": ""},
        ]
        distinct = set()
        for s in subjects:
            for f in grind(s).findings:
                distinct.add((f.layer, f.code))
        assert len(distinct) >= 4
