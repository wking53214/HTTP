"""CLI surface: exit codes and output shape."""

import json

import pytest

from http_protocol.cli import EXIT_BLOCKED, EXIT_PASS, EXIT_USAGE, main


@pytest.fixture
def subject_file(tmp_path):
    def _write(payload):
        p = tmp_path / "subject.json"
        p.write_text(json.dumps(payload))
        return str(p)

    return _write


CLEAN = {"method": "GET", "path": "/api/v1/data", "headers": {"User-Agent": "p"}, "body": ""}
HOSTILE = {"method": "POST", "path": "/x", "headers": {}, "body": "eval(1)"}


def test_clean_subject_exits_zero(subject_file, capsys):
    assert main(["grind", subject_file(CLEAN)]) == EXIT_PASS
    assert "PASS" in capsys.readouterr().out


def test_hostile_subject_exits_one(subject_file, capsys):
    assert main(["grind", subject_file(HOSTILE)]) == EXIT_BLOCKED
    assert "BLOCKED" in capsys.readouterr().out


def test_json_output_parses(subject_file, capsys):
    main(["grind", subject_file(HOSTILE), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "BLOCKED"
    assert "findings" in payload and "parity" in payload


def test_malformed_input_is_a_usage_error(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert main(["grind", str(bad)]) == EXIT_USAGE


def test_non_object_subject_is_a_usage_error(subject_file):
    assert main(["grind", subject_file(["a", "list"])]) == EXIT_USAGE


def test_compare_emits_both_engines(subject_file, capsys):
    main(["compare", subject_file(HOSTILE)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["v1"]["status"] == "SUCCESS"
    assert payload["v2"]["status"] == "BLOCKED"


def test_limitations_lists_every_documented_defect(capsys):
    from http_protocol.legacy import KNOWN_LIMITATIONS

    assert main(["limitations"]) == EXIT_PASS
    out = capsys.readouterr().out
    assert out.count("\n") >= len(KNOWN_LIMITATIONS)


def test_bench_runs(capsys):
    assert main(["bench", "--size", "40", "--repeats", "1"]) == EXIT_PASS
    assert "fail-fast order" in capsys.readouterr().out
