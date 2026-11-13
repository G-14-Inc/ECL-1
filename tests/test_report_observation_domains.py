"""Active finding allocation and meaningful effect identities in replay reports.

Synthetic reports test binding rules; they do not claim corpus execution.
Robert F. Tilley Jr.; G-14, Inc.
"""
import json
import pytest
from test_external_report_v3 import bound, row_for
from test_external_report_identifiers import report_version, failing_row
from scripts.run_conformance import scope_matches
from scripts.external_report_v3 import observations_match

@pytest.mark.parametrize("status", ["deprecated", "reserved", "retired"])
@pytest.mark.parametrize("registry,identifier", [
    ("semantic-rules", "ecl.rule.decision-basis-one-way.v1"),
    ("error-codes", "ecl.error.schema-invalid.v1"),
])
@pytest.mark.parametrize("truthful", [False, True])
def test_inactive_findings_cannot_be_met(report_version, tmp_path, status, registry, identifier, truthful):
    report, bind, check = report_version
    path = tmp_path / "corpus/registries" / (registry + ".json")
    value = json.loads(path.read_bytes())
    next(row for row in value["entries"] if row["id"] == identifier)["status"] = status
    path.write_text(json.dumps(value))
    row = failing_row(report)
    row["observed_secondary_ids"] = [identifier]
    if truthful: row["status"] = "not-met"; report["decision"] = "fail"
    bind()
    if truthful:
        result = check(); assert result["decision"] == "verified-report-integrity" and result["replay_decision"] == "fail"
        assert row["id"] in result["not_met_vectors"]
    else:
        with pytest.raises(ValueError, match="registered finding identifiers"): check()

@pytest.mark.parametrize("text", [" ", "\t\n", "\x85", "\u00a0", "\u1680", "\u2000\u200a", "\u2028\u2029", "\u202f\u205f\u3000"])
@pytest.mark.parametrize("truthful", [False, True])
def test_blank_extra_effect_is_retained_only_as_not_met(bound, text, truthful):
    report, bind, check = bound; row = row_for(report, "observed_effects")
    row["observed_effects"].append({"action_id": text, "level": "none"})
    if truthful: row["status"] = "not-met"; report["decision"] = "fail"
    bind()
    if truthful:
        assert check()["not_met_vectors"] == [row["id"]]
        assert row["observed_effects"][-1]["action_id"] == text
    else:
        with pytest.raises(ValueError, match="status does not match"): check()

@pytest.mark.parametrize("text,met", [("", False), (" ", False), ("\x85", False), ("\u00a0", False),
    ("\u2000\u2028\u3000", False), ("custom-token", True), (" token ", True), ("\ufeff", True), ("\x1c", True)])
def test_effect_identity_rule_matches_runner_and_report(text, met):
    effects = [{"action_id": "control", "level": "none"}]
    vector = {"id": "effect-domain", "expected": "pass", "expected_effects": effects}
    actual = effects + [{"action_id": text, "level": "none"}]
    assert scope_matches(vector, {"effects": actual}) is met
    assert observations_match({"id": vector["id"], "status": "met", "observed_effects": actual}, vector) is met


def test_no_effect_expectation_does_not_invent_one():
    assert scope_matches({"id": "no-effects"}, None)


def test_empty_effect_expectation_still_checks_retained_action_names():
    vector = {"id": "no-named-effects", "expected": "pass", "expected_effects": []}
    actual = [{"action_id": "   ", "level": "none"}]
    assert not scope_matches(vector, {"effects": actual})
    assert not observations_match({"id": vector["id"], "status": "met", "observed_effects": actual}, vector)
    assert scope_matches(vector, {"effects": []})
