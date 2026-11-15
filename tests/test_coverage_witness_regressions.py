"""Counterfactual coverage remains tied to the declared denominator and one refusal.

Robert F. Tilley Jr.; G-14, Inc.
"""
from pathlib import Path
import json
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts"), str(ROOT / "packages/ecl-verify/src")]
from scripts import coverage_denominator as coverage
from scripts.run_conformance import manifest_paths

TARGETS = {
    "otel-invalid-object-not-ecl",
    "dcmp-invalid-admit-use-policy-outside-enum",
    "dcmp-invalid-request-use-policy-outside-enum",
    "dcmp-valid-admit-single-use-explicit-one",
    "dcmp-valid-request-single-use-explicit-one",
    "single-use-request-maximum-two-refused",
    "single-use-request-boolean-maximum-refused",
    "single-use-admit-maximum-two-refused",
    "single-use-admit-boolean-maximum-refused",
}
VECTORS = [row for path in manifest_paths(ROOT) for row in coverage.read(path)["vectors"] if row["id"] in TARGETS]
assert {row["id"] for row in VECTORS} == TARGETS


@pytest.fixture(scope="module")
def environment():
    units = {row["id"]: row for row in coverage.enumerate_units(ROOT, coverage.read(ROOT / coverage.DENOMINATOR))}
    return units, coverage.attribution_for(ROOT)


@pytest.mark.parametrize("vector", VECTORS, ids=lambda row: row["id"])
def test_every_declared_witness_names_a_real_decisive_unit(vector, environment):
    units, attribution = environment
    value = coverage.read(ROOT / vector["path"])
    assert vector["covers"]
    for identifier in vector["covers"]:
        assert identifier in units, identifier
        assert attribution.witnesses(units[identifier], vector, value), identifier


@pytest.mark.parametrize("kind,member", [("request", "authority_request"), ("admit", "authorization")])
@pytest.mark.parametrize("case,expected_value", [("maximum-two-refused", 2), ("boolean-maximum-refused", True)])
def test_maximum_controls_still_test_the_original_invalid_values(environment, kind, member, case, expected_value):
    _, attribution = environment
    vector = next(row for row in VECTORS if row["id"] == "single-use-" + kind + "-" + case)
    value = coverage.read(ROOT / vector["path"])
    actual = value[member]["max_uses"]
    assert type(actual) is type(expected_value) and actual == expected_value
    assert value[member]["use_policy"] == "single_use"
    assert "DCMP2-050" in vector["requirement_ids"] and "DCMP2-050" in vector["negates"]
    assert not attribution.valid(vector["schema"], value)


def test_otel_negative_retains_its_required_matching_after_snapshot():
    vector = next(row for row in VECTORS if row["id"] == "otel-invalid-object-not-ecl")
    value = coverage.read(ROOT / vector["path"])
    assert value["object"] == value["evidence_after"] == {"protocol": "DCMP-2", "message_type": "decision_response"}
    assert vector["expected_primary_id"] == "ecl.error.schema-invalid.v1"
    assert vector["negates"] == ["OE1-009"]
