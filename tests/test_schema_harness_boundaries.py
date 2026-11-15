"""Schema dispatch and report-boundary regressions.

Robert F. Tilley Jr.; G-14, Inc.
"""
from copy import deepcopy
import json
from pathlib import Path

import pytest
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from ecl_verify.resources import schema_is_valid, registry_document, extension_value_validators
from ecl_verify.schema import ecl_format_checker
from ecl_verify.schema_patterns import schema_validator, validation_schema
from ecl_verify.semantic import SemanticValidator, active_extension_versions, allocated_extension_versions, extension_applicability
from scripts.run_conformance import scope_matches
from test_external_report_v3 import bound

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "tests/fixtures/schema-boundaries.json").read_text())


@pytest.fixture(scope="module")
def semantics():
    entries = registry_document("extensions")["entries"]
    return SemanticValidator([e["id"] for e in entries], extension_value_validators(entries),
        active_versions=active_extension_versions(entries), allocated_versions=allocated_extension_versions(entries),
        applicability=extension_applicability(entries))


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_typed_dispatch_and_reserved_namespace(case, semantics):
    if case["schema"]:
        assert schema_is_valid(case["schema"], case["value"]) is case["expected_schema"]
    assert sorted({f.rule_id for f in semantics.validate(case["value"])}) == case["expected_rules"]


@pytest.mark.parametrize("terminator", ["\n", "\r", "\u2028", "\u2029"])
def test_bound_negative_observation_still_has_a_valid_digest_shape(bound, terminator):
    report, bind, check = bound
    assert check()["replay_decision"] == "pass"
    row = next(r for r in report["vector_results"] if "observed_canonical_sha256" in r and r["expected"] == "fail")
    row["observed_canonical_sha256"] = "0" * 64 + terminator
    bind()
    with pytest.raises(ValueError, match="cross-implementation-report/3"):
        check()


@pytest.mark.parametrize("reported,expected", [([], False), (["urn:p1"], True),
    (["urn:p1", "urn:p1"], False), (["urn:p2", "urn:p1"], False), (None, False), ([{}], False)])
def test_unresolved_predecessors_are_a_distinct_typed_set(reported, expected):
    assert scope_matches({"expected_unresolved_predecessor_ids": ["urn:p1"]},
                         {"unresolved_predecessor_ids": reported}) is expected


@pytest.mark.parametrize("name", ["default", "const", "enum", "examples"])
def test_schema_positions_and_annotation_data_remain_distinct(name):
    literal = {"pattern": "^[0-9]+$", "$schema": "https://json-schema.org/draft/2020-12/schema"}
    child = {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object",
             "properties": {name: {"$schema": "https://json-schema.org/draft/2020-12/schema",
                                    "type": "string", "pattern": "^[0-9]+$"}},
             "default": literal, "examples": [literal]}
    original = deepcopy(child)
    copied = validation_schema(child)
    assert copied["default"] == literal and copied["examples"] == [literal]
    resources = Registry().with_resource("urn:example:child", Resource.from_contents(copied, default_specification=DRAFT202012))
    validator = schema_validator({"$ref": "urn:example:child"}, registry=resources, format_checker=ecl_format_checker())
    assert validator.is_valid({name: "1"})
    assert not validator.is_valid({name: "1\n"})
    assert child == original


@pytest.mark.parametrize("name,valid", [("x", True), ("x\n", False), ("x\r", False),
    ("x\u2028", False), ("x\u2029", False), ("y", False)])
def test_pattern_properties_and_additional_properties_share_ecma_patterns(name, valid):
    value = {"type": "object", "patternProperties": {"^x$": {"const": 1}}, "additionalProperties": False}
    validator = schema_validator(value, registry=Registry(), format_checker=ecl_format_checker())
    assert validator.is_valid({name: 1}) is valid
    assert not validator.is_valid({"x": 2})


def test_duplicate_object_id_does_not_imply_a_state_transition():
    from ecl_verify.bundle import analyze_bundle
    value = json.loads((ROOT / "conformance/vectors/bundles/invalid-duplicate-object-id.json").read_text())
    report = analyze_bundle(value["records"])
    assert {f.rule_id for f in report.findings} == {"ecl.rule.bundle-object-identifiers-unique.v1"}


@pytest.mark.parametrize("member,rule", [
    ('"duplicate":1,"duplicate":2', "ecl.rule.json-no-duplicate-members.v1"),
    ('"number":1.5', "ecl.rule.json-restricted-numbers.v1"),
    ('"text":"\\uffff"', "ecl.rule.json-strict-syntax.v1"),
])
def test_malformed_json_cannot_supply_an_optional_extension_declaration(tmp_path, member, rule):
    from scripts.shared_corpus import capability_of, carried_extensions
    artifact = tmp_path / "value.json"
    artifact.write_text('{"extensions":[{"id":"ecl.ext.decision-basis.v1"}],' + member + '}')
    assert carried_extensions(artifact) == set()
    vector = {"stage": "protocol", "path": "value.json", "expected": "fail",
              "expected_primary_id": rule, "expected_secondary_ids": []}
    assert capability_of(tmp_path, "boundary-probe", vector) == "strict-json"
    artifact.write_text('{"extensions":[{"id":"ecl.ext.decision-basis.v1"}]}')
    assert carried_extensions(artifact) == {"ecl.ext.decision-basis.v1"}
