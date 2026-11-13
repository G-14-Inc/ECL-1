"""Public schema scope and directly attributed component/report cases.

Synthetic report records below test schema shape only; they claim no execution.
Robert F. Tilley Jr.; G-14, Inc.
"""
import json
import sys
from pathlib import Path

import pytest
from referencing import Registry

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import coverage_denominator as coverage
from scripts import generate_repair_coverage_vectors as generated
from scripts.run_conformance import observed_for_vector, schema_environment
from ecl_verify.resources import extension_value_validators
from ecl_verify.schema import ecl_format_checker
from ecl_verify.schema_patterns import schema_validator
from ecl_verify.semantic import SemanticValidator, active_extension_versions, allocated_extension_versions, composable_extensions

COMPONENT = "https://externalcontrollayer.ai/ns/schema/component-implementation-report/1"
CASES = coverage.read(ROOT / "conformance/suites/repair-coverage/manifest.json")["vectors"]


@pytest.fixture(scope="module")
def environment():
    schemas, schema_registry = schema_environment(ROOT)
    entries = coverage.read(ROOT / "registries/extensions.json")["entries"]
    semantics = SemanticValidator((item["id"] for item in entries), extension_value_validators(entries),
        allocated_versions=allocated_extension_versions(entries), composable=composable_extensions(entries), active_versions=active_extension_versions(entries))
    return {"schemas": schemas, "schema_registry": schema_registry, "semantics": semantics}


@pytest.mark.parametrize("vector", CASES, ids=lambda row: row["id"])
def test_new_coverage_witnesses_have_exact_executable_results_and_attribution(vector, environment):
    actual = observed_for_vector(ROOT, vector, **environment)
    expected = [] if vector["expected"] == "pass" else [vector["expected_primary_id"], *vector["expected_secondary_ids"]]
    assert sorted(actual) == sorted(expected)
    units = {row["id"]: row for row in coverage.enumerate_units(ROOT, coverage.read(ROOT / coverage.DENOMINATOR))}
    attribution = coverage.attribution_for(ROOT)
    for claim in vector["covers"]:
        assert attribution.witnesses(units[claim], vector, coverage.read(ROOT / vector["path"])), claim


def test_schema_only_binding_shape_is_not_a_semantic_rule_witness():
    rule = {"applies_to": ["https://externalcontrollayer.ai/ns/schema/binding/mcp-gateway-exchange/1"]}
    for vector in CASES:
        if vector["stage"] == "protocol":
            assert not coverage.positive_rule_witness(rule, vector)
    for path, content in generated.build(ROOT).items():
        assert (ROOT / path).read_bytes() == content


def test_public_schema_scope_is_a_complete_disjoint_partition():
    denominator = coverage.read(ROOT / coverage.DENOMINATOR)
    coverage.validate_scope(denominator, coverage.schemas_on_disk(ROOT))
    assert COMPONENT in denominator["included_schemas"]
    exclusions = {row["schema_id"]: row["justification"] for row in denominator["excluded_schemas"]}
    for name in ("cross-implementation-report", "external-vector-raw-result"):
        assert "test_public_review_denominator.py" in exclusions[f"https://externalcontrollayer.ai/ns/schema/{name}/3"]


def test_every_component_schema_unit_has_attributed_positive_and_negative_cases():
    schema = coverage.read(ROOT / "schemas/ecl-component-implementation-report-v1.schema.json")
    units = {row["id"]: row for row in coverage.schema_units(COMPONENT, schema)}
    found = {key: set() for key in units}
    vectors = coverage.read(ROOT / "conformance/suites/repair-contracts/manifest.json")["vectors"]
    attribution = coverage.attribution_for(ROOT)
    for vector in vectors:
        for claim in vector["covers"]:
            assert attribution.witnesses(units[claim], vector, coverage.read(ROOT / vector["path"])), (vector["id"], claim)
            found[claim].add(vector["expected"])
    assert all(sides == {"pass", "fail"} for sides in found.values()), found


def report_fixture(kind):
    row = {
        "id": "synthetic-report-schema-case", "suite": "synthetic-report-schema",
        "artifact_sha256": "ab" * 32, "expected": "pass", "status": "met",
        "observed_primary_id": None, "observed_secondary_ids": [],
        "observed_verdict": "verified", "observed_effects": [],
        "observed_unresolved_predecessor_ids": [],
        "observed_canonical_sha256": "cd" * 32,
        "observed_scope": {"established": ["bindings"], "not_established": [], "reasons": {},
                           "checks": {"bindings": {"checks": ["schema"], "objects": [0]}}},
    }
    if kind == "external-vector-raw-result":
        return {"schema_version": "ecl_external_vector_raw_result_v3", "implementation_revision": "synthetic", "result": row}, row
    report = coverage.read(ROOT / "conformance/report-template-v3.json")
    row["raw_result_sha256"] = "ef" * 32
    report.update(decision="pass", vector_results=[row])
    report["suite"]["vector_count"] = 1
    return report, row


@pytest.mark.parametrize("kind", ["cross-implementation-report", "external-vector-raw-result"])
@pytest.mark.parametrize("case", ["complete", "unknown-observation", "duplicate-check", "duplicate-object", "unsupported-with-observation", "missing-primary", "secondary-without-primary"])
def test_excluded_v3_metadata_schemas_accept_complete_shape_and_refuse_bad_shape(kind, case):
    report, row = report_fixture(kind)
    schema = coverage.read(ROOT / f"schemas/ecl-{kind}-v3.schema.json")
    validator = schema_validator(schema, registry=Registry(), format_checker=ecl_format_checker())
    assert validator.is_valid(report)
    if case == "unknown-observation":
        row["unregistered_observation"] = True
    elif case == "duplicate-check":
        row["observed_scope"]["checks"]["bindings"]["checks"] *= 2
    elif case == "duplicate-object":
        row["observed_scope"]["checks"]["bindings"]["objects"] *= 2
    elif case == "unsupported-with-observation":
        row.update(status="unsupported", unsupported_capability="evidence-bundle-verification")
    elif case == "missing-primary":
        del row["observed_primary_id"]
    elif case == "secondary-without-primary":
        row["observed_secondary_ids"] = ["ecl.error.schema-invalid.v1"]
    assert validator.is_valid(report) is (case == "complete")
