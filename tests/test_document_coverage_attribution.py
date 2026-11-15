"""Coverage witnesses remain isolated when document contracts gain sibling guards.

Robert F. Tilley Jr.; G-14, Inc.
"""
from pathlib import Path
import copy
import json
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts"), str(ROOT / "packages/ecl-verify/src")]
from scripts import coverage_denominator as coverage
from scripts import generate_document_vectors as documents
from scripts import generate_work_intent_vectors as intents

PACKAGE = documents.PACKAGE
CONTEXT = "ecl.rule.work-intent-context-consistent.v1"
ASSESSMENT_ID = "assessment-invalid-finding-severity-outside-enum"


@pytest.fixture(scope="module")
def attribution():
    return coverage.attribution_for(ROOT)


def assessment_vector():
    generated = documents.build(ROOT)
    manifest = json.loads(generated[documents.SUITE / "manifest.json"])
    vector = next(row for row in manifest["vectors"] if row["id"] == ASSESSMENT_ID)
    return vector, json.loads(generated[Path(vector["path"])])


def test_assessment_severity_negative_is_caused_by_its_enum_alone(attribution):
    vector, value = assessment_vector()
    unit = next(row for row in coverage.schema_units(PACKAGE, coverage.read(ROOT / "schemas/ecl-assessment-package-v1.schema.json")) if row["id"] == documents.AP_SEVERITY)
    assert not attribution.valid(PACKAGE, value)
    assert attribution.witnesses(unit, vector, value)


def test_severity_positive_control_changes_only_the_unregistered_value(attribution):
    _, value = assessment_vector()
    invalid = [row for row in value["findings"] if row["severity"] == "high"]
    assert len(invalid) == 1
    invalid[0]["severity"] = "minor"
    assert attribution.valid(PACKAGE, value)


@pytest.mark.parametrize("severity,valid", [(None, False), ("observation", False), ("minor", True)])
def test_failed_checklist_still_requires_a_non_observation_finding(attribution, severity, valid):
    value = coverage.read(ROOT / documents.PACKAGE_EXAMPLE)
    assert any(row["result"] == "fail" for row in value["checklist"])
    value["findings"] = [] if severity is None else [{**copy.deepcopy(value["findings"][0]), "severity": severity}]
    assert attribution.valid(PACKAGE, value) is valid


@pytest.mark.parametrize("kind", ["both", "context", "reference"])
def test_schema_first_work_intent_keeps_secondary_without_claiming_primary_coverage(attribution, kind):
    generated, _ = intents.build(ROOT)
    manifest = json.loads(generated[Path("conformance/suites/work-intent-contract/manifest.json")])
    identifier = "work-intent-contract-parent-" + kind + "-no-cause"
    vector = next(row for row in manifest["vectors"] if row["id"] == identifier)
    assert vector["expected_primary_id"] == "ecl.error.schema-invalid.v1"
    assert vector["expected_secondary_ids"] == [CONTEXT]
    assert vector["requirement_ids"] == vector["negates"] == ["DW1-002"]
    assert CONTEXT not in vector["covers"]
    assert vector["covers"]
    units = {row["id"]: row for row in coverage.schema_units(documents.INTENT, coverage.read(ROOT / "schemas/ecl-work-intent-v1.schema.json"))}
    value = json.loads(generated[Path(vector["path"])])
    assert all(attribution.witnesses(units[item], vector, value) for item in vector["covers"])


@pytest.mark.parametrize("suffix", ["", "-reversed"])
def test_schema_first_safe_state_keeps_secondary_without_claiming_primary_coverage(suffix):
    generated, _ = intents.build(ROOT)
    manifest = json.loads(generated[Path("conformance/suites/safe-state-declaration-contract/manifest.json")])
    vector = next(row for row in manifest["vectors"] if row["id"] == "safe-state-declaration-contract-duplicate-identical" + suffix)
    assert vector["expected_primary_id"] == "ecl.error.schema-invalid.v1"
    assert vector["expected_secondary_ids"] == [intents.ACTION]
    assert vector["requirement_ids"] == vector["negates"] == ["TS1-016"]
    assert intents.ACTION not in vector["covers"]


@pytest.mark.parametrize("suite,rule", [("work-intent-contract", CONTEXT), ("safe-state-declaration-contract", intents.ACTION)])
def test_context_rules_retain_genuine_positive_and_decisive_negative_witnesses(suite, rule):
    generated, _ = intents.build(ROOT)
    vectors = json.loads(generated[Path("conformance/suites") / suite / "manifest.json"])["vectors"]
    assert any(row["expected"] == "pass" and rule in row["covers"] for row in vectors)
    assert any(row.get("expected_primary_id") == rule and rule in row["covers"] for row in vectors)


@pytest.mark.parametrize("generator", [documents, intents], ids=["documents", "work-intent"])
def test_document_generators_match_staged_artifacts(generator):
    generated = generator.build(ROOT)
    artifacts = generated[0] if isinstance(generated, tuple) else generated
    for path, content in artifacts.items():
        assert (ROOT / path).read_bytes() == content, path
