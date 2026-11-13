"""Executable shape checks for excluded repository metadata schemas.

Scenario shape checks do not replay a deployment. Robert F. Tilley Jr.; G-14, Inc.
"""
from copy import deepcopy
import json
from pathlib import Path
import re
import pytest

from ecl_verify.resources import validator_for

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads((ROOT / path).read_text())


def test_passing_bare_bundle_inputs_have_the_runner_shape():
    validator = validator_for("https://externalcontrollayer.ai/ns/schema/conformance-bundle-input/1")
    manifests = [ROOT / "conformance/manifest.json", *sorted((ROOT / "conformance/suites").glob("*/manifest.json"))]
    cases = [v for p in manifests for v in json.loads(p.read_text())["vectors"] if v["stage"] == "bundle" and v["expected"] == "pass"]
    assert cases
    for case in cases:
        value = read(case["path"])
        validator.validate(value)
        changed = deepcopy(value)
        del changed["records"]
        assert not validator.is_valid(changed)


def test_scenario_shapes_have_both_acceptance_and_refusal_controls():
    validator = validator_for("https://externalcontrollayer.ai/ns/schema/incident-scenario/1")
    paths = sorted((ROOT / "conformance/scenarios").glob("*.json"))
    assert paths
    for path in paths:
        value = json.loads(path.read_text())
        validator.validate(value)
        changed = deepcopy(value)
        changed["schema_version"] = "unknown"
        assert not validator.is_valid(changed)


def test_public_review_template_shape_and_disposition_domain():
    validator = validator_for("https://externalcontrollayer.ai/ns/schema/review-disposition-log/1")
    value = read("governance/review-disposition-log-template.json")
    validator.validate(value)
    changed = deepcopy(value)
    changed["comments"][0]["disposition"]["category"] = "ignored"
    assert not validator.is_valid(changed)


def test_named_metadata_test_evidence_is_present():
    value = read("conformance/coverage-denominator.json")
    for row in value["excluded_schemas"]:
        for path in re.findall(r"tests/[A-Za-z0-9_/-]+\.py", row["justification"]):
            assert (ROOT / path).is_file(), (row["schema_id"], path)


@pytest.mark.parametrize("schema,paths", [
    ("registry/2", [p.relative_to(ROOT).as_posix() for p in sorted((ROOT / "registries").glob("*.json"))
        if json.loads(p.read_text()).get("schema_version") == "ecl_registry_v2"]),
    ("requirement-registry/2", ["registries/requirements-compiled.json"]),
    ("evaluation-implementation-map/2", ["conformance/evaluation-implementation-map.json"]),
    ("requirement-evaluation-catalog/2", ["conformance/requirement-evaluations.json"]),
    ("conformance-vector-manifest/3", ["conformance/manifest.json", *[p.relative_to(ROOT).as_posix()
        for p in sorted((ROOT / "conformance/suites").glob("*/manifest.json"))]]),
])
def test_persisted_metadata_instances_and_discriminator_refusal(schema, paths):
    assert paths
    validator = validator_for("https://externalcontrollayer.ai/ns/schema/" + schema)
    for path in paths:
        value = read(path)
        validator.validate(value)
        changed = deepcopy(value)
        changed["schema_version"] = "unknown"
        assert not validator.is_valid(changed), path
