"""ACS completeness witnesses retain decisive schema attribution.

Robert F. Tilley Jr.; G-14, Inc.
"""
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts"), str(ROOT / "packages/ecl-verify/src")]
from scripts import coverage_denominator as coverage
from ecl_verify.bindings import binding_findings

NAMES = {
    "acs-failed-signed-paired-control",
    "acs-failed-signed-before-submission-control",
    "acs-failed-signed-without-params",
    "acs-failed-signed-without-digest",
    "acs-decided-result-control",
    "acs-decided-without-result",
    "acs-decided-without-result-and-dependencies",
}
MANIFEST = coverage.read(ROOT / "conformance/suites/repair-coverage/manifest.json")
VECTORS = [row for row in MANIFEST["vectors"] if row["id"] in {"repair-coverage-" + name for name in NAMES}]
assert len(VECTORS) == len(NAMES)


@pytest.fixture(scope="module")
def environment():
    units = {row["id"]: row for row in coverage.enumerate_units(ROOT, coverage.read(ROOT / coverage.DENOMINATOR))}
    return units, coverage.attribution_for(ROOT)


@pytest.mark.parametrize("vector", VECTORS, ids=lambda row: row["id"])
def test_acs_witness_attributes_one_conditional_without_relaxing_other_rules(vector, environment):
    units, attribution = environment
    value = coverage.read(ROOT / vector["path"])
    assert vector["stage"] == "binding"
    assert len(vector["covers"]) == 1
    assert attribution.valid(vector["schema"], value) == (vector["expected"] == "pass")
    assert attribution.witnesses(units[vector["covers"][0]], vector, value)
    if vector["expected"] == "pass":
        assert binding_findings(value) == []


def test_failed_signed_control_preserves_pre_submission_without_fabricated_params():
    row = next(row for row in VECTORS if row["id"].endswith("before-submission-control"))
    value = json.loads((ROOT / row["path"]).read_text())
    assert value["guardian"]["status"] == "failed"
    assert value["guardian"]["channel"] == "signed"
    assert "request_params" not in value["guardian"]
    assert "request_digest" not in value["guardian"]
    assert value["response"]["outcome"] == "deny"
    assert "release" not in value
