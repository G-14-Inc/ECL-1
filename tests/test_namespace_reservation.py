"""XR1-017 reservation comparison preserves exact identifiers and private namespaces."""
import copy
import json
from pathlib import Path

import pytest

from ecl_verify.resources import object_findings, validator_for
from ecl_verify.schema import reserved_extension_namespace

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "tests/fixtures/namespace-reservation-cases.json").read_text())
REQUEST = json.loads((ROOT / "tests/fixtures/extension-consumer-cases/request-control.json").read_text())
SCHEMA = validator_for("https://externalcontrollayer.ai/ns/schema/dcmp/2")


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
@pytest.mark.parametrize("critical", [False, True], ids=["noncritical", "critical"])
def test_namespace_reservation(case, critical):
    request = copy.deepcopy(REQUEST)
    request["extensions"] = [{"id": case["identifier"], "version": 1,
                              "critical": critical, "value": {"grant_authority": True}}]
    before = copy.deepcopy(request)
    assert reserved_extension_namespace(case["identifier"]) is case["reserved"]
    assert SCHEMA.is_valid(request) is not case["reserved"]
    expected = set()
    if case["reserved"]:
        expected.update({"ecl.error.schema-invalid.v1", "ecl.rule.extension-namespace-allocated.v1"})
    if critical:
        expected.add("ecl.rule.unknown-critical-extension-rejected.v1")
    assert {finding.rule_id for finding in object_findings(request)} == expected
    assert request == before
