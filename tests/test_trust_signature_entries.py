"""IE1-034 per-signature time and TP1-006 current attestation dependency regressions."""
import json
from pathlib import Path

import pytest

from ecl_verify.bundle_verification import report_to_json, verify_bundle
from ecl_verify.trust import TrustPolicy

CASES = json.loads((Path(__file__).resolve().parent / "fixtures/trust-signature-entry.json").read_bytes())


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_signature_entry_times_and_attestation_policy(case):
    policy = TrustPolicy.load(json.dumps(case["policy"]).encode())
    report = report_to_json(verify_bundle(case["bundle"], policy, now=case["now"]))
    expected = case["expected"]
    assert (report["verdict"], report["primary"]) == (expected["verdict"], expected["primary"])
    for dependency in expected["dependencies"]:
        matches = [d for d in report["trust_dependencies"]
                   if d["index"] == dependency["index"] and d["role"] == dependency["role"]]
        actual = matches[dependency["occurrence"]]
        for key, value in dependency.items():
            if key != "occurrence":
                assert actual[key] == value, (case["id"], dependency, actual)
