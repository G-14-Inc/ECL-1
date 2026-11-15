"""The approved request-expiry and admitted-continuation contracts, on signed histories."""
import base64
import copy
import json
from pathlib import Path

import pytest

from ecl_verify.binding import BindingError, check_response_binding
from ecl_verify.bundle_verification import report_to_json, verify_bundle
from ecl_verify.resources import validator_for
from ecl_verify.trust import TrustPolicy

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "conformance/suites/public-review-design-decisions/manifest.json").read_bytes())
HISTORICAL_IDS = {
    "bundle-invalid-continuation-second-of-one-challenge",
    "bundle-invalid-continuation-second-of-one-challenge-approval-absent",
}
HISTORICAL = [v for v in json.loads((ROOT / "conformance/suites/evidence-bundle/manifest.json").read_bytes())["vectors"] if v["id"] in HISTORICAL_IDS]
VECTORS = MANIFEST["vectors"] + HISTORICAL
REQUEST_ERROR = "ecl.error.request-binding-invalid.v1"


def payloads(vector):
    bundle = json.loads((ROOT / vector["path"]).read_bytes())
    return [json.loads(base64.b64decode(e["payload"])) for e in bundle["envelopes"]]


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["id"])
def test_signed_design_contract(vector):
    bundle = json.loads((ROOT / vector["path"]).read_bytes())
    policy = TrustPolicy.load((ROOT / vector["trust_policy_path"]).read_bytes())
    report = report_to_json(verify_bundle(bundle, policy, now=vector["evaluated_at"]))
    assert report["verdict"] == vector["expected_verdict"], report
    assert report["primary"] == vector.get("expected_primary_id"), report
    if vector["expected_verdict"] in ("verified", "incomplete"):
        assert report["findings"] == []
    else:
        assert len(report["findings"]) == 1, report
        assert report["findings"][0].startswith(vector["expected_primary_id"] + ":")
    if "approval-absent" in vector["id"] and vector["expected_verdict"] == "incomplete":
        assert "bindings" not in report["scope"]["established"]
        assert "causal-completeness" not in report["scope"]["established"]
        assert report["unresolved_predecessor_ids"]
    # These controls isolate the pair/history rule: every signed payload passes its own schema.
    for payload in payloads(vector):
        schema = "dcmp/2" if payload["protocol"] == "DCMP-2" else "ebmp/2"
        assert not list(validator_for("https://externalcontrollayer.ai/ns/schema/" + schema).iter_errors(payload))


@pytest.mark.parametrize("vector", [v for v in MANIFEST["vectors"] if v["id"].startswith("request-expiry-")], ids=lambda v: v["id"])
def test_pair_request_expiry(vector):
    request, response = payloads(vector)[:2]
    if vector["expected_verdict"] == "invalid":
        for skew in (0, 1):
            with pytest.raises(BindingError) as raised:
                check_response_binding(request, response, response_clock_skew_seconds=skew)
            assert raised.value.code == REQUEST_ERROR
            assert "evaluated_at" in str(raised.value)
    else:
        check_response_binding(request, response)


def test_request_expiry_preserves_first_failure_order():
    vector = next(v for v in MANIFEST["vectors"] if v["id"] == "request-expiry-admit-equal")
    request, response = payloads(vector)[:2]
    response["authorization"]["audience"] = "urn:example:wrong-audience"
    variants = []
    bad_digest = copy.deepcopy(response)
    bad_digest["workflow"]["causal_predecessors"][0]["digest"]["value"] = "f" * 64
    variants.append((bad_digest, "ecl.error.digest-mismatch.v1", "digest"))
    early = copy.deepcopy(response)
    early["issued_at"] = "2026-09-29T09:59:59.999999999Z"
    variants.append((early, REQUEST_ERROR, "issued_at"))
    variants.append((response, REQUEST_ERROR, "evaluated_at"))
    unexpired = copy.deepcopy(response)
    unexpired["evaluated_at"] = "2026-09-29T10:00:00.099999999Z"
    variants.append((unexpired, "ecl.error.audience-mismatch.v1", "audience"))
    for answer, code, fragment in variants:
        with pytest.raises(BindingError) as raised:
            check_response_binding(request, answer)
        assert raised.value.code == code
        assert fragment in str(raised.value)


def test_request_expiry_manifest_is_well_formed():
    assert not list(validator_for("https://externalcontrollayer.ai/ns/schema/conformance-vector-manifest/3").iter_errors(MANIFEST))


def test_response_audience_failure_precedes_scope_failure():
    # DCMP-2 section 8 orders audience before scope after the request binding.
    vector = next(v for v in MANIFEST["vectors"] if v["id"] == "request-expiry-admit-equal")
    request, response = payloads(vector)[:2]
    response["evaluated_at"] = "2026-09-29T10:00:00.099999999Z"
    response["authorization"]["audience"] = "urn:example:wrong-audience"
    response["authorization"]["scope_digest"]["value"] = "f" * 64
    with pytest.raises(BindingError) as raised:
        check_response_binding(request, response)
    assert raised.value.code == "ecl.error.audience-mismatch.v1"
    response["authorization"]["audience"] = request["authority_request"]["audience"]
    with pytest.raises(BindingError) as raised:
        check_response_binding(request, response)
    assert raised.value.code == "ecl.error.scope-mismatch.v1"
