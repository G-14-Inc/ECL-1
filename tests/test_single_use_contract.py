"""Supported authority domain at direct APIs and the signed evidence boundary.

Signing uses only the deterministic public corpus fixture keys. These checks do
not exercise a running gateway, transactional effect store or OAuth server.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ecl_verify.binding import (
    BindingError,
    check_authority_event_binding,
    check_event_binding,
    check_response_binding,
)
from ecl_verify.bundle_verification import (
    _Entry,
    _check_use_counts,
    report_to_json,
    verify_bundle,
)
from ecl_verify.canonical import canonicalize, object_digest
from ecl_verify.integrity import signing_input
from ecl_verify.trust import TrustPolicy


ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "conformance/suites/evidence-bundle"
REQUEST_ERROR = "ecl.error.request-binding-invalid.v1"
EVENT_ERROR = "ecl.error.decision-binding-invalid.v1"


def _fixture():
    bundle = json.loads((SUITE / "bundle-valid-succeeded.json").read_bytes())
    payloads = [json.loads(base64.b64decode(e["payload"])) for e in bundle["envelopes"]]
    return bundle, payloads


def _refresh(payloads):
    by_id = {p.get("message_id", p.get("object_id")): p for p in payloads}
    authorities = {
        p["authorization"]["authorization_id"]: p["authorization"]
        for p in payloads if "authorization" in p
    }
    for _ in range(len(payloads) + 1):
        changed = False
        for payload in payloads:
            references = list(payload["workflow"].get("causal_predecessors", []))
            references += [payload["event"][m] for m in ("request", "decision", "authority")
                           if m in payload.get("event", {})]
            for reference in references:
                key = reference.get("id", reference.get("uri"))
                target = by_id.get(key, authorities.get(key))
                if target is not None and "digest" in reference:
                    digest = object_digest(target)
                    if reference["digest"]["value"] != digest:
                        reference["digest"]["value"] = digest
                        changed = True
        if not changed:
            return
    raise AssertionError("cyclic test fixture references")


def _assert_binding_error(code, call):
    with pytest.raises(BindingError) as caught:
        call()
    assert caught.value.code == code


@pytest.mark.parametrize("request_limit,response_limit", [(None, None), (None, 1), (1, 1)])
def test_supported_single_use_representations(request_limit, response_limit):
    _, payloads = _fixture()
    request, response = payloads[:2]
    for target, limit in ((request["authority_request"], request_limit),
                          (response["authorization"], response_limit)):
        target.pop("max_uses", None)
        if limit is not None:
            target["max_uses"] = limit
    _refresh(payloads)
    check_response_binding(request, response)
    check_authority_event_binding(payloads[2], response=response)
    for event in payloads[3:]:
        check_event_binding(event, request=request, response=response)


def test_explicit_requested_one_still_requires_echo():
    _, payloads = _fixture()
    request, response = payloads[:2]
    request["authority_request"]["max_uses"] = 1
    response["authorization"].pop("max_uses")
    _refresh(payloads)
    _assert_binding_error(REQUEST_ERROR, lambda: check_response_binding(request, response))


@pytest.mark.parametrize("outcome", ["admit", "deny", "hold", "challenge"])
@pytest.mark.parametrize("policy", ["bounded_multi_use", "unregistered_policy"])
def test_response_binding_refuses_unsupported_request_even_without_admission(outcome, policy):
    _, payloads = _fixture()
    request, response = payloads[:2]
    request["authority_request"]["use_policy"] = policy
    response["outcome"] = outcome
    if outcome == "admit":
        response["authorization"]["use_policy"] = policy
    else:
        response.pop("authorization")
    _refresh(payloads)
    _assert_binding_error(REQUEST_ERROR, lambda: check_response_binding(request, response))


@pytest.mark.parametrize("outcome", ["admit", "deny"])
@pytest.mark.parametrize("limit", [0, -1, 2, True, False, None, "1", 1.0])
def test_request_limit_domain_precedes_other_binding_checks(outcome, limit):
    _, payloads = _fixture()
    request, response = payloads[:2]
    request["authority_request"]["max_uses"] = limit
    response["outcome"] = outcome
    # Deliberately leave the old request digest: the supported domain is checked first.
    _assert_binding_error(REQUEST_ERROR, lambda: check_response_binding(request, response))


@pytest.mark.parametrize("member,value", [
    ("use_policy", "bounded_multi_use"), ("use_policy", "unregistered_policy"),
    ("max_uses", 0), ("max_uses", 2), ("max_uses", True),
    ("max_uses", None), ("max_uses", "1"), ("max_uses", 1.0),
])
def test_admit_domain_precedes_audience_and_other_authority_checks(member, value):
    _, payloads = _fixture()
    request, response = payloads[:2]
    response["authorization"][member] = value
    response["authorization"]["audience"] = "urn:example:wrong-audience"
    _assert_binding_error(REQUEST_ERROR, lambda: check_response_binding(request, response))


@pytest.mark.parametrize("event_index", [3, 4])
@pytest.mark.parametrize("target", ["request", "authorization"])
def test_direct_execution_event_binding_refuses_reserved_policy(event_index, target):
    _, payloads = _fixture()
    request, response = payloads[:2]
    authority = request["authority_request"] if target == "request" else response["authorization"]
    authority["use_policy"] = "bounded_multi_use"
    _refresh(payloads)
    _assert_binding_error(EVENT_ERROR, lambda: check_event_binding(
        payloads[event_index], request=request, response=response))


@pytest.mark.parametrize("member,value", [
    ("use_policy", "bounded_multi_use"), ("max_uses", 2), ("max_uses", True),
])
def test_direct_authority_event_binding_refuses_unsupported_authority(member, value):
    _, payloads = _fixture()
    response = payloads[1]
    response["authorization"][member] = value
    _refresh(payloads)
    _assert_binding_error(EVENT_ERROR, lambda: check_authority_event_binding(
        payloads[2], response=response))


@pytest.mark.parametrize("limit", [None, 2])
def test_consumption_analysis_never_treats_reserved_policy_as_unlimited(limit):
    _, payloads = _fixture()
    response, event = payloads[1:3]
    response["authorization"]["use_policy"] = "bounded_multi_use"
    response["authorization"].pop("max_uses", None)
    if limit is not None:
        response["authorization"]["max_uses"] = limit
    findings = []
    entries = [_Entry(i, False, {}, p, None, frozenset()) for i, p in enumerate([event, response])]
    _check_use_counts([(entries[0], entries[1])], findings)
    assert any(f.startswith(EVENT_ERROR + ":") for f in findings), findings


def _signed_bundle(multi_use):
    bundle, payloads = _fixture()
    if multi_use:
        payloads[0]["authority_request"].update(use_policy="bounded_multi_use", max_uses=2)
        payloads[1]["authorization"].update(use_policy="bounded_multi_use", max_uses=2)
    _refresh(payloads)
    keys = {"urn:example:key:" + name: Ed25519PrivateKey.from_private_bytes(bytes(range(i, i + 32)))
            for name, i in {"bundle-agent": 0, "bundle-decision": 1, "bundle-ep": 2}.items()}
    for envelope, payload in zip(bundle["envelopes"], payloads):
        raw = canonicalize(payload)
        envelope["payload"] = base64.b64encode(raw).decode()
        envelope["payload_digest"]["value"] = hashlib.sha256(raw).hexdigest()
        for signature in envelope["signatures"]:
            signature["signature"] = base64.b64encode(keys[signature["key_id"]].sign(
                signing_input(envelope["payload_type"], raw))).decode()
    return bundle


@pytest.mark.parametrize("multi_use", [False, True])
def test_signed_bundle_authority_support_boundary(multi_use):
    policy = TrustPolicy.load((SUITE / "trust-policy.json").read_bytes())
    report = report_to_json(verify_bundle(_signed_bundle(multi_use), policy,
                                          now="2026-10-01T00:00:00Z"))
    assert report["verdict"] == ("invalid" if multi_use else "verified"), report
    if multi_use:
        assert report["findings"]


@pytest.mark.parametrize("name", [
    "bundle-invalid-single-use-consumed-twice.json",
    "bundle-invalid-single-use-release-without-consumption.json",
    "bundle-invalid-use-count-beyond-policy.json",
])
def test_existing_single_use_replay_and_consumption_failures_remain_invalid(name):
    policy = TrustPolicy.load((SUITE / "trust-policy.json").read_bytes())
    bundle = json.loads((SUITE / name).read_bytes())
    report = report_to_json(verify_bundle(bundle, policy, now="2026-10-01T00:00:00Z"))
    assert report["verdict"] == "invalid", report
    assert any(f.startswith(EVENT_ERROR + ":") for f in report["findings"]), report
