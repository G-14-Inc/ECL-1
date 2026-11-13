"""Immediate attestations share the bundle's pre-signature decoded-node budget."""
import base64
import hashlib
import json
from pathlib import Path

import pytest

from ecl_verify import integrity
from ecl_verify.bundle_verification import MAX_TOTAL_PAYLOAD_NODES, report_to_json, verify_bundle
from ecl_verify.canonical import canonicalize
from ecl_verify.trust import TrustPolicy

ROOT = Path(__file__).resolve().parents[3]
SUITE = ROOT / "conformance/suites/evidence-bundle"
RESOURCE = "ecl.error.resource-limit-exceeded.v1"
INVALID_TIME = "ecl.error.trusted-time-invalid.v1"


def fixture():
    return (json.loads((SUITE / "bundle-valid-trusted-time.json").read_bytes()),
            TrustPolicy.load((SUITE / "trust-policy-time-authority.json").read_bytes()))


def decode(envelope):
    return json.loads(base64.b64decode(envelope["payload"]))


def replace_payload(envelope, payload):
    raw = canonicalize(payload)
    envelope["payload"] = base64.b64encode(raw).decode()
    envelope["payload_digest"]["value"] = hashlib.sha256(raw).hexdigest()


def nodes(value):
    return 1 + sum(map(nodes, value.values())) if isinstance(value, dict) else 1 + sum(map(nodes, value)) if isinstance(value, list) else 1


def total(bundle):
    return sum(nodes(decode(envelope)) + sum(nodes(decode(entry["attestation"])) for entry in envelope.get("countersignatures", []))
               for envelope in bundle["envelopes"] + bundle.get("observations", []))


def result(bundle, policy):
    return report_to_json(verify_bundle(bundle, policy, now="2026-10-01T00:00:00Z"))


def test_valid_trusted_time_control():
    assert result(*fixture())["verdict"] == "verified"


def test_attestation_depth_refusal_preserves_earlier_payload_check(monkeypatch):
    bundle, policy = fixture()
    outer = bundle["envelopes"][0]
    outer["payload_digest"]["value"] = "0" * 64
    attestation = outer["countersignatures"][0]["attestation"]
    raw = b"[" * 257 + b"0" + b"]" * 257
    attestation["payload"] = base64.b64encode(raw).decode()
    attestation["payload_digest"]["value"] = hashlib.sha256(raw).hexdigest()
    def unexpected_crypto(**kwargs):
        raise AssertionError("signature work ran before the attestation depth limit")
    monkeypatch.setattr(integrity, "_verify_signature", unexpected_crypto)
    report = result(bundle, policy)
    assert report["primary"] == RESOURCE
    assert len(report["envelope_checks"]) == 1


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_attestation_shared_node_boundary(offset):
    bundle, policy = fixture()
    attestation = bundle["envelopes"][0]["countersignatures"][0]["attestation"]
    statement = decode(attestation)
    statement["padding"] = []
    replace_payload(attestation, statement)
    statement["padding"] = [0] * (MAX_TOTAL_PAYLOAD_NODES + offset - total(bundle))
    replace_payload(attestation, statement)
    assert total(bundle) == MAX_TOTAL_PAYLOAD_NODES + offset
    # Padding violates the inner schema; only exceeding the earlier parser budget changes
    # that historical refusal to a stage-2 resource refusal.
    assert result(bundle, policy)["primary"] == (RESOURCE if offset > 0 else INVALID_TIME)


@pytest.mark.parametrize("split,malformed_outer", [(False, False), (True, False), (False, True)])
def test_attestation_budget_stops_before_crypto(monkeypatch, split, malformed_outer):
    bundle, policy = fixture()
    for envelope in bundle["envelopes"][:2 if split else 1]:
        attestation = envelope["countersignatures"][0]["attestation"]
        statement = decode(attestation)
        statement["padding"] = [0] * (50000 if split else 100001)
        replace_payload(attestation, statement)
    if malformed_outer:
        bundle["envelopes"][0]["payload_digest"]["value"] = "0" * 64

    def unexpected_crypto(**kwargs):
        raise AssertionError("signature work ran before the shared payload budget")

    monkeypatch.setattr(integrity, "_verify_signature", unexpected_crypto)
    report = result(bundle, policy)
    assert report["primary"] == RESOURCE
    assert report["verdict"] == "invalid"


@pytest.mark.parametrize("registered", [False, True])
def test_only_registered_time_claim_supplies_future_instant(registered):
    bundle, policy = fixture()
    entry = bundle["envelopes"][0]["countersignatures"][0]
    statement = decode(entry["attestation"])
    statement["issued_at"] = "2099-01-01T00:00:00Z"
    replace_payload(entry["attestation"], statement)
    if not registered:
        entry["claim"] = "ecl.claim.unregistered.v1"
    assert result(bundle, policy)["primary"] == ("ecl.error.clock-regressed.v1" if registered else INVALID_TIME)


@pytest.mark.parametrize("size", [20000, 21848, 21852])
def test_failed_attestation_signature_keeps_ie1_034_classification(size):
    bundle, policy = fixture()
    bundle["envelopes"][0]["countersignatures"][0]["attestation"]["signatures"][0]["signature"] = "A" * size
    assert result(bundle, policy)["primary"] == INVALID_TIME
