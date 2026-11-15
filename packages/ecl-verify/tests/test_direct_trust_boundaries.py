"""Direct verifier APIs retain the loaded-policy key domain and exact ECL instants."""
from __future__ import annotations

import base64
import copy
from dataclasses import replace
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ecl_verify.integrity import (
    AlgorithmRegistryChange, IntegrityError, KeyRevocation, signature_verifies,
    verify_envelope,
)
from ecl_verify.timing import EmergencyChannelDrill, TimingError
from ecl_verify.trust import TrustPolicy

ROOT = Path(__file__).resolve().parents[3]
KEY_ID = "urn:example:key:vector-ed"
BOUNDARY = "2026-11-10T12:00:00.000000500Z"


def fixture(name):
    return json.loads((ROOT / "conformance/suites" / name).read_text())


def setup():
    policy = TrustPolicy.load((ROOT / "conformance/suites/envelope/trust-policy.json").read_bytes())
    context = policy.verification_context(evaluated_at=BOUNDARY, time_policy="ecl.time.issued-at.v1")
    return fixture("envelope/envelope-valid-ed25519-signed.json"), policy.keyring(), context


@pytest.mark.parametrize("kind", ["valid_from", "valid_until", "revocation"])
@pytest.mark.parametrize("offset", [-1, 0, 1])
@pytest.mark.parametrize("own_time", [False, True])
def test_direct_key_interval_and_revocation_exact_boundaries(kind, offset, own_time):
    envelope, keys, context = setup()
    at = f"2026-11-10T12:00:00.{500 + offset:09d}Z"
    if kind == "revocation":
        context = replace(context, revocations=(KeyRevocation(KEY_ID, BOUNDARY, "synthetic test"),))
        expected = None if offset < 0 else "ecl.error.revoked.v1"
    else:
        keys[KEY_ID] = replace(keys[KEY_ID], **{kind: BOUNDARY})
        accepted = offset >= 0 if kind == "valid_from" else offset < 0
        expected = None if accepted else "ecl.error.expired.v1"
    context = replace(context, evaluated_at="2026-11-10T12:00:01Z" if own_time else at)
    kwargs = {"key_times": {KEY_ID: at}} if own_time else {}
    if expected is None:
        assert KEY_ID in verify_envelope(envelope, keys, context, **kwargs).valid_key_ids
    else:
        with pytest.raises(IntegrityError) as caught:
            verify_envelope(envelope, keys, context, **kwargs)
        assert caught.value.code == expected


@pytest.mark.parametrize("index", range(14))
def test_direct_key_rejects_every_policy_forbidden_small_order_encoding(index):
    envelope, keys, context = setup()
    policy = fixture(f"trust-policy/trust-policy-invalid-small-order-{index:02d}.json")
    raw = base64.b64decode(next(k["public_key"] for k in policy["keys"] if k["key_id"] == KEY_ID))
    keys[KEY_ID] = replace(keys[KEY_ID], public_key=Ed25519PublicKey.from_public_bytes(raw))
    forged = copy.deepcopy(envelope)
    forged["signatures"][0]["signature"] = base64.b64encode(b"\x01" + bytes(63)).decode()
    assert not signature_verifies(forged, forged["signatures"][0], keys[KEY_ID])
    with pytest.raises(IntegrityError) as caught:
        verify_envelope(forged, keys, context)
    assert caught.value.code == "ecl.error.signature-policy-invalid.v1"


@pytest.mark.parametrize("name,accepted", [
    ("envelope-valid-ed25519-signed", True), ("envelope-valid-mixed-order", True),
    ("envelope-invalid-mixed-order", False), ("envelope-invalid-torsion-r", False),
    ("envelope-invalid-noncanonical-s", False), ("envelope-valid-p256-low-s", True),
])
def test_supported_key_and_signature_domain_is_preserved(name, accepted):
    _, keys, _ = setup()
    envelope = fixture(f"envelope/{name}.json")
    entry = envelope["signatures"][0]
    assert signature_verifies(envelope, entry, keys[entry["key_id"]]) is accepted


@pytest.mark.parametrize("kind", ["interval", "architecture"])
@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_emergency_drill_exact_boundaries(kind, offset):
    at = f"2026-11-10T12:00:00.{500 + offset:09d}Z"
    drill = EmergencyChannelDrill(
        channel_id="urn:example:channel:boundary", interval_seconds=60,
        last_tested_at=BOUNDARY,
        evaluated_at=at.replace("12:00:00", "12:01:00") if kind == "interval" else "2026-11-10T12:00:01Z",
        material_architecture_change_at=at if kind == "architecture" else None,
        independence_verified=True,
    )
    if offset > 0:
        with pytest.raises(TimingError):
            drill.validate()
    else:
        drill.validate()


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_algorithm_transition_exact_boundary(offset):
    change = AlgorithmRegistryChange(
        suite_id="ecl.sig.ed25519.v1", status="deprecated", registry_version=2,
        security_rationale="synthetic boundary test", effective_at=BOUNDARY,
        affected_profiles=("test",), appeal_uri="urn:example:appeal",
        offline_snapshot_digest="a" * 64,
        replacement_suite_id="ecl.sig.ecdsa-p256-sha256.v1",
        transition_until=f"2026-11-10T12:00:00.{500 + offset:09d}Z",
    )
    if offset > 0:
        change.validate()
    else:
        with pytest.raises(IntegrityError):
            change.validate()
