"""Offline verification checks and read-only metadata for signing."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

ED25519_SUITE = "ecl.sig.ed25519.v1"

P256_SUITE = "ecl.sig.ecdsa-p256-sha256.v1"

_PAYLOAD_TYPES = {
    "DCMP-2": "application/vnd.ecl.dcmp+json",
    "EBMP-2": "application/vnd.ecl.ebmp+json",
}

TIME_ATTESTATION_TYPE = "application/vnd.ecl.time-attestation+json"

TIME_ATTESTATION_VERSION = "ecl_time_attestation_v1"


def payload_type_for(value: Mapping[str, Any]) -> str:
    """The media type that `integrity.verify_envelope` requires for this ECL object.

    A DCMP-2 or EBMP-2 object has its protocol's type, and a time attestation (`schema_version`
    `ecl_time_attestation_v1`, without `protocol`) has `TIME_ATTESTATION_TYPE`. Raises ValueError
    for anything that is not a mapping, and for any other object.
    """
    if not isinstance(value, Mapping):
        raise ValueError("an ECL object must be a mapping")
    if "protocol" not in value and value.get("schema_version") == TIME_ATTESTATION_VERSION:
        return TIME_ATTESTATION_TYPE
    protocol = value.get("protocol")
    if not isinstance(protocol, str) or protocol not in _PAYLOAD_TYPES:
        raise ValueError("protocol must be 'DCMP-2' or 'EBMP-2'")
    return _PAYLOAD_TYPES[protocol]
