"""Supported DCMP wire domain: one authorization permits one use."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from ecl_verify.resources import validator_for

ROOT = Path(__file__).resolve().parents[3]
DCMP = "https://externalcontrollayer.ai/ns/schema/dcmp/2"


def message(kind: str) -> tuple[dict, dict]:
    name = "valid-decision-request" if kind == "request" else "valid-decision-response-admit"
    value = json.loads((ROOT / f"conformance/vectors/dcmp-2/{name}.json").read_bytes())
    authority = value["authority_request" if kind == "request" else "authorization"]
    authority["use_policy"] = "single_use"
    return value, authority


@pytest.mark.parametrize("kind", ["request", "admit"])
def test_single_use_wire_accepts_absent_or_one_maximum(kind: str) -> None:
    value, authority = message(kind)
    validator = validator_for(DCMP)
    authority.pop("max_uses", None)
    assert validator.is_valid(value)
    authority["max_uses"] = 1
    assert validator.is_valid(value)


@pytest.mark.parametrize("kind", ["request", "admit"])
@pytest.mark.parametrize("policy", ["bounded_multi_use", "unlimited", "Single_Use", "", None, True])
def test_single_use_wire_refuses_unsupported_policy(kind: str, policy: object) -> None:
    value, authority = message(kind)
    authority.update(use_policy=policy, max_uses=1)
    assert not validator_for(DCMP).is_valid(value)


@pytest.mark.parametrize("kind", ["request", "admit"])
@pytest.mark.parametrize("maximum", [0, 2, 1_000_000, "1", True, False, None, 1.5, [], {}])
def test_single_use_wire_refuses_contradictory_maximum(kind: str, maximum: object) -> None:
    value, authority = message(kind)
    authority["max_uses"] = copy.deepcopy(maximum)
    assert not validator_for(DCMP).is_valid(value)


def test_historical_multi_use_allocation_is_reserved_not_supported() -> None:
    registry = json.loads((ROOT / "registries/operational-values.json").read_bytes())
    validator_for("https://externalcontrollayer.ai/ns/schema/registry/2").validate(registry)
    entries = {entry["id"]: entry for entry in registry["entries"]}
    historical = entries["ecl.authority-use.bounded-multi-use.v1"]
    assert historical["status"] == "reserved"
    assert historical["introduced_in"] == "1.0-rc.3"
    assert historical["attributes"]["wire_value"] == "bounded_multi_use"
    assert historical["attributes"]["supported"] is False
    assert entries["ecl.authority-use.single-use.v1"]["status"] == "active"
