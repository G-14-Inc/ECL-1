"""A simulated records workflow, using only public ECL formats and verifier APIs.

All keys, times and source assertions are teaching fixtures. This process has
no administrative separation, durable use ledger or production credentials.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ecl_verify.canonical import canonicalize
from ecl_verify.integrity import signing_input

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "conformance/fixtures/evidence"


def digest(value: Any) -> dict[str, str]:
    return {
        "algorithm": "ecl.digest.sha-256.v1",
        "value": hashlib.sha256(canonicalize(value)).hexdigest(),
    }


@dataclass(frozen=True)
class Permit:
    identifier: int
    action_digest: str
    expires_at: int


class Workflow:
    """Demonstrate guards around an in-memory effect, without a deployment claim."""

    def __init__(self) -> None:
        self.records = {"r-1": {"status": "open"}}
        self.proof_available = True
        self.proof_expires_at = 10
        self._issued: dict[int, Permit] = {}
        self._used: set[int] = set()

    def decide(
        self, action: dict[str, Any], *, now: int = 0, approved_digest: str | None = None
    ) -> tuple[str, Permit | None]:
        if not self.proof_available or now >= self.proof_expires_at:
            return "deny", None
        if set(action) != {"record_id", "patch"}:
            return "deny", None
        patch = action["patch"]
        if action["record_id"] != "r-1" or type(patch) is not dict or set(patch) != {"status"}:
            return "deny", None
        if patch["status"] not in ("closed", "archived"):
            return "deny", None
        action_digest = digest(action)["value"]
        if patch["status"] == "archived" and approved_digest != action_digest:
            return "hold", None
        permit = Permit(len(self._issued) + 1, action_digest, now + 5)
        self._issued[permit.identifier] = permit
        return "admit", permit

    def release(self, action: dict[str, Any], permit: Permit | None, *, now: int = 1) -> bool:
        if permit is None or self._issued.get(permit.identifier) is not permit:
            return False
        if permit.identifier in self._used or digest(action)["value"] != permit.action_digest:
            return False
        if now >= permit.expires_at or not self.proof_available or now >= self.proof_expires_at:
            return False
        self._used.add(permit.identifier)
        self.records[action["record_id"]] = copy.deepcopy(action["patch"])
        return True


def rewrite(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, dict):
        return {key: rewrite(item, replacements) for key, item in value.items()}
    if isinstance(value, list):
        return [rewrite(item, replacements) for item in value]
    return replacements.get(value, value) if isinstance(value, str) else value


def evidence(action: dict[str, Any], *, admitted: bool, name: str) -> dict[str, Any]:
    """Instantiate published wire examples with new bindings and published test keys.

    No private implementation is imported. The fixture policy and decision-input
    assertions remain synthetic and are not independent proof of our simulation.
    """
    template = json.loads(
        (FIXTURES / ("succeeded.json" if admitted else "denied.json")).read_text()
    )
    objects = [json.loads(base64.b64decode(item["payload"])) for item in template["envelopes"]]
    request, response = objects[:2]
    replacements: dict[str, str] = {}
    for index, value in enumerate(objects):
        for key in ("message_id", "object_id", "decision_id"):
            if key in value:
                replacements[value[key]] = f"urn:example:bounded:{name}:{key}:{index}"
    replacements[request["action"]["action_id"]] = f"urn:example:bounded:{name}:action"
    replacements[request["workflow"]["workflow_id"]] = f"urn:example:bounded:{name}:workflow"
    replacements[request["workflow"]["root_trace_id"]] = f"urn:example:bounded:{name}:trace"
    if admitted:
        replacements[response["authorization"]["authorization_id"]] = (
            f"urn:example:bounded:{name}:authority"
        )
    for value in objects:
        event = value.get("event", {})
        if "attempt_id" in event:
            replacements[event["attempt_id"]] = f"urn:example:bounded:{name}:attempt"
    request["action"]["parameters"] = copy.deepcopy(action)
    request["action"]["parameters_digest"] = digest(action)
    envelopes = []
    for original, source in zip(template["envelopes"], objects, strict=True):
        value = rewrite(source, replacements)
        if value.get("message_type") == "decision_response" and admitted:
            old = source["authorization"]
            value["authorization"]["scope_digest"] = digest(
                {"request_id": objects[0]["message_id"], "action": objects[0]["action"]}
            )
            # The request above has already been replaced and stored below.
            replacements[digest(old)["value"]] = digest(value["authorization"])["value"]
        if value.get("event", {}).get("state") == "succeeded":
            value["event"]["side_effects"] = [
                {"uri": "urn:example:bounded:record:r-1", "digest": digest(action["patch"])}
            ]
        body = canonicalize(value)
        signer = original["signatures"][0]["key_id"]
        offset = {
            "urn:example:key:bundle-agent": 0,
            "urn:example:key:bundle-decision": 1,
            "urn:example:key:bundle-ep": 2,
        }[signer]
        signing_key = Ed25519PrivateKey.from_private_bytes(bytes(range(offset, offset + 32)))
        envelopes.append(
            {
                "envelope_version": original["envelope_version"],
                "payload_type": original["payload_type"],
                "payload": base64.b64encode(body).decode("ascii"),
                "payload_digest": digest(value),
                "signatures": [
                    {
                        "key_id": signer,
                        "suite_id": "ecl.sig.ed25519.v1",
                        "signature": base64.b64encode(
                            signing_key.sign(signing_input(original["payload_type"], body))
                        ).decode("ascii"),
                    }
                ],
            }
        )
        replacements[original["payload_digest"]["value"]] = digest(value)["value"]
        if value.get("message_type") == "decision_request":
            objects[0] = value
    return {"schema_version": "ecl_evidence_bundle_v1", "envelopes": envelopes}


def exercise() -> dict[str, bool]:
    action = {"record_id": "r-1", "patch": {"status": "closed"}}
    flow = Workflow()
    outcome, permit = flow.decide(action)
    admitted = outcome == "admit" and flow.release(action, permit)
    replay = not flow.release(action, permit)
    flow = Workflow()
    _, permit = flow.decide(action)
    changed = {"record_id": "r-2", "patch": {"status": "closed"}}
    binding = not flow.release(changed, permit) and flow.records["r-1"]["status"] == "open"
    flow = Workflow()
    _, permit = flow.decide(action)
    expired = not flow.release(action, permit, now=5)
    flow = Workflow()
    _, permit = flow.decide(action)
    flow.proof_available = False
    outage = not flow.release(action, permit)
    flow = Workflow()
    _, permit = flow.decide(action)
    flow.proof_expires_at = 1
    stale = not flow.release(action, permit)
    archived = {"record_id": "r-1", "patch": {"status": "archived"}}
    flow = Workflow()
    held, _ = flow.decide(archived)
    approved, permit = flow.decide(archived, approved_digest=digest(archived)["value"])
    approval = held == "hold" and approved == "admit" and flow.release(archived, permit)
    denied, permit = Workflow().decide(changed)
    return {
        "admit": admitted,
        "deny": denied == "deny" and permit is None,
        "hold_then_bound_approval": approval,
        "replay_refused": replay,
        "changed_target_refused": binding,
        "expired_authority_refused": expired,
        "proof_outage_refused": outage,
        "stale_proof_refused": stale,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    results = exercise()
    action = {"record_id": "r-1", "patch": {"status": "closed"}}
    for name, admitted in (("admitted", True), ("denied", False)):
        (args.output / (name + ".json")).write_bytes(
            canonicalize(evidence(action, admitted=admitted, name=name)) + b"\n"
        )
    (args.output / "trust-policy.json").write_bytes((FIXTURES / "trust-policy.json").read_bytes())
    (args.output / "simulation-results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
