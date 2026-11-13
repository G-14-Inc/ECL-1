"""Generate signed, synthetic controls for the approved DESIGN-05 and DESIGN-08 contracts.

Only public deterministic fixture keys are used. The released continuation-reuse
fixtures remain byte-for-byte intact; their expectation migration is separate.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/ecl-verify/src"))
from ecl_verify.canonical import canonicalize, object_digest
from ecl_verify.integrity import signing_input

SUITE = ROOT / "conformance/suites/evidence-bundle"
OUTPUT = ROOT / "conformance/suites/public-review-design-decisions"
REQUEST_ERROR = "ecl.error.request-binding-invalid.v1"
CONTINUATION_ERROR = "ecl.error.decision-binding-invalid.v1"
CLOSURE_ERROR = "ecl.error.causal-closure-incomplete.v1"
SEEDS = {"bundle-agent": 0, "bundle-decision": 1, "bundle-ep": 2,
         "bundle-observer": 3, "bundle-approval-service": 50}
KEYS = {"urn:example:key:" + name: Ed25519PrivateKey.from_private_bytes(bytes(range(start, start + 32)))
        for name, start in SEEDS.items()}


def load(name):
    bundle = json.loads((SUITE / (name + ".json")).read_bytes())
    envelopes = bundle["envelopes"] + bundle.get("observations", [])
    return bundle, [json.loads(base64.b64decode(e["payload"])) for e in envelopes]


def identifier(payload):
    return payload.get("message_id", payload.get("object_id"))


def signed(bundle, payloads):
    """Rebind every changed causal, decision and authority reference, then sign."""
    by_id = {identifier(p): p for p in payloads}
    authorities = {p["authorization"]["authorization_id"]: p["authorization"]
                   for p in payloads if "authorization" in p}
    for _ in range(len(payloads) + 1):
        changed = False
        for payload in payloads:
            references = list(payload["workflow"].get("causal_predecessors", []))
            event = payload.get("event", {})
            references.extend(event[name] for name in ("decision", "authority") if name in event)
            for reference in references:
                name = reference.get("id", reference.get("uri"))
                target = by_id.get(name, authorities.get(name))
                if target is not None and "digest" in reference:
                    digest = object_digest(target)
                    if reference["digest"]["value"] != digest:
                        reference["digest"]["value"] = digest
                        changed = True
        if not changed:
            break
    else:
        raise ValueError("Fixture causal rebinding did not converge")
    envelopes = bundle["envelopes"] + bundle.get("observations", [])
    assert len(envelopes) == len(payloads)
    for envelope, payload in zip(envelopes, payloads):
        raw = canonicalize(payload)
        envelope["payload"] = base64.b64encode(raw).decode()
        envelope["payload_digest"]["value"] = hashlib.sha256(raw).hexdigest()
        for entry in envelope["signatures"]:
            assert entry["suite_id"] == "ecl.sig.ed25519.v1"
            entry["signature"] = base64.b64encode(KEYS[entry["key_id"]].sign(signing_input(envelope["payload_type"], raw))).decode()
    return bundle


def expiry_case(outcome, boundary, issued_after=False):
    bundle, payloads = load("bundle-valid-succeeded")
    request, response = payloads[:2]
    request["expires_at"] = "2026-09-29T10:00:00." + {
        "before": "100000001", "equal": "100000000", "after": "099999999"
    }[boundary] + "Z"
    # The names describe evaluation relative to expiry, at one-nanosecond precision.
    if issued_after:
        response["issued_at"] = "2026-09-29T10:00:00.100000002Z"
        response["authorization"]["valid_from"] = response["issued_at"]
    if outcome != "admit":
        response["outcome"] = outcome
        if outcome == "challenge":
            response["challenge_id"] = "urn:example:challenge:request-expiry"
        response.pop("authorization")
        response["reasons"] = [{"code": "ecl.reason.native-policy-disposition.v1", "detail": "Synthetic refusal recorded at the request-expiry boundary", "retryable": False}]
        terminal = payloads[-1]
        terminal["event"].pop("authority")
        terminal["event"].pop("side_effects")
        terminal["event"]["state"] = {"deny": "denied", "hold": "held", "challenge": "challenged"}[outcome]
        terminal["workflow"]["causal_predecessors"] = [{"id": response["message_id"], "relation": "ecl.relation.follows.v1", "digest": {"algorithm": "ecl.digest.sha-256.v1", "value": object_digest(response)}}]
        bundle["envelopes"] = [bundle["envelopes"][i] for i in (0, 1, 4)]
        payloads = [request, response, terminal]
    return bundle, payloads


def chronological_reuse(outcome="deny", missing_approval=False, reverse=False):
    bundle, payloads = load("bundle-invalid-continuation-second-of-one-challenge")
    request, response, terminal = payloads[9:12]
    request["issued_at"] = "2026-09-29T10:00:00.500000Z"
    request["workflow"]["causal_predecessors"].append({
        "id": identifier(payloads[8]), "relation": "ecl.relation.follows.v1",
        "digest": {"algorithm": "ecl.digest.sha-256.v1", "value": object_digest(payloads[8])}})
    response["issued_at"] = response["evaluated_at"] = "2026-09-29T10:00:00.600000Z"
    response["expires_at"] = "2026-09-29T10:00:15.600000Z"
    response["outcome"] = outcome
    if outcome == "challenge":
        response["challenge_id"] = "urn:example:challenge:continuation-reuse-second"
    terminal["observed_at"] = "2026-09-29T10:00:00.700000Z"
    if outcome != "admit":
        terminal["event"]["state"] = {"deny": "denied", "challenge": "challenged"}[outcome]
    else:
        response["reasons"] = []
        response["extensions"] = copy.deepcopy(payloads[5]["extensions"])
        response["authorization"] = copy.deepcopy(payloads[5]["authorization"])
        auth = response["authorization"]
        auth["authorization_id"] = "urn:example:authority:continuation-reuse-second"
        auth["scope_digest"]["value"] = object_digest({"request_id": request["message_id"], "action": request["action"]})
        auth["valid_from"] = response["issued_at"]
        auth["valid_until"] = response["expires_at"]
        ids = {identifier(payloads[5]): identifier(response)}
        appended = copy.deepcopy(payloads[6:9])
        for index, event in enumerate(appended):
            old_id = identifier(event)
            event["object_id"] = "urn:example:event:continuation-reuse-second-" + str(index)
            ids[old_id] = event["object_id"]
        for index, event in enumerate(appended):
            event["observed_at"] = f"2026-09-29T10:00:00.{700000 + index * 100000:06d}Z"
            event["workflow"]["attempt"] = 3
            event["workflow"]["sequence"] = 33 + index
            for edge in event["workflow"]["causal_predecessors"]:
                edge["id"] = ids[edge["id"]]
            details = event["event"]
            details["authority"]["uri"] = auth["authorization_id"]
            if "authorization_id" in details:
                details["authorization_id"] = auth["authorization_id"]
            if "decision" in details:
                details["decision"]["uri"] = response["message_id"]
            if "attempt_id" in details:
                details["attempt_id"] = "urn:example:attempt:events-1-3"
        payloads[11:] = appended
        bundle["envelopes"][11:] = copy.deepcopy(bundle["envelopes"][6:9])
    if missing_approval:
        del payloads[3]
        del bundle["envelopes"][3]
    signed(bundle, payloads)
    if reverse:
        bundle["envelopes"].reverse()
    return bundle


def outputs():
    policy = json.loads((SUITE / "trust-policy.json").read_bytes())
    for key in policy["keys"]:
        if key["key_id"] in KEYS:
            public = KEYS[key["key_id"]].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            assert base64.b64encode(public).decode() == key["public_key"], key["key_id"]
    result = {}
    vectors = []
    def add(name, bundle, decision, verdict, primary, description, base):
        relative = f"conformance/suites/public-review-design-decisions/{name}.json"
        result[relative] = bundle
        vector = {
            "id": name, "path": relative, "stage": "evidence-bundle",
            "schema": "https://externalcontrollayer.ai/ns/schema/evidence-bundle/1",
            "expected": "pass" if verdict == "verified" else "fail",
            "expected_verdict": verdict, "expected_secondary_ids": [],
            "requirement_ids": ["DCMP2-047", "DCMP2-049"] if decision == "DESIGN-05" else ["DCMP2-057", "EBMP2-078"],
            "covers": [], "evaluated_at": "2026-10-01T00:00:00Z",
            "trust_policy_path": "conformance/suites/evidence-bundle/trust-policy.json",
            "trust_policy_history_paths": [],
            "source": {"kind": "mutation", "generator": "scripts/generate_design_decision_vectors.py",
                       "base_vector": "conformance/suites/evidence-bundle/" + base + ".json",
                       "mutation": decision + ": " + description},
        }
        if primary:
            vector["expected_primary_id"] = primary
            vector["negates"] = ["DCMP2-047"] if decision == "DESIGN-05" else ["EBMP2-078"]
        if verdict == "incomplete":
            vector["requirement_ids"].extend(["EBMP2-023", "EBMP2-059"])
            vector["negates"] = ["EBMP2-023", "EBMP2-059"]
        vectors.append(vector)
    for outcome in ("admit", "deny", "hold", "challenge"):
        for boundary in ("before", "equal", "after"):
            invalid = outcome == "admit" and boundary != "before"
            bundle, payloads = expiry_case(outcome, boundary)
            add(f"request-expiry-{outcome}-{boundary}", signed(bundle, payloads), "DESIGN-05",
                "invalid" if invalid else "verified", REQUEST_ERROR if invalid else None,
                f"{outcome} evaluation {boundary} exclusive request expiry; before/after differ by one nanosecond",
                "bundle-valid-succeeded")
    bundle, payloads = expiry_case("admit", "before", issued_after=True)
    add("request-expiry-evaluation-before-issue-after", signed(bundle, payloads), "DESIGN-05", "verified", None,
        "evaluation is one nanosecond before expiry, issue is one nanosecond after expiry and authorization outlives the request", "bundle-valid-succeeded")
    for outcome in ("deny", "challenge", "admit"):
        for missing in (False, True):
            verdict = "invalid" if outcome == "admit" else "incomplete" if missing else "verified"
            primary = CONTINUATION_ERROR if outcome == "admit" else CLOSURE_ERROR if missing else None
            name = "continuation-admitted-then-" + outcome + ("-approval-absent" if missing else "")
            add(name, chronological_reuse(outcome, missing), "DESIGN-08", verdict, primary,
                "chronological admitted continuation followed by " + outcome + ("; named approval omitted" if missing else "; all approval, request and challenge objects held"),
                "bundle-invalid-continuation-second-of-one-challenge")
    for outcome in ("deny", "admit"):
        add("continuation-admitted-then-" + outcome + "-reversed-array", chronological_reuse(outcome, reverse=True), "DESIGN-08",
            "invalid" if outcome == "admit" else "verified", CONTINUATION_ERROR if outcome == "admit" else None,
            "reverse envelope array without changing signed chronological reuse history", "bundle-invalid-continuation-second-of-one-challenge")
    original = json.loads((SUITE / "manifest.json").read_bytes())
    result["conformance/suites/public-review-design-decisions/manifest.json"] = {
        "candidate_version": original["candidate_version"], "schema_version": original["schema_version"],
        "suite": "public-review-design-decisions", "vectors": vectors}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    produced = outputs()
    for relative, value in produced.items():
        path = ROOT / relative
        raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        if args.check:
            if not path.exists() or path.read_bytes() != raw:
                raise SystemExit("Stale design-decision fixture: " + relative)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
    print(f"Design decisions: {len(produced) - 1} signed vectors and manifest {'checked' if args.check else 'generated'}")


if __name__ == "__main__":
    main()
