"""Generate deterministic policy/error-contract regression fixtures.

All signing keys here are public test fixtures, unsuitable for real authority.
The published envelope fixture supplies the unchanged request and key-A identity.
The corpus tests distinguish payload semantic checks from standalone envelope
checks, and a discarded optional signature from a failed signature threshold.
"""
from __future__ import annotations
import argparse, base64, copy, hashlib, json, sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/ecl-verify/src"))
from ecl_verify.canonical import canonicalize
from ecl_verify.integrity import decode_canonical_json_payload, signing_input
from ecl_verify.trust import TrustPolicy

SUITE = Path("conformance/suites/error-contract")
GENERATOR = "scripts/generate_error_contract_vectors.py"
RULE = "ecl.rule.integrity-threshold-consistent.v1"
POLICY_ERROR = "ecl.error.signature-policy-invalid.v1"
THRESHOLD_ERROR = "ecl.error.threshold-not-met.v1"
SCHEMAS = {"protocol": "https://externalcontrollayer.ai/ns/schema/dcmp/2",
           "envelope": "https://externalcontrollayer.ai/ns/schema/integrity-envelope/1",
           "evidence-bundle": "https://externalcontrollayer.ai/ns/schema/evidence-bundle/1"}

def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()

def build(root: Path):
    original = json.loads((root / "conformance/suites/envelope/envelope-valid-ed25519-signed.json").read_text())
    source_policy = json.loads((root / "conformance/suites/envelope/trust-policy.json").read_text())
    key_a = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    key_b = Ed25519PrivateKey.from_private_bytes(bytes(range(32,64)))
    key_c = ec.derive_private_key(7, ec.SECP256R1())
    key_r = Ed25519PrivateKey.from_private_bytes(bytes(range(64,96)))
    a = "urn:example:key:vector-ed"
    b = "urn:example:key:error-contract-b"
    c = "urn:example:key:error-contract-p256"
    r = "urn:example:key:error-contract-revoked"
    description_a = copy.deepcopy(next(k for k in source_policy["keys"] if k["key_id"] == a))
    if base64.b64encode(key_a.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode() != description_a["public_key"]:
        raise ValueError("Public fixture key differs from the source trust policy")
    description_b = copy.deepcopy(description_a)
    description_b.update(key_id=b, public_key=base64.b64encode(key_b.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode())
    description_a["purposes"] = description_b["purposes"] = ["ecl.purpose.decision-request.v1"]
    policy_doc = copy.deepcopy(source_policy)
    description_c = copy.deepcopy(description_a)
    description_c.update(key_id=c, suite_id="ecl.sig.ecdsa-p256-sha256.v1", public_key=base64.b64encode(key_c.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)).decode())
    description_r = copy.deepcopy(description_a)
    description_r.update(key_id=r, public_key=base64.b64encode(key_r.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode())
    policy_doc["keys"] = [description_a, description_b, description_c, description_r]
    policy_doc["revocations"] = [dict(key_id=r, effective_at=decode_canonical_json_payload(original)["issued_at"], reason="Public test fixture for ordered signer errors")]
    policy = TrustPolicy.load(encoded(policy_doc))
    payload = decode_canonical_json_payload(original)
    payload["integrity_policy"].update(trust_policy=policy.reference(), eligible_key_ids=[a], required_key_ids=[a], threshold=1,
                                       accepted_suites=["ecl.sig.ed25519.v1"])
    keys = {a:key_a, b:key_b, c:key_c, r:key_r}
    def signature(name, message):
        if name != c:
            return "ecl.sig.ed25519.v1", keys[name].sign(message)
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        r_value, s_value = decode_dss_signature(key_c.sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
        return "ecl.sig.ecdsa-p256-sha256.v1", encode_dss_signature(r_value, min(s_value, order-s_value))
    def sign(value, signers):
        raw = canonicalize(value)
        entries = []
        for name in signers:
            suite, signed = signature(name, signing_input(original["payload_type"], raw))
            entries.append(dict(key_id=name, suite_id=suite, signature=base64.b64encode(signed).decode()))
        return {"envelope_version":"ECL-IE-1", "payload_type":original["payload_type"],
                "payload":base64.b64encode(raw).decode(),
                "payload_digest":{"algorithm":"ecl.digest.sha-256.v1", "value":hashlib.sha256(raw).hexdigest()},
                "signatures":entries}
    baseline = sign(payload, [a])
    optional = copy.deepcopy(baseline)
    extra = copy.deepcopy(optional["signatures"][0]);extra["suite_id"]="ecl.sig.ecdsa-p256-sha256.v1"
    optional["signatures"].append(extra)
    subset = copy.deepcopy(payload);subset["integrity_policy"]["required_key_ids"]=[b]
    below = copy.deepcopy(payload);below["integrity_policy"].update(eligible_key_ids=[a,b], required_key_ids=[a,b])
    subset_a = sign(subset,[a]);subset_ab = sign(subset,[a,b])
    extra_key = sign(payload, [a,b])
    suite_payload = copy.deepcopy(payload);suite_payload["integrity_policy"]["eligible_key_ids"] = [a,c]
    extra_suite = sign(suite_payload, [a,c])
    wildcard_payload = copy.deepcopy(payload);wildcard_payload["integrity_policy"]["eligible_key_ids"] = []
    ordered_payload = copy.deepcopy(payload);ordered_payload["integrity_policy"]["eligible_key_ids"] = [a,r]
    bundle = lambda envelope: {"schema_version":"ecl_evidence_bundle_v1", "envelopes":[envelope]}
    cases = [
        ("error-contract-valid-policy-baseline", "envelope", baseline, None, ["IE1-040"], "valid threshold and required signer"),
        ("error-contract-valid-extra-unaccepted-suite", "envelope", optional, None, ["IE1-040"], "append an uncounted signature using an unaccepted suite; required signer and threshold remain satisfied"),
        ("error-contract-invalid-payload-required-key-not-eligible", "protocol", subset, RULE, ["IE1-013"], "decode the payload and require a key outside its nonempty eligible-key list"),
        ("error-contract-invalid-envelope-required-key-absent", "envelope", subset_a, THRESHOLD_ERROR, ["IE1-040"], "require an ineligible key that supplies no signature; step 6 records no failure for the valid present key"),
        ("error-contract-invalid-envelope-required-key-ineligible", "envelope", subset_ab, POLICY_ERROR, ["IE1-040"], "add the required but ineligible key signature; step 6 records its rejection"),
        ("error-contract-invalid-payload-threshold-below-required", "protocol", below, RULE, ["IE1-013"], "decode the payload and set its threshold below the number of required signers"),
        ("error-contract-invalid-envelope-threshold-below-required", "envelope", sign(below,[a,b]), POLICY_ERROR, ["IE1-040"], "set the threshold below the required-key count; standalone verification rejects the policy at step 4"),
        ("error-contract-invalid-bundle-payload-policy", "evidence-bundle", {"schema_version":"ecl_evidence_bundle_v1","envelopes":[subset_a]}, RULE, ["IE1-013","EBMP2-068"], "place the payload with a required key outside its eligible list in a bundle; object semantics is stage 3"),
    ]
    cases += [
        ("error-contract-valid-extra-ineligible-key", "envelope", extra_key, None, ["IE1-040"], "append a valid signature by a trusted but payload-ineligible key; the required signer meets the threshold"),
        ("error-contract-valid-extra-registered-unaccepted-suite", "envelope", extra_suite, None, ["IE1-040"], "append a valid P-256 signature under a matching trusted and eligible key, while the payload accepts only Ed25519"),
        ("error-contract-valid-empty-eligible-list", "envelope", sign(wildcard_payload,[a,b]), None, ["IE1-040"], "use the empty eligible-key list as unrestricted and retain the required signer"),
        ("error-contract-invalid-bundle-extra-ineligible-key", "evidence-bundle", bundle(extra_key), POLICY_ERROR, ["IE1-040","EBMP2-057"], "bundle verification applies the payload eligible-key restriction to every signature, counted or not"),
        ("error-contract-invalid-bundle-extra-unaccepted-suite", "evidence-bundle", bundle(extra_suite), POLICY_ERROR, ["IE1-040","EBMP2-057"], "bundle verification applies the payload accepted-suite restriction to every signature, counted or not"),
        ("error-contract-invalid-bundle-extra-mismatched-suite", "evidence-bundle", bundle(optional), POLICY_ERROR, ["IE1-040","EBMP2-057"], "the extra signature is both payload-unaccepted and mismatched to the trust-policy key suite"),
        ("error-contract-invalid-step6-revoked-first", "envelope", sign(ordered_payload,[r,b]), POLICY_ERROR, ["IE1-040"], "examine a revoked key before an ineligible key; the earlier sub-step reason still wins over signature-list order"),
        ("error-contract-invalid-step6-ineligible-first", "envelope", sign(ordered_payload,[b,r]), POLICY_ERROR, ["IE1-040"], "reverse the two rejected signatures; the sub-step-priority error remains the same"),
    ]
    artifacts = {SUITE / "trust-policy.json": encoded(policy_doc)}
    vectors = []
    for identifier, stage, value, primary, requirements, mutation in cases:
        path = SUITE / (identifier + ".json"); artifacts[path] = encoded(value)
        row = dict(id=identifier, path=path.as_posix(), stage=stage, schema=SCHEMAS[stage],
                   expected="fail" if primary else "pass", expected_secondary_ids=[], requirement_ids=requirements, covers=[],
                   source=dict(kind="authored", generator=GENERATOR))
        if identifier != "error-contract-valid-policy-baseline":
            row["source"] = dict(kind="mutation", generator=GENERATOR, base_vector=(SUITE/"error-contract-valid-policy-baseline.json").as_posix(), mutation=mutation)
        if primary: row.update(expected_primary_id=primary, negates=requirements)
        if stage == "evidence-bundle":
            row.update(expected_verdict="invalid", trust_policy_path=(SUITE/"trust-policy.json").as_posix(), trust_policy_history_paths=[], evaluated_at=payload["issued_at"])
        vectors.append(row)
    artifacts[SUITE/"manifest.json"] = encoded(dict(schema_version="ecl_conformance_vector_manifest_v3", candidate_version="1.0",
        suite="ecl-1-v1.0-error-contract", trust_policy_path=(SUITE/"trust-policy.json").as_posix(), vectors=sorted(vectors,key=lambda v:v["id"])))
    return artifacts

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,default=ROOT);parser.add_argument("--check",action="store_true")
    args=parser.parse_args()
    for relative, content in build(args.root).items():
        path=args.root/relative
        if args.check:
            if not path.is_file() or path.read_bytes()!=content:raise SystemExit(f"stale error-contract fixture: {relative}")
        else:
            path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(content)
    print("error-contract vectors: check passed" if args.check else "error-contract vectors: generated")

if __name__ == "__main__":main()
