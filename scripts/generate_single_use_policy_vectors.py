#!/usr/bin/env python3
"""Reproduce single-use policy fixtures and the prior DPoP authorization control.

All records and signing seeds are synthetic. Robert F. Tilley Jr.; G-14, Inc.
The schema-coverage migration preserves existing positive coverage while naming
the narrowed behavior. The prior DPoP control proves that cached jti reuse can
come from another authorization while the current authorization is used once.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
from pathlib import Path

from ecl_verify.bindings import jose, oauth
from ecl_verify.canonical import object_digest

ROOT = Path(__file__).resolve().parents[1]
SUITE = Path("conformance/suites/single-use-policy")
SCHEMA = "https://externalcontrollayer.ai/ns/schema/dcmp/2"
INVALID = "ecl.error.schema-invalid.v1"
# Independently retained metadata for the controls migrated in existing suites.
EXPECTED_SCHEMA_ROWS = {'dcmp-invalid-admit-use-policy-outside-enum': {'covers': ['https://externalcontrollayer.ai/ns/schema/dcmp/2##root',
                                                           'https://externalcontrollayer.ai/ns/schema/dcmp/2#/$defs/authorization/properties/use_policy/enum#enum'],
                                                'expected': 'fail',
                                                'expected_primary_id': 'ecl.error.schema-invalid.v1',
                                                'expected_secondary_ids': [],
                                                'id': 'dcmp-invalid-admit-use-policy-outside-enum',
                                                'negates': ['DCMP2-001', 'DCMP2-013'],
                                                'path': 'conformance/suites/schema-coverage/dcmp-invalid-admit-use-policy-outside-enum.json',
                                                'requirement_ids': ['DCMP2-001', 'DCMP2-013'],
                                                'schema': 'https://externalcontrollayer.ai/ns/schema/dcmp/2',
                                                'source': {'base_vector': 'conformance/suites/schema-coverage/dcmp-valid-admit-single-use-explicit-one.json',
                                                           'generator': 'scripts/generate_single_use_policy_vectors.py',
                                                           'kind': 'mutation',
                                                           'mutation': 'Set an unregistered use '
                                                                       'policy while retaining '
                                                                       'max_uses=1 to isolate its '
                                                                       'enum.'},
                                                'stage': 'protocol'},
 'dcmp-invalid-request-use-policy-outside-enum': {'covers': ['https://externalcontrollayer.ai/ns/schema/dcmp/2##root',
                                                             'https://externalcontrollayer.ai/ns/schema/dcmp/2#/$defs/decisionRequest/allOf/1/properties/authority_request/properties/use_policy/enum#enum'],
                                                  'expected': 'fail',
                                                  'expected_primary_id': 'ecl.error.schema-invalid.v1',
                                                  'expected_secondary_ids': [],
                                                  'id': 'dcmp-invalid-request-use-policy-outside-enum',
                                                  'negates': ['DCMP2-001'],
                                                  'path': 'conformance/suites/schema-coverage/dcmp-invalid-request-use-policy-outside-enum.json',
                                                  'requirement_ids': ['DCMP2-001'],
                                                  'schema': 'https://externalcontrollayer.ai/ns/schema/dcmp/2',
                                                  'source': {'base_vector': 'conformance/suites/schema-coverage/dcmp-valid-request-single-use-explicit-one.json',
                                                             'generator': 'scripts/generate_single_use_policy_vectors.py',
                                                             'kind': 'mutation',
                                                             'mutation': 'Set an unregistered use '
                                                                         'policy while retaining '
                                                                         'max_uses=1 to isolate '
                                                                         'its enum.'},
                                                  'stage': 'protocol'},
 'dcmp-valid-admit-single-use-explicit-one': {'covers': ['https://externalcontrollayer.ai/ns/schema/common/1#/$defs/extensionId/anyOf#anyOf[0]',
                                                         'https://externalcontrollayer.ai/ns/schema/common/1#/$defs/obligation/properties/satisfaction/enum#enum',
                                                         'https://externalcontrollayer.ai/ns/schema/dcmp/2##root',
                                                         'https://externalcontrollayer.ai/ns/schema/dcmp/2#/$defs/authorization/properties/use_policy/enum#enum',
                                                         'https://externalcontrollayer.ai/ns/schema/dcmp/2#/$defs/decisionResponse/allOf/1/allOf/0/if#if[0]',
                                                         'https://externalcontrollayer.ai/ns/schema/dcmp/2#/$defs/decisionResponse/allOf/1/properties/outcome/enum#enum'],
                                              'expected': 'pass',
                                              'expected_secondary_ids': [],
                                              'id': 'dcmp-valid-admit-single-use-explicit-one',
                                              'path': 'conformance/suites/schema-coverage/dcmp-valid-admit-single-use-explicit-one.json',
                                              'requirement_ids': ['DCMP2-001',
                                                                  'DCMP2-013',
                                                                  'DCMP2-050'],
                                              'schema': 'https://externalcontrollayer.ai/ns/schema/dcmp/2',
                                              'source': {'base_vector': 'conformance/vectors/dcmp-2/valid-decision-response-admit.json',
                                                         'generator': 'scripts/generate_single_use_policy_vectors.py',
                                                         'kind': 'mutation',
                                                         'mutation': 'Set supported single_use '
                                                                     'policy and explicit '
                                                                     'max_uses=1.'},
                                              'stage': 'protocol'},
 'dcmp-valid-request-single-use-explicit-one': {'covers': ['https://externalcontrollayer.ai/ns/schema/common/1##root',
                                                           'https://externalcontrollayer.ai/ns/schema/common/1#/$defs/extensionId/anyOf#anyOf[0]',
                                                           'https://externalcontrollayer.ai/ns/schema/dcmp/2##root',
                                                           'https://externalcontrollayer.ai/ns/schema/dcmp/2#/$defs/decisionRequest/allOf/1/properties/authority_request/properties/use_policy/enum#enum'],
                                                'expected': 'pass',
                                                'expected_secondary_ids': [],
                                                'id': 'dcmp-valid-request-single-use-explicit-one',
                                                'path': 'conformance/suites/schema-coverage/dcmp-valid-request-single-use-explicit-one.json',
                                                'requirement_ids': ['DCMP2-001', 'DCMP2-050'],
                                                'schema': 'https://externalcontrollayer.ai/ns/schema/dcmp/2',
                                                'source': {'base_vector': 'conformance/vectors/dcmp-2/valid-decision-request.json',
                                                           'generator': 'scripts/generate_single_use_policy_vectors.py',
                                                           'kind': 'mutation',
                                                           'mutation': 'Set supported single_use '
                                                                       'policy and explicit '
                                                                       'max_uses=1.'},
                                                'stage': 'protocol'}}
EXPECTED_OAUTH_ROW = {'covers': [],
 'expected': 'fail',
 'expected_primary_id': 'ecl.rule.oauth-token-expresses-admit.v1',
 'expected_secondary_ids': ['ecl.rule.oauth-presentation-checked.v1'],
 'id': 'oauth-invalid-entry-max-uses-boolean',
 'negates': ['OA1-001'],
 'path': 'conformance/suites/oauth-authority/oauth-invalid-entry-max-uses-boolean.json',
 'requirement_ids': ['OA1-001'],
 'schema': 'https://externalcontrollayer.ai/ns/schema/binding/oauth-presentation/1',
 'source': {'base_vector': 'conformance/suites/oauth-authority/oauth-valid-dpop-es256-accepted.json',
            'generator': 'scripts/generate_oauth_authority_vectors.py',
            'kind': 'mutation',
            'mutation': 'issue an entry whose max_uses is true where the admit grants one use, and '
                        'accept its presentation'},
 'stage': 'binding'}


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def build(root=ROOT, *, binding_generator=None):
    files, vectors, removed = {}, [], []

    def read(path):
        return json.loads((root / path).read_bytes())

    def add(name, value, requirements, *, fail=False, covers=(), schema=SCHEMA, stage="protocol", note=""):
        identifier = "single-use-" + name
        path = SUITE / (identifier + ".json")
        files[path] = encode(value)
        row = {"id": identifier, "path": path.as_posix(), "schema": schema, "stage": stage,
               "requirement_ids": requirements, "expected": "fail" if fail else "pass",
               "expected_secondary_ids": [], "covers": list(covers),
               "source": {"kind": "mutation", "generator": "scripts/generate_single_use_policy_vectors.py",
                          "mutation": note or name.replace("-", " ")}}
        if fail:
            row.update(expected_primary_id=INVALID, negates=requirements)
        vectors.append(row)

    coverage_path = Path("conformance/suites/schema-coverage/manifest.json")
    coverage = read(coverage_path)
    for kind, base_name, member, pointer, requirements in [
        ("request", "valid-decision-request", "authority_request", "/$defs/decisionRequest/allOf/1/properties/authority_request", ["DCMP2-001", "DCMP2-050"]),
        ("admit", "valid-decision-response-admit", "authorization", "/$defs/authorization", ["DCMP2-001", "DCMP2-013", "DCMP2-050"]),
    ]:
        base = read(Path("conformance/vectors/dcmp-2") / (base_name + ".json"))
        base[member].update(use_policy="single_use", max_uses=1)
        policy_unit = SCHEMA + "#" + pointer + "/properties/use_policy/enum#enum"
        old_id = "dcmp-valid-" + kind + "-bounded-multi-use"
        new_id = "dcmp-valid-" + kind + "-single-use-explicit-one"
        old_path = coverage_path.parent / (old_id + ".json")
        new_path = coverage_path.parent / (new_id + ".json")
        files[new_path] = encode(base)
        removed.append(old_path)
        negative_id = "dcmp-invalid-" + kind + "-use-policy-outside-enum"
        matched = {new_id: 0, negative_id: 0}
        for row in coverage["vectors"]:
            identifier = new_id if row["id"] in (old_id, new_id) else row["id"]
            if identifier in matched:
                matched[identifier] += 1
                row.clear()
                row.update(copy.deepcopy(EXPECTED_SCHEMA_ROWS[identifier]))
            elif row.get("source", {}).get("base_vector") == old_path.as_posix():
                row["source"]["base_vector"] = new_path.as_posix()
        if any(count != 1 for count in matched.values()):
            raise ValueError("expected one positive and one negative schema migration for " + kind)
        # Reconstruct the targeted enum refusal from its positive base, rather
        # than accepting other mutations from the output fixture under test.
        negative = copy.deepcopy(base)
        negative[member]["use_policy"] = "unlimited"
        files[Path(EXPECTED_SCHEMA_ROWS[negative_id]["path"])] = encode(negative)
        missing = copy.deepcopy(base)
        missing[member].pop("max_uses")
        add(kind + "-absent-maximum-control", missing, requirements, covers=[SCHEMA + "##root", policy_unit])
        unsupported = copy.deepcopy(base)
        unsupported[member]["use_policy"] = "bounded_multi_use"
        add(kind + "-bounded-policy-unsupported", unsupported, requirements, fail=True,
            covers=[SCHEMA + "##root", policy_unit],
            note="Reject reserved bounded_multi_use while max_uses=1 isolates the unsupported policy.")
        excessive = copy.deepcopy(base)
        excessive[member]["max_uses"] = 2
        add(kind + "-maximum-two-refused", excessive, requirements, fail=True,
            covers=[SCHEMA + "##root"])
        boolean = copy.deepcopy(base)
        boolean[member]["max_uses"] = True
        add(kind + "-boolean-maximum-refused", boolean, requirements, fail=True,
            covers=[SCHEMA + "##root"])
    files[coverage_path] = encode(coverage)

    # The unchanged negative token fixture has two independently invalid declarations:
    # its boolean maximum is neither an admit-bound maximum nor a supported use count.
    oauth_manifest_path = Path("conformance/suites/oauth-authority/manifest.json")
    oauth_manifest = read(oauth_manifest_path)
    matches = [row for row in oauth_manifest["vectors"]
               if row["id"] == "oauth-invalid-entry-max-uses-boolean"]
    if len(matches) != 1:
        raise ValueError("expected the existing boolean-maximum token refusal")
    matches[0].clear()
    matches[0].update(copy.deepcopy(EXPECTED_OAUTH_ROW))
    files[oauth_manifest_path] = encode(oauth_manifest)

    path = binding_generator or root / "scripts/generate_repair_bindings_vectors.py"
    spec = importlib.util.spec_from_file_location("single_use_binding_fixtures", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = root
    prior = module.oauth_record()
    prior["dpop_proof_window_seconds"] = 1
    prior["response"]["authorization"]["authorization_id"] = "urn:example:authorization:prior-dpop-cache"
    prior["response"]["message_id"] = "urn:example:message:prior-dpop-cache-admit"
    prior["response"]["decision_id"] = "urn:example:decision:prior-dpop-cache-admit"
    prior["presentation"].update(presented_at="2026-09-30T09:00:01Z", use_count=1, seen_dpop_jti=[])
    header, claims, _, _ = jose.decode(prior["token"])
    claims["jti"] = "at-prior-dpop-cache"
    entry = claims["authorization_details"][0]
    entry["authorization_id"] = prior["response"]["authorization"]["authorization_id"]
    entry["decision"] = {"uri": prior["response"]["message_id"],
                         "digest": {"algorithm": "ecl.digest.sha-256.v1", "value": object_digest(prior["response"])}}
    prior["token"] = module.jws(header, claims, module.issuer)
    proof_header, proof, _, _ = jose.decode(prior["presentation"]["dpop_proof"])
    proof["ath"] = jose.token_hash(prior["token"])
    prior["presentation"]["dpop_proof"] = module.jws(proof_header, proof, module.sender)
    add("dpop-other-authorization-cache-control", prior, ["OA1-004", "OA1-005"],
        schema=oauth.PRESENTATION_SCHEMA, stage="binding", covers=[oauth.PRESENTATION_SCHEMA + "##root"],
        note="Valid first use of a distinct authorization at the same proof key, method and htu; its dpop-0001 identifier supplies the replay-cache state for the migrated timing/replay fixtures.")
    files[SUITE / "manifest.json"] = encode({"schema_version": "ecl_conformance_vector_manifest_v3",
        "candidate_version": "1.0", "suite": "ecl-1-public-review-single-use-policy", "vectors": vectors})
    return files, removed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    files, removed = build(args.root)
    differences = []
    for relative, content in files.items():
        path = args.root / relative
        if args.check:
            if not path.is_file() or path.read_bytes() != content:
                differences.append(relative.as_posix())
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    for relative in removed:
        path = args.root / relative
        if args.check:
            if path.exists():
                differences.append(relative.as_posix())
        else:
            path.unlink(missing_ok=True)
    print(json.dumps({"files": len(files), "retired_fixture_paths": [p.as_posix() for p in removed],
                      "differences": differences}, indent=2))
    return bool(differences)


if __name__ == "__main__":
    raise SystemExit(main())
