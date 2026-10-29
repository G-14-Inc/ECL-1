"""Describe every manifest vector and the capability needed to evaluate it.

A vector needs the capability of its stage, with these refinements. A vector of a suite that the
capability of a new or changed rule governs needs that capability. A failing vector that expects a
finding of a rule whose behavior forms its own capability needs that capability, whatever its
stage. A stage that only a profile's own rules evaluate (the binding records of the binding
profiles, and the claim and assessment documents) is its own optional capability, whatever the
vector expects, because an implementation without that stage cannot evaluate even its schema; so
is a stage whose vectors name a verdict (a signed bundle, alone or in an offline package), because
only its verifier produces the verdict. A protocol or semantic vector whose artifact carries a
registered extension with rules of its own needs that extension's capability. Otherwise a
schema-invalid failure needs schema validation, a strict-input failure strict JSON, and a vector
of a suite whose rules form their own capability needs that capability.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = ("strict-json", "canonical-digest", "semantic-rules", "safe-state-profile-rules")
OPTIONAL = (
    "schema-validation",
    "trust-policy-load",
    "envelope-signature-verification",
    "evidence-bundle-verification",
    "control-extension-rules",
    "binding-profile-rules",
    "decision-basis-rule",
    "document-validation",
    "extension-version-rule",
    "document-extension-rules",
    "key-role-separation",
    "binding-basis-agreement-rule",
    "otel-export-keyed-digests",
    "offline-package-verification",
)
# Suites whose rules form their own optional capability, whatever their stage.
SUITE_CAPABILITIES = {
    "ecl-1-v1.0-control-extensions": "control-extension-rules",
    "ecl-1-v1.0-aarm-binding": "binding-profile-rules",
    "ecl-1-v1.0-acs-binding": "binding-profile-rules",
    "ecl-1-v1.0-mcp-gateway": "binding-profile-rules",
    "ecl-1-v1.0-otel-export": "binding-profile-rules",
    "ecl-1-v1.0-oauth-authority": "binding-profile-rules",
}
# Suites whose every vector, passing or failing, needs a capability that RC-5 adds for a new or
# changed rule, because a library without it cannot evaluate even their passing vectors as the
# suite means them. An override takes precedence over SUITE_CAPABILITIES.
SUITE_OVERRIDES = {
    # TP1-009 and TP1-010: a trust-policy key holds one role, and a DCMP-2 request or response
    # counts only under a key of its role.
    "ecl-1-v1.0-key-roles": "key-role-separation",
    # AB1-013 and AC1-012: an AARM or ACS record's inputs agree with its response's decision basis.
    "ecl-1-v1.0-binding-basis": "binding-basis-agreement-rule",
    # OE1-004 and OE1-010: an OpenTelemetry record carries no digest that needs no key, and its
    # digests are keyed with the deployment's export key, which the suite's manifest names.
    "ecl-1-v1.0-otel-export": "otel-export-keyed-digests",
}
# Stages that are their own optional capability for every vector, passing or failing.
STAGE_CAPABILITIES = {
    # The binding records that the binding profiles' checkers read (ecl_verify.bindings).
    "binding": "binding-profile-rules",
    # A claim or assessment document, evaluated by its schema alone, passing or failing.
    "document": "document-validation",
    # A signed evidence bundle (EBMP-2 section 11), whose vector names the verdict of EBMP2-060
    # that only a bundle verifier produces, whatever its primary finding.
    "evidence-bundle": "evidence-bundle-verification",
    # An offline package (IE1-021, IE1-022): an ecl.zip.store.v1 archive, not a JSON value, whose
    # evidence bundle is verified under the caller's trust policy.
    "package": "offline-package-verification",
}
# Registered rules whose behavior forms its own optional capability: a failing vector that expects a
# finding of one of them, as its primary or a secondary finding, needs that capability, whatever its
# stage or suite.
RULE_CAPABILITIES = {
    # XR1-010: one object carries each extension identifier at one version.
    "ecl.rule.extension-single-version.v1": "extension-version-rule",
    # AB1-013 and AC1-012: a binding record's inputs agree with its response's decision basis.
    "ecl.rule.aarm-inputs-match-basis.v1": "binding-basis-agreement-rule",
    "ecl.rule.acs-inputs-match-basis.v1": "binding-basis-agreement-rule",
}
# ECL1N-0178 and DCMP2-053: the rule a verifier applies to a register before it checks a decision
# basis against it. A document vector that it refuses needs the decision-basis capability.
REGISTER_RULE = "ecl.rule.register-declarations-consistent.v1"
# Registered extensions whose rules form their own optional capability: a vector whose artifact
# carries one needs it, whatever its suite.
EXTENSION_CAPABILITIES = {
    "ecl.ext.decision-basis.v1": "decision-basis-rule",
}
STAGES = {
    "strict-json": "strict-json",
    "canonical": "canonical-digest",
    "protocol": "semantic-rules",
    "semantic": "semantic-rules",
    "bundle": "semantic-rules",
    "safe-state-profile": "safe-state-profile-rules",
    "trust-policy": "trust-policy-load",
    "envelope": "envelope-signature-verification",
    "evidence-bundle": "evidence-bundle-verification",
    "package": "offline-package-verification",
}


def carried_extensions(path: Path) -> set[str]:
    """The identifiers of the extensions that a JSON object artifact carries, or none."""
    try:
        value = json.loads(path.read_bytes())
    except ValueError:
        return set()
    extensions = value.get("extensions") if isinstance(value, dict) else None
    if not isinstance(extensions, list):
        return set()
    return {
        item["id"]
        for item in extensions
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def capability_of(root: Path, suite: str, vector: dict[str, Any]) -> str:
    if suite in SUITE_OVERRIDES:
        return SUITE_OVERRIDES[suite]
    stage = vector["stage"]
    primary = vector.get("expected_primary_id", "")
    expected = [primary, *vector["expected_secondary_ids"]] if vector["expected"] == "fail" else []
    if stage == "document" and REGISTER_RULE in expected:
        # A register that the register declarations rule refuses, which a bundle verifier given
        # the register applies before it checks a decision basis against it (DCMP2-053).
        return "decision-basis-rule"
    if stage == "document" and any(name.startswith("ecl.rule.") for name in expected):
        # A document that a registered rule refuses: the extension rules that apply to a work
        # intent (ECL-WI-1) at the document stage, beyond its schema.
        return "document-extension-rules"
    own = sorted({RULE_CAPABILITIES[name] for name in expected if name in RULE_CAPABILITIES})
    if own:
        return own[0]
    if stage in STAGE_CAPABILITIES:
        return STAGE_CAPABILITIES[stage]
    if stage in ("protocol", "semantic"):
        own = sorted(
            EXTENSION_CAPABILITIES[name]
            for name in carried_extensions(root / vector["path"])
            if name in EXTENSION_CAPABILITIES
        )
        if own:
            return own[0]
    if vector["expected"] == "fail" and primary == "ecl.error.schema-invalid.v1":
        return "schema-validation"
    if vector["expected"] == "fail" and primary.startswith("ecl.rule.json-"):
        return "strict-json"
    return SUITE_CAPABILITIES.get(suite, STAGES[stage])


def manifests(root: Path) -> list[Path]:
    return [
        root / "conformance/manifest.json",
        *sorted((root / "conformance/suites").glob("*/manifest.json")),
    ]


def unknown_suites(declared: set[str]) -> list[str]:
    """The suites that the capability maps name and no manifest declares. The maps are keyed by
    suite identifier, which carries the version, so a renamed suite must be renamed here too: a
    key that matches no suite would otherwise send the suite's vectors to their stage's capability
    without a word."""
    return sorted((set(SUITE_CAPABILITIES) | set(SUITE_OVERRIDES)) - declared)


def build(root: Path) -> dict[str, Any]:
    vectors: list[dict[str, str]] = []
    seen: set[str] = set()
    suites: set[str] = set()
    for path in manifests(root):
        manifest = json.loads(path.read_bytes())
        if manifest["schema_version"] != "ecl_conformance_vector_manifest_v3":
            raise ValueError("shared corpus requires v3 manifests")
        suites.add(manifest["suite"])
        for vector in manifest["vectors"]:
            if vector["id"] in seen:
                raise ValueError("manifest vector identifiers must be globally unique")
            seen.add(vector["id"])
            capability = capability_of(root, manifest["suite"], vector)
            vectors.append(
                {"suite": manifest["suite"], "id": vector["id"], "capability": capability}
            )
    if unknown := unknown_suites(suites):
        raise ValueError(
            "the capability maps name suites that no manifest declares: " + ", ".join(unknown)
        )
    versions = json.loads((root / "release/VERSION_SET.json").read_bytes())
    return {
        "schema_version": "ecl_shared_corpus_v1",
        "version": 1,
        "candidate_version": versions["candidate_version"],
        "required_capabilities": list(REQUIRED),
        "optional_capabilities": list(OPTIONAL),
        "vectors": sorted(vectors, key=lambda row: (row["suite"], row["id"])),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = (json.dumps(build(args.root), indent=2, sort_keys=True) + "\n").encode()
    target = args.root / "conformance/shared-corpus.json"
    if args.check:
        if target.read_bytes() != data:
            parser.exit(1, "shared corpus is stale\n")
    else:
        target.write_bytes(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
