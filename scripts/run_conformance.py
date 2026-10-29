#!/usr/bin/env python3
"""Run the deterministic conformance-vector harness for the current version."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012


ROOT = Path(__file__).resolve().parents[1]
# The Python verifier (packages/ecl-verify), when it is not installed in the environment.
sys.path.insert(0, str(ROOT / "packages" / "ecl-verify" / "src"))

from ecl_verify.bindings import binding_findings  # noqa: E402
from ecl_verify.bindings.otel import ExportKey, load_export_keys  # noqa: E402
from ecl_verify.bundle import analyze_bundle  # noqa: E402
from ecl_verify.bundle_verification import (  # noqa: E402
    MAX_REGISTER_BYTES,
    load_register,
    reported_identifiers,
    verify_bundle,
)
from ecl_verify.canonical import (  # noqa: E402
    MAX_JSON_BYTES,
    CanonicalizationError,
    canonicalize,
    load_json_strict,
    loads_json_strict,
)
from ecl_verify.offline import DEFAULT_OFFLINE_RESOURCE_LIMITS  # noqa: E402
from ecl_verify.resources import extension_value_validators  # noqa: E402
from ecl_verify.semantic import (  # noqa: E402
    SemanticValidator,
    active_extension_versions,
    allocated_extension_versions,
    composable_extensions,
)
from ecl_verify.schema import ecl_format_checker  # noqa: E402
from ecl_verify.schema_patterns import schema_validator, validation_schema  # noqa: E402
from ecl_verify.semantic_rc4 import validate_safe_state_profile  # noqa: E402
from ecl_verify.integrity import IntegrityError, decode_canonical_json_payload, verify_envelope  # noqa: E402
from ecl_verify.package_verification import reported_package_identifiers, verify_offline_package  # noqa: E402
from ecl_verify.trust import MAX_TRUST_POLICY_BYTES, TrustPolicy, TrustPolicyError  # noqa: E402


SCHEMA_PATHS = {
    "https://externalcontrollayer.ai/ns/schema/trust-policy/1": "schemas/ecl-trust-policy-v1.schema.json",
    "https://externalcontrollayer.ai/ns/schema/safe-state-profile/1": "schemas/ecl-safe-state-profile-v1.schema.json",
    "https://externalcontrollayer.ai/ns/schema/common/1": "schemas/ecl-common-v1.schema.json",
    "https://externalcontrollayer.ai/ns/schema/integrity-envelope/1": (
        "schemas/ecl-integrity-envelope-v1.schema.json"
    ),
    "https://externalcontrollayer.ai/ns/schema/dcmp/2": "schemas/dcmp-2.schema.json",
    "https://externalcontrollayer.ai/ns/schema/ebmp/2": "schemas/ebmp-2.schema.json",
    "https://externalcontrollayer.ai/ns/schema/adapter-binding/1": (
        "schemas/ecl-adapter-binding-v1.schema.json"
    ),
    "https://externalcontrollayer.ai/ns/schema/binding/aarm-exchange/1": (
        "schemas/ecl-binding-aarm-exchange-v1.schema.json"
    ),
    "https://externalcontrollayer.ai/ns/schema/binding/acs-exchange/1": (
        "schemas/ecl-binding-acs-exchange-v1.schema.json"
    ),
    "https://externalcontrollayer.ai/ns/schema/binding/mcp-gateway-exchange/1": (
        "schemas/ecl-binding-mcp-gateway-exchange-v1.schema.json"
    ),
    "https://externalcontrollayer.ai/ns/schema/binding/otel-export/1": (
        "schemas/ecl-binding-otel-export-v1.schema.json"
    ),
    "https://externalcontrollayer.ai/ns/schema/binding/oauth-presentation/1": (
        "schemas/ecl-binding-oauth-presentation-v1.schema.json"
    ),
    # The AARM and ACS exchange records list their inputs as entries of the decision basis.
    "https://externalcontrollayer.ai/ns/schema/extension/decision-basis/1": (
        "schemas/ecl-ext-decision-basis-v1.schema.json"
    ),
    # The MCP gateway exchange record holds the discharge of the pre-release obligations (MG1-013).
    "https://externalcontrollayer.ai/ns/schema/extension/obligation-discharge/1": (
        "schemas/ecl-ext-obligation-discharge-v1.schema.json"
    ),
    # The claim and assessment documents that the `document` stage validates.
    "https://externalcontrollayer.ai/ns/schema/action-register/1": (
        "schemas/ecl-action-register-v1.schema.json"
    ),
    "https://externalcontrollayer.ai/ns/schema/assessment-package/1": (
        "schemas/ecl-assessment-package-v1.schema.json"
    ),
    "https://externalcontrollayer.ai/ns/schema/conformance-claim/1": (
        "schemas/ecl-conformance-claim-v1.schema.json"
    ),
    "https://externalcontrollayer.ai/ns/schema/deployment-profile/1": (
        "schemas/ecl-deployment-profile-v1.schema.json"
    ),
    "https://externalcontrollayer.ai/ns/schema/lifecycle-policy/1": (
        "schemas/ecl-lifecycle-policy-v1.schema.json"
    ),
    "https://externalcontrollayer.ai/ns/schema/mapping-packet/1": (
        "schemas/ecl-mapping-packet-v1.schema.json"
    ),
    "https://externalcontrollayer.ai/ns/schema/offline-verification-package/1": (
        "schemas/ecl-offline-verification-package-v1.schema.json"
    ),
    "https://externalcontrollayer.ai/ns/schema/work-intent/1": (
        "schemas/ecl-work-intent-v1.schema.json"
    ),
}
RESULT_PATH = Path("release/conformance-results.json")
# The generator of the foundation vectors is G-14's tooling: where it is present (the maintainers'
# repository) the runner first checks that the vectors are current; the ECL-1 package holds the
# vectors without their generator.
FOUNDATION_GENERATOR = Path("scripts/generate_foundation_vectors.py")


def read_json(path: Path) -> dict[str, Any]:
    value = load_json_strict(path)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: root must be an object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def schema_environment(
    root: Path,
) -> tuple[dict[str, dict[str, Any]], Registry]:
    schemas = {uri: read_json(root / path) for uri, path in SCHEMA_PATHS.items()}
    registry = Registry()
    for uri, schema in schemas.items():
        # IE1-038: a referenced schema is read through a private copy whose patterns match as
        # ECMA-262 patterns do; the root schema's patterns are adapted by schema_validator. The
        # copy leaves out the dialect's `$schema`, so it is read as Draft 2020-12 by default.
        registry = registry.with_resource(
            uri,
            Resource.from_contents(validation_schema(schema), default_specification=DRAFT202012),
        )
    return schemas, registry


def document_rules(root: Path, kind: object) -> frozenset[str]:
    """The active semantic rules whose `applies_to` names the document type `kind`: a protocol,
    such as ECL-WI-1 for a work intent, which carries extensions (XR1-006, XR1-009, XR1-010,
    XR1-017), or the `$id` of a document's schema, such as the action register's (ECL1N-0178)."""
    if not isinstance(kind, str):
        return frozenset()
    entries = read_json(root / "registries/semantic-rules.json")["entries"]
    return frozenset(
        item["id"]
        for item in entries
        if item["status"] == "active" and kind in item.get("attributes", {}).get("applies_to", [])
    )


# The registered rules of strict input (IE1-002, IE1-037). A strict refusal names one of them, or
# ecl.error.resource-limit-exceeded.v1 for a declared limit.
STRICT_RULES = frozenset(
    {
        "ecl.rule.json-strict-syntax.v1",
        "ecl.rule.json-no-duplicate-members.v1",
        "ecl.rule.json-restricted-numbers.v1",
    }
)


def strict_failure_id(exc: CanonicalizationError) -> str:
    """The finding of a strict refusal: the first of the ordered checks of IE1-037 that failed."""
    return exc.finding_id


# The corpus's declared package limit on archive bytes (IE1-028), which the package stage reads to.
MAX_PACKAGE_BYTES = DEFAULT_OFFLINE_RESOURCE_LIMITS.max_archive_bytes


def read_limited(path: Path, limit: int) -> bytes:
    """The artifact's bytes, read no further than one byte past `limit` (IE1-029)."""
    with path.open("rb") as source:
        return source.read(limit + 1)


def load_trust_policy(root: Path, value: str) -> TrustPolicy:
    with safe_artifact_path(root, value).open("rb") as source:
        return TrustPolicy.load(source.read(MAX_TRUST_POLICY_BYTES + 1))


def load_suite_export_keys(root: Path, value: str) -> dict[str, ExportKey]:
    """The published test export keys of a suite (OTEL-EVIDENCE-EXPORT-1, OE1-010)."""
    with safe_artifact_path(root, value).open("rb") as source:
        return load_export_keys(source.read(MAX_TRUST_POLICY_BYTES + 1))


def evidence_bundle_findings(
    root: Path, vector: dict[str, Any], value: object, scopes: dict[str, Any] | None = None
) -> tuple[str, list[str]]:
    """Verify a signed bundle (EBMP-2 section 11) and return its verdict and its identifiers, in
    the order of EBMP2-068 with the primary finding first.

    An invalid bundle yields the codes of its findings. An incomplete one without findings yields
    the causal-closure code. A current-trust-failed one yields the current statuses that are not
    valid, so that the vector also names why the signer is not acceptable now (EBMP2-060). Every
    decision response must record its decision basis (DCMP2-053), and a vector that names
    `register_path` checks each basis against it. A vector that sets
    `accept_current_trust_failure` is verified with that acceptance (EBMP2-060); `scopes`, when
    given, receives the report's scope (EBMP2-076) and evidence levels (EBMP2-061) under the
    vector's identifier.
    """
    report = verify_bundle(
        value,  # type: ignore[arg-type]
        load_trust_policy(root, vector["trust_policy_path"]),
        now=vector["evaluated_at"],
        history=tuple(
            load_trust_policy(root, item) for item in vector["trust_policy_history_paths"]
        ),
        accept_current_trust_failure=vector.get("accept_current_trust_failure", False),
        require_trusted_time=vector.get("require_trusted_time", False),
        register=vector_register(root, vector),
    )
    if scopes is not None:
        scopes[vector["id"]] = {
            "scope": {
                "established": list(report.scope.established),
                "not_established": list(report.scope.not_established),
                "reasons": dict(sorted(report.scope.reasons.items())),
            },
            "effects": [
                {"action_id": item.action_id, "level": item.level} for item in report.effects
            ],
            # EBMP2-076: an incomplete report lists the predecessors it could not resolve. A
            # report without the member has none to compare.
            "unresolved_predecessor_ids": getattr(report, "unresolved_predecessor_ids", None),
        }
    return report.verdict, reported_identifiers(report)


def scope_matches(vector: dict[str, Any], observed: dict[str, Any] | None) -> bool:
    """Whether a bundle's reported scope, evidence levels and unresolved predecessors are those its
    vector names, when it names them (EBMP2-076, EBMP2-061): the scope lists and reasons exactly,
    for each listed action every reported level of its terminal effects, and the unresolved
    predecessor identifiers as a set."""
    if not {"expected_scope", "expected_effects", "expected_unresolved_predecessor_ids"} & set(
        vector
    ):
        return True
    if observed is None:
        return False
    if "expected_scope" in vector and observed["scope"] != vector["expected_scope"]:
        return False
    if "expected_unresolved_predecessor_ids" in vector:
        reported = observed.get("unresolved_predecessor_ids")
        if reported is None or set(reported) != set(vector["expected_unresolved_predecessor_ids"]):
            return False
    for expected in vector.get("expected_effects", []):
        levels = {
            item["level"]
            for item in observed["effects"]
            if item["action_id"] == expected["action_id"]
        }
        if levels != {expected["level"]}:
            return False
    return True


def vector_register(root: Path, vector: dict[str, Any]) -> dict[str, Any] | None:
    """The Consequential Action Register that an evidence-bundle or package vector names, if any."""
    if "register_path" not in vector:
        return None
    with safe_artifact_path(root, vector["register_path"]).open("rb") as source:
        return load_register(source.read(MAX_REGISTER_BYTES + 1))


def package_findings(root: Path, vector: dict[str, Any], value: bytes) -> tuple[str, list[str]]:
    """Verify an offline package (IE1-021, IE1-022) and return its verdict and its identifiers, in
    order with the primary finding first: the code of the first check of IE1-022 that fails, or
    the bundle's findings in the order of EBMP2-068; a current-trust-failed package adds the
    current statuses that are not valid, as for a bundle, and an incomplete one without findings
    yields the causal-closure code. The package's bundle is verified under the same caller inputs as an
    evidence-bundle vector's: the decision basis is required, and a vector that names
    `register_path` checks each basis against it.
    """
    report = verify_offline_package(
        value,
        load_trust_policy(root, vector["trust_policy_path"]),
        now=vector["evaluated_at"],
        history=tuple(
            load_trust_policy(root, item) for item in vector["trust_policy_history_paths"]
        ),
        accept_current_trust_failure=vector.get("accept_current_trust_failure", False),
        require_trusted_time=vector.get("require_trusted_time", False),
        register=vector_register(root, vector),
    )
    return report.verdict, reported_package_identifiers(report)


def observed_for_vector(
    root: Path,
    vector: dict[str, Any],
    *,
    schemas: dict[str, dict[str, Any]],
    schema_registry: Registry,
    semantics: SemanticValidator,
    trust_policy: TrustPolicy | None = None,
    verdicts: dict[str, str] | None = None,
    export_keys: dict[str, ExportKey] | None = None,
    scopes: dict[str, Any] | None = None,
) -> list[str]:
    path = root / vector["path"]
    stage = vector["stage"]
    if stage == "trust-policy":
        try:
            with path.open("rb") as source:
                TrustPolicy.load(source.read(MAX_TRUST_POLICY_BYTES + 1))
        except TrustPolicyError as exc:
            return [exc.code]
        return []
    if stage == "package":
        # The artifact is an archive, so the stage reads bytes, not strict JSON.
        verdict, codes = package_findings(root, vector, read_limited(path, MAX_PACKAGE_BYTES))
        if verdicts is not None:
            verdicts[vector["id"]] = verdict
        return codes
    # The Parse step applies the vector's declared limits when it states them (IE1-028), and
    # otherwise the reference's own; a file is read no further than one byte past the byte limit.
    limits = vector.get("strict_json_limits", {})
    try:
        value = loads_json_strict(
            read_limited(path, limits.get("max_bytes", MAX_JSON_BYTES)), **limits
        )
    except CanonicalizationError as exc:
        return [strict_failure_id(exc)]
    if stage == "strict-json":
        return []
    if stage == "canonical":
        digest = hashlib.sha256(canonicalize(value)).hexdigest()
        return (
            []
            if digest == vector["expected_canonical_sha256"]
            else ["ecl.error.canonicalization-mismatch.v1"]
        )
    if stage == "bundle":
        if not isinstance(value, dict) or not isinstance(value.get("records"), list):
            return ["ecl.error.schema-invalid.v1"]
        analysis = analyze_bundle(value["records"])
        found = sorted({item.rule_id for item in analysis.findings})
        # EBMP2-023/DW1-028: a bundle offered as complete whose closure recalculation leaves an
        # unresolved predecessor or open action fails, even when no rule names a defect.
        if not found and analysis.status != "complete":
            return ["ecl.error.causal-closure-incomplete.v1"]
        return found
    if stage == "evidence-bundle":
        verdict, codes = evidence_bundle_findings(root, vector, value, scopes)
        if verdicts is not None:
            verdicts[vector["id"]] = verdict
        return codes

    if not isinstance(value, dict):
        return ["ecl.error.schema-invalid.v1"]
    validator = schema_validator(
        schemas[vector["schema"]],
        registry=schema_registry,
        format_checker=ecl_format_checker(),
    )
    schema_errors = list(validator.iter_errors(value))
    if stage == "document":
        # A claim or assessment document: strict parsing, its declared schema, and the registered
        # semantic rules whose `applies_to` names its type, its `protocol` or the `$id` of its
        # schema. Of these documents only the work intent (ECL-WI-1) carries extensions, and the
        # extension rules apply to it; the register declarations rule applies to an action register
        # (ECL1N-0178).
        scoped = document_rules(root, value.get("protocol")) | document_rules(
            root, vector["schema"]
        )
        found = sorted(
            {item.rule_id for item in semantics.validate(value) if item.rule_id in scoped}
        )
        return (["ecl.error.schema-invalid.v1"] if schema_errors else []) + found
    if stage == "envelope":
        if schema_errors:
            return ["ecl.error.schema-invalid.v1"]
        if trust_policy is None:
            raise ValueError("envelope suite requires a caller-supplied trust-policy artifact")
        try:
            payload = decode_canonical_json_payload(value)
            at = (
                payload.get("issued_at")
                if payload.get("protocol") == "DCMP-2"
                else payload.get("observed_at")
            )
            if not isinstance(at, str):
                return ["ecl.error.schema-invalid.v1"]
            time_policy = (
                "ecl.time.issued-at.v1"
                if payload.get("protocol") == "DCMP-2"
                else "ecl.time.observed-at.v1"
            )
            verify_envelope(
                value,
                trust_policy.keyring(),
                trust_policy.verification_context(evaluated_at=at, time_policy=time_policy),
            )
        except IntegrityError as exc:
            return [exc.code]
        return []
    if stage == "binding":
        # A binding profile's checker reads only records its schema accepts.
        if schema_errors:
            return ["ecl.error.schema-invalid.v1"]
        return sorted({item.rule_id for item in binding_findings(value, export_keys=export_keys)})
    findings = (
        validate_safe_state_profile(value)
        if stage == "safe-state-profile"
        else semantics.validate(value)
    )
    semantic_ids = sorted({item.rule_id for item in findings})
    if stage == "semantic":
        return semantic_ids + (["ecl.error.schema-invalid.v1"] if schema_errors else [])
    return (["ecl.error.schema-invalid.v1"] if schema_errors else []) + semantic_ids


def verify_generated_vectors(root: Path) -> None:
    module = load_module(
        "generate_vectors_for_harness",
        root / FOUNDATION_GENERATOR,
    )
    generated, _manifest = module.build(root)
    stale = [
        relative.as_posix()
        for relative, expected in generated.items()
        if not (root / relative).is_file() or (root / relative).read_bytes() != expected
    ]
    if stale:
        raise ValueError(f"generated conformance vectors are stale: {stale}")


def manifest_paths(root: Path) -> list[Path]:
    return [
        root / "conformance/manifest.json",
        *sorted((root / "conformance/suites").glob("*/manifest.json")),
    ]


def rule_precedence(root: Path) -> dict[str, int]:
    entries = read_json(root / "registries/semantic-rules.json")["entries"]
    result: dict[str, int] = {}
    for item in entries:
        if item["status"] != "active":
            continue
        value = item.get("attributes", {}).get("precedence")
        if type(value) is not int or value < 0 or value in result.values() or item["id"] in result:
            raise ValueError("semantic precedence is missing, duplicate or invalid")
        result[item["id"]] = value
    return result


def select_findings(
    observed: list[str], precedence: dict[str, int], errors: set[str] | None = None
) -> tuple[str | None, list[str]]:
    findings = set(observed)
    error_ids = {"ecl.error.schema-invalid.v1"} | (errors or set())
    unknown = findings - set(precedence) - error_ids
    if unknown:
        raise ValueError(f"unregistered findings: {sorted(unknown)}")
    strict = findings & STRICT_RULES
    if strict:
        primary = min(strict, key=precedence.__getitem__)
    elif "ecl.error.schema-invalid.v1" in findings:
        primary = "ecl.error.schema-invalid.v1"
    elif findings & error_ids:
        reported = findings & error_ids
        if len(reported) != 1:
            raise ValueError(
                "ambiguous interface errors: a vector must have one loader or integrity error"
            )
        primary = next(iter(reported))
    elif findings:
        primary = min(findings, key=precedence.__getitem__)
    else:
        return None, []
    return primary, sorted(findings - {primary})


def select_bundle_finding(
    observed: list[str], precedence: dict[str, int], errors: set[str]
) -> tuple[str | None, list[str]]:
    """The primary finding of a signed bundle, alone or carried in an offline package: the first of
    its identifiers, which the verifier orders by EBMP2-068 (and a package's own checks by
    IE1-022). A bundle has no required secondary findings, so none is reported."""
    unknown = set(observed) - set(precedence) - errors - {"ecl.error.schema-invalid.v1"}
    if unknown:
        raise ValueError(f"unregistered findings: {sorted(unknown)}")
    return (observed[0] if observed else None), []


def registered_errors(root: Path) -> set[str]:
    return {
        item["id"]
        for item in read_json(root / "registries/error-codes.json")["entries"]
        if item["status"] == "active"
    }


def safe_artifact_path(root: Path, value: str) -> Path:
    path = Path(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != value
        or not (root / path).resolve().is_relative_to(root.resolve())
    ):
        raise ValueError("unsafe vector path")
    return root / path


def validate_manifest_coverage(root: Path, manifest: dict[str, Any] | list[dict[str, Any]]) -> None:
    manifests = [manifest] if isinstance(manifest, dict) else manifest
    schema = read_json(root / "schemas/ecl-conformance-vector-manifest-v3.schema.json")
    precedence = rule_precedence(root)
    errors = registered_errors(root)
    requirements = {
        item["requirement_id"]
        for item in read_json(root / "registries/requirements-compiled.json")["requirements"]
    }
    vectors: dict[str, dict[str, Any]] = {}
    suites: set[str] = set()
    paths: set[str] = set()
    shadowed: set[str] = set()
    for value in manifests:
        Draft202012Validator(schema).validate(value)
        if value["suite"] in suites:
            raise ValueError("duplicate suite")
        suites.add(value["suite"])
        if any(v["stage"] == "envelope" for v in value["vectors"]):
            if "trust_policy_path" not in value:
                raise ValueError("envelope suite requires trust_policy_path")
            safe_artifact_path(root, value["trust_policy_path"])
        if "export_keys_path" in value:
            safe_artifact_path(root, value["export_keys_path"])
        for vector in value["vectors"]:
            safe_artifact_path(root, vector["path"])
            if vector["stage"] in ("evidence-bundle", "package"):
                for item in [vector["trust_policy_path"], *vector["trust_policy_history_paths"]]:
                    safe_artifact_path(root, item)
                if vector["expected_secondary_ids"]:
                    raise ValueError(
                        "a signed bundle has no required secondary findings (EBMP2-068)"
                    )
                if (vector["expected"] == "pass") != (vector["expected_verdict"] == "verified"):
                    raise ValueError(
                        f"an {vector['stage']} vector passes exactly when it is verified"
                    )
            if vector["id"] in vectors or vector["path"] in paths:
                raise ValueError("duplicate vector id or path")
            vectors[vector["id"]] = vector
            paths.add(vector["path"])
            secondary = vector["expected_secondary_ids"]
            if (
                secondary != sorted(set(secondary))
                or vector.get("expected_primary_id") in secondary
            ):
                raise ValueError(
                    "secondary findings must be sorted, unique and exclude the primary"
                )
            if set(vector["requirement_ids"]) - requirements:
                raise ValueError("vector manifest references unknown requirements")
            if vector["expected"] == "fail" and (
                not vector.get("negates") or set(vector["negates"]) - set(vector["requirement_ids"])
            ):
                raise ValueError(
                    "a failing vector must name the requirements it negates among its own"
                )
            select_findings(
                [
                    *secondary,
                    *([vector["expected_primary_id"]] if "expected_primary_id" in vector else []),
                ],
                precedence,
                errors,
            )
    for value in manifests:
        for item in value.get("schema_shadowed_rules", []):
            vector = vectors.get(item["vector"])
            if (
                item["rule"] in shadowed
                or item["rule"] not in precedence
                or vector is None
                or vector.get("expected_primary_id") != "ecl.error.schema-invalid.v1"
                or item["rule"] not in vector["expected_secondary_ids"]
                or not item["justification"].strip()
            ):
                raise ValueError("invalid schema-shadowed rule witness")
            shadowed.add(item["rule"])
    exercised = {v.get("expected_primary_id") for v in vectors.values() if v["expected"] == "fail"}
    unexercised = set(precedence) - exercised - shadowed
    if unexercised:
        raise ValueError(f"semantic rules lack negative vectors: {sorted(unexercised)}")


def result_section(suite: str, results: list[dict[str, Any]]) -> dict[str, Any]:
    passed = sum(item["decision"] == "pass" for item in results)
    return {
        "suite": suite,
        "decision": "pass" if passed == len(results) else "fail",
        "vector_count": len(results),
        "passed_vector_count": passed,
        "failed_vector_count": len(results) - passed,
        "results": results,
    }


def run(root: Path) -> dict[str, Any]:
    if (root / FOUNDATION_GENERATOR).is_file():
        verify_generated_vectors(root)
    manifests = [read_json(path) for path in manifest_paths(root)]
    validate_manifest_coverage(root, manifests)
    precedence = rule_precedence(root)
    errors = registered_errors(root)
    schemas, registry = schema_environment(root)
    extensions = read_json(root / "registries/extensions.json")
    semantics = SemanticValidator(
        (item["id"] for item in extensions["entries"]),
        extension_value_validators(extensions["entries"]),
        allocated_versions=allocated_extension_versions(extensions["entries"]),
        composable=composable_extensions(extensions["entries"]),
        active_versions=active_extension_versions(extensions["entries"]),
    )
    sections: list[dict[str, Any]] = []
    all_results: list[dict[str, Any]] = []
    for manifest in manifests:
        results: list[dict[str, Any]] = []
        trust_policy = None
        if "trust_policy_path" in manifest:
            trust_policy = load_trust_policy(root, manifest["trust_policy_path"])
        export_keys = None
        if "export_keys_path" in manifest:
            export_keys = load_suite_export_keys(root, manifest["export_keys_path"])
        for vector in manifest["vectors"]:
            verdicts: dict[str, str] = {}
            scopes: dict[str, Any] = {}
            observed = observed_for_vector(
                root,
                vector,
                schemas=schemas,
                schema_registry=registry,
                semantics=semantics,
                trust_policy=trust_policy,
                verdicts=verdicts,
                export_keys=export_keys,
                scopes=scopes,
            )
            if vector["stage"] in ("evidence-bundle", "package"):
                primary, secondaries = select_bundle_finding(observed, precedence, errors)
            else:
                primary, secondaries = select_findings(observed, precedence, errors)
            if vector["expected"] == "pass":
                decision = "pass" if primary is None else "fail"
            else:
                decision = (
                    "pass"
                    if primary == vector["expected_primary_id"]
                    and set(secondaries) == set(vector["expected_secondary_ids"])
                    else "fail"
                )
            # EBMP2-060 and IE1-022: an evidence-bundle or package vector also names the one verdict
            # it must receive.
            if (
                "expected_verdict" in vector
                and verdicts.get(vector["id"]) != vector["expected_verdict"]
            ):
                decision = "fail"
            # EBMP2-076 and EBMP2-061: a vector that names the scope or the evidence levels of its
            # verdict passes only with them.
            if not scope_matches(vector, scopes.get(vector["id"])):
                decision = "fail"
            results.append(
                {
                    "id": vector["id"],
                    "decision": decision,
                    "expected": vector["expected"],
                    "observed_primary_id": primary,
                    "observed_secondary_ids": secondaries,
                    "artifact_sha256": sha256_file(root / vector["path"]),
                }
            )
        all_results.extend(results)
        sections.append(result_section(manifest["suite"], results))
    report = {
        "schema_version": "ecl_conformance_result_v2",
        "candidate_version": "1.0",
        **result_section("ecl-1-v1.0-conformance", all_results),
        "suites": sections,
    }
    Draft202012Validator(
        read_json(root / "schemas/ecl-conformance-result-v2.schema.json")
    ).validate(report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    destination = root / RESULT_PATH
    try:
        report = run(root)
        if args.check:
            if read_json(destination) != report:
                raise ValueError("conformance result is stale")
        elif not args.no_write:
            write_json(destination, report)
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        json.JSONDecodeError,
    ) as exc:
        print(f"conformance harness failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["decision"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
