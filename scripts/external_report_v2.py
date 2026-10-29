"""Verify exact current-candidate corpus/evidence binding without converting findings to passes.

The rules are those of conformance/EXTERNAL_IMPLEMENTATION_PROFILE.md. Each refusal names the
member or vector at fault and what the profile requires, so that a report can be corrected from
the message alone.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from ecl_verify.canonical import CanonicalizationError, load_json_strict

TreeReader = Callable[[Path], tuple[str, list[dict[str, Any]]]]

REPORT_SCHEMA = "schemas/ecl-cross-implementation-report-v2.schema.json"
RAW_RESULT_SCHEMA = "schemas/ecl-external-vector-raw-result-v2.schema.json"
RAW_RESULT_VERSION = "ecl_external_vector_raw_result_v2"
# The stage whose verification-time policy a report states when it declares the capability that
# evaluates the stage (IE1-023; conformance/README.md fixes the policy of each stage).
TIME_POLICY_STAGES = {
    "envelope-signature-verification": "envelope",
    "evidence-bundle-verification": "evidence-bundle",
    "offline-package-verification": "package",
}
# A capability that an implementation may declare only together with another: bundle verification
# applies the one-way rule of DCMP2-053 to each decision basis, and so do the
# AARM, ACS and MCP checkers to the decision responses that an exchange record holds (AB1-013,
# AC1-012, MG1-007); package verification verifies the evidence bundle that the package carries
# (IE1-022).
IMPLIED_CAPABILITIES = {
    "binding-basis-agreement-rule": "decision-basis-rule",
    "binding-profile-rules": "decision-basis-rule",
    "evidence-bundle-verification": "decision-basis-rule",
    "offline-package-verification": "evidence-bundle-verification",
}


def read(path: Path) -> dict[str, Any]:
    value = load_json_strict(path)
    if not isinstance(value, dict):
        raise ValueError("external report artifact root must be an object")
    return value


def location(error: ValidationError) -> str:
    """The JSON Pointer of the member a schema error concerns, `/` for the whole value."""
    return "/" + "/".join(str(part) for part in error.absolute_path)


def first_schema_error(validator: Draft202012Validator, value: object) -> ValidationError | None:
    errors = sorted(validator.iter_errors(value), key=lambda item: [str(p) for p in item.path])
    return errors[0] if errors else None


def raw_result_problem(
    raw_path: Path,
    row: dict[str, Any],
    revision: str,
    validator: Draft202012Validator,
) -> str | None:
    """Why an evidence file is not the raw result of `row`, or None when it is.

    The file holds any JSON text that the strict parser accepts (UTF-8 without a byte order mark,
    no repeated member name, integers only in the exact range); its value must be the object of
    exactly three members that the profile describes.
    """
    try:
        raw = load_json_strict(raw_path)
    except CanonicalizationError as error:
        return f"the raw result is not strict JSON: {error}"
    problem = first_schema_error(validator, raw)
    if problem is not None:
        return (
            f"the raw result does not satisfy external-vector-raw-result/2 at "
            f"{location(problem)}: {problem.message[:200]}"
        )
    if raw["implementation_revision"] != revision:
        return (
            f"raw evidence differs from report row: implementation_revision is "
            f"{raw['implementation_revision']!r}, not implementation.source_revision {revision!r}"
        )
    bound = {key: value for key, value in row.items() if key != "raw_result_sha256"}
    result = raw["result"]
    if result != bound:
        for key in sorted(set(bound) | set(result)):
            if key not in result:
                return f"raw evidence differs from report row: result lacks the row's {key}"
            if key not in bound:
                return f"raw evidence differs from report row: result has {key}, the row has not"
            if result[key] != bound[key]:
                return (
                    f"raw evidence differs from report row: result {key} is {result[key]!r}, "
                    f"the row's is {bound[key]!r}"
                )
    return None


def verify_v2(
    root: Path,
    report: dict[str, Any],
    *,
    evidence_root: Path | None,
    implementation_root: Path | None,
    source_tree: TreeReader,
    confined_file: Callable[[Path, str], Path],
    sha256_file: Callable[[Path], str],
) -> dict[str, Any]:
    error = first_schema_error(Draft202012Validator(read(root / REPORT_SCHEMA)), report)
    if error is not None:
        raise ValueError(
            f"the report does not satisfy cross-implementation-report/2 at {location(error)}: "
            f"{error.message[:200]}"
        )
    if report["decision"] == "not_run":
        raise ValueError("not_run is an unexecuted draft, not replay evidence")
    if report["network_used"] or evidence_root is None or implementation_root is None:
        raise ValueError("network-free report needs source and evidence roots")
    implementation = report["implementation"]
    if (
        any(
            implementation[key] == "UNASSIGNED"
            for key in (
                "name",
                "version",
                "source_repository",
                "source_revision",
                "language",
                "runtime",
                "maintainer",
            )
        )
        or not implementation["relationship_disclosure"].strip()
    ):
        raise ValueError("external implementation provenance is unassigned")
    tree_hash, tree_entries = source_tree(implementation_root)
    if implementation["source_tree_sha256"] != tree_hash:
        raise ValueError("external implementation source-tree digest mismatch")
    corpus_path = root / "conformance/shared-corpus.json"
    corpus = read(corpus_path)
    required, optional = set(corpus["required_capabilities"]), set(corpus["optional_capabilities"])
    capabilities = set(implementation["capabilities"])
    if not required <= capabilities or not capabilities <= required | optional:
        raise ValueError("required or undeclared capability")
    for declared, implied in sorted(IMPLIED_CAPABILITIES.items()):
        if declared in capabilities and implied not in capabilities:
            raise ValueError(f"an implementation that declares {declared} also declares {implied}")
    stated = set(report["time_policies"])
    due = {stage for capability, stage in TIME_POLICY_STAGES.items() if capability in capabilities}
    if stated != due:
        raise ValueError(
            "time_policies must state exactly the stages the implementation evaluates: "
            f"expected {sorted(due)}, found {sorted(stated)}"
        )
    if (
        report["suite"]["manifest_sha256"] != sha256_file(corpus_path)
        or report["suite"]["corpus_version"] != corpus["version"]
    ):
        raise ValueError("external corpus digest/version mismatch")
    if report["suite"]["vector_count"] != len(corpus["vectors"]):
        raise ValueError("external vector count mismatch")
    vectors: dict[str, dict[str, Any]] = {}
    for path in (
        root / "conformance/manifest.json",
        *sorted((root / "conformance/suites").glob("*/manifest.json")),
    ):
        manifest = read(path)
        for vector in manifest["vectors"]:
            if vector["id"] in vectors:
                raise ValueError("manifest vector identifiers repeat")
            vectors[vector["id"]] = {**vector, "suite": manifest["suite"]}
    declarations = {row["id"]: row for row in corpus["vectors"]}
    results = {row["id"]: row for row in report["vector_results"]}
    if (
        len(results) != len(report["vector_results"])
        or set(results) != set(declarations)
        or set(results) != set(vectors)
    ):
        raise ValueError("external result set differs from complete corpus")
    evidence = report["evidence"]
    if len(evidence) > 100_000 or len({row["path"] for row in evidence}) != len(evidence):
        raise ValueError("external evidence count/path violation")
    bound: dict[str, Path] = {}
    total = 0
    for row in evidence:
        path = confined_file(evidence_root, row["path"])
        total += path.stat().st_size
        if total > 4 * 1024**3 or sha256_file(path) != row["sha256"]:
            raise ValueError("external evidence byte budget or digest mismatch")
        bound[row["sha256"]] = path
    raw_validator = Draft202012Validator(read(root / RAW_RESULT_SCHEMA))
    seen: set[str] = set()
    failed: list[str] = []
    unsupported: list[str] = []
    for identifier, row in results.items():
        vector, declaration = vectors[identifier], declarations[identifier]
        if (
            row["artifact_sha256"] != sha256_file(confined_file(root, vector["path"]))
            or row["expected"] != vector["expected"]
            or row["suite"] != vector["suite"]
        ):
            raise ValueError(identifier + ": vector artifact/class/suite mismatch")
        capability = declaration["capability"]
        if row["status"] == "unsupported":
            if (
                capability not in optional
                or capability in capabilities
                or row["unsupported_capability"] != capability
            ):
                raise ValueError(identifier + ": unsupported required or declared capability")
            unsupported.append(identifier)
        else:
            if capability not in capabilities:
                raise ValueError(identifier + ": evaluation for undeclared capability")
            primary = row["observed_primary_id"]
            secondary = row["observed_secondary_ids"]
            if (primary is None and secondary) or primary in secondary:
                raise ValueError(identifier + ": findings require one distinct primary")
            met = (
                primary is None and not row["observed_secondary_ids"]
                if vector["expected"] == "pass"
                else primary == vector["expected_primary_id"]
            )
            if (row["status"] == "met") != met:
                raise ValueError(identifier + ": status does not match actual primary result")
            if not met:
                failed.append(identifier)
        raw_hash = row["raw_result_sha256"]
        if raw_hash in seen or raw_hash not in bound:
            raise ValueError(identifier + ": raw result is absent or reused")
        seen.add(raw_hash)
        problem = raw_result_problem(
            bound[raw_hash], row, implementation["source_revision"], raw_validator
        )
        if problem is not None:
            raise ValueError(f"{identifier}: {problem}")
    if report["decision"] != ("fail" if failed else "pass"):
        raise ValueError("external decision does not retain failed vectors")
    return {
        "schema_version": "ecl_external_implementation_verification_v2",
        "candidate_version": "1.0",
        "decision": "verified-report-integrity",
        "replay_decision": report["decision"],
        "not_met_vectors": sorted(failed),
        "unsupported_optional_vectors": sorted(unsupported),
        "vector_count": len(results),
        "verified_raw_result_count": len(seen),
        "implementation_source_file_count": len(tree_entries),
        "corpus_sha256": hashlib.sha256(corpus_path.read_bytes()).hexdigest(),
        "claim_boundary": report["claim_boundary"],
    }
