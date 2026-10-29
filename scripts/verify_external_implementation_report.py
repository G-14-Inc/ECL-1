#!/usr/bin/env python3
"""Verify the report of an ECL implementation's frozen-suite replay (the report profile)."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError


ROOT = Path(__file__).resolve().parents[1]
# The Python verifier (packages/ecl-verify), when it is not installed in the environment.
sys.path.insert(0, str(ROOT / "packages" / "ecl-verify" / "src"))
sys.path.insert(0, str(ROOT))

from scripts.external_report_v2 import verify_v2  # noqa: E402

from ecl_verify.canonical import MAX_JSON_BYTES, load_json_strict  # noqa: E402
from ecl_verify.offline import safe_relative_path  # noqa: E402

MAX_BOUND_FILE_BYTES = 512 * 1024 * 1024
MAX_BOUND_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_BOUND_FILE_COUNT = 100_000


def read_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> dict[str, Any]:
    """Read one bounded strict-JSON object without first loading an unbounded file."""

    value = load_json_strict(path, max_bytes=max_bytes)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: root must be an object")
    return value


def sha256_file(path: Path) -> str:
    expected_size = path.stat().st_size
    if expected_size > MAX_BOUND_FILE_BYTES:
        raise ValueError(f"bound file exceeds verifier budget: {path}")
    digest = hashlib.sha256()
    observed_size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            observed_size += len(chunk)
            if observed_size > MAX_BOUND_FILE_BYTES:
                raise ValueError(f"bound file exceeds verifier budget: {path}")
            digest.update(chunk)
    if observed_size != expected_size or path.stat().st_size != expected_size:
        raise ValueError(f"bound file changed during verification: {path}")
    return digest.hexdigest()


def source_tree(root: Path) -> tuple[str, list[dict[str, Any]]]:
    """Digest an exact, clean source export without VCS metadata."""

    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("external implementation root is not a directory")
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    visited_count = 0
    for path in root.rglob("*"):
        visited_count += 1
        if visited_count > MAX_BOUND_FILE_COUNT * 2:
            raise ValueError(
                "external implementation tree exceeds verifier budget"
            )
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError(
                f"external implementation source contains a symlink: {relative}"
            )
        if ".git" in path.parts:
            raise ValueError(
                "external implementation source must be a clean export "
                "without .git metadata"
            )
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(
                f"external implementation source is not a regular file: {relative}"
            )
        safe_relative_path(relative)
        total_bytes += path.stat().st_size
        if total_bytes > MAX_BOUND_TOTAL_BYTES:
            raise ValueError(
                "external implementation tree exceeds verifier byte budget"
            )
        entries.append(
            {
                "path": relative,
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    if not entries:
        raise ValueError("external implementation source tree is empty")
    if len(entries) > MAX_BOUND_FILE_COUNT:
        raise ValueError("external implementation tree exceeds verifier file budget")
    entries.sort(key=lambda item: item["path"].encode("utf-8"))
    encoded = json.dumps(
        entries,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), entries


def confined_file(root: Path, relative: str) -> Path:
    root = root.resolve(strict=True)
    safe = safe_relative_path(relative)
    current = root
    for part in safe.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"evidence path traverses a symlink: {relative}")
    resolved = current.resolve(strict=True)
    if root not in resolved.parents or not resolved.is_file():
        raise ValueError(
            f"evidence path escapes its root or is not a file: {relative}"
        )
    return resolved


def verify(
    root: Path,
    report: dict[str, Any],
    *,
    evidence_root: Path | None = None,
    implementation_root: Path | None = None,
) -> dict[str, Any]:
    if report.get("schema_version") == "ecl_cross_implementation_report_v2":
        return verify_v2(root, report, evidence_root=evidence_root, implementation_root=implementation_root, source_tree=source_tree, confined_file=confined_file, sha256_file=sha256_file)
    schema = read_json(
        root / "schemas" / "ecl-cross-implementation-report-v1.schema.json"
    )
    Draft202012Validator(schema).validate(report)
    if report["decision"] != "pass":
        raise ValueError("external implementation report is not a passing run")
    if report["network_used"]:
        raise ValueError("external implementation run used a network dependency")

    implementation = report["implementation"]
    if any(
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
    ):
        raise ValueError("external implementation provenance is unassigned")
    if implementation["source_tree_sha256"] == "0" * 64:
        raise ValueError("external implementation source digest is a placeholder")
    if evidence_root is None or implementation_root is None:
        raise ValueError(
            "passing external reports require evidence-root and "
            "implementation-root"
        )
    observed_tree_digest, source_entries = source_tree(implementation_root)
    if implementation["source_tree_sha256"] != observed_tree_digest:
        raise ValueError("external implementation source-tree digest mismatch")

    manifest_path = root / "conformance" / "manifest.json"
    manifest = read_json(manifest_path)
    suite = report["suite"]
    if suite["id"] != manifest["suite"]:
        raise ValueError("external implementation suite identifier mismatch")
    if suite["manifest_sha256"] != sha256_file(manifest_path):
        raise ValueError("external implementation manifest digest mismatch")
    if suite["vector_count"] != len(manifest["vectors"]):
        raise ValueError("external implementation vector count mismatch")

    results = {item["id"]: item for item in report["vector_results"]}
    if len(results) != len(report["vector_results"]):
        raise ValueError("external implementation result identifiers repeat")
    expected = {item["id"]: item for item in manifest["vectors"]}
    if set(results) != set(expected):
        missing = sorted(set(expected) - set(results))
        extra = sorted(set(results) - set(expected))
        raise ValueError(
            f"external implementation result set mismatch; missing={missing}, "
            f"extra={extra}"
        )
    for identifier, vector in expected.items():
        result = results[identifier]
        artifact = root / vector["path"]
        if result["artifact_sha256"] != sha256_file(artifact):
            raise ValueError(f"{identifier}: vector artifact digest mismatch")
        if result["expected"] != vector["expected"]:
            raise ValueError(f"{identifier}: expected class mismatch")
        required_ids = set(vector["expected_primary_ids"])
        if not required_ids.issubset(set(result["observed_primary_ids"])):
            raise ValueError(f"{identifier}: intended primary result is absent")
        if vector["expected"] == "pass" and result["observed_primary_ids"]:
            raise ValueError(f"{identifier}: passing vector reported findings")
        if not result["expectation_met"]:
            raise ValueError(f"{identifier}: expectation was not met")
        if result["raw_result_sha256"] == "0" * 64:
            raise ValueError(f"{identifier}: raw-result digest is a placeholder")

    evidence = report["evidence"]
    if not evidence:
        raise ValueError("external implementation evidence set is empty")
    if any(item["sha256"] == "0" * 64 for item in evidence):
        raise ValueError("external implementation evidence uses a placeholder digest")
    if len(evidence) > MAX_BOUND_FILE_COUNT:
        raise ValueError("external implementation evidence exceeds verifier budget")
    evidence_paths = [item["path"] for item in evidence]
    if len(evidence_paths) != len(set(evidence_paths)):
        raise ValueError("external implementation evidence paths repeat")
    verified_evidence: dict[str, str] = {}
    evidence_by_digest: dict[str, list[Path]] = {}
    evidence_bytes = 0
    for item in evidence:
        path = confined_file(evidence_root, item["path"])
        evidence_bytes += path.stat().st_size
        if evidence_bytes > MAX_BOUND_TOTAL_BYTES:
            raise ValueError(
                "external implementation evidence exceeds verifier byte budget"
            )
        actual = sha256_file(path)
        if actual != item["sha256"]:
            raise ValueError(
                f"external implementation evidence digest mismatch: {item['path']}"
            )
        verified_evidence[item["path"]] = actual
        evidence_by_digest.setdefault(actual, []).append(path)
    evidence_digests = set(verified_evidence.values())
    missing_raw_results = sorted(
        identifier
        for identifier, result in results.items()
        if result["raw_result_sha256"] not in evidence_digests
    )
    if missing_raw_results:
        raise ValueError(
            "raw vector results are not bound to verified evidence files: "
            f"{missing_raw_results}"
        )
    raw_schema = read_json(
        root / "schemas" / "ecl-external-vector-raw-result-v1.schema.json"
    )
    raw_digests = [item["raw_result_sha256"] for item in results.values()]
    if len(raw_digests) != len(set(raw_digests)):
        raise ValueError(
            "per-vector raw-result digests must be distinct and vector-bound"
        )
    for identifier, result in results.items():
        raw_path = evidence_by_digest[result["raw_result_sha256"]][0]
        raw = read_json(raw_path)
        Draft202012Validator(raw_schema).validate(raw)
        expected_raw = {
            "schema_version": "ecl_external_vector_raw_result_v1",
            "suite_id": suite["id"],
            "vector_id": identifier,
            "implementation_revision": implementation["source_revision"],
            "artifact_sha256": result["artifact_sha256"],
            "expected": result["expected"],
            "observed_primary_ids": result["observed_primary_ids"],
            "expectation_met": result["expectation_met"],
        }
        if raw != expected_raw:
            raise ValueError(
                f"{identifier}: raw result does not match the signed-off report row"
            )

    return {
        "schema_version": "ecl_external_implementation_verification_v1",
        "candidate_version": "1.0-rc.3",
        "decision": "pass",
        "implementation": implementation["name"],
        "implementation_revision": implementation["source_revision"],
        "manifest_sha256": suite["manifest_sha256"],
        "vector_count": len(results),
        "implementation_source_file_count": len(source_entries),
        "verified_evidence_file_count": len(verified_evidence),
        "verified_raw_result_count": len(results),
        "claim_boundary": report["claim_boundary"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--implementation-root", type=Path)
    args = parser.parse_args()
    try:
        result = verify(
            args.root.resolve(),
            read_json(args.report.resolve()),
            evidence_root=(
                args.evidence_root.resolve()
                if args.evidence_root is not None
                else None
            ),
            implementation_root=(
                args.implementation_root.resolve()
                if args.implementation_root is not None
                else None
            ),
        )
    except ValidationError as exc:
        where = "/" + "/".join(str(part) for part in exc.absolute_path)
        print(f"external implementation verification failed: schema at {where}: {exc.message}", file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print(f"external implementation verification failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
