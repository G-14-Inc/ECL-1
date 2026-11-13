"""Legacy-format compatibility on synthetic historical-shaped local inputs.

The fixture is not an archived RC-3 execution or an authenticity claim. It
exercises the explicit legacy opt-in and its narrower report-binding contract.

Robert F. Tilley Jr.; G-14, Inc.
"""

import copy
import shutil

import pytest

from test_external_report_v3 import ROOT, digest, write
from scripts.verify_external_implementation_report import source_tree, verify


@pytest.fixture
def legacy_bound(tmp_path):
    root = tmp_path / "corpus"
    evidence = tmp_path / "evidence"
    implementation = tmp_path / "implementation"
    evidence.mkdir()
    implementation.mkdir()
    (implementation / "NOTICE.txt").write_text("Synthetic legacy-shape fixture; no historical run claimed.\n")
    for name in ("ecl-cross-implementation-report-v1.schema.json", "ecl-external-vector-raw-result-v1.schema.json"):
        target = root / "schemas" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "schemas" / name, target)
    (root / "conformance").mkdir()
    (root / "conformance/input.json").write_text("{}\n")
    manifest = {
        "schema_version": "ecl_conformance_vector_manifest_v1",
        "suite": "ecl-1-v1.0-rc.3-foundation",
        "vectors": [{"id": "synthetic-control", "path": "conformance/input.json", "expected": "pass", "expected_primary_ids": []}],
    }
    declared = {
        "name": "Synthetic legacy fixture", "version": "fixture", "source_repository": "local fixture",
        "source_revision": "synthetic-legacy-shape", "source_tree_sha256": source_tree(implementation)[0],
        "language": "fixture", "runtime": "no implementation executed", "maintainer": "fixture author",
        "relationship_disclosure": "Synthetic report, not an external review", "imports_ecl_reference": False,
    }
    row = {
        "id": "synthetic-control", "artifact_sha256": digest(root / "conformance/input.json"),
        "expected": "pass", "observed_primary_ids": [], "expectation_met": True, "raw_result_sha256": "",
    }
    report = {
        "schema_version": "ecl_cross_implementation_report_v1", "candidate_version": "1.0-rc.3",
        "profile_version": "1", "decision": "pass", "implementation": declared,
        "suite": {"id": manifest["suite"], "manifest_sha256": "", "vector_count": 1},
        "network_used": False, "vector_results": [row], "evidence": [], "limitations": [],
        "claim_boundary": "cross-implementation-replay-only-not-independent-assessment",
    }

    def bind():
        write(root / "conformance/manifest.json", manifest)
        report["suite"]["manifest_sha256"] = digest(root / "conformance/manifest.json")
        raw = {
            "schema_version": "ecl_external_vector_raw_result_v1", "suite_id": report["suite"]["id"],
            "vector_id": row["id"], "implementation_revision": declared["source_revision"],
            "artifact_sha256": row["artifact_sha256"], "expected": row["expected"],
            "observed_primary_ids": row["observed_primary_ids"], "expectation_met": row["expectation_met"],
        }
        write(evidence / "raw.json", raw)
        row["raw_result_sha256"] = digest(evidence / "raw.json")
        report["evidence"] = [{"path": "raw.json", "sha256": row["raw_result_sha256"]}]

    def check(**kwargs):
        return verify(root, report, evidence_root=evidence, implementation_root=implementation, **kwargs)

    bind()
    return root, manifest, report, bind, check


def test_legacy_matching_input_root_retains_historical_boundary(legacy_bound):
    root, manifest, report, bind, check = legacy_bound
    result = check(allow_legacy_v2=True)
    assert result["claim_boundary"] == "legacy-v1-rc3-suite-observations-unverified"
    assert result["vector_count"] == 1
    with pytest.raises(ValueError, match="version 1 bound the frozen RC-3 suite"):
        check()


def test_current_manifest_is_not_a_historical_manifest(legacy_bound):
    root, manifest, report, bind, check = legacy_bound
    # Retain the old suite ID to reach the missing historical-field guard.
    manifest["schema_version"] = "ecl_conformance_vector_manifest_v3"
    manifest["vectors"][0].pop("expected_primary_ids")
    manifest["vectors"][0]["expected_secondary_ids"] = []
    bind()
    with pytest.raises(ValueError, match="requires id, path, expected and distinct expected_primary_ids"):
        check(allow_legacy_v2=True)


@pytest.mark.parametrize("primary", [None, "not-an-array", [None], [""], ["a", "a"]])
def test_legacy_manifest_primary_shape_is_checked_before_comparison(legacy_bound, primary):
    root, manifest, report, bind, check = legacy_bound
    manifest["vectors"][0]["expected_primary_ids"] = primary
    bind()
    with pytest.raises(ValueError, match="distinct expected_primary_ids"):
        check(allow_legacy_v2=True)


@pytest.mark.parametrize("field,value", [("id", None), ("path", None), ("expected", "unknown")])
def test_legacy_manifest_required_comparison_fields_are_typed(legacy_bound, field, value):
    root, manifest, report, bind, check = legacy_bound
    manifest["vectors"][0][field] = value
    bind()
    with pytest.raises(ValueError, match="requires id, path, expected"):
        check(allow_legacy_v2=True)


def test_duplicate_manifest_vector_ids_cannot_collapse_to_one_result(legacy_bound):
    root, manifest, report, bind, check = legacy_bound
    manifest["vectors"].append(copy.deepcopy(manifest["vectors"][0]))
    report["suite"]["vector_count"] = 2
    bind()
    with pytest.raises(ValueError, match="manifest vector identifiers repeat"):
        check(allow_legacy_v2=True)


@pytest.mark.parametrize("mode", ["traversal", "absolute", "file-symlink", "directory-symlink"])
def test_legacy_artifacts_are_confined_without_symlink_traversal(legacy_bound, mode):
    root, manifest, report, bind, check = legacy_bound
    outside = root.parent / "outside"
    outside.mkdir()
    (outside / "input.json").write_text("{}\n")
    if mode == "traversal":
        relative = "../outside/input.json"
    elif mode == "absolute":
        relative = str(outside / "input.json")
    elif mode == "file-symlink":
        (root / "conformance/link.json").symlink_to(outside / "input.json")
        relative = "conformance/link.json"
    else:
        (root / "linked").symlink_to(outside, target_is_directory=True)
        relative = "linked/input.json"
    manifest["vectors"][0]["path"] = relative
    bind()
    with pytest.raises(ValueError, match="path|symlink"):
        check(allow_legacy_v2=True)


def test_legacy_nested_regular_artifact_is_valid(legacy_bound):
    root, manifest, report, bind, check = legacy_bound
    path = root / "conformance/nested/input.json"
    path.parent.mkdir()
    path.write_text("{}\n")
    manifest["vectors"][0]["path"] = path.relative_to(root).as_posix()
    bind()
    assert check(allow_legacy_v2=True)["vector_count"] == 1


@pytest.mark.parametrize("member", ["artifact_sha256", "raw_result_sha256"])
def test_legacy_opt_in_does_not_skip_exact_byte_bindings(legacy_bound, member):
    root, manifest, report, bind, check = legacy_bound
    report["vector_results"][0][member] = "f" * 64
    with pytest.raises(ValueError, match="digest mismatch|not bound"):
        check(allow_legacy_v2=True)
