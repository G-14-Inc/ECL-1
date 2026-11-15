"""Registry source discovery and allocation-reference boundaries.

Robert F. Tilley Jr.; G-14, Inc.
"""
import copy
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import compile_rc3_registries as registry

UNKNOWN = "ecl.error.unregistered-reference-probe.v1"


@pytest.fixture
def source(tmp_path):
    for folder in ("standard", "protocols", "profiles", "schemas", "registries"):
        (tmp_path / folder).mkdir()
        for path in (ROOT / folder).glob("*"):
            if path.is_file():
                shutil.copyfile(path, tmp_path / folder / path.name)
    for rel in ("packages/ecl-verify/src/ecl_verify/runtime.py", "packages/ecl-ts/src/runtime.ts", "go/crosscheck/runtime.go"):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('"ecl.error.schema-invalid.v1"\n')
    root = tmp_path / "conformance"
    root.mkdir()
    (root / "pass.json").write_text('{"id":"ecl.error.schema-invalid.v1"}\n')
    (root / "fail.json").write_text(json.dumps({"id": UNKNOWN}))
    (root / "manifest.json").write_text(json.dumps({"vectors": [
        {"id": "pass", "path": "conformance/pass.json", "expected": "pass"},
        {"id": "fail", "path": "conformance/fail.json", "expected": "fail"},
    ]}))
    (root / "suites/example").mkdir(parents=True)
    (root / "suites/example/pass.json").write_text('{}\n')
    (root / "suites/example/manifest.json").write_text(json.dumps({"vectors": [
        {"id": "suite-pass", "path": "conformance/suites/example/pass.json", "expected": "pass"},
    ]}))
    return tmp_path


@pytest.mark.parametrize("relative", [
    "profiles/MCP-GATEWAY-1.md", "packages/ecl-verify/src/ecl_verify/runtime.py",
    "packages/ecl-ts/src/runtime.ts", "go/crosscheck/runtime.go",
    "conformance/suites/example/pass.json",
])
def test_active_reference_sources_cannot_introduce_unallocated_tokens(source, relative):
    path = source / relative
    if path.suffix == ".json":
        path.write_text(json.dumps({"unallocated_reference": UNKNOWN}))
    else:
        path.write_text(path.read_text() + "\n" + UNKNOWN + "\n")
    with pytest.raises(ValueError, match="unallocated reserved ECL identifiers"):
        registry.build(source)


def test_source_registry_attributes_are_checked(source):
    path = source / "registries/operational-values.json"
    value = json.loads(path.read_bytes())
    value["entries"][0].setdefault("attributes", {})["rule_reference"] = UNKNOWN
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="unallocated reserved ECL identifiers"):
        registry.build(source)


@pytest.mark.parametrize("relative", ["profiles", "packages/ecl-verify/src/ecl_verify", "packages/ecl-ts/src", "go/crosscheck"])
def test_missing_required_source_directory_is_not_an_empty_pass(source, relative):
    shutil.rmtree(source / relative)
    with pytest.raises(ValueError, match="required reference source"):
        registry.build(source)


@pytest.mark.parametrize("target", [UNKNOWN, "https://externalcontrollayer.ai/ns/missing/successor", "ecl.test.retired-probe.v1"])
def test_supersession_target_is_allocated_and_distinct(source, target):
    path = source / "registries/operational-values.json"
    value = json.loads(path.read_bytes())
    value["entries"].append({"id": "ecl.test.retired-probe.v1", "status": "superseded", "owner_class": "ecl-standard", "introduced_in": "1.0.2-review.1", "compatibility": "behavioral", "description": "A retired test allocation.", "superseded_by": target})
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="superseded_by"):
        registry.build(source)


@pytest.mark.parametrize("uri", [False, True])
def test_allocated_successor_may_be_token_or_uri(source, uri):
    target = registry.compile_fields(source)["entries"][0]["id"] if uri else "ecl.error.schema-invalid.v1"
    path = source / "registries/operational-values.json"
    value = json.loads(path.read_bytes())
    value["entries"].append({"id": "ecl.test.retired-probe.v1", "status": "superseded", "owner_class": "ecl-standard", "introduced_in": "1.0.2-review.1", "compatibility": "behavioral", "description": "A retired test allocation.", "superseded_by": target})
    path.write_text(json.dumps(value))
    assert registry.build(source)[1]["decision"] == "pass"


def test_negative_fixtures_history_and_unit_tests_are_intentionally_outside_scan(source):
    for rel in ("registries/predecessor-example-history.json", "tests/unallocated.py", "go/crosscheck/probe_test.go", "packages/ecl-ts/src/probe.test.ts"):
        path = source / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"id": UNKNOWN}))
    assert registry.build(source)[1]["decision"] == "pass"


def test_example_and_legacy_exclusions_are_exact_pairs(source):
    cases = {
        "go/crosscheck/internal/strictjson/strictjson.go": "ecl.rule.json-syntax-valid.v1",
        "conformance/suites/safe-state-declaration-contract/safe-state-declaration-contract-distinct-classes-control.json": "ecl.action.test-distinct.v1",
    }
    manifest = source / "conformance/manifest.json"
    value = json.loads(manifest.read_bytes())
    for rel, token in cases.items():
        path = source / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"id": token}))
        if rel.endswith('.json'):
            value["vectors"].append({"id": rel, "path": rel, "expected": "pass"})
    manifest.write_text(json.dumps(value))
    assert registry.build(source)[1]["decision"] == "pass"
    for rel, token in cases.items():
        path = source / rel
        old = path.read_bytes()
        path.write_text(json.dumps({"id": token.replace('.v1', '-new.v1')}))
        try:
            with pytest.raises(ValueError, match="unallocated reserved ECL identifiers"):
                registry.build(source)
        finally:
            path.write_bytes(old)
    (source / "packages/ecl-verify/src/ecl_verify/runtime.py").write_text('"ecl.rule.json-syntax-valid.v1"')
    with pytest.raises(ValueError, match="unallocated reserved ECL identifiers"):
        registry.build(source)


def test_scan_report_discloses_schema_scope_and_binary_exclusion(source):
    path = source / "conformance/suites/example/manifest.json"
    value = json.loads(path.read_bytes())
    value["vectors"].append({"id": "binary", "path": "conformance/suites/example/package.zip", "expected": "pass"})
    path.write_text(json.dumps(value))
    (source / "conformance/suites/example/package.zip").write_bytes(b'PK\xff\x00')
    report = registry.build(source)[1]
    assert report["compiled_schema_count"] == 15
    assert len(report["compiled_schema_paths"]) == 15
    assert "schemas/ecl-binding-otel-export-v1.schema.json" in report["schemas_not_compiled_for_fields_or_wire_values"]
    assert report["reference_scan"]["unscanned_binary_artifacts"] == ["conformance/suites/example/package.zip"]
    assert report["reference_scan"]["source_file_count"] > 4


def test_current_registry_build_keeps_derived_identities_and_exposes_all_scope():
    values, report = registry.build(ROOT)
    assert report["decision"] == "pass"
    assert report["compiled_schema_count"] == len(registry.PROTOCOL_SCHEMAS)
    assert report["reference_scan"]["excluded_references"]
    assert report["referenced_ecl_identifier_count"] > 98
    assert any(row["path"] == "profiles/MCP-GATEWAY-1.md" for row in report["reference_scan"]["files"])
    assert all(row["reason"] for row in report["reference_scan"]["excluded_references"])


def test_json_escape_does_not_hide_an_unallocated_reference(source):
    path = source / "conformance/suites/example/pass.json"
    path.write_text('{"id":"\\u0065cl.error.unregistered-reference-probe.v1"}')
    with pytest.raises(ValueError, match="unallocated reserved ECL identifiers"):
        registry.build(source)


def test_term_definition_keeps_later_paragraphs_until_next_term(source):
    terms = registry.compile_terms(source)["entries"]
    term = next(row for row in terms if row["id"] == "ecl.term.strictness-order.v1")
    for phrase in ("condition for progress implies", "An absent deadline counts", "every human-approval threshold", "including when the compared values are incomparable"):
        assert phrase in term["description"]
    assert "Transaction-bound authority scoped" not in term["description"]
    old_hash = term["attributes"]["definition_sha256"]
    path = source / registry.CORE
    old = path.read_text()
    assert "An absent deadline\ncounts as later" in old
    path.write_text(old.replace("An absent deadline\ncounts as later", "An absent deadline\ncounts explicitly as later", 1))
    changed = next(row for row in registry.compile_terms(source)["entries"] if row["id"] == term["id"])
    assert changed["attributes"]["definition_sha256"] != old_hash


@pytest.mark.parametrize("token,refused", [(UNKNOWN, True), ("ecl.error.schema-invalid.v1", False)])
def test_deep_passing_json_needs_no_recursive_artifact_parse(source, token, refused):
    path = source / "conformance/suites/example/pass.json"
    path.write_text('[' * 4000 + json.dumps(token) + ']' * 4000)
    if refused:
        with pytest.raises(ValueError, match="unallocated reserved ECL identifiers"):
            registry.build(source)
    else:
        assert registry.build(source)[1]["decision"] == "pass"
