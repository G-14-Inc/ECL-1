"""Source derivation, review identity and document-fixture regressions.

Robert F. Tilley Jr.; G-14, Inc.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
from scripts import compile_rc3_requirements as requirements
from scripts import compile_rc3_registries as registries
from scripts import generate_document_vectors as documents
from scripts.run_conformance import observed_for_vector, schema_environment
from ecl_verify import __build__, __version__
from ecl_verify.bundle_verification import report_to_json, verify_bundle
from ecl_verify.resources import extension_value_validators
from ecl_verify.semantic import SemanticValidator, active_extension_versions, allocated_extension_versions, composable_extensions
from ecl_verify.trust import TrustPolicy
import l1_path
import render_spec_html as render
import spec_index

CORRECTIONS = json.loads((ROOT / "tests/fixtures/document-digest-repairs/corrections.json").read_bytes())["corrections"]
PATHS = sorted({row["path"] for row in CORRECTIONS})
CASES = [row for row in json.loads((ROOT / "conformance/suites/document-coverage/manifest.json").read_bytes())["vectors"] if row["path"] in PATHS]


def pointer(value, path):
    for part in path.split("/")[1:]:
        part = part.replace("~1", "/").replace("~0", "~")
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


@pytest.mark.parametrize("path", PATHS)
def test_exact_document_digest_corrections(path):
    value = json.loads((ROOT / path).read_bytes())
    for row in CORRECTIONS:
        if row["path"] == path:
            assert pointer(value, row["pointer"]) == row["after"]


def test_document_digest_algorithm_lengths_and_generator():
    assert len(CORRECTIONS) == 139 and len(PATHS) == 25
    def walk(value):
        if isinstance(value, dict):
            if value.get("algorithm") == "ecl.digest.sha-256.v1":
                assert re.fullmatch(r"[0-9a-f]{64}", value["value"]), value
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    for path in (ROOT / "conformance/suites/document-coverage").glob("*.json"):
        walk(json.loads(path.read_bytes()))
    for path, content in documents.build(ROOT).items():
        assert (ROOT / path).read_bytes() == content, path
    assert len(documents.digest("e1")["value"]) == 64


@pytest.fixture(scope="module")
def environment():
    schemas, schema_registry = schema_environment(ROOT)
    entries = json.loads((ROOT / "registries/extensions.json").read_bytes())["entries"]
    semantics = SemanticValidator(
        (item["id"] for item in entries), extension_value_validators(entries),
        allocated_versions=allocated_extension_versions(entries),
        composable=composable_extensions(entries), active_versions=active_extension_versions(entries),
    )
    return {"schemas": schemas, "schema_registry": schema_registry, "semantics": semantics}


@pytest.mark.parametrize("case", CASES, ids=lambda row: row["id"])
def test_document_targeted_results_preserved(case, environment):
    found = observed_for_vector(ROOT, case, **environment)
    expected = [] if case["expected"] == "pass" else [case["expected_primary_id"], *case.get("expected_secondary_ids", [])]
    assert found == expected


def test_software_identity_matches_packages_and_review_descriptor():
    descriptor = render.build_descriptor(ROOT)
    assert __version__ == "1.0.2a1" and __build__ == descriptor["source_version"] == "1.0.2-review.1"
    assert f'version = "{__version__}"' in (ROOT / "packages/ecl-verify/pyproject.toml").read_text(encoding="utf-8")
    assert f'name = "ecl-verify"\nversion = "{__version__}"' in (ROOT / "packages/ecl-verify/uv.lock").read_text(encoding="utf-8")
    package = json.loads((ROOT / "packages/ecl-ts/package.json").read_bytes())
    lock = json.loads((ROOT / "packages/ecl-ts/package-lock.json").read_bytes())
    assert package["version"] == lock["version"] == lock["packages"][""]["version"] == __build__
    policy = TrustPolicy.load((ROOT / "conformance/fixtures/evidence/trust-policy.json").read_bytes())
    report = report_to_json(verify_bundle({}, policy, now="2026-10-01T00:00:00Z"))
    assert report["software"] == {"name": "ecl-verify", "version": __version__, "source_build": __build__}
    assert report["response_clock_skew_seconds"] == 0


def test_version_set_binds_current_source_bytes_and_preserves_wire_versions():
    value = json.loads((ROOT / "release/VERSION_SET.json").read_bytes())
    for entry in [value["standard"], *value["companions"], value["reference_package"], *value["software_packages"]]:
        assert entry["source_sha256"] == hashlib.sha256((ROOT / entry["path"]).read_bytes()).hexdigest()
        if "wire_schema" in entry:
            assert entry["wire_schema_sha256"] == hashlib.sha256((ROOT / entry["wire_schema"]).read_bytes()).hexdigest()
            assert entry["version"] == entry["wire_schema_version"] == "2.0"
    assert value["standard"]["version"] == value["candidate_version"] == "1.0"
    assert value["release"]["descriptor_sha256"] == hashlib.sha256((ROOT / value["release"]["descriptor"]).read_bytes()).hexdigest()
    assert value["release"]["status"] == "public-review-local-candidate"


def test_continuations_include_all_prose_and_table_without_duplicate_id(tmp_path):
    source = tmp_path / "profile.md"
    source.write_text("# Profile\n\n**AB1-001** — A caller MUST bind the request.\n\n## Details\n\n**AB1-001 (continued)** — It MUST check the value.\n\n**AB1-001 (continued)** — The dependent rule is TS1-035.\n\n| Value | Meaning |\n| --- | --- |\n| a | a complete binding |\n\n**AB1-002** — It MAY stop.\n", encoding="utf-8", newline="\n")
    rows, orphans = requirements.extract(source, tmp_path)
    assert not orphans
    assert [row["requirement_id"] for row in rows] == ["AB1-001", "AB1-002"]
    assert "TS1-035" in rows[0]["text"] and "| a | a complete binding |" in rows[0]["text"]
    assert rows[0]["source_line"] == 3
    assert rows[0]["normative_forces"] == ["MUST"]


def test_unknown_continuation_is_refused(tmp_path):
    source = tmp_path / "profile.md"
    source.write_text("# Profile\n\n**AB1-001 (continued)** — It MUST bind.\n", encoding="utf-8", newline="\n")
    with pytest.raises(ValueError, match="earlier definition"):
        requirements.extract(source, tmp_path)


def test_l1_closure_follows_compiled_continuations_and_trust_dependencies(monkeypatch, tmp_path):
    def row(identifier, source, text):
        return spec_index.Requirement(identifier, source, "Section", text, ("MUST",), hashlib.sha256(text.encode()).hexdigest())
    rows = [row("ECL1N-0001", spec_index.STANDARD, "A claim MUST use INTEGRITY-ENVELOPE-1.\n\nTiming follows TS1-035 and TS1-036."),
            row("IE1-001", "protocols/INTEGRITY-ENVELOPE-1.md", "Verification MUST follow TRUST-POLICY-1."),
            row("TP1-001", "profiles/TRUST-POLICY-1.md", "Keys MUST be authorized."),
            row("TS1-035", "protocols/TIMING-SAFE-STATE-1.md", "Separate deadlines MUST be declared."),
            row("TS1-036", "protocols/TIMING-SAFE-STATE-1.md", "Bounds MUST name observation points.")]
    monkeypatch.setattr(spec_index, "requirements", lambda _: rows)
    monkeypatch.setattr(spec_index, "documents", lambda _: {spec_index.STANDARD: "Core", "protocols/INTEGRITY-ENVELOPE-1.md": "INTEGRITY-ENVELOPE-1", "profiles/TRUST-POLICY-1.md": "TRUST-POLICY-1", "protocols/TIMING-SAFE-STATE-1.md": "TIMING-SAFE-STATE-1"})
    monkeypatch.setattr(spec_index, "checklist", lambda _: [])
    assert {entry.requirement.identifier for entry in l1_path.derive(tmp_path).entries} == {row.identifier for row in rows}


@pytest.mark.parametrize("field,value", [("designation", "absent"), ("source_version", "unknown"), ("review_date", "2026-1-1"), ("publication_authorized", True)])
def test_renderer_refuses_unresolved_or_false_release_identity(tmp_path, field, value):
    (tmp_path / "release").mkdir()
    descriptor = json.loads((ROOT / render.STATUS).read_bytes())
    descriptor[field] = value
    (tmp_path / render.STATUS).write_text(json.dumps(descriptor), encoding="utf-8", newline="\n")
    with pytest.raises(ValueError):
        render.release_status(tmp_path)


def test_renderer_retains_source_hash_body_and_review_credits(tmp_path):
    (tmp_path / "release").mkdir()
    (tmp_path / render.STATUS).write_bytes((ROOT / render.STATUS).read_bytes())
    source = "# Sample\n\nA complete source body.\n"
    (tmp_path / "sample.md").write_text(source, encoding="utf-8", newline="\n")
    record = render.source_record(tmp_path, "sample.md")
    output, _, _ = render.render_document(source, {}, {}, {}, "sample.md", record)
    assert hashlib.sha256(source.encode()).hexdigest().encode() in output
    assert b"A complete source body." in output
    assert b"ECL-1 Version 1 public review" in output and b"2026-11-10" in output
    assert b"source 1.0.2-review.1" in output and b">absent<" not in output


def test_rendered_documents_bind_all_current_sources_and_unique_requirements():
    rows = json.loads((ROOT / "registries/requirements-compiled.json").read_bytes())["requirements"]
    for source in render.sources(ROOT):
        output = (ROOT / "render" / render.slug(source)).read_bytes()
        assert hashlib.sha256(source.read_bytes()).hexdigest().encode() in output
        assert source.relative_to(ROOT).as_posix().encode() in output
        assert b"ECL-1 Version 1 public review" in output
        assert b"source 1.0.2-review.1; review date 2026-11-10; local candidate" in output
        for row in rows:
            if row["source_path"] == source.relative_to(ROOT).as_posix():
                assert output.count(('id="' + row["requirement_id"] + '"').encode()) == 1
    index = (ROOT / "render/index.html").read_bytes()
    assert b"Robert F. Tilley Jr." in index and b"G-14, Inc." in index


def test_all_current_derived_registry_pointers_and_catalog_digests():
    values, report = registries.build(ROOT)
    assert report["decision"] == "pass"
    schema_by_id = {json.loads(path.read_bytes())["$id"]: json.loads(path.read_bytes()) for path in (ROOT / "schemas").glob("*.json")}
    fields = values[Path("registries/fields.json")]
    for field in fields["entries"]:
        if field["status"] == "active":
            at = field["attributes"]
            assert at["constraint_sha256"] == registries.digest_json(pointer(schema_by_id[at["schema_id"]], at["json_schema_pointer"]))
    for entry in values[Path("registries/registry-catalog.json")]["entries"]:
        path = Path(entry["attributes"]["source_path"])
        source = values[path] if path in values else json.loads((ROOT / path).read_bytes())
        matched = next(row for row in source["entries"] if row["id"] == entry["id"])
        assert entry["description"] == matched["description"]
        assert entry["attributes"]["entry_sha256"] == registries.digest_json(matched)
    all_terms = values[Path("registries/terms.json")]["entries"]
    terms = [term for term in all_terms if term["status"] == "active"]
    assert len(terms) == 78
    former = next(term for term in all_terms if term["id"] == "ecl.term.component-or-profile-implementation-claim.v1")
    assert former["status"] == "superseded"
    assert former["superseded_by"] == "ecl.term.component-or-profile-implementation-report.v1"
    assert former["introduced_in"] == "1.0-rc.3"
    assert former["attributes"]["superseded_in"] == "1.0.2-review.1"
    replacement = next(term for term in terms if term["id"] == former["superseded_by"])
    assert replacement["introduced_in"] == "1.0.2-review.1"
    for term in terms:
        at = term["attributes"]
        lines = (ROOT / at["source_path"]).read_text(encoding="utf-8").splitlines()
        marker = "**" + at["term"] + "**:"
        starts = [i for i, line in enumerate(lines) if line.startswith(marker)]
        assert starts == [at["source_line"] - 1], term["id"]
        start = starts[0]
        parts = [lines[start][len(marker):].strip()]
        for line in lines[start + 1:]:
            # A definition ends at the next term or heading, not at a paragraph break.
            if re.match(r"^(?:#{1,6}\s|\*\*[^*]+\*\*:)", line):
                break
            if line.strip():
                parts.append(line.strip())
        definition = " ".join(parts)
        assert term["description"] == definition
        assert at["definition_sha256"] == hashlib.sha256(definition.encode()).hexdigest()


def test_term_rename_requires_explicit_predecessor_retirement(monkeypatch):
    original = registries.declared_retirements
    monkeypatch.setattr(registries, 'declared_retirements', lambda root, versions=None: {key: value for key, value in original(root, versions).items() if key != 'terms'})
    with pytest.raises(ValueError, match='predecessor identities disappeared'):
        registries.compile_terms(ROOT)
