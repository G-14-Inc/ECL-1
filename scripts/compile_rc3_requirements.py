#!/usr/bin/env python3
"""Compile current requirements and fail on untagged normative prose.

Each requirement also receives one evaluation class, in this order of strength:
`vector-tested` when a failing conformance vector negates it; `reference-tested` when an
implementation group runs the reference implementation for it; `assessor-procedure` when only an
assessor's examination of the claimant's evidence can establish it; `self-declaration` when the
claimant's own declaration establishes it. Tests that only check that a declaration, a text or a
registry entry is present are traceability, not evaluation, and are reported apart.

The compiled registry and the evaluation catalog are public files: they name public vectors and
requirements only. References in the maintainer's legacy `tests.` namespace are written to
registries/requirements-internal-refs.json instead (decision V4 of 16 October 2026). Some such
tests are shipped with the verifier; others are absent from a public source export. The coverage
report states their availability in the source tree, without claiming test execution.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from jsonschema.exceptions import ValidationError
from referencing import Registry


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/ecl-verify/src"))
from ecl_verify.schema import ecl_format_checker  # noqa: E402
from ecl_verify.schema_patterns import schema_validator  # noqa: E402


def metadata_validator(schema: dict[str, Any]):
    return schema_validator(schema, registry=Registry(), format_checker=ecl_format_checker())

REQUIREMENT_RE = re.compile(
    r"^(?:\s*(?:[-+*]|\d+\.)\s+)?"
    r"\*\*([A-Z][A-Z0-9]{1,11}-[0-9]{3,5})\*\*\s+[—-]\s+(.*)$"
)
CONTINUATION_RE = re.compile(
    r"^\s*(?:(?:[-+*]|\d+\.)\s+)?"
    r"\*\*([A-Z][A-Z0-9]{1,11}-[0-9]{3,5}) \(continued\)\*\*\s+[—-]\s+(.*)$"
)
TABLE_REQUIREMENT_RE = re.compile(
    r"^\|\s*([A-Z][A-Z0-9]{1,11}-[0-9]{3,5})\s*\|.*\b"
    r"(MUST NOT|SHOULD NOT|SHALL NOT|NOT RECOMMENDED|MUST|SHOULD|SHALL|"
    r"REQUIRED|RECOMMENDED|MAY|OPTIONAL)\b"
)
FORCE_RE = re.compile(
    r"\b(MUST NOT|SHOULD NOT|SHALL NOT|NOT RECOMMENDED|MUST|SHOULD|SHALL|"
    r"REQUIRED|RECOMMENDED|MAY|OPTIONAL)\b"
)
# Lowercase phrasing that reads as an obligation, permission or prohibition. Outside a tagged
# requirement it hides a rule from the compiler, so it is an orphan as uppercase keywords are.
LOWERCASE_NORMATIVE_RE = re.compile(
    r"\b(must|shall|is required|are required|required on|is permitted only|"
    r"are permitted only|is prohibited|are prohibited|may not)\b"
)
HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*$")
LIST_RE = re.compile(r"^\s*(?:[-+*]|\d+\.)\s+")
EVALUATION_CLASSES = ("vector-tested", "reference-tested", "assessor-procedure", "self-declaration")
MAP_SCHEMA = Path("schemas/ecl-evaluation-implementation-map-v2.schema.json")
INTERNAL_REFS = Path("registries/requirements-internal-refs.json")


def is_internal(reference: str) -> bool:
    """A legacy test reference kept in the sidecar, independently of local availability."""
    return reference.startswith("tests.")


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: root must be an object")
    return value


def source_paths(root: Path) -> list[Path]:
    values = [root / "standard" / "ECL-1_Standard.md"]
    values.extend(
        path for path in sorted((root / "protocols").glob("*.md")) if path.name != "README.md"
    )
    values.extend(
        path
        for path in sorted((root / "profiles").glob("*.md"))
        if "Requirement-IDs: compiled" in path.read_text(encoding="utf-8").splitlines()[:10]
    )
    return values


def implementation_groups(root: Path) -> dict[str, list[dict[str, Any]]]:
    value = read_json(root / "conformance" / "evaluation-implementation-map.json")
    metadata_validator(read_json(root / MAP_SCHEMA)).validate(value)
    groups: dict[str, list[dict[str, Any]]] = {}
    seen_group_ids: set[str] = set()
    for group in value["groups"]:
        group_id = group["id"]
        if group_id in seen_group_ids:
            raise ValueError(f"duplicate evaluation implementation group: {group_id}")
        seen_group_ids.add(group_id)
        for requirement_id in group["requirement_ids"]:
            groups.setdefault(requirement_id, []).append(group)
    return groups


def implementation_traceability(root: Path) -> dict[str, list[str]]:
    """The maintainer's tests that trace a requirement without evaluating it, by requirement (the
    map's `traceability_refs`; implementation_groups validates the map)."""
    value = read_json(root / "conformance" / "evaluation-implementation-map.json")
    return {key: list(refs) for key, refs in (value.get("traceability_refs") or {}).items()}


# Where a test module named `tests.<module>` lives: the repository's tests, or the tests of the
# public verifier package, which moved there with the modules they test.
TEST_DIRECTORIES = ("tests", "packages/ecl-verify/tests")


def test_reference_exists(root: Path, reference: str) -> bool:
    """True for `tests.<module>.<Class>.<method>` or `tests.<module>.<function>` that exists."""
    parts = reference.split(".")
    if len(parts) not in (3, 4) or parts[0] != "tests":
        return False
    functions = (ast.FunctionDef, ast.AsyncFunctionDef)
    for folder in TEST_DIRECTORIES:
        path = root / folder / f"{parts[1]}.py"
        if not path.is_file():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if len(parts) == 3:
            if any(isinstance(node, functions) and node.name == parts[2] for node in tree.body):
                return True
        else:
            for node in tree.body:
                if isinstance(node, ast.ClassDef) and node.name == parts[2] and any(
                    isinstance(child, functions) and child.name == parts[3] for child in node.body
                ):
                    return True
    return False


def evaluation_class(negated: bool, groups: list[dict[str, Any]]) -> str | None:
    """The strongest evaluation a requirement has, or None when it has none."""
    if negated:
        return "vector-tested"
    declared = {group["evaluation_class"] for group in groups}
    return next((name for name in EVALUATION_CLASSES[1:] if name in declared), None)


def normalized_forces(text: str) -> list[str]:
    mapping = {
        "MUST NOT": "MUST_NOT",
        "SHOULD NOT": "SHOULD_NOT",
        "SHALL NOT": "SHALL_NOT",
        "NOT RECOMMENDED": "NOT_RECOMMENDED",
    }
    return sorted({mapping.get(value, value) for value in FORCE_RE.findall(text)})


def is_bcp14_declaration(text: str) -> bool:
    lowered = text.lower()
    return (
        "key words must, must not, required" in lowered
        or 'key words "must", "must not"' in lowered
        or "bcp 14 interpretation" in lowered
        or ("normative keywords" in lowered and "interpreted" in lowered)
        or "are to be interpreted as" in lowered
        or ("in this document are to be" in lowered and '"may"' in lowered)
    )


def list_item_indent(line: str) -> int | None:
    """The indentation of a list item's marker, or None when the line does not start an item."""
    if not LIST_RE.match(line):
        return None
    return len(line) - len(line.lstrip())


def ends_list_item(line: str, indent: int | None) -> bool:
    """True when `line` starts a list item at or above the indentation `indent` of the list item
    that holds a requirement, so that it is the next item of that list and not part of the
    requirement. A deeper item belongs to the requirement; None means the requirement is not a
    list item, and then no item ends it."""
    found = list_item_indent(line)
    return indent is not None and found is not None and found <= indent


def requirement_body(lines: list[str], index: int, first: str, indent: int | None) -> tuple[str, int]:
    """One tagged paragraph and its adjacent table or introduced list.

    A blank line ends prose even after a continued marker. Additional prose needs its own
    same-ID marker; a table remains one block, and blank-separated list items remain a list.
    """
    def boundary(line: str) -> bool:
        return bool(HEADING_RE.match(line) or REQUIREMENT_RE.match(line)
                    or CONTINUATION_RE.match(line) or TABLE_REQUIREMENT_RE.match(line)
                    or ends_list_item(line, indent))

    body = [first.strip()]
    cursor = index + 1
    while cursor < len(lines) and lines[cursor].strip() and not boundary(lines[cursor]):
        if lines[cursor].lstrip().startswith("|") and cursor + 1 < len(lines) and re.fullmatch(
            r"\s*\|(?:\s*:?-+:?\s*\|)+\s*", lines[cursor + 1]
        ):
            break
        body.append(lines[cursor].strip())
        cursor += 1
    blocks = [" ".join(body)]
    list_open = blocks[0].rstrip().endswith(":")
    while cursor < len(lines):
        lookahead = cursor
        while lookahead < len(lines) and not lines[lookahead].strip():
            lookahead += 1
        if lookahead >= len(lines) or boundary(lines[lookahead]):
            break
        if lines[lookahead].lstrip().startswith("|"):
            end = lookahead
            while end < len(lines) and lines[end].lstrip().startswith("|"):
                end += 1
            table = lines[lookahead:end]
            # Requirement-ID rows are independent requirements, not an attached table.
            if any(TABLE_REQUIREMENT_RE.match(row) for row in table):
                break
            if len(table) < 2 or not re.fullmatch(r"\s*\|(?:\s*:?-+:?\s*\|)+\s*", table[1]):
                break
            blocks.append("\n".join(row.strip() for row in table))
            cursor = end
            list_open = False
            continue
        if list_open and LIST_RE.match(lines[lookahead]):
            end = lookahead
            while end < len(lines) and lines[end].strip() and not boundary(lines[end]):
                end += 1
            blocks.append("\n".join(row.rstrip() for row in lines[lookahead:end]))
            cursor = end
            continue
        break
    return "\n\n".join(blocks), cursor


def extract(path: Path, root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    relative = path.relative_to(root).as_posix()
    requirements: list[dict[str, Any]] = []
    orphans: list[dict[str, Any]] = []
    heading = ""
    index = 0
    while index < len(lines):
        line = lines[index]
        heading_match = HEADING_RE.match(line)
        if heading_match:
            heading = heading_match.group(1)
        continuation = CONTINUATION_RE.match(line)
        marker = REQUIREMENT_RE.match(line) or continuation
        table_marker = TABLE_REQUIREMENT_RE.match(line)
        if marker:
            requirement_id, first = marker.groups()
            indent = list_item_indent(line)
            text, cursor = requirement_body(lines, index, first, indent)
            if continuation:
                prior = [item for item in requirements if item["requirement_id"] == requirement_id]
                if len(prior) != 1:
                    raise ValueError(f"{relative}:{index + 1}: continuation requires one earlier definition of {requirement_id}")
                prior[0]["text"] += "\n\n" + text
                prior[0]["normative_forces"] = normalized_forces(prior[0]["text"])
                index = cursor
                continue
            requirements.append(
                {
                    "requirement_id": requirement_id,
                    "source_path": relative,
                    "source_line": index + 1,
                    "source_heading": heading,
                    "text": text,
                    "normative_forces": normalized_forces(text),
                }
            )
            index = cursor
            continue
        if table_marker:
            requirement_id = table_marker.group(1)
            text = line.strip()
            requirements.append(
                {
                    "requirement_id": requirement_id,
                    "source_path": relative,
                    "source_line": index + 1,
                    "source_heading": heading,
                    "text": text,
                    "normative_forces": normalized_forces(text),
                }
            )
            index += 1
            continue
        forces = normalized_forces(line)
        lowercase = LOWERCASE_NORMATIVE_RE.findall(line)
        if not forces and lowercase and not line.lstrip().startswith("|"):
            forces = sorted({"lowercase:" + phrase for phrase in lowercase})
        if forces and not is_bcp14_declaration(line):
            orphans.append(
                {
                    "source_path": relative,
                    "source_line": index + 1,
                    "source_heading": heading,
                    "text": line.strip(),
                    "normative_forces": forces,
                }
            )
        index += 1
    return requirements, orphans


def declared_test_availability(
    root: Path, compiled: list[dict[str, Any]], implementations: dict[str, list[dict[str, Any]]],
    classes: dict[str, str | None], *, public_source: bool,
) -> tuple[list[str], dict[str, Any]]:
    """Resolve all compiled test refs, allowing only recorded omissions in public exports."""
    by_requirement = {
        row["requirement_id"]: {ref for ref in row["test_refs"] if is_internal(ref)}
        for row in compiled
    }
    all_refs = set().union(*by_requirement.values())
    present = {ref: test_reference_exists(root, ref) for ref in all_refs}
    missing = sorted(ref for ref in all_refs if not present[ref])
    if missing and not public_source:
        raise ValueError(f"compiled requirements have dangling test refs: {missing}")
    if missing:
        path = root / INTERNAL_REFS
        archived = read_json(path) if path.is_file() else {}
        if archived.get("schema_version") != "ecl_requirement_internal_refs_v1" or archived.get("candidate_version") != "1.0" or not isinstance(archived.get("requirements"), list):
            raise ValueError("public source missing test refs require the recorded internal sidecar")
        recorded: dict[str, set[str]] = {}
        for row in archived["requirements"]:
            if not isinstance(row, dict) or not isinstance(row.get("requirement_id"), str) or row["requirement_id"] in recorded:
                raise ValueError("invalid recorded requirement test refs")
            refs: set[str] = set()
            for key in ("test_refs", "evaluation_refs", "traceability_refs"):
                values = row.get(key, [])
                if not isinstance(values, list) or any(not isinstance(ref, str) or not is_internal(ref) for ref in values):
                    raise ValueError("invalid recorded requirement test refs")
                refs.update(values)
            recorded[row["requirement_id"]] = refs
        unrecorded = {
            identifier: sorted(ref for ref in refs if not present[ref] and ref not in recorded.get(identifier, set()))
            for identifier, refs in by_requirement.items()
        }
        unrecorded = {key: value for key, value in unrecorded.items() if value}
        if unrecorded:
            raise ValueError(f"public source has unrecorded missing test refs: {unrecorded}")
    availability: dict[str, list[str]] = {name: [] for name in ("all_present", "partially_present", "unavailable_only")}
    for identifier, name in sorted(classes.items()):
        if name != "reference-tested":
            continue
        refs = {ref for group in implementations.get(identifier, []) if group["evaluation_class"] == "reference-tested" for ref in group["evaluation_refs"]}
        count = sum(present[ref] for ref in refs)
        key = "all_present" if count == len(refs) else "partially_present" if count else "unavailable_only"
        availability[key].append(identifier)
    return missing, {
        "meaning": "Declared reference-test availability in this source tree; no test execution is asserted.",
        "counts": {key: len(value) for key, value in availability.items()},
        "requirement_ids": availability,
    }


def compile_registry(root: Path, *, public_source: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    metadata = read_json(root / "registries" / "requirement-metadata.json")
    implementations = implementation_groups(root)
    traced = implementation_traceability(root)
    manifest_paths = [
        root / "conformance" / "manifest.json",
        *sorted((root / "conformance/suites").glob("*/manifest.json")),
    ]
    vectors = [vector for path in manifest_paths for vector in read_json(path)["vectors"]]
    vector_refs: dict[str, list[str]] = {}
    for vector in vectors:
        for requirement_id in vector["requirement_ids"]:
            vector_refs.setdefault(requirement_id, []).append(f"conformance.vector:{vector['id']}")
    negating: dict[str, list[str]] = {}
    for vector in vectors:
        for requirement_id in vector.get("negates", []):
            negating.setdefault(requirement_id, []).append(f"conformance.vector:{vector['id']}")
    defaults = metadata["defaults"]
    prefix_profiles = metadata.get("prefix_profiles") or {}
    overrides = metadata["overrides"]
    requirements: list[dict[str, Any]] = []
    orphans: list[dict[str, Any]] = []
    paths = source_paths(root)
    missing = [path for path in paths if not path.is_file()]
    if missing:
        raise FileNotFoundError(", ".join(str(path) for path in missing))
    for path in paths:
        extracted, path_orphans = extract(path, root)
        requirements.extend(extracted)
        orphans.extend(path_orphans)
    known_requirement_ids = {item["requirement_id"] for item in requirements}
    unknown_implementation_ids = sorted(
        (set(implementations) | set(traced)) - known_requirement_ids
    )
    if unknown_implementation_ids:
        raise ValueError(
            "evaluation implementation map references unknown requirements: "
            f"{unknown_implementation_ids}"
        )

    counts: dict[str, int] = {}
    classes: dict[str, str | None] = {}
    compiled: list[dict[str, Any]] = []
    for item in requirements:
        identifier = item["requirement_id"]
        counts[identifier] = counts.get(identifier, 0) + 1
        merged = dict(defaults)
        prefix = identifier.split("-", 1)[0]
        merged.update(prefix_profiles.get(prefix) or {})
        merged.update(overrides.get(identifier) or {})
        merged["test_refs"] = [f"conformance:requirement:{identifier}", *merged.get("test_refs", [])]
        if identifier in vector_refs:
            merged["test_refs"] = [
                *merged["test_refs"],
                *vector_refs[identifier],
                (
                    "tests.test_conformance_harness.ConformanceHarnessTests."
                    "test_all_foundation_vectors_produce_expected_result"
                ),
            ]
            merged["evidence_obligations"] = [
                *merged["evidence_obligations"],
                "requirement-linked deterministic conformance vector result",
            ]
        if identifier in traced:
            merged["test_refs"] = [*merged["test_refs"], *traced[identifier]]
        groups = implementations.get(identifier) or []
        if groups:
            methods = {group["method"] for group in groups}
            merged["testability"] = next(iter(methods)) if len(methods) == 1 else "hybrid"
            merged["test_refs"] = [
                *merged["test_refs"],
                *(reference for group in groups for reference in group["evaluation_refs"]),
            ]
            merged["evidence_obligations"] = [
                *merged["evidence_obligations"],
                *(obligation for group in groups for obligation in group["evidence_obligations"]),
            ]
        text_hash = hashlib.sha256(item["text"].encode("utf-8")).hexdigest()
        classes[identifier] = evaluation_class(identifier in negating, groups)
        compiled.append(
            {
                "requirement_id": identifier,
                "status": merged["status"],
                "source_path": item["source_path"],
                "source_line": item["source_line"],
                "source_heading": item["source_heading"],
                "text": item["text"],
                "normative_forces": item["normative_forces"],
                "introduced_in": merged["introduced_in"],
                "text_sha256": text_hash,
                "testability": merged["testability"],
                "evidence_obligations": sorted(set(merged["evidence_obligations"])),
                "test_refs": sorted(set(merged["test_refs"])),
                "conformance_roles": sorted(set(merged["conformance_roles"])),
            }
        )
    missing_test_refs, reference_availability = declared_test_availability(
        root, compiled, implementations, classes, public_source=public_source,
    )
    compiled.sort(key=lambda item: item["requirement_id"])
    duplicates = sorted(key for key, count in counts.items() if count > 1)
    registry = {
        "schema_version": "ecl_requirement_registry_v2",
        "standard_id": "ECL-1",
        "candidate_version": "1.0",
        "source_files": [path.relative_to(root).as_posix() for path in paths],
        "requirements": compiled,
        "orphan_normative_statements": sorted(
            orphans,
            key=lambda item: (item["source_path"], item["source_line"]),
        ),
        "duplicate_requirement_ids": duplicates,
    }
    unassigned = sorted(
        {
            item["requirement_id"]
            for item in compiled
            if item["testability"] == "unassigned"
            or not item["evidence_obligations"]
            or not item["test_refs"]
            or not item["conformance_roles"]
            or classes[item["requirement_id"]] is None
        }
    )
    by_class = {
        name: sorted(key for key, value in classes.items() if value == name)
        for name in EVALUATION_CLASSES
    }
    coverage = {
        "schema_version": "ecl_requirement_coverage_v2",
        "candidate_version": "1.0",
        "requirement_count": len(compiled),
        "orphan_normative_statement_count": len(orphans),
        "duplicate_requirement_ids": duplicates,
        "unassigned_requirement_ids": unassigned,
        "evaluation_class_counts": {name: len(ids) for name, ids in by_class.items()},
        "evaluation_classes": by_class,
        "decision": "pass" if not orphans and not duplicates and not unassigned else "fail",
        "unavailable_internal_test_refs": missing_test_refs,
        "reference_test_availability": reference_availability,
        "evaluation_note": "Compiled procedure and traceability metadata; no implementation test execution or qualification is asserted.",
    }
    return registry, coverage


def json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json_bytes(value))


VECTOR_PROCEDURE = [
    "Run the deterministic conformance harness on every vector that negates the requirement.",
    "Confirm that each artifact digest matches and that the observed primary result is the "
    "manifest's expected primary.",
]
VECTOR_PASS = ["Every negating vector is refused with its exact expected primary result."]
VECTOR_FAIL = [
    "A negating vector is stale or missing, or is accepted or refused with another primary result."
]
HARNESS_TEST = (
    "tests.test_conformance_harness.ConformanceHarnessTests."
    "test_all_foundation_vectors_produce_expected_result"
)


def build_evaluation_catalog(
    registry: dict[str, Any],
    root: Path,
) -> dict[str, Any]:
    implementations = implementation_groups(root)
    manifest_paths = [
        root / "conformance" / "manifest.json",
        *sorted((root / "conformance/suites").glob("*/manifest.json")),
    ]
    negating: dict[str, list[str]] = {}
    for path in manifest_paths:
        for vector in read_json(path)["vectors"]:
            for requirement_id in vector.get("negates", []):
                negating.setdefault(requirement_id, []).append(f"conformance.vector:{vector['id']}")
    entries: list[dict[str, Any]] = []
    for requirement in registry["requirements"]:
        identifier = requirement["requirement_id"]
        groups = implementations.get(identifier) or []
        refuted_by = sorted(negating.get(identifier, []))
        name = evaluation_class(bool(refuted_by), groups)
        reference_refs = [
            ref
            for group in groups
            if group["evaluation_class"] == "reference-tested"
            for ref in group["evaluation_refs"]
        ]
        if name == "vector-tested":
            evaluation_refs = sorted({*refuted_by, HARNESS_TEST, *reference_refs})
        elif name == "reference-tested":
            evaluation_refs = sorted(set(reference_refs))
        else:
            evaluation_refs = []
        traceability_refs = sorted(
            {
                ref
                for ref in requirement["test_refs"]
                if not ref.startswith("conformance:requirement:")
            }
            - set(evaluation_refs)
        )
        procedure = [step for group in groups for step in group["procedure"]]
        pass_criteria = [item for group in groups for item in group["pass_criteria"]]
        fail_criteria = [item for group in groups for item in group["fail_criteria"]]
        if name == "vector-tested":
            procedure = [*VECTOR_PROCEDURE, *procedure]
            pass_criteria = [*VECTOR_PASS, *pass_criteria]
            fail_criteria = [*VECTOR_FAIL, *fail_criteria]
        if not procedure:
            procedure = [
                "Implement a requirement-specific evaluation before making a conformance claim."
            ]
            pass_criteria = ["the implementation or claim satisfies the exact normative text"]
            fail_criteria = [
                "the normative behavior is absent, bypassable, ambiguous, or contradicted"
            ]
        entries.append(
            {
                "requirement_id": identifier,
                "requirement_text_sha256": requirement["text_sha256"],
                "evaluation_class": name or "assessor-procedure",
                "method": requirement["testability"],
                "evaluation_refs": evaluation_refs,
                "traceability_refs": traceability_refs,
                "evidence_obligations": requirement["evidence_obligations"],
                "conformance_roles": requirement["conformance_roles"],
                "implementation_groups": sorted(group["id"] for group in groups),
                "procedure": procedure,
                "pass_criteria": sorted(set(pass_criteria)),
                "fail_criteria": sorted(set(fail_criteria)),
            }
        )
    override_path = root / "conformance/evaluation-procedure-overrides.json"
    if override_path.is_file():
        overrides = read_json(override_path)["requirements"]
        known = {entry["requirement_id"] for entry in entries}
        if set(overrides) - known:
            raise ValueError("evaluation overrides name unknown requirements")
        for entry in entries:
            replacement = overrides.get(entry["requirement_id"], {})
            if set(replacement) - {"procedure", "pass_criteria", "fail_criteria"}:
                raise ValueError("evaluation override changes an undeclared field")
            entry.update(replacement)
    return {
        "schema_version": "ecl_requirement_evaluation_catalog_v2",
        "candidate_version": registry["candidate_version"],
        "entries": entries,
    }


def split_internal(
    registry: dict[str, Any], evaluations: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """The public registry and evaluation catalog, without the references to the maintainer's
    tests, and the platform sidecar that holds those references by requirement."""
    internal: dict[str, dict[str, list[str]]] = {}
    requirements = []
    for item in registry["requirements"]:
        if refs := [ref for ref in item["test_refs"] if is_internal(ref)]:
            internal.setdefault(item["requirement_id"], {})["test_refs"] = refs
        requirements.append(
            {**item, "test_refs": [ref for ref in item["test_refs"] if not is_internal(ref)]}
        )
    entries = []
    for entry in evaluations["entries"]:
        public = dict(entry)
        for key in ("evaluation_refs", "traceability_refs"):
            if refs := [ref for ref in entry[key] if is_internal(ref)]:
                internal.setdefault(entry["requirement_id"], {})[key] = refs
            public[key] = [ref for ref in entry[key] if not is_internal(ref)]
        entries.append(public)
    sidecar = {
        "schema_version": "ecl_requirement_internal_refs_v1",
        "candidate_version": registry["candidate_version"],
        "description": (
            "The references of registries/requirements-compiled.json (test_refs) and of"
            " conformance/requirement-evaluations.json (evaluation_refs, traceability_refs) to"
            " G-14's tests in the legacy tests namespace. Local availability is reported in"
            " release/requirement-coverage.json; this sidecar alone does not establish execution."
            " A platform record, written by scripts/compile_rc3_requirements.py."
        ),
        "requirements": [
            {"requirement_id": key, **value} for key, value in sorted(internal.items())
        ],
    }
    return (
        {**registry, "requirements": requirements},
        {**evaluations, "entries": entries},
        sidecar,
    )


def validate_public_outputs(registry: dict[str, Any], evaluations: dict[str, Any], root: Path) -> None:
    """Validate shapes and cross-file identities before writing either public artifact."""
    metadata_validator(read_json(root / "schemas/ecl-requirement-registry-v2.schema.json")).validate(registry)
    metadata_validator(read_json(root / "schemas/ecl-requirement-evaluation-catalog-v2.schema.json")).validate(evaluations)
    requirements = {row["requirement_id"]: row for row in registry["requirements"]}
    entries = {row["requirement_id"]: row for row in evaluations["entries"]}
    if len(requirements) != len(registry["requirements"]) or len(entries) != len(evaluations["entries"]):
        raise ValueError("duplicate requirement identity in compiled outputs")
    if requirements.keys() != entries.keys() or registry["candidate_version"] != evaluations["candidate_version"]:
        raise ValueError("evaluation catalog does not cover the same version and requirement identities")
    for identifier, entry in entries.items():
        if entry["requirement_text_sha256"] != requirements[identifier]["text_sha256"]:
            raise ValueError(f"evaluation text identity differs: {identifier}")
        if set(entry["evaluation_refs"]) & set(entry["traceability_refs"]):
            raise ValueError(f"evaluation and traceability references overlap: {identifier}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--allow-incomplete", action="store_true")
    parser.add_argument("--public-source", action="store_true", help="allow missing test references already recorded for the requirement in the retained internal sidecar")
    args = parser.parse_args()
    root = args.root.resolve()
    registry_path = root / "registries" / "requirements-compiled.json"
    coverage_path = root / "release" / "requirement-coverage.json"
    evaluation_path = root / "conformance" / "requirement-evaluations.json"
    internal_path = root / INTERNAL_REFS
    try:
        registry, coverage = compile_registry(root, public_source=args.public_source)
        evaluations = build_evaluation_catalog(registry, root)
        registry, evaluations, internal = split_internal(registry, evaluations)
        validate_public_outputs(registry, evaluations, root)
        if args.check:
            if registry_path.read_bytes() != json_bytes(registry):
                raise ValueError("compiled requirement registry is stale")
            if coverage_path.read_bytes() != json_bytes(coverage):
                raise ValueError("requirement coverage report is stale")
            if evaluation_path.read_bytes() != json_bytes(evaluations):
                raise ValueError("requirement evaluation catalog is stale")
            if internal_path.read_bytes() != json_bytes(internal):
                raise ValueError("internal test reference sidecar is stale")
        else:
            write_json(registry_path, registry)
            write_json(coverage_path, coverage)
            write_json(evaluation_path, evaluations)
            write_json(internal_path, internal)
    except (OSError, KeyError, TypeError, ValueError, ValidationError) as exc:
        print(f"requirement compilation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(coverage, sort_keys=True))
    if coverage["decision"] != "pass" and not args.allow_incomplete:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
