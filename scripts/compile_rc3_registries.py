#!/usr/bin/env python3
"""Compile and validate current terms, fields, wire values, and registry catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

from jsonschema.exceptions import ValidationError
from referencing import Registry


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/ecl-verify/src"))
from ecl_verify.schema import ecl_format_checker  # noqa: E402
from ecl_verify.schema_patterns import schema_validator  # noqa: E402


def metadata_validator(schema: dict[str, Any]):
    return schema_validator(schema, registry=Registry(), format_checker=ecl_format_checker())

REGISTRY_SCHEMA = Path("schemas/ecl-registry-v2.schema.json")
RETIREMENTS = Path("registries/derived-id-retirements.json")
CORE = Path("standard/ECL-1_Standard.md")
GENERATED = {
    "terms.json",
    "fields.json",
    "schema-wire-values.json",
    "registry-catalog.json",
}
PROTOCOL_SCHEMAS = (
    "ecl-common-v1.schema.json",
    "dcmp-2.schema.json",
    "ebmp-2.schema.json",
    "ecl-integrity-envelope-v1.schema.json",
    "ecl-action-register-v1.schema.json",
    "ecl-conformance-claim-v1.schema.json",
    "ecl-assessment-package-v1.schema.json",
    "ecl-component-implementation-report-v1.schema.json",
    "ecl-mapping-packet-v1.schema.json",
    "ecl-adapter-binding-v1.schema.json",
    "ecl-deployment-profile-v1.schema.json",
    "ecl-work-intent-v1.schema.json",
    "ecl-safe-state-profile-v1.schema.json",
    "ecl-lifecycle-policy-v1.schema.json",
    "ecl-offline-verification-package-v1.schema.json",
)
TERM_RE = re.compile(r"^\*\*([^*]+)\*\*:\s*(.*)$")
HEADING_RE = re.compile(r"^#{1,6}\s+")
ALLOCATED_ID_RE = re.compile(r"\becl\.[a-z0-9][a-z0-9._-]*\.v[0-9]+\b")


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: root must be an object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def digest_json(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


# RC-3 and earlier were issued as ECI-1. The frozen predecessor map keeps that spelling. RC-4
# made two respellings of the same identifiers, and neither changes what an identifier names:
# 1. the ECL-1 rename respelled the token "eci" (any case, never inside a longer word) as "ecl"
#    with the same case;
# 2. the namespace decision moved every `urn:ecl:a:b:c` identifier to
#    `https://externalcontrollayer.ai/ns/a/b/c` and every `application/ecl-x+json` media type to
#    the vendor tree, `application/vnd.ecl.x+json`.
# A respelled identifier keeps its allocation history.
NAMESPACE = "https://externalcontrollayer.ai/ns/"
_PREDECESSOR_TOKEN = re.compile(r"(?<![A-Za-z])(eci|ECI|Eci)(?![a-z])")
_RESPELL = {"eci": "ecl", "ECI": "ECL", "Eci": "Ecl"}
_URN = re.compile(r"urn:ecl:((?:[A-Za-z0-9._~-]+:)*[A-Za-z0-9._~-]*)")
_FACET_MEDIA = re.compile(r"application/ecl-([a-z0-9-]+)\+(json|zip)")


def current_spelling(identifier: str) -> str:
    respelled = _PREDECESSOR_TOKEN.sub(lambda match: _RESPELL[match.group(1)], identifier)
    respelled = _URN.sub(lambda match: NAMESPACE + match.group(1).replace(":", "/"), respelled)
    return _FACET_MEDIA.sub(r"application/vnd.ecl.\1+\2", respelled)


# Field and wire-value identities are hashes over the schema $id, pointer and value. They hash
# that input in the RC-3 spelling, so both respellings leave every derived identity, and with it
# the allocation history, unchanged apart from the identifier's own prefix. Before RC-4 no
# protocol schema used the token "ecl", the namespace URI or a vendor-tree media type, and no
# identifier path segment contains ":" or "/", so the reverse respelling is exact.
_CURRENT_TOKEN = re.compile(r"(?<![A-Za-z])(ecl|ECL|Ecl)(?![a-z])")
_HISTORICAL = {"ecl": "eci", "ECL": "ECI", "Ecl": "Eci"}
_NAMESPACED = re.compile(re.escape(NAMESPACE) + r"([A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)")
_VENDOR_MEDIA = re.compile(r"application/vnd\.ecl\.([a-z0-9-]+)\+(json|zip)")


def identity_input(text: str) -> bytes:
    historical = _NAMESPACED.sub(lambda match: "urn:ecl:" + match.group(1).replace("/", ":"), text)
    historical = _VENDOR_MEDIA.sub(r"application/ecl-\1+\2", historical)
    return _CURRENT_TOKEN.sub(lambda match: _HISTORICAL[match.group(1)], historical).encode("utf-8")


CANDIDATE_VERSION = "1.0.2-review.1"
# The frozen map of each earlier candidate's derived and term identities. RC-3's keeps the ECI-1
# spelling; RC-4's, RC-5's and RC-6's (the identities of those review candidates) are in the
# current spelling.
RC4_PREDECESSOR_MAP = "registries/predecessor-ids-rc4.json"
RC5_PREDECESSOR_MAP = "registries/predecessor-ids-rc5.json"
RC6_PREDECESSOR_MAP = "registries/predecessor-ids-rc6.json"


def candidate_ids(root: Path, path: str, version: str) -> set[str]:
    """The derived and term identities of one earlier ECL-1 candidate, current and superseded."""
    value = read_json(root / path)
    ids = value.get("ids")
    if (
        set(value) != {"schema_version", "predecessor_version", "ids"}
        or value["schema_version"] != "ecl_predecessor_ids_v1"
        or value["predecessor_version"] != version
        or not isinstance(ids, list)
        or any(not isinstance(item, str) or not item for item in ids)
        or ids != sorted(set(ids))
    ):
        raise ValueError(f"invalid {version} predecessor identifier map")
    return set(ids)


def rc4_ids(root: Path) -> set[str]:
    """The RC-4 derived and term identities, current and superseded."""
    return candidate_ids(root, RC4_PREDECESSOR_MAP, "1.0-rc.4")


def rc5_ids(root: Path) -> set[str]:
    """The RC-5 derived and term identities, current and superseded."""
    return candidate_ids(root, RC5_PREDECESSOR_MAP, "1.0-rc.5")


def rc6_ids(root: Path) -> set[str]:
    """The RC-6 derived and term identities, current and superseded."""
    return candidate_ids(root, RC6_PREDECESSOR_MAP, "1.0-rc.6")


def first_introduction(identifier: str, maps: list[tuple[str, set[str]]]) -> str:
    """The earliest candidate whose map holds `identifier`, or the current version."""
    return next((version for version, ids in maps if identifier in ids), CANDIDATE_VERSION)


def introduction_maps(root: Path) -> list[tuple[str, set[str]]]:
    """Each earlier candidate's identities, oldest first."""
    return [
        ("1.0-rc.3", predecessor_ids(root)),
        ("1.0-rc.4", rc4_ids(root)),
        ("1.0-rc.5", rc5_ids(root)),
        ("1.0-rc.6", rc6_ids(root)),
        ("1.0", candidate_ids(root, "registries/predecessor-ids-v1.json", "1.0")),
    ]


def predecessor_ids(root: Path) -> set[str]:
    """The RC-3 derived and term identities, in the current spelling."""
    value = read_json(root / "registries/predecessor-ids.json")
    ids = value.get("ids")
    if (
        set(value) != {"schema_version", "predecessor_version", "ids"}
        or value["schema_version"] != "eci_predecessor_ids_v1"
        or value["predecessor_version"] != "1.0-rc.3"
        or not isinstance(ids, list)
        or any(not isinstance(item, str) or not item for item in ids)
        or ids != sorted(set(ids))
    ):
        raise ValueError("invalid predecessor identifier map")
    return {current_spelling(item) for item in ids}


def known_versions(root: Path) -> set[str]:
    """The versions a retirement may name: each candidate of the introduction maps and the
    current version."""
    return {version for version, _ in introduction_maps(root)} | {CANDIDATE_VERSION}


def declared_retirements(
    root: Path, versions: set[str] | None = None
) -> dict[str, list[dict[str, Any]]]:
    """The derived identities a schema change retired, by registry, as the editor declared them.

    A field or wire-value identity is a digest over its schema location (and value); a term
    identity follows its declared name. Changing either identity retires the old entry as
    `superseded`, names the identity that replaces it and gives the reason. A predecessor identity
    that is neither derived nor declared retired fails compilation: none disappears silently. A
    retirement names one of `versions` (`known_versions` by default): the version that retired it
    is a candidate the introduction maps know, or the current version.
    """
    if versions is None:
        versions = known_versions(root)
    value = read_json(root / RETIREMENTS)
    rows = value.get("retirements")
    if (
        set(value) != {"schema_version", "retirements"}
        or value["schema_version"] != ("ecl_derived_id_retirements_v1")
        or not isinstance(rows, list)
    ):
        raise ValueError("invalid derived-identity retirement record")
    grouped: dict[str, list[dict[str, Any]]] = {}
    seen: set[str] = set()
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row) != {"id", "registry", "superseded_by", "retired_in", "reason", "former"}
            or row["registry"] not in {"terms", "fields", "schema-wire-values"}
            or row["retired_in"] not in versions
            or not isinstance(row["reason"], str)
            or not row["reason"].strip()
            or not isinstance(row["former"], dict)
            or set(row["former"]) != {"description", "attributes"}
            or row["id"] in seen
        ):
            raise ValueError(f"invalid derived-identity retirement: {row!r}")
        seen.add(row["id"])
        grouped.setdefault(row["registry"], []).append(row)
    return grouped


def apply_retirements(
    root: Path, name: str, prefix: str, entries: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Append the declared superseded entries; refuse a predecessor identity that vanished."""
    live = {entry["id"] for entry in entries}
    maps = introduction_maps(root)
    versions = {version for version, _ in maps} | {CANDIDATE_VERSION}
    rows = declared_retirements(root, versions).get(name, [])
    retired = {row["id"]: row for row in rows}
    for row in rows:
        if row["id"] in live:
            raise ValueError(f"a retired identity is still derived: {row['id']}")
        # The replacement is derived, or a later declaration retired it in turn: the chain of
        # replacements ends at a derived identity (1.0 retired the 2.0-rc.2 values that RC-4's
        # retirements name), and each row keeps the replacement it recorded.
        successor, seen = row["superseded_by"], {row["id"]}
        while successor not in live:
            if successor not in retired or successor in seen:
                raise ValueError(f"a retirement names an identity that is not derived: {row['id']}")
            seen.add(successor)
            successor = retired[successor]["superseded_by"]
        entries.append(
            {
                "id": row["id"],
                "status": "superseded",
                "owner_class": "ecl-standard",
                "introduced_in": first_introduction(row["id"], maps),
                "compatibility": "behavioral",
                "description": row["former"]["description"],
                "superseded_by": row["superseded_by"],
                "attributes": {
                    **row["former"]["attributes"],
                    "superseded_in": row["retired_in"],
                    "supersession_reason": row["reason"],
                },
            }
        )
    # First-published-v1 term IDs are the public conservation baseline. Earlier ECI candidate
    # term slugs have namespace/name aliases without a supplied retirement history; their maps
    # still determine actual introduction metadata, but cannot invent historical definitions.
    conservation_maps = [("1.0", candidate_ids(root, "registries/predecessor-ids-v1.json", "1.0"))] if name == "terms" else maps
    vanished = sorted(
        identifier
        for identifier in {item for _, ids in conservation_maps for item in ids}
        if identifier.startswith(prefix)
        and identifier not in live
        and identifier not in {row["id"] for row in rows}
    )
    if vanished:
        raise ValueError(
            f"predecessor identities disappeared without a declared retirement: {vanished}"
        )
    return entries


def record_introductions(root: Path, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Retain predecessor introductions; new derived allocations belong to the current version.

    An identity in the RC-3 map was introduced in RC-3, one first in the RC-4 map in RC-4, one
    first in the RC-5 map in RC-5, one first in the RC-6 map in RC-6, and any other in the
    current version.
    """
    maps = introduction_maps(root)
    for entry in entries:
        entry["introduced_in"] = first_introduction(entry["id"], maps)
    return entries


def slug(value: str) -> str:
    result = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not result:
        raise ValueError(f"cannot allocate empty slug for {value!r}")
    return result


def registry(
    identifier: str,
    entries: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": "ecl_registry_v2",
        "registry_id": identifier,
        "registry_version": 1,
        "status": "active",
        "change_control": "governance/REGISTRY_POLICY.md",
        "entries": entries,
    }


def compile_terms(root: Path) -> dict[str, Any]:
    path = root / CORE
    lines = path.read_text(encoding="utf-8").splitlines()
    in_terms = False
    entries: list[dict[str, Any]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if re.fullmatch(r"#{1,6} 4\. Terms and Definitions", line):
            in_terms = True
            index += 1
            continue
        if in_terms and re.match(r"^#{1,6} 5\.", line):
            break
        match = TERM_RE.match(line) if in_terms else None
        if not match:
            index += 1
            continue
        term, first = match.groups()
        source_line = index + 1
        body = [first.strip()]
        cursor = index + 1
        while cursor < len(lines):
            candidate = lines[cursor]
            if TERM_RE.match(candidate) or HEADING_RE.match(candidate):
                break
            if candidate.strip():
                body.append(candidate.strip())
            cursor += 1
        definition = " ".join(body).strip()
        entries.append(
            {
                "id": f"ecl.term.{slug(term)}.v1",
                "status": "active",
                "owner_class": "ecl-standard",
                "introduced_in": "1.0-rc.3",
                "compatibility": "behavioral",
                "description": definition,
                "attributes": {
                    "term": term,
                    "source_path": CORE.as_posix(),
                    "source_line": source_line,
                    "definition_sha256": hashlib.sha256(definition.encode("utf-8")).hexdigest(),
                },
            }
        )
        index = cursor
    identifiers = [item["id"] for item in entries]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("term slug collision")
    if not entries:
        raise ValueError("no normative terms were compiled")
    entries = record_introductions(root, entries)
    entries = apply_retirements(root, "terms", "ecl.term.", entries)
    return registry("https://externalcontrollayer.ai/ns/registry/terms", entries)


def pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def type_summary(node: Any) -> list[str]:
    if not isinstance(node, dict):
        return ["boolean-schema"]
    value = node.get("type")
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return sorted(str(item) for item in value)
    if "$ref" in node:
        return ["reference"]
    if "const" in node:
        return [type(node["const"]).__name__]
    if "enum" in node:
        return sorted({type(item).__name__ for item in node["enum"]})
    if any(key in node for key in ("oneOf", "anyOf", "allOf")):
        return ["composed"]
    return ["unspecified"]


def walk_schema_fields(
    node: Any,
    schema_id: str,
    pointer: str = "",
) -> Iterable[dict[str, Any]]:
    if isinstance(node, dict):
        required = set(node.get("required") or [])
        properties = node.get("properties")
        if isinstance(properties, dict):
            for name, child in properties.items():
                child_pointer = f"{pointer}/properties/{pointer_escape(name)}"
                identity = hashlib.sha256(
                    identity_input(f"{schema_id}\0{child_pointer}")
                ).hexdigest()
                yield {
                    "id": f"https://externalcontrollayer.ai/ns/field/{identity[:32]}",
                    "status": "active",
                    "owner_class": "ecl-standard",
                    "introduced_in": "1.0-rc.3",
                    "compatibility": "behavioral",
                    "description": (
                        f"Field {name!r} at {child_pointer!r} in {schema_id}; "
                        "the referenced schema constraints are normative."
                    ),
                    "attributes": {
                        "schema_id": schema_id,
                        "json_schema_pointer": child_pointer,
                        "field_name": name,
                        "required_by_parent": name in required,
                        "type_summary": type_summary(child),
                        "constraint_sha256": digest_json(child),
                    },
                }
        for key, child in node.items():
            yield from walk_schema_fields(
                child,
                schema_id,
                f"{pointer}/{pointer_escape(str(key))}",
            )
    elif isinstance(node, list):
        for index, child in enumerate(node):
            yield from walk_schema_fields(
                child,
                schema_id,
                f"{pointer}/{index}",
            )


def compile_fields(root: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for name in PROTOCOL_SCHEMAS:
        schema = read_json(root / "schemas" / name)
        schema_id = schema["$id"]
        entries.extend(walk_schema_fields(schema, schema_id))
    entries.sort(
        key=lambda item: (
            item["attributes"]["schema_id"],
            item["attributes"]["json_schema_pointer"],
        )
    )
    identifiers = [item["id"] for item in entries]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("field identity collision")
    entries = record_introductions(root, entries)
    entries = apply_retirements(root, "fields", NAMESPACE + "field/", entries)
    return registry("https://externalcontrollayer.ai/ns/registry/fields", entries)


def walk_wire_values(
    node: Any,
    schema_id: str,
    pointer: str = "",
) -> Iterable[dict[str, Any]]:
    if isinstance(node, dict):
        for kind in ("const", "enum"):
            if kind not in node:
                continue
            values = [node[kind]] if kind == "const" else node[kind]
            for value in values:
                identity = hashlib.sha256(
                    identity_input(
                        f"{schema_id}\0{pointer}\0{kind}\0" + json.dumps(value, sort_keys=True)
                    )
                ).hexdigest()
                yield {
                    "id": f"https://externalcontrollayer.ai/ns/wire-value/{identity[:32]}",
                    "status": "active",
                    "owner_class": "ecl-standard",
                    "introduced_in": "1.0-rc.3",
                    "compatibility": "behavioral",
                    "description": (f"Allowed {kind} wire value at {pointer!r} in {schema_id}."),
                    "attributes": {
                        "schema_id": schema_id,
                        "json_schema_pointer": pointer,
                        "constraint_kind": kind,
                        "wire_value": value,
                    },
                }
        for key, child in node.items():
            yield from walk_wire_values(
                child,
                schema_id,
                f"{pointer}/{pointer_escape(str(key))}",
            )
    elif isinstance(node, list):
        for index, child in enumerate(node):
            yield from walk_wire_values(
                child,
                schema_id,
                f"{pointer}/{index}",
            )


def compile_wire_values(root: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for name in PROTOCOL_SCHEMAS:
        schema = read_json(root / "schemas" / name)
        entries.extend(walk_wire_values(schema, schema["$id"]))
    entries.sort(
        key=lambda item: (
            item["attributes"]["schema_id"],
            item["attributes"]["json_schema_pointer"],
            json.dumps(item["attributes"]["wire_value"], sort_keys=True),
        )
    )
    entries = record_introductions(root, entries)
    entries = apply_retirements(root, "schema-wire-values", NAMESPACE + "wire-value/", entries)
    return registry("https://externalcontrollayer.ai/ns/registry/schema-wire-values", entries)


def source_registry_paths(root: Path) -> list[Path]:
    return sorted(
        path
        for path in (root / "registries").glob("*.json")
        if path.name not in GENERATED and read_json(path).get("schema_version") == "ecl_registry_v2"
    )


def validate_registries(
    root: Path,
    generated: list[tuple[Path, dict[str, Any]]],
) -> tuple[list[tuple[Path, dict[str, Any]]], set[str]]:
    schema = read_json(root / REGISTRY_SCHEMA)
    validator = metadata_validator(schema)
    values = [(path, read_json(path)) for path in source_registry_paths(root)]
    values.extend(generated)
    registry_ids: dict[str, str] = {}
    entry_ids: dict[str, str] = {}
    allocated_ecl_ids: set[str] = set()
    for path, value in values:
        validator.validate(value)
        registry_id = value["registry_id"]
        if registry_id in registry_ids:
            raise ValueError(
                f"duplicate registry id {registry_id}: {registry_ids[registry_id]} and {path}"
            )
        registry_ids[registry_id] = path.as_posix()
        for entry in value["entries"]:
            identifier = entry["id"]
            if identifier in entry_ids:
                raise ValueError(
                    f"duplicate entry id {identifier}: {entry_ids[identifier]} and {path}"
                )
            entry_ids[identifier] = path.as_posix()
            if identifier.startswith("ecl."):
                allocated_ecl_ids.add(identifier)
            if entry["status"] == "superseded" and not entry.get("superseded_by"):
                raise ValueError(f"{path}: superseded entry lacks superseded_by: {identifier}")
    # Resolve after collecting every registry, so file order does not constrain a successor.
    # The registry schema describes superseded_by as an allocated preferred successor; a
    # token's syntax, or a URI under the namespace, does not establish that allocation.
    for path, value in values:
        for entry in value["entries"]:
            if "superseded_by" in entry:
                successor = entry["superseded_by"]
                if successor == entry["id"] or successor not in entry_ids:
                    raise ValueError(
                        f"{path}: superseded_by must name a distinct allocated entry: "
                        f"{entry['id']} -> {successor}"
                    )
    return values, allocated_ecl_ids


# These are exact source/identifier pairs, not namespace or directory exemptions. The
# namespace policy explicitly distinguishes example identifiers from production allocations.
# The two internal Go files also retain historical diagnostics: the public strict parser uses
# its registered findings, and the public semantic/corpus adapters map the legacy shape finding.
REFERENCE_EXCEPTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "go/crosscheck/internal/strictjson/strictjson.go": (
        "Legacy diagnostics of the embedded-asset loader, not public strict-parser findings.",
        ("ecl.rule.json-restricted-unicode.v1", "ecl.rule.json-syntax-valid.v1"),
    ),
    "go/crosscheck/internal/validator/validator.go": (
        "Legacy internal shape finding mapped to the registered schema error by public adapters.",
        ("ecl.rule.artifact-shape-recognized.v1",),
    ),
    "conformance/suites/document-coverage/register-valid-published-example.json": (
        "Illustrative action and evidence-profile names retained from the published example.",
        ("ecl.action.payment.v1", "ecl.evidence.expanded.v1"),
    ),
    "conformance/suites/document-coverage/register-valid-pending-review-and-confined-entries.json": (
        "Illustrative action and evidence-profile names in the example-derived register.",
        ("ecl.action.draft-summary.v1", "ecl.action.payment-refund.v1", "ecl.action.payment.v1",
         "ecl.evidence.expanded.v1", "ecl.evidence.summary.v1"),
    ),
    "conformance/suites/safe-state-declaration-contract/safe-state-declaration-contract-distinct-classes-control.json": (
        "Illustrative distinct action class in the schema/contract positive control.",
        ("ecl.action.test-distinct.v1",),
    ),
    "conformance/suites/safe-state-declaration-contract/safe-state-declaration-contract-empty-additional-prohibitions-control.json": (
        "Illustrative evidence profile in the schema/contract positive control.",
        ("ecl.profile.audit.v1",),
    ),
}


def json_reference_ids(text: str) -> set[str]:
    """Read JSON string tokens without constructing recursively nested artifact values.

    Syntax and artifact validity belong to their existing validators. This lexical discovery
    only unescapes string tokens, so a valid deep-input control does not need a second parser
    with a shallower runtime nesting limit.
    """
    decoder = json.JSONDecoder()
    found: set[str] = set()
    cursor = 0
    while True:
        start = text.find('"', cursor)
        if start < 0:
            return found
        value, cursor = decoder.raw_decode(text, start)
        found.update(ALLOCATED_ID_RE.findall(value))


def reference_inventory(root: Path) -> tuple[set[str], dict[str, Any]]:
    """Discover literal tokens in declared current sources, without interpreting encoded data.

    Negative fixtures may deliberately use unallocated tokens. Historical predecessor maps,
    unit tests, example directories and generated copies are not normative allocation sources.
    Passing ZIPs and encoded payloads require their own artifact checks, not a text scan.
    """
    paths = {root / CORE, *source_registry_paths(root)}
    for directory, pattern in (
        ("protocols", "*.md"), ("profiles", "*.md"), ("schemas", "*.json"),
        ("packages/ecl-verify/src/ecl_verify", "**/*.py"),
        ("packages/ecl-ts/src", "**/*.ts"), ("go/crosscheck", "**/*.go"),
    ):
        selected = [
            path for path in (root / directory).glob(pattern)
            if path.is_file() and not path.name.endswith(("_test.go", ".test.ts", ".spec.ts"))
        ]
        if not selected:
            raise ValueError(f"required reference source directory is absent or empty: {directory}")
        paths.update(selected)
    source_paths = set(paths)
    binary: set[str] = set()
    manifests = [root / "conformance/manifest.json", *sorted((root / "conformance/suites").glob("*/manifest.json"))]
    for manifest in manifests:
        for vector in read_json(manifest)["vectors"]:
            if vector["expected"] != "pass":
                continue
            relative = Path(vector["path"])
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError(f"passing-vector path is not repository-relative: {relative}")
            path = root / relative
            if not path.is_file():
                raise ValueError(f"passing-vector artifact is missing: {relative}")
            if path.suffix != ".json":
                binary.add(relative.as_posix())
            else:
                paths.add(path)
    found: set[str] = set()
    files: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    for path in sorted(paths):
        data = path.read_bytes()
        # JSON escapes are spelling, not a different registry identifier. Decode JSON string
        # values before discovery; base64 payloads remain outside this literal-token check.
        text = data.decode("utf-8")
        identifiers = json_reference_ids(text) if path.suffix == ".json" else set(ALLOCATED_ID_RE.findall(text))
        relative = path.relative_to(root).as_posix()
        reason, examples = REFERENCE_EXCEPTIONS.get(relative, ("", ()))
        for identifier in sorted(identifiers & set(examples)):
            excluded.append({"path": relative, "identifier": identifier, "reason": reason})
        found.update(identifiers - set(examples))
        files.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest()})
    return found, {
        "source_file_count": len(source_paths),
        "passing_json_artifact_count": len(paths - source_paths),
        "manifest_count": len(manifests),
        "files": files,
        "excluded_references": excluded,
        "unscanned_binary_artifacts": sorted(binary),
        "scope": "Literal ecl.*.vN tokens in current standard, protocols, profiles, schemas, source "
        "registries, Python/TypeScript/Go runtime sources and passing JSON artifacts. This is "
        "allocation-reference discovery, not semantic, signature or conformance verification.",
        "not_scanned": ["negative artifacts", "unit tests", "historical predecessor maps",
                        "standalone example directories", "encoded or compressed payload contents"],
    }


def referenced_ecl_ids(root: Path) -> set[str]:
    return reference_inventory(root)[0]


def compile_catalog(
    values: list[tuple[Path, dict[str, Any]]],
    root: Path,
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for path, registry_value in values:
        relative = path.relative_to(root).as_posix()
        for entry in registry_value["entries"]:
            entries.append(
                {
                    "id": entry["id"],
                    "status": entry["status"],
                    "owner_class": entry["owner_class"],
                    "introduced_in": entry["introduced_in"],
                    "compatibility": entry["compatibility"],
                    "description": entry["description"],
                    **({"superseded_by": entry["superseded_by"]} if "superseded_by" in entry else {}),
                    "attributes": {
                        "source_registry_id": registry_value["registry_id"],
                        "source_path": relative,
                        "entry_sha256": digest_json(entry),
                    },
                }
            )
    entries.sort(key=lambda item: item["id"])
    return registry("https://externalcontrollayer.ai/ns/registry/catalog", entries)


def build(root: Path) -> tuple[dict[Path, dict[str, Any]], dict[str, Any]]:
    generated = {
        Path("registries/terms.json"): compile_terms(root),
        Path("registries/fields.json"): compile_fields(root),
        Path("registries/schema-wire-values.json"): compile_wire_values(root),
    }
    values, allocated = validate_registries(
        root,
        [(root / path, value) for path, value in generated.items()],
    )
    referenced, scan = reference_inventory(root)
    missing = sorted(referenced - allocated)
    if missing:
        raise ValueError(f"unallocated reserved ECL identifiers: {missing}")
    catalog = compile_catalog(values, root)
    metadata_validator(read_json(root / REGISTRY_SCHEMA)).validate(catalog)
    generated[Path("registries/registry-catalog.json")] = catalog
    report = {
        "schema_version": "ecl_registry_compilation_report_v1",
        "registry_count": len(values),
        "entry_count": sum(len(value["entries"]) for _, value in values),
        "referenced_ecl_identifier_count": len(referenced),
        "reference_scan": scan,
        "compiled_schema_count": len(PROTOCOL_SCHEMAS),
        "compiled_schema_paths": [f"schemas/{name}" for name in PROTOCOL_SCHEMAS],
        "schemas_not_compiled_for_fields_or_wire_values": sorted(
            path.relative_to(root).as_posix() for path in (root / "schemas").glob("*.json")
            if path.name not in PROTOCOL_SCHEMAS
        ),
        "schema_derivation_scope": "The compatibility-preserved core and document schema set "
        "listed above supplies field and wire-value allocations; other schemas are scanned for "
        "literal registry tokens but are not included in those two derived registries.",
        "unallocated_ecl_identifiers": missing,
        "decision": "pass",
    }
    return generated, report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        generated, report = build(root)
        for relative, value in generated.items():
            path = root / relative
            if args.check:
                if path.read_bytes() != (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"):
                    raise ValueError(f"generated registry is stale: {relative}")
            else:
                write_json(path, value)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, ValidationError) as exc:
        print(f"registry compilation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
