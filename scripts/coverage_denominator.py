"""Compute two-sided coverage against a versioned schema/rule denominator.

A vector's `covers` claim on a schema unit is accepted only when changing that one unit changes the
vector's result. The artifact is validated against the vector's schema twice: as published, and
with the unit changed. A passing vector witnesses a unit when the artifact becomes invalid once the
unit refuses (an enum admits no value, a conditional arm or an alternative is `false`): the unit was
evaluated and accepted the artifact. A failing vector, whose primary finding is schema invalidity,
witnesses a unit when the artifact becomes valid once the unit accepts (the enum is removed, the arm
or the alternative is `true`): the unit alone caused the failure. A unit inside a conditional's
predicate is witnessed through that conditional: positively when the predicate held, the arm it
selected was satisfied, and refusing the unit stops it holding; negatively when refusing the unit
removes the failure. A root unit is witnessed by validating the whole artifact. A unit of an
extension value schema is tested on the values of the registered extensions it constrains (XR1-023),
and a failing vector witnesses it when its primary finding is the extension-value rule. This
measurement is bounded to these rules, not arbitrary code paths.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, cast

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from ecl_verify.canonical import CanonicalizationError, loads_json_strict
from ecl_verify.schema import ecl_format_checker
from ecl_verify.schema_patterns import validation_schema

ROOT = Path(__file__).resolve().parents[1]
DENOMINATOR = Path("conformance/coverage-denominator.json")
REPORT = Path("release/coverage-report.json")
SCHEMA_INVALID = "ecl.error.schema-invalid.v1"
VALUE_RULE = "ecl.rule.extension-value-valid.v1"
# Keywords whose next path segment is a member name or an item index rather than a keyword.
NAMED_CHILDREN = frozenset(
    {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"}
)
INDEXED_CHILDREN = frozenset({"allOf", "oneOf", "anyOf", "prefixItems"})
DELETE = object()
Change = tuple[list[str], str | int, Any]
MEASUREMENT_LIMITS = (
    "Each schema-unit claim is attributed by changing that unit alone: a positive witness becomes "
    "invalid when the unit refuses, a negative witness becomes valid when the unit accepts, and a "
    "unit inside a conditional's predicate is attributed through that conditional. Extension value "
    "schemas are tested on the extension values an artifact carries. Attribution does not show "
    "which alternative of a union a refused value was meant to match. Coverage does not establish "
    "deployment conformance."
)


def read(path: Path) -> dict[str, Any]:
    value = loads_json_strict(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"document root is not an object: {path}")
    return cast(dict[str, Any], value)


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def schemas_on_disk(root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted((root / "schemas").glob("*.json")):
        value = read(path)
        identifier = value.get("$id")
        if isinstance(identifier, str):
            if identifier in result:
                raise ValueError("duplicate schema identifier")
            result[identifier] = value
    return result


def validate_scope(denominator: dict[str, Any], schemas: dict[str, dict[str, Any]]) -> None:
    if set(denominator) != {
        "schema_version",
        "version",
        "candidate_version",
        "unit_rules",
        "included_schemas",
        "excluded_schemas",
        "unit_exclusions",
    }:
        raise ValueError("invalid denominator members")
    if (
        denominator["schema_version"] != "ecl_coverage_denominator_v1"
        or denominator["candidate_version"] != "1.0"
    ):
        raise ValueError("invalid denominator identity")
    if type(denominator["version"]) is not int or denominator["version"] < 1:
        raise ValueError("invalid denominator version")
    included = denominator["included_schemas"]
    excluded = denominator["excluded_schemas"]
    if (
        not isinstance(included, list)
        or not all(isinstance(x, str) for x in included)
        or len(set(included)) != len(included)
    ):
        raise ValueError("invalid included schemas")
    if not isinstance(excluded, list):
        raise ValueError("invalid excluded schemas")
    identifiers: list[str] = []
    for row in excluded:
        if (
            not isinstance(row, dict)
            or set(row) != {"schema_id", "justification"}
            or not isinstance(row["schema_id"], str)
            or not isinstance(row["justification"], str)
            or not row["justification"].strip()
        ):
            raise ValueError("excluded schemas need a named justification")
        identifiers.append(row["schema_id"])
    if (
        len(set(identifiers)) != len(identifiers)
        or set(identifiers) & set(included)
        or set(identifiers) | set(included) != set(schemas)
    ):
        raise ValueError("included and excluded schemas must partition every schema id")


def schema_units(identifier: str, value: object, pointer: str = "") -> list[dict[str, Any]]:
    units: list[dict[str, Any]] = []
    if pointer == "":
        units.append(
            {"id": identifier + "##root", "schema_id": identifier, "pointer": "", "kind": "root"}
        )
    if isinstance(value, dict):
        for keyword in ("oneOf", "anyOf"):
            alternatives = value.get(keyword)
            if isinstance(alternatives, list):
                for index in range(len(alternatives)):
                    path = pointer + "/" + keyword
                    units.append(
                        {
                            "id": f"{identifier}#{path}#{keyword}[{index}]",
                            "schema_id": identifier,
                            "pointer": path,
                            "kind": keyword,
                            "index": index,
                        }
                    )
        if "if" in value:
            path = pointer + "/if"
            units.append(
                {
                    "id": identifier + "#" + path + "#if[0]",
                    "schema_id": identifier,
                    "pointer": path,
                    "kind": "if",
                    "index": 0,
                }
            )
            if "else" in value:
                units.append(
                    {
                        "id": identifier + "#" + path + "#if[1]",
                        "schema_id": identifier,
                        "pointer": path,
                        "kind": "if",
                        "index": 1,
                    }
                )
        if isinstance(value.get("enum"), list):
            path = pointer + "/enum"
            units.append(
                {
                    "id": identifier + "#" + path + "#enum",
                    "schema_id": identifier,
                    "pointer": path,
                    "kind": "enum",
                    "values": value["enum"],
                }
            )
        for keyword in (
            "properties",
            "patternProperties",
            "$defs",
            "definitions",
            "dependentSchemas",
        ):
            children = value.get(keyword)
            if isinstance(children, dict):
                for key, child in sorted(children.items()):
                    escaped = str(key).replace("~", "~0").replace("/", "~1")
                    units.extend(
                        schema_units(identifier, child, pointer + "/" + keyword + "/" + escaped)
                    )
        for keyword in ("allOf", "oneOf", "anyOf", "prefixItems"):
            children = value.get(keyword)
            if isinstance(children, list):
                for index, child in enumerate(children):
                    units.extend(
                        schema_units(identifier, child, pointer + "/" + keyword + "/" + str(index))
                    )
        for keyword in (
            "items",
            "additionalProperties",
            "contains",
            "if",
            "then",
            "else",
            "not",
            "propertyNames",
            "unevaluatedProperties",
            "unevaluatedItems",
        ):
            child = value.get(keyword)
            if isinstance(child, (dict, bool)):
                units.extend(schema_units(identifier, child, pointer + "/" + keyword))
    return units


def enumerate_units(root: Path, denominator: dict[str, Any]) -> list[dict[str, Any]]:
    schemas = schemas_on_disk(root)
    validate_scope(denominator, schemas)
    units = [
        unit
        for identifier in sorted(denominator["included_schemas"])
        for unit in schema_units(identifier, schemas[identifier])
    ]
    units.extend(
        {"id": rule["id"], "kind": "rule", "applies_to": rule["attributes"]["applies_to"]}
        for rule in read(root / "registries/semantic-rules.json")["entries"]
        if rule["status"] == "active"
    )
    ids = [unit["id"] for unit in units]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate denominator unit")
    excluded: set[str] = set()
    for row in denominator["unit_exclusions"]:
        if (
            set(row) != {"unit", "justification"}
            or row["unit"] not in ids
            or row["unit"] in excluded
            or not isinstance(row["justification"], str)
            or not row["justification"].strip()
        ):
            raise ValueError("invalid unit exclusion")
        excluded.add(row["unit"])
    return sorted(units, key=lambda x: x["id"])


def harness(root: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "coverage_harness", root / "scripts/run_conformance.py"
    )
    if spec is None or spec.loader is None:
        raise ValueError("cannot load the conformance harness")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def pointer_parts(pointer: str) -> list[str]:
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/")[1:]]


def keyword_positions(parts: list[str]) -> list[int]:
    """The positions of schema keywords in a unit path, skipping member names and item indexes."""
    positions: list[int] = []
    index = 0
    while index < len(parts):
        positions.append(index)
        index += 2 if parts[index] in NAMED_CHILDREN | INDEXED_CHILDREN else 1
    return positions


def unit_change(unit: dict[str, Any], accept: bool) -> Change:
    """The one change that makes a unit accept every instance, or refuse every instance."""
    parts = pointer_parts(unit["pointer"])
    if unit["kind"] == "enum":
        return parts[:-1], "enum", DELETE if accept else []
    if unit["kind"] == "if":
        return parts[:-1], "then" if unit["index"] == 0 else "else", accept
    if unit["kind"] in {"oneOf", "anyOf"}:
        return parts, int(unit["index"]), accept
    raise ValueError(f"no attribution for unit kind: {unit['id']}")


def enclosing_condition(unit: dict[str, Any]) -> list[str] | None:
    """The path of the conditional whose predicate contains the unit, if there is one."""
    parts = pointer_parts(unit["pointer"])
    keywords = [(index, parts[index]) for index in keyword_positions(parts)[:-1]]
    predicates = [index for index, keyword in keywords if keyword == "if"]
    if any(keyword == "not" for _, keyword in keywords) or len(predicates) > 1:
        raise ValueError(f"no attribution for a unit in this position: {unit['id']}")
    return parts[: predicates[0]] if predicates else None


class Attribution:
    """Validate an artifact against the published schemas, or with one unit changed.

    `value_schemas` maps the identifier of an extension value schema to the registered extensions
    whose values it constrains (XR1-023). A unit of such a schema is tested on those values, and a
    failing vector witnesses it when its primary finding is the extension-value rule.
    """

    def __init__(self, documents: dict[str, Any], value_schemas: dict[str, set[str]]) -> None:
        self.documents = documents
        self.value_schemas = value_schemas

    def carried(self, schema_id: str, value: object) -> list[object]:
        """The values of the registered extensions in an artifact that a value schema constrains."""
        extensions = value.get("extensions") if isinstance(value, dict) else None
        if not isinstance(extensions, list):
            return []
        names = self.value_schemas[schema_id]
        return [
            item["value"]
            for item in extensions
            if isinstance(item, dict) and item.get("id") in names and "value" in item
        ]

    def valid(
        self,
        context: str,
        value: object,
        target: str | None = None,
        changes: list[Change] | None = None,
    ) -> bool:
        documents = self.documents
        if target is not None and changes:
            document = copy.deepcopy(documents[target])
            for parts, key, new in changes:
                container = document
                for part in parts:
                    container = (
                        container[int(part)] if isinstance(container, list) else container[part]
                    )
                if new is DELETE:
                    del container[key]
                else:
                    container[key] = new
            documents = {**documents, target: document}
        registry: Registry[Any] = Registry().with_resources(
            (identifier, Resource.from_contents(contents, default_specification=DRAFT202012))
            for identifier, contents in documents.items()
        )
        return bool(
            Draft202012Validator(
                documents[context], registry=registry, format_checker=ecl_format_checker()
            ).is_valid(value)
        )

    def witnesses(self, unit: dict[str, Any], vector: dict[str, Any], value: object) -> bool:
        target = cast(str, unit["schema_id"])
        passing = vector["expected"] == "pass"
        if target in self.value_schemas:
            values = self.carried(target, value)
            if not values or (not passing and vector.get("expected_primary_id") != VALUE_RULE):
                return False

            def check(changes: list[Change] | None = None) -> bool:
                return all(self.valid(target, item, target, changes) for item in values)

        else:
            if not passing and vector.get("expected_primary_id") != SCHEMA_INVALID:
                return False
            schema = vector.get("schema")
            context = (
                schema
                if unit["kind"] != "root" and isinstance(schema, str) and schema in self.documents
                else target
            )

            def check(changes: list[Change] | None = None) -> bool:
                return self.valid(context, value, target, changes)

        if check() is not passing:
            return False
        if unit["kind"] == "root":
            return True
        refuse = [unit_change(unit, accept=False)]
        condition = enclosing_condition(unit)
        if condition is None:
            return not check(refuse) if passing else check([unit_change(unit, accept=True)])
        if passing:
            consequence: list[Change] = [(condition, "then", False), (condition, "else", True)]
            return not check(consequence) and check(consequence + refuse)
        return check([(condition, "else", True), *refuse])


def attribution_for(root: Path) -> Attribution:
    """The attribution engine over the schemas on disk and the extension registry's value schemas."""
    value_schemas: dict[str, set[str]] = {}
    for entry in read(root / "registries/extensions.json")["entries"]:
        schema_id = entry.get("attributes", {}).get("value_schema")
        if isinstance(schema_id, str):
            value_schemas.setdefault(schema_id, set()).add(entry["id"])
    return Attribution(
        {
            identifier: validation_schema(schema)
            for identifier, schema in schemas_on_disk(root).items()
        },
        value_schemas,
    )


def positive_rule_witness(unit: dict[str, Any], vector: dict[str, Any]) -> bool:
    if vector["expected"] != "pass":
        return False
    stage = cast(str, vector["stage"])
    schema = cast(str | None, vector.get("schema"))
    names = set(unit["applies_to"])
    if "all-json" in names:
        return True
    if "EBMP-2 bundle" in names:
        # The causal-bundle stage and the signed evidence bundle, whose verifier also applies the
        # rules that read a whole bundle (DCMP2-053 in the evidence, EBMP2-032).
        return stage in ("bundle", "evidence-bundle")
    if "SAFE-STATE-PROFILE" in names:
        return stage == "safe-state-profile"
    if "ECL adapter binding" in names:
        return schema == "https://externalcontrollayer.ai/ns/schema/adapter-binding/1"
    # A binding profile's rule names the schema of the records it reads.
    if schema in names:
        # A schema-only protocol-stage record does not execute a binding checker. Its
        # structural acceptance cannot witness that binding's semantic rules.
        return stage == "binding" if "/schema/binding/" in str(schema) else stage in {"document", "semantic", "protocol"}
    pairs = {
        "DCMP-2": "https://externalcontrollayer.ai/ns/schema/dcmp/2",
        "EBMP-2": "https://externalcontrollayer.ai/ns/schema/ebmp/2",
        "ECL-IE-1": "https://externalcontrollayer.ai/ns/schema/integrity-envelope/1",
        "ECL-WI-1": "https://externalcontrollayer.ai/ns/schema/work-intent/1",
    }
    return any(schema == pairs.get(name) for name in names)


def compute(root: Path, replay_report: Path | None = None) -> dict[str, Any]:
    denominator = read(root / DENOMINATOR)
    units = enumerate_units(root, denominator)
    by_id = {unit["id"]: unit for unit in units}
    attribution = attribution_for(root)
    runner = harness(root)
    actual = runner.run(root)
    if replay_report is not None:
        replay_report.parent.mkdir(parents=True, exist_ok=True)
        replay_report.write_bytes(json_bytes(actual))
    if actual["decision"] != "pass":
        failed = [row["id"] for row in actual["results"] if row["decision"] != "pass"]
        raise ValueError("coverage requires passing, exactly attributed vector results; failed vectors: " + ", ".join(failed))
    manifests = [runner.read_json(path) for path in runner.manifest_paths(root)]
    positives: dict[str, list[str]] = {identifier: [] for identifier in by_id}
    negatives: dict[str, list[str]] = {identifier: [] for identifier in by_id}
    for manifest in manifests:
        for vector in manifest["vectors"]:
            identifier = vector["id"]
            for unit in units:
                if unit["kind"] == "rule":
                    if positive_rule_witness(unit, vector):
                        positives[unit["id"]].append(identifier)
                    if vector.get("expected_primary_id") == unit["id"]:
                        negatives[unit["id"]].append(identifier)
            for claimed in vector["covers"]:
                if claimed not in by_id:
                    raise ValueError(f"covers names an unknown unit: {claimed}")
                unit = by_id[claimed]
                if unit["kind"] == "rule":
                    valid = (
                        positive_rule_witness(unit, vector)
                        if vector["expected"] == "pass"
                        else vector.get("expected_primary_id") == claimed
                    )
                else:
                    value = loads_json_strict((root / vector["path"]).read_bytes())
                    valid = attribution.witnesses(unit, vector, value)
                if not valid:
                    raise ValueError(f"unsupported cover claim: {identifier}: {claimed}")
                (positives if vector["expected"] == "pass" else negatives)[claimed].append(
                    identifier
                )
    exclusions = {row["unit"]: row["justification"] for row in denominator["unit_exclusions"]}
    rows: list[dict[str, Any]] = []
    for unit in units:
        identifier = unit["id"]
        positive, negative = sorted(set(positives[identifier])), sorted(set(negatives[identifier]))
        status = (
            "excluded"
            if identifier in exclusions
            else "covered"
            if positive and negative
            else "positive-only"
            if positive
            else "negative-only"
            if negative
            else "uncovered"
        )
        row = {
            "unit": identifier,
            "kind": unit["kind"],
            "status": status,
            "positive_witnesses": positive,
            "negative_witnesses": negative,
        }
        if identifier in exclusions:
            row["justification"] = exclusions[identifier]
        rows.append(row)
    counts = {
        status: sum(row["status"] == status for row in rows)
        for status in ("covered", "positive-only", "negative-only", "uncovered", "excluded")
    }
    measured = len(rows) - counts["excluded"]
    return {
        "schema_version": "ecl_coverage_report_v1",
        "candidate_version": "1.0",
        "denominator_version": denominator["version"],
        "denominator_sha256": hashlib.sha256((root / DENOMINATOR).read_bytes()).hexdigest(),
        "unit_count": len(rows),
        "measured_unit_count": measured,
        "counts": counts,
        "coverage_ratio": round(counts["covered"] / measured, 6) if measured else 0,
        "units": rows,
        "uncovered": [row["unit"] for row in rows if row["status"] == "uncovered"],
        "excluded_schemas": denominator["excluded_schemas"],
        "measurement_limits": MEASUREMENT_LIMITS,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--replay-report", type=Path, help="Retain the complete corpus replay result used by this measurement")
    args = parser.parse_args(argv)
    try:
        content = json_bytes(compute(args.root, args.replay_report))
        path = args.root / REPORT
        if args.check:
            if not path.is_file() or path.read_bytes() != content:
                raise ValueError("coverage report is stale")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    except (OSError, ValueError, CanonicalizationError) as error:
        print("coverage denominator: " + str(error), file=sys.stderr)
        return 1
    print("coverage denominator: check passed" if args.check else "coverage denominator: generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
