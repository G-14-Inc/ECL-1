"""The ECL schemas and registries, found the same way in a source checkout and in a wheel.

A wheel carries them as package data under `_data/`, copied there at build time by the package's
build step (ecl_verify_build.py). A checkout has them as the top-level `schemas/` and
`registries/`, so it never needs a copy, and a stale `_data/` beside its sources cannot shadow the
real files.

What is cached is immutable (the bytes of each file, the data root) or private (the registry and
the semantic validator that `object_findings` uses: no public function returns either, or anything
that refers to them). Each document, registry and validator that a public function returns is built
for that call from the cached bytes, and so are the schemas that a validator's errors point to. A
caller may change any of them without affecting a later call or `object_findings`, which reports
only strings. `schema_is_valid` also uses the private registry and returns only a boolean.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping
from functools import cache
from itertools import chain, islice
from pathlib import Path
from types import MappingProxyType
from typing import Any

from jsonschema.protocols import Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from .canonical import loads_json_strict
from .schema import ecl_format_checker
from .schema_patterns import schema_validator, validation_schema
from .semantic import (
    Finding,
    SemanticValidator,
    active_extension_versions,
    allocated_extension_versions,
    composable_extensions,
)

SCHEMA_INVALID = "ecl.error.schema-invalid.v1"
# Pilot contract, section 8 (parser limits, IE1-028): an object nests at most this deep.
MAX_DEPTH = 32
# Pilot contract, section 8 (parser limits, IE1-028): an object has at most this many JSON nodes.
MAX_NODES = 10_000
# A hostile value must not make a finding, or the list of findings, as large as the value is.
MAX_FINDINGS_PER_RULE = 100
MAX_TEXT = 200
ELLIPSIS = "\N{HORIZONTAL ELLIPSIS}"

_BUNDLED = "_data"
_DIRECTORIES = ("schemas", "registries")
_PROTOCOL_SCHEMAS = {
    "DCMP-2": "https://externalcontrollayer.ai/ns/schema/dcmp/2",
    "EBMP-2": "https://externalcontrollayer.ai/ns/schema/ebmp/2",
}
_ENVELOPE_SCHEMA = "https://externalcontrollayer.ai/ns/schema/integrity-envelope/1"
_ENVELOPE_VERSION = "ECL-IE-1"


def _holds_data(root: Path) -> bool:
    return all((root / name).is_dir() for name in _DIRECTORIES)


def locate_data(module_file: Path) -> Path:
    """The directory with `schemas/` and `registries/` for the module at `module_file`.

    That is the repository root when the module sits in a checkout, as packages/ecl-verify/src/ecl_verify/,
    and otherwise the `_data` directory beside the module.
    """
    package = module_file.resolve().parent
    # A checkout holds the module at packages/ecl-verify/src/ecl_verify/, four levels down.
    repository = package.parents[3] if len(package.parents) > 3 else None
    checkout = (
        repository / "packages" / "ecl-verify" / "src" / "ecl_verify"
        if repository is not None
        else None
    )
    if repository is not None and package == checkout and _holds_data(repository):
        return repository
    if _holds_data(package / _BUNDLED):
        return package / _BUNDLED
    raise FileNotFoundError(
        f"no schemas/ and registries/ for {package}: it is neither in a checkout"
        f" nor an installed wheel with {_BUNDLED}/"
    )


@cache
def data_root() -> Path:
    """Where `schemas/` and `registries/` are for this installation."""
    return locate_data(Path(__file__))


def _read_json_files(directory: str) -> dict[str, bytes]:
    paths = sorted((data_root() / directory).glob("*.json"))
    return {path.name: path.read_bytes() for path in paths if path.is_file()}


def _index_by_id(files: Mapping[str, bytes]) -> dict[str, bytes]:
    """The schema files (name to bytes) that have an `$id`, by that `$id`."""
    indexed: dict[str, bytes] = {}
    for name, data in files.items():
        document = loads_json_strict(data)
        schema_id = document.get("$id") if isinstance(document, dict) else None
        if schema_id is None:
            continue
        if not isinstance(schema_id, str) or schema_id in indexed:
            raise ValueError(f"schemas/{name}: $id must be a string that no other schema has")
        indexed[schema_id] = data
    return indexed


@cache
def _schema_files() -> Mapping[str, bytes]:
    return MappingProxyType(_index_by_id(_read_json_files("schemas")))


@cache
def _registry_files() -> Mapping[str, bytes]:
    """The bytes of each registry, by name: the file name without `.json`."""
    files = _read_json_files("registries")
    return MappingProxyType({name.removesuffix(".json"): data for name, data in files.items()})


def schema_documents() -> Mapping[str, Mapping[str, Any]]:
    """Every schema in schemas/ that has an `$id`, by that `$id`."""
    return {schema_id: loads_json_strict(data) for schema_id, data in _schema_files().items()}


def _build_registry(*, validation: bool = False) -> Registry[Any]:
    pairs = (
        (
            schema_id,
            Resource.from_contents(
                validation_schema(document) if validation else document,
                default_specification=DRAFT202012,
            ),
        )
        for schema_id, document in schema_documents().items()
    )
    return Registry().with_resources(pairs).crawl()


@cache
def _shared_registry() -> Registry[Any]:
    """The registry that `object_findings` uses. No public function returns it."""
    return _build_registry(validation=True)


def schema_registry() -> Registry[Any]:
    """Every schema by `$id`, as Draft 2020-12 resources."""
    return _build_registry()


def _schema_data(schema_id: str) -> bytes:
    try:
        return _schema_files()[schema_id]
    except KeyError:
        raise KeyError(f"no schema has the $id {schema_id!r}") from None


def _validator(data: bytes, registry: Registry[Any]) -> Validator:
    return schema_validator(
        loads_json_strict(data),
        registry=registry,
        format_checker=ecl_format_checker(),
    )


def validator_for(schema_id: str) -> Validator:
    """A Draft 2020-12 validator for the schema with this `$id`, with the ECL format checks.

    The validator resolves references in a registry built for this call. An error it reports
    points to the schemas in that registry (`error.schema`), so changing them changes only this
    validator.
    """
    return _validator(_schema_data(schema_id), _build_registry(validation=True))


def schema_is_valid(schema_id: str, value: Any) -> bool:
    """Check a schema without exposing a validator, its errors or the cached schema registry.

    Each call creates its own validator. Its referenced schemas remain in the same private
    registry used by object_findings; no object returned by this function can mutate them.
    """
    return bool(_validator(_schema_data(schema_id), _shared_registry()).is_valid(value))


def registry_document(name: str) -> Mapping[str, Any]:
    """The registry in registries/<name>.json, for example "error-codes"."""
    try:
        data = _registry_files()[name]
    except KeyError:
        raise KeyError(f"no registry is named {name!r}") from None
    document = loads_json_strict(data)
    if not isinstance(document, dict):
        raise ValueError(f"registries/{name}.json is not a JSON object")
    return document


def extension_value_validators(
    entries: Iterable[Mapping[str, Any]],
) -> dict[str, Callable[[Any], list[str]]]:
    """For each registry entry that names a value schema (XR1-023), a function that returns the
    messages of every way a value fails that schema."""

    def messages(validator: Validator) -> Callable[[Any], list[str]]:
        def check(value: Any) -> list[str]:
            return [error.message for error in validator.iter_errors(value)]

        return check

    result: dict[str, Callable[[Any], list[str]]] = {}
    for entry in entries:
        attributes = entry.get("attributes")
        schema_id = attributes.get("value_schema") if isinstance(attributes, Mapping) else None
        if isinstance(schema_id, str):
            result[str(entry["id"])] = messages(validator_for(schema_id))
    return result


@cache
def _semantics() -> SemanticValidator:
    """Seeded from the extensions registry, as scripts/run_conformance.py seeds it."""
    entries = registry_document("extensions")["entries"]
    return SemanticValidator(
        (entry["id"] for entry in entries),
        extension_value_validators(entries),
        allocated_versions=allocated_extension_versions(entries),
        composable=composable_extensions(entries),
        active_versions=active_extension_versions(entries),
    )


def _cut(text: str) -> str:
    return text if len(text) <= MAX_TEXT else text[: MAX_TEXT - len(ELLIPSIS)] + ELLIPSIS


def _bounded(rule_id: str, path: str, message: str) -> Finding:
    return Finding(rule_id, _cut(path), _cut(message))


def _invalid(path: str, message: str) -> Finding:
    return _bounded(SCHEMA_INVALID, path, message)


def _pointer(parts: Iterable[object]) -> str:
    return "/" + "/".join(str(part).replace("~", "~0").replace("/", "~1") for part in parts)


def _schema_id_for(value: Mapping[str, Any]) -> str | None:
    protocol = value.get("protocol")
    if isinstance(protocol, str) and protocol in _PROTOCOL_SCHEMAS:
        return _PROTOCOL_SCHEMAS[protocol]
    if value.get("envelope_version") == _ENVELOPE_VERSION:
        return _ENVELOPE_SCHEMA
    return None


def _without_shadows(errors: list[Any]) -> list[Any]:
    """`errors` without each unevaluatedProperties error that an error at or below it may explain.

    A subschema that fails does not mark its members as evaluated, so the unevaluatedProperties of
    its parent then reports all of them: a shadow of the real error, and a misleading one.
    """
    paths = [tuple(error.absolute_path) for error in errors]
    at_or_below: Counter[tuple[Any, ...]] = Counter()
    for path in paths:
        at_or_below.update(path[:depth] for depth in range(len(path) + 1))
    kept = [
        error
        for error, path in zip(errors, paths, strict=True)
        if error.validator != "unevaluatedProperties" or at_or_below[path] == 1
    ]
    return kept or errors


def _causes(error: Any) -> Iterator[Any]:
    """The errors that say what is wrong in `error`: itself, unless it is a failed oneOf or anyOf.

    The message of a failed oneOf or anyOf is the whole value and "is not valid under any of the
    given schemas". Its causes are the errors of the branch that came closest, the one with the
    fewest errors (the first, on a tie).
    """
    if error.validator not in {"oneOf", "anyOf"} or not error.context:
        yield error
        return
    branches: dict[Any, list[Any]] = {}
    for inner in error.context:
        branches.setdefault(next(iter(inner.relative_schema_path), None), []).append(inner)
    closest = min(branches.values(), key=len)
    for inner in _without_shadows(closest):
        yield from _causes(inner)


def _schema_findings(schema_id: str, value: Mapping[str, Any]) -> list[Finding]:
    validator = _validator(_schema_data(schema_id), _shared_registry())
    causes = chain.from_iterable(map(_causes, validator.iter_errors(value)))
    errors = list(islice(causes, MAX_FINDINGS_PER_RULE + 1))
    findings = [
        _invalid(_pointer(error.absolute_path), f"{error.validator}: {error.message}")
        for error in errors[:MAX_FINDINGS_PER_RULE]
    ]
    if len(errors) > MAX_FINDINGS_PER_RULE:
        findings.append(_invalid("/", "more schema errors follow, and are not listed"))
    return findings


def _capped(findings: list[Finding]) -> list[Finding]:
    """The first MAX_FINDINGS_PER_RULE findings of each rule, then one per rule counting the rest."""
    kept: list[Finding] = []
    found: dict[str, int] = {}
    for finding in findings:
        found[finding.rule_id] = found.get(finding.rule_id, 0) + 1
        if found[finding.rule_id] <= MAX_FINDINGS_PER_RULE:
            kept.append(finding)
    kept += [
        _bounded(rule_id, "/", f"{count - MAX_FINDINGS_PER_RULE} more follow, and are not listed")
        for rule_id, count in found.items()
        if count > MAX_FINDINGS_PER_RULE
    ]
    return kept


def _semantic_findings(value: dict[str, Any]) -> list[Finding]:
    found = _semantics().validate(value)
    return _capped([_bounded(item.rule_id, item.path, item.message) for item in found])


def _limit_exceeded(value: dict[str, Any]) -> str | None:
    """A message saying which parser limit `value` exceeds, or None if it keeps to both.

    Depth counts the objects and arrays around a value, the top-level object being 1. Nodes are
    every object, array and scalar value. The walk is iterative and stops at the first excess, so it
    takes about MAX_NODES steps at most and cannot reach Python's recursion limit. A value that
    holds itself is met again and again, and is refused for its depth.
    """
    nodes = 1
    pending: list[tuple[Any, int]] = [(value, 1)]
    while pending:
        container, depth = pending.pop()
        if depth > MAX_DEPTH:
            return f"nesting depth exceeds {MAX_DEPTH}"
        children = container.values() if isinstance(container, dict) else container
        nodes += len(children)
        if nodes > MAX_NODES:
            return f"node count exceeds {MAX_NODES}"
        pending.extend((child, depth + 1) for child in children if isinstance(child, dict | list))
    return None


def _guarded(step: str, check: Callable[[], list[Finding]]) -> list[Finding]:
    """The findings of `check`; if it fails, one finding instead, since a crash must not pass."""
    try:
        return check()
    except Exception as error:
        return [_invalid("/", f"{step} could not be completed: {type(error).__name__}")]


def _validate(value: object) -> list[Finding]:
    if not isinstance(value, dict):
        return [_invalid("/", "an ECL object must be a JSON object")]
    excess = _limit_exceeded(value)
    if excess is not None:
        return [_invalid("/", excess)]
    schema_id = _schema_id_for(value)
    if schema_id is None:
        return [_invalid("/", "not a DCMP-2 or EBMP-2 object, and not an ECL-IE-1 envelope")]
    findings = _guarded("schema validation", lambda: _schema_findings(schema_id, value))
    findings += _guarded("semantic validation", lambda: _semantic_findings(value))
    return sorted(findings, key=lambda item: (item.rule_id, item.path, item.message))


def object_findings(value: Mapping[str, Any]) -> list[Finding]:
    """The schema and semantic findings for a DCMP-2, EBMP-2 or ECL-IE-1 value.

    Total: it returns findings for any input and never raises. Something that is not a JSON
    object, or not one of those three kinds, yields one `ecl.error.schema-invalid.v1` finding.
    Only a `dict` is a JSON object: a `Mapping` of another kind is refused too, which fails closed
    and agrees with jsonschema, whose `object` type is `dict`.

    First, before any other work, it enforces the parser limits of the pilot contract, section 8:
    an object nested deeper than MAX_DEPTH (32) or with more than MAX_NODES (10 000) nodes gets one
    such finding, and nothing is validated. Depth counts the objects and arrays around a value, the
    top-level object being 1; nodes are all the objects, arrays and scalar values. The count is
    iterative and stops at the first excess.

    A schema finding names the keyword that failed and points at the member that is wrong. For a
    failed oneOf that is the error of the closest branch, not the whole value. Each of the two
    checks lists at most MAX_FINDINGS_PER_RULE findings of a rule, then one under the same rule
    that says more follow, so no rule is dropped. Paths and messages are cut to MAX_TEXT
    characters, and a cut ends in an ellipsis.
    """
    return _guarded("object validation", lambda: _validate(value))
