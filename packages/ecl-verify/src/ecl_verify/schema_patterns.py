"""Translate the anchors and dot in the repository's ECMA-262 pattern subset.

This is not a general JavaScript regular-expression engine. Repository schemas
use explicit character classes, ordinary groups and lookarounds without flags.
Keep their public bytes unchanged; translate only private validation copies.
ECMA-262's dollar assertion requires the actual end without multiline mode,
and its dot excludes all four line terminators. Python differs on both points.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from jsonschema.protocols import Validator
from jsonschema.validators import extend
from referencing import Registry


def python_pattern(pattern: str) -> str:
    out: list[str] = []
    escaped = False
    in_class = False
    for character in pattern:
        if escaped:
            out.append(character)
            escaped = False
        elif character == "\\":
            out.append(character)
            escaped = True
        elif character == "[" and not in_class:
            in_class = True
            out.append(character)
        elif character == "]" and in_class:
            in_class = False
            out.append(character)
        elif character == "$" and not in_class:
            out.append("\\Z")
        elif character == "." and not in_class:
            out.append("[^\\n\\r\\u2028\\u2029]")
        else:
            out.append(character)
    return "".join(out)


# The canonical base64 pattern of the repository's schemas. Python's backtracking engine keeps
# state for each repetition of its four-character group, about 30 bytes for each character of
# the input, so a payload within the schema's maximum length could cost hundreds of megabytes
# before any other limit applies (IE1-029, EBMP2-062). It is decided by an equivalent check in
# constant memory: alphabet characters, then at most two "=", in a length that is a multiple of
# four. ECMA-262 and Go's engine match the pattern itself without that cost.
BASE64_PATTERN = "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
_BASE64_EQUIVALENT = re.compile(r"\A[A-Za-z0-9+/]*={0,2}\Z")
_BASE64_TRANSLATED = python_pattern(BASE64_PATTERN)


# The dialect of every repository schema. A private validation copy leaves out a `$schema` that
# names it, so that a validator that follows a reference into the copy keeps the class that
# applies the ECMA pattern conventions (and the pattern above in constant memory), instead of
# selecting the base Draft 2020-12 class from the copy's `$schema`; the copy is still read as
# Draft 2020-12, the default of the registry's resources.
DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"


def validation_schema(value: Any) -> Any:
    """Copy a schema, adapting pattern keywords without touching const/enum data."""
    if isinstance(value, list):
        return [validation_schema(item) for item in value]
    if not isinstance(value, dict):
        return value
    return {
        key: python_pattern(item)
        if key == "pattern" and isinstance(item, str)
        else item
        if key in ("const", "enum", "default", "examples")
        else validation_schema(item)
        for key, item in value.items()
        if not (key == "$schema" and item == DRAFT_2020_12)
    }


def pattern_matches(pattern: str, instance: str) -> bool:
    """Whether `instance` matches the repository pattern `pattern` under ECMA-262 semantics."""
    translated = python_pattern(pattern)
    if translated == _BASE64_TRANSLATED:
        return len(instance) % 4 == 0 and _BASE64_EQUIVALENT.match(instance) is not None
    return re.search(translated, instance) is not None


def _pattern(
    validator: Any, pattern: str, instance: Any, _schema: Any
) -> Iterator[ValidationError]:
    if validator.is_type(instance, "string") and not pattern_matches(pattern, instance):
        yield ValidationError(f"{instance!r} does not match {pattern!r}")


_ECMA_VALIDATOR = extend(Draft202012Validator, validators={"pattern": _pattern})


def schema_validator(
    schema: Any, *, registry: Registry[Any], format_checker: FormatChecker
) -> Validator:
    """Keep the root schema exact while enforcing its ECMA pattern keywords.

    Referenced private resources are separately adapted because jsonschema can
    select the base draft validator when a referenced schema names its draft.
    """
    return cast(
        Validator, _ECMA_VALIDATOR(schema, registry=registry, format_checker=format_checker)
    )
