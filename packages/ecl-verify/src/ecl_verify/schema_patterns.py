"""Translate the repository's supported ECMA-262 Unicode pattern subset.

This is not a general JavaScript regular-expression engine. Repository schemas
use explicit character classes, ordinary groups and lookarounds without flags.
Keep their public bytes unchanged; translate only private validation copies.
Unsupported escapes and group syntax fail closed rather than acquiring Python
semantics. ECMA-262's digit escapes use ASCII digits; its dollar assertion
requires the actual end without multiline mode, and its dot excludes all four
line terminators. Python differs on these points.
"""

from __future__ import annotations

import re
import math
from copy import deepcopy
from collections.abc import Iterator
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from jsonschema.protocols import Validator
from jsonschema.validators import extend
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012


class _PythonPattern(str):
    """An already-adapted private pattern, including Python's end assertion."""


def python_pattern(pattern: str) -> str:
    """Adapt the supported ECMA Unicode syntax; refuse incompatible constructs.

    A private marker makes repeated schema adaptation idempotent without accepting
    Python's internal escapes as public ECMA syntax. Neither schema files nor
    ordinary string annotations are changed.
    """
    if isinstance(pattern, _PythonPattern):
        return pattern
    out: list[str] = []
    in_class = False
    class_start = -1
    class_atom = 0  # 0: none; 1: single character; 2: set; 3: completed range.
    class_range = False
    groups: list[bool] = []
    index = 0

    def record_class_atom(is_set: bool) -> None:
        nonlocal class_atom, class_range
        if not in_class:
            return
        if class_range:
            if is_set:
                raise ValueError("a character-class escape cannot be a range endpoint")
            class_atom, class_range = 3, False
        else:
            class_atom = 2 if is_set else 1

    while index < len(pattern):
        character = pattern[index]
        following = pattern[index + 1:index + 2]
        if character == "\\":
            allowed = r"^$\.*+?()[]{}|/dDfnrtv0x"
            if not following or following not in allowed and not (in_class and following == "-"):
                raise ValueError("unsupported ECMA-262 Unicode escape")
            if following == "0" and pattern[index + 2:index + 3] in "0123456789" and index + 2 < len(pattern):
                raise ValueError("legacy octal escapes are unsupported")
            record_class_atom(following in "dD")
            if following == "x":
                digits = pattern[index + 2:index + 4]
                if len(digits) != 2 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                    raise ValueError("invalid hexadecimal escape")
                out.append(pattern[index:index + 4])
                index += 4
                continue
            if following == "d":
                out.append("0-9" if in_class else "[0-9]")
            elif following == "D":
                out.append(r"\x00-\x2f\x3a-\U0010ffff" if in_class else "[^0-9]")
            else:
                out.append(pattern[index:index + 2])
            index += 2
            continue
        if character == "[":
            if in_class:
                raise ValueError("nested character-class syntax is unsupported")
            in_class, class_start, class_atom, class_range = True, index, 0, False
        elif character == "]":
            if not in_class:
                raise ValueError("unescaped closing character-class delimiter")
            if index == class_start + 1 or (
                index == class_start + 2 and pattern[class_start + 1] == "^"
            ):
                raise ValueError("empty character classes are unsupported")
            in_class = False
        elif in_class:
            if character == "-" and class_atom in (1, 2) and following and following != "]":
                if class_atom == 2:
                    raise ValueError("a character-class escape cannot be a range endpoint")
                class_atom, class_range = 0, True
            elif not (index == class_start + 1 and character == "^"):
                record_class_atom(False)
        elif character == "(":
            assertion = False
            if following == "?":
                if pattern.startswith(("(?=", "(?!", "(?<=", "(?<!"), index):
                    assertion = True
                elif not pattern.startswith("(?:", index):
                    raise ValueError("unsupported ECMA-262 group construct")
            groups.append(assertion)
        elif character == ")":
            if not groups:
                raise ValueError("unmatched closing group delimiter")
            if groups.pop() and following and following in "*+?{":
                raise ValueError("a lookaround assertion cannot be quantified")
        elif character in "^$":
            if following and following in "*+?{":
                raise ValueError("an anchor assertion cannot be quantified")
            if character == "$":
                out.append(r"\Z")
                index += 1
                continue
        elif character in "*+?" and following == "+":
            raise ValueError("possessive quantifiers are not ECMA-262 syntax")
        elif character == "{":
            quantifier = re.match(r"\{[0-9]+(?:,[0-9]*)?\}", pattern[index:])
            if quantifier is None:
                raise ValueError("invalid ECMA-262 quantifier")
            if pattern[index + len(quantifier.group()):index + len(quantifier.group()) + 1] == "+":
                raise ValueError("possessive quantifiers are not ECMA-262 syntax")
            out.append(quantifier.group())
            index += len(quantifier.group())
            continue
        elif character == "}":
            raise ValueError("unescaped closing quantifier delimiter")
        elif character == ".":
            out.append(r"[^\n\r\u2028\u2029]")
            index += 1
            continue
        out.append(character)
        index += 1
    translated = _PythonPattern("".join(out))
    re.compile(translated)  # Refuse incomplete groups/classes and invalid ranges at adaptation.
    return translated

# The canonical base64 pattern of the repository's schemas. Python's backtracking engine keeps
# state for each repetition of its four-character group, about 30 bytes for each character of
# the input, so a payload within the schema's maximum length could cost hundreds of megabytes
# before any other limit applies (IE1-029, EBMP2-062). It is decided by an equivalent check in
# constant memory: alphabet characters, then at most two "=", in a length that is a multiple of
# four. ECMA-262 and Go's engine match the pattern itself without that cost.
BASE64_PATTERN = "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
_BASE64_EQUIVALENT = re.compile(r"\A[A-Za-z0-9+/]*={0,2}\Z")
_BASE64_TRANSLATED = python_pattern(BASE64_PATTERN)

# OTLP bytes use the Protobuf JSON domain: either alphabet (including mixtures),
# padded or unpadded. Preserve that exact schema language without retaining a
# backtracking frame for every four-character group. With padding the total
# length must be a multiple of four; without it only a remainder of one is invalid.
_OTLP_BASE64_PATTERN = "^(?:[A-Za-z0-9+/_-]{4})*(?:[A-Za-z0-9+/_-]{2}(?:==)?|[A-Za-z0-9+/_-]{3}=?)?$"
_OTLP_BASE64_EQUIVALENT = re.compile(r"\A[A-Za-z0-9+/_-]*={0,2}\Z")
_OTLP_BASE64_TRANSLATED = python_pattern(_OTLP_BASE64_PATTERN)


# The dialect of every repository schema. A private validation copy leaves out a `$schema` that
# names it, so that a validator that follows a reference into the copy keeps the class that
# applies the ECMA pattern conventions (and the pattern above in constant memory), instead of
# selecting the base Draft 2020-12 class from the copy's `$schema`; the copy is still read as
# Draft 2020-12, the default of the registry's resources.
DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"


def validation_schema(value: Any) -> Any:
    """Copy schema positions, adapting patterns while retaining annotation and literal data.

    Names under properties/$defs are data keys, even when named ``const`` or
    ``default``. patternProperties keys are patterns, not schema keywords.
    """
    if not isinstance(value, dict):
        return deepcopy(value)
    maps = {"properties", "$defs", "definitions", "dependentSchemas"}
    lists = {"allOf", "anyOf", "oneOf", "prefixItems"}
    singles = {"additionalProperties", "unevaluatedProperties", "propertyNames", "items",
               "unevaluatedItems", "contains", "not", "if", "then", "else", "contentSchema"}
    result = {}
    for key, item in value.items():
        if key == "$schema" and item == DRAFT_2020_12:
            continue
        if key == "pattern" and isinstance(item, str):
            result[key] = python_pattern(item)
        elif key in maps and isinstance(item, dict):
            result[key] = {name: validation_schema(child) for name, child in item.items()}
        elif key == "patternProperties" and isinstance(item, dict):
            patterns = {}
            for pattern, child in item.items():
                translated, adapted = python_pattern(pattern), validation_schema(child)
                if translated in patterns:
                    # Equivalent source patterns still apply every constraint. Keep the
                    # conjunction at this property value, preserving additionalProperties
                    # and evaluated-property behavior at the enclosing schema location.
                    patterns[translated] = {"allOf": [patterns[translated], adapted]}
                else:
                    patterns[translated] = adapted
            result[key] = patterns
        elif key in lists and isinstance(item, list):
            result[key] = [validation_schema(child) for child in item]
        elif key in singles:
            result[key] = validation_schema(item)
        else:
            result[key] = deepcopy(item)
    return result


def pattern_matches(pattern: str, instance: str) -> bool:
    """Whether `instance` matches the repository pattern `pattern` under ECMA-262 semantics."""
    translated = python_pattern(pattern)
    if translated == _BASE64_TRANSLATED:
        return len(instance) % 4 == 0 and _BASE64_EQUIVALENT.match(instance) is not None
    if translated == _OTLP_BASE64_TRANSLATED:
        length_valid = len(instance) % 4 == 0 if instance.endswith("=") else len(instance) % 4 != 1
        return length_valid and _OTLP_BASE64_EQUIVALENT.match(instance) is not None
    return re.search(translated, instance) is not None


def _pattern(
    validator: Any, pattern: str, instance: Any, _schema: Any
) -> Iterator[ValidationError]:
    if validator.is_type(instance, "string") and not pattern_matches(pattern, instance):
        yield ValidationError(f"{instance!r} does not match {pattern!r}")


def _json_equality_key(value: Any) -> Any:
    """Hashable JSON Schema equality: numeric values agree; booleans stay distinct."""
    if value is None:
        return ("null",)
    if type(value) is bool:
        return ("boolean", value)
    if type(value) is str:
        return ("string", value)
    if type(value) is int or type(value) is float and math.isfinite(value):
        return ("number", value)
    if type(value) is list:
        return ("array", tuple(_json_equality_key(item) for item in value))
    if type(value) is dict and all(type(key) is str for key in value):
        return ("object", frozenset((key, _json_equality_key(item)) for key, item in value.items()))
    raise TypeError("value is outside the JSON data model")


def _unique_items(
    validator: Any, required: bool, instance: Any, schema: Any
) -> Iterator[ValidationError]:
    if not required or not validator.is_type(instance, "array"):
        return
    seen = set()
    try:
        for item in instance:
            key = _json_equality_key(item)
            if key in seen:
                yield ValidationError("array has non-unique elements")
                return
            seen.add(key)
    except TypeError:
        # Preserve the underlying library's behavior for caller-supplied non-JSON types.
        yield from Draft202012Validator.VALIDATORS["uniqueItems"](validator, required, instance, schema)


def _finite_json_number(_checker: Any, value: Any) -> bool:
    """JSON Schema numbers exclude host NaN/infinities and keep booleans separate."""
    return type(value) is int or type(value) is float and math.isfinite(value)


_ECMA_VALIDATOR = extend(
    Draft202012Validator,
    validators={"pattern": _pattern, "uniqueItems": _unique_items},
    type_checker=Draft202012Validator.TYPE_CHECKER.redefine("number", _finite_json_number),
)


def _validation_registry(registry: Registry[Any]) -> Registry[Any]:
    """Adapt registered and retrieved ECL schemas without changing the caller's registry."""
    def adapt(resource: Resource[Any]) -> Resource[Any]:
        return Resource.from_contents(
            validation_schema(resource.contents), default_specification=DRAFT202012
        )

    def retrieve(uri: str) -> Resource[Any]:
        # Delegate to the caller's retrieval policy, including its missing-resource
        # errors; only the returned schema copy belongs to this validator.
        return adapt(registry.get_or_retrieve(uri).value)

    return Registry(retrieve=retrieve).with_resources(
        (uri, adapt(resource)) for uri, resource in registry.items()
    ).crawl()


def schema_validator(
    schema: Any, *, registry: Registry[Any], format_checker: FormatChecker
) -> Validator:
    """Validate through a private copy that enforces the schema's ECMA patterns.

    Root and referenced private resources are adapted because jsonschema can
    select the base draft validator when a referenced schema names its draft.
    """
    return cast(
        Validator, _ECMA_VALIDATOR(
            validation_schema(schema), registry=_validation_registry(registry),
            format_checker=format_checker,
        )
    )
