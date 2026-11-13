"""ECMA digit semantics and fail-closed public custom-pattern boundaries."""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest
from referencing import Registry

from ecl_verify.schema import ecl_format_checker
from ecl_verify.schema_patterns import pattern_matches, python_pattern, schema_validator, validation_schema

ROOT = Path(__file__).resolve().parents[3]
CASES = [case for case in json.loads((ROOT / "tests/fixtures/schema-constructor-cases.json").read_text()) if case["id"].startswith("regex-")]


def validator(schema: object):
    return schema_validator(schema, registry=Registry(), format_checker=ecl_format_checker())


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_custom_pattern_and_property_pattern(case: dict) -> None:
    pattern = case["schema"]["pattern"]
    instance = case["instance"]
    property_schema = {"type": "object", "patternProperties": {pattern: {"const": "ok"}}, "additionalProperties": False}
    if not case["build"]:
        with pytest.raises((ValueError, re.error)):
            python_pattern(pattern)
        with pytest.raises((ValueError, re.error)):
            validator(case["schema"])
        with pytest.raises((ValueError, re.error)):
            validator(property_schema)
        return
    assert pattern_matches(pattern, instance) is case["valid"]
    assert validator(case["schema"]).is_valid(instance) is case["valid"]
    assert validator(property_schema).is_valid({instance: "ok"}) is case["valid"]


@pytest.mark.parametrize("pattern", [r"^\d+$", r"^[\D]+$", r"^.+$", r"^\\d$", r"^a(?!b)c$"])
def test_repeated_private_adaptation_preserves_pattern_identity(pattern: str) -> None:
    translated = python_pattern(pattern)
    assert python_pattern(translated) == translated
    assert python_pattern(copy.deepcopy(translated)) == translated
    original = {"pattern": pattern, "description": pattern, "default": pattern,
                "patternProperties": {pattern: {"const": pattern}}}
    snapshot = copy.deepcopy(original)
    once = validation_schema(original)
    twice = validation_schema(copy.deepcopy(once))
    assert twice == once
    assert original == snapshot
    assert once["description"] == once["default"] == pattern
    assert next(iter(once["patternProperties"].values()))["const"] == pattern


@pytest.mark.parametrize("reverse", [False, True])
def test_equivalent_property_patterns_keep_both_constraints(reverse: bool) -> None:
    rows = [(r"^\d$", {"minLength": 2}), (r"^[0-9]$", {"maxLength": 1})]
    if reverse:
        rows.reverse()
    schema = {"type": "object", "patternProperties": dict(rows), "additionalProperties": False}
    assert not validator(schema).is_valid({"1": "x"})
    assert not validator(schema).is_valid({"1": "xx"})
    # Compatible constraints still accept a genuine positive control.
    rows = [(r"^\d$", {"minLength": 1}), (r"^[0-9]$", {"maxLength": 1})]
    if reverse:
        rows.reverse()
    schema["patternProperties"] = dict(rows)
    assert validator(schema).is_valid({"1": "x"})
    assert not validator(schema).is_valid({"١": "x"})
