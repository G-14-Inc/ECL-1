"""Private schema adaptation across registered and retrieved references.

Robert F. Tilley Jr.; G-14, Inc.
"""
from copy import deepcopy
import json
from pathlib import Path
import re

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource, Unresolvable
from referencing.jsonschema import DRAFT202012

from ecl_verify.resources import schema_registry, schema_is_valid
from ecl_verify.schema import ecl_format_checker
from ecl_verify import schema_patterns as patterns

DRAFT = "https://json-schema.org/draft/2020-12/schema"
URI = "https://example.test/schema/child"


def resource(schema):
    return Resource.from_contents(schema, default_specification=DRAFT202012)


def validator(schema, registry=None):
    return patterns.schema_validator(schema, registry=Registry() if registry is None else registry,
                                     format_checker=ecl_format_checker())


def referenced(schema, *, lazy=False):
    child = {"$schema": DRAFT, **schema}
    if lazy:
        def retrieve(uri):
            if uri != URI:
                raise NoSuchResource(ref=uri)
            return resource(child)
        registry = Registry(retrieve=retrieve)
    else:
        registry = Registry().with_resource(URI, resource(child))
    return validator({"$ref": URI}, registry)


def test_public_registry_preserves_ascii_token_exact_end():
    registry = schema_registry()
    uri = "https://externalcontrollayer.ai/ns/schema/common/1"
    before = deepcopy(registry.contents(uri))
    check = validator({"$ref": uri + "#/$defs/asciiToken"}, registry)
    assert check.is_valid("token")
    assert not check.is_valid("token\n")
    assert registry.contents(uri) == before
    assert registry.contents(uri)["$schema"] == DRAFT


@pytest.mark.parametrize("lazy", [False, True])
@pytest.mark.parametrize("pattern,value,expected", [
    ("^[a-z]+$", "abc", True), ("^[a-z]+$", "abc\n", False),
    (".", "x", True), (".", "\n", False), (".", "\r", False),
    (".", "\u2028", False), (".", "\u2029", False),
    (r"\d", "1", True), (r"\d", "١", False),
    (r"\D", "1", False), (r"\D", "١", True),
])
def test_references_retain_ecma_pattern_semantics(lazy, pattern, value, expected):
    assert referenced({"type": "string", "pattern": pattern}, lazy=lazy).is_valid(value) is expected


@pytest.mark.parametrize("lazy", [False, True])
@pytest.mark.parametrize("value,expected", [
    (float("nan"), False), (float("inf"), False), (float("-inf"), False),
    (True, False), (False, False), (0, True), (0.5, True), (1, True), (-1, False), (2, False),
])
def test_references_retain_finite_number_domain(lazy, value, expected):
    assert referenced({"type": "number", "minimum": 0, "maximum": 1}, lazy=lazy).is_valid(value) is expected


@pytest.mark.parametrize("value,expected", [
    ([True, 1], True), ([False, 0], True), ([1, 1.0], False),
    ([{"a": True}, {"a": 1}], True), ([[1], [1.0]], False),
])
def test_reference_unique_items_has_json_equality(value, expected):
    schema = {"type": "array", "uniqueItems": True}
    # The ordinary library also keeps booleans separate. This is a control,
    # not evidence that typed equality was previously wrong across references.
    assert Draft202012Validator(schema).is_valid(value) is expected
    assert referenced(schema).is_valid(value) is expected


@pytest.mark.parametrize("lazy", [False, True])
def test_references_keep_constant_memory_base64_matcher(lazy, monkeypatch):
    calls = []
    original = patterns._BASE64_EQUIVALENT
    class CountingMatcher:
        def match(self, value):
            calls.append(value)
            return original.match(value)
    monkeypatch.setattr(patterns, "_BASE64_EQUIVALENT", CountingMatcher())
    check = referenced({"type": "string", "pattern": patterns.BASE64_PATTERN}, lazy=lazy)
    assert check.is_valid("YQ==")
    assert not check.is_valid("YQ=!")
    assert calls == ["YQ==", "YQ=!"]


@pytest.mark.parametrize("lazy", [False, True])
def test_referenced_property_patterns_and_literal_annotations(lazy):
    literal = {"pattern": "^x$", "$schema": DRAFT}
    schema = {"type": "object", "patternProperties": {"^x$": {"const": literal}},
              "additionalProperties": False, "default": literal}
    before = deepcopy(schema)
    check = referenced(schema, lazy=lazy)
    assert check.is_valid({"x": literal})
    assert not check.is_valid({"x\n": literal})
    assert not check.is_valid({"x": {"pattern": r"^x\Z", "$schema": DRAFT}})
    assert schema == before


@pytest.mark.parametrize("crawl", [False, True])
def test_registered_alias_anchor_and_nested_id_keep_resolution(crawl):
    child = {"$schema": DRAFT, "$id": URI, "$defs": {
        "token": {"$anchor": "token", "type": "string", "pattern": "^[a-z]+$"},
        "nested": {"$id": "nested", "$schema": DRAFT, "$anchor": "nestedToken",
                   "type": "string", "pattern": "^[a-z]+$"}}}
    before = deepcopy(child)
    registry = Registry().with_resource("https://example.test/alias", resource(child))
    if crawl:
        registry = registry.crawl()
    original_uris = set(registry)
    for ref in ("https://example.test/alias#token", URI + "#token",
                "https://example.test/schema/nested#nestedToken"):
        check = validator({"$ref": ref}, registry)
        assert check.is_valid("abc")
        assert not check.is_valid("abc\n")
    assert child == before
    assert set(registry) == original_uris
    assert registry.contents("https://example.test/alias") == before


def test_lazy_retrieval_preserves_policy_and_source():
    child = {"$schema": DRAFT, "$id": URI, "$anchor": "token", "type": "string", "pattern": "^[a-z]+$"}
    before = deepcopy(child)
    calls = []
    def retrieve(uri):
        calls.append(uri)
        if uri != URI:
            raise NoSuchResource(ref=uri)
        return resource(child)
    registry = Registry(retrieve=retrieve)
    check = validator({"$ref": URI + "#token"}, registry)
    assert calls == []
    assert check.is_valid("abc")
    assert not check.is_valid("abc\n")
    assert calls and set(calls) == {URI}
    assert child == before and len(registry) == 0
    missing = validator({"$ref": "https://example.test/missing"}, registry)
    with pytest.raises(Unresolvable):
        missing.is_valid("abc")
    assert calls[-1] == "https://example.test/missing"


def test_dynamic_anchor_recursion_keeps_referenced_patterns():
    schema = {"$schema": DRAFT, "$id": URI, "$dynamicAnchor": "node", "type": "object",
              "properties": {"token": {"type": "string", "pattern": "^[a-z]+$"},
                             "next": {"$dynamicRef": "#node"}}, "required": ["token"],
              "additionalProperties": False}
    check = referenced(schema)
    assert check.is_valid({"token": "a", "next": {"token": "b"}})
    assert not check.is_valid({"token": "a", "next": {"token": "b\n"}})


@pytest.mark.parametrize("pattern", ["^[][a]$", "^[^][a]$"])
@pytest.mark.parametrize("entrypoint", ["pattern", "root", "properties"])
def test_empty_character_classes_fail_closed(pattern, entrypoint):
    with pytest.raises(ValueError, match="empty character class"):
        if entrypoint == "pattern":
            patterns.python_pattern(pattern)
        elif entrypoint == "root":
            validator({"type": "string", "pattern": pattern})
        else:
            validator({"type": "object", "patternProperties": {pattern: {"type": "string"}}})


@pytest.mark.parametrize("pattern,value,expected", [
    (r"^[\]]$", "]", True), (r"^[\]]$", "a", False),
    (r"^[\^]$", "^", True), (r"^[^^]$", "a", True), (r"^[^^]$", "^", False),
    (r"^[^\]]$", "a", True), (r"^[^\]]$", "]", False),
    (r"^[\]a]$", "]", True), (r"^[\]a]$", "a", True),
    ("^[a-z]$", "a", True), ("^[a-z]$", "1", False),
])
def test_nonempty_character_class_controls(pattern, value, expected):
    assert validator({"type": "string", "pattern": pattern}).is_valid(value) is expected


@pytest.mark.parametrize("pattern", ["[]", "[^]", "[]a", "[^]a"])
def test_standalone_empty_classes_remain_refused(pattern):
    with pytest.raises((ValueError, re.error)):
        validator({"type": "string", "pattern": pattern})


def test_whole_public_schema_reference_retains_nested_patterns():
    root = Path(__file__).resolve().parents[1]
    uri = "https://externalcontrollayer.ai/ns/schema/dcmp/2"
    value = json.loads((root / "conformance/vectors/dcmp-2/valid-decision-request.json").read_bytes())
    check = validator({"$ref": uri}, schema_registry())
    assert check.is_valid(value)
    assert schema_is_valid(uri, value)
    value["action"]["operation"] += "\n"
    assert not check.is_valid(value)
    assert not schema_is_valid(uri, value)
