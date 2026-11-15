"""Validate the published scope registry against its schema, source table and references.

Robert F. Tilley Jr.; G-14, Inc.
"""
from copy import deepcopy
import json
from pathlib import Path
import re

from ecl_verify.resources import validator_for

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads((ROOT / path).read_text())


def test_scope_registry_schema_and_negative_controls():
    value = read("registries/scope-checks.json")
    validator = validator_for("https://externalcontrollayer.ai/ns/schema/scope-checks/1")
    validator.validate(value)
    for member in ("items", "checks", "object_sets", "evidence_levels"):
        changed = deepcopy(value)
        del changed[member]
        assert not validator.is_valid(changed), member
    changed = deepcopy(value)
    changed["items"][0]["established"] = "unconditionally"
    assert not validator.is_valid(changed)


def test_scope_registry_references_and_normative_item_order():
    value = read("registries/scope-checks.json")
    ids = {}
    for group in ("object_sets", "checks", "trust_knowledge", "waivers"):
        ids[group] = {row["id"] for row in value[group]}
        assert len(ids[group]) == len(value[group]), group
    items = [row["item"] for row in value["items"]]
    assert len(items) == len(set(items))
    text = (ROOT / "protocols/EBMP-2.md").read_text()
    table = text.split("**EBMP2-076 (continued)**", 1)[1]
    source_items = re.findall(r"^\| `([^`]+)` \|", table, re.MULTILINE)
    assert source_items[:len(items)] == items
    for row in value["items"]:
        assert row["object_set"] is None or row["object_set"] in ids["object_sets"]
        assert set(row["required_checks"]) <= ids["checks"]
        assert set(row["trust_knowledge"]) <= ids["trust_knowledge"]
        assert set(row["permitted_waivers"]) <= ids["waivers"]
    for row in value["evidence_levels"]:
        assert row["object_set"] in ids["object_sets"]
        assert set(row["required_checks"]) <= ids["checks"]
        assert set(row["requires_items"]) <= set(items)
    requirements = {r["requirement_id"] for r in read("registries/requirements-compiled.json")["requirements"]}
    codes = {r["id"] for f in ("error-codes", "semantic-rules") for r in read("registries/" + f + ".json")["entries"]}
    for group in ("object_sets", "checks", "trust_knowledge", "waivers"):
        for row in value[group]:
            assert set(row.get("requirements", [])) <= requirements
            assert set(row.get("codes", [])) <= codes
