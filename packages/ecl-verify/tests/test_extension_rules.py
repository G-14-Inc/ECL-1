"""EXTENSION-REGISTRY-1 consumer rules that RC-5 makes machine-checkable.

XR1-010: one object carries each extension identifier at one version only, unless the registry
entry of that identifier sets `composable_versions` to true; a version the consumer does not know
counts as a version (`ecl.rule.extension-single-version.v1`).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from ecl_verify.resources import object_findings, registry_document
from ecl_verify.semantic import (
    EXTENSION_VERSION_RULE,
    SemanticValidator,
    allocated_extension_versions,
    composable_extensions,
)

ROOT = Path(__file__).resolve().parents[3]
REQUEST = ROOT / "conformance/vectors/dcmp-2/valid-private-extensions.json"
DUPLICATE_RULE = "ecl.rule.extension-identifiers-unique.v1"
UNKNOWN_CRITICAL_RULE = "ecl.rule.unknown-critical-extension-rejected.v1"
TAG = "com.example.audit-tag.v1"


def request() -> dict[str, Any]:
    value = json.loads(REQUEST.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def validator(**options: Any) -> SemanticValidator:
    entries = registry_document("extensions")["entries"]
    return SemanticValidator(
        (entry["id"] for entry in entries),
        allocated_versions=allocated_extension_versions(entries),
        **options,
    )


def with_tag_at(value: dict[str, Any], version: int, *, critical: bool = False) -> dict[str, Any]:
    result = copy.deepcopy(value)
    result["extensions"].append(
        {"id": TAG, "version": version, "critical": critical, "value": {"tag": "quarterly-close"}}
    )
    return result


def rules(value: dict[str, Any], semantics: SemanticValidator | None = None) -> set[str]:
    return {item.rule_id for item in (semantics or validator()).validate(value)}


def test_two_versions_of_one_extension_are_refused() -> None:
    assert rules(request()) == set()
    findings = validator().validate(with_tag_at(request(), 2))
    assert [(item.rule_id, item.path) for item in findings] == [
        (EXTENSION_VERSION_RULE, "/extensions/3")
    ]
    assert "version 1 and at version 2" in findings[0].message


def test_a_version_the_consumer_does_not_know_still_conflicts() -> None:
    # A non-critical extension at an unknown version is preserved, not refused (XR1-007), but it
    # is a version all the same: beside version 1 of the same identifier it is a conflict.
    value = with_tag_at(request(), 7)
    assert rules(value) == {EXTENSION_VERSION_RULE}


def test_the_same_version_twice_is_a_duplicate_and_not_a_version_conflict() -> None:
    assert rules(with_tag_at(request(), 1)) == {DUPLICATE_RULE}


def test_distinct_extensions_may_carry_different_versions() -> None:
    value = copy.deepcopy(request())
    value["extensions"].append(
        {"id": "com.example.review-ticket.v1", "version": 2, "critical": False, "value": {}}
    )
    assert rules(value) == set()


def test_a_critical_extension_at_an_unallocated_version_is_also_unknown() -> None:
    value = copy.deepcopy(request())
    coupling = next(
        item for item in value["extensions"] if item["id"] == "ecl.ext.consequence-coupling.v1"
    )
    value["extensions"].append(dict(copy.deepcopy(coupling), version=2))
    assert rules(value) == {UNKNOWN_CRITICAL_RULE, EXTENSION_VERSION_RULE}


def test_versions_the_registry_declares_composable_may_appear_together() -> None:
    value = with_tag_at(request(), 2)
    assert rules(value, validator(composable=[TAG])) == set()
    # Composability does not excuse a duplicate pair (XR1-009).
    assert rules(with_tag_at(value, 2), validator(composable=[TAG])) == {DUPLICATE_RULE}


def test_only_composable_versions_set_to_true_declares_composability() -> None:
    entries: list[dict[str, Any]] = [
        {"id": "ecl.ext.a.v1", "attributes": {"composable_versions": True}},
        {"id": "ecl.ext.b.v1", "attributes": {"composable_versions": "true"}},
        {"id": "ecl.ext.c.v1", "attributes": {"composable_versions": 1}},
        {"id": "ecl.ext.d.v1", "attributes": {}},
        {"id": "ecl.ext.e.v1"},
    ]
    assert composable_extensions(entries) == frozenset({"ecl.ext.a.v1"})
    # No entry of the registry snapshot declares composability.
    assert composable_extensions(registry_document("extensions")["entries"]) == frozenset()


def test_the_object_checks_of_the_verifier_apply_the_rule() -> None:
    assert EXTENSION_VERSION_RULE in {
        item.rule_id for item in object_findings(with_tag_at(request(), 2))
    }


def test_the_rule_is_registered_for_xr1_010() -> None:
    entries = {entry["id"]: entry for entry in registry_document("semantic-rules")["entries"]}
    entry = entries[EXTENSION_VERSION_RULE]
    assert entry["status"] == "active"
    assert entry["introduced_in"] == "1.0-rc.5"
    assert entry["attributes"]["requirements"] == ["XR1-010"]
    assert set(entry["attributes"]["applies_to"]) >= {"DCMP-2", "EBMP-2", "ECL-IE-1"}
    text = (ROOT / "protocols/EXTENSION-REGISTRY-1.md").read_text(encoding="utf-8")
    assert EXTENSION_VERSION_RULE in text
    assert "`composable_versions`" in text


def test_the_corpus_gives_the_rule_its_own_capability() -> None:
    corpus = json.loads((ROOT / "conformance/shared-corpus.json").read_text(encoding="utf-8"))
    manifest = json.loads(
        (ROOT / "conformance/suites/extension-rules/manifest.json").read_text(encoding="utf-8")
    )
    capability = {row["id"]: row["capability"] for row in corpus["vectors"]}
    assert "extension-version-rule" in corpus["optional_capabilities"]
    refused = [
        vector
        for vector in manifest["vectors"]
        if EXTENSION_VERSION_RULE
        in [vector.get("expected_primary_id"), *vector["expected_secondary_ids"]]
    ]
    # A protocol-stage refusal needs the rule's own capability; a work intent refused at the
    # document stage needs the document stage's extension rules, which include it.
    expected = {
        "protocol": "extension-version-rule",
        "document": "document-extension-rules",
    }
    assert len([vector for vector in refused if vector["stage"] == "protocol"]) == 4
    for vector in refused:
        assert capability[vector["id"]] == expected[vector["stage"]], vector["id"]
