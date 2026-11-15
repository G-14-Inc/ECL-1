"""Safe-state declaration identity and the advisory work-intent contract."""
import copy
import json
from pathlib import Path
import pytest
from ecl_verify.resources import validator_for, _semantics
from ecl_verify.semantic_rc4 import validate_safe_state_profile
ROOT = Path(__file__).resolve().parents[1]
ROWS = [row for suite in ("safe-state-declaration-contract", "work-intent-contract")
        for row in json.loads((ROOT/"conformance/suites"/suite/"manifest.json").read_text())["vectors"]]
RULES = json.loads((ROOT/"registries/semantic-rules.json").read_text())["entries"]
@pytest.mark.parametrize("row", ROWS, ids=lambda row: row["id"])
def test_work_intent_contract(row):
    value = json.loads((ROOT/row["path"]).read_text())
    original = copy.deepcopy(value)
    actual = {"ecl.error.schema-invalid.v1"} if list(validator_for(row["schema"]).iter_errors(value)) else set()
    if row["stage"] == "safe-state-profile":
        found = validate_safe_state_profile(value)
    else:
        allowed = {rule["id"] for rule in RULES if value.get("protocol") in rule["attributes"]["applies_to"] and rule["status"] == "active"}
        found = [item for item in _semantics().validate(value) if item.rule_id in allowed]
    actual.update(item.rule_id for item in found)
    expected = {row["expected_primary_id"], *row["expected_secondary_ids"]} if row["expected"] == "fail" else set()
    assert actual == expected, found
    assert value == original


def test_work_intent_capability_is_distinct_from_extension_processing():
    import importlib.util
    path = ROOT / "scripts/shared_corpus.py"
    spec = importlib.util.spec_from_file_location("work_intent_corpus_mapping", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for row in ROWS:
        if row["stage"] != "document":
            continue
        assert module.capability_of(ROOT, "ecl-1-v1.0-work-intent-contract", row) == "work-intent-contract"
        expected = {row.get("expected_primary_id"), *row["expected_secondary_ids"]}
        if expected & {"ecl.rule.work-intent-context-consistent.v1", "ecl.rule.expiry-after-issue.v1", "ecl.rule.message-cannot-cause-itself.v1"}:
            assert module.capability_of(ROOT, "other-suite", row) == "work-intent-contract"
        elif "ecl.rule.unknown-critical-extension-rejected.v1" in expected:
            assert module.capability_of(ROOT, "other-suite", row) == "document-extension-rules"
    assert "work-intent-contract" in module.OPTIONAL
    for version in (2, 3):
        schema = json.loads((ROOT/f"schemas/ecl-cross-implementation-report-v{version}.schema.json").read_text())
        def enums(value):
            if isinstance(value, dict):
                if "enum" in value:
                    yield value["enum"]
                for child in value.values():
                    yield from enums(child)
            elif isinstance(value, list):
                for child in value:
                    yield from enums(child)
        assert any("work-intent-contract" in values for values in enums(schema))
