"""Terminal checks compose with binding errors without losing corpus diagnostics."""
import hashlib
import json
from pathlib import Path

import pytest

from scripts import run_conformance as runner
from ecl_verify.semantic import SemanticValidator

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "tests/fixtures/corpus-terminal-selection/manifest.json").read_bytes())
PRECEDENCE = runner.rule_precedence(ROOT)
ERRORS = runner.registered_errors(ROOT)
SCHEMAS, REGISTRY = runner.schema_environment(ROOT)


@pytest.mark.parametrize("case", MANIFEST["record_cases"], ids=lambda case: case["id"])
def test_terminal_record_through_corpus_evaluator_and_selector(case):
    data = (ROOT / case["path"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == case["sha256"]
    observed = runner.observed_for_vector(
        ROOT, {"id": case["id"], "path": case["path"], "stage": "binding", "schema": case["schema"]},
        schemas=SCHEMAS, schema_registry=REGISTRY, semantics=SemanticValidator([]),
    )
    assert sorted(set(observed)) == case["observed"]
    assert runner.select_findings(observed, PRECEDENCE, ERRORS) == (case["primary"], case["secondary"])
    assert (ROOT / case["path"]).read_bytes() == data


@pytest.mark.parametrize("case", MANIFEST["selection_cases"], ids=lambda case: case["id"])
def test_generic_fallback_preserves_selector_boundaries(case):
    original = case["observed"]
    for observed in [original, list(reversed(original)), original + original]:
        if "error_contains" in case:
            with pytest.raises(ValueError, match=case["error_contains"]):
                runner.select_findings(observed, PRECEDENCE, ERRORS)
        else:
            assert runner.select_findings(observed, PRECEDENCE, ERRORS) == (case["primary"], case["secondary"])
