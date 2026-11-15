"""Active applicability, uninterpreted future data, and IE1-040 step-3 precedence."""
import json
import os
from pathlib import Path
import pytest
from ecl_verify.canonical import loads_json_strict
from ecl_verify.integrity import IntegrityError, verify_envelope
from ecl_verify.resources import _semantics, validator_for
from ecl_verify.semantic import SemanticValidator
from ecl_verify.trust import TrustPolicy
from ecl_verify.bundle_verification import verify_bundle

ROOT = Path(os.environ.get("ECL_EXTENSION_FIXTURES", str(Path(__file__).resolve().parents[1] / "tests/fixtures/extension-consumer-cases")))
MANIFEST = json.loads((ROOT / "manifest.json").read_text())
POLICY = TrustPolicy.load((ROOT / "envelope-trust.json").read_bytes())
BUNDLE_POLICY = TrustPolicy.load((ROOT / "bundle-trust.json").read_bytes())
CONTEXT = POLICY.verification_context(evaluated_at=MANIFEST["evaluated_at"], time_policy="ecl.time.issued-at.v1")
TAG = MANIFEST["custom_identifier"]
VALUE_SCHEMA = validator_for(MANIFEST["custom_value_schema"])
CUSTOM = SemanticValidator([TAG], {TAG: lambda value: [error.message for error in VALUE_SCHEMA.iter_errors(value)]}, active_versions={TAG: [1]}, applicability={TAG: {1: ["DCMP-2", "EBMP-2", "ECL-IE-1", "ECL-WI-1"]}})


@pytest.mark.parametrize("case", MANIFEST["cases"], ids=lambda case: case["id"])
def test_extension_consumers(case):
    value = loads_json_strict((ROOT / case["file"]).read_bytes())
    before = json.dumps(value, sort_keys=True)
    if case["kind"] == "envelope":
        actual = None
        try:
            verify_envelope(value, POLICY.keyring(), CONTEXT)
        except IntegrityError as error:
            actual = error.code
        assert actual == case["expected"]
    elif case["kind"] == "bundle":
        assert verify_bundle(value, BUNDLE_POLICY, now="2026-10-01T00:00:00Z").verdict == case["expected"]
    else:
        consumer = CUSTOM if case["kind"] == "custom" else _semantics()
        assert sorted({f.rule_id for f in consumer.validate(value)}) == case["expected"]
        if case["kind"] == "custom":
            assert sorted({f.rule_id for f in consumer.extension_findings(value)}) == case["expected"]
    assert json.dumps(value, sort_keys=True) == before
