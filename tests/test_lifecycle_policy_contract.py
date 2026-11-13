"""EL1-002 policy areas and EL1-007 retention-duration syntax."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest
from ecl_verify.canonical import loads_json_strict
from ecl_verify.resources import validator_for

ROOT = Path(__file__).resolve().parents[1]
ROWS = json.loads((ROOT / "conformance/suites/lifecycle-policy-contract/manifest.json").read_bytes())["vectors"]


@pytest.mark.parametrize("row", ROWS, ids=lambda row: row["id"])
def test_lifecycle_policy_contract(row):
    value = loads_json_strict((ROOT / row["path"]).read_bytes())
    original = copy.deepcopy(value)
    errors = list(validator_for(row["schema"]).iter_errors(value))
    actual = ["ecl.error.schema-invalid.v1"] if errors else []
    expected = [row["expected_primary_id"], *row["expected_secondary_ids"]] if row["expected"] == "fail" else []
    assert actual == expected, errors
    assert value == original


def test_lifecycle_cases_are_reproducible_and_attributable():
    import sys
    original_path = sys.path[:]
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        spec = importlib.util.spec_from_file_location("lifecycle_policy_vectors", ROOT / "scripts/generate_lifecycle_policy_vectors.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        outputs, receipt = module.build(ROOT)
        assert not receipt["missing_two_sided_attribution"]
        assert receipt["new_schema_units"] == 0
        assert all((ROOT / path).read_bytes() == value for path, value in outputs.items())
    finally:
        sys.path[:] = original_path
