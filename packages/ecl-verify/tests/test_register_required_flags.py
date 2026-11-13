"""Direct register matching refuses values outside the boolean flag domain."""
import json
from pathlib import Path
import pytest
from ecl_verify.decision_basis_checks import register_problems, register_reference
ROOT = Path(__file__).resolve().parents[3]
CASES = json.loads((ROOT / "tests/fixtures/register-required-flags/cases.json").read_text())

@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_register_required_flag_domain(case):
    value = {**case["basis"], "register": register_reference(case["register"])}
    problems = register_problems(value, case["register"], case["action_class"])
    assert any(path == "/inputs/0/required" for path, _ in problems) is case["required_problem"]
    assert all(path == "/inputs/0/required" for path, _ in problems)
