"""Finite JSON numbers at the schema helper boundary.

Robert F. Tilley Jr.; G-14, Inc.
"""
import pytest
from referencing import Registry
from ecl_verify.schema import ecl_format_checker
from ecl_verify.schema_patterns import schema_validator

@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), True, False])
def test_number_schema_refuses_non_numbers_and_nonfinite_host_values(value):
    validator = schema_validator({"type": "number"}, registry=Registry(), format_checker=ecl_format_checker())
    assert not validator.is_valid(value)
    assert list(validator.iter_errors(value))

@pytest.mark.parametrize("value", [0, -1, 1.5, 1e100])
def test_schema_finite_numbers_are_separate_from_restricted_wire_numbers(value):
    validator = schema_validator({"type": "number"}, registry=Registry(), format_checker=ecl_format_checker())
    assert validator.is_valid(value)


def test_numeric_domain_through_nested_schema():
    validator = schema_validator({"type": "object", "properties": {"n": {"type": "number", "minimum": 0, "maximum": 1}}}, registry=Registry(), format_checker=ecl_format_checker())
    assert not validator.is_valid({"n": float("nan")})
    assert validator.is_valid({"n": 0.5})
