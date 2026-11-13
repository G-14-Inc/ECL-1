"""JSON equality and bounded large-document uniqueness checks."""
import copy
import itertools
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry

from ecl_verify.canonical import loads_json_strict
from ecl_verify.resources import validator_for
from ecl_verify.schema import ecl_format_checker
from ecl_verify.schema_patterns import schema_validator


def checker():
    return schema_validator({"uniqueItems": True}, registry=Registry(), format_checker=ecl_format_checker())


VALUES = [None, False, True, 0, 1, -1, 1.0, -0.0, 1.5, "", "1", [], [1], [True],
          {}, {"x": 1}, {"x": True}, {"a": [0, {"x": 1}], "b": None},
          {"b": None, "a": [0.0, {"x": 1.0}]}, {"x": "\U0001f511"}]


@pytest.mark.parametrize("left,right", itertools.product(VALUES, repeat=2))
def test_json_equality_matches_draft_2020_12(left, right):
    value = [copy.deepcopy(left), copy.deepcopy(right)]
    assert checker().is_valid(value) == Draft202012Validator({"uniqueItems": True}).is_valid(value)


def test_large_objects_do_not_use_pairwise_reference_comparison(monkeypatch):
    import jsonschema._utils as utils
    count = 0
    original = utils.equal

    def counted(left, right):
        nonlocal count
        count += 1
        return original(left, right)

    monkeypatch.setattr(utils, "equal", counted)
    values = [{"kind": "file", "identifier": f"p/{i}"} for i in range(1000)]
    assert checker().is_valid(values)
    assert count < 10000
    values.append(copy.deepcopy(values[0]))
    assert not checker().is_valid(values)


def test_work_intent_maximum_target_count():
    import os
    root = Path(os.environ.get("ECL_DATA_ROOT", str(Path(__file__).resolve().parents[3])))
    value = json.loads((root / "conformance/suites/document-coverage/work-intent-valid.json").read_text())
    value["exact_targets"] = [{"kind": "file", "identifier": f"p/{i}"} for i in range(100000)]
    encoded = json.dumps(value, separators=(",", ":"))
    assert len(encoded.encode()) < 16 * 1024 * 1024
    parsed = loads_json_strict(encoded, max_bytes=16 * 1024 * 1024)
    validator = validator_for("https://externalcontrollayer.ai/ns/schema/work-intent/1")
    assert validator.is_valid(parsed)
    parsed["exact_targets"][-1] = copy.deepcopy(parsed["exact_targets"][0])
    assert not validator.is_valid(parsed)
