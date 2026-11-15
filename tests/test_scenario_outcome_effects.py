"""Reject incident expectations that cannot meet the replay's effect contract.

Robert F. Tilley Jr.; G-14, Inc.
"""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('metadata_effects', ROOT / 'scripts/check_repository_metadata.py')
metadata = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(metadata)
BASE = json.loads((ROOT / 'conformance/scenarios/record-1-knight-2012.json').read_bytes())


@pytest.mark.parametrize('outcome', ['admit', 'deny', 'hold', 'challenge', 'no-decision', ['deny', 'hold'], ['admit', 'deny']])
@pytest.mark.parametrize('effect', ['none', 'committed'])
def test_nonempty_expectation_has_a_possible_outcome_effect_pair(outcome, effect):
    value = copy.deepcopy(BASE)
    next(s for s in value['steps'] if s['step'] == 's4')['expect'] = {'outcome': outcome, 'effect': effect}
    allowed = outcome if isinstance(outcome, list) else [outcome]
    expected = any((item == 'admit') == (effect == 'committed') for item in allowed)
    result = metadata.check_document(value)
    assert result['valid'] == expected, result
    assert ('outcome-effect' in {error['code'] for error in result['errors']}) == (not expected)


@pytest.mark.parametrize('count,expected', [(29, False), (30, True)])
def test_empty_rest_creates_no_effect_obligation(count, expected):
    value = copy.deepcopy(BASE)
    selected = next(s for s in value['steps'] if s['step'] == 's7')
    assert selected['repeat'] == 30
    selected['expect'] = {
        'first': {'count': count, 'outcome': 'admit', 'effect': 'committed'},
        'rest': {'outcome': 'deny', 'effect': 'committed'},
    }
    result = metadata.check_document(value)
    assert result['valid'] == expected, result
