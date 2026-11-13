"""Unresolved checklist failures need active findings in the claim decision.

Robert F. Tilley Jr.; G-14, Inc.
"""
import copy
import itertools
import json
from pathlib import Path

import pytest

from ecl_verify.resources import validator_for

ROOT = Path(__file__).resolve().parents[1]
BASE = json.loads((ROOT / 'conformance/suites/document-coverage/assessment-valid-l4-class-c.json').read_bytes())
SCHEMA = 'https://externalcontrollayer.ai/ns/schema/assessment-package/1'
CASES = list(itertools.product(
    ('critical', 'major', 'minor', 'observation'),
    ('open', 'accepted_condition', 'remediated', 'rejected'),
    (False, True),
    ('assessment_only', 'conditional_conformance', 'full_conformance'),
))


@pytest.mark.parametrize('severity,disposition,failed,status', CASES)
def test_assessment_claim_accounts_for_active_findings(severity, disposition, failed, status):
    value = copy.deepcopy(BASE)
    value['level'] = 2
    value['independence']['class'] = 'B'
    for item in value['checklist']:
        item['result'] = 'fail' if failed else 'pass'
    value['findings'][0].update(severity=severity, disposition=disposition)
    value['claim_decision']['status'] = status

    # Historical findings cannot account for a currently failed checklist.
    active = disposition in {'open', 'accepted_condition'}
    expected = not failed or (active and severity != 'observation')
    # Critical findings prevent a conformance claim; major findings prevent full conformance.
    if active and severity == 'critical' and status != 'assessment_only':
        expected = False
    if active and severity == 'major' and status == 'full_conformance':
        expected = False
    errors = list(validator_for(SCHEMA).iter_errors(value))
    assert (not errors) == expected, [error.message for error in errors]
