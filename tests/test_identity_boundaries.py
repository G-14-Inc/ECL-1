"""Typed graph and signature identities at the direct verifier boundary."""
import copy
import json
from pathlib import Path
import pytest
from ecl_verify.bundle import analyze_bundle
from ecl_verify.integrity import IntegrityError, verify_envelope
from ecl_verify.trust import TrustPolicy
ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / 'tests/fixtures/identity-boundaries/cases.json').read_text())

@pytest.mark.parametrize('row', CASES['causal'], ids=lambda row: row['name'])
def test_causal_identity_boundary(row):
    result = analyze_bundle(row['records'], identifier_members=tuple(row.get('identifier_members', ['object_id'])))
    actual = {'status': result.status, 'terminal': list(result.terminal_action_ids), 'open': list(result.open_action_ids), 'rules': sorted({f.rule_id for f in result.findings})}
    assert actual == row['expected']

@pytest.mark.parametrize('row', CASES['envelopes'], ids=lambda row: row['name'])
def test_signature_identity_boundary(row):
    envelope = json.loads((ROOT / 'conformance/suites/envelope/envelope-valid-ed25519-signed.json').read_text())
    policy = TrustPolicy.load((ROOT / 'conformance/suites/envelope/trust-policy.json').read_bytes())
    entry = envelope['signatures'][0]
    if row['operation'] == 'duplicate':
        envelope['signatures'].append(copy.deepcopy(entry))
    elif row['operation'] == 'remove':
        del entry[row['member']]
    elif row['operation'] == 'replace':
        entry[row['member']] = row['value']
    elif row['operation'] == 'object-pair':
        entry['key_id'] = {'b': 1, '1': 1}
        other = copy.deepcopy(entry)
        other['key_id'] = {'1': 1, 'b': 1}
        envelope['signatures'].append(other)
    try:
        verify_envelope(envelope, policy.keyring(), policy.verification_context(evaluated_at='2026-11-10T12:00:00Z', time_policy='ecl.time.issued-at.v1'))
        actual = ''
    except IntegrityError as error:
        actual = error.code
    assert actual == row['expected']
