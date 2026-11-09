"""Deterministic MCP recovery/binding vectors derived from retained public fixtures.

These are unsigned exchange-record tests, not gateway executions or signed bundles.
The original generator and its fixtures are preserved. This script owns only the
explicit vector IDs returned by build(); it does not regenerate other suites.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path

SCHEMA = 'https://externalcontrollayer.ai/ns/schema/binding/mcp-gateway-exchange/1'
RESULT = 'ecl.rule.mcp-result-bound.v1'
EXT = 'ecl.ext.mcp-binding.v1'
REASON = 'ecl.ext.outcome-reason.v1'
AT = '2026-09-30T09:00:09.000000Z'
SUITE = 'conformance/suites/mcp-gateway'

def encoded(value):
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + '\n'

def build(root):
    def load(name):
        return json.loads((root / SUITE / (name + '.json')).read_text())
    entries = []
    outputs = {}
    recovered_base = load('mcp-valid-recovered-not-released')
    binding_extension = copy.deepcopy(next(e for e in recovered_base['terminal']['extensions'] if e['id'] == EXT))
    def add(name, record, base, description, valid=False):
        data = copy.deepcopy(record)
        if 'terminal' in data:
            data['terminal']['object_id'] = 'https://externalcontrollayer.ai/ns/receipt/sha256/' + hashlib.sha256(name.encode()).hexdigest()
        path = f'{SUITE}/{name}.json'
        outputs[path] = encoded(data)
        entry = dict(id=name, path=path, schema=SCHEMA, stage='binding', expected='pass' if valid else 'fail',
                     expected_secondary_ids=[], covers=[], requirement_ids=['MG1-010', 'MG1-016'],
                     source=dict(kind='mutation', base_vector=f'{SUITE}/{base}.json',
                                 generator='scripts/generate_mcp_recovery_vectors.py', mutation=description))
        if not valid:
            entry.update(expected_primary_id=RESULT, negates=['MG1-010', 'MG1-016'])
        entries.append(entry)
        return data
    def recovered(name):
        data = load(name)
        data.pop('returned', None); data.pop('returned_at', None)
        data['recovery'] = dict(classification='not-released', recovered_at=AT)
        terminal = data['terminal']; terminal['observed_at'] = AT
        terminal['extensions'] = [e for e in terminal['extensions'] if e['id'] != EXT]
        terminal['extensions'].append(copy.deepcopy(binding_extension))
        return data
    base_name = 'mcp-valid-recovered-not-released'
    unconsumed = copy.deepcopy(recovered_base)
    unconsumed.pop('prepared', None)
    terminal = unconsumed['terminal']; terminal['event']['state'] = 'denied'; terminal['event'].pop('authority')
    terminal['event']['residual_state'] = 'The request was not sent; the consumption operation was resolved without a committed use.'
    decision = terminal['event']['decision']
    terminal['workflow']['causal_predecessors'] = [dict(id=decision['uri'], digest=copy.deepcopy(decision['digest']), relation='ecl.relation.follows.v1')]
    terminal['workflow']['sequence'] = unconsumed['decision']['response']['workflow']['sequence'] + 1
    terminal['extensions'].append(dict(id=REASON, version=1, critical=False, value=dict(code='ecl.error.evidence-unavailable.v1')))
    add('mcp-valid-recovered-unconsumed-admit-denied', unconsumed, base_name,
        'A recovered admit whose store resolution established no consumed use: denied, no authority, evidence-unavailable reason, following the response.', True)
    for suffix in ['names-authority', 'without-reason', 'wrong-reason', 'with-prepared']:
        d = copy.deepcopy(unconsumed)
        if suffix == 'names-authority': d['terminal']['event']['authority'] = copy.deepcopy(recovered_base['terminal']['event']['authority'])
        elif suffix == 'without-reason': d['terminal']['extensions'] = [e for e in d['terminal']['extensions'] if e['id'] != REASON]
        elif suffix == 'wrong-reason': next(e for e in d['terminal']['extensions'] if e['id'] == REASON)['value']['code'] = 'ecl.error.expired.v1'
        else: d['prepared'] = copy.deepcopy(recovered_base['prepared'])
        add('mcp-invalid-recovered-admit-denied-' + suffix, d, base_name, 'Unconsumed recovered admit with ' + suffix + '.')
    for state in ['denied', 'held', 'challenged']:
        base = f'mcp-valid-{state}-refused'; d = recovered(base)
        add(f'mcp-valid-recovered-{state}', d, base, f'Recovery preserves an answered decision\'s {state} state.', True)
        for wrong in ['denied', 'held', 'challenged', 'cancelled']:
            if wrong == state: continue
            x = copy.deepcopy(d); x['terminal']['event']['state'] = wrong
            add(f'mcp-invalid-recovered-{state}-as-{wrong}', x, base, f'Record a recovered {state} decision as {wrong}.')
    base = 'mcp-valid-decision-invalid-holds-refused-response'; d = recovered(base)
    add('mcp-valid-recovered-unverified-decision-denied', d, base, 'Recovery of a refused unverified response remains denied without authority.', True)
    x = copy.deepcopy(d); x['terminal']['event']['state'] = 'cancelled'
    add('mcp-invalid-recovered-unverified-as-cancelled', x, base, 'Treat an unverified response as consumed authority.')
    for prefix, base in [('recovered', base_name), ('live', 'mcp-valid-final-check-cancelled')]:
        for suffix in ['without-authority', 'foreign-authority', 'wrong-authority-digest', 'wrong-decision-digest']:
            d = load(base); event = d['terminal']['event']
            if suffix == 'without-authority': event.pop('authority')
            elif suffix == 'foreign-authority': event['authority']['uri'] = load('mcp-valid-forwarded-on-admit')['terminal']['event']['authority']['uri']
            elif suffix == 'wrong-authority-digest': event['authority']['digest']['value'] = '0' * 64
            else: event['decision']['digest']['value'] = '0' * 64
            add(f'mcp-invalid-{prefix}-cancelled-{suffix}', d, base, f'A {prefix} cancelled terminal with {suffix}.')
    base = 'mcp-valid-forwarded-on-admit'; d = load(base)
    d['terminal']['event']['authority']['digest']['value'] = '0' * 64
    add('mcp-invalid-forwarded-terminal-authority-digest', d, base, 'A forwarded terminal names the correct authority URI but changes its digest.')
    for state, wrong in [('held', 'denied'), ('decision-unavailable', 'held')]:
        base = f'mcp-valid-{state}-refused'; d = load(base); d['terminal']['event']['state'] = wrong
        add(f'mcp-invalid-live-{state}-as-{wrong}', d, base, 'A refused live terminal disagrees with the accepted decision or its absence.')
    # Already-recorded outcomes retain their original terminal; they are not re-signed recovery outcomes.
    for state in ['denied', 'held']:
        base = f'mcp-valid-{state}-refused'; d = load(base)
        d.pop('returned', None); d.pop('returned_at', None)
        d['recovery'] = dict(classification='outcome-recorded', recovered_at=AT)
        add(f'mcp-valid-recorded-{state}', d, base, 'Recovery keeps an existing non-release terminal without a recovered-at extension.', True)
        x = copy.deepcopy(d); x['terminal']['event']['state'] = 'cancelled' if state == 'denied' else 'denied'
        add(f'mcp-invalid-recorded-{state}-wrong-state', x, base, 'An outcome-recorded classification cannot waive decision/state binding.')
        if state == 'denied':
            x = copy.deepcopy(d); x['terminal']['event']['authority'] = copy.deepcopy(recovered_base['terminal']['event']['authority'])
            add('mcp-invalid-recorded-denied-names-authority', x, base, 'A recorded denial cannot name consumed authority.')
    base = 'mcp-valid-obligation-unsupported-refused'; d = load(base)
    d.pop('returned', None); d.pop('returned_at', None)
    d['recovery'] = dict(classification='outcome-recorded', recovered_at=AT)
    add('mcp-valid-recorded-admit-denied', d, base, 'A previously recorded denied admit retains its original obligation-unproven reason.', True)
    base = 'mcp-valid-final-check-cancelled'; d = load(base)
    d.pop('returned', None); d.pop('returned_at', None)
    d['recovery'] = dict(classification='outcome-recorded', recovered_at=AT)
    d['terminal']['event'].pop('authority')
    add('mcp-invalid-recorded-cancelled-without-authority', d, base, 'A recorded cancellation still needs its authority reference.')
    for name, base, change in [
        ('mcp-invalid-live-cancelled-side-effects', 'mcp-valid-final-check-cancelled', 'effects'),
        ('mcp-invalid-live-denied-side-effects', 'mcp-valid-denied-refused', 'effects'),
        ('mcp-invalid-live-cancelled-no-residual', 'mcp-valid-final-check-cancelled', 'residual'),
    ]:
        d = load(base)
        if change == 'effects': d['terminal']['event']['side_effects'] = [dict(uri='urn:example:unexpected-effect')]
        else: d['terminal']['event'].pop('residual_state')
        add(name, d, base, 'A non-forwarded terminal violates its no-effects or cancellation residual-state requirement.')
    for base in ['mcp-valid-final-check-cancelled', 'mcp-valid-release-guard-exceeded-cancelled']:
        d = load(base)
        d.pop('terminal')
        name = base.replace('mcp-valid-', 'mcp-invalid-') + '-without-terminal'
        add(name, d, base, 'Remove the terminal from a non-forwarded attempt whose prepared or released event records consumption.')
        entries[-1]['requirement_ids'] = ['MG1-010', 'MG1-014', 'MG1-017']
        entries[-1]['negates'] = ['MG1-010', 'MG1-014', 'MG1-017']
    return outputs, entries

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(); root = args.root.resolve()
    outputs, entries = build(root); ids = {v['id'] for v in entries}
    manifest_path = f'{SUITE}/manifest.json'
    manifest = json.loads((root / manifest_path).read_text())
    manifest['vectors'] = sorted([v for v in manifest['vectors'] if v['id'] not in ids] + entries, key=lambda v: v['id'])
    outputs[manifest_path] = encoded(manifest)
    differences = []
    for name, text in outputs.items():
        p = root / name
        if not p.exists() or p.read_text() != text:
            differences.append(name)
            if not args.check:
                p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text)
    print(json.dumps(dict(generated_vectors=len(entries), differences=differences, check=args.check)))
    if args.check and differences: raise SystemExit(1)

if __name__ == '__main__': main()
