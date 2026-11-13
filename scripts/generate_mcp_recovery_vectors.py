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
# These 18 historical reconstructions are owned by the later explicit migration.
SUPERSEDED_IDS = frozenset(['mcp-invalid-final-check-cancelled-without-terminal',
 'mcp-invalid-forwarded-terminal-authority-digest',
 'mcp-invalid-live-cancelled-foreign-authority',
 'mcp-invalid-live-cancelled-no-residual',
 'mcp-invalid-live-cancelled-side-effects',
 'mcp-invalid-live-cancelled-without-authority',
 'mcp-invalid-live-cancelled-wrong-authority-digest',
 'mcp-invalid-live-cancelled-wrong-decision-digest',
 'mcp-invalid-recorded-cancelled-without-authority',
 'mcp-invalid-recovered-admit-denied-names-authority',
 'mcp-invalid-recovered-admit-denied-with-prepared',
 'mcp-invalid-recovered-admit-denied-without-reason',
 'mcp-invalid-recovered-admit-denied-wrong-reason',
 'mcp-invalid-recovered-cancelled-foreign-authority',
 'mcp-invalid-recovered-cancelled-without-authority',
 'mcp-invalid-recovered-cancelled-wrong-authority-digest',
 'mcp-invalid-recovered-cancelled-wrong-decision-digest',
 'mcp-invalid-release-guard-exceeded-cancelled-without-terminal'])

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
    # Recovery establishes the absence of consumption; it does not reconstruct
    # an initial release check that the surviving record does not carry.
    unconsumed.pop('release_observations', None)
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
        else:
            d['prepared'] = copy.deepcopy(recovered_base['prepared'])
            d['release_observations'] = copy.deepcopy(recovered_base['release_observations'])
        description = {
            'with-prepared': 'An unconsumed recovered admit incorrectly retains a prepared event.',
            'without-reason': 'An unconsumed recovered admit omits the required refusal reason.',
        }.get(suffix, 'Unconsumed recovered admit with ' + suffix + '.')
        add('mcp-invalid-recovered-admit-denied-' + suffix, d, base_name, description)
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
    entries[-1]['expected_primary_id'] = 'ecl.rule.mcp-decision-failure-not-forwarded.v1'
    entries[-1]['expected_secondary_ids'] = [RESULT]
    for prefix, base in [('recovered', base_name), ('live', 'mcp-valid-final-check-cancelled')]:
        for suffix in ['without-authority', 'foreign-authority', 'wrong-authority-digest', 'wrong-decision-digest']:
            d = load(base); event = d['terminal']['event']
            if suffix == 'without-authority': event.pop('authority')
            elif suffix == 'foreign-authority': event['authority']['uri'] = load('mcp-valid-forwarded-on-admit')['terminal']['event']['authority']['uri']
            elif suffix == 'wrong-authority-digest': event['authority']['digest']['value'] = '0' * 64
            else: event['decision']['digest']['value'] = '0' * 64
            description = f'A {prefix} cancelled terminal omits its authority reference.' if suffix == 'without-authority' else f'A {prefix} cancelled terminal with {suffix}.'
            add(f'mcp-invalid-{prefix}-cancelled-{suffix}', d, base, description)
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
        if base == 'mcp-valid-release-guard-exceeded-cancelled':
            entries[-1]['expected_primary_id'] = 'ecl.rule.mcp-refusal-defined.v1'
            entries[-1]['expected_secondary_ids'] = [RESULT]
    # These mutations deliberately carry a cancelled terminal without its residual state.
    # Complete validation of the supplied event also reports EBMP2-013. Its registry
    # precedence 250 precedes MCP rules 840/850; retain the exact original findings
    # as secondaries without changing the mutation or its invalid verdict.
    missing_residual = {
        'mcp-invalid-live-cancelled-no-residual',
        'mcp-invalid-recorded-denied-wrong-state',
        'mcp-invalid-recovered-challenged-as-cancelled',
        'mcp-invalid-recovered-denied-as-cancelled',
        'mcp-invalid-recovered-held-as-cancelled',
        'mcp-invalid-recovered-unverified-as-cancelled',
    }
    for entry in entries:
        if entry['id'] in missing_residual:
            previous_primary = entry['expected_primary_id']
            entry['expected_primary_id'] = 'ecl.rule.terminal-execution-state-consistent.v1'
            entry['expected_secondary_ids'] = [previous_primary, *entry['expected_secondary_ids']]
    return outputs, entries

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(); root = args.root.resolve()
    outputs, entries = build(root)
    manifest_path = f'{SUITE}/manifest.json'
    manifest = json.loads((root / manifest_path).read_text())
    # Ownership is fixed in this generator, never inferred from the manifest
    # being checked. Preserve the order and content of unrelated suite rows.
    by_id = {}
    for row in manifest['vectors']:
        if row['id'] in by_id:
            raise SystemExit('duplicate MCP vector ID: ' + row['id'])
        by_id[row['id']] = row
    for name in SUPERSEDED_IDS:
        if name not in by_id or by_id[name].get('source', {}).get('generator') != 'scripts/generate_mcp_public_review_migration.py':
            raise SystemExit('unexpected migration ownership: ' + name)
    omitted = {v['path'] for v in entries if v['id'] in SUPERSEDED_IDS}
    entries = [v for v in entries if v['id'] not in SUPERSEDED_IDS]
    outputs = {path: text for path, text in outputs.items() if path not in omitted}
    expected = {v['id']: v for v in entries}
    manifest['vectors'] = [expected.get(v['id'], v) for v in manifest['vectors']]
    manifest['vectors'].extend(expected[name] for name in sorted(expected.keys() - by_id.keys()))
    outputs[manifest_path] = encoded(manifest)
    differences = []
    for name, text in outputs.items():
        p = root / name
        content = text.encode('utf-8')
        if not p.exists() or p.read_bytes() != content:
            differences.append(name)
            if not args.check:
                p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(content)
    print(json.dumps(dict(generated_vectors=len(entries), differences=differences, check=args.check)))
    if args.check and differences: raise SystemExit(1)

if __name__ == '__main__': main()
