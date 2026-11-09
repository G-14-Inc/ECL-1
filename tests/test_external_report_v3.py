"""Report-binding regressions using synthetic reports, not claimed vector executions.

The fixtures retain real vector bytes/expectations and use a small subset so each
mutation tests one binding rule. Actual producer replays are a separate check.
"""
from pathlib import Path
import copy, hashlib, json, shutil, sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'packages/ecl-verify/src')]
from scripts.verify_external_implementation_report import verify, source_tree
from scripts.external_report_v3 import OBSERVATIONS

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,value):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(value,sort_keys=True)+'\n')

@pytest.fixture
def bound(tmp_path):
    root=tmp_path/'corpus';evidence=tmp_path/'evidence';implementation=tmp_path/'implementation'
    evidence.mkdir();implementation.mkdir();(implementation/'fixture.txt').write_text('Synthetic report-integrity fixture; no vector execution claimed.\n')
    corpus=json.loads((ROOT/'conformance/shared-corpus.json').read_text())
    paths=[ROOT/'conformance/manifest.json',*sorted((ROOT/'conformance/suites').glob('*/manifest.json'))]
    vectors=[(p,v) for p in paths for v in json.loads(p.read_text())['vectors']]
    wanted=[]
    for predicate in [lambda v:'expected_effects' in v,lambda v:bool(v.get('expected_unresolved_predecessor_ids')),
        lambda v:v.get('expected_verdict')=='current-trust-failed',
        lambda v:v['stage']=='canonical' and v['expected']=='pass',
        lambda v:v['stage']=='canonical' and v['expected']=='fail',
        lambda v:v['stage']=='strict-json' and v['expected']=='pass']:
        item=next((p,v) for p,v in vectors if predicate(v))
        if item not in wanted:wanted.append(item)
    ids={v['id'] for p,v in wanted};corpus['vectors']=[v for v in corpus['vectors'] if v['id'] in ids]
    write(root/'conformance/shared-corpus.json',corpus)
    for p in paths:
        m=json.loads(p.read_text());m['vectors']=[v for v in m['vectors'] if v['id'] in ids]
        if m['vectors'] or p==paths[0]:write(root/p.relative_to(ROOT),m)
    for p,v in wanted:
        dst=root/v['path'];dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/v['path'],dst)
    for version in (2,3):
        for name in (f'ecl-cross-implementation-report-v{version}.schema.json',f'ecl-external-vector-raw-result-v{version}.schema.json'):
            dst=root/'schemas'/name;dst.parent.mkdir(exist_ok=True);shutil.copyfile(ROOT/'schemas'/name,dst)
    report=json.loads((ROOT/'conformance/report-template-v3.json').read_text())
    report['decision']='pass';report['implementation'].update(source_tree_sha256=source_tree(implementation)[0],
        source_revision='synthetic-binding-fixture',capabilities=corpus['required_capabilities']+corpus['optional_capabilities'])
    report['suite'].update(manifest_sha256=digest(root/'conformance/shared-corpus.json'),vector_count=len(ids))
    report['time_policies']={'envelope':['ecl.time.issued-at.v1','ecl.time.observed-at.v1'],
        'evidence-bundle':['ecl.verification-profile.reference-trusted-time.v1','ecl.verification-profile.reference.v1'],
        'package':['ecl.verification-profile.reference-trusted-time.v1','ecl.verification-profile.reference.v1']}
    rows=[]
    for p,v in wanted:
        m=json.loads(p.read_text());row=dict(id=v['id'],suite=m['suite'],artifact_sha256=digest(root/v['path']),
            expected=v['expected'],status='met',observed_primary_id=v.get('expected_primary_id'),observed_secondary_ids=[])
        for expected,observed in OBSERVATIONS.items():
            if expected in v:row[observed]=None if expected=='expected_canonical_sha256' and v['expected']=='fail' else copy.deepcopy(v[expected])
        rows.append(row)
    report['vector_results']=rows
    def bind_raw(version=3):
        report['evidence']=[]
        for i,row in enumerate(rows):
            result={k:v for k,v in row.items() if k!='raw_result_sha256'}
            p=evidence/f'{i}.json';write(p,dict(schema_version=f'ecl_external_vector_raw_result_v{version}',implementation_revision=report['implementation']['source_revision'],result=result))
            row['raw_result_sha256']=digest(p);report['evidence'].append(dict(path=p.name,sha256=digest(p)))
    def check(**kwargs):return verify(root,report,evidence_root=evidence,implementation_root=implementation,**kwargs)
    bind_raw()
    return report,bind_raw,check

def row_for(report,field):
    return next(r for r in report['vector_results'] if field in r and (field!='observed_canonical_sha256' or r['expected']=='pass'))

def test_complete_binding_and_negative_canonical_placeholder(bound):
    report,bind,check=bound
    assert check()['replay_decision']=='pass'
    assert any(r.get('observed_canonical_sha256','absent') is None and r['expected']=='fail' for r in report['vector_results'])

@pytest.mark.parametrize('field',list(OBSERVATIONS.values()))
def test_missing_required_observation_is_not_evidence(bound,field):
    report,bind,check=bound;del row_for(report,field)[field];bind()
    with pytest.raises(ValueError,match='observation members differ'):check()

@pytest.mark.parametrize('field',list(OBSERVATIONS.values()))
@pytest.mark.parametrize('truthful',[False,True])
def test_unavailable_observation_cannot_be_met(bound,field,truthful):
    report,bind,check=bound;r=row_for(report,field);r[field]=None
    if truthful:r['status']='not-met';report['decision']='fail'
    bind()
    if truthful:assert check()['not_met_vectors']==[r['id']]
    else:
        with pytest.raises(ValueError,match='status does not match'):check()

@pytest.mark.parametrize('field',list(OBSERVATIONS.values()))
def test_raw_value_must_equal_report_observation(bound,field):
    report,bind,check=bound;r=row_for(report,field);r[field]=None;r['status']='not-met';report['decision']='fail'
    # Intentionally keep the formerly valid raw bytes and their digest.
    with pytest.raises(ValueError,match='raw evidence differs'):check()

def test_scope_order_and_reasons_are_part_of_comparison(bound):
    report,bind,check=bound;r=row_for(report,'observed_scope')
    r['observed_scope']['established'].reverse();bind()
    with pytest.raises(ValueError,match='status does not match'):check()

def test_effect_mixed_levels_are_not_collapsed(bound):
    report,bind,check=bound;r=row_for(report,'observed_effects');e=copy.deepcopy(r['observed_effects'][0])
    e['level']='none' if e['level']!='none' else 'issuer-asserted';r['observed_effects'].append(e);bind()
    with pytest.raises(ValueError,match='status does not match'):check()

def test_unresolved_order_is_irrelevant_but_duplicates_are_refused(bound):
    report,bind,check=bound;r=row_for(report,'observed_unresolved_predecessor_ids')
    r['observed_unresolved_predecessor_ids'].reverse();bind();assert check()['replay_decision']=='pass'
    r['observed_unresolved_predecessor_ids']*=2;bind()
    with pytest.raises(ValueError,match='cross-implementation-report/3'):check()

def test_unrequested_observation_is_refused(bound):
    report,bind,check=bound;r=next(r for r in report['vector_results'] if 'observed_verdict' not in r)
    r['observed_verdict']='verified';bind()
    with pytest.raises(ValueError,match='observation members differ'):check()

def test_legacy_requires_explicit_opt_in_and_retains_its_boundary(bound):
    report,bind,check=bound
    report.update(schema_version='ecl_cross_implementation_report_v2',profile_version='2',claim_boundary='cross-implementation-replay-only-not-independent-assessment')
    for r in report['vector_results']:
        for name in OBSERVATIONS.values():r.pop(name,None)
    bind(2)
    with pytest.raises(ValueError,match='version 2 omits'):check()
    assert check(allow_legacy_v2=True)['claim_boundary']=='legacy-v2-primary-only-observations-unverified'

def test_legacy_v1_requires_explicit_opt_in(bound):
    report,bind,check=bound;report['schema_version']='ecl_cross_implementation_report_v1'
    with pytest.raises(ValueError,match='version 1'):check()

def test_wrong_verdict_claimed_met_is_refused(bound):
    report,bind,check=bound;r=row_for(report,'observed_verdict')
    r['observed_verdict']='verified' if r['observed_verdict']!='verified' else 'invalid';bind()
    with pytest.raises(ValueError,match='status does not match'):check()

def test_wrong_positive_canonical_digest_claimed_met_is_refused(bound):
    report,bind,check=bound;row_for(report,'observed_canonical_sha256')['observed_canonical_sha256']='f'*64;bind()
    with pytest.raises(ValueError,match='status does not match'):check()

def test_honest_not_met_row_requires_fail_decision(bound):
    report,bind,check=bound;r=row_for(report,'observed_verdict');r['observed_verdict']=None;r['status']='not-met';bind()
    with pytest.raises(ValueError,match='does not retain failed vectors'):check()

def test_unsupported_row_carries_no_observations(bound):
    report,bind,check=bound;corpus=json.loads((ROOT/'conformance/shared-corpus.json').read_text())
    capability={v['id']:v['capability'] for v in corpus['vectors']}
    rows=[r for r in report['vector_results'] if 'observed_verdict' in r and capability[r['id']] in corpus['optional_capabilities']]
    dropped={capability[r['id']] for r in rows}|{'offline-package-verification'}
    report['implementation']['capabilities']=[c for c in report['implementation']['capabilities'] if c not in dropped]
    for cap,stage in (('evidence-bundle-verification','evidence-bundle'),('offline-package-verification','package')):
        if cap in dropped:report['time_policies'].pop(stage)
    for r in rows:
        r.update(status='unsupported',unsupported_capability=capability[r['id']]);r.pop('observed_primary_id')
        for name in OBSERVATIONS.values():r.pop(name,None)
    bind();assert check()['unsupported_optional_vectors']==sorted(r['id'] for r in rows)
    rows[0]['observed_verdict']=None;bind()
    with pytest.raises(ValueError,match='cross-implementation-report/3'):check()
