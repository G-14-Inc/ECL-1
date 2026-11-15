"""Complete graph and signed-bundle ROOT-037 controls; bounded iterative graph regressions."""
import json
from pathlib import Path
import sys
import pytest
from ecl_verify.bundle import analyze_bundle
from ecl_verify.bundle_verification import verify_bundle, report_to_json
from ecl_verify.canonical import object_digest
from ecl_verify.trust import TrustPolicy

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT/'tests/fixtures/repair-causal-origin.json').read_bytes())
POLICY = TrustPolicy.load((ROOT/'conformance/suites/evidence-bundle/trust-policy.json').read_bytes())

@pytest.mark.parametrize('case', CASES, ids=lambda c:c['name'])
def test_child_origin_graph_and_signed_bundle(case):
    graph = analyze_bundle(case['records'], check_context=True, allowed_external_predecessors=case['allowed_external_predecessors'])
    assert graph.status == case['status']
    assert sorted({f.rule_id for f in graph.findings}) == case['expected_rules']
    assert list(graph.unresolved_predecessor_ids) == case['expected_unresolved']
    report = report_to_json(verify_bundle(json.loads((ROOT/case['bundle_path']).read_bytes()), POLICY, now='2026-10-01T00:00:00Z'))
    assert (report['verdict'],report['primary']) == (case['expected_verdict'],case['expected_primary']), report
    assert ('causal-completeness' in report['scope']['established']) == (case['expected_verdict']=='verified')
    assert all(e['historical']==e['current']=='valid' for e in report['envelope_checks']), report['envelope_checks']

def test_child_origin_vectors_are_byte_exact():
    sys.path.insert(0,str(ROOT))
    from scripts.generate_causal_origin_vectors import build
    for path,data in build(ROOT).items(): assert (ROOT/path).read_bytes()==data,path

def minimal(identifier, workflow, sequence, prior=None, parent=None):
    value={'object_id':identifier,'workflow':{'workflow_id':workflow,'root_trace_id':'urn:trace','attempt':1,'sequence':sequence,'causal_predecessors':[]}}
    if parent:value['workflow']['parent_workflow_id']=parent
    if prior:value['workflow']['causal_predecessors']=[{'id':prior['object_id'],'digest':{'algorithm':'ecl.digest.sha-256.v1','value':object_digest(prior)}}]
    return value

def test_deep_child_progression_and_many_joins_are_iterative():
    start=minimal('urn:parent:0','urn:parent',0);records=[start];prior=start
    for n in range(2048):
        child=minimal(f'urn:child:{n:04}','urn:child',n,prior,'urn:parent')
        records.extend([child,minimal(f'urn:join:{n:04}','urn:parent',n+1,child)])
        prior=child
    result=analyze_bundle(reversed(records),check_context=True,max_records=5000)
    assert result.status=='complete' and not result.findings

@pytest.mark.parametrize('length',[3,2048])
def test_cycle_normalization_preserves_order_and_bounded_diagnostic(length):
    # The public API reads these deliberately non-matching digest references; the cycle finding
    # remains deterministic and bounded even when the cycle is deeper than a recursive walk.
    names=[f'urn:cycle:{n:04}' for n in range(length)]
    records=[minimal(name,'urn:cycle',n) for n,name in enumerate(names)]
    for n,r in enumerate(records):r['workflow']['causal_predecessors']=[{'id':names[(n+1)%length],'digest':{'algorithm':'ecl.digest.sha-256.v1','value':'0'*64}}]
    for ordered in [records,list(reversed(records))]:
        result=analyze_bundle(ordered,max_records=3000)
        cycles=[f for f in result.findings if f.rule_id=='ecl.rule.bundle-causal-graph-acyclic.v1']
        assert len(cycles)==1
        display=names+[names[0]]
        if len(display)>18:display=display[:8]+['...']+display[-8:]
        assert cycles[0].message=='causal cycle: '+' -> '.join(display)
