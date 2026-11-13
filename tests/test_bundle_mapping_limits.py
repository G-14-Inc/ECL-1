"""Parsed bundle inputs have finite depth/node bounds; byte limits belong to byte interfaces."""
import json
from pathlib import Path
import pytest
from ecl_verify.bundle_verification import verify_bundle
from ecl_verify.canonical import MAX_JSON_DEPTH, MAX_JSON_NODES
from ecl_verify.cli import main
from ecl_verify.trust import TrustPolicy
ROOT=Path(__file__).resolve().parents[1]/'tests/fixtures/bundle-contract-regressions'
POLICY_PATH=ROOT/'f001-prepared-control.policy.json'
POLICY=TrustPolicy.load(POLICY_PATH.read_bytes())
RESOURCE='ecl.error.resource-limit-exceeded.v1'
def bundle(value):
    b=json.loads((ROOT/'f001-prepared-control.bundle.json').read_text())
    b['envelopes'][0]['extensions']=[{'id':'com.example.annotation.v1','version':1,'critical':False,'value':value}]
    return b

def nodes(value):
    todo=[value];n=0
    while todo:
        x=todo.pop();n+=1
        if isinstance(x,dict):todo.extend(x.values())
        elif isinstance(x,list):todo.extend(x)
    return n
@pytest.mark.parametrize('case,excess',[('depth-at',False),('depth-over',True),('nodes-at',False),('nodes-over',True),('cycle',True),('shared',False),('shared-over',True),('large-string',False)])
def test_mapping_resource_boundary(case,excess):
    value=None
    if case.startswith('depth'):
        # Root 0, envelopes 1, envelope 2, extensions 3, occurrence 4, value 5.
        for _ in range(MAX_JSON_DEPTH-5+(case=='depth-over')):value=[value]
    elif case.startswith('nodes'):
        value=[0]*(MAX_JSON_NODES-nodes(bundle([]))+(case=='nodes-over'))
    elif case=='cycle':value=[];value.append(value)
    elif case=='shared':shared={'values':[1,2]};value=[shared,shared]
    elif case=='shared-over':
        for _ in range(20):value=[value,value]
    else:value='a'*(1024*1024+1)
    report=verify_bundle(bundle(value),POLICY,now='2026-10-01T00:00:00Z')
    assert report.verdict==('invalid' if excess else 'verified'),report.findings
    if excess:
        assert report.findings[0].startswith(RESOURCE+':')
        assert not report.envelope_checks

def test_large_string_still_hits_byte_interface_limit(tmp_path,capsys):
    path=tmp_path/'large-bundle.json';path.write_text(json.dumps(bundle('a'*(1024*1024+1))))
    assert main([str(path),'--trust-policy',str(POLICY_PATH),'--now','2026-10-01T00:00:00Z'])==2
    captured=capsys.readouterr()
    assert RESOURCE in captured.err+captured.out
