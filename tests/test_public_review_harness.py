"""Regression tests for harness evidence and generator checks; no qualification claim."""
from __future__ import annotations
import base64
import copy
import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from ecl_verify.integrity import IntegrityError, verify_envelope
from ecl_verify.semantic import SemanticValidator
from scripts import check_public, generate_correction_changelog, generate_mcp_recovery_vectors
from scripts.external_report_v2 import required_time_policy_stages
from scripts.external_report_v3 import observations_match
from scripts.run_conformance import (schema_environment, load_trust_policy, observed_for_vector, scope_matches)
from scripts.scope_expectations import scope_expectation_matches

ROOT=Path(__file__).resolve().parents[1]
MANIFEST=json.loads((ROOT/'conformance/suites/repair-harness/manifest.json').read_bytes())

@pytest.fixture(scope='module')
def harness():
    schemas,registry=schema_environment(ROOT)
    return schemas,registry,SemanticValidator([]),load_trust_policy(ROOT,MANIFEST['trust_policy_path'])

@pytest.mark.parametrize('vector',MANIFEST['vectors'],ids=lambda v:v['id'])
def test_ordered_envelope_and_full_scope_oracles(harness,vector):
    schemas,registry,semantics,policy=harness;scopes={};verdicts={}
    actual=observed_for_vector(ROOT,vector,schemas=schemas,schema_registry=registry,semantics=semantics,trust_policy=policy,scopes=scopes,verdicts=verdicts)
    if vector['expected']=='pass':assert actual==[]
    else:assert actual and actual[0]==vector['expected_primary_id']
    if 'expected_verdict' in vector:assert verdicts[vector['id']]==vector['expected_verdict']
    assert scope_matches(vector,scopes.get(vector['id']))


def test_manifest_accepts_full_check_oracle():
    schema=json.loads((ROOT/'schemas/ecl-conformance-vector-manifest-v3.schema.json').read_bytes())
    Draft202012Validator(schema).validate(MANIFEST)

@pytest.mark.parametrize('name',['array','media-before-time','budget-before-payload','missing-policy-and-time'])
def test_context_provider_does_not_run_before_payload_and_policy_preflight(harness,name):
    policy=harness[3];calls=[]
    def provider(payload):calls.append(payload);raise RuntimeError('must not run')
    envelope=json.loads((ROOT/f'conformance/suites/repair-harness/repair-harness-envelope-{name}.json').read_bytes())
    with pytest.raises(IntegrityError) as error:verify_envelope(envelope,policy.keyring(),provider)
    assert calls==[]
    assert error.value.code==('ecl.error.resource-limit-exceeded.v1' if name=='budget-before-payload' else 'ecl.error.integrity-invalid.v1')


def test_lazy_context_and_existing_direct_context_agree(harness):
    policy=harness[3];envelope=json.loads((ROOT/'conformance/suites/repair-harness/repair-harness-envelope-valid-control.json').read_bytes())
    payload=json.loads(base64.b64decode(envelope['payload']))
    context=policy.verification_context(evaluated_at=payload['issued_at'],time_policy='ecl.time.issued-at.v1')
    assert verify_envelope(envelope,policy.keyring(),context)==verify_envelope(envelope,policy.keyring(),lambda _:context)
    def bad(_):raise RuntimeError('unavailable caller context')
    with pytest.raises(IntegrityError) as error:verify_envelope(envelope,policy.keyring(),bad)
    assert error.value.code=='ecl.error.signature-policy-invalid.v1'

@pytest.mark.parametrize('mutation',['missing-map','missing-check','extra-check','wrong-object','missing-object','extra-object','duplicate-object','duplicate-check'])
def test_scope_evidence_mutations_cannot_be_reported_met(mutation):
    vector=next(v for v in MANIFEST['vectors'] if v['id']=='repair-harness-scope-valid-succeeded-with-register')
    actual=copy.deepcopy(vector['expected_scope']);entry=actual['checks']['release-within-authority']
    if mutation=='missing-map':actual.pop('checks')
    elif mutation=='missing-check':entry['checks']=[]
    elif mutation=='extra-check':entry['checks'].append('current-status')
    elif mutation=='wrong-object':entry['objects'][0]=99
    elif mutation=='missing-object':entry['objects'].pop()
    elif mutation=='extra-object':entry['objects'].append(2)
    elif mutation=='duplicate-object':entry['objects'].append(entry['objects'][0])
    else:entry['checks']*=2
    assert not scope_expectation_matches(actual,vector['expected_scope'])
    expectation={'id':'synthetic-scope-integrity-test','expected':'pass','expected_scope':vector['expected_scope']}
    assert not observations_match({'id':expectation['id'],'status':'met','observed_scope':actual},expectation)


def test_scope_index_order_does_not_change_the_object_set():
    expected=next(v['expected_scope'] for v in MANIFEST['vectors'] if v['id']=='repair-harness-scope-valid-trusted-time')
    actual=copy.deepcopy(expected)
    for entry in actual['checks'].values():entry['checks'].reverse();entry['objects'].reverse()
    assert scope_expectation_matches(actual,expected)


def test_key_role_only_capability_requires_its_envelope_stage_policy():
    manifest=json.loads((ROOT/'conformance/suites/key-roles/manifest.json').read_bytes())
    vectors={v['id']:v for v in manifest['vectors']}
    declarations={identifier:{'capability':'key-role-separation'} for identifier in vectors}
    assert required_time_policy_stages(vectors,declarations,{'key-role-separation'})=={'envelope'}
    assert required_time_policy_stages(vectors,declarations,set())==set()

@pytest.mark.parametrize('optimized',[False,True])
@pytest.mark.parametrize('fault',['fixture','key','suite','base'])
def test_bundle_generator_cannot_accept_corrupt_bytes_with_python_optimization(tmp_path,optimized,fault):
    root=tmp_path/'source'
    shutil.copytree(ROOT/'conformance/suites/evidence-bundle',root/'conformance/suites/evidence-bundle')
    shutil.copytree(ROOT/'tests/fixtures/bundle-gating',root/'tests/fixtures/bundle-gating')
    argv=[sys.executable,*(['-O'] if optimized else []),str(ROOT/'scripts/generate_bundle_gating_fixtures.py'),'--root',str(root),'--check']
    control=subprocess.run(argv,capture_output=True,text=True)
    assert control.returncode==0,control.stderr
    if fault=='fixture':
        target=root/'tests/fixtures/bundle-gating/core-binding-gates-release-window.json';target.write_bytes(target.read_bytes()+b' ')
        message='Stale full-finding fixture'
    elif fault=='key':
        target=root/'conformance/suites/evidence-bundle/trust-policy.json';value=json.loads(target.read_bytes())
        value['keys'][0]['public_key']=base64.b64encode(bytes(32)).decode();target.write_text(json.dumps(value));message='Public fixture key differs'
    elif fault=='suite':
        target=root/'conformance/suites/evidence-bundle/bundle-invalid-release-guard-reaches-valid-until.json';value=json.loads(target.read_bytes())
        value['envelopes'][0]['signatures'][0]['suite_id']='ecl.sig.unknown.v1';target.write_text(json.dumps(value));message='Unsupported fixture signature suite'
    else:
        target=root/'tests/fixtures/bundle-gating/expected.json';value=json.loads(target.read_bytes())
        next(row for row in value['cases'] if row['id']=='core-binding-gates-release-window')['base_sha256']='0'*64
        target.write_text(json.dumps(value));message='Base suite fixture drifted'
    result=subprocess.run(argv,capture_output=True,text=True)
    assert result.returncode!=0 and message in result.stderr



def test_mcp_generator_rejects_crlf_as_different_bytes(tmp_path):
    root=tmp_path/'source';shutil.copytree(ROOT/'conformance/suites/mcp-gateway',root/'conformance/suites/mcp-gateway')
    argv=[sys.executable,str(ROOT/'scripts/generate_mcp_recovery_vectors.py'),'--root',str(root)]
    control=subprocess.run(argv,capture_output=True,text=True);assert control.returncode==0,control.stderr
    target=root/'conformance/suites/mcp-gateway/mcp-valid-recovered-held.json'
    target.write_bytes(target.read_bytes().replace(b'\n',b'\r\n'))
    result=subprocess.run([*argv,'--check'],capture_output=True,text=True)
    assert result.returncode!=0 and target.name in result.stdout


def historical_fixture(tmp_path):
    root=tmp_path/'source';(root/'release').mkdir(parents=True);(root/'registries').mkdir()
    before={'requirements':[{'requirement_id':'R-1','source_path':'spec.md','text':'Before.'}]}
    after={'requirements':[{'requirement_id':'R-1','source_path':'spec.md','text':'After.'}]}
    archive=tmp_path/'before.zip'
    with zipfile.ZipFile(archive,'w') as z:
        z.writestr('CHANGELOG.md','Generated from `registries/requirement-ledger.json` (version 1.0).\n\n## 1.0\n')
        z.writestr('registries/requirements-compiled.json',json.dumps(before))
        z.writestr('registries/requirement-ledger.json','{}')
    row={'requirement_id':'R-1','source_path':'spec.md','before':'Before.','after':'After.'}
    for member in ('before','after'):row[member+'_text_sha256']=hashlib.sha256(row[member].encode()).hexdigest()
    record={'original_source_archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'requirement_count':1,'requirements_added':[],'requirements_removed':[],'changed_requirement_text':[row]}
    (root/'release/CORRECTIONS-1.0.1.json').write_text(json.dumps(record))
    (root/'registries/requirements-compiled.json').write_text(json.dumps(after))
    (root/'registries/requirement-ledger.json').write_text('{}')
    return root,archive,record

@pytest.mark.parametrize('member',['before','after'])
def test_historical_ledger_checks_exact_text_not_only_changed_ids(tmp_path,member):
    root,archive,record=historical_fixture(tmp_path)
    generate_correction_changelog.historical_inputs(root,archive)
    row=record['changed_requirement_text'][0];row[member]='Forged text.';row[member+'_text_sha256']=hashlib.sha256(row[member].encode()).hexdigest()
    (root/'release/CORRECTIONS-1.0.1.json').write_text(json.dumps(record))
    with pytest.raises(ValueError,match='text or digest differs'):generate_correction_changelog.historical_inputs(root,archive)


def test_frozen_correction_after_image_is_separate_from_current_draft(tmp_path):
    root,archive,_=historical_fixture(tmp_path);corrected=tmp_path/'after.zip'
    with zipfile.ZipFile(corrected,'w') as z:
        for name in ('release/CORRECTIONS-1.0.1.json','registries/requirements-compiled.json','registries/requirement-ledger.json'):z.write(root/name,name)
    digest=hashlib.sha256(corrected.read_bytes()).hexdigest()
    after=json.loads((root/'registries/requirements-compiled.json').read_bytes());after['requirements'][0]['text']='Later review draft.'
    (root/'registries/requirements-compiled.json').write_text(json.dumps(after))
    with pytest.raises(ValueError,match='text or digest differs'):generate_correction_changelog.historical_inputs(root,archive)
    assert generate_correction_changelog.historical_inputs(root,archive,corrected,digest)[2]['R-1']['text']=='After.'
    with pytest.raises(ValueError,match='recorded SHA-256'):generate_correction_changelog.historical_inputs(root,archive,corrected,'0'*64)


def test_public_check_includes_both_pytest_trees(monkeypatch):
    commands=[];monkeypatch.setattr(check_public,'run',lambda argv,cwd=None:commands.append(argv))
    monkeypatch.setattr(sys,'argv',['check_public.py','--language','python'])
    assert check_public.main()==0
    assert [sys.executable,'-m','pytest','tests','packages/ecl-verify/tests'] in commands


def test_public_check_uses_a_nonzero_explicit_revision():
    assert check_public.source_revision(ROOT,'a'*40)=='a'*40
    with pytest.raises(ValueError,match='nonzero'):check_public.source_revision(ROOT,'0'*40)


def test_source_export_does_not_inherit_parent_repository_identity(tmp_path,monkeypatch):
    monkeypatch.setattr(subprocess,'check_output',lambda *args,**kwargs:str(tmp_path.parent))
    with pytest.raises(ValueError,match='repository of its own'):check_public.source_revision(tmp_path)


def test_key_role_only_report_cannot_omit_applied_time_policy(tmp_path):
    from scripts.verify_external_implementation_report import verify, source_tree
    root=tmp_path/'corpus';evidence=tmp_path/'evidence';implementation=tmp_path/'implementation'
    evidence.mkdir();implementation.mkdir();(implementation/'NOTICE.txt').write_text('Synthetic report binding fixture; no execution result claimed.\n')
    def write(path,value):
        path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True)+'\n')
        return hashlib.sha256(path.read_bytes()).hexdigest()
    manifest=json.loads((ROOT/'conformance/suites/key-roles/manifest.json').read_bytes())
    corpus=json.loads((ROOT/'conformance/shared-corpus.json').read_bytes())
    ids={v['id'] for v in manifest['vectors']};corpus['vectors']=[v for v in corpus['vectors'] if v['id'] in ids]
    corpus_hash=write(root/'conformance/shared-corpus.json',corpus)
    write(root/'conformance/suites/key-roles/manifest.json',manifest)
    empty=json.loads((ROOT/'conformance/manifest.json').read_bytes());empty['vectors']=[];write(root/'conformance/manifest.json',empty)
    for vector in manifest['vectors']:
        dst=root/vector['path'];dst.parent.mkdir(exist_ok=True,parents=True);shutil.copyfile(ROOT/vector['path'],dst)
    for name in ('ecl-cross-implementation-report-v3.schema.json','ecl-external-vector-raw-result-v3.schema.json'):
        dst=root/'schemas'/name;dst.parent.mkdir(exist_ok=True);shutil.copyfile(ROOT/'schemas'/name,dst)
    for name in ('error-codes', 'semantic-rules'):
        dst=root/'registries'/f'{name}.json';dst.parent.mkdir(exist_ok=True);shutil.copyfile(ROOT/'registries'/f'{name}.json',dst)
    report=json.loads((ROOT/'conformance/report-template-v3.json').read_bytes())
    report['decision']='pass';report['implementation'].update(name='synthetic-key-role-only',source_revision='synthetic-binding-fixture',source_tree_sha256=source_tree(implementation)[0],capabilities=corpus['required_capabilities']+['key-role-separation'])
    report['suite'].update(manifest_sha256=corpus_hash,vector_count=len(ids));report['time_policies']={}
    report['vector_results']=[];report['evidence']=[]
    for index,vector in enumerate(manifest['vectors']):
        row=dict(id=vector['id'],suite=manifest['suite'],artifact_sha256=hashlib.sha256((ROOT/vector['path']).read_bytes()).hexdigest(),expected=vector['expected'],status='met',observed_primary_id=vector.get('expected_primary_id'),observed_secondary_ids=[])
        sha=write(evidence/f'{index}.json',dict(schema_version='ecl_external_vector_raw_result_v3',implementation_revision=report['implementation']['source_revision'],result=row))
        row['raw_result_sha256']=sha;report['vector_results'].append(row);report['evidence'].append({'path':f'{index}.json','sha256':sha})
    with pytest.raises(ValueError,match='supported vector stages'):verify(root,report,evidence_root=evidence,implementation_root=implementation)
    report['time_policies']={'envelope':['ecl.time.issued-at.v1','ecl.time.observed-at.v1']}
    assert verify(root,report,evidence_root=evidence,implementation_root=implementation)['verified_raw_result_count']==len(ids)
