"""Reproduce declaration-contract vectors and attribute their schema branch coverage."""
from __future__ import annotations
import argparse,copy,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'packages/ecl-verify/src'))
from coverage_denominator import attribution_for,schema_units
NS='https://externalcontrollayer.ai/ns/schema/';ERROR='ecl.error.schema-invalid.v1';RULE='ecl.rule.deployment-timing-case-consistent.v1'
GENERATOR='scripts/generate_claim_deployment_vectors.py';SUITES=('claim-deployment-contract','deployment-timing-case')
FIELDS=('connected_revocation_seconds','offline_staleness_seconds','evidence_export_seconds');DEFAULT={1:(86400,86400,259200),2:(900,14400,86400),3:(300,3600,14400),4:(60,900,3600)}
def encoded(v):return (json.dumps(v,indent=2,sort_keys=True)+'\n').encode()
def build(root):
    def read(path):return json.loads((root/path).read_bytes())
    ap='conformance/suites/document-coverage/assessment-valid-l4-class-c.json';cp='conformance/suites/document-coverage/claim-valid-full-l4-class-c.json';dp='conformance/suites/document-coverage/deployment-valid-centralized-example.json';fp='conformance/suites/document-coverage/deployment-valid-federated-example.json'
    assessment,claim,deployment,federated=map(read,(ap,cp,dp,fp));outputs={};rows={name:[] for name in SUITES}
    def add(name,value,schema,base,requirements,fail=False,semantic=False):
        suite=SUITES[int(semantic)];identifier=suite+'-'+name.replace('_','-');path=Path('conformance/suites')/suite/(identifier+'.json');outputs[path]=encoded(value)
        row=dict(id=identifier,path=path.as_posix(),stage='document',schema=NS+schema+'/1',source=dict(kind='mutation',generator=GENERATOR,base_vector=base,mutation=name),expected='fail' if fail else 'pass',expected_secondary_ids=[],requirement_ids=sorted(requirements),covers=[RULE] if semantic else [])
        if fail:row.update(expected_primary_id=RULE if semantic else ERROR,negates=sorted(requirements))
        rows[suite].append(row)
    def a(level=2):
        x=copy.deepcopy(assessment);x['level']=level;x['independence'].update({'class':'C' if level==4 else 'B' if level>=2 else 'A','direct_implementation_within_24_months':False});return x
    for level in (1,2,3,4):
        x=a(level);add(f'assessment-l{level}-control',x,'assessment-package',ap,['ECL1N-0086','ECL1N-0148'])
        if level==1:
            x['independence'].pop('direct_implementation_within_24_months');add('assessment-l1-history-omitted-control',x,'assessment-package',ap,['ECL1N-0148'])
            x['independence'].update(direct_implementation_within_24_months=True,managed_operator_within_24_months=True,claim_approval_authority_within_24_months=True,material_affiliate_or_reseller=True);add('assessment-l1-conflicts-control',x,'assessment-package',ap,['ECL1N-0148'])
        else:
            for field in ('direct_implementation_within_24_months','managed_operator_within_24_months','claim_approval_authority_within_24_months','material_affiliate_or_reseller'):
                x=a(level);x['independence'][field]=True;add(f'assessment-l{level}-{field}',x,'assessment-package',ap,['ECL1N-0086'],True)
            x=a(level);x['independence'].pop('direct_implementation_within_24_months');add(f'assessment-l{level}-history-omitted',x,'assessment-package',ap,['ECL1N-0086'],True)
            x=a(level);x['independence'].update(material_affiliate_or_reseller=True,published_sector_exception={'uri':'urn:example:sector:published-exception'});add(f'assessment-l{level}-affiliate-exception-control',x,'assessment-package',ap,['ECL1N-0086'])
    for severity in ('critical','major','minor','observation'):
        for disposition in ('open','accepted_condition','remediated','rejected'):
            x=a();x['findings'][0].update(severity=severity,disposition=disposition);x['claim_decision']['status']='full_conformance'
            if severity=='observation' or disposition in ('remediated','rejected'):
                for item in x['checklist']:item['result']='pass'
            add(f'assessment-full-{severity}-{disposition}',x,'assessment-package',ap,['ECL1N-0081','ECL1N-0147'],severity in ('critical','major') and disposition in ('open','accepted_condition'))
    for severity in ('critical','major','minor'):
        x=a();x['findings'][0]['severity']=severity;x['claim_decision']['status']='conditional_conformance';add(f'assessment-conditional-{severity}-artifact-reference',x,'assessment-package',ap,['ECL1N-0081','ECL1N-0147'],severity=='critical')
    for severity in ('critical','major','minor'):
        for disposition in ('remediated','rejected'):
            x=a();x['findings'][0].update(severity=severity,disposition=disposition)
            x['claim_decision']['status']='full_conformance'
            add(f'assessment-failed-item-only-{severity}-{disposition}',x,'assessment-package',ap,['ECL1N-0081','ECL1N-0147'],True)
    x=a();x['findings'][0]['severity']='minor';historical=copy.deepcopy(x['findings'][0]);historical.update(finding_id='urn:example:historical-finding',severity='critical',disposition='remediated');x['findings'].append(historical);x['claim_decision']['status']='full_conformance';add('assessment-active-minor-with-historical-critical-control',x,'assessment-package',ap,['ECL1N-0081','ECL1N-0147'])
    x=a();x['findings']=[];add('assessment-failed-item-no-finding',x,'assessment-package',ap,['ECL1N-0147'],True)
    x=a();x['findings'][0]['severity']='observation';add('assessment-failed-item-only-observation',x,'assessment-package',ap,['ECL1N-0147'],True)
    x=a();x['findings'][0]['severity']='critical';add('assessment-critical-assessment-only-control',x,'assessment-package',ap,['ECL1N-0147'])
    x=copy.deepcopy(claim);x.update(limitations=[],valid_until='2027-01-01T00:00:00Z');add('claim-full-empty-limitations-expiry-control',x,'conformance-claim',cp,['ECL1N-0078'])
    x['conditions']=read('conformance/suites/document-coverage/claim-valid-conditional-l3-class-c.json')['conditions'];add('claim-full-conditional-remediation',x,'conformance-claim',cp,['ECL1N-0077','ECL1N-0081'],True)
    x['status']='assessment_only';add('claim-assessment-only-remediation-control',x,'conformance-claim',cp,['ECL1N-0081'])
    def d(level):
        x=copy.deepcopy(deployment);x['claim_level']=level;t=x['timing_case'];t.update(zip(FIELDS,DEFAULT[level]));t.update(uses_default_baseline=True,trusted_time_or_secure_monotonic=level>=3)
        for k in ('variance_rationale','control_assumptions','residual_risk','assessor_deviation_approval'):t.pop(k,None)
        return x
    def disclosed(t):t.update(uses_default_baseline=False,variance_rationale='Explicit engineered timing case.',control_assumptions=['Declared update channel.'],residual_risk='Documented exposure during the interval.')
    for level in (1,2,3,4):
        x=d(level);add(f'deployment-l{level}-baseline-control',x,'deployment-profile',dp,['ECL1N-0098','ECL1N-0100'])
        if level>=3:
            x['timing_case']['trusted_time_or_secure_monotonic']=False;add(f'deployment-l{level}-untrusted-order',x,'deployment-profile',dp,['ECL1N-0100'],True)
        for field,limit in zip(FIELDS,DEFAULT[level]):
            x=d(level);x['timing_case'][field]=limit-1;add(f'deployment-l{level}-false-baseline-{field}',x,'deployment-profile',dp,['ECL1N-0098'],True)
            x=d(level);t=x['timing_case'];disclosed(t);t[field]=limit+1;add(f'deployment-l{level}-unapproved-{field}',x,'deployment-profile',dp,['ECL1N-0098'],True)
            t['assessor_deviation_approval']={'uri':'urn:example:assessor:timing-approval'};add(f'deployment-l{level}-approved-{field}-control',x,'deployment-profile',dp,['ECL1N-0098'])
        x=d(level);disclosed(x['timing_case']);x['timing_case'].update({k:0 for k in FIELDS});add(f'deployment-l{level}-stricter-zero-control',x,'deployment-profile',dp,['ECL1N-0098'])
    for surface in ('hosted_control_plane','self_managed_control_plane'):
        x=copy.deepcopy(federated);x['delivery_surfaces']=['local_gate',surface];add('federated-'+surface+'-control',x,'deployment-profile',fp,['ECL1N-0092','ECL1N-0099'])
    x=copy.deepcopy(federated);x['delivery_surfaces']=['local_gate'];add('federated-no-control-plane',x,'deployment-profile',fp,['ECL1N-0092'],True)
    x=copy.deepcopy(federated);x['timing_case'].pop('federated_exchange_seconds');add('federated-no-timing',x,'deployment-profile',fp,['ECL1N-0099'],True)
    for value in (-1,True,'1',None):
        x=copy.deepcopy(federated);x['timing_case']['federated_exchange_seconds']=value;add('federated-invalid-interval-'+str(value).lower(),x,'deployment-profile',fp,['ECL1N-0099'],True)
    for offset in (-1,0,1):
        x=copy.deepcopy(federated);x['timing_case']['federated_exchange_seconds']=x['timing_case']['connected_revocation_seconds']+offset;add('exchange-boundary-'+str(offset),x,'deployment-profile',fp,['ECL1N-0099'],offset>0,True)
    x=copy.deepcopy(federated);disclosed(x['timing_case']);x['timing_case'].update(connected_revocation_seconds=0,federated_exchange_seconds=0);add('exchange-zero-control',x,'deployment-profile',fp,['ECL1N-0099'],semantic=True)
    # Expected verdicts are authored above. Only coverage attribution uses schema mutation.
    attr=attribution_for(root);units=[]
    for schema,file in [('assessment-package','ecl-assessment-package-v1.schema.json'),('conformance-claim','ecl-conformance-claim-v1.schema.json'),('deployment-profile','ecl-deployment-profile-v1.schema.json')]:
        for unit in schema_units(NS+schema+'/1',read('schemas/'+file)):
            ptr=unit['pointer'];wanted=(schema=='assessment-package' and (ptr.startswith('/allOf/0/then/properties/independence/allOf/') or any(ptr.startswith(f'/allOf/{i}/') for i in (3,4,5)))) or (schema=='conformance-claim' and ptr.startswith('/allOf/5/')) or (schema=='deployment-profile' and (ptr.startswith('/allOf/1/then/properties/delivery_surfaces/contains') or any(ptr.startswith(f'/allOf/{i}/') for i in range(5,10))))
            if wanted:units.append(unit)
    for row in rows[SUITES[0]]:
        value=json.loads(outputs[Path(row['path'])]);row['covers']=[u['id'] for u in units if u['schema_id']==row['schema'] and attr.witnesses(u,row,value)]
    missing=[u['id']+':'+outcome for u in units for outcome in ('pass','fail') if not any(r['expected']==outcome and u['id'] in r['covers'] for r in rows[SUITES[0]])]
    if missing:raise ValueError('unattributed schema branches: '+str(missing))
    for suite,vectors in rows.items():outputs[Path('conformance/suites')/suite/'manifest.json']=encoded(dict(schema_version='ecl_conformance_vector_manifest_v3',candidate_version='1.0',suite='ecl-1-v1.0-'+suite,vectors=sorted(vectors,key=lambda x:x['id'])))
    return outputs,{'document_vectors':len(rows[SUITES[0]]),'timing_vectors':len(rows[SUITES[1]]),'new_schema_units':len(units),'missing_two_sided_attribution':missing}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);p.add_argument('--check',action='store_true');a=p.parse_args();out,receipt=build(a.root)
    for path,data in out.items():
        target=a.root/path
        if a.check:
            if not target.is_file() or target.read_bytes()!=data:raise SystemExit('stale declaration vector: '+str(path))
        else:target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    print(json.dumps({**receipt,'check':a.check}))
if __name__=='__main__':main()
