"""Isolated, deterministic TLC diagnostics for the repaired priority and deadline rules.

Mutation copies are temporary evidence artifacts; they never edit the candidate models.
Every output, configuration and changed model is retained and hashed.
"""
from pathlib import Path
import datetime
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys

W=Path(__file__).resolve().parents[1];S=W/'source';OUT=W/'validation/formal-boundaries-001'
OUT.mkdir(exist_ok=False)
spec=importlib.util.spec_from_file_location('ecl_diagnostic_runner',S/'formal/run_checks.py')
f=importlib.util.module_from_spec(spec);sys.modules[spec.name]=f;spec.loader.exec_module(f)
core=(S/'formal/tla/ECLCore.tla').read_text();mc=(S/'formal/tla/MC.tla').read_text()
base=(S/'formal/tla/configs/correct-liveness.cfg').read_text().split('SPECIFICATION Spec')[0]
base=base.replace('MaxTime = 3','MaxTime = 2').replace('MaxRequests = 2','MaxRequests = 1').replace('MaxOutages = 1','MaxOutages = 0').replace('AllowHalt = TRUE','AllowHalt = FALSE')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
priority=r'''
PriorityCases ==
    \A r \in Requests :
        /\ (Verifiable(r) = "forbid" =>
             /\ Evaluate(r, "ok", "low") = "deny"
             /\ Evaluate(r, "bad", "low") = "deny"
             /\ Evaluate(r, "ok", "high") = "deny"
             /\ Evaluate(r, "bad", "high") = "deny")
        /\ (Verifiable(r) = "permit" =>
             /\ Evaluate(r, "ok", "low") = "admit"
             /\ Evaluate(r, "bad", "low") = "challenge"
             /\ Evaluate(r, "ok", "high") = "hold"
             /\ Evaluate(r, "bad", "high") = "hold")
JudgmentOverride == \A r \in Requests : Evaluate(r, "bad", "low") = "admit"
SelfReportOverride == \A r \in Requests : Evaluate(r, "ok", "high") = "admit"
ClampDeadline == \A p \in pending : p.deadline = MaxTime
'''
full='INVARIANTS Safety\nPROPERTIES NoLateDecision HoldResolves RequestResolves HaltTakesEffect\n'
cases=[]
def add(name,expected='pass',*,body=full,config=base,model=core):
 cases.append(dict(name=name,expected=expected,body=body,config=config,model=model))
add('priority-correct',body='INVARIANTS PriorityCases\n')
add('priority-judgment-override',body='INVARIANTS JudgmentOverride\n',config=base.replace('Variant = "correct"','Variant = "judgment_admits"'))
add('priority-self-report-override',body='INVARIANTS SelfReportOverride\n',config=base.replace('Variant = "correct"','Variant = "self_report_admits"'))
zero_decision=base.replace('DecisionDeadline = 1','DecisionDeadline = 0')
add('zero-decision-safe',body='INVARIANTS Safety WitnessNoEffect\nPROPERTIES NoLateDecision RequestResolves HoldResolves\n',config=zero_decision)
add('zero-decision-times-out','WitnessNoTimeout',body='INVARIANTS WitnessNoTimeout\n',config=zero_decision)
add('zero-hold-safe',body='INVARIANTS Safety WitnessNoAdmitAfterHold\nPROPERTIES NoLateDecision RequestResolves HoldResolves\n',config=base.replace('HoldDeadline = 1','HoldDeadline = 0'))
add('one-tick-boundaries')
horizon=core.replace('Submit(r) ==\n','Submit(r) ==\n    /\\ now = MaxTime\n')
add('horizon-submission-safe',body='INVARIANTS Safety WitnessNoEffect ClampDeadline\nPROPERTIES NoLateDecision RequestResolves HoldResolves\n',model=horizon)
add('horizon-submission-times-out','WitnessNoTimeout',body='INVARIANTS WitnessNoTimeout\n',model=horizon)
add('horizon-shortened-deadline',body='INVARIANTS Safety ClampDeadline\nPROPERTIES NoLateDecision RequestResolves HoldResolves\n',config=base.replace('DecisionDeadline = 1','DecisionDeadline = 2'),model=core.replace('Submit(r) ==\n','Submit(r) ==\n    /\\ now = MaxTime - 1\n'))
mutations={
 'mutate-decision-guard':('    /\\ (Flawed("late_decision_used") \\/ now < p.deadline)\n','', 'NoLateDecision'),
 'mutate-hold-guard':('    /\\ now < h.deadline\n','', 'NoLateDecision'),
 'mutate-pending-tick':('    /\\ \\/ Flawed("no_decision_timeout") \\/ Flawed("late_decision_used")\n       \\/ \\A p \\in pending : now < p.deadline\n','', 'DeadlineBound'),
 'mutate-held-tick':('    /\\ \\/ Flawed("hold_never_times_out")\n       \\/ \\A h \\in held : now < h.deadline\n','', 'DeadlineBound'),
}
for name,(before,after,expected) in mutations.items():
 assert core.count(before)==1
 add(name,expected,body='INVARIANTS DeadlineBound\nPROPERTIES NoLateDecision\n',model=core.replace(before,after))
tools=f.Tools(shutil.which('java'),W/'tooling/formal-pins/tla2tools-1.7.4.jar',None,None)
assert not f.pin_problems(tools,tlc=True,tamarin=False)
receipt={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=S,text=True).strip(),
 'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'script_sha256':sha(Path(__file__)),
 'scope':'Focused reduced-configuration diagnostics and four deliberately mutated copies; not additions to the 32 standard TLC check count.',
 'source_files':{p:sha(S/p) for p in ['formal/tla/ECLCore.tla','formal/tla/MC.tla','formal/run_checks.py','formal/tla/configs/correct-liveness.cfg']},'results':[]}
(OUT/'RUN.json').write_text(json.dumps(receipt,indent=2)+'\n')
for case in cases:
 d=OUT/case['name'];t=d/'formal/tla';(t/'configs').mkdir(parents=True)
 (t/'ECLCore.tla').write_text(case['model']);(t/'MC.tla').write_text(mc.replace('=============================================================================',priority+'\n============================================================================='))
 (t/'configs'/f"{case['name']}.cfg").write_text(case['config']+'SPECIFICATION Spec\n'+case['body']+'CHECK_DEADLOCK FALSE\n')
 f.FORMAL=d/'formal';f.TLA=t;f.TLC_CHECKS[case['name']]=case['expected']
 (d/'logs').mkdir();(d/'scratch').mkdir()
 result=f.run_tlc(tools,case['name'],120,d/'scratch',d/'logs')
 receipt['results'].append(f.asdict(result));print(f.summary(result),flush=True)
 (OUT/'RUN.json').write_text(json.dumps(receipt,indent=2)+'\n')
receipt.update(finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),passed=all(x['passed'] for x in receipt['results']))
(OUT/'RUN.json').write_text(json.dumps(receipt,indent=2)+'\n')
sys.exit(0 if receipt['passed'] else 1)
