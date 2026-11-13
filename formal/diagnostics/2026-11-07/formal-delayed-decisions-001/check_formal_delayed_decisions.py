"""Check safety and demonstrate delayed decisions/resolutions with two-tick deadlines."""
from pathlib import Path
import datetime,hashlib,importlib.util,json,shutil,subprocess,sys
W=Path(__file__).resolve().parents[1];S=W/'source';O=W/'validation/formal-delayed-decisions-001';O.mkdir(exist_ok=False)
spec=importlib.util.spec_from_file_location('delayed_runner',S/'formal/run_checks.py');f=importlib.util.module_from_spec(spec);sys.modules[spec.name]=f;spec.loader.exec_module(f)
core=(S/'formal/tla/ECLCore.tla').read_text();mc=(S/'formal/tla/MC.tla').read_text()
base=(S/'formal/tla/configs/correct-liveness.cfg').read_text().split('SPECIFICATION Spec')[0]
for a,b in [('MaxRequests = 2','MaxRequests = 1'),('MaxOutages = 1','MaxOutages = 0'),('AllowHalt = TRUE','AllowHalt = FALSE'),('DecisionDeadline = 1','DecisionDeadline = 2'),('HoldDeadline = 1','HoldDeadline = 2')]:
 assert base.count(a)==1;base=base.replace(a,b)
extra=r'''
\* With deadline 2 and MaxTime 3, deadline = 2 identifies creation at tick 0.
\* A new decision at tick 1 therefore answers a request/hold from an earlier tick.
WitnessNoDelayedDecision ==
    [][~(\E d \in decisions' \ decisions :
           d.at = 1 /\ \E p \in pending : p.req = d.req /\ p.deadline = 2)]_vars
WitnessNoDelayedResolution ==
    [][~(\E d \in decisions' \ decisions :
           d.at = 1 /\ \E h \in held : h.req = d.req /\ h.deadline = 2)]_vars
'''
tools=f.Tools(shutil.which('java'),W/'tooling/formal-pins/tla2tools-1.7.4.jar',None,None)
assert not f.pin_problems(tools,tlc=True,tamarin=False)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
r=dict(source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=S,text=True).strip(),started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),script_sha256=sha(Path(__file__)),source_files={n:sha(S/n) for n in ['formal/tla/ECLCore.tla','formal/tla/MC.tla','formal/run_checks.py','formal/tla/configs/correct-liveness.cfg']},scope='Three focused diagnostics on unchanged source model with two-tick decision and hold deadlines. Separate from the 32 standard TLC checks and the preceding 14 priority/boundary/mutation diagnostics.',results=[])
cases=[('two-tick-safety-and-liveness','pass','INVARIANTS Safety\nPROPERTIES NoLateDecision RequestResolves HoldResolves HaltTakesEffect\n'),('delayed-decision-witness','WitnessNoDelayedDecision','PROPERTIES WitnessNoDelayedDecision\n'),('delayed-resolution-witness','WitnessNoDelayedResolution','PROPERTIES WitnessNoDelayedResolution\n')]
for name,expected,body in cases:
 d=O/name;t=d/'formal/tla';(t/'configs').mkdir(parents=True);(d/'logs').mkdir();(d/'scratch').mkdir()
 (t/'ECLCore.tla').write_text(core);(t/'MC.tla').write_text(mc.replace('=============================================================================',extra+'\n============================================================================='))
 (t/'configs'/f'{name}.cfg').write_text(base+'SPECIFICATION Spec\n'+body+'CHECK_DEADLOCK FALSE\n')
 f.FORMAL=d/'formal';f.TLA=t;f.TLC_CHECKS[name]=expected
 c=f.run_tlc(tools,name,120,d/'scratch',d/'logs');r['results'].append(f.asdict(c));print(f.summary(c),flush=True)
 (O/'RUN.json').write_text(json.dumps(r,indent=2)+'\n')
r.update(finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),passed=all(c['passed'] for c in r['results']));(O/'RUN.json').write_text(json.dumps(r,indent=2)+'\n')
sys.exit(0 if r['passed'] else 1)
