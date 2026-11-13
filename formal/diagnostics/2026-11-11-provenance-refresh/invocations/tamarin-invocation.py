"""Exercise every affected symbolic check on the staged theory; retain hashes/logs."""
from pathlib import Path
import dataclasses
import importlib.util
import json
import sys

P = Path(__file__).resolve().parent
W = P.parents[1]
PIN = W.parent / 'ecl-1-source-repairs-20261107-1/tooling/formal-pins'
R = W / 'reports/protocol-validation-17-001/repaired-checks-001'
R.mkdir(exist_ok=False)
spec = importlib.util.spec_from_file_location('protocol_repaired_runner', P / 'preview-source/formal/run_checks.py')
runner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runner
spec.loader.exec_module(runner)
tools = runner.Tools(java=None, tla2tools=None, tamarin=PIN / 'tamarin-prover', maude_dir=PIN)
assert not runner.pin_problems(tools, tlc=False, tamarin=True)
rows = []
for name in runner.TAMARIN_CHECKS:
    row = runner.run_tamarin(tools, name, 120, 10, R)
    rows.append(dataclasses.asdict(row))
    (R / 'RESULTS.json').write_text(json.dumps({'checks': rows, 'complete': len(rows) == len(runner.TAMARIN_CHECKS),
        'all_expected': all(x['passed'] for x in rows), 'runner_sha256': runner.sha256(P / 'preview-source/formal/run_checks.py'),
        'script_sha256': runner.sha256(Path(__file__)), 'pins': runner.record_pins(), 'timeout_seconds': 120,
        'derivcheck_timeout': 10, 'candidate_written': False}, indent=2) + '\n')
    print(json.dumps({k: rows[-1][k] for k in ('name', 'observed', 'passed', 'seconds')}), flush=True)
