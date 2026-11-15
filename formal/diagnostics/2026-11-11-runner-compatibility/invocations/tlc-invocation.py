"""Run only the explicitly prepared 58-check TLC command and retain its output."""
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import time

W = Path(__file__).resolve().parent
D = W.parent.parent / 'reports' / W.name
preparation = json.loads((D / 'PREPARATION.json').read_text())
assert json.loads((D / 'COMMENT-ONLY-CHECK.json').read_text())['executable_source_characters_equal'] is True
folder = D / 'tlc-001'
assert not (folder / 'COMMAND-START.json').exists()
assert not (folder / 'logs').exists() and not (folder / 'RESULTS.json').exists()
started = dt.datetime.now(dt.timezone.utc).isoformat()
(folder / 'COMMAND-START.json').write_text(json.dumps(
    {'started_utc': started, 'argv': preparation['argv'], 'scope': preparation['purpose']}, indent=2) + '\n')
environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
start = time.monotonic()
with (folder / 'COMMAND.log').open('x') as log:
    process = subprocess.Popen(preparation['argv'], cwd=W / 'source', env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in process.stdout:
        log.write(line)
        log.flush()
        sys.stdout.write(line)
        sys.stdout.flush()
    code = process.wait()
(folder / 'COMMAND-RESULT.json').write_text(json.dumps(
    {'started_utc': started, 'finished_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
     'elapsed_seconds': time.monotonic() - start, 'exit_code': code,
     'argv': preparation['argv'], 'settings': preparation['settings'],
     'tamarin_executed': False, 'software_qualification_executed': False}, indent=2) + '\n')
raise SystemExit(code)
