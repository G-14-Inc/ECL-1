"""Generator checks must detect corpus drift, including under Python optimization."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from ecl_verify.bindings import mcp
from scripts import generate_mcp_recovery_vectors as recovery

ROOT = Path(__file__).resolve().parents[1]
MCP = 'conformance/suites/mcp-gateway'
NEGATIVE = 'mcp-invalid-encoded-noncharacter-id-forwarded'
POSITIVE = 'mcp-valid-supplementary-id-forwarded'


def clone(root, paths):
    for rel in paths:
        source, target = ROOT / rel, root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copy2(source, target)


def run(root, script, optimized=False, check=True):
    return subprocess.run([sys.executable, *(['-O'] if optimized else []),
                           str(root / 'scripts' / script), *(['--check'] if check else [])],
                          cwd=root, capture_output=True, text=True)


def write(path, value, sorted_keys=True):
    path.write_text(json.dumps(value, indent=2, sort_keys=sorted_keys)+'\n')


@pytest.mark.parametrize('script', [
    'generate_mcp_recovery_vectors.py', 'generate_binding_input_migration.py',
    'generate_repair_bindings_vectors.py', 'generate_safe_state_authorization_vectors.py',
    'generate_schema_boundary_vectors.py'])
@pytest.mark.parametrize('optimized', [False, True])
def test_current_generator_output_is_reproducible(script, optimized):
    result = run(ROOT, script, optimized)
    assert result.returncode == 0, result.stdout + result.stderr


def test_recovered_prepared_control_isolates_terminal_binding():
    outputs, entries = recovery.build(ROOT)
    name = 'mcp-invalid-recovered-admit-denied-with-prepared'
    value = json.loads(outputs[f'{MCP}/{name}.json'])
    assert {f.rule_id for f in mcp.check(value)} == {'ecl.rule.mcp-result-bound.v1'}
    row = next(row for row in entries if row['id'] == name)
    assert row['expected_primary_id'] == 'ecl.rule.mcp-result-bound.v1'
    assert row['expected_secondary_ids'] == []


@pytest.mark.parametrize('optimized', [False, True])
def test_relabeling_recovery_ownership_cannot_hide_payload_drift(tmp_path, optimized):
    root = tmp_path / 'source'
    script = 'generate_mcp_recovery_vectors.py'
    clone(root, [f'scripts/{script}', MCP])
    # Older generator sorts unrelated rows; retain that baseline behavior in
    # this negative test so its failure isolates the ownership bypass.
    assert run(root, script, optimized, check=False).returncode == 0
    assert run(root, script, optimized).returncode == 0
    manifest_path = root / MCP / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    name = 'mcp-valid-recovered-held'
    row = next(row for row in manifest['vectors'] if row['id'] == name)
    row['source']['generator'] = 'scripts/generate_mcp_public_review_migration.py'
    write(manifest_path, manifest)
    payload = root / MCP / (name+'.json')
    payload.write_bytes(payload.read_bytes()+b' ')
    result = run(root, script, optimized)
    assert result.returncode != 0, result.stdout + result.stderr


@pytest.mark.parametrize('optimized', [False, True])
@pytest.mark.parametrize('fault', ['verdict', 'negative-attribution', 'secondary',
                                  'path', 'positive-coverage', 'source',
                                  'otel-attribution', 'retained-bytes'])
def test_binding_migration_rejects_input_or_oracle_drift(tmp_path, optimized, fault):
    root = tmp_path / 'source'
    script = 'generate_binding_input_migration.py'
    clone(root, [f'scripts/{script}', MCP, 'conformance/suites/otel-export'])
    assert run(root, script, optimized).returncode == 0
    if fault == 'retained-bytes':
        path = root / MCP / (NEGATIVE+'.json')
        path.write_bytes(path.read_bytes()+b' ')
    else:
        rel = 'conformance/suites/otel-export/manifest.json' if fault == 'otel-attribution' else MCP+'/manifest.json'
        path = root / rel
        manifest = json.loads(path.read_text())
        name = 'otel-invalid-body-undeclared' if fault == 'otel-attribution' else POSITIVE if fault == 'positive-coverage' else NEGATIVE
        row = next(row for row in manifest['vectors'] if row['id'] == name)
        if fault == 'verdict': row['expected'] = 'pass'
        elif fault == 'negative-attribution': row['negates'] = []
        elif fault == 'secondary': row['expected_secondary_ids'] = ['ecl.rule.mcp-result-bound.v1']
        elif fault == 'path': row['path'] = 'conformance/wrong.json'
        elif fault == 'positive-coverage': row['covers'] = []
        elif fault == 'source': row['source']['kind'] = 'mutation'
        else: row['negates'] = ['OE1-004']
        write(path, manifest)
    result = run(root, script, optimized)
    assert result.returncode != 0, result.stdout + result.stderr


@pytest.mark.parametrize('optimized', [False, True])
@pytest.mark.parametrize('fault', ['verdict', 'primary', 'secondary', 'attribution', 'path', 'source'])
def test_schema_generator_checks_the_complete_duplicate_id_oracle(tmp_path, optimized, fault):
    root = tmp_path / 'source'
    script = 'generate_schema_boundary_vectors.py'
    clone(root, [f'scripts/{script}', 'conformance/manifest.json',
                 'conformance/vectors/dcmp-2/valid-decision-request.json',
                 'conformance/suites/document-coverage/register-valid-published-example.json',
                 'tests/fixtures/schema-boundaries.json'])
    assert run(root, script, optimized).returncode == 0
    path = root / 'conformance/manifest.json'
    manifest = json.loads(path.read_text())
    row = next(row for row in manifest['vectors'] if row['id'] == 'ebmp2-invalid-duplicate-object-id')
    if fault == 'verdict': row['expected'] = 'pass'
    elif fault == 'primary': row['expected_primary_id'] = 'ecl.rule.bundle-causal-sequence-monotonic.v1'
    elif fault == 'secondary': row['expected_secondary_ids'] = ['ecl.rule.bundle-causal-sequence-monotonic.v1']
    elif fault == 'attribution': row['negates'] = []
    elif fault == 'path': row['path'] = 'conformance/wrong.json'
    else: row['source']['mutation'] = 'unrelated mutation'
    write(path, manifest, sorted_keys=False)
    result = run(root, script, optimized)
    assert result.returncode != 0, result.stdout + result.stderr
