"""Corpus regeneration checks independent metadata and retained input bytes.

Robert F. Tilley Jr.; G-14, Inc.
"""
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
MCP = 'conformance/suites/mcp-gateway'
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=os.pathsep.join([
    str(ROOT / 'packages/ecl-verify/src'), str(ROOT / 'scripts'), str(ROOT)]))
SCRIPTS = ('generate_mcp_public_review_migration.py', 'generate_otel_schema_witness.py',
           'generate_single_use_policy_vectors.py', 'generate_repair_coverage_vectors.py',
           'generate_mcp_retained_evidence_regressions.py')


def invoke(root, script, *, optimized=False, write=False, baseline=None):
    args = [sys.executable, *(['-O'] if optimized else []), str(root / 'scripts' / script)]
    if script == SCRIPTS[0]:
        args += ['--report', str(root / 'migration-report.json')]
        if baseline is not None:
            args += ['--baseline-dir', str(baseline)]
        args += ['--write' if write else '--check']
    elif not write:
        args += ['--check']
    return subprocess.run(args, cwd=root, env=ENV, capture_output=True, text=True)


@pytest.fixture(scope='module')
def workspace(tmp_path_factory):
    root = tmp_path_factory.mktemp('generator-oracles')
    paths = ['scripts', 'schemas', 'registries', 'conformance/vectors/dcmp-2',
             *['conformance/suites/' + name for name in ('mcp-gateway', 'otel-export',
               'oauth-authority', 'single-use-policy', 'schema-coverage')],
             *['tests/fixtures/' + name for name in ('mcp-record-consistency',
               'mcp-retained-evidence-regressions', 'mcp-public-review-repairs',
               'mcp-release-progress-regressions')]]
    for relative in paths:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(ROOT / relative, target, ignore=shutil.ignore_patterns('__pycache__'))
    for script in (SCRIPTS[0], SCRIPTS[1], SCRIPTS[2], SCRIPTS[4]):
        result = invoke(root, script)
        assert result.returncode == 0, result.stdout + result.stderr
    return root


@contextmanager
def changed_json(path, change):
    original = path.read_bytes()
    value = json.loads(original)
    change(value)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    try:
        yield
    finally:
        path.write_bytes(original)


@pytest.mark.parametrize('script', SCRIPTS)
@pytest.mark.parametrize('optimized', [False, True])
def test_current_outputs_match_fixed_oracles(script, optimized, tmp_path):
    # Reports go outside the source; the check modes must not rewrite inputs.
    if script == SCRIPTS[0]:
        result = subprocess.run([sys.executable, *(['-O'] if optimized else []),
            str(ROOT / 'scripts' / script), '--check', '--report', str(tmp_path / 'report.json')],
            cwd=ROOT, env=ENV, capture_output=True, text=True)
    else:
        result = invoke(ROOT, script, optimized=optimized)
    assert result.returncode == 0, result.stdout + result.stderr


ORACLES = [
    (SCRIPTS[0], MCP + '/manifest.json', 'mcp-valid-forwarded-release-order', 'pass'),
    (SCRIPTS[1], 'conformance/suites/otel-export/manifest.json', 'otel-invalid-object-not-ecl', 'fail'),
    (SCRIPTS[2], 'conformance/suites/schema-coverage/manifest.json', 'dcmp-valid-request-single-use-explicit-one', 'pass'),
    (SCRIPTS[2], 'conformance/suites/schema-coverage/manifest.json', 'dcmp-invalid-admit-use-policy-outside-enum', 'fail'),
    (SCRIPTS[2], 'conformance/suites/oauth-authority/manifest.json', 'oauth-invalid-entry-max-uses-boolean', 'fail'),
]


@pytest.mark.parametrize('script,relative,identifier,verdict', ORACLES)
@pytest.mark.parametrize('fault', ['verdict', 'stage', 'path', 'attribution', 'secondary', 'provenance'])
def test_output_metadata_cannot_seed_its_own_oracle(workspace, script, relative, identifier, verdict, fault):
    def change(manifest):
        row = next(row for row in manifest['vectors'] if row['id'] == identifier)
        if fault == 'verdict': row['expected'] = 'fail' if verdict == 'pass' else 'pass'
        elif fault == 'stage': row['stage'] = 'strict-json'
        elif fault == 'path': row['path'] = 'conformance/wrong.json'
        elif fault == 'attribution': row['negates' if verdict == 'fail' else 'covers'] = ['unreviewed-attribution']
        elif fault == 'secondary': row['expected_secondary_ids'].append('ecl.rule.mcp-result-bound.v1')
        else: row['source']['generator'] = 'scripts/unrelated.py'
    with changed_json(workspace / relative, change):
        result = invoke(workspace, script, optimized=True)
        assert result.returncode != 0, result.stdout + result.stderr


@pytest.mark.parametrize('fault', ['file', 'hash', 'schema-validity', 'payload-and-hash'])
def test_retained_control_is_bound_to_fixed_path_bytes_and_metadata(workspace, fault):
    manifest = workspace / 'tests/fixtures/mcp-record-consistency/manifest.json'
    payload = manifest.parent / 'clock-intrinsic-proof-failure-control.json'
    original = payload.read_bytes()
    def change(value):
        row = next(row for row in value['cases'] if row['id'] == 'clock-intrinsic-proof-failure-control')
        if fault == 'file': row['file'] = '../mcp-public-review-repairs/forward-complete-control.json'
        elif fault == 'hash': row['sha256'] = '0' * 64
        elif fault == 'schema-validity': row['schema_valid'] = False
        else:
            payload.write_bytes(original + b' ')
            row['sha256'] = hashlib.sha256(payload.read_bytes()).hexdigest()
    try:
        with changed_json(manifest, change):
            result = invoke(workspace, SCRIPTS[4], optimized=True)
            assert result.returncode != 0, result.stdout + result.stderr
    finally:
        payload.write_bytes(original)


@pytest.mark.parametrize('script,relative,identifier,_', ORACLES[1:])
def test_targeted_oracle_repair_preserves_other_rows(workspace, script, relative, identifier, _):
    path = workspace / relative
    original = path.read_bytes()
    manifest = json.loads(original)
    other = next(row for row in manifest['vectors'] if row['id'] != identifier and
                 row.get('source', {}).get('generator') not in (SCRIPTS[2], 'scripts/' + SCRIPTS[2]))
    other_id = other['id']
    other['source']['mutation'] = 'Unrelated retained explanation.'
    def change(value):
        value.clear(); value.update(copy.deepcopy(manifest))
        next(row for row in value['vectors'] if row['id'] == identifier)['expected'] = 'unreviewed'
    with changed_json(path, change):
        result = invoke(workspace, script, write=True)
        assert result.returncode == 0, result.stdout + result.stderr
        after = json.loads(path.read_bytes())
        assert next(row for row in after['vectors'] if row['id'] == other_id) == other
        assert next(row for row in after['vectors'] if row['id'] == identifier)['expected'] in ('pass', 'fail')


def test_migration_writes_an_unmigrated_suite_manifest_and_rechecks(workspace, tmp_path):
    suite = workspace / MCP
    original = {path.name: path.read_bytes() for path in suite.glob('*.json')}
    baseline = tmp_path / 'baseline'; baseline.mkdir()
    archive = workspace / 'scripts/fixtures/mcp-reconstruction-baseline.zip'
    try:
        for path in suite.glob('*.json'): path.unlink()
        with zipfile.ZipFile(archive) as retained:
            for name in retained.namelist():
                content = retained.read(name)
                (baseline / name).write_bytes(content)
                (suite / name).write_bytes(content)
        baseline_before = {path.name: path.read_bytes() for path in baseline.iterdir()}
        result = invoke(workspace, SCRIPTS[0], write=True, baseline=baseline)
        assert result.returncode == 0, result.stdout + result.stderr
        assert {path.name: path.read_bytes() for path in baseline.iterdir()} == baseline_before
        assert {path.name: path.read_bytes() for path in suite.glob('*.json')} == original
        assert invoke(workspace, SCRIPTS[0], baseline=baseline).returncode == 0
    finally:
        for path in suite.glob('*.json'): path.unlink()
        for name, content in original.items(): (suite / name).write_bytes(content)


@pytest.mark.parametrize('fault', ['missing', 'empty', 'changed', 'omitted', 'additional'])
def test_migration_refuses_unpinned_input_without_seeding(workspace, tmp_path, fault):
    baseline = tmp_path / 'baseline'
    if fault != 'missing': baseline.mkdir()
    if fault not in ('missing', 'empty'):
        with zipfile.ZipFile(workspace / 'scripts/fixtures/mcp-reconstruction-baseline.zip') as retained:
            for name in retained.namelist(): (baseline / name).write_bytes(retained.read(name))
        first = next(path for path in sorted(baseline.iterdir()) if path.name != 'manifest.json')
        if fault == 'changed': first.write_bytes(first.read_bytes() + b' ')
        elif fault == 'omitted': first.unlink()
        else: (baseline / 'additional.json').write_text('{}')
    before = {path.name: path.read_bytes() for path in baseline.glob('*')} if baseline.exists() else None
    result = invoke(workspace, SCRIPTS[0], write=True, baseline=baseline)
    assert result.returncode != 0, result.stdout + result.stderr
    after = {path.name: path.read_bytes() for path in baseline.glob('*')} if baseline.exists() else None
    assert after == before


def test_single_use_negative_payload_is_reconstructed_not_reused(workspace):
    path = workspace / 'conformance/suites/schema-coverage/dcmp-invalid-request-use-policy-outside-enum.json'
    with changed_json(path, lambda value: value['authority_request'].update(use_policy='single_use')):
        result = invoke(workspace, SCRIPTS[2], optimized=True)
        assert result.returncode != 0, result.stdout + result.stderr


def test_mcp_release_witnesses_use_binding_stage_and_decisive_schema_units():
    from scripts import coverage_denominator as coverage, shared_corpus
    from ecl_verify.bindings import mcp
    manifest = json.loads((ROOT / 'conformance/suites/repair-coverage/manifest.json').read_bytes())
    units = {row['id']: row for row in coverage.enumerate_units(ROOT, coverage.read(ROOT / coverage.DENOMINATOR))}
    attribution = coverage.attribution_for(ROOT)
    rows = [row for row in manifest['vectors'] if row['id'].startswith('repair-coverage-mcp-release-journal-')]
    assert len(rows) == 3
    for row in rows:
        value = coverage.read(ROOT / row['path'])
        assert row['stage'] == 'binding'
        assert shared_corpus.capability_of(ROOT, manifest['suite'], row) == 'binding-profile-rules'
        assert all(attribution.witnesses(units[unit], row, value) for unit in row['covers'])
        if row['expected'] == 'pass':
            assert attribution.valid(row['schema'], value)
            assert mcp.check(value) == []
        else:
            assert not attribution.valid(row['schema'], value)
            assert row['expected_primary_id'] == 'ecl.error.schema-invalid.v1'


def test_retained_archive_inventory_matches_exact_members():
    inventory = json.loads((ROOT / 'scripts/fixtures/mcp-reconstruction-baseline.json').read_bytes())
    path = ROOT / 'scripts/fixtures' / inventory['archive']['path']
    assert hashlib.sha256(path.read_bytes()).hexdigest() == inventory['archive']['sha256']
    assert path.stat().st_size == inventory['archive']['bytes']
    expected = {row['path']: row for row in inventory['members']}
    assert len(expected) == len(inventory['members']) == 140
    with zipfile.ZipFile(path) as archive:
        assert set(archive.namelist()) == expected.keys()
        for name, row in expected.items():
            raw = archive.read(name)
            assert len(raw) == row['bytes']
            assert hashlib.sha256(raw).hexdigest() == row['sha256']
            assert archive.getinfo(name).external_attr >> 16 == 0o100644
        assert len(json.loads(archive.read('manifest.json'))['vectors']) == 139


def test_changed_bundled_baseline_is_refused(workspace):
    path = workspace / 'scripts/fixtures/mcp-reconstruction-baseline.zip'
    original = path.read_bytes()
    try:
        path.write_bytes(original + b' ')
        result = invoke(workspace, SCRIPTS[0], optimized=True)
        assert result.returncode != 0
        assert 'does not match its pin' in result.stderr
    finally:
        path.write_bytes(original)
