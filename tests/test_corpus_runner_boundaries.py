"""Malformed inputs and declared replay boundaries must not produce false passes."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest
from jsonschema.exceptions import ValidationError
from referencing import Registry

from ecl_verify.semantic import SemanticValidator
from scripts import run_conformance as runner
from scripts import shared_corpus as shared


def vector(stage, path='input.json', **extra):
    return {'id': 'boundary', 'stage': stage, 'path': path,
            'schema': 'urn:test:object', 'expected': 'pass',
            'expected_secondary_ids': [], **extra}


def observe(root, item, **kwargs):
    return runner.observed_for_vector(
        root, item, schemas={'urn:test:object': {'type': 'object'}},
        schema_registry=Registry(), semantics=SemanticValidator([]), **kwargs)


@pytest.mark.parametrize('stage', ['unknown', 'safe-state', 'documents', ''])
def test_unknown_stage_is_a_usage_error(tmp_path, stage):
    (tmp_path / 'input.json').write_text('{}')
    with pytest.raises(ValueError, match='stage'):
        observe(tmp_path, vector(stage))


@pytest.mark.parametrize('kind', ['leaf', 'parent'])
def test_intraroot_symlink_is_not_a_vector_path(tmp_path, kind):
    actual = tmp_path / 'actual'
    actual.mkdir()
    (actual / 'input.json').write_text('{}')
    if kind == 'leaf':
        (tmp_path / 'input.json').symlink_to(actual / 'input.json')
        relative = 'input.json'
    else:
        (tmp_path / 'link').symlink_to(actual, target_is_directory=True)
        relative = 'link/input.json'
    with pytest.raises(ValueError, match='symlink'):
        observe(tmp_path, vector('strict-json', relative))


def test_direct_caller_cannot_escape_root(tmp_path):
    root = tmp_path / 'root'
    root.mkdir()
    (tmp_path / 'input.json').write_text('{}')
    with pytest.raises(ValueError, match='path'):
        observe(root, vector('strict-json', '../input.json'))


@pytest.mark.parametrize('data,limits,finding', [
    (b'PK', {}, 'ecl.rule.json-strict-syntax.v1'),
    (b'{"a":1,"a":2}', {}, 'ecl.rule.json-no-duplicate-members.v1'),
    (b'{"a":1.5}', {}, 'ecl.rule.json-restricted-numbers.v1'),
    (b'{}', {'max_bytes': 1}, 'ecl.error.resource-limit-exceeded.v1'),
])
def test_malformed_bundle_vector_has_invalid_verdict_without_claimed_scope(
        tmp_path, data, limits, finding):
    (tmp_path / 'input.json').write_bytes(data)
    verdicts, scopes = {}, {}
    result = observe(tmp_path, vector('evidence-bundle', strict_json_limits=limits),
                     verdicts=verdicts, scopes=scopes)
    assert result == [finding]
    assert verdicts == {'boundary': 'invalid'}
    assert scopes == {}


def test_valid_strict_json_control_has_no_bundle_verdict(tmp_path):
    (tmp_path / 'input.json').write_bytes(b'{}')
    verdicts = {}
    assert observe(tmp_path, vector('strict-json'), verdicts=verdicts) == []
    assert verdicts == {}


def test_schema_invalid_manifest_uses_usage_exit(monkeypatch, capsys):
    def invalid(_root):
        raise ValidationError('manifest is invalid')
    monkeypatch.setattr(runner, 'run', invalid)
    monkeypatch.setattr(sys, 'argv', ['run_conformance.py', '--no-write'])
    assert runner.main() == 2
    assert 'manifest is invalid' in capsys.readouterr().err


def test_digest_reader_does_not_load_whole_file(tmp_path, monkeypatch):
    path = tmp_path / 'input.bin'
    path.write_bytes(b'a' * 1025)
    def forbidden(_path):
        raise AssertionError('unbounded read_bytes')
    monkeypatch.setattr(Path, 'read_bytes', forbidden)
    assert runner.sha256_file(path) == hashlib.sha256(b'a' * 1025).hexdigest()


def test_digest_budget_refusal_is_distinct_from_vector_failure(tmp_path, monkeypatch):
    path = tmp_path / 'input.bin'
    path.write_bytes(b'123456789')
    monkeypatch.setattr(runner, 'MAX_REPORT_ARTIFACT_BYTES', 8, raising=False)
    with pytest.raises(ValueError, match='budget'):
        runner.sha256_file(path)


def test_large_json_refusal_binds_entire_input_without_unbounded_read(tmp_path, monkeypatch):
    data = b' ' * (16 * 1024 * 1024) + b'{}'
    path = tmp_path / 'input.json'
    path.write_bytes(data)
    def forbidden(_path):
        raise AssertionError('unbounded read_bytes')
    monkeypatch.setattr(Path, 'read_bytes', forbidden)
    hashes = {}
    assert observe(tmp_path, vector('strict-json', strict_json_limits={
        'max_bytes': 16 * 1024 * 1024}), artifact_hashes=hashes) == [
        'ecl.error.resource-limit-exceeded.v1']
    assert hashes == {'boundary': hashlib.sha256(data).hexdigest()}


def test_result_hash_is_bound_to_consumed_bytes_not_later_file(tmp_path, monkeypatch):
    path = tmp_path / 'input.json'
    original = b'{}'
    path.write_bytes(original)
    parser = runner.loads_json_strict
    def parse_then_replace(data, **limits):
        result = parser(data, **limits)
        path.write_bytes(b'{"changed":true}')
        return result
    monkeypatch.setattr(runner, 'loads_json_strict', parse_then_replace)
    hashes = {}
    assert observe(tmp_path, vector('strict-json'), artifact_hashes=hashes) == []
    assert hashes == {'boundary': hashlib.sha256(original).hexdigest()}
    assert path.read_bytes() != original


def test_stage_gets_only_budget_prefix_while_hash_covers_suffix(tmp_path, monkeypatch):
    data = b'{"member":"' + b'a' * 1024 + b'"}'
    (tmp_path / 'input.json').write_bytes(data)
    parser = runner.loads_json_strict
    received = []
    def record_size(value, **limits):
        received.append(len(value))
        return parser(value, **limits)
    monkeypatch.setattr(runner, 'loads_json_strict', record_size)
    hashes = {}
    assert observe(tmp_path, vector('strict-json', strict_json_limits={'max_bytes': 16}),
                   artifact_hashes=hashes) == ['ecl.error.resource-limit-exceeded.v1']
    assert received == [17]
    assert hashes == {'boundary': hashlib.sha256(data).hexdigest()}


def test_emitted_result_does_not_rehash_replaced_artifact(tmp_path, monkeypatch):
    for directory in ['conformance', 'registries', 'schemas']:
        (tmp_path / directory).mkdir()
    (tmp_path / 'conformance/manifest.json').write_text(json.dumps({
        'suite': 'ordinary', 'vectors': [vector('strict-json')]}))
    (tmp_path / 'registries/extensions.json').write_text('{"entries":[]}')
    (tmp_path / 'schemas/ecl-conformance-result-v2.schema.json').write_text('{"type":"object"}')
    path = tmp_path / 'input.json'
    path.write_bytes(b'{}')
    monkeypatch.setattr(runner, 'validate_manifest_coverage', lambda *args: None)
    monkeypatch.setattr(runner, 'rule_precedence', lambda root: {})
    monkeypatch.setattr(runner, 'registered_errors', lambda root: set())
    monkeypatch.setattr(runner, 'schema_environment', lambda root: ({}, Registry()))
    parser = runner.loads_json_strict
    def parse_then_replace(data, **limits):
        result = parser(data, **limits)
        path.write_bytes(b'{"changed":true}')
        return result
    monkeypatch.setattr(runner, 'loads_json_strict', parse_then_replace)
    result = runner.run(tmp_path)
    assert result['results'][0]['decision'] == 'pass'
    assert result['results'][0]['artifact_sha256'] == hashlib.sha256(b'{}').hexdigest()


def test_file_changed_during_stream_is_a_usage_error(tmp_path, monkeypatch):
    path = tmp_path / 'input.bin'
    path.write_bytes(b'a' * (1024 * 1024 + 4))
    real_open = Path.open
    class ChangingReader:
        def __init__(self, stream):
            self.stream = stream
            self.changed = False
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.stream.close()
        def fileno(self):
            return self.stream.fileno()
        def read(self, size):
            value = self.stream.read(size)
            if value and not self.changed:
                self.changed = True
                with real_open(path, 'ab') as output:
                    output.write(b'changed')
            return value
    def changing_open(p, mode='r', *args, **kwargs):
        stream = real_open(p, mode, *args, **kwargs)
        return ChangingReader(stream) if p == path and mode == 'rb' else stream
    monkeypatch.setattr(Path, 'open', changing_open)
    with pytest.raises(ValueError, match='changed'):
        runner.sha256_file(path)


@pytest.mark.parametrize('finding', [
    'ecl.rule.json-strict-syntax.v1',
    'ecl.rule.json-no-duplicate-members.v1',
    'ecl.rule.json-restricted-numbers.v1',
])
def test_document_parse_refusal_is_not_an_extension_rule(tmp_path, finding):
    item = vector('document', expected='fail', expected_primary_id=finding)
    # Document dispatch remains its own optional stage under profile rule4.
    assert shared.capability_of(tmp_path, 'ordinary', item) == 'document-validation'


def test_document_extension_version_capability_is_intentionally_scoped(tmp_path):
    item = vector('document', expected='fail',
                  expected_primary_id='ecl.rule.extension-single-version.v1')
    assert shared.capability_of(tmp_path, 'ordinary', item) == 'document-extension-rules'
    item['stage'] = 'protocol'
    assert shared.capability_of(tmp_path, 'ordinary', item) == 'extension-version-rule'


@pytest.mark.parametrize('depth,limit,expected', [(270, 512, 'decision-basis-rule'),
                                                (3, 1, 'semantic-rules')])
def test_extension_classification_uses_vector_parse_limits(tmp_path, depth, limit, expected):
    nested = 0
    for _ in range(depth):
        nested = [nested]
    value = {'extensions': [{'id': 'ecl.ext.decision-basis.v1', 'value': nested}]}
    (tmp_path / 'input.json').write_text(json.dumps(value))
    item = vector('protocol', strict_json_limits={
        'max_bytes': 16777216, 'max_depth': limit, 'max_nodes': 1000000})
    assert shared.capability_of(tmp_path, 'ordinary', item) == expected


def minimal_corpus(root):
    (root / 'conformance/suites').mkdir(parents=True)
    (root / 'release').mkdir()
    manifest = {'schema_version': 'ecl_conformance_vector_manifest_v3',
                'suite': 'ordinary', 'vectors': []}
    (root / 'conformance/manifest.json').write_text(json.dumps(manifest))
    (root / 'release/VERSION_SET.json').write_text('{"candidate_version":"test"}')
    return manifest


@pytest.mark.parametrize('target', ['manifest', 'versions'])
def test_corpus_builder_rejects_duplicate_json_members(tmp_path, monkeypatch, target):
    minimal_corpus(tmp_path)
    monkeypatch.setattr(shared, 'unknown_suites', lambda suites: [])
    if target == 'manifest':
        (tmp_path / 'conformance/manifest.json').write_text(
            '{"schema_version":"ecl_conformance_vector_manifest_v3",'
            '"suite":"first","suite":"second","vectors":[]}')
    else:
        (tmp_path / 'release/VERSION_SET.json').write_text(
            '{"candidate_version":"first","candidate_version":"second"}')
    with pytest.raises(ValueError):
        shared.build(tmp_path)


def test_corpus_builder_rejects_duplicate_suite_names(tmp_path, monkeypatch):
    manifest = minimal_corpus(tmp_path)
    child = tmp_path / 'conformance/suites/other'
    child.mkdir()
    (child / 'manifest.json').write_text(json.dumps(manifest))
    monkeypatch.setattr(shared, 'unknown_suites', lambda suites: [])
    with pytest.raises(ValueError, match='duplicate suite'):
        shared.build(tmp_path)


def test_corpus_builder_valid_control(tmp_path, monkeypatch):
    minimal_corpus(tmp_path)
    monkeypatch.setattr(shared, 'unknown_suites', lambda suites: [])
    result = shared.build(tmp_path)
    assert result['candidate_version'] == 'test' and result['vectors'] == []
