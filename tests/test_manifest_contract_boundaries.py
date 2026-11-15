"""Manifest preflight and schema-derived producer types, without executing the corpus."""
from pathlib import Path
import json
import sys

import pytest
from referencing import Registry

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'packages/ecl-verify/src')]
from scripts.run_conformance import manifest_paths, validate_manifest_coverage
from scripts.generate_sdk_sources import TypeWriter
from ecl_verify.schema_patterns import schema_validator
from ecl_verify.schema import ecl_format_checker

def manifest():
    return next(json.loads(p.read_text()) for p in manifest_paths(ROOT)
                if any(v['stage'] == 'evidence-bundle' for v in json.loads(p.read_text())['vectors']))

def validator():
    schema = json.loads((ROOT / 'schemas/ecl-conformance-vector-manifest-v3.schema.json').read_text())
    return schema_validator(schema, registry=Registry(), format_checker=ecl_format_checker())

@pytest.mark.parametrize('timestamp', ['2026-02-30T00:00:00Z', '2026-10-01T24:00:00Z'])
def test_manifest_rejects_nonexistent_evaluation_time(timestamp):
    value = manifest()
    next(v for v in value['vectors'] if v['stage'] == 'evidence-bundle')['evaluated_at'] = timestamp
    assert not validator().is_valid(value)

@pytest.mark.parametrize('timestamp', ['2024-02-29T00:00:00Z', '2026-10-01T23:59:59.999Z',
                                      '2026-10-01T00:00:00.123456Z'])
def test_manifest_keeps_supported_utc_precision(timestamp):
    value = manifest()
    next(v for v in value['vectors'] if v['stage'] == 'evidence-bundle')['evaluated_at'] = timestamp
    assert validator().is_valid(value)

def test_scope_check_map_uses_registered_scope_names():
    value = next(json.loads(p.read_text()) for p in manifest_paths(ROOT)
                 if any('expected_scope' in v for v in json.loads(p.read_text())['vectors']))
    scope = next(v['expected_scope'] for v in value['vectors'] if 'expected_scope' in v)
    scope.setdefault('checks', {})['not-a-scope-item'] = {'checks': [], 'objects': []}
    assert not validator().is_valid(value)
    del scope['checks']['not-a-scope-item']
    assert validator().is_valid(value)

def test_register_path_is_confined_during_manifest_preflight():
    values = [json.loads(p.read_text()) for p in manifest_paths(ROOT)]
    validate_manifest_coverage(ROOT, values)
    vector = next(v for m in values for v in m['vectors'] if v['stage'] == 'evidence-bundle')
    vector['register_path'] = 'conformance/suites/../../outside.json'
    with pytest.raises(ValueError, match='unsafe vector path'):
        validate_manifest_coverage(ROOT, values)

def test_typed_map_generation_preserves_member_schema():
    documents = {value['$id']: (str(path), value) for path in (ROOT / 'schemas').glob('*.json')
                 if '$id' in (value := json.loads(path.read_text()))}
    writer = TypeWriter(documents)
    base = 'https://externalcontrollayer.ai/ns/schema/ebmp/2'
    frontiers = documents[base][1]['$defs']['stateEvent']['properties']['frontiers']
    assert writer.expression(frontiers, base, '') == '{ [member: string]: CommonNonNegativeSafeInteger }'
    assert writer.expression({'type': 'object', 'additionalProperties': {'type': 'string'}}, base, '') == '{ [member: string]: string }'
    assert writer.expression({'type': 'object'}, base, '') == '{ [member: string]: JsonValue }'
