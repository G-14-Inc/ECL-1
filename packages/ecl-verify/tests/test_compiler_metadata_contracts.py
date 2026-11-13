"""Invalid generated metadata is rejected before any public artifact is written."""
import copy
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]


def compiler(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def registry_value():
    value = json.loads((ROOT / 'registries/error-codes.json').read_text())
    value['entries'] = value['entries'][:1]
    return value


@pytest.mark.parametrize('uri,valid', [
    ('not a URI', False), ('https://example.invalid/%ZZ', False),
    ('urn:example:registry', True), ('https://example.invalid/registry', True),
])
def test_registry_compiler_asserts_ecl_uri_format(tmp_path, uri, valid):
    mod = compiler('compile_rc3_registries')
    (tmp_path / 'schemas').mkdir()
    (tmp_path / mod.REGISTRY_SCHEMA).write_bytes((ROOT / mod.REGISTRY_SCHEMA).read_bytes())
    value = registry_value(); value['registry_id'] = uri
    if valid:
        mod.validate_registries(tmp_path, [(tmp_path / 'registries/test.json', value)])
    else:
        with pytest.raises(Exception) as caught:
            mod.validate_registries(tmp_path, [(tmp_path / 'registries/test.json', value)])
        assert isinstance(caught.value, (ValueError, __import__('jsonschema').ValidationError))


def test_registry_catalog_retains_supersession_identity():
    mod = compiler('compile_rc3_registries')
    value = registry_value(); row = value['entries'][0]
    row.update(status='superseded', superseded_by='ecl.example.successor.v1')
    catalog = mod.compile_catalog([(ROOT / 'registries/test.json', value)], ROOT)
    assert catalog['entries'][0].get('superseded_by') == row['superseded_by']
    assert catalog['entries'][0]['attributes']['entry_sha256'] == mod.digest_json(row)


@pytest.mark.parametrize('field,bad', [
    ('procedure', []), ('procedure', ['']), ('procedure', 'do something'),
    ('pass_criteria', []), ('pass_criteria', [False]), ('fail_criteria', []),
    ('fail_criteria', ['']),
])
def test_invalid_procedure_override_never_written(monkeypatch, field, bad):
    mod = compiler('compile_rc3_requirements')
    registry = mod.read_json(ROOT / 'registries/requirements-compiled.json')
    coverage = mod.read_json(ROOT / 'release/requirement-coverage.json')
    original = mod.read_json
    def read(path):
        if path == ROOT / 'conformance/evaluation-procedure-overrides.json':
            value = copy.deepcopy(original(path))
            value['requirements'].setdefault(registry['requirements'][0]['requirement_id'], {})[field] = bad
            return value
        return original(path)
    monkeypatch.setattr(mod, 'read_json', read)
    monkeypatch.setattr(mod, 'compile_registry', lambda *a, **kw: (registry, coverage))
    writes = []
    monkeypatch.setattr(mod, 'write_json', lambda *args: writes.append(args))
    monkeypatch.setattr(sys, 'argv', ['compile_rc3_requirements.py', '--root', str(ROOT)])
    assert mod.main() == 2
    assert writes == []


@pytest.mark.parametrize('mutation', ['duplicate', 'missing', 'hash', 'overlap', 'empty'])
def test_generated_catalog_identity_contract(monkeypatch, mutation):
    mod = compiler('compile_rc3_requirements')
    registry = mod.read_json(ROOT / 'registries/requirements-compiled.json')
    coverage = mod.read_json(ROOT / 'release/requirement-coverage.json')
    catalog = mod.read_json(ROOT / 'conformance/requirement-evaluations.json')
    if mutation == 'duplicate': catalog['entries'].append(copy.deepcopy(catalog['entries'][0]))
    elif mutation == 'missing': catalog['entries'].pop()
    elif mutation == 'hash': catalog['entries'][0]['requirement_text_sha256'] = '0' * 64
    elif mutation == 'overlap':
        row = next(row for row in catalog['entries'] if row['evaluation_refs'])
        row['traceability_refs'].append(row['evaluation_refs'][0])
    elif mutation == 'empty': catalog['entries'] = []
    monkeypatch.setattr(mod, 'compile_registry', lambda *a, **kw: (registry, coverage))
    monkeypatch.setattr(mod, 'build_evaluation_catalog', lambda *a: catalog)
    writes = []
    monkeypatch.setattr(mod, 'write_json', lambda *args: writes.append(args))
    monkeypatch.setattr(sys, 'argv', ['compile_rc3_requirements.py', '--root', str(ROOT)])
    assert mod.main() == 2
    assert writes == []


def test_all_existing_evaluation_classes_and_methods_remain_valid(monkeypatch):
    mod = compiler('compile_rc3_requirements')
    registry = mod.read_json(ROOT / 'registries/requirements-compiled.json')
    coverage = mod.read_json(ROOT / 'release/requirement-coverage.json')
    catalog = mod.read_json(ROOT / 'conformance/requirement-evaluations.json')
    assert len(registry['requirements']) == len(catalog['entries']) > 0
    monkeypatch.setattr(mod, 'compile_registry', lambda *a, **kw: (registry, coverage))
    monkeypatch.setattr(mod, 'build_evaluation_catalog', lambda *a: catalog)
    writes = []
    monkeypatch.setattr(mod, 'write_json', lambda *args: writes.append(args))
    monkeypatch.setattr(sys, 'argv', ['compile_rc3_requirements.py', '--root', str(ROOT)])
    assert mod.main() == (0 if coverage["decision"] == "pass" else 1)
    assert len(writes) == 4


@pytest.mark.parametrize('kind,surfaces,valid', [
    ('direct_runtime_support', (), False),
    ('supporting_evidence_only', (), False),
    ('out_of_scope', (), True),
    ('direct_runtime_support', ('FR-101',), True),
    ('supporting_evidence_only', ('FR-101',), True),
])
def test_mapping_helper_cites_support(kind, surfaces, valid):
    from ecl_verify.claims import MappingPacket, ClaimError
    packet = MappingPacket('urn:example:packet', '1', 'Example', '2026',
        {'clause': kind}, {'clause': surfaces}, {'clause': 'Residual duties remain.'},
        ('The declared boundary applies.',), 'draft', '2026-11-11T00:00:00Z')
    if valid: packet.validate()
    else:
        with pytest.raises(ClaimError): packet.validate()
