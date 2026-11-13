"""Schema-derived producer shapes and deterministic exported names."""
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.generate_sdk_sources import GenerationError, NS, TypeWriter, selected_schemas


def expression(schema):
    return TypeWriter({}).expression(schema, NS + 'common/1', '')


def test_closed_empty_object_does_not_become_an_open_json_map():
    assert expression({'type': 'object', 'additionalProperties': False}) == 'Record<string, never>'
    assert expression({'type': 'object', 'properties': {}, 'additionalProperties': False}) == 'Record<string, never>'


def test_open_named_properties_keep_json_additional_members():
    result = expression({'type': 'object', 'properties': {'name': {'type': 'string'}}})
    assert '"name"?: string;' in result
    assert result.endswith(' & { [member: string]: JsonValue }')
    assert 'undefined' not in result


def test_typed_additional_members_do_not_make_named_members_impossible():
    result = expression({'type': 'object', 'properties': {'id': {'type': 'number'}},
                         'required': ['id'], 'additionalProperties': {'type': 'string'}})
    assert '"id": number;' in result
    assert result.endswith(' & { [member: string]: string | number }')


def test_closed_named_object_keeps_excess_literal_check():
    result = expression({'type': 'object', 'properties': {'id': {'type': 'string'}},
                         'required': ['id'], 'additionalProperties': False})
    assert result == '{\n  "id": string;\n}'


def test_pattern_values_are_conservative_without_forbidding_every_key():
    schema = {'type': 'object', 'patternProperties': {'^allowed$': {'type': 'number'}},
              'additionalProperties': False}
    assert expression(schema) == '{ [member: string]: number }'
    # This is intentionally a value approximation, not a claim to type-check the regex domain.


@pytest.mark.parametrize('schema', [{'additionalProperties': False},
                                  {'patternProperties': {'^allowed$': {'type': 'number'}}}])
def test_object_applicators_alone_do_not_imply_an_object_type(schema):
    assert expression(schema) == 'JsonValue'


@pytest.mark.parametrize('documents', [
    {NS + 'probe/1': ('probe.json', {'$defs': {'foo-bar': True, 'fooBar': True}})},
    {NS + 'foo-bar/1': ('one.json', {}), NS + 'fooBar/1': ('two.json', {})},
    {NS + 'extension/probe/1': ('probe.json', {'$defs': {'value': True}})},
    {NS + 'json-value/1': ('probe.json', {})},
])
def test_duplicate_export_names_are_refused_before_source_emission(documents):
    with pytest.raises(GenerationError, match='duplicate TypeScript type name'):
        TypeWriter(documents).declarations()


def test_current_schema_export_names_remain_distinct():
    lines = TypeWriter(selected_schemas(ROOT)).declarations()
    names = [line.split(' = ', 1)[0] for line in lines if line.startswith('export type ')]
    assert len(names) == len(set(names))
    assert len(names) > 100
