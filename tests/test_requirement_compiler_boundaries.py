"""Requirement extraction and declared test availability stay evidence-bound.

Robert F. Tilley Jr.; G-14, Inc.
"""
import copy
import hashlib
import json
from pathlib import Path

import pytest
from scripts import compile_rc3_requirements as compiler

ROOT = Path(__file__).resolve().parents[1]
LOCAL = 'tests.test_local.test_exists'
MISSING = 'tests.missing_module.test_absent'


def put(root, path, value):
    destination = root / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(value) if isinstance(value, (dict, list)) else value)


def miniature(root, *, vectors=False):
    put(root, 'standard/ECL-1_Standard.md', '# Minimal\n\n**AB1-001** — A caller MUST bind its request.\n')
    metadata = json.loads((ROOT / 'registries/requirement-metadata.json').read_text())
    metadata['prefix_profiles'] = {}; metadata['overrides'] = {}
    group = copy.deepcopy(json.loads((ROOT / 'conformance/evaluation-implementation-map.json').read_text())['groups'][0])
    group.update(requirement_ids=['AB1-001'], evaluation_refs=[LOCAL])
    put(root, 'conformance/evaluation-implementation-map.json', {'schema_version': 'ecl_evaluation_implementation_map_v2', 'candidate_version': '1.0', 'groups': [group], 'traceability_refs': {}})
    put(root, str(compiler.MAP_SCHEMA), (ROOT / compiler.MAP_SCHEMA).read_text())
    put(root, 'conformance/manifest.json', {'vectors': [{'id': 'minimal-vector', 'requirement_ids': ['AB1-001'], 'negates': ['AB1-001']}] if vectors else []})
    put(root, 'tests/test_local.py', 'def test_exists(): pass\n')
    put(root, 'tests/test_conformance_harness.py', 'class ConformanceHarnessTests:\n    def test_all_foundation_vectors_produce_expected_result(self): pass\n')
    put(root, str(compiler.INTERNAL_REFS), {'schema_version': 'ecl_requirement_internal_refs_v1', 'candidate_version': '1.0', 'requirements': []})
    put(root, 'registries/requirement-metadata.json', metadata)
    return metadata


@pytest.mark.parametrize('continued', [False, True])
def test_attached_table_rows_are_hashed_in_both_requirement_blocks(tmp_path, continued):
    text = '**AB1-001** — A caller MUST bind its request.\n\n'
    if continued:
        text += '**AB1-001 (continued)** — The following table gives the baseline.\n\n'
    table = '| Level | Bound |\n|---|---|\n| L1 | 24 hours |'
    source = tmp_path / 'profile.md'; source.write_text(text + table + '\n')
    rows, orphans = compiler.extract(source, tmp_path)
    assert not orphans and len(rows) == 1
    assert '\n\n' + table in rows[0]['text']
    before = hashlib.sha256(rows[0]['text'].encode()).hexdigest()
    source.write_text((text + table).replace('24 hours', '999 hours') + '\n')
    changed, _ = compiler.extract(source, tmp_path)
    assert hashlib.sha256(changed[0]['text'].encode()).hexdigest() != before


@pytest.mark.parametrize('sentence', ['A caller MUST reject an untagged condition.', 'A caller must reject an untagged condition.'])
def test_continuation_does_not_absorb_new_untagged_paragraph(tmp_path, sentence):
    source = tmp_path / 'profile.md'
    source.write_text('**AB1-001** — A caller MUST bind.\n\n**AB1-001 (continued)** — It MUST check.\n\n' + sentence + '\n')
    rows, orphans = compiler.extract(source, tmp_path)
    assert sentence not in rows[0]['text']
    assert [row['text'] for row in orphans] == [sentence]


@pytest.mark.parametrize('prefix', ['', '  ', '- ', '1. '])
def test_explicit_continuations_preserve_paragraph_scope(tmp_path, prefix):
    source = tmp_path / 'profile.md'
    source.write_text('**AB1-001** — A caller MUST bind.\n\n' + prefix + '**AB1-001 (continued)** — It MUST check.\n\n' + prefix + '**AB1-001 (continued)** — This explanatory paragraph retains its scope.\n')
    rows, orphans = compiler.extract(source, tmp_path)
    assert not orphans and len(rows) == 1
    assert rows[0]['text'] == 'A caller MUST bind.\n\nIt MUST check.\n\nThis explanatory paragraph retains its scope.'


def test_attached_loose_list_retains_each_item_and_orphan_boundary(tmp_path):
    source = tmp_path / 'profile.md'
    source.write_text('**AB1-001** — A caller MUST check:\n\n- first item;\n\n- second item.\n\nA separate caller MUST stop.\n')
    rows, orphans = compiler.extract(source, tmp_path)
    assert rows[0]['text'] == 'A caller MUST check:\n\n- first item;\n\n- second item.'
    assert [row['text'] for row in orphans] == ['A separate caller MUST stop.']


def test_next_sibling_list_item_is_not_attached(tmp_path):
    source = tmp_path / 'profile.md'
    source.write_text('- **AB1-001** — A caller MUST check:\n\n  - a nested item.\n\n- A second caller MUST stop.\n')
    rows, orphans = compiler.extract(source, tmp_path)
    assert 'a nested item' in rows[0]['text']
    assert [row['text'] for row in orphans] == ['- A second caller MUST stop.']


def test_independent_requirement_rows_are_not_attached_to_prior_text(tmp_path):
    source = tmp_path / 'profile.md'
    source.write_text('**AB1-001** — A caller MUST bind.\n\n| ID | Rule |\n|---|---|\n| AB1-002 | A producer MUST check. |\n')
    rows, orphans = compiler.extract(source, tmp_path)
    assert not orphans
    assert [row['requirement_id'] for row in rows] == ['AB1-001', 'AB1-002']
    assert '| ID |' not in rows[0]['text']


@pytest.mark.parametrize('slot', ['defaults', 'prefix', 'override', 'map', 'trace'])
@pytest.mark.parametrize('public_source', [False, True])
def test_unrecorded_missing_test_reference_fails(tmp_path, slot, public_source):
    metadata = miniature(tmp_path)
    if slot == 'defaults': metadata['defaults']['test_refs'] = [MISSING]
    elif slot == 'prefix': metadata['prefix_profiles']['AB1'] = {'test_refs': [MISSING]}
    elif slot == 'override': metadata['overrides']['AB1-001'] = {'test_refs': [MISSING]}
    else:
        path = tmp_path / 'conformance/evaluation-implementation-map.json'; value = json.loads(path.read_text())
        if slot == 'map': value['groups'][0]['evaluation_refs'] = [MISSING]
        else: value['traceability_refs']['AB1-001'] = [MISSING]
        put(tmp_path, path.relative_to(tmp_path), value)
    put(tmp_path, 'registries/requirement-metadata.json', metadata)
    with pytest.raises(ValueError, match='test refs'):
        compiler.compile_registry(tmp_path, public_source=public_source)


@pytest.mark.parametrize('location', ['same', 'other', 'absent'])
def test_missing_public_reference_requires_its_recorded_requirement(tmp_path, location):
    metadata = miniature(tmp_path); metadata['overrides']['AB1-001'] = {'test_refs': [MISSING]}
    put(tmp_path, 'registries/requirement-metadata.json', metadata)
    sidecar = {'schema_version': 'ecl_requirement_internal_refs_v1', 'candidate_version': '1.0', 'requirements': [{'requirement_id': 'AB1-001' if location == 'same' else 'AB1-002', 'test_refs': [MISSING]}] if location != 'absent' else []}
    put(tmp_path, str(compiler.INTERNAL_REFS), sidecar)
    if location == 'same':
        registry, coverage = compiler.compile_registry(tmp_path, public_source=True)
        assert coverage['decision'] == 'pass'
        assert coverage['unavailable_internal_test_refs'] == [MISSING]
        assert f'conformance:requirement:AB1-001' in registry['requirements'][0]['test_refs']
        with pytest.raises(ValueError, match='test refs'):
            compiler.compile_registry(tmp_path)
    else:
        with pytest.raises(ValueError, match='test refs'):
            compiler.compile_registry(tmp_path, public_source=True)


@pytest.mark.parametrize('field,value', [('evidence_obligations', ['custom obligation']), ('test_refs', [LOCAL])])
def test_override_cannot_clobber_derived_vector_links(tmp_path, field, value):
    metadata = miniature(tmp_path, vectors=True); metadata['overrides']['AB1-001'] = {field: value}
    put(tmp_path, 'registries/requirement-metadata.json', metadata)
    registry, _ = compiler.compile_registry(tmp_path)
    row = registry['requirements'][0]
    assert 'conformance:requirement:AB1-001' in row['test_refs']
    assert 'conformance.vector:minimal-vector' in row['test_refs']
    assert compiler.HARNESS_TEST in row['test_refs']
    assert 'requirement-linked deterministic conformance vector result' in row['evidence_obligations']
    assert set(value) <= set(row[field])


@pytest.mark.parametrize('name', ['test_exists', 'test_package', 'Case.test_package'])
def test_test_reference_resolution_considers_both_directories(tmp_path, name):
    miniature(tmp_path)
    put(tmp_path, 'packages/ecl-verify/tests/test_local.py', 'def test_package(): pass\nclass Case:\n    def test_package(self): pass\n')
    assert compiler.test_reference_exists(tmp_path, 'tests.test_local.' + name)
    assert not compiler.test_reference_exists(tmp_path, 'tests.test_local.not_present')


@pytest.mark.parametrize('presence', ['all', 'partial', 'none'])
def test_reference_class_is_separate_from_local_test_availability(tmp_path, presence):
    miniature(tmp_path)
    path = tmp_path / 'conformance/evaluation-implementation-map.json'; value = json.loads(path.read_text())
    refs = {'all': [LOCAL], 'partial': [LOCAL, MISSING], 'none': [MISSING]}[presence]
    value['groups'][0]['evaluation_refs'] = refs; put(tmp_path, path.relative_to(tmp_path), value)
    put(tmp_path, str(compiler.INTERNAL_REFS), {'schema_version': 'ecl_requirement_internal_refs_v1', 'candidate_version': '1.0', 'requirements': [{'requirement_id': 'AB1-001', 'evaluation_refs': [MISSING]}]})
    _, coverage = compiler.compile_registry(tmp_path, public_source=True)
    assert coverage['evaluation_class_counts']['reference-tested'] == 1
    key = {'all': 'all_present', 'partial': 'partially_present', 'none': 'unavailable_only'}[presence]
    assert coverage['reference_test_availability']['requirement_ids'][key] == ['AB1-001']
    assert sum(coverage['reference_test_availability']['counts'].values()) == 1
    assert 'no implementation test execution' in coverage['evaluation_note']


def test_attached_table_without_blank_line_keeps_rows(tmp_path):
    source = tmp_path / 'profile.md'
    table = '| Level | Bound |\n|---|---|\n| L1 | 24 hours |'
    source.write_text('**AB1-001** — A caller MUST apply the table.\n' + table + '\n')
    rows, orphans = compiler.extract(source, tmp_path)
    assert not orphans and '\n\n' + table in rows[0]['text']


def test_prerelease_proof_gates_remain_part_of_the_compiled_requirement(tmp_path):
    relative = Path("protocols/EBMP-2.md")
    source = (ROOT / relative).read_text()
    target = tmp_path / relative
    target.parent.mkdir(parents=True)
    target.write_text(source)
    rows, _ = compiler.extract(target, tmp_path)
    text = next(row["text"] for row in rows if row["requirement_id"] == "EBMP2-070")
    for phrase in (
        "These checks belong to stage 8 of EBMP2-068",
        "An entry with defect 1 is not checked further.",
        "Checks 5, 6, and 8 apply only to a proof carried in the bundle.",
        "prevents checks 5 and 8",
        "`issuer-not-named` (EBMP2-076)",
        "its report says so (EBMP2-076).",
    ):
        assert phrase in text
    assert "The `observed_at` of an `execution_released` event MUST be" not in text
    old_digest = hashlib.sha256(text.encode()).hexdigest()
    # This condition changes without introducing a MUST token; it must still change
    # the owning requirement's content digest.
    changed = source.replace("An entry\nwith defect 1 is not checked further.",
                             "An entry\nwith defect 1 is checked further.", 1)
    assert changed != source
    target.write_text(changed)
    rows, _ = compiler.extract(target, tmp_path)
    amended = next(row["text"] for row in rows if row["requirement_id"] == "EBMP2-070")
    assert hashlib.sha256(amended.encode()).hexdigest() != old_digest


# Conditions that were once outside their owning compiled requirement text.
OWNED_PROSE_MUTATIONS = [('approval-purpose-alone',
  'profiles/TRUST-POLICY-1.md',
  'TP1-003',
  'refuses a trust policy in which a key holds it alone.',
  'accepts a trust policy in which a key holds it alone.'),
 ('export-key-identifier-reuse',
  'profiles/OTEL-EVIDENCE-EXPORT-1.md',
  'OE1-010',
  'identifier that no earlier export key of the deployment has used',
  'identifier that an earlier export key of the deployment has used'),
 ('human-approval-threshold',
  'standard/ECL-1_Standard.md',
  'ECL1N-0177',
  'the two compared as exact decimals',
  'the two compared as approximate decimals'),
 ('execution-transition-table',
  'protocols/EBMP-2.md',
  'EBMP2-065',
  '| `prepared` | `released`, `cancelled`, `timed_out`, `denied`, `held`, `challenged`, '
  '`expired_before_release` |',
  '| `prepared` | `released`, `cancelled`, `timed_out`, `denied`, `held`, '
  '`expired_before_release` |'),
 ('duplicate-value-traversal',
  'protocols/INTEGRITY-ENVELOPE-1.md',
  'IE1-037',
  'including each value of a repeated\nmember name',
  'excluding each value of a repeated\nmember name'),
 ('syntax-limit-precedence',
  'protocols/INTEGRITY-ENVELOPE-1.md',
  'IE1-037',
  'Every consumer completes check 2 on an input nested no deeper than\n10,000 levels',
  'Every consumer completes check 2 on an input nested no deeper than\n1,000 levels'),
 ('empty-eligible-list',
  'protocols/INTEGRITY-ENVELOPE-1.md',
  'IE1-013',
  'An empty list of eligible keys\nleaves the eligible keys unbounded',
  'An empty list of eligible keys\nleaves the eligible keys bounded'),
 ('oversized-threshold-scope',
  'protocols/INTEGRITY-ENVELOPE-1.md',
  'IE1-013',
  'is not an IE1-013 consistency failure',
  'is an IE1-013 consistency failure'),
 ('acs-chain-hash-domain',
  'profiles/ACS-BINDING-1.md',
  'AC1-008',
  'followed by the 32 bytes that',
  'followed by the 16 bytes that')]

@pytest.mark.parametrize("case,relative,identifier,old,new", OWNED_PROSE_MUTATIONS, ids=[row[0] for row in OWNED_PROSE_MUTATIONS])
def test_controlling_prose_mutation_changes_owning_requirement(tmp_path, case, relative, identifier, old, new):
    source = (ROOT / relative).read_text()
    assert source.count(old) == 1
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source)
    before, orphans = compiler.extract(target, tmp_path)
    assert not orphans
    prior = {row["requirement_id"]: row["text"] for row in before}
    target.write_text(source.replace(old, new, 1))
    after, orphans = compiler.extract(target, tmp_path)
    assert not orphans
    amended = {row["requirement_id"]: row["text"] for row in after}
    assert prior.keys() == amended.keys()
    assert hashlib.sha256(prior[identifier].encode()).hexdigest() != hashlib.sha256(amended[identifier].encode()).hexdigest()
    assert {key for key in prior if prior[key] != amended[key]} == {identifier}
    if identifier == "EBMP2-065":
        assert "| `prepared` |" in prior[identifier]
        assert "| `prepared` |" not in prior["EBMP2-011"]
