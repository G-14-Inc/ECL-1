"""Evidence-kind counts, source linkage and record provenance in the gap annex.

Robert F. Tilley Jr.; G-14, Inc.
"""
import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tools"), str(ROOT)]
import gap_coverage as gap


@pytest.fixture
def source(tmp_path):
    for rel in ("registries/gap-coverage.json", "registries/requirements-compiled.json", "registries/semantic-rules.json", "standard/ECL-1_Standard.md", "release/BUILD_DESCRIPTOR.json", "conformance/suites/evidence-bundle/manifest.json", "conformance/suites/key-roles/manifest.json"):
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, target)
    (tmp_path / "docs").mkdir()
    return tmp_path


def test_unrelated_active_rule_does_not_count_as_core_check(source):
    value = gap.read_data(source)
    value["gaps"][2]["machine_checks"] = ["ecl.rule.aarm-outcome-no-weaker.v1"]
    with pytest.raises(gap.GapCoverageError, match="does not cite a listed core requirement"):
        gap.validate(source, value)


def test_matching_core_rule_keeps_its_specific_requirement_linkage(source):
    value = gap.read_data(source)
    row = next(row for row in value["gaps"] if row["id"] == "G5")
    assert row["machine_checks"] == ["ecl.rule.coupling-results-permit-admit.v1"]
    gap.validate(source, value)
    row["requirements"].remove("DCMP2-052")
    with pytest.raises(gap.GapCoverageError, match="does not cite a listed core requirement"):
        gap.validate(source, value)


def test_summary_separates_rules_suites_vectors_and_profile_rules(source):
    text = gap.render(source)
    assert "Core rules | Core suites (vectors) | Profile rules |" in text
    assert "unique" in text and "29 record entries" in text
    assert "not test results or conformance percentages" in text
    assert "can occur in more than one gap" in text
    assert "source-file digest" in text and "not rechecked" in text


def test_bracket_and_backslash_titles_remain_one_literal_link_label(source):
    value = gap.read_data(source)
    value["record"]["entries"]["1"] = r"Knight ](https://example.invalid/injected) [Capital] \\ test"
    (source / gap.DATA).write_text(json.dumps(value))
    text = gap.render(source)
    assert r"Knight \](https://example.invalid/injected) \[Capital\] \\\\ test" in text
    assert "[Record 1: Knight ](" not in text


@pytest.mark.parametrize("scalar,expected", [
    ("Plain title, 2026", "Plain title, 2026"),
    ("'NEDA''s [Tessa], 2023'", "NEDA's [Tessa], 2023"),
    (json.dumps('A "quoted" title'), 'A "quoted" title'),
])
def test_fixed_layout_record_decodes_single_and_double_quoted_titles(tmp_path, scalar, expected):
    path = tmp_path / "record.yml"
    path.write_text(f"- n: 1\n  short: {scalar}\n  codes:\n    - code: G2\n")
    entries, coded = gap.record_codes(path)
    assert entries == {"1": expected}
    assert coded == {"G2": [1]}


@pytest.mark.parametrize("content", [
    "- n: 1\n  short: 'unterminated\n  codes:\n    - code: G2\n",
    '- n: 1\n  short: "unterminated\n  codes:\n    - code: G2\n',
    "- n: 1\n  short: First\n- n: 1\n  short: Duplicate\n",
    "- n: 1\n  short: First\n  codes:\n    - code: G14\n",
])
def test_record_refresh_rejects_ambiguous_or_out_of_classification_input(tmp_path, content):
    path = tmp_path / "record.yml"
    path.write_text(content)
    with pytest.raises(gap.GapCoverageError):
        gap.record_codes(path)


def test_refresh_parses_and_hashes_one_read_of_the_same_bytes(source):
    first = b"- n: 1\n  short: 'NEDA''s [Tessa], 2023'\n  codes:\n    - code: G2\n"
    second = b"- n: 2\n  short: Other title\n  codes:\n    - code: G1\n"
    class Record:
        calls = 0
        def read_text(self, **kwargs):
            self.calls += 1
            return first.decode()
        def read_bytes(self):
            self.calls += 1
            return first if self.calls == 1 else second
    path = Record()
    gap.refresh_record(source, path)
    result = gap.read_data(source)
    assert path.calls == 1
    assert result["record"]["entries"] == {"1": "NEDA's [Tessa], 2023"}
    assert result["record"]["sha256"] == hashlib.sha256(first).hexdigest()


def test_invalid_refresh_does_not_write_data_or_derived_doc(source, tmp_path):
    path = tmp_path / "bad.yml"
    path.write_text("- n: 1\n  short: 'unterminated\n")
    before = (source / gap.DATA).read_bytes()
    assert gap.main(["--root", str(source), "--write", "--record", str(path)]) == 1
    assert (source / gap.DATA).read_bytes() == before
    assert not (source / gap.OUTPUT).exists()


@pytest.mark.parametrize("digest", ["", "not-a-digest", "F" * 64, 10**63])
def test_external_provenance_hash_has_a_sha256_shape(source, digest):
    value = gap.read_data(source)
    value["record"]["sha256"] = digest
    with pytest.raises(gap.GapCoverageError, match="record source-file digest"):
        gap.validate(source, value)


def test_well_formed_external_hash_is_not_claimed_to_be_reverified(source):
    value = gap.read_data(source)
    value["record"]["sha256"] = "a" * 64
    gap.validate(source, value)


def test_current_gap_scope_preserves_level_and_boundary_qualifications(source):
    value = gap.read_data(source)
    rows = {row["id"]: row for row in value["gaps"]}
    assert "ECL1N-0156" in rows["G2"]["requirements"]
    assert "At every level, ECL1N-0156" in rows["G2"]["open"]
    assert "general plaintext-secret prohibition start at L2" in rows["G2"]["open"]
    assert "full-system mediation claim must include and mediate every reachable consequential action path" in rows["G4"]["open"]
    assert "that check does not show that the authority was still valid when the effect occurred" in rows["G4"]["open"]


@pytest.mark.parametrize("key", ["requirements", "profile_requirements", "checklist", "machine_checks", "record_entries"])
def test_per_gap_duplicates_cannot_inflate_association_counts(source, key):
    value = gap.read_data(source)
    row = value["gaps"][0]
    row[key].append(row[key][0])
    with pytest.raises(gap.GapCoverageError, match="repeats an entry"):
        gap.validate(source, value)


@pytest.mark.parametrize("scalar,expected", [
    ("'> Literal title'", "> Literal title"),
    (json.dumps('[A] title: with # punctuation'), '[A] title: with # punctuation'),
])
def test_quoted_yaml_control_punctuation_is_literal(tmp_path, scalar, expected):
    path = tmp_path / "record.yml"
    path.write_text(f"- n: 1\n  short: {scalar}\n  codes:\n    - code: G2\n  not_coded:\n    - code: G1\n")
    assert gap.record_codes(path) == ({"1": expected}, {"G2": [1]})


@pytest.mark.parametrize("suffix", ["G2 # comment", "garbage", "G٢"])
def test_gap_code_lines_outside_fixed_subset_are_not_silently_dropped(tmp_path, suffix):
    path = tmp_path / "record.yml"
    path.write_text(f"- n: 1\n  short: A title\n  codes:\n    - code: {suffix}\n")
    with pytest.raises(gap.GapCoverageError):
        gap.record_codes(path)
