"""Record and bundle consumers interpret only their supported extension occurrence."""
import copy
import json
from pathlib import Path
import pytest

from ecl_verify.canonical import loads_json_strict
from ecl_verify.bindings import binding_findings
from ecl_verify.bindings.otel import load_export_keys
from ecl_verify.bundle_verification import verify_bundle, primary_finding
from ecl_verify.extensions import ExtensionDescriptor, ExtensionOccurrence, ExtensionError, process_extensions
from ecl_verify.extension_selection import interpreted_extension
from ecl_verify.resources import validator_for
from ecl_verify.trust import TrustPolicy

ROOT = Path(__file__).resolve().parents[1] / "tests/fixtures/extension-selection-cases"
MANIFEST = json.loads((ROOT / "manifest.json").read_text())
POLICY = TrustPolicy.load((ROOT / "bundle-trust.json").read_bytes())
KEYS = load_export_keys((ROOT / "export-keys.json").read_bytes())


@pytest.mark.parametrize("case", MANIFEST["cases"], ids=lambda case: case["id"])
def test_extension_selection_record(case):
    value = loads_json_strict((ROOT / case["file"]).read_bytes())
    before = copy.deepcopy(value)
    if case["kind"] == "binding":
        errors = list(validator_for(case["schema"]).iter_errors(value))
        assert not errors, [error.message for error in errors]
        found = binding_findings(value, export_keys=KEYS)
        assert (not found) == case["accepted"], found
        if not case["accepted"]:
            assert case["required_code"] in {item.rule_id for item in found}
    else:
        report = verify_bundle(value, POLICY, now=MANIFEST["evaluated_at"])
        assert (report.verdict == "verified") == case["accepted"], report
        if not case["accepted"]:
            assert primary_finding(report) == case["required_code"]
    assert value == before


@pytest.mark.parametrize("kind,version,expected", [("EBMP-2", 1, True), ("DCMP-2", 1, False), ("EBMP-2", 2, False), ("EBMP-2", True, False)])
def test_default_interpretation_is_scoped(kind, version, expected):
    entry = {"id": "ecl.ext.outcome-reason.v1", "version": version, "critical": False, "value": {"code": "ecl.error.expired.v1"}}
    assert interpreted_extension({"protocol": kind}, entry) is expected


def test_descriptor_consumer_requires_explicit_object_type():
    descriptor = ExtensionDescriptor("ecl.ext.test.v1", 1, ("DCMP-2",), ("extensions",), "urn:example:interpretation", "private", "active", "additive", False)
    registry = {(descriptor.identifier, 1): descriptor}
    occurrence = ExtensionOccurrence(descriptor.identifier, 1, False, {"opaque": [1, 2]})
    with pytest.raises(TypeError):
        process_extensions([occurrence], registry=registry)
    known = process_extensions([occurrence], registry=registry, object_type="DCMP-2")
    assert known.known == (occurrence,)
    unknown = process_extensions([occurrence], registry=registry, object_type="EBMP-2")
    assert unknown.known == ()
    assert unknown.preserved_unknown_noncritical == (occurrence,)
    assert unknown.preserved_unknown_noncritical[0] is not occurrence
    with pytest.raises(ExtensionError, match="unknown critical"):
        process_extensions([ExtensionOccurrence(descriptor.identifier, 1, True, {})], registry=registry, object_type="EBMP-2")
    with pytest.raises(ExtensionError, match="object type"):
        process_extensions([occurrence], registry=registry, object_type="")


@pytest.mark.parametrize("version,critical", [(True, False), (1.0, False), (0, False), (-1, False), (1, 0), (1, 1), (1, "false")])
def test_descriptor_consumer_does_not_coerce_occurrence_domains(version, critical):
    descriptor = ExtensionDescriptor("ecl.ext.test.v1", 1, ("DCMP-2",), ("extensions",), "urn:example:interpretation", "private", "active", "additive", False)
    registry = {(descriptor.identifier, 1): descriptor}
    with pytest.raises(ExtensionError):
        process_extensions([ExtensionOccurrence(descriptor.identifier, version, critical, {})], registry=registry, object_type="DCMP-2")


def test_descriptor_consumer_preserves_valid_future_noncritical_occurrence():
    descriptor = ExtensionDescriptor("ecl.ext.test.v1", 1, ("DCMP-2",), ("extensions",), "urn:example:interpretation", "private", "active", "additive", False)
    value = ExtensionOccurrence(descriptor.identifier, 2, False, {"future": ["opaque", 9]})
    result = process_extensions([value], registry={(descriptor.identifier, 1): descriptor}, object_type="DCMP-2")
    assert result.known == ()
    assert result.preserved_unknown_noncritical == (value,)
    assert result.preserved_unknown_noncritical[0] is not value
