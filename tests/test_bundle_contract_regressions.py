"""Concrete signed counterexamples, positive controls, and raw graph classifications."""
from dataclasses import asdict
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/ecl-verify/src"))
from ecl_verify.bundle import analyze_bundle
from ecl_verify.bundle_verification import verify_bundle, report_to_json
from ecl_verify.extensions import ExtensionDescriptor, ExtensionError
from ecl_verify.trust import TrustPolicy

FIXTURES = ROOT / "tests/fixtures/bundle-contract-regressions"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_bytes())
GRAPHS = json.loads((FIXTURES / "causal.json").read_bytes())["cases"]


@pytest.mark.parametrize("case", MANIFEST["cases"], ids=lambda case: case["id"])
def test_signed_contract(case):
    policy = TrustPolicy.load((FIXTURES / case["policy"]).read_bytes())
    report = report_to_json(verify_bundle(json.loads((FIXTURES / case["bundle"]).read_bytes()),
                                         policy, now=MANIFEST["now"]))
    assert report["verdict"] == case["verdict"], report["findings"]
    assert report["primary"] == case["primary"]
    if case["invalid_extra_signature"]:
        assert "envelope-signatures" not in report["scope"]["established"]
        assert any(d["key_id"] == "urn:example:key:probe-extra-approval-key"
                   and d["historical"] == "ecl.error.integrity-invalid.v1"
                   for d in report["trust_dependencies"])
    if case["continuation_empty_key_guard"]:
        assert any(f.startswith("ecl.error.decision-binding-invalid.v1:")
                   for f in report["findings"])


@pytest.mark.parametrize("case", GRAPHS, ids=lambda case: case["id"])
def test_causal_contract(case):
    report = analyze_bundle(case["records"], **case["options"])
    assert report.status == case["status"], report
    assert list(report.unresolved_predecessor_ids) == case["unresolved"]
    if "duplicate" in case["id"]:
        assert any(f.rule_id == "ecl.rule.bundle-object-identifiers-unique.v1" for f in report.findings)


def test_duplicate_graph_report_is_permutation_invariant():
    reports = [asdict(analyze_bundle(case["records"])) for case in GRAPHS if "duplicate" in case["id"]]
    assert all(report == reports[0] for report in reports)


@pytest.mark.parametrize("value", ["false", 0, 1, None, [], {}])
def test_current_trust_waiver_requires_boolean(value):
    suite = ROOT / "conformance/suites/evidence-bundle"
    policy = TrustPolicy.load((suite / "trust-policy-revoked-after-use.json").read_bytes())
    history = [TrustPolicy.load((suite / "trust-policy.json").read_bytes())]
    bundle = json.loads((suite / "bundle-current-trust-failed-revoked-after-use.json").read_bytes())
    with pytest.raises(ValueError, match="accept_current_trust_failure"):
        verify_bundle(bundle, policy, history=history, now=MANIFEST["now"], accept_current_trust_failure=value)


@pytest.mark.parametrize("value,verdict", [(False, "current-trust-failed"), (True, "verified")])
def test_current_trust_waiver_boolean_control(value, verdict):
    suite = ROOT / "conformance/suites/evidence-bundle"
    policy = TrustPolicy.load((suite / "trust-policy-revoked-after-use.json").read_bytes())
    history = [TrustPolicy.load((suite / "trust-policy.json").read_bytes())]
    bundle = json.loads((suite / "bundle-current-trust-failed-revoked-after-use.json").read_bytes())
    report = verify_bundle(bundle, policy, history=history, now=MANIFEST["now"], accept_current_trust_failure=value)
    assert report.verdict == verdict
    assert report.accepted_current_trust_failure is value


@pytest.mark.parametrize("value", [True, False, 1.5, "1", None, 0, -1])
def test_extension_version_requires_positive_exact_integer(value):
    descriptor = ExtensionDescriptor("ecl.ext.example.v1", value, ("DCMP-2",), ("decision_response",),
                                     "urn:example:interpretation", "ecl-registry", "active", "additive", True)
    with pytest.raises(ExtensionError):
        descriptor.validate()


def test_actual_registry_compatibility_classes_are_supported():
    entries = json.loads((ROOT / "registries/extensions.json").read_bytes())["entries"]
    for entry in entries:
        attrs = entry["attributes"]
        ExtensionDescriptor(entry["id"], attrs["version"], tuple(attrs["applies_to"]),
                            tuple(attrs["affected_fields"]), "urn:example:interpretation",
                            entry["owner_class"], entry["status"], entry["compatibility"],
                            bool(attrs.get("critical_by_default"))).validate()
