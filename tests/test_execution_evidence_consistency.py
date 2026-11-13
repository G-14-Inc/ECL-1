"""Signed execution and report-scope regressions. Robert F. Tilley Jr.; G-14, Inc."""
import base64
import json
from dataclasses import replace
from pathlib import Path

import pytest

from ecl_verify.binding import BindingError, check_event_binding
from ecl_verify.bundle_verification import report_scope, report_to_json, verify_bundle
from ecl_verify.trust import TrustPolicy

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/execution-evidence-consistency"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text())


@pytest.mark.parametrize("case", MANIFEST["cases"], ids=lambda case: case["id"])
def test_signed_execution_evidence(case):
    bundle = json.loads((FIXTURES / case["bundle"]).read_text())
    policy = TrustPolicy.load((FIXTURES / case["policy"]).read_bytes())
    report = report_to_json(verify_bundle(bundle, policy, now=MANIFEST["now"]))
    assert report["verdict"] == case["verdict"], report["findings"]
    assert report["primary"] == case["primary"], report["findings"]
    if case["verdict"] == "invalid":
        assert report["scope"]["established"] == []
    elif case["verdict"] == "incomplete":
        assert "bindings" in report["scope"]["established"]
        assert "causal-completeness" not in report["scope"]["established"]
    else:
        assert "bindings" in report["scope"]["established"]
        assert "causal-completeness" in report["scope"]["established"]
    payloads = [json.loads(base64.b64decode(envelope["payload"])) for envelope in bundle["envelopes"]]
    request = payloads[0]
    response = next((p for p in payloads if p.get("message_type") == "decision_response"), None)
    for event in payloads:
        if event.get("event_type") not in case["direct"]:
            continue
        code = None
        try:
            check_event_binding(event, request=request, response=response)
        except BindingError as error:
            code = error.code
        assert code == case["direct"][event["event_type"]]


@pytest.mark.parametrize("case", MANIFEST["reconstructed_scopes"], ids=lambda case: case["id"])
def test_reconstructed_report_consistency(case):
    suite = ROOT / "conformance/suites/evidence-bundle"
    base = verify_bundle(json.loads((suite / "bundle-valid-trusted-time.json").read_text()),
                         TrustPolicy.load((suite / "trust-policy-time-authority.json").read_bytes()), now=MANIFEST["now"])
    assert base.verdict == "verified"
    report, mode = base, case["id"]
    if mode in {"signer-historical-invalid", "time-authority-historical-invalid", "current-signer-invalid"}:
        role = "time-authority" if mode.startswith("time-authority") else "signer"
        dependencies = list(report.trust_dependencies)
        index = next(i for i, dependency in enumerate(dependencies) if dependency.role == role)
        field = "current" if mode == "current-signer-invalid" else "historical"
        dependencies[index] = replace(dependencies[index], **{field: "ecl.error.integrity-invalid.v1"})
        report = replace(report, trust_dependencies=tuple(dependencies))
    elif mode in {"missing-trusted-time", "envelope-historical-invalid"}:
        checks = list(report.envelope_checks)
        checks[0] = replace(checks[0], **({"trusted_time": None} if mode == "missing-trusted-time" else {"historical": "ecl.error.integrity-invalid.v1"}))
        report = replace(report, envelope_checks=tuple(checks))
    elif mode == "missing-signer-dependency":
        report = replace(report, trust_dependencies=tuple(d for d in report.trust_dependencies if not (d.index == 0 and d.role == "signer")))
    elif mode == "invalid-verdict":
        report = replace(report, verdict="invalid")
    expected = [] if case["remove"] == "all" else [item for item in base.scope.established if item not in case["remove"]]
    assert list(report_scope(report).established) == expected
