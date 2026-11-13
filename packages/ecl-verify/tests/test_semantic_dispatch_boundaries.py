"""Readable semantic inputs retain every applicable rule after unrelated schema failures."""
import dataclasses
import copy
import os
import subprocess
import sys
import json
from pathlib import Path
import pytest
from ecl_verify.resources import _semantics, object_findings
from ecl_verify.semantic import SemanticValidator
from ecl_verify.bundle_verification import verify_bundle, with_scope
from ecl_verify.trust import TrustPolicy
ROOT=Path(__file__).resolve().parents[3]
CASES=json.loads((ROOT/"tests/fixtures/semantic-dispatch-boundaries/cases.json").read_text())
POLICY=TrustPolicy.load((ROOT/"conformance/suites/evidence-bundle/trust-policy.json").read_bytes())

@pytest.mark.parametrize("case",[x for x in CASES if not x.get("go_only")],ids=lambda x:x["id"])
def test_semantic_dispatch_boundaries(case):
    value=case["value"]
    before=copy.deepcopy(value)
    if case.get("api")=="bundle":
        # Nested envelopes have no bundle signing purpose; these tests assert Stage-3 ordering,
        # not valid signatures or acceptance of the deliberately changed outer payload.
        report=verify_bundle(value,POLICY,now="2026-10-01T00:00:00Z")
        assert value==before
        assert report.verdict=="invalid"
        codes={x.split(":")[0] for x in report.findings}
        for rule in case["required"]:assert rule in codes
        return
    validator=_semantics()
    if "options" in case:
        identifier="urn:example:review-extension"
        validator=SemanticValidator([identifier],allocated_versions={identifier:[1]},active_versions={identifier:[1]} if case["options"]=="custom" else {},applicability={identifier:{1:[case["kind"]]}})
    findings=object_findings(value) if case.get("api")=="object" else validator.validate(value)
    assert value==before
    if case["id"]=="adapter-generic-operand-complete-semantic":
        assert len({(f.rule_id,f.path) for f in findings})==len(findings)
    for rule, maximum in case.get("max_rule_counts", {}).items():
        assert sum(f.rule_id == rule for f in findings) <= maximum
    ids={x.rule_id for x in findings}
    assert set(case["required"])<=ids
    assert not set(case["absent"])&ids
    if case["clean"]:assert findings==[]
    for rule,paths in case.get("required_paths",{}).items():assert set(paths)<={x.path for x in findings if x.rule_id==rule}
    if case["id"] in {"dcmp-adapter-discriminator","ebmp-adapter-discriminator"}:
        assert "ecl.error.schema-invalid.v1" in {x.rule_id for x in object_findings(value)}

@pytest.mark.parametrize("mode",["valid","all-time-authority","one-time-authority","none","signer-and-time-authority"])
def test_scope_requires_object_signer_dependencies(mode):
    bundle=json.loads((ROOT/"conformance/suites/evidence-bundle/bundle-valid-observation-corroborates.json").read_text())
    report=verify_bundle(bundle,POLICY,now="2026-10-01T00:00:00Z")
    assert report.verdict=="verified" and report.effects[0].level=="corroborated"
    dependencies=report.trust_dependencies
    if mode=="none":dependencies=()
    elif mode=="all-time-authority":dependencies=tuple(dataclasses.replace(x,role="time-authority") for x in dependencies)
    elif mode=="one-time-authority":dependencies=tuple(dataclasses.replace(x,role="time-authority") if x.index==0 else x for x in dependencies)
    elif mode=="signer-and-time-authority":dependencies+=tuple(dataclasses.replace(x,role="time-authority") for x in dependencies)
    result=with_scope(dataclasses.replace(report,trust_dependencies=dependencies))
    supported=mode in {"valid","signer-and-time-authority"}
    assert ("envelope-signatures" in result.scope.established)==supported
    assert result.effects[0].level==("corroborated" if supported else "issuer-asserted")


@pytest.mark.parametrize("envelope", [None, "", "ECL-IE-1"])
def test_outcome_reason_interpretation_uses_protocol(envelope):
    from ecl_verify.extension_selection import interpreted_extension
    value=json.loads((ROOT/"conformance/suites/control-extensions/outcome-reason-valid-expired-before-release.json").read_text())
    if envelope is not None:
        value["envelope_version"]=envelope
    before=copy.deepcopy(value)
    assert interpreted_extension(value,value["extensions"][0])
    assert value==before


def test_adapter_noncanonical_host_value_is_structured():
    value=json.loads((ROOT/"conformance/vectors/adapters/valid-native-binding.json").read_text())
    value["noncanonical"]=1.5
    before=copy.deepcopy(value)
    findings=_semantics().validate(value)
    assert any(f.rule_id=="ecl.rule.adapter-source-binding-valid.v1" and f.path=="/binding_digest" for f in findings)
    assert value==before


@pytest.mark.parametrize("first,second", [("semantic","extension_selection"),("extension_selection","semantic")])
def test_extension_selector_import_orders(first,second):
    code=(f"import ecl_verify.{first}; import ecl_verify.{second}; "
          "from ecl_verify.semantic import extension_object_type as a; "
          "from ecl_verify.extension_selection import extension_object_type as b; "
          "assert a is b; assert a({'protocol': []}) is None; "
          "assert a({'protocol': {}}) is None")
    subprocess.run([sys.executable,"-c",code],check=True,timeout=10,env=os.environ.copy())
