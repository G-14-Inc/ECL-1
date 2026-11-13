"""Declaration input regressions. Robert F. Tilley Jr.; G-14, Inc."""
from dataclasses import replace
import pytest

from ecl_verify.deployment import (
    DeploymentError, DeclaredTimingCase, DeploymentProfile, FallbackProfile, FederatedAuthorityContext, SecurityPosture,
    PrivacyPosture, RedactedProvenanceExport, FEDERATED_FIELDS,
    BASELINE_ADVERSARIES, UNTRUSTED_CONTENT_CLASSES, REDACTED_PROVENANCE_FIELDS,
)

central = DeploymentProfile("centralized-distributed-enforcement", True, True)
offline = DeploymentProfile("offline-edge", policy_cache_staleness_seconds=0,
    trust_cache_staleness_seconds=0, stale_transition="restricted", reconnect_reconciliation_id="urn:reconcile")
fallback = FallbackProfile(("loss",), True, ("read",), "restricted", ("expired",), (),
    ("integrity",), ("emergency_halt", "restricted", "degraded", "ordinary"), True, False)
federated = FederatedAuthorityContext({k:"urn:"+k for k in FEDERATED_FIELDS}, True)
security = SecurityPosture(BASELINE_ADVERSARIES, UNTRUSTED_CONTENT_CLASSES, True, True,
    "urn:change", "urn:retention", False, "urn:exercise", "urn:incident", "urn:recovery", "urn:heartbeat")
privacy = PrivacyPosture("urn:secret", "urn:redaction", "urn:minimize", False, None)
redaction = RedactedProvenanceExport(REDACTED_PROVENANCE_FIELDS, "a"*64, "b"*64, "c"*64, False, "full_conformance")
cases = [(name, obj, True) for name,obj in [
    ("central-control",central),("offline-zero-control",offline),("fallback-empty-restricted-actions-control",fallback),
    ("federated-control",federated),("security-control",security),("privacy-none-review-control",privacy),("redaction-control",redaction)]]
for label,obj,fields in [
    ("central",central,["centralized_low_latency_updates","centralized_audit_and_rapid_revocation"]),
    ("fallback",fallback,["degraded_signed_cached_state","stricter_transition_allowed","weaker_transition_after_trigger_allowed"]),
    ("federated",federated,["semantically_lossless_or_narrower"]),
    ("security",security,["fail_closed_on_policy_proof_integrity","architecture_independence","human_is_sole_control"]),
    ("privacy",privacy,["materially_hidden_context"]),
    ("redaction",redaction,["removed_required_evidence"]),
]:
    for field in fields:
        for index,value in enumerate(["false",1,0,None,[],{}]):
            cases.append((f"{label}-{field}-{index}",replace(obj,**{field:value}),False))
for field in ["policy_cache_staleness_seconds","trust_cache_staleness_seconds"]:
    for index,value in enumerate([True,False,0.5,float("nan"),float("inf"),"0",-1]):
        cases.append((f"offline-{field}-{index}",replace(offline,**{field:value}),False))
for field in ["source_digest","derivative_digest","redaction_manifest_digest"]:
    for index,value in enumerate(["g"*64,"a"*63+"\n",["a"]*64,None]):
        cases.append((f"redaction-{field}-{index}",replace(redaction,**{field:value}),False))
cases += [("federated-nonstring-values",replace(federated, values={k:1 for k in FEDERATED_FIELDS}),False),
          ("central-nonstring-model",replace(central,model=[]),False),
          ("privacy-nonstring-ref",replace(privacy,secret_reference_mechanism_id=["ref"]),False),
          ("fallback-string-conditions",replace(fallback,degraded_entry_conditions="loss"),False)]

timing = DeclaredTimingCase(1, 86401, 86400, 259200, "rationale", ("assumption",), "residual", None, False, "urn:approval")
cases.append(("timing-approved-control", timing, True))
for field in ["rationale", "residual_risk", "assessor_deviation_approval"]:
    for index, value in enumerate([True, 1, ["ref"], {"ref": "x"}]):
        cases.append((f"timing-{field}-{index}", replace(timing, **{field:value}), False))
for index, value in enumerate(["assumption", [1], [None], True, {"assumption":"x"}]):
    cases.append((f"timing-control-assumptions-{index}", replace(timing, control_assumptions=value), False))

@pytest.mark.parametrize("name,declaration,expected", cases, ids=[case[0] for case in cases])
def test_deployment_declaration_inputs(name, declaration, expected):
    if expected:
        declaration.validate()
    else:
        with pytest.raises(DeploymentError):
            declaration.validate()
