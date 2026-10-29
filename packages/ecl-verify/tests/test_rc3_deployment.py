from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "ecl-verify" / "src"))

from ecl_verify.deployment import (  # noqa: E402
    BASELINE_ADVERSARIES,
    DEFAULT_TIMING,
    FEDERATED_FIELDS,
    REDACTED_PROVENANCE_FIELDS,
    UNTRUSTED_CONTENT_CLASSES,
    DeclaredTimingCase,
    DeploymentError,
    DeploymentProfile,
    FallbackProfile,
    FederatedAuthorityContext,
    PrivacyPosture,
    RedactedProvenanceExport,
    SecurityPosture,
)


class Rc3DeploymentTests(unittest.TestCase):
    def test_each_deployment_model_has_topology_specific_controls(self) -> None:
        DeploymentProfile(
            model="centralized-distributed-enforcement",
            centralized_low_latency_updates=True,
            centralized_audit_and_rapid_revocation=True,
        ).validate()
        DeploymentProfile(
            model="federated-multi-domain",
            trust_bundle_exchange_id="https://externalcontrollayer.ai/ns/trust-exchange/1",
            cross_domain_delegation_id="https://externalcontrollayer.ai/ns/delegation-profile/1",
            cross_domain_verification_id="https://externalcontrollayer.ai/ns/verification-profile/1",
            federated_timing_case_id="https://externalcontrollayer.ai/ns/timing/1",
        ).validate()
        DeploymentProfile(
            model="sovereign-self-managed",
            residency_or_mission_local_control=True,
            local_policy_key_evidence_control=True,
        ).validate()
        DeploymentProfile(
            model="offline-edge",
            policy_cache_staleness_seconds=900,
            trust_cache_staleness_seconds=900,
            stale_transition="restricted",
            reconnect_reconciliation_id="https://externalcontrollayer.ai/ns/reconciliation/1",
        ).validate()
        DeploymentProfile(
            model="air-gapped-segmented",
            airgap_update_media_integrity_id="https://externalcontrollayer.ai/ns/test/update-media/1",
            airgap_export_integrity_id="https://externalcontrollayer.ai/ns/test/export/1",
            emergency_policy_dual_control_id="https://externalcontrollayer.ai/ns/dual-control/1",
            disconnected_revocation_workflow_id="https://externalcontrollayer.ai/ns/workflow/revoke/1",
            disconnected_incident_workflow_id="https://externalcontrollayer.ai/ns/workflow/incident/1",
        ).validate()

    def test_declared_timing_case_is_default_or_fully_justified(self) -> None:
        default = DEFAULT_TIMING[3]
        DeclaredTimingCase(
            level=3,
            connected_revocation_seconds=default[0],
            offline_staleness_seconds=default[1],
            evidence_export_seconds=default[2],
            rationale=None,
            control_assumptions=(),
            residual_risk=None,
            federated_exchange_seconds=default[0],
            trusted_time_or_secure_monotonic=True,
        ).validate()
        with self.assertRaisesRegex(DeploymentError, "lacks disclosure"):
            DeclaredTimingCase(
                level=3,
                connected_revocation_seconds=600,
                offline_staleness_seconds=default[1],
                evidence_export_seconds=default[2],
                rationale=None,
                control_assumptions=(),
                residual_risk=None,
                federated_exchange_seconds=600,
                trusted_time_or_secure_monotonic=True,
            ).validate()

    def test_a_less_strict_timing_value_needs_assessor_approval(self) -> None:
        default = DEFAULT_TIMING[2]
        disclosed = {
            "level": 2,
            "offline_staleness_seconds": default[1],
            "evidence_export_seconds": default[2],
            "rationale": "sector profile",
            "control_assumptions": ("revocation feed is pushed",),
            "residual_risk": "stated",
            "federated_exchange_seconds": None,
            "trusted_time_or_secure_monotonic": False,
        }
        # Stricter than the default: disclosure suffices.
        DeclaredTimingCase(connected_revocation_seconds=default[0] // 2, **disclosed).validate()
        with self.assertRaisesRegex(DeploymentError, "lacks assessor approval"):
            DeclaredTimingCase(connected_revocation_seconds=default[0] * 2, **disclosed).validate()
        DeclaredTimingCase(
            connected_revocation_seconds=default[0] * 2,
            assessor_deviation_approval="urn:example:assessment:deviation-1",
            **disclosed,
        ).validate()

    def test_fallback_state_is_cached_bounded_and_strictly_ordered(self) -> None:
        FallbackProfile(
            degraded_entry_conditions=("remote control plane unavailable",),
            degraded_signed_cached_state=True,
            degraded_bounded_actions=("read-only diagnosed action",),
            degraded_expires_to="restricted",
            restricted_entry_conditions=("cached policy expired",),
            restricted_allowed_actions=("diagnose", "safe_shutdown"),
            emergency_entry_conditions=("critical integrity failure",),
            precedence=(
                "emergency_halt",
                "restricted",
                "degraded",
                "ordinary",
            ),
            stricter_transition_allowed=True,
            weaker_transition_after_trigger_allowed=False,
        ).validate()
        with self.assertRaisesRegex(DeploymentError, "new consequential"):
            FallbackProfile(
                degraded_entry_conditions=("dependency unavailable",),
                degraded_signed_cached_state=True,
                degraded_bounded_actions=("read",),
                degraded_expires_to="restricted",
                restricted_entry_conditions=("cache expired",),
                restricted_allowed_actions=("submit_payment",),
                emergency_entry_conditions=("integrity failure",),
                precedence=(
                    "emergency_halt",
                    "restricted",
                    "degraded",
                    "ordinary",
                ),
                stricter_transition_allowed=True,
                weaker_transition_after_trigger_allowed=False,
            ).validate()

    def test_federated_authority_exchange_is_complete_and_never_widened(self) -> None:
        values = {name: f"value:{name}" for name in FEDERATED_FIELDS}
        FederatedAuthorityContext(values, True).validate()
        with self.assertRaisesRegex(DeploymentError, "widens authority"):
            FederatedAuthorityContext(values, False).validate()

    def test_security_posture_assumes_hostile_content_and_not_human_only(
        self,
    ) -> None:
        SecurityPosture(
            adversaries=BASELINE_ADVERSARIES,
            untrusted_content_classes=UNTRUSTED_CONTENT_CLASSES,
            fail_closed_on_policy_proof_integrity=True,
            architecture_independence=True,
            privileged_change_control_id="https://externalcontrollayer.ai/ns/control/privileged-change/1",
            evidence_retention_profile_id="https://externalcontrollayer.ai/ns/retention/1",
            human_is_sole_control=False,
            red_team_exercise_id="https://externalcontrollayer.ai/ns/redteam/1",
            incident_forensic_preservation_id="https://externalcontrollayer.ai/ns/incident/1",
            staged_recovery_id="https://externalcontrollayer.ai/ns/recovery/1",
            heartbeat_safe_state_test_id="https://externalcontrollayer.ai/ns/test/heartbeat/1",
        ).validate()

    def test_privacy_and_redacted_export_preserve_reviewable_accountability(
        self,
    ) -> None:
        PrivacyPosture(
            secret_reference_mechanism_id="https://externalcontrollayer.ai/ns/secret-broker/1",
            redaction_or_partition_profile_id="https://externalcontrollayer.ai/ns/redaction/1",
            least_necessary_disclosure_test_id="https://externalcontrollayer.ai/ns/test/minimization/1",
            materially_hidden_context=True,
            sealed_review_or_escrow_path_id="https://externalcontrollayer.ai/ns/sealed-review/1",
        ).validate()
        RedactedProvenanceExport(
            preserved_fields=REDACTED_PROVENANCE_FIELDS,
            source_digest="a" * 64,
            derivative_digest="b" * 64,
            redaction_manifest_digest="c" * 64,
            removed_required_evidence=True,
            resulting_claim_status="downgraded",
        ).validate()
        with self.assertRaisesRegex(DeploymentError, "unsupported claim"):
            RedactedProvenanceExport(
                preserved_fields=REDACTED_PROVENANCE_FIELDS,
                source_digest="a" * 64,
                derivative_digest="b" * 64,
                redaction_manifest_digest="c" * 64,
                removed_required_evidence=True,
                resulting_claim_status="full_conformance",
            ).validate()


if __name__ == "__main__":
    unittest.main()
