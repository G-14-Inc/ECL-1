"""Deployment topology, timing case, fallback, security, and privacy profiles."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


class DeploymentError(ValueError):
    """Raised when a deployment or security profile is incomplete."""


@dataclass(frozen=True)
class DeploymentProfile:
    model: str
    centralized_low_latency_updates: bool = False
    centralized_audit_and_rapid_revocation: bool = False
    trust_bundle_exchange_id: str | None = None
    cross_domain_delegation_id: str | None = None
    cross_domain_verification_id: str | None = None
    federated_timing_case_id: str | None = None
    residency_or_mission_local_control: bool = False
    local_policy_key_evidence_control: bool = False
    policy_cache_staleness_seconds: int | None = None
    trust_cache_staleness_seconds: int | None = None
    stale_transition: str | None = None
    reconnect_reconciliation_id: str | None = None
    airgap_update_media_integrity_id: str | None = None
    airgap_export_integrity_id: str | None = None
    emergency_policy_dual_control_id: str | None = None
    disconnected_revocation_workflow_id: str | None = None
    disconnected_incident_workflow_id: str | None = None

    def validate(self) -> None:
        if self.model not in {
            "centralized-distributed-enforcement",
            "federated-multi-domain",
            "sovereign-self-managed",
            "offline-edge",
            "air-gapped-segmented",
        }:
            raise DeploymentError("deployment model is unknown")
        if self.model == "centralized-distributed-enforcement":
            if not (
                self.centralized_low_latency_updates
                and self.centralized_audit_and_rapid_revocation
            ):
                raise DeploymentError(
                    "centralized model lacks its stated selection drivers"
                )
        elif self.model == "federated-multi-domain":
            if not all(
                (
                    self.trust_bundle_exchange_id,
                    self.cross_domain_delegation_id,
                    self.cross_domain_verification_id,
                    self.federated_timing_case_id,
                )
            ):
                raise DeploymentError("federated model is incomplete")
        elif self.model == "sovereign-self-managed":
            if not (
                self.residency_or_mission_local_control
                and self.local_policy_key_evidence_control
            ):
                raise DeploymentError("sovereign model lacks local control")
        elif self.model == "offline-edge":
            if (
                self.policy_cache_staleness_seconds is None
                or self.policy_cache_staleness_seconds < 0
                or self.trust_cache_staleness_seconds is None
                or self.trust_cache_staleness_seconds < 0
                or self.stale_transition
                not in {"restricted", "emergency_halt", "quarantine"}
                or not self.reconnect_reconciliation_id
            ):
                raise DeploymentError("offline-edge model is incomplete")
        elif not all(
            (
                self.airgap_update_media_integrity_id,
                self.airgap_export_integrity_id,
                self.emergency_policy_dual_control_id,
                self.disconnected_revocation_workflow_id,
                self.disconnected_incident_workflow_id,
            )
        ):
            raise DeploymentError("air-gapped model is incomplete")


DEFAULT_TIMING = {
    1: (86400, 86400, 259200),
    2: (900, 14400, 86400),
    3: (300, 3600, 14400),
    4: (60, 900, 3600),
}


@dataclass(frozen=True)
class DeclaredTimingCase:
    level: int
    connected_revocation_seconds: int
    offline_staleness_seconds: int
    evidence_export_seconds: int
    rationale: str | None
    control_assumptions: tuple[str, ...]
    residual_risk: str | None
    federated_exchange_seconds: int | None
    trusted_time_or_secure_monotonic: bool
    # A reference to the assessor's recorded approval of a value less strict than the default.
    assessor_deviation_approval: str | None = None

    def validate(self) -> None:
        if self.level not in DEFAULT_TIMING:
            raise DeploymentError("timing case level is invalid")
        values = (
            self.connected_revocation_seconds,
            self.offline_staleness_seconds,
            self.evidence_export_seconds,
        )
        if any(value < 0 for value in values):
            raise DeploymentError("timing case cannot use a negative interval")
        default = DEFAULT_TIMING[self.level]
        if values != default and (
            not self.rationale or not self.control_assumptions or not self.residual_risk
        ):
            raise DeploymentError("non-default timing case lacks disclosure")
        # ECL1N-0098: a longer interval than the default is less strict and needs approval.
        if any(value > limit for value, limit in zip(values, default, strict=True)) and not (
            self.assessor_deviation_approval
        ):
            raise DeploymentError("less strict timing value lacks assessor approval")
        if (
            self.federated_exchange_seconds is not None
            and self.federated_exchange_seconds > self.connected_revocation_seconds
        ):
            raise DeploymentError("federated exchange misses revocation timing case")
        if self.level >= 3 and not self.trusted_time_or_secure_monotonic:
            raise DeploymentError("L3+ timing lacks trusted order evidence")


@dataclass(frozen=True)
class FallbackProfile:
    degraded_entry_conditions: tuple[str, ...]
    degraded_signed_cached_state: bool
    degraded_bounded_actions: tuple[str, ...]
    degraded_expires_to: str
    restricted_entry_conditions: tuple[str, ...]
    restricted_allowed_actions: tuple[str, ...]
    emergency_entry_conditions: tuple[str, ...]
    precedence: tuple[str, ...]
    stricter_transition_allowed: bool
    weaker_transition_after_trigger_allowed: bool

    def validate(self) -> None:
        if (
            not self.degraded_entry_conditions
            or not self.degraded_signed_cached_state
            or not self.degraded_bounded_actions
            or self.degraded_expires_to not in {"restricted", "emergency_halt"}
            or not self.restricted_entry_conditions
            or not self.emergency_entry_conditions
        ):
            raise DeploymentError("fallback profile is incomplete")
        if any(
            action not in {"diagnose", "recover", "contain", "safe_shutdown"}
            for action in self.restricted_allowed_actions
        ):
            raise DeploymentError("restricted mode permits a new consequential action")
        if self.precedence != (
            "emergency_halt",
            "restricted",
            "degraded",
            "ordinary",
        ):
            raise DeploymentError("fallback precedence is invalid")
        if not self.stricter_transition_allowed or self.weaker_transition_after_trigger_allowed:
            raise DeploymentError("fallback transition can remain too weak")


FEDERATED_FIELDS = frozenset(
    {
        "trust_domain",
        "issuer_or_trust_bundle",
        "decision_contract_version",
        "root_trace_id",
        "actor",
        "subject",
        "authorization_or_capability",
        "resource_scope",
        "expiry",
        "policy_reference",
        "evidence_profile",
        "unique_token_id",
        "delegation_depth",
    }
)


@dataclass(frozen=True)
class FederatedAuthorityContext:
    values: Mapping[str, str]
    semantically_lossless_or_narrower: bool

    def validate(self) -> None:
        if set(self.values) != FEDERATED_FIELDS or any(
            not value for value in self.values.values()
        ):
            raise DeploymentError("federated authority context is incomplete")
        if not self.semantically_lossless_or_narrower:
            raise DeploymentError("federated translation widens authority")


BASELINE_ADVERSARIES = frozenset(
    {
        "malicious_or_compromised_agent",
        "compromised_plugin_tool_or_dependency",
        "network_or_supply_chain_attacker",
        "privileged_insider",
        "claim_boundary_manipulator",
    }
)
UNTRUSTED_CONTENT_CLASSES = frozenset(
    {
        "conversation",
        "retrieved_content",
        "tool_response",
        "machine_consumable_output",
    }
)


@dataclass(frozen=True)
class SecurityPosture:
    adversaries: frozenset[str]
    untrusted_content_classes: frozenset[str]
    fail_closed_on_policy_proof_integrity: bool
    architecture_independence: bool
    privileged_change_control_id: str
    evidence_retention_profile_id: str
    human_is_sole_control: bool
    red_team_exercise_id: str
    incident_forensic_preservation_id: str
    staged_recovery_id: str
    heartbeat_safe_state_test_id: str

    def validate(self) -> None:
        if not BASELINE_ADVERSARIES.issubset(self.adversaries):
            raise DeploymentError("baseline adversary model is incomplete")
        if not UNTRUSTED_CONTENT_CLASSES.issubset(
            self.untrusted_content_classes
        ):
            raise DeploymentError("language or machine content is implicitly trusted")
        if not (
            self.fail_closed_on_policy_proof_integrity
            and self.architecture_independence
            and self.privileged_change_control_id
            and self.evidence_retention_profile_id
            and self.red_team_exercise_id
            and self.incident_forensic_preservation_id
            and self.staged_recovery_id
            and self.heartbeat_safe_state_test_id
        ):
            raise DeploymentError("operational security posture is incomplete")
        if self.human_is_sole_control:
            raise DeploymentError("human oversight is the sole consequential control")


@dataclass(frozen=True)
class PrivacyPosture:
    secret_reference_mechanism_id: str
    redaction_or_partition_profile_id: str
    least_necessary_disclosure_test_id: str
    materially_hidden_context: bool
    sealed_review_or_escrow_path_id: str | None

    def validate(self) -> None:
        if not all(
            (
                self.secret_reference_mechanism_id,
                self.redaction_or_partition_profile_id,
                self.least_necessary_disclosure_test_id,
            )
        ):
            raise DeploymentError("privacy posture is incomplete")
        if self.materially_hidden_context and not self.sealed_review_or_escrow_path_id:
            raise DeploymentError(
                "materially hidden context lacks sealed review or escrow"
            )


REDACTED_PROVENANCE_FIELDS = frozenset(
    {
        "root_trace_id",
        "action_id",
        "actor_or_pseudonym",
        "subject_or_pseudonym",
        "policy_reference",
        "decision_outcome",
        "timing_metadata",
        "causal_predecessors",
        "action_state",
        "artifact_digests",
        "registry_roots",
        "signature_verification_material",
    }
)


@dataclass(frozen=True)
class RedactedProvenanceExport:
    preserved_fields: frozenset[str]
    source_digest: str
    derivative_digest: str
    redaction_manifest_digest: str
    removed_required_evidence: bool
    resulting_claim_status: str

    def validate(self) -> None:
        if not REDACTED_PROVENANCE_FIELDS.issubset(self.preserved_fields):
            raise DeploymentError("redacted export omits verifier-critical fields")
        if (
            len(self.source_digest) != 64
            or len(self.derivative_digest) != 64
            or len(self.redaction_manifest_digest) != 64
            or self.source_digest == self.derivative_digest
        ):
            raise DeploymentError("redacted export derivative binding is invalid")
        if self.removed_required_evidence and self.resulting_claim_status not in {
            "indeterminate",
            "failed",
            "downgraded",
        }:
            raise DeploymentError("redaction preserves an unsupported claim")
