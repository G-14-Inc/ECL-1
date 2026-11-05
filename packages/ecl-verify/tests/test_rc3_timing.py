from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "ecl-verify" / "src"))

from ecl_verify.timing import (  # noqa: E402
    AvailabilityEvidence,
    DependencyDeclaration,
    EmergencyChannelDrill,
    LatencyEvidence,
    LatencyMeasurementPlan,
    LocalGateDependencyProfile,
    TimeEvidence,
    TimingError,
)


class Rc3TimingTests(unittest.TestCase):
    def test_time_classes_and_monotonic_domains_are_explicit(self) -> None:
        wall = TimeEvidence(
            time_class="observer_wall",
            wall_time="2026-07-27T05:00:00Z",
        )
        first = TimeEvidence(
            time_class="monotonic_duration",
            clock_id="https://externalcontrollayer.ai/ns/clock/process-1",
            ticks=100,
            unit="nanosecond",
        )
        same = TimeEvidence(
            time_class="monotonic_duration",
            clock_id=first.clock_id,
            ticks=200,
            unit=first.unit,
        )
        other = TimeEvidence(
            time_class="monotonic_duration",
            clock_id="https://externalcontrollayer.ai/ns/clock/process-2",
            ticks=1,
            unit="nanosecond",
        )
        wall.validate()
        self.assertTrue(first.comparable_to(same))
        self.assertFalse(first.comparable_to(other))
        self.assertFalse(first.comparable_to(wall))

    def test_latency_claim_binds_plan_observations_and_configuration(self) -> None:
        plan = LatencyMeasurementPlan(
            start_boundary="gate receives canonical request bytes",
            end_boundary="gate emits release or safe-state disposition",
            percentiles=("p50", "p95", "p99", "max"),
            sampling_interval="one hour",
            warmup_handling="discard first 100 measured requests",
            environment_class="x86_64 four-core isolated local process",
            action_classes=("ecl.action.read.v1",),
            hot_path_dependencies=("signed cached policy", "local key material"),
        )
        LatencyEvidence(
            plan=plan,
            raw_observations_ns=(1000, 1200, 1800),
            calculation_method="nearest-rank over the complete interval",
            exclusions=("declared warm-up samples",),
            breach_observation_ids=(),
            tested_configuration_digest="a" * 64,
            product_claim_configuration_digest="a" * 64,
        ).validate()
        with self.assertRaisesRegex(TimingError, "exceeds tested"):
            LatencyEvidence(
                plan=plan,
                raw_observations_ns=(1000,),
                calculation_method="nearest-rank",
                exclusions=(),
                breach_observation_ids=(),
                tested_configuration_digest="a" * 64,
                product_claim_configuration_digest="b" * 64,
            ).validate()

    def test_local_gate_has_separate_budgets_and_no_remote_hot_path(self) -> None:
        local = LocalGateDependencyProfile(
            dependencies=(
                DependencyDeclaration(
                    "https://externalcontrollayer.ai/ns/dependency/cached-policy",
                    "cached",
                    900,
                    True,
                ),
                DependencyDeclaration(
                    "https://externalcontrollayer.ai/ns/dependency/evidence-export",
                    "asynchronous",
                    3600,
                    False,
                ),
            ),
            domain_budgets_seconds={
                "policy": 900,
                "trust_root": 900,
                "registry": 3600,
                "revocation": 300,
                "evidence_export": 86400,
            },
            undeclared_network_dependency=False,
        )
        local.validate()
        remote = LocalGateDependencyProfile(
            dependencies=(
                DependencyDeclaration(
                    "https://control.example/decision",
                    "hot_path",
                    5,
                    True,
                ),
            ),
            domain_budgets_seconds=local.domain_budgets_seconds,
            undeclared_network_dependency=False,
        )
        with self.assertRaisesRegex(TimingError, "non-cached remote"):
            remote.validate()

    def test_emergency_channel_is_periodic_independent_and_change_retested(
        self,
    ) -> None:
        EmergencyChannelDrill(
            channel_id="https://externalcontrollayer.ai/ns/emergency-channel/1",
            interval_seconds=86400,
            last_tested_at="2026-07-27T05:00:00Z",
            evaluated_at="2026-07-28T04:59:59Z",
            material_architecture_change_at="2026-07-27T04:00:00Z",
            independence_verified=True,
        ).validate()
        with self.assertRaisesRegex(TimingError, "architecture change"):
            EmergencyChannelDrill(
                channel_id="https://externalcontrollayer.ai/ns/emergency-channel/1",
                interval_seconds=86400,
                last_tested_at="2026-07-27T05:00:00Z",
                evaluated_at="2026-07-28T04:59:59Z",
                material_architecture_change_at="2026-07-27T06:00:00Z",
                independence_verified=True,
            ).validate()

    def test_availability_evidence_separates_fact_design_and_assumption(self) -> None:
        AvailabilityEvidence(
            measured_behavior=("local gate continued during control-plane partition",),
            designed_behavior=("evidence export retries with bounded backoff",),
            untested_assumptions=("removable-media transfer completes within one hour",),
        ).validate()
        with self.assertRaisesRegex(TimingError, "multiple evidence classes"):
            AvailabilityEvidence(
                measured_behavior=("partition safe state",),
                designed_behavior=("partition safe state",),
                untested_assumptions=(),
            ).validate()


if __name__ == "__main__":
    unittest.main()
