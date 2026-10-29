"""Declared time classes, latency evidence, dependency budgets, and drills."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Mapping

from .schema import parse_rfc3339_utc


class TimingError(ValueError):
    """Raised when timing or availability evidence is ambiguous."""


def _time(value: str) -> datetime:
    """An ECL RFC 3339 UTC instant, by the shared parser (one to nine fractional digits)."""
    try:
        return parse_rfc3339_utc(value)
    except ValueError as exc:
        raise TimingError(f"invalid UTC timestamp: {value!r}") from exc

@dataclass(frozen=True)
class TimeEvidence:
    time_class: str
    wall_time: str | None = None
    clock_id: str | None = None
    ticks: int | None = None
    unit: str | None = None
    trusted_source_id: str | None = None
    epoch_name: str | None = None
    epoch_value: int | None = None

    def validate(self) -> None:
        if self.time_class not in {
            "issuer_wall",
            "observer_wall",
            "trusted_external",
            "monotonic_duration",
            "causal_order",
            "policy_epoch",
            "revocation_epoch",
        }:
            raise TimingError("unknown time class")
        if self.time_class in {"issuer_wall", "observer_wall"}:
            if not self.wall_time:
                raise TimingError("wall-time class lacks wall time")
            _time(self.wall_time)
        elif self.time_class == "trusted_external":
            if not self.wall_time or not self.trusted_source_id:
                raise TimingError("trusted time lacks time or source")
            _time(self.wall_time)
        elif self.time_class == "monotonic_duration":
            if (
                not self.clock_id
                or not isinstance(self.ticks, int)
                or self.ticks < 0
                or self.unit not in {"nanosecond", "microsecond", "millisecond"}
            ):
                raise TimingError(
                    "monotonic evidence lacks clock, ticks, or unit"
                )
        elif self.time_class in {"policy_epoch", "revocation_epoch"}:
            if (
                not self.epoch_name
                or not isinstance(self.epoch_value, int)
                or self.epoch_value < 0
            ):
                raise TimingError("epoch evidence is incomplete")

    def comparable_to(self, other: "TimeEvidence") -> bool:
        self.validate()
        other.validate()
        if self.time_class == other.time_class == "monotonic_duration":
            return self.clock_id == other.clock_id and self.unit == other.unit
        if self.time_class in {
            "issuer_wall",
            "observer_wall",
            "trusted_external",
        } and other.time_class in {
            "issuer_wall",
            "observer_wall",
            "trusted_external",
        }:
            return self.time_class == other.time_class
        return False


@dataclass(frozen=True)
class LatencyMeasurementPlan:
    start_boundary: str
    end_boundary: str
    percentiles: tuple[str, ...]
    sampling_interval: str
    warmup_handling: str
    environment_class: str
    action_classes: tuple[str, ...]
    hot_path_dependencies: tuple[str, ...]

    def validate(self) -> None:
        if (
            not self.start_boundary
            or not self.end_boundary
            or self.start_boundary == self.end_boundary
            or not self.percentiles
            or not self.sampling_interval
            or not self.warmup_handling
            or not self.environment_class
            or not self.action_classes
        ):
            raise TimingError("latency measurement plan is incomplete")
        allowed = {"p50", "p90", "p95", "p99", "p99.9", "max"}
        if set(self.percentiles) - allowed:
            raise TimingError("latency plan contains an unknown percentile")


@dataclass(frozen=True)
class LatencyEvidence:
    plan: LatencyMeasurementPlan
    raw_observations_ns: tuple[int, ...]
    calculation_method: str
    exclusions: tuple[str, ...]
    breach_observation_ids: tuple[str, ...]
    tested_configuration_digest: str
    product_claim_configuration_digest: str

    def validate(self) -> None:
        self.plan.validate()
        if (
            not self.raw_observations_ns
            or any(value < 0 for value in self.raw_observations_ns)
            or not self.calculation_method
            or len(self.tested_configuration_digest) != 64
        ):
            raise TimingError("latency evidence is incomplete")
        if self.tested_configuration_digest != self.product_claim_configuration_digest:
            raise TimingError("product latency claim exceeds tested configuration")


@dataclass(frozen=True)
class DependencyDeclaration:
    dependency_id: str
    dependency_class: str
    staleness_budget_seconds: int
    required_before_release: bool

    def validate(self) -> None:
        if self.dependency_class not in {
            "hot_path",
            "cached",
            "asynchronous",
            "advisory",
        }:
            raise TimingError("unknown dependency class")
        if not self.dependency_id or self.staleness_budget_seconds < 0:
            raise TimingError("dependency declaration is incomplete")


REQUIRED_STALENESS_DOMAINS = frozenset(
    {"policy", "trust_root", "registry", "revocation", "evidence_export"}
)


@dataclass(frozen=True)
class LocalGateDependencyProfile:
    dependencies: tuple[DependencyDeclaration, ...]
    domain_budgets_seconds: Mapping[str, int]
    undeclared_network_dependency: bool

    def validate(self) -> None:
        for dependency in self.dependencies:
            dependency.validate()
        if set(self.domain_budgets_seconds) != REQUIRED_STALENESS_DOMAINS:
            raise TimingError("staleness budgets are not separately declared")
        if any(value < 0 for value in self.domain_budgets_seconds.values()):
            raise TimingError("staleness budget cannot be negative")
        if self.undeclared_network_dependency:
            raise TimingError("local gate has an undeclared network dependency")
        remote_before_release = [
            dependency.dependency_id
            for dependency in self.dependencies
            if dependency.required_before_release
            and dependency.dependency_class != "cached"
        ]
        if remote_before_release:
            raise TimingError(
                "local gate release requires a non-cached remote dependency"
            )


@dataclass(frozen=True)
class EmergencyChannelDrill:
    channel_id: str
    interval_seconds: int
    last_tested_at: str
    evaluated_at: str
    material_architecture_change_at: str | None
    independence_verified: bool

    def validate(self) -> None:
        if (
            not self.channel_id
            or self.interval_seconds < 1
            or not self.independence_verified
        ):
            raise TimingError("emergency-channel drill is incomplete")
        last = _time(self.last_tested_at)
        evaluated = _time(self.evaluated_at)
        if evaluated - last > timedelta(seconds=self.interval_seconds):
            raise TimingError("emergency-channel drill interval is overdue")
        if self.material_architecture_change_at:
            changed = _time(self.material_architecture_change_at)
            if changed > last:
                raise TimingError(
                    "emergency channel was not retested after architecture change"
                )


@dataclass(frozen=True)
class AvailabilityEvidence:
    measured_behavior: tuple[str, ...]
    designed_behavior: tuple[str, ...]
    untested_assumptions: tuple[str, ...]

    def validate(self) -> None:
        groups: tuple[Iterable[str], ...] = (
            self.measured_behavior,
            self.designed_behavior,
            self.untested_assumptions,
        )
        values = [item for group in groups for item in group]
        if len(values) != len(set(values)):
            raise TimingError(
                "availability statement occupies multiple evidence classes"
            )
        if not self.measured_behavior and not self.untested_assumptions:
            raise TimingError(
                "availability evidence has neither measurement nor disclosed assumption"
            )
