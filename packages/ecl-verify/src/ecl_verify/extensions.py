"""Offline verification checks and read-only metadata for extensions."""

from __future__ import annotations

import copy
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any


class ExtensionError(ValueError):
    """Raised when an extension or registry transition is not interoperable."""

STATUSES = frozenset(
    {"active", "deprecated", "prohibited", "superseded", "reserved"}
)

COMPATIBILITY_CLASSES = frozenset({"additive", "behavioral", "breaking"})

@dataclass(frozen=True)
class ExtensionDescriptor:
    identifier: str
    version: int
    applicable_object_types: tuple[str, ...]
    affected_fields: tuple[str, ...]
    interpretation_uri: str
    owner_class: str
    status: str
    compatibility_class: str
    core_semantics_affected: bool
    registry_requires_critical: bool = False
    composable_versions: frozenset[int] = frozenset()

    def validate(self) -> None:
        if (
            not self.identifier.startswith("ecl.")
            or not self.identifier.rsplit(".", 1)[-1].startswith("v")
            or self.version < 1
            or not self.applicable_object_types
            or not self.affected_fields
            or not self.interpretation_uri
            or not self.owner_class
        ):
            raise ExtensionError("extension descriptor is incomplete")
        if self.status not in STATUSES:
            raise ExtensionError("extension descriptor status is unknown")
        if self.compatibility_class not in COMPATIBILITY_CLASSES:
            raise ExtensionError("extension compatibility class is unknown")

@dataclass(frozen=True)
class ExtensionOccurrence:
    identifier: str
    version: int
    critical: bool
    value: Any

@dataclass(frozen=True)
class ExtensionProcessingResult:
    known: tuple[ExtensionOccurrence, ...]
    preserved_unknown_noncritical: tuple[ExtensionOccurrence, ...]
    reports: tuple[str, ...]

def process_extensions(
    occurrences: Iterable[ExtensionOccurrence],
    *,
    registry: Mapping[tuple[str, int], ExtensionDescriptor],
    profile_required_critical: Iterable[str] = (),
) -> ExtensionProcessingResult:
    values = tuple(occurrences)
    seen_pairs: set[tuple[str, int]] = set()
    versions: dict[str, set[int]] = {}
    known: list[ExtensionOccurrence] = []
    preserved: list[ExtensionOccurrence] = []
    reports: list[str] = []
    required_critical = set(profile_required_critical)
    for occurrence in values:
        key = (occurrence.identifier, occurrence.version)
        if key in seen_pairs:
            raise ExtensionError("duplicate extension identifier/version pair")
        seen_pairs.add(key)
        versions.setdefault(occurrence.identifier, set()).add(occurrence.version)
        descriptor = registry.get(key)
        if descriptor is None:
            if occurrence.critical:
                raise ExtensionError("unknown critical extension")
            preserved.append(copy.deepcopy(occurrence))
            reports.append(f"preserved-unknown:{occurrence.identifier}:{occurrence.version}")
            continue
        descriptor.validate()
        must_be_critical = (
            descriptor.core_semantics_affected
            or descriptor.registry_requires_critical
            or occurrence.identifier in required_critical
        )
        if must_be_critical and not occurrence.critical:
            raise ExtensionError(
                "semantics-affecting extension is not marked critical"
            )
        if not occurrence.critical and descriptor.core_semantics_affected:
            raise ExtensionError("non-critical extension alters core semantics")
        known.append(occurrence)
    for identifier, present_versions in versions.items():
        if len(present_versions) <= 1:
            continue
        descriptors = [
            registry.get((identifier, version)) for version in present_versions
        ]
        if any(descriptor is None for descriptor in descriptors):
            raise ExtensionError("conflicting extension versions are unresolved")
        allowed = set.intersection(
            *(set(descriptor.composable_versions) for descriptor in descriptors if descriptor)
        )
        if not present_versions.issubset(allowed):
            raise ExtensionError("conflicting extension versions are not composable")
    return ExtensionProcessingResult(
        tuple(known),
        tuple(preserved),
        tuple(reports),
    )

@dataclass(frozen=True)
class RegistryChange:
    operation: str
    identifier: str
    version: int
    status: str
    rationale: str
    effective_at: str
    replacement: str | None = None
    transition_until: str | None = None
    compatibility_impact: str | None = None
    affected_profiles: tuple[str, ...] = ()
    appeal_uri: str | None = None

@dataclass(frozen=True)
class PrivateExtension:
    identifier: str
    critical: bool
    documented: bool

    def validate_namespace(self) -> None:
        if self.identifier.startswith("ecl."):
            raise ExtensionError("private extension cannot use unallocated ecl.* name")
        if ":" not in self.identifier:
            raise ExtensionError("private extension lacks owner-controlled namespace")

def validate_private_claim_extensions(
    extensions: Iterable[PrivateExtension],
    *,
    disclosed_critical_ids: Iterable[str],
    public_interoperability_claim: bool,
) -> None:
    values = tuple(extensions)
    disclosed = set(disclosed_critical_ids)
    for extension in values:
        extension.validate_namespace()
        if extension.critical and extension.identifier not in disclosed:
            raise ExtensionError("critical private extension is not disclosed")
        if public_interoperability_claim and extension.critical and not extension.documented:
            raise ExtensionError(
                "public interoperability depends on undocumented private critical extension"
            )

def classify_extension_change(
    *,
    old_critical: bool,
    new_critical: bool,
    interpretation_changed: bool,
    accepted_values_narrowed: bool,
    core_state_behavior_changed: bool,
) -> str:
    if (
        old_critical != new_critical
        or interpretation_changed
        or accepted_values_narrowed
        or core_state_behavior_changed
    ):
        return "breaking"
    if not new_critical:
        return "additive"
    return "behavioral"

MAPPING_CLASSES = frozenset(
    {"preserved", "translated", "defaulted", "dropped", "impossible"}
)

@dataclass(frozen=True)
class ExtensionConversionReport:
    mappings: Mapping[str, str]

    def validate(self) -> None:
        if not self.mappings:
            raise ExtensionError("extension conversion report is empty")
        unknown = set(self.mappings.values()) - MAPPING_CLASSES
        if unknown:
            raise ExtensionError(
                f"extension conversion uses unknown mapping classes: {sorted(unknown)}"
            )
