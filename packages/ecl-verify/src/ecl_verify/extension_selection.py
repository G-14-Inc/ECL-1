"""Select interpretations supported by this installation's extension registry.

This does not validate a value or remove an occurrence from its carrying object.
Unknown, future and inapplicable occurrences remain available for preservation.
"""
from collections.abc import Mapping
from functools import cache

from .semantic_numbers import schema_int


@cache
def _implemented() -> frozenset[tuple[str, int, str]]:
    # The lazy import keeps registry loading separate from semantic-rule imports.
    from .resources import registry_document
    result = set()
    for entry in registry_document("extensions")["entries"]:
        attributes = entry.get("attributes", {})
        identifier, version = entry.get("id"), attributes.get("version")
        kinds = attributes.get("applies_to", [])
        if entry.get("status") == "active" and isinstance(identifier, str) and type(version) is int:
            result.update((identifier, version, kind) for kind in kinds if isinstance(kind, str))
    return frozenset(result)


def extension_object_type(value: Mapping[str, object]) -> str | None:
    """Keep readable protocol semantics when an unrelated envelope field is invalid."""
    protocol = value.get("protocol")
    if isinstance(protocol, str) and protocol in {"DCMP-2", "EBMP-2", "ECL-WI-1"}:
        return protocol
    envelope_kind = value.get("envelope_version")
    kind = envelope_kind if isinstance(envelope_kind, str) else protocol
    return kind if isinstance(kind, str) else None


def interpreted_extension(value: object, occurrence: object) -> bool:
    """Whether this library interprets an occurrence on this carrying object."""
    if not isinstance(value, Mapping) or not isinstance(occurrence, Mapping):
        return False
    kind = extension_object_type(value)
    identifier, version = occurrence.get("id"), schema_int(occurrence.get("version"))
    return (isinstance(kind, str) and isinstance(identifier, str) and type(version) is int
            and (identifier, version, kind) in _implemented())
