"""Offline checkers for the five ECL binding profiles.

Each profile has a module: `aarm` (AARM-BINDING-1), `acs` (ACS-BINDING-1), `mcp` (MCP-GATEWAY-1),
`otel` (OTEL-EVIDENCE-EXPORT-1) and `oauth` (OAUTH-AUTHORITY-1), with `jcs` (RFC 8785) and `jose`
(compact JWS verification and JWK thumbprints) beneath them. Each module's `check` reads one
of the profile's records and returns the findings of
the profile's registered rules.

`binding_findings` dispatches on the record's `schema_version`. It runs no schema validation: a
caller validates the record against `RECORD_SCHEMAS[schema_version]` first, as the conformance
runner does for its `binding` stage. A record of no binding profile yields one schema finding.
The export keys a caller holds (OTEL-EVIDENCE-EXPORT-1, OE1-010) go to the OpenTelemetry checker,
which compares a record's keyed digests only under a key it is given.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Any

from ecl_verify.semantic import Finding

from . import aarm, acs, mcp, oauth, otel

SCHEMA_INVALID = "ecl.error.schema-invalid.v1"
CHECKERS: Mapping[str, Callable[[Mapping[str, Any]], list[Finding]]] = MappingProxyType(
    {
        aarm.EXCHANGE_VERSION: aarm.check,
        acs.EXCHANGE_VERSION: acs.check,
        mcp.EXCHANGE_VERSION: mcp.check,
        otel.EXPORT_VERSION: otel.check,
        oauth.PRESENTATION_VERSION: oauth.check,
    }
)
RECORD_SCHEMAS: Mapping[str, str] = MappingProxyType(
    {
        aarm.EXCHANGE_VERSION: aarm.EXCHANGE_SCHEMA,
        acs.EXCHANGE_VERSION: acs.EXCHANGE_SCHEMA,
        mcp.EXCHANGE_VERSION: mcp.EXCHANGE_SCHEMA,
        otel.EXPORT_VERSION: otel.EXPORT_SCHEMA,
        oauth.PRESENTATION_VERSION: oauth.PRESENTATION_SCHEMA,
    }
)
RULES = (*aarm.RULES, *acs.RULES, *mcp.RULES, *otel.RULES, *oauth.RULES)


def binding_findings(
    value: object, *, export_keys: Mapping[str, otel.ExportKey] | None = None
) -> list[Finding]:
    """The findings of the binding profile whose record `value` is, sorted by rule and path."""
    version = value.get("schema_version") if type(value) is dict else None
    checker = CHECKERS.get(version) if type(version) is str else None
    if checker is None or type(value) is not dict:
        return [Finding(SCHEMA_INVALID, "/schema_version", "not a binding profile record")]
    found = (
        otel.check(value, export_keys=export_keys)
        if version == otel.EXPORT_VERSION
        else checker(value)
    )
    return sorted(found, key=lambda item: (item.rule_id, item.path, item.message))
