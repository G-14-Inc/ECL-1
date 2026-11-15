"""EBMP2-056 checks for a terminal retained by a binding record.

These run separately from object semantics: bundle verification keeps its outcome-reason
checks at stage 9. A caller enables paired mode only when it has established which
verified response belongs to the terminal, or that no verified response was retained.
"""
from __future__ import annotations

from collections.abc import Mapping
from functools import cache
from typing import Any

from ecl_verify.semantic import Finding

from .common import extension_entries, text

OUTCOME_REASON = "ecl.ext.outcome-reason.v1"
SEMANTIC_INVALID = "ecl.error.semantic-invalid.v1"


@cache
def _active_errors() -> frozenset[str]:
    from ecl_verify.resources import registry_document
    return frozenset(entry["id"] for entry in registry_document("error-codes")["entries"]
                     if entry.get("status") == "active" and entry["id"].startswith("ecl.error."))


def terminal_reason_findings(
    terminal: Mapping[str, Any] | None, *, response_outcome: str | None = None,
    paired: bool = False,
) -> list[Finding]:
    """Intrinsic terminal checks, plus the denied-response clause in paired mode.

    Findings use paths relative to the terminal. Intrinsic mode cannot decide whether
    a denied terminal needs an explicit reason: its decision response is unpaired.
    Unknown noncritical extension versions are preserved, never interpreted as version 1.
    """
    if terminal is None or text(terminal, "event_type") != "execution_terminal":
        return []
    state = text(terminal, "event", "state")
    entries = extension_entries(terminal, OUTCOME_REASON)
    findings: list[Finding] = []

    def add(message: str) -> None:
        findings.append(Finding(SEMANTIC_INVALID, "/extensions", message))

    if len(entries) > 1:
        add("a terminal has multiple outcome reasons")
    for entry in entries:
        value = entry.get("value")
        if (type(value) is not dict or set(value) != {"code"}
                or type(value.get("code")) is not str or value["code"] not in _active_errors()):
            add("a terminal has an invalid outcome reason")
    if entries and state == "succeeded":
        add("a succeeded terminal has an outcome reason")
    if not entries and (state == "expired_before_release"
                        or (paired and state == "denied" and response_outcome in {None, "admit"})):
        add("a terminal is missing its required outcome reason")
    return findings
