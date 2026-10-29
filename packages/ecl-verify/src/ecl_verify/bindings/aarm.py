"""Offline verification checks and read-only metadata for bindings.aarm."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from ecl_verify.decision_basis_checks import input_key
from ecl_verify.semantic import Finding

from . import jcs
from .common import (
    ONE_WAY_RULE,
    OUTCOMES,
    Exchange,
    array,
    basis_class_problems,
    basis_problems,
    deferral_problems,
    digest_of,
    exchanges,
    extension_values,
    findings,
    input_problems,
    instant,
    member,
    message_findings,
    modification_basis_problems,
    modification_problems,
    modification_response_problems,
    new_request_problems,
    obj,
    one_way_response_problems,
    release_problems,
    same_digest,
    text,
)

AARM_VERSION = "1.0"

EXCHANGE_VERSION = "ecl_aarm_exchange_v1"

EXCHANGE_SCHEMA = "https://externalcontrollayer.ai/ns/schema/binding/aarm-exchange/1"

RECEIPT_EXTENSION = "ecl.ext.aarm-receipt.v1"

RECEIPT_SCHEMA = "https://externalcontrollayer.ai/ns/schema/extension/aarm-receipt/1"

DECISIONS = ("ALLOW", "DENY", "MODIFY", "STEP_UP", "DEFER")

ROLES = ("decision-layer", "judgment-source")

JUDGMENT_REQUIREMENTS = frozenset({"R2", "R3", "R7"})

DECISION_REQUIREMENT = "R4"

PERMITTED_OUTCOMES: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "ALLOW": frozenset(OUTCOMES),
        "DENY": frozenset({"deny"}),
        "MODIFY": frozenset({"deny"}),
        "STEP_UP": frozenset({"challenge", "hold", "deny"}),
        "DEFER": frozenset({"hold", "deny"}),
    }
)

MODIFICATION_RULE = "ecl.rule.aarm-modification-new-request.v1"

DEFERRAL_RULE = "ecl.rule.aarm-deferral-no-release.v1"

JUDGMENT_RULE = "ecl.rule.aarm-judgment-inputs.v1"

OUTCOME_RULE = "ecl.rule.aarm-outcome-no-weaker.v1"

RELEASE_RULE = "ecl.rule.aarm-release-requires-admit.v1"

RECEIPT_RULE = "ecl.rule.aarm-receipt-bound.v1"

BASIS_RULE = "ecl.rule.aarm-inputs-match-basis.v1"

RULES = (
    MODIFICATION_RULE,
    DEFERRAL_RULE,
    JUDGMENT_RULE,
    OUTCOME_RULE,
    RELEASE_RULE,
    RECEIPT_RULE,
    BASIS_RULE,
)


def _modification(record: Mapping[str, Any], decision: str | None) -> list[tuple[str, str]]:
    if decision != "MODIFY":
        return new_request_problems(record)
    request = obj(record, "request")
    if request is None:
        return []
    if "modification_request" not in record and obj(record, "release") is None:
        # AB1-004: a MODIFY that ends in deny of the original with no new request, as one that
        # changes the target or operation must, releases nothing; the record does not show why.
        return modification_response_problems(record)
    parameters = member(record, "aarm_decision", "modified_parameters")
    problems = [
        ("/" + path, message)
        for path, message in modification_problems(
            request, member(record, "modification_request"), parameters
        )
    ]
    named = text(record, "release", "request_id")
    if obj(record, "release") is not None and named != text(
        record, "modification_request", "message_id"
    ):
        problems.append(
            ("/release/request_id", "a modification is released only under its new request")
        )
    return problems


def _judgment(record: Mapping[str, Any], outcome: str | None) -> list[tuple[str, str]]:
    inputs = array(record, "inputs")
    all_aarm = text(record, "role") == "judgment-source"
    required = [
        index
        for index, item in enumerate(inputs)
        if text(item, "aarm_requirement") in JUDGMENT_REQUIREMENTS
        or (all_aarm and text(item, "aarm_requirement") is not None)
    ]
    problems = input_problems(inputs, outcome, judgment_required=required)
    # AB1-006: these classes hold in every decision basis that the record holds, the modification
    # response's included, whose admit releases the modified action (AB1-004).
    problems += basis_class_problems(
        record,
        ("modification_response",),
        {
            input_key(name): "judgment"
            for index in required
            if (name := text(inputs[index], "input")) is not None
        },
    )
    if all_aarm:
        # AB1-006: the AARM decision is an input of the decision in this role; an unlabelled one
        # would escape the class check above.
        decisions = [
            index
            for index, item in enumerate(inputs)
            if text(item, "aarm_requirement") == DECISION_REQUIREMENT
        ]
        if not decisions:
            problems.append(("/inputs", "the inputs do not list the AARM decision as an R4 input"))
        problems.extend(
            (
                f"/inputs/{index}/aarm_requirement",
                "the inputs list the AARM decision more than once",
            )
            for index in decisions[1:]
        )
    return problems


def _receipt(record: Mapping[str, Any], candidates: list[Exchange]) -> list[tuple[str, str]]:
    receipt = obj(record, "receipt")
    terminal = obj(record, "terminal")
    values = extension_values(terminal, RECEIPT_EXTENSION)
    if receipt is None and not values:
        return []
    if receipt is None:
        return [("/receipt", "the terminal event binds a receipt that the record does not retain")]
    if len(values) != 1:
        return [("/terminal/extensions", "the terminal event binds the receipt exactly once")]
    value = values[0]
    problems: list[tuple[str, str]] = []
    if value.get("receipt_id") != receipt.get("receipt_id"):
        problems.append(("/terminal/extensions", "the bound receipt_id is not the receipt's"))
    try:
        expected = jcs.digest(receipt)
    except jcs.JcsError:
        expected = None
    if expected is None or not same_digest(value.get("receipt_digest"), expected):
        problems.append(("/terminal/extensions", "the bound digest is not the receipt's"))
    recorded = member(receipt, "decision", "result")
    if value.get("decision") != recorded or recorded != text(record, "aarm_decision", "decision"):
        problems.append(("/receipt/decision", "the receipt's decision is not the AARM decision"))
    original = obj(record, "request")
    if not same_digest(
        digest_of(member(receipt, "action", "parameters")),
        member(original, "action", "parameters_digest"),
    ):
        problems.append(
            ("/receipt/action/parameters", "the receipt's parameters are not the requested ones")
        )
    actions = {text(item.request, "action", "action_id") for item in candidates}
    if text(terminal, "event", "action_id") not in actions:
        problems.append(("/terminal/event/action_id", "the receipt is bound to another action"))
    return problems


def check(record: Mapping[str, Any]) -> list[Finding]:
    """The findings of an `ecl_aarm_exchange_v1` record that its schema has accepted."""
    decision = text(record, "aarm_decision", "decision")
    candidates = exchanges(
        record, ("request", "response"), ("modification_request", "modification_response")
    )
    outcome = text(record, "response", "outcome")
    result = findings(MODIFICATION_RULE, _modification(record, decision))
    if decision in ("DEFER", "STEP_UP") and outcome in ("hold", "challenge"):
        deadline = instant(member(record, "aarm_decision", "deadline"))
        result += findings(DEFERRAL_RULE, deferral_problems(member(record, "response"), deadline))
    result += findings(JUDGMENT_RULE, _judgment(record, outcome))
    permitted = PERMITTED_OUTCOMES.get(decision or "")
    if permitted is not None and outcome not in permitted:
        result.append(
            Finding(OUTCOME_RULE, "/response/outcome", f"{decision} cannot become {outcome}")
        )
    result += findings(RELEASE_RULE, release_problems(member(record, "release"), candidates))
    result += findings(RECEIPT_RULE, _receipt(record, candidates))
    result += findings(BASIS_RULE, basis_problems(record, "aarm_requirement"))
    result += findings(BASIS_RULE, modification_basis_problems(record))
    result += findings(
        ONE_WAY_RULE,
        one_way_response_problems(
            record,
            (("request",), ("response",)),
            (("modification_request",), ("modification_response",)),
        ),
    )
    result += message_findings(
        record,
        ("request",),
        ("response",),
        ("modification_request",),
        ("modification_response",),
    )
    return result
