"""Causal-closure and execution-state analysis for EBMP-2 bundles."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .canonical import CanonicalizationError, object_digest
from .semantic import Finding

TERMINAL_STATES = frozenset(
    {
        "succeeded",
        "failed",
        "partially_succeeded",
        "cancelled",
        "timed_out",
        "rolled_back",
        "compensated",
        "unknown",
        "denied",
        "held",
        "challenged",
        "expired_before_release",
    }
)

ALLOWED_EXECUTION_TRANSITIONS = {
    "not_started": {"prepared", "denied", "held", "challenged", "expired_before_release"},
    "prepared": {
        "released",
        "cancelled",
        "timed_out",
        "denied",
        "held",
        "expired_before_release",
    },
    "released": {
        "running",
        "succeeded",
        "failed",
        "partially_succeeded",
        "cancelled",
        "timed_out",
        "unknown",
    },
    "running": {
        "succeeded",
        "failed",
        "partially_succeeded",
        "cancelled",
        "timed_out",
        "rolled_back",
        "compensated",
        "unknown",
    },
}

MAX_BUNDLE_RECORDS = 1_000_000
MAX_PREDECESSORS_PER_RECORD = 128
# EBMP2-077: a predecessor that the bundle holds has its successor's root trace and is in its
# successor's workflow, with an attempt no greater, or in the workflow its successor names as
# its parent.
CONTEXT_RULE = "ecl.rule.bundle-causal-context-consistent.v1"


def _identity(record: dict[str, Any], members: tuple[str, ...]) -> Any:
    """The record's identifier: the first of `members` that it carries."""
    for member in members:
        if member in record:
            return record[member]
    return None


def _attempt(workflow: dict[str, Any]) -> int | None:
    value = workflow.get("attempt")
    return value if type(value) is int else None


def _context_consistent(prior: dict[str, Any], workflow: dict[str, Any]) -> bool:
    """EBMP2-077 for one predecessor that the bundle holds."""
    prior_workflow = prior.get("workflow")
    if not isinstance(prior_workflow, dict):
        return False
    if prior_workflow.get("root_trace_id") != workflow.get("root_trace_id"):
        return False
    if prior_workflow.get("workflow_id") == workflow.get("workflow_id"):
        before, after = _attempt(prior_workflow), _attempt(workflow)
        return before is not None and after is not None and before <= after
    parent = workflow.get("parent_workflow_id")
    return isinstance(parent, str) and prior_workflow.get("workflow_id") == parent


# A declared limit of the analysis (IE1-028, EBMP2-062).
RESOURCE_LIMIT = "ecl.error.resource-limit-exceeded.v1"


@dataclass(frozen=True)
class BundleAnalysis:
    status: str
    terminal_action_ids: tuple[str, ...]
    open_action_ids: tuple[str, ...]
    unresolved_predecessor_ids: tuple[str, ...]
    findings: tuple[Finding, ...]


def _sequence(
    record: dict[str, Any],
    *,
    path: str,
    findings: list[Finding],
) -> int:
    workflow = record.get("workflow")
    if not isinstance(workflow, dict):
        findings.append(
            Finding(
                "ecl.error.schema-invalid.v1",
                path + "/workflow",
                "workflow must be an object",
            )
        )
        return 0
    value = workflow.get("sequence")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        findings.append(
            Finding(
                "ecl.error.schema-invalid.v1",
                path + "/workflow/sequence",
                "workflow sequence must be a non-negative integer",
            )
        )
        return 0
    return value


def _execution(
    records: Iterable[dict[str, Any]],
    findings: list[Finding],
) -> dict[tuple[str, str], list[dict]]:
    grouped: dict[tuple[str, str], list[dict]] = {}
    for index, record in enumerate(records):
        event = record.get("event") or {}
        if not isinstance(event, dict):
            findings.append(
                Finding(
                    "ecl.error.schema-invalid.v1",
                    f"/records/{index}/event",
                    "event must be an object",
                )
            )
            continue
        if event.get("kind") != "execution":
            continue
        action_id = event.get("action_id")
        attempt_id = event.get("attempt_id")
        if not isinstance(action_id, str) or not isinstance(attempt_id, str):
            findings.append(
                Finding(
                    "ecl.error.schema-invalid.v1",
                    f"/records/{index}/event",
                    "execution event requires string action_id and attempt_id",
                )
            )
            continue
        key = (action_id, attempt_id)
        grouped.setdefault(key, []).append(record)
    for values in grouped.values():
        values.sort(
            key=lambda item: (
                _sequence(
                    item,
                    path="/records",
                    findings=findings,
                ),
                str(item.get("object_id")),
            )
        )
    return grouped


def _cycle_findings(edges: dict[str, set[str]]) -> list[Finding]:
    findings: list[Finding] = []
    state: dict[str, int] = {}
    reported: set[tuple[str, ...]] = set()
    for start in sorted(edges):
        if state.get(start, 0):
            continue
        state[start] = 1
        path = [start]
        positions = {start: 0}
        stack: list[tuple[str, Any]] = [(start, iter(sorted(edges.get(start, ()))))]
        while stack:
            node, predecessors = stack[-1]
            try:
                predecessor = next(predecessors)
            except StopIteration:
                stack.pop()
                state[node] = 2
                positions.pop(node, None)
                path.pop()
                continue
            if predecessor not in edges:
                continue
            predecessor_state = state.get(predecessor, 0)
            if predecessor_state == 0:
                state[predecessor] = 1
                positions[predecessor] = len(path)
                path.append(predecessor)
                stack.append(
                    (
                        predecessor,
                        iter(sorted(edges.get(predecessor, ()))),
                    )
                )
                continue
            if predecessor_state != 1:
                continue
            cycle = tuple(path[positions[predecessor] :] + [predecessor])
            canonical = min(
                tuple(cycle[index:-1] + cycle[:index] + (cycle[index],))
                for index in range(len(cycle) - 1)
            )
            if canonical in reported:
                continue
            reported.add(canonical)
            display = list(cycle)
            if len(display) > 18:
                display = display[:8] + ["..."] + display[-8:]
            findings.append(
                Finding(
                    "ecl.rule.bundle-causal-graph-acyclic.v1",
                    "/workflow/causal_predecessors",
                    "causal cycle: " + " -> ".join(display),
                )
            )
    return findings


def analyze_bundle(
    records: Iterable[dict[str, Any]],
    *,
    allowed_external_predecessors: Iterable[str] = (),
    max_records: int = MAX_BUNDLE_RECORDS,
    max_predecessors_per_record: int = MAX_PREDECESSORS_PER_RECORD,
    identifier_members: tuple[str, ...] = ("object_id",),
    check_context: bool = False,
) -> BundleAnalysis:
    """The causal closure and execution-state analysis of records (EBMP-2 section 4). A record's
    identifier is the first of `identifier_members` that it carries, so that the bundle verifier
    can analyze DCMP-2 messages (`message_id`) and EBMP-2 records (`object_id`) as one graph
    (EBMP2-059); `check_context` applies EBMP2-077 to each predecessor that the records hold."""
    # IE1-028: each limit is an integer of at least 1, checked by type, since NaN, an infinity, a
    # fraction or a bool would pass a comparison and turn a finite limit into none.
    for limit in (max_records, max_predecessors_per_record):
        if type(limit) is not int or limit < 1:
            raise ValueError("bundle resource limits must be integers of at least 1")
    values: list[dict[str, Any]] = []
    findings: list[Finding] = []
    for index, record in enumerate(records):
        if index >= max_records:
            findings.append(
                Finding(
                    RESOURCE_LIMIT,
                    "/records",
                    "bundle record count exceeds the verifier budget",
                )
            )
            break
        if not isinstance(record, dict):
            findings.append(
                Finding(
                    "ecl.error.schema-invalid.v1",
                    f"/records/{index}",
                    "bundle record must be an object",
                )
            )
            continue
        values.append(record)
    by_id: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(values):
        object_id = _identity(record, identifier_members)
        if not isinstance(object_id, str) or not object_id:
            findings.append(
                Finding(
                    "ecl.rule.bundle-object-identifiers-unique.v1",
                    f"/records/{index}/object_id",
                    "bundle record is missing object_id",
                )
            )
            continue
        if object_id in by_id:
            findings.append(
                Finding(
                    "ecl.rule.bundle-object-identifiers-unique.v1",
                    f"/records/{index}/object_id",
                    f"duplicate object_id {object_id}",
                )
            )
            continue
        by_id[object_id] = record

    external = set(allowed_external_predecessors)
    unresolved: set[str] = set()
    edges: dict[str, set[str]] = {identifier: set() for identifier in by_id}
    for object_id, record in by_id.items():
        path = f"/records/{object_id}"
        sequence = _sequence(record, path=path, findings=findings)
        workflow = record.get("workflow")
        if not isinstance(workflow, dict):
            continue
        predecessors = workflow.get("causal_predecessors") or []
        if not isinstance(predecessors, list):
            findings.append(
                Finding(
                    "ecl.error.schema-invalid.v1",
                    path + "/workflow/causal_predecessors",
                    "causal_predecessors must be an array",
                )
            )
            continue
        if len(predecessors) > max_predecessors_per_record:
            findings.append(
                Finding(
                    RESOURCE_LIMIT,
                    path + "/workflow/causal_predecessors",
                    "predecessor count exceeds the verifier budget",
                )
            )
            predecessors = predecessors[:max_predecessors_per_record]
        for predecessor in predecessors:
            if not isinstance(predecessor, dict):
                findings.append(
                    Finding(
                        "ecl.error.schema-invalid.v1",
                        path + "/workflow/causal_predecessors",
                        "causal predecessor must be an object",
                    )
                )
                continue
            predecessor_id = predecessor.get("id")
            if not isinstance(predecessor_id, str) or not predecessor_id:
                findings.append(
                    Finding(
                        "ecl.error.schema-invalid.v1",
                        path + "/workflow/causal_predecessors",
                        "causal predecessor requires a non-empty string id",
                    )
                )
                continue
            edges[object_id].add(predecessor_id)
            prior = by_id.get(predecessor_id)
            if prior is None:
                if predecessor_id not in external:
                    unresolved.add(predecessor_id)
                continue
            expected_digest = predecessor.get("digest") or {}
            try:
                digest_matches = (
                    isinstance(expected_digest, dict)
                    and expected_digest.get("algorithm") == "ecl.digest.sha-256.v1"
                    and expected_digest.get("value") == object_digest(prior)
                )
            except (CanonicalizationError, RecursionError, TypeError, ValueError):
                digest_matches = False
            if not digest_matches:
                findings.append(
                    Finding(
                        "ecl.rule.bundle-predecessor-digest-valid.v1",
                        f"/records/{object_id}/workflow/causal_predecessors",
                        f"predecessor digest mismatch for {predecessor_id}",
                    )
                )
            prior_sequence = _sequence(
                prior,
                path=f"/records/{predecessor_id}",
                findings=findings,
            )
            prior_workflow = prior.get("workflow")
            same_workflow = isinstance(prior_workflow, dict) and prior_workflow.get(
                "workflow_id"
            ) == workflow.get("workflow_id")
            if check_context and not _context_consistent(prior, workflow):
                findings.append(
                    Finding(
                        CONTEXT_RULE,
                        f"/records/{object_id}/workflow/causal_predecessors",
                        f"predecessor {predecessor_id} is outside the causal context of {object_id}",
                    )
                )
            if same_workflow and prior_sequence >= sequence:
                findings.append(
                    Finding(
                        "ecl.rule.bundle-causal-sequence-monotonic.v1",
                        f"/records/{object_id}/workflow/sequence",
                        f"predecessor {predecessor_id} does not precede {object_id}",
                    )
                )
    findings.extend(_cycle_findings(edges))

    terminal_actions: set[str] = set()
    open_actions: set[str] = set()
    for (action_id, attempt_id), attempt_records in _execution(
        values,
        findings,
    ).items():
        states = [str((item.get("event") or {}).get("state")) for item in attempt_records]
        for prior_state, current_state in zip(states, states[1:]):
            if (
                prior_state in TERMINAL_STATES
                or current_state
                not in ALLOWED_EXECUTION_TRANSITIONS.get(
                    prior_state,
                    set(),
                )
            ):
                findings.append(
                    Finding(
                        "ecl.rule.execution-state-transition-valid.v1",
                        f"/attempts/{attempt_id}",
                        f"invalid execution transition {prior_state} -> {current_state}",
                    )
                )
        if states and states[-1] in TERMINAL_STATES:
            terminal_actions.add(action_id)
        else:
            open_actions.add(action_id)

    if unresolved or open_actions:
        status = "incomplete"
    elif findings:
        status = "indeterminate"
    else:
        status = "complete"
    return BundleAnalysis(
        status=status,
        terminal_action_ids=tuple(sorted(terminal_actions)),
        open_action_ids=tuple(sorted(open_actions)),
        unresolved_predecessor_ids=tuple(sorted(unresolved)),
        findings=tuple(sorted(findings, key=lambda item: (item.rule_id, item.path, item.message))),
    )
