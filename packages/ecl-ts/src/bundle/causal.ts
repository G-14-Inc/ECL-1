/**
 * Causal closure and execution-state analysis of EBMP-2 records (EBMP-2 section 4, EBMP2-022 to
 * EBMP2-029, DISTRIBUTED-WORKFLOW-1): unique object identifiers, digest-bound predecessors, an
 * acyclic graph, monotonic sequences within a workflow, and execution attempts whose states move
 * only forward. The status is `incomplete` when a predecessor is missing or an attempt has no
 * terminal state, `indeterminate` when a rule fails, and `complete` otherwise.
 */

import { CanonicalizationError, objectDigest } from "../json/canonical.js";
import { compareCodePoints, get, isArray, isInteger, isObject, pythonEquals, truthy } from "../json/value.js";
import type { JsonObject, JsonValue } from "../json/value.js";
import { str } from "../semantic/python.js";
import { sortFindings } from "../semantic/rules.js";
import type { Finding } from "../semantic/rules.js";

export const TERMINAL_STATES: ReadonlySet<string> = new Set([
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
]);

const ALLOWED_TRANSITIONS: Record<string, ReadonlySet<string>> = {
  not_started: new Set(["prepared", "denied", "held", "challenged", "expired_before_release"]),
  prepared: new Set(["released", "cancelled", "timed_out", "denied", "held", "challenged", "expired_before_release"]),
  released: new Set(["running", "succeeded", "failed", "partially_succeeded", "cancelled", "timed_out", "unknown"]),
  running: new Set(["succeeded", "failed", "partially_succeeded", "cancelled", "timed_out", "rolled_back", "compensated", "unknown"]),
};

export const MAX_BUNDLE_RECORDS = 1_000_000;
export const MAX_PREDECESSORS_PER_RECORD = 128;
const SCHEMA_INVALID = "ecl.error.schema-invalid.v1";
/** A declared limit of the analysis (IE1-028, EBMP2-062). */
const RESOURCE_LIMIT = "ecl.error.resource-limit-exceeded.v1";

/** The result of a causal analysis. */
export interface BundleAnalysis {
  readonly status: "complete" | "incomplete" | "indeterminate";
  readonly terminalActionIds: readonly string[];
  readonly openActionIds: readonly string[];
  readonly unresolvedPredecessorIds: readonly string[];
  readonly findings: readonly Finding[];
}

function sequenceOf(record: JsonObject, path: string, findings: Finding[]): number {
  const workflow = get(record, "workflow");
  if (!isObject(workflow)) {
    findings.push({ ruleId: SCHEMA_INVALID, path: path + "/workflow", message: "workflow must be an object" });
    return 0;
  }
  const value = get(workflow, "sequence");
  if (!isInteger(value) || value < 0) {
    findings.push({ ruleId: SCHEMA_INVALID, path: path + "/workflow/sequence", message: "workflow sequence must be a non-negative integer" });
    return 0;
  }
  return value;
}

function sortedIds(values: Iterable<string>): string[] {
  return [...values].sort(compareCodePoints);
}

function cycleFindings(edges: Map<string, Set<string>>): Finding[] {
  const findings: Finding[] = [];
  const state = new Map<string, number>();
  const reported = new Set<string>();
  for (const start of sortedIds(edges.keys())) {
    if ((state.get(start) ?? 0) !== 0) {
      continue;
    }
    state.set(start, 1);
    const path = [start];
    const positions = new Map<string, number>([[start, 0]]);
    const stack: Array<[string, string[], number]> = [[start, sortedIds(edges.get(start) ?? []), 0]];
    while (stack.length > 0) {
      const top = stack[stack.length - 1] as [string, string[], number];
      const [node, predecessors, next] = top;
      if (next >= predecessors.length) {
        stack.pop();
        state.set(node, 2);
        positions.delete(node);
        path.pop();
        continue;
      }
      top[2] = next + 1;
      const predecessor = predecessors[next] as string;
      if (!edges.has(predecessor)) {
        continue;
      }
      const predecessorState = state.get(predecessor) ?? 0;
      if (predecessorState === 0) {
        state.set(predecessor, 1);
        positions.set(predecessor, path.length);
        path.push(predecessor);
        stack.push([predecessor, sortedIds(edges.get(predecessor) ?? []), 0]);
        continue;
      }
      if (predecessorState !== 1) {
        continue;
      }
      const cycle = [...path.slice(positions.get(predecessor) as number), predecessor];
      // A simple DFS cycle has unique IDs, so its least rotation starts at its least ID.
      let first = 0;
      for (let index = 1; index < cycle.length - 1; index += 1) {
        if (compareCodePoints(cycle[index] as string, cycle[first] as string) < 0) first = index;
      }
      const canonical = [...cycle.slice(first, -1), ...cycle.slice(0, first), cycle[first] as string];
      const key = JSON.stringify(canonical);
      if (reported.has(key)) {
        continue;
      }
      reported.add(key);
      const display = cycle.length > 18 ? [...cycle.slice(0, 8), "...", ...cycle.slice(-8)] : cycle;
      findings.push({
        ruleId: "ecl.rule.bundle-causal-graph-acyclic.v1",
        path: "/workflow/causal_predecessors",
        message: "causal cycle: " + display.join(" -> "),
      });
    }
  }
  return findings;
}

function executionGroups(records: JsonObject[], findings: Finding[], identify: (record: JsonObject) => JsonValue | undefined): Map<string, { actionId: string; attemptId: string; records: JsonObject[] }> {
  const grouped = new Map<string, { actionId: string; attemptId: string; records: JsonObject[] }>();
  records.forEach((record, index) => {
    const rawEvent = get(record, "event");
    const event = truthy(rawEvent) ? rawEvent : {};
    if (!isObject(event)) {
      findings.push({ ruleId: SCHEMA_INVALID, path: `/records/${index}/event`, message: "event must be an object" });
      return;
    }
    if (!pythonEquals(get(event, "kind"), "execution")) {
      return;
    }
    const actionId = get(event, "action_id");
    const attemptId = get(event, "attempt_id");
    if (typeof actionId !== "string" || typeof attemptId !== "string") {
      findings.push({ ruleId: SCHEMA_INVALID, path: `/records/${index}/event`, message: "execution event requires string action_id and attempt_id" });
      return;
    }
    const key = JSON.stringify([actionId, attemptId]);
    let group = grouped.get(key);
    if (group === undefined) {
      group = { actionId, attemptId, records: [] };
      grouped.set(key, group);
    }
    group.records.push(record);
  });
  for (const group of grouped.values()) {
    // The reference computes each sort key once, recording a finding for a bad sequence.
    const keyed = group.records.map((record) => ({
      record,
      sequence: sequenceOf(record, "/records", findings),
      id: identify(record) as string,
    }));
    keyed.sort((a, b) => a.sequence - b.sequence || compareCodePoints(a.id, b.id));
    group.records = keyed.map((entry) => entry.record);
  }
  return grouped;
}

/** How `analyzeBundle` reads a graph whose nodes are not all EBMP-2 records. */
export interface AnalysisOptions {
  /**
   * The identifier of a node: by default its `object_id`. The signed bundle verifier identifies a
   * DCMP-2 message by its `message_id` (EBMP2-059), so that one graph holds every object.
   */
  readonly identify?: (record: JsonObject) => JsonValue | undefined;
  /**
   * EBMP2-077: also check that each predecessor the records hold has its successor's root trace,
   * is in its successor's workflow, its named parent, or a child with a held origin path, and has
   * no greater attempt (`ecl.rule.bundle-causal-context-consistent.v1`).
   */
  readonly causalContext?: boolean;
}

export const CAUSAL_CONTEXT_RULE = "ecl.rule.bundle-causal-context-consistent.v1";

/** EBMP2-077: why `prior` cannot be a causal predecessor of the record whose workflow is `workflow`. */
function contextProblem(workflow: JsonObject, prior: JsonObject): string | undefined {
  const priorWorkflow = get(prior, "workflow");
  if (!isObject(priorWorkflow)) {
    return "has no workflow";
  }
  if (!pythonEquals(get(priorWorkflow, "root_trace_id"), get(workflow, "root_trace_id"))) {
    return "has another root trace";
  }
  const sameWorkflow = pythonEquals(get(priorWorkflow, "workflow_id"), get(workflow, "workflow_id"));
  const parent = get(workflow, "parent_workflow_id");
  const childParent = get(priorWorkflow, "parent_workflow_id");
  if (!sameWorkflow && !(typeof parent === "string" && pythonEquals(get(priorWorkflow, "workflow_id"), parent))
      && !(typeof childParent === "string" && pythonEquals(childParent, get(workflow, "workflow_id")))) {
    return "is in a workflow that is neither its successor's, its parent, nor its child";
  }
  const attempt = get(workflow, "attempt");
  const priorAttempt = get(priorWorkflow, "attempt");
  // An attempt that is not an integer is not known to be no greater (as the reference reads it).
  if (sameWorkflow && !(isInteger(attempt) && isInteger(priorAttempt) && priorAttempt <= attempt)) {
    return "has a later attempt than its successor";
  }
  return undefined;
}

/** O(V+E) extra work: iterative multi-source propagation and shared ancestor walks.
 * childEdges already satisfy digest, root, workflow, parent, attempt and sequence constraints.
 */
function childOriginFindings(
  childEdges: ReadonlyMap<string, ReadonlySet<string>>,
  originSeeds: ReadonlySet<string>,
  missing: ReadonlyMap<string, ReadonlySet<string>>,
  parentConflicts: ReadonlyMap<string, ReadonlySet<string>>,
  joins: readonly (readonly [string, string])[],
  unresolved: Set<string>,
): Finding[] {
  const successors = new Map<string, string[]>();
  for (const [child, predecessors] of childEdges) for (const prior of predecessors) {
    const values = successors.get(prior) ?? [];
    values.push(child); successors.set(prior, values);
  }
  const propagate = (seeds: Iterable<string>): Set<string> => {
    const reached = new Set(seeds), pending = [...reached];
    for (let i = 0; i < pending.length; i += 1) {
      for (const child of successors.get(pending[i] as string) ?? []) if (!reached.has(child)) {
        reached.add(child); pending.push(child);
      }
    }
    return reached;
  };
  const originated = propagate(originSeeds), uncertain = propagate(missing.keys());
  const needed = new Set<string>(), findings: Finding[] = [];
  for (const [parent, child] of joins) {
    if (originated.has(child)) continue;
    if (uncertain.has(child)) needed.add(child);
    else findings.push({ ruleId: CAUSAL_CONTEXT_RULE, path: `/records/${parent}/workflow/causal_predecessors`, message: `child predecessor ${child} has no digest-bound origin in its declared parent workflow` });
  }
  const pending = [...needed];
  for (let i = 0; i < pending.length; i += 1) {
    const child = pending[i] as string;
    for (const missingId of missing.get(child) ?? []) unresolved.add(missingId);
    for (const prior of childEdges.get(child) ?? []) if (uncertain.has(prior) && !needed.has(prior)) {
      needed.add(prior); pending.push(prior);
    }
  }
  const ancestry = new Set(joins.map(([, child]) => child)), ancestors = [...ancestry];
  for (let i = 0; i < ancestors.length; i += 1) {
    const child = ancestors[i] as string;
    for (const prior of parentConflicts.get(child) ?? []) findings.push({ ruleId: CAUSAL_CONTEXT_RULE, path: `/records/${child}/workflow/causal_predecessors`, message: `child predecessor ${prior} changes the declared parent in joined child ancestry` });
    for (const prior of childEdges.get(child) ?? []) if (!ancestry.has(prior)) {
      ancestry.add(prior); ancestors.push(prior);
    }
  }
  return findings;
}

/** Analyze EBMP-2 records; `allowedExternalPredecessors` are identifiers outside the records that
 * may be named without making the closure incomplete. */
export function analyzeBundle(
  records: readonly JsonValue[],
  allowedExternalPredecessors: Iterable<string> = [],
  maxRecords = MAX_BUNDLE_RECORDS,
  maxPredecessorsPerRecord = MAX_PREDECESSORS_PER_RECORD,
  options: AnalysisOptions = {},
): BundleAnalysis {
  const identify = options.identify ?? ((record: JsonObject): JsonValue | undefined => get(record, "object_id"));
  // IE1-028: each limit is a safe integer of at least 1, since NaN, an infinity or a fraction
  // would pass a comparison and turn a finite limit into none.
  for (const limit of [maxRecords, maxPredecessorsPerRecord]) {
    if (!Number.isSafeInteger(limit) || limit < 1) {
      throw new Error("bundle resource limits must be integers of at least 1");
    }
  }
  const values: JsonObject[] = [];
  const findings: Finding[] = [];
  for (let index = 0; index < records.length; index += 1) {
    if (index >= maxRecords) {
      return {status: "indeterminate", terminalActionIds: [], openActionIds: [], unresolvedPredecessorIds: [], findings: [{ruleId: RESOURCE_LIMIT, path: "/records", message: "bundle record count exceeds the verifier budget"}]};
    }
    const record = records[index] as JsonValue;
    if (!isObject(record)) {
      findings.push({ ruleId: SCHEMA_INVALID, path: `/records/${index}`, message: "bundle record must be an object" });
      continue;
    }
    values.push(record);
  }
  const byId = new Map<string, JsonObject>();
  const collidingIds = new Set<string>();
  values.forEach((record, index) => {
    const objectId = identify(record);
    if (typeof objectId !== "string" || objectId === "") {
      findings.push({ ruleId: "ecl.rule.bundle-object-identifiers-unique.v1", path: `/records/${index}/object_id`, message: "bundle record is missing object_id" });
      return;
    }
    if (collidingIds.has(objectId)) return;
    if (byId.has(objectId)) {
      collidingIds.add(objectId);
      byId.delete(objectId);
      return;
    }
    byId.set(objectId, record);
  });
  for (const objectId of sortedIds(collidingIds)) findings.push({ruleId: "ecl.rule.bundle-object-identifiers-unique.v1", path: `/records/${objectId}/object_id`, message: `duplicate object_id ${objectId}`});
  const external = new Set(allowedExternalPredecessors);
  const unresolved = new Set<string>();
  const edges = new Map<string, Set<string>>();
  const childEdges = new Map<string, Set<string>>();
  const originSeeds = new Set<string>();
  const missingOrigins = new Map<string, Set<string>>();
  const parentConflicts = new Map<string, Set<string>>();
  const parentJoins: Array<[string, string]> = [];
  for (const identifier of byId.keys()) {
    edges.set(identifier, new Set());
  }
  for (const objectId of sortedIds(byId.keys())) {
    const record = byId.get(objectId) as JsonObject;
    const path = `/records/${objectId}`;
    const sequence = sequenceOf(record, path, findings);
    const workflow = get(record, "workflow");
    if (!isObject(workflow)) {
      continue;
    }
    const listed = get(workflow, "causal_predecessors");
    let predecessors = truthy(listed) ? listed : [];
    if (!isArray(predecessors)) {
      findings.push({ ruleId: SCHEMA_INVALID, path: path + "/workflow/causal_predecessors", message: "causal_predecessors must be an array" });
      continue;
    }
    if (predecessors.length > maxPredecessorsPerRecord) {
      return {status: "indeterminate", terminalActionIds: [], openActionIds: [], unresolvedPredecessorIds: [], findings: [{ruleId: RESOURCE_LIMIT, path: path + "/workflow/causal_predecessors", message: "predecessor count exceeds the verifier budget"}]};
    }
    for (const predecessor of predecessors) {
      if (!isObject(predecessor)) {
        findings.push({ ruleId: SCHEMA_INVALID, path: path + "/workflow/causal_predecessors", message: "causal predecessor must be an object" });
        continue;
      }
      const predecessorId = get(predecessor, "id");
      if (typeof predecessorId !== "string" || predecessorId === "") {
        findings.push({ ruleId: SCHEMA_INVALID, path: path + "/workflow/causal_predecessors", message: "causal predecessor requires a non-empty string id" });
        continue;
      }
      (edges.get(objectId) as Set<string>).add(predecessorId);
      if (collidingIds.has(predecessorId)) continue;
      const prior = byId.get(predecessorId);
      if (prior === undefined) {
        if (!external.has(predecessorId)) {
          unresolved.add(predecessorId);
        }
        if (options.causalContext === true && typeof get(workflow, "parent_workflow_id") === "string") {
          const missing = missingOrigins.get(objectId) ?? new Set<string>();
          missing.add(predecessorId); missingOrigins.set(objectId, missing);
        }
        continue;
      }
      const rawDigest = get(predecessor, "digest");
      const expected = truthy(rawDigest) ? rawDigest : {};
      let matches: boolean;
      try {
        matches =
          isObject(expected) &&
          pythonEquals(get(expected, "algorithm"), "ecl.digest.sha-256.v1") &&
          pythonEquals(get(expected, "value"), objectDigest(prior));
      } catch (error) {
        if (!(error instanceof CanonicalizationError)) {
          throw error;
        }
        matches = false;
      }
      if (!matches) {
        findings.push({ ruleId: "ecl.rule.bundle-predecessor-digest-valid.v1", path: `/records/${objectId}/workflow/causal_predecessors`, message: `predecessor digest mismatch for ${predecessorId}` });
      }
      const contextValid = options.causalContext === true && contextProblem(workflow, prior) === undefined;
      if (options.causalContext === true) {
        if (!contextValid) {
          findings.push({ ruleId: CAUSAL_CONTEXT_RULE, path: `/records/${objectId}/workflow/causal_predecessors`, message: `predecessor ${predecessorId} is outside the causal context of ${objectId}` });
        }
      }
      const priorSequence = sequenceOf(prior, `/records/${predecessorId}`, findings);
      const priorWorkflow = get(prior, "workflow");
      const sameWorkflow = isObject(priorWorkflow) && pythonEquals(get(priorWorkflow, "workflow_id"), get(workflow, "workflow_id"));
      if (contextValid && isObject(priorWorkflow)) {
        const parent = get(workflow, "parent_workflow_id"), priorParent = get(priorWorkflow, "parent_workflow_id");
        if (!sameWorkflow && pythonEquals(priorParent, get(workflow, "workflow_id"))) parentJoins.push([objectId, predecessorId]);
        if (matches && typeof parent === "string") {
          if (!sameWorkflow && pythonEquals(get(priorWorkflow, "workflow_id"), parent)) originSeeds.add(objectId);
          else if (sameWorkflow && pythonEquals(priorParent, parent) && priorSequence < sequence) {
            const predecessors = childEdges.get(objectId) ?? new Set<string>();
            predecessors.add(predecessorId); childEdges.set(objectId, predecessors);
          } else if (sameWorkflow && !pythonEquals(priorParent, parent)) {
            const conflicts = parentConflicts.get(objectId) ?? new Set<string>();
            conflicts.add(predecessorId); parentConflicts.set(objectId, conflicts);
          }
        }
      }
      if (sameWorkflow && priorSequence >= sequence) {
        findings.push({ ruleId: "ecl.rule.bundle-causal-sequence-monotonic.v1", path: `/records/${objectId}/workflow/sequence`, message: `predecessor ${predecessorId} does not precede ${objectId}` });
      }
    }
  }
  if (options.causalContext === true) findings.push(...childOriginFindings(childEdges, originSeeds, missingOrigins, parentConflicts, parentJoins, unresolved));
  findings.push(...cycleFindings(edges));
  const terminalActions = new Set<string>();
  const openActions = new Set<string>();
  for (const group of executionGroups([...byId.values()], findings, identify).values()) {
    const states = group.records.map((record) => {
      const rawEvent = get(record, "event");
      const event = truthy(rawEvent) ? rawEvent : {};
      return str(get(event, "state"));
    });
    let invalidTransition = false;
    for (let index = 0; index + 1 < states.length; index += 1) {
      const prior = states[index] as string;
      const current = states[index + 1] as string;
      const allowed = Object.prototype.hasOwnProperty.call(ALLOWED_TRANSITIONS, prior) ? ALLOWED_TRANSITIONS[prior] : undefined;
      if (TERMINAL_STATES.has(prior) || allowed === undefined || !allowed.has(current)) {
        invalidTransition = true;
        findings.push({ ruleId: "ecl.rule.execution-state-transition-valid.v1", path: `/attempts/${group.attemptId}`, message: `invalid execution transition ${prior} -> ${current}` });
      }
    }
    if (invalidTransition) continue;
    const last = states[states.length - 1];
    if (last !== undefined && TERMINAL_STATES.has(last)) {
      terminalActions.add(group.actionId);
    } else {
      openActions.add(group.actionId);
    }
  }
  const status = collidingIds.size > 0 ? "indeterminate" : unresolved.size > 0 || openActions.size > 0 ? "incomplete" : findings.length > 0 ? "indeterminate" : "complete";
  return {
    status,
    terminalActionIds: sortedIds(terminalActions),
    openActionIds: sortedIds(openActions),
    unresolvedPredecessorIds: sortedIds(unresolved),
    findings: sortFindings(findings),
  };
}
