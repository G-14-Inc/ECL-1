/**
 * AARM-BINDING-1: an AARM control plane as the ECL Decision Layer or as a source of judgment.
 *
 * `check` reads an `ecl_aarm_exchange_v1` record (AB1-009) that its schema has accepted and reports
 * each way the exchange weakened the ECL guarantee, under the rule that the profile's requirement
 * names:
 *
 * - `ecl.rule.aarm-modification-new-request.v1` (AB1-004): a MODIFY released the original action,
 *   or its modified action was not a new request for the original's action carrying the modified
 *   parameters as the same JSON values, linked to the original by
 *   `ecl.relation.modification-of.v1` and admitted on its own; a record of a MODIFY holds a
 *   modification response without its new request; or a record of another decision holds a new
 *   request, which only a MODIFY has. A record of a MODIFY that holds neither a new request nor a
 *   release is a deny of the original;
 * - `ecl.rule.aarm-deferral-no-release.v1` (AB1-005): a hold or challenge mapped from DEFER or
 *   STEP_UP outlasts the deadline or expires into a safe state that permits a new effect;
 * - `ecl.rule.aarm-judgment-inputs.v1` (AB1-006): an R2, R3 or R7 output, or in the
 *   judgment-source role any AARM output, is not classed `judgment`; in the judgment-source role
 *   the inputs do not list the AARM decision exactly once, as an R4 input; or an `admit` rests on
 *   anything but `verifiable` inputs;
 * - `ecl.rule.aarm-outcome-no-weaker.v1` (AB1-003): the ECL outcome is weaker than the mapping;
 * - `ecl.rule.aarm-release-requires-admit.v1` (AB1-002): the action went ahead without an admit
 *   bound to the exact request, outside its window, or with other parameters;
 * - `ecl.rule.aarm-receipt-bound.v1` (AB1-007, AB1-008): the receipt and the ECL evidence that
 *   binds it disagree;
 * - `ecl.rule.aarm-inputs-match-basis.v1` (AB1-013): the record's inputs are not the inputs, classes
 *   and digests that the response records in `ecl.ext.decision-basis.v1`, or the decision basis of
 *   the modification response carries another `register` reference, compared member for member,
 *   or does not record the record's inputs with their declared class, required flag, source and
 *   `derived_from`.
 *
 * AB1-013 also holds the record's `response`, and its `modification_response`, to DCMP2-053: a
 * decision basis that one of them records and that breaks the one-way rule is reported under that
 * rule, `ecl.rule.decision-basis-one-way.v1`, which is the response's own rule and not one of the
 * profile's (`RULES`).
 *
 * The decision names are those of the pinned AARM text (ALLOW, DENY, MODIFY, STEP_UP, DEFER).
 */

import { pythonEquals } from "../json/value.js";
import type { JsonObject } from "../json/value.js";
import { inputKey } from "../semantic/rules.js";
import type { Finding } from "../semantic/rules.js";
import {
  ONE_WAY_RULE,
  OUTCOMES,
  array,
  basisClassProblems,
  basisProblems,
  at,
  deferralProblems,
  digestOf,
  exchanges,
  extensionValues,
  findings,
  inputProblems,
  instant,
  member,
  messageFindings,
  modificationBasisProblems,
  modificationProblems,
  modificationResponseProblems,
  newRequestProblems,
  obj,
  oneWayResponseProblems,
  releaseProblems,
  sameDigest,
  text,
} from "./common.js";
import type { Exchange, Problem } from "./common.js";
import { JcsError, jcsDigest } from "./jcs.js";

export const AARM_VERSION = "1.0";
export const EXCHANGE_VERSION = "ecl_aarm_exchange_v1";
export const EXCHANGE_SCHEMA = "https://externalcontrollayer.ai/ns/schema/binding/aarm-exchange/1";
export const RECEIPT_EXTENSION = "ecl.ext.aarm-receipt.v1";
/** AB1-006: the AARM requirements whose outputs are judgment in either role. */
const JUDGMENT_REQUIREMENTS = new Set(["R2", "R3", "R7"]);
/**
 * AB1-006: the requirement whose output is the AARM decision itself. In the judgment-source role the
 * inputs list it exactly once, as a judgment input.
 */
const DECISION_REQUIREMENT = "R4";
/**
 * AB1-003: the ECL outcomes no weaker than each AARM decision. MODIFY denies the original
 * request; its modified action is a new request (AB1-004).
 */
const PERMITTED_OUTCOMES: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  ["ALLOW", new Set(OUTCOMES)],
  ["DENY", new Set(["deny"])],
  ["MODIFY", new Set(["deny"])],
  ["STEP_UP", new Set(["challenge", "hold", "deny"])],
  ["DEFER", new Set(["hold", "deny"])],
]);

export const MODIFICATION_RULE = "ecl.rule.aarm-modification-new-request.v1";
export const DEFERRAL_RULE = "ecl.rule.aarm-deferral-no-release.v1";
export const JUDGMENT_RULE = "ecl.rule.aarm-judgment-inputs.v1";
export const OUTCOME_RULE = "ecl.rule.aarm-outcome-no-weaker.v1";
export const RELEASE_RULE = "ecl.rule.aarm-release-requires-admit.v1";
export const RECEIPT_RULE = "ecl.rule.aarm-receipt-bound.v1";
export const BASIS_RULE = "ecl.rule.aarm-inputs-match-basis.v1";

/** What every rule of the profile reads from one record. */
interface View {
  readonly record: JsonObject;
  readonly decision: string | null;
  readonly outcome: string | null;
  readonly candidates: readonly Exchange[];
}

function modification(view: View): Problem[] {
  const { record } = view;
  if (view.decision !== "MODIFY") {
    return newRequestProblems(record);
  }
  const request = obj(record, "request");
  if (request === null) {
    return [];
  }
  if (!Object.prototype.hasOwnProperty.call(record, "modification_request") && obj(record, "release") === null) {
    return modificationResponseProblems(record);
  }
  const problems: Problem[] = modificationProblems(request, member(record, "modification_request"), member(record, "aarm_decision", "modified_parameters")).map(
    ([path, message]): Problem => ["/" + path, message],
  );
  if (obj(record, "release") !== null && text(record, "release", "request_id") !== text(record, "modification_request", "message_id")) {
    problems.push(["/release/request_id", "a modification is released only under its new request"]);
  }
  return problems;
}

function deferral(view: View): Problem[] {
  if ((view.decision === "DEFER" || view.decision === "STEP_UP") && (view.outcome === "hold" || view.outcome === "challenge")) {
    const deadline = instant(member(view.record, "aarm_decision", "deadline"));
    return deferralProblems(member(view.record, "response"), deadline);
  }
  return [];
}

function judgment(view: View): Problem[] {
  const inputs = array(view.record, "inputs");
  const allAarm = text(view.record, "role") === "judgment-source";
  const required: number[] = [];
  inputs.forEach((item, index) => {
    const requirement = text(item, "aarm_requirement");
    if ((requirement !== null && JUDGMENT_REQUIREMENTS.has(requirement)) || (allAarm && requirement !== null)) {
      required.push(index);
    }
  });
  const problems = inputProblems(inputs, view.outcome, required);
  // AB1-006: these classes hold in every decision basis that the record holds, the modification
  // response's included, whose admit releases the modified action (AB1-004).
  const judged = new Map<string, string>();
  for (const index of required) {
    const name = text(inputs[index], "input");
    if (name !== null) {
      judged.set(inputKey(name), "judgment");
    }
  }
  problems.push(...basisClassProblems(view.record, ["modification_response"], judged));
  if (allAarm) {
    // AB1-006: the AARM decision is an input of the decision in this role; an unlabelled one would
    // escape the class check above.
    const decisions: number[] = [];
    inputs.forEach((item, index) => {
      if (text(item, "aarm_requirement") === DECISION_REQUIREMENT) {
        decisions.push(index);
      }
    });
    if (decisions.length === 0) {
      problems.push(["/inputs", "the inputs do not list the AARM decision as an R4 input"]);
    }
    for (const index of decisions.slice(1)) {
      problems.push([`/inputs/${index}/aarm_requirement`, "the inputs list the AARM decision more than once"]);
    }
  }
  return problems;
}

function outcomeNoWeaker(view: View): Problem[] {
  const permitted = PERMITTED_OUTCOMES.get(view.decision ?? "");
  if (permitted !== undefined && (view.outcome === null || !permitted.has(view.outcome))) {
    return [["/response/outcome", `${String(view.decision)} cannot become ${view.outcome === null ? "None" : view.outcome}`]];
  }
  return [];
}

function release(view: View): Problem[] {
  return releaseProblems(member(view.record, "release"), view.candidates);
}

function receipt(view: View): Problem[] {
  const { record } = view;
  const retained = obj(record, "receipt");
  const terminal = obj(record, "terminal");
  const values = extensionValues(terminal, RECEIPT_EXTENSION);
  if (retained === null && values.length === 0) {
    return [];
  }
  if (retained === null) {
    return [["/receipt", "the terminal event binds a receipt that the record does not retain"]];
  }
  if (values.length !== 1) {
    return [["/terminal/extensions", "the terminal event binds the receipt exactly once"]];
  }
  const value = values[0] as JsonObject;
  const problems: Problem[] = [];
  if (!pythonEquals(at(value, "receipt_id"), at(retained, "receipt_id"))) {
    problems.push(["/terminal/extensions", "the bound receipt_id is not the receipt's"]);
  }
  let expected: JsonObject | null;
  try {
    expected = jcsDigest(retained);
  } catch (error) {
    if (!(error instanceof JcsError)) {
      throw error;
    }
    expected = null;
  }
  if (expected === null || !sameDigest(at(value, "receipt_digest"), expected)) {
    problems.push(["/terminal/extensions", "the bound digest is not the receipt's"]);
  }
  const recorded = member(retained, "decision", "result");
  if (!pythonEquals(at(value, "decision"), recorded) || !pythonEquals(recorded, text(record, "aarm_decision", "decision"))) {
    problems.push(["/receipt/decision", "the receipt's decision is not the AARM decision"]);
  }
  const original = obj(record, "request");
  if (!sameDigest(digestOf(member(retained, "action", "parameters")), member(original, "action", "parameters_digest"))) {
    problems.push(["/receipt/action/parameters", "the receipt's parameters are not the requested ones"]);
  }
  const actions = new Set(view.candidates.map((item) => text(item.request, "action", "action_id")));
  if (!actions.has(text(terminal, "event", "action_id"))) {
    problems.push(["/terminal/event/action_id", "the receipt is bound to another action"]);
  }
  return problems;
}

/**
 * The rules of the profile, in the order the reference reports them. A rule added to the
 * registry for this profile is one function above and one row here.
 */
export const RULES: ReadonlyArray<readonly [string, (view: View) => Problem[]]> = [
  [MODIFICATION_RULE, modification],
  [DEFERRAL_RULE, deferral],
  [JUDGMENT_RULE, judgment],
  [OUTCOME_RULE, outcomeNoWeaker],
  [RELEASE_RULE, release],
  [RECEIPT_RULE, receipt],
  [BASIS_RULE, (view) => [...basisProblems(view.record, "aarm_requirement"), ...modificationBasisProblems(view.record)]],
];

/** The findings of an `ecl_aarm_exchange_v1` record that its schema has accepted. */
export function check(record: JsonObject): Finding[] {
  const view: View = {
    record,
    decision: text(record, "aarm_decision", "decision"),
    outcome: text(record, "response", "outcome"),
    candidates: exchanges(record, ["request", "response"], ["modification_request", "modification_response"]),
  };
  return [
    ...RULES.flatMap(([rule, problems]) => findings(rule, problems(view))),
    ...findings(ONE_WAY_RULE, oneWayResponseProblems(record, [["request"], ["response"]], [["modification_request"], ["modification_response"]])),
    ...messageFindings(record, ["request"], ["response"], ["modification_request"], ["modification_response"]),
  ];
}
