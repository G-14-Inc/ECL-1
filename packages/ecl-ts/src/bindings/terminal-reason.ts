/** EBMP2-056 for binding records; bundle outcome-reason checks remain at stage 9. */
import type { JsonObject } from "../json/value.js";
import { isObject } from "../json/value.js";
import { activeErrorCodes } from "../registry/registries.js";
import type { Finding } from "../semantic/rules.js";
import { extensionEntries, text } from "./common.js";

const OUTCOME_REASON = "ecl.ext.outcome-reason.v1";
const SEMANTIC_INVALID = "ecl.error.semantic-invalid.v1";

/** Findings are relative to the terminal. Enable paired mode only when the caller has
 * established the verified response, or its absence. Intrinsic mode leaves a denied
 * terminal's response-dependent requirement to that pairing. Unknown noncritical
 * extension versions are not reinterpreted as version 1.
 */
export function terminalReasonFindings(terminal: JsonObject | null,
  responseOutcome: string | null = null, paired = false): Finding[] {
  if (terminal === null || text(terminal, "event_type") !== "execution_terminal") return [];
  const state = text(terminal, "event", "state");
  const entries = extensionEntries(terminal, OUTCOME_REASON);
  const findings: Finding[] = [];
  const add = (message: string): void => { findings.push({ ruleId: SEMANTIC_INVALID, path: "/extensions", message }); };
  if (entries.length > 1) add("a terminal has multiple outcome reasons");
  for (const entry of entries) {
    const value = entry["value"];
    if (!isObject(value) || Object.keys(value).length !== 1 || !Object.prototype.hasOwnProperty.call(value, "code")
        || typeof value["code"] !== "string" || !activeErrorCodes().has(value["code"])) {
      add("a terminal has an invalid outcome reason");
    }
  }
  if (entries.length > 0 && state === "succeeded") add("a succeeded terminal has an outcome reason");
  if (entries.length === 0 && (state === "expired_before_release"
      || (paired && state === "denied" && (responseOutcome === null || responseOutcome === "admit")))) {
    add("a terminal is missing its required outcome reason");
  }
  return findings;
}
