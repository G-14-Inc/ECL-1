/**
 * The STRICT-FAILURE-1 checks of a safe-state profile: the loss of a dependency that supplies
 * required proof blocks the effect, and a profile that claims STRICT-FAILURE-1 in
 * `claimed_profiles` (SF1-004; its name decides nothing) declares no `fail_open` disposition.
 */

import { get, inList, isArray, isObject, isString, pythonEquals } from "../json/value.js";
import type { JsonValue } from "../json/value.js";
import type { Finding } from "./rules.js";

export const PROOF_RULE = "ecl.rule.required-proof-dependency-fails-closed.v1";
export const CLASSIFICATION_RULE = "ecl.rule.dependency-classification-consistent.v1";
export const STRICT_RULE = "ecl.rule.strict-profile-forbids-fail-open.v1";
export const ACTION_CLASS_RULE = "ecl.rule.action-class-policy-unambiguous.v1";
export const STRICT_PROFILE = "STRICT-FAILURE-1";
const CLOSED_DISPOSITIONS = new Set(["fail_closed", "quarantine", "emergency_halt"]);
const ACTION_DISPOSITIONS = [
  "timeout_disposition",
  "dependency_disposition",
  "stale_dependency_disposition",
  "buffer_exhaustion_disposition",
];

/** The findings of the declared dispositions, in the reference's order. */
export function validateSafeStateProfile(value: JsonValue): Finding[] {
  const findings: Finding[] = [];
  const claimed = get(value, "claimed_profiles");
  const strict = isArray(claimed) && inList(STRICT_PROFILE, claimed);
  const dependencies = get(value, "dependencies");
  const declared = new Map<string, JsonValue | undefined>();
  if (isArray(dependencies)) {
    dependencies.forEach((dependency, index) => {
      if (!isObject(dependency)) {
        return;
      }
      const identifier = get(dependency, "id");
      if (isString(identifier)) {
        if (declared.has(identifier)) {
          findings.push({ ruleId: CLASSIFICATION_RULE, path: `/dependencies/${index}/id`, message: "a dependency identifier is declared more than once" });
          declared.set(identifier, undefined);
        } else { declared.set(identifier, dependency); }
      }
      const disposition = get(dependency, "loss_disposition");
      const path = `/dependencies/${index}/loss_disposition`;
      if (pythonEquals(get(dependency, "class"), "advisory") && get(dependency, "supplies_required_proof") === true) {
        findings.push({ ruleId: CLASSIFICATION_RULE, path: `/dependencies/${index}/class`, message: "an advisory dependency cannot supply required proof" });
      }
      if (get(dependency, "supplies_required_proof") === true && (!isString(disposition) || !CLOSED_DISPOSITIONS.has(disposition))) {
        findings.push({ ruleId: PROOF_RULE, path, message: "required-proof loss must block the effect" });
      }
      if (strict && pythonEquals(disposition, "fail_open")) {
        findings.push({ ruleId: STRICT_RULE, path, message: "strict failure forbids fail_open" });
      }
    });
  }
  const classes = get(value, "action_classes");
  if (isArray(classes)) {
    const declaredClasses = new Set<string>();
    classes.forEach((action, index) => {
      if (!isObject(action)) {
        return;
      }
      const identifier = get(action, "action_class");
      if (isString(identifier)) {
        if (declaredClasses.has(identifier)) findings.push({ ruleId: ACTION_CLASS_RULE, path: `/action_classes/${index}/action_class`, message: "an action class is declared more than once" });
        declaredClasses.add(identifier);
      }
      const authorization = get(action, "fail_open_authorization");
      if (isObject(authorization)) {
        const covered = get(authorization, "covered_advisory_dependencies");
        const base = `/action_classes/${index}/fail_open_authorization/covered_advisory_dependencies`;
        if (!isArray(covered) || covered.length === 0) {
          findings.push({ ruleId: CLASSIFICATION_RULE, path: base, message: "fail-open authorization names its covered advisory dependencies" });
        } else {
          const seen = new Set<string>();
          covered.forEach((identifier, position) => {
            const dependency = isString(identifier) ? declared.get(identifier) : undefined;
            if (!isString(identifier) || identifier.trim() === "" || seen.has(identifier) || !isObject(dependency) || get(dependency, "class") !== "advisory" || get(dependency, "supplies_required_proof") !== false) {
              findings.push({ ruleId: CLASSIFICATION_RULE, path: `${base}/${position}`, message: "fail-open coverage must name each declared advisory dependency once and none may supply required proof" });
            }
            if (isString(identifier)) seen.add(identifier);
          });
        }
      }
      if (!strict) return;
      for (const member of ACTION_DISPOSITIONS) {
        if (pythonEquals(get(action, member), "fail_open")) {
          findings.push({ ruleId: STRICT_RULE, path: `/action_classes/${index}/${member}`, message: "strict failure forbids fail_open" });
        }
      }
    });
  }
  const buffer = get(value, "evidence_buffer");
  if (strict && isObject(buffer) && pythonEquals(get(buffer, "overflow"), "fail_open")) {
    findings.push({ ruleId: STRICT_RULE, path: "/evidence_buffer/overflow", message: "strict failure forbids fail_open" });
  }
  return findings;
}
