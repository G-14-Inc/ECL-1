/**
 * Plain-language explanations of verdicts, envelope statuses and finding codes, for people who
 * read a verification report. The registered identifiers stay authoritative; these texts only
 * explain them. A code without its own text falls back to its registry description.
 */

import { ERROR_CODES, SEMANTIC_RULES } from "../generated/registries.js";
import type { Verdict } from "./verify.js";

export interface Explanation {
  /** A short label. */
  readonly title: string;
  /** One or more plain sentences. */
  readonly text: string;
}

const VERDICTS: Record<Verdict, Explanation> = {
  verified: {
    title: "Verified",
    text:
      "The records passed the checks for the options you chose. " +
      "See Scope for what was checked and the report for any current trust failure you accepted. " +
      "Passing these checks does not prove that the statements are true or that an action happened.",
  },
  invalid: {
    title: "Invalid",
    text:
      "At least one check of the supplied evidence failed. The findings identify the failing checks. " +
      "Do not rely on this evidence as a verified account of what happened.",
  },
  incomplete: {
    title: "Incomplete",
    text:
      "Some records are missing. This may be a file the package needs, an earlier linked record, or the final record for a request or action attempt. " +
      "Ask the producer for the missing records, then verify again.",
  },
  "current-trust-failed": {
    title: "Current trust failed",
    text:
      "The checks on the original records passed, but your current trust policy rejects a required signing key at the evaluation time, or the package has expired. " +
      "The primary finding names the first reason; the report gives the key and its role when a key is involved. " +
      "You can explicitly accept a current trust failure for a signing key. The report records that choice. It cannot waive package expiry or fix evidence that failed its historical checks.",
  },
};

const CODES: Record<string, Explanation> = {
  valid: { title: "Valid", text: "The check passed." },
  "ecl.error.schema-invalid.v1": {
    title: "Structure not valid",
    text: "An object does not have the structure its schema requires: a member is missing, has the wrong type or form, or is not allowed.",
  },
  "ecl.error.semantic-invalid.v1": {
    title: "Rule broken",
    text: "An object is well formed but breaks a rule of the protocol, for example a missing or misplaced outcome reason, or an observation that is not a verification event.",
  },
  "ecl.error.integrity-invalid.v1": {
    title: "Integrity check failed",
    text: "A payload, digest or signature does not verify: the bytes changed after signing, the payload is not in canonical form, or no trusted signature covers it.",
  },
  "ecl.error.signature-policy-invalid.v1": {
    title: "Signature not acceptable under the trust policy",
    text: "A signature cannot count: its key is unknown to the trust policy, is trusted for another purpose or another principal, or the object names a trust-policy version that you did not supply.",
  },
  "ecl.error.revoked.v1": {
    title: "Key revoked",
    text: "A signing key had been revoked at the time that matters: the object's own time for historical validity, or the evaluation time for current status.",
  },
  "ecl.error.expired.v1": {
    title: "Outside the validity window",
    text: "A key, an authorization or an offline package was outside its validity window at the time that matters.",
  },
  "ecl.error.request-binding-invalid.v1": {
    title: "Response does not match its request",
    text: "A decision response does not answer the request it names, or grants authority that differs from what the request asked for.",
  },
  "ecl.error.decision-binding-invalid.v1": {
    title: "Event does not match its decision",
    text: "An evidence event does not belong to the request, decision or authority it records, objects are paired more than once, or an event's state contradicts the decision.",
  },
  "ecl.error.digest-mismatch.v1": {
    title: "Digest does not match",
    text: "A reference names an object by a digest that is not that object's digest, so the reference points at different content.",
  },
  "ecl.error.audience-mismatch.v1": {
    title: "Wrong audience",
    text: "The authorization was granted for an audience other than the one the request asked for.",
  },
  "ecl.error.scope-mismatch.v1": {
    title: "Wrong scope",
    text: "The authorization's scope digest is not the digest of the request's action, so it may authorize a different action.",
  },
  "ecl.error.trusted-time-required.v1": {
    title: "Trusted time required",
    text: "The verification profile requires a trusted-time attestation, but no acceptable attestation was established for a signature that required one.",
  },
  "ecl.error.trusted-time-invalid.v1": {
    title: "Trusted time not valid",
    text: "A trusted-time countersignature does not verify, covers another payload or signature set, comes from the object's own signer, or attests a time earlier than the object's own time.",
  },
  "ecl.error.causal-closure-incomplete.v1": {
    title: "Record incomplete",
    text: "Required package material or causal history is missing, or a request or action attempt has no terminal state.",
  },
  "ecl.rule.decision-basis-one-way.v1": {
    title: "Decision rests on an input that cannot support it",
    text:
      "A decision response's record of its inputs breaks the one-way rule. An input that is not verifiable, or that was not available, is recorded as supporting the outcome; an admit names no verifiable input that supports it, or a required input was missing; an input is listed twice; or an input computed from one that is not verifiable is declared verifiable.",
  },
  "ecl.rule.decision-basis-required.v1": {
    title: "Decision basis missing",
    text:
      "A decision response does not record its decision basis: the register version it was made under and the decision inputs it consulted. ECL-1 requires every decision response to carry one.",
  },
  "ecl.rule.prerelease-obligations-discharged.v1": {
    title: "Obligation before release not discharged",
    text:
      "A release rests on a decision that left an obligation to enforcement before the release, such as an approval or a state witness to check, and the release does not record a discharge of it. Or a recorded discharge names an obligation that the decision does not carry, was checked after the release or before the decision, has a proof obtained after the check or issued by the requesting agent, or names an object of the bundle by another digest.",
  },
  "ecl.rule.decision-basis-matches-register.v1": {
    title: "Decision basis does not match the register",
    text:
      "A decision response's record of its inputs does not match the Consequential Action Register you supplied. It names another register or another version of it, lists an input that the register does not declare for the action, leaves out a declared input, or gives a class, required flag or source other than the declared one.",
  },
};

function registryDescription(code: string): string | undefined {
  return [...ERROR_CODES, ...SEMANTIC_RULES].find((entry) => entry.id === code)?.description;
}

/** The plain-language explanation of a verdict. */
export function describeVerdict(verdict: Verdict): Explanation {
  return VERDICTS[verdict];
}

/** The plain-language explanation of a status or finding code. */
export function describeCode(code: string): Explanation {
  const known = CODES[code];
  if (known !== undefined) {
    return known;
  }
  const description = registryDescription(code);
  if (description !== undefined) {
    return { title: code, text: description };
  }
  return { title: code, text: "A registered rule or error identifier." };
}
