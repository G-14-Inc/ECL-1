/**
 * Verification from files' bytes, with the byte limits that TRUST-POLICY-1 sets for a verifier
 * interface (TP1-007): each trust policy at most 256 KiB, the evidence bundle at most 1 MiB,
 * enforced before parsing; a Consequential Action Register, when the caller gives one, at most
 * 1 MiB. This is what the command-line verifier and the browser verifier call. Every refusal at a
 * byte limit carries the registered code `ecl.error.resource-limit-exceeded.v1` (TP1-007), as the
 * strict parser's own budgets do.
 */

import { parseStrictJson, RESOURCE_LIMIT, StrictJsonError } from "../json/strict.js";
import type { JsonObject, JsonValue } from "../json/value.js";
import { MAX_TRUST_POLICY_BYTES, TrustPolicy, TrustPolicyError } from "../trust/policy.js";
import { REGISTER_DOCUMENT_RULE, registerSchemaProblems } from "./decision-basis.js";
import { registerDocumentProblems } from "../semantic/rules.js";
import { verifyBundle } from "./verify.js";
import type { BundleReport } from "./verify.js";

export const MAX_BUNDLE_BYTES = 1024 * 1024;
export const MAX_REGISTER_BYTES = 1024 * 1024;

/** A usage error: an input that cannot be verified at all (the reference CLI exits with 2). */
export class VerifierInputError extends Error {
  /** The registered code of the underlying refusal, when there is one. */
  readonly code: string | undefined;

  constructor(message: string, code?: string) {
    super(message);
    this.name = "VerifierInputError";
    this.code = code;
  }
}

/**
 * The refusal of an input file above its byte limit (TP1-007), before it is parsed: a usage error
 * with the registered code `ecl.error.resource-limit-exceeded.v1`. `label` names the limit, as
 * "256 KiB".
 */
export function oversizedInput(kind: string, label: string): VerifierInputError {
  return new VerifierInputError(`${kind} file exceeds the ${label} limit`, RESOURCE_LIMIT);
}

export interface BytesOptions {
  readonly now: string;
  readonly history?: readonly Uint8Array[];
  readonly acceptCurrentTrustFailure?: boolean;
  readonly requireTrustedTime?: boolean;
  /** The bytes of a Consequential Action Register to check each decision basis against. */
  readonly register?: Uint8Array;
}

/**
 * A register document from its bytes: strict JSON that satisfies the register schema and
 * `ecl.rule.register-declarations-consistent.v1`, so that no action class and no input of a class
 * is declared twice (DCMP2-053, ECL1N-0178). Anything else is a usage error.
 */
export function loadRegister(data: Uint8Array): JsonValue {
  if (data.length > MAX_REGISTER_BYTES) {
    throw oversizedInput("register", "1 MiB");
  }
  let value: JsonValue;
  try {
    value = parseStrictJson(data, { maxBytes: MAX_REGISTER_BYTES });
  } catch (error) {
    if (error instanceof StrictJsonError) {
      throw new VerifierInputError("malformed register: the register is not strict JSON", error.ruleId);
    }
    throw error;
  }
  const problems = registerSchemaProblems(value);
  if (problems.length > 0) {
    throw new VerifierInputError(`malformed register: the register does not satisfy its schema: ${problems[0] as string}`, "ecl.error.schema-invalid.v1");
  }
  const inconsistent = registerDocumentProblems(value as JsonObject);
  if (inconsistent.length > 0) {
    const [path, message] = inconsistent[0] as [string, string];
    throw new VerifierInputError(`malformed register: the register breaks ${REGISTER_DOCUMENT_RULE}: ${path}: ${message}`);
  }
  return value;
}

/** A trust policy from its bytes; anything that is not one is a usage error with its code. */
export function loadPolicyBytes(data: Uint8Array, kind: string): TrustPolicy {
  if (data.length > MAX_TRUST_POLICY_BYTES) {
    throw oversizedInput(kind, "256 KiB");
  }
  try {
    return TrustPolicy.load(data);
  } catch (error) {
    if (error instanceof TrustPolicyError) {
      throw new VerifierInputError(`malformed ${kind}: ${error.message}`, error.code);
    }
    throw error;
  }
}

/** Verify a bundle file against a trust policy file (and earlier versions of it). */
export function verifyBundleBytes(bundle: Uint8Array, trustPolicy: Uint8Array, options: BytesOptions): { report: BundleReport; policy: TrustPolicy } {
  const policy = loadPolicyBytes(trustPolicy, "trust policy");
  const history = (options.history ?? []).map((data) => loadPolicyBytes(data, "trust policy history"));
  const register = options.register === undefined ? undefined : loadRegister(options.register);
  if (bundle.length > MAX_BUNDLE_BYTES) {
    throw oversizedInput("bundle", "1 MiB");
  }
  let value;
  try {
    value = parseStrictJson(bundle, { maxBytes: MAX_BUNDLE_BYTES });
  } catch (error) {
    if (error instanceof StrictJsonError) {
      throw new VerifierInputError(`malformed bundle JSON: ${error.message}`, error.ruleId);
    }
    throw error;
  }
  try {
    const report = verifyBundle(value, policy, {
      now: options.now,
      history,
      acceptCurrentTrustFailure: options.acceptCurrentTrustFailure === true,
      requireTrustedTime: options.requireTrustedTime === true,
      ...(register === undefined ? {} : { register }),
    });
    return { report, policy };
  } catch (error) {
    if (error instanceof RangeError) {
      throw new VerifierInputError(`invalid evaluation time: ${error.message}`);
    }
    throw error;
  }
}
