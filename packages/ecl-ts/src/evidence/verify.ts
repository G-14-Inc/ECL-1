/**
 * Offline verification of signed ECL evidence bundles (EBMP-2 section 11, EBMP2-057 to
 * EBMP2-062), under the reference verification profile `ecl.verification-profile.reference.v1`.
 *
 * Every envelope is evaluated twice (TRUST-POLICY-1): historical validity at the object's own
 * time under the trust-policy version the object names, or at the earliest trusted time when the
 * envelope carries valid trusted-time countersignatures (IE1-032 to IE1-035); and current status
 * at the caller's evaluation time under the caller's current policy. Objects are paired by
 * identity, never by an event's claimed decision URI; each pair is bound (DCMP-2 section 8,
 * EBMP-2 section 10); one causal graph over every object of the bundle, its DCMP-2 messages and
 * observations included, is analyzed with no external predecessor (EBMP2-059, EBMP2-077); and
 * each terminal effect gets its evidence level, decided after the scope (EBMP2-061).
 *
 * The verdict is exactly one of `invalid`, `incomplete`, `current-trust-failed` and `verified`
 * (EBMP2-060). A bundle that would otherwise verify but has a signer that is not acceptable now is
 * `current-trust-failed`, unless the caller explicitly accepts that, and the report says so.
 * Malformed bundle input gives an `invalid` report; only invalid caller arguments throw.
 *
 * The decision basis (ECL1N-0181, DCMP2-053): every signed decision response is checked under the
 * one-way rule as an object. A caller that requires the decision basis also refuses a decision
 * response without `ecl.ext.decision-basis.v1`; a caller that supplies the Consequential Action
 * Register also refuses a decision basis that disagrees with it (`./decision-basis.ts`). A register
 * that fails its schema or `ecl.rule.register-declarations-consistent.v1` is a usage error. Every
 * caller refuses a decision basis that records as `verifiable` an input whose source is the
 * request's actor.
 *
 * Pre-release obligations (DCMP2-017, EBMP2-070): an `execution_released` event whose signed
 * response carries an obligation to be met before release, or a witness result required before
 * release, records in `ecl.ext.obligation-discharge.v1` a discharge of each one, the obligations
 * taken from the response as the bundle holds it (`ecl.rule.prerelease-obligations-discharged.v1`).
 * A terminal event that records, in `ecl.ext.mcp-binding.v1`, a forward completed outside the
 * authorization's window or a release after `valid_until` is `ecl.error.expired.v1` (EBMP2-072); use
 * counts stay within the use policy (EBMP2-073); a release of single-use authority has its
 * consumption recorded (EBMP2-074); and an event that carries the MCP binding names the call its
 * request bound (EBMP2-075). Every report carries its scope (EBMP2-076), computed by `reportScope`.
 */

import { AUDIENCE_MISMATCH, checkAuthorityEventBinding, checkEventBinding, checkResponseBinding, BindingError, REQUEST_BINDING_INVALID, SCOPE_MISMATCH } from "../binding/binding.js";
import { analyzeBundle } from "../bundle/causal.js";
import { fromCanonicalBase64, sha256Hex, toHex } from "../crypto/bytes.js";
import { SignatureEncodingError, UnsupportedSuiteError, verifySignature } from "../crypto/signatures.js";
import { objectDigest } from "../json/canonical.js";
import { get, has, isArray, isInteger, isObject, isString, objectAt, pythonEquals, textAt, truthy } from "../json/value.js";
import type { JsonObject, JsonValue } from "../json/value.js";
import { decodeCanonicalJsonPayload, decodePayload, IntegrityError, PayloadNodeBudgetError, signingInput, TIME_ATTESTATION_TYPE, TRUSTED_TIME_CLAIM, verifyEnvelope } from "../integrity/envelope.js";
import type { VerificationContext } from "../integrity/envelope.js";
import { activeErrorCodes, rulePrecedence, ruleStage } from "../registry/registries.js";
import { eclSchemas } from "../schema/validator.js";
import { objectFindings } from "../semantic/object.js";
import { DECISION_BASIS_RULE, inputKey } from "../semantic/rules.js";
import { InstantError, instantNanoseconds, isInstant } from "../time.js";
import {
  PURPOSE_APPROVAL,
  PURPOSE_DECISION_REQUEST,
  PURPOSE_DECISION_RESPONSE,
  PURPOSE_EVIDENCE_EVENT,
  PURPOSE_OBSERVATION,
  PURPOSE_TRUSTED_TIME,
  TrustPolicy,
  TrustPolicyError,
} from "../trust/policy.js";
import type { TrustedKey } from "../trust/policy.js";
import { basisValues, REGISTER_RULE, registerProblems, registerReference, registerUsageProblems, requestProblems, REQUIRED_RULE } from "./decision-basis.js";

export const BUNDLE_SCHEMA = "https://externalcontrollayer.ai/ns/schema/evidence-bundle/1";
export const TIME_ATTESTATION_SCHEMA = "https://externalcontrollayer.ai/ns/schema/time-attestation/1";
export const MAX_ENVELOPES = 256;
export const MAX_OBSERVATIONS = 256;
export const MAX_TOTAL_PAYLOAD_NODES = 100_000;
export const REFERENCE_PROFILE = "ecl.verification-profile.reference.v1";
export const TRUSTED_TIME_PROFILE = "ecl.verification-profile.reference-trusted-time.v1";

export const CURRENT_TRUST_FAILED = "current-trust-failed";
export const TRUSTED_TIME_REQUIRED = "ecl.error.trusted-time-required.v1";
export const TRUSTED_TIME_INVALID = "ecl.error.trusted-time-invalid.v1";
export const SCHEMA_INVALID = "ecl.error.schema-invalid.v1";
export const SEMANTIC_INVALID = "ecl.error.semantic-invalid.v1";
export const INTEGRITY_INVALID = "ecl.error.integrity-invalid.v1";
export const POLICY_INVALID = "ecl.error.signature-policy-invalid.v1";
export const DECISION_BINDING_INVALID = "ecl.error.decision-binding-invalid.v1";
export const DIGEST_MISMATCH = "ecl.error.digest-mismatch.v1";
export const REVOKED = "ecl.error.revoked.v1";
export const EXPIRED = "ecl.error.expired.v1";
export const RESOURCE_LIMIT = "ecl.error.resource-limit-exceeded.v1";
export const THRESHOLD_NOT_MET = "ecl.error.threshold-not-met.v1";
export const CAUSAL_CLOSURE_INCOMPLETE = "ecl.error.causal-closure-incomplete.v1";
/** EBMP2-057 (F08): an object time or an attested time later than the evaluation time. */
export const CLOCK_REGRESSED = "ecl.error.clock-regressed.v1";
const OUTCOME_REASON = "ecl.ext.outcome-reason.v1";
/** EBMP2-070: the record of the obligations Enforcement proved before the release, and its rule. */
export const OBLIGATION_DISCHARGE = "ecl.ext.obligation-discharge.v1";
export const DISCHARGE_RULE = "ecl.rule.prerelease-obligations-discharged.v1";
const COUPLING = "ecl.ext.consequence-coupling.v1";
const WITNESS_OBLIGATION_TYPE = "ecl.obligation.verify-witness.v1";
const APPROVAL_OBLIGATION_TYPE = "ecl.obligation.approval-record.v1";
const POST_RELEASE = new Set(["during_execution", "after_execution"]);
/** EBMP2-070: the finding of a carried proof that fails one of its checks, or of a stale proof. */
export const OBLIGATION_UNPROVEN = "ecl.error.obligation-unproven.v1";
/** EBMP2-076: the items a stated reason keeps out of `established`, and the reasons. */
export const SCOPE_RELEASE = "release-within-authority";
export const SCOPE_PROOFS = "prerelease-obligations-proofs-verified";
export const REASON_NO_RELEASE = "no-release-recorded";
export const REASON_PROOF_NOT_ECL_OBJECT = "proof-not-ecl-object";
export const REASON_ISSUER_NOT_NAMED = "issuer-not-named";
/** EBMP2-072 and EBMP2-075: the MCP binding of a request and of the events of its action. */
const MCP_BINDING = "ecl.ext.mcp-binding.v1";
const MCP_RESPONSE_STATES = new Set(["succeeded", "failed"]);

/**
 * EBMP2-076: the scope of a verdict. The checks a verifier makes, in the order of the table of
 * EBMP2-076, then the statements that no verification establishes. Three checks and one
 * statement apply only to some bundles (`decision-basis-register` when the caller supplied a
 * register, as `registries/scope-checks.json` gives its condition); the others apply to every
 * report.
 */
export const SCOPE_CHECKS: readonly string[] = [
  "envelope-signatures",
  "current-trust",
  "trusted-time",
  "object-rules",
  "decision-basis-recorded",
  "decision-basis-register",
  "bindings",
  "release-within-authority",
  "causal-completeness",
  "prerelease-obligations-discharge-recorded",
  "prerelease-obligations-proofs-verified",
];
export const SCOPE_NEVER: readonly string[] = [
  "prerelease-obligations-met",
  "post-release-obligations-met",
  "recorded-times-true",
  "effects-occurred",
  "deployment-assessed",
  "statements-true",
];
const SCOPE_DISCHARGE: readonly string[] = ["prerelease-obligations-discharge-recorded", "prerelease-obligations-proofs-verified", "prerelease-obligations-met"];
const SCOPE_POST_RELEASE = "post-release-obligations-met";
/** EBMP2-076 and `registries/scope-checks.json`: the register item applies when the caller supplied one. */
const SCOPE_REGISTER = "decision-basis-register";
const CONDITIONAL_SCOPE = new Set([...SCOPE_DISCHARGE, SCOPE_POST_RELEASE, SCOPE_REGISTER]);
/** The sentence for people that each item of the scope stands for (the table of EBMP2-076). */
export const SCOPE_TEXT: Readonly<Record<string, string>> = {
  "envelope-signatures":
    "each envelope's and observation's payload digest and signatures verify under the trust-policy version its object names, at the object's own time or its trusted time, and the current trust policy revokes none of its trust dependencies at or before its time",
  "current-trust":
    "each trust dependency, each signing key of each envelope and observation and of each time attestation, is acceptable under the current trust policy at the evaluation time",
  "trusted-time":
    "a separate time authority attests a time for each signature of each envelope and observation, binding that signature, each signature was valid at that time, and each time authority's key was valid then and is not revoked by the current trust policy at or before it",
  "object-rules": "each signed object satisfies its schema and semantic rules, the one-way rule for a recorded decision basis among them",
  "decision-basis-recorded": "each decision response records its decision basis",
  "decision-basis-register": "each decision basis agrees with the Consequential Action Register supplied",
  bindings:
    "each response binds its request, each event binds its request, response and authority, with the digests and use counts they name, each continuation binds the request, challenge and approval it continues, and each terminal event carries the outcome reason its state and response require",
  "release-within-authority": "each recorded release time lies within the authorization's validity window",
  "causal-completeness":
    "over every object of the bundle, observations included, every causal predecessor is in the bundle with the digest that names it and in the workflow, trace and attempt that the rules allow, the graph is acyclic, identifiers are unique, and every request has a terminal event",
  "prerelease-obligations-discharge-recorded":
    "each release records a discharge of every obligation its decision left to Enforcement before the release, checked no later than the release was observed",
  "prerelease-obligations-proofs-verified":
    "each pre-release discharge carries its proof, and each proof is a valid ECL object under the trust policy, signed by the issuer the obligation names, of a type the obligation admits, bound to this exchange and fresh at the release",
  "prerelease-obligations-met": "that each pre-release obligation was met: the verifier checks a proof's signatures, issuer, type, binding and freshness, not what the proof shows",
  "post-release-obligations-met": "that the obligations to be met during or after execution were met, which the verifier does not check",
  "recorded-times-true": "that each recorded time is the true time of its event: each producer states its own times",
  "effects-occurred": "that the effects happened: a terminal event is its producer's statement, and corroboration is another signed statement, an observation bound to that terminal event and its attempt",
  "deployment-assessed": "that the deployment that produced the evidence has been assessed or meets ECL-1",
  "statements-true": "that the statements in the bundle are true, among them the enforcement point's statements of what it checked and released",
};
const NOW = /^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:[0-2][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{3}|\.[0-9]{6})?Z$/;
const NON_RELEASE = new Set(["denied", "held", "challenged", "expired_before_release"]);

export type Verdict = "verified" | "invalid" | "incomplete" | "current-trust-failed";

/** One envelope's statuses: `valid`, or the registered error that makes it not so. */
export interface EnvelopeCheck {
  readonly index: number;
  readonly objectId: string | null;
  readonly kind: string;
  readonly signerKeyIds: readonly string[];
  readonly historical: string;
  readonly current: string;
  readonly historicalPolicyVersion: string | null;
  readonly trustedTime: string | null;
}

/**
 * One trust dependency (TP1-006): a signature entry of an object of the bundle (`signer`) or of a
 * time attestation that a trusted-time countersignature of the object carries (`time-authority`).
 * `at` is the dependency's own time: the attested time that IE1-034 gives a signer's signature, or
 * else the object's own time, and a time attestation's attested time; null when it was not
 * evaluated. `historical` is its status at that time under the policy version its object or
 * attestation names, with the current policy's revocations applied (TP1-006); `current` its status
 * at the evaluation time under the current policy, `currentPolicyVersion`, whose revocation of the
 * key, if any, took effect at `revokedEffectiveAt`.
 */
export interface TrustDependency {
  readonly index: number;
  readonly role: "signer" | "time-authority";
  readonly counterId: string | null;
  readonly keyId: string;
  readonly suite: string;
  readonly at: string | null;
  readonly historicalPolicyVersion: string | null;
  readonly historical: string;
  readonly currentPolicyVersion: string;
  readonly revokedEffectiveAt: string | null;
  readonly current: string;
}

/**
 * EBMP2-076 and `registries/scope-checks.json`: the checks a verification ran, each with the
 * `index` values of the objects it ran over and of those over which it did not hold. Every check
 * that leads to a finding makes the verdict `invalid`; `failed` records the checks whose failure
 * leaves a verdict that can establish items (the current status, closure and trusted-time coverage).
 */
export interface CheckRecord {
  readonly ran: readonly number[];
  readonly failed: readonly number[];
}

/** One binding rule applied to a pair of objects. */
export interface BindingCheck {
  readonly name: string;
  readonly passed: boolean;
  readonly code: string | null;
}

/** The evidence level of one terminal effect (EBMP2-061). */
export interface EffectEvidence {
  readonly actionId: string;
  readonly state: string;
  readonly level: "none" | "issuer-asserted" | "corroborated";
  readonly authority: "consumed" | "issued-unused" | "none";
  readonly reason: string | null;
}

/**
 * EBMP2-076: what a verdict establishes and what it does not, each in the order of its table, and
 * the stated reason of each item that a reason keeps out of `established`: `release-within-authority`
 * is `no-release-recorded` when the bundle records no release, and
 * `prerelease-obligations-proofs-verified` is `proof-not-ecl-object` when an entry's proof is not an
 * object of the bundle, or `issuer-not-named` when every proof is carried and the decision names no
 * issuer for an obligation.
 */
export interface ReportScope {
  readonly established: readonly string[];
  readonly notEstablished: readonly string[];
  readonly reasons: Readonly<Record<string, string>>;
  /**
   * For each item in `established`, the checks of `registries/scope-checks.json` that the verifier
   * ran for it and that held, in registry order, and the `index` values of the objects they covered.
   */
  readonly checks: Readonly<Record<string, ScopeChecks>>;
}

/** The checks behind one established item and the objects they covered (EBMP2-076). */
export interface ScopeChecks {
  readonly checks: readonly string[];
  readonly objects: readonly number[];
}

/** A rule that failed: the registered error or rule identifier, and a message for people. */
export interface BundleFinding {
  readonly code: string;
  readonly message: string;
}

/** The result of verifying a bundle. */
export interface BundleReport {
  readonly verdict: Verdict;
  readonly envelopeChecks: readonly EnvelopeCheck[];
  readonly bindingChecks: readonly BindingCheck[];
  readonly causalStatus: string;
  readonly effects: readonly EffectEvidence[];
  readonly findings: readonly BundleFinding[];
  readonly verificationProfile: string;
  readonly acceptedCurrentTrustFailure: boolean;
  /** The register version the decision bases were checked against, if the caller gave one. */
  readonly register: JsonObject | null;
  /** EBMP2-076: the scope of the verdict; `reportScope` computes it from the rest of the report. */
  readonly scope: ReportScope;
  /** TP1-006: every trust dependency, by object, then signature entry, then countersignature. */
  readonly trustDependencies: readonly TrustDependency[];
  /** The checks that ran, by check identifier of `registries/scope-checks.json`, for `reportScope`. */
  readonly checksRun: Readonly<Record<string, CheckRecord>>;
  /**
   * The `index` values of the objects of each object set of `registries/scope-checks.json` that the
   * verification found, by object-set identifier (as pairing found them), for `reportScope`.
   */
  readonly objectSets: Readonly<Record<string, readonly number[]>>;
  /** EBMP2-057: the evaluation time the verification used (`now`), as the caller gave it. */
  readonly evaluationTime: string | null;
  /** EBMP-2 section 4: the identifiers of the causal predecessors the bundle does not hold, sorted. */
  readonly unresolvedPredecessorIds: readonly string[];
  /**
   * EBMP2-072: whether a terminal event records, in the MCP binding, a server answer that arrived at
   * or after the authorization's `valid_until`. The release itself was inside the window, or the
   * bundle is invalid: this member is information, not a finding.
   */
  readonly completionAfterWindow: boolean;
}

/** What the caller supplies besides the bundle and its current trust policy. */
export interface VerifyBundleOptions {
  /** The evaluation time: RFC 3339 UTC with 0, 3 or 6 fractional digits. */
  readonly now: string;
  /** Exact earlier versions of the same trust policy, which old evidence may name. */
  readonly history?: readonly TrustPolicy[];
  /** The response clock-skew allowance in seconds (DCMP2-047); the reference profile declares 0. */
  readonly responseClockSkewSeconds?: number;
  /** Report `verified`, with the acceptance stated, when a signer is not acceptable now. */
  readonly acceptCurrentTrustFailure?: boolean;
  /** Refuse an envelope without a valid trusted-time countersignature (IE1-035). */
  readonly requireTrustedTime?: boolean;
  /** A Consequential Action Register document; each decision basis is checked against it. */
  readonly register?: JsonValue;
}

interface Entry {
  readonly index: number;
  readonly observation: boolean;
  readonly envelope: JsonObject;
  readonly payload: JsonObject;
  readonly check: EnvelopeCheck;
  readonly signingKeys: ReadonlySet<string>;
}

type AttemptKey = string;

interface Pairs {
  readonly requests: Map<string, Entry>;
  readonly responses: Map<string, Entry>;
  readonly eventRequest: Map<number, Entry>;
  readonly eventResponse: Map<number, Entry | undefined>;
  readonly consumed: Set<AttemptKey>;
  readonly released: Set<AttemptKey>;
  readonly terminal: Set<AttemptKey>;
  /** The envelope indexes of the execution_released events that bind their request and response. */
  readonly boundReleases: Set<number>;
  /** Whether any envelope holds an execution_released event (EBMP2-076: `no-release-recorded`). */
  readonly releaseRecorded: boolean;
  /** EBMP2-072: whether a bound terminal records a server answer at or after `valid_until`. */
  readonly completionAfterWindow: boolean;
}

/** The objects that pairing and binding consider (EBMP2-058): the `request-response-pairs` set. */
const PAIRED_KINDS: ReadonlySet<string> = new Set(["decision_request", "decision_response", "authority_issued", "authority_consumed", "execution_released", "execution_terminal"]);

function issue(code: string, message: string): BundleFinding {
  return { code, message };
}

// EBMP2-068: the stages of verification, in order, and within each stage the order of its
// findings. RULES stands for the registered rules, which rank by their registry precedence.
const STAGE_PAYLOADS = 2;
const STAGE_OBJECTS = 3;
const STAGE_SIGNERS = 4;
const STAGE_PAIRING = 5;
const STAGE_REQUESTS = 6;
const STAGE_EVENTS = 7;
const STAGE_CAUSAL = 8;
const STAGE_REASONS = 9;
const RULES = "registered rules";
/** The order of stage 4 of EBMP2-068, which also orders the current statuses (EBMP2-060). */
export const SIGNER_ORDER: readonly string[] = [CLOCK_REGRESSED, POLICY_INVALID, TRUSTED_TIME_INVALID, TRUSTED_TIME_REQUIRED, REVOKED, EXPIRED, RESOURCE_LIMIT, INTEGRITY_INVALID, THRESHOLD_NOT_MET];
const STAGE_ORDERS: ReadonlyMap<number, readonly string[]> = new Map<number, readonly string[]>([
  [STAGE_PAYLOADS, [RESOURCE_LIMIT, INTEGRITY_INVALID]],
  [STAGE_OBJECTS, [SCHEMA_INVALID, RULES, SEMANTIC_INVALID]],
  [STAGE_SIGNERS, SIGNER_ORDER],
  [STAGE_PAIRING, [SCHEMA_INVALID, DECISION_BINDING_INVALID]],
  [STAGE_REQUESTS, [REQUEST_BINDING_INVALID, DIGEST_MISMATCH, AUDIENCE_MISMATCH, SCOPE_MISMATCH]],
  [STAGE_EVENTS, [DECISION_BINDING_INVALID, DIGEST_MISMATCH, EXPIRED]],
  [STAGE_CAUSAL, [RESOURCE_LIMIT, RULES, DECISION_BINDING_INVALID, OBLIGATION_UNPROVEN]],
  [STAGE_REASONS, [SEMANTIC_INVALID]],
]);

/** Where findings go: an array, or the findings of one stage. */
interface Sink {
  push(...items: BundleFinding[]): number;
}

/** The findings of one verification, each with the stage that found it (EBMP2-068). */
class Findings {
  private readonly items: Array<readonly [number, BundleFinding]> = [];

  add(stage: number, finding: BundleFinding): void {
    this.items.push([stage, finding]);
  }

  at(stage: number): Sink {
    return {
      push: (...found: BundleFinding[]): number => {
        for (const finding of found) {
          this.add(stage, finding);
        }
        return this.items.length;
      },
    };
  }

  get size(): number {
    return this.items.length;
  }

  /**
   * The findings in the order of EBMP2-068; findings that rank alike keep their order. A bundle
   * rule ranks in the stage that its registry entry names (`stage`), by precedence.
   */
  ordered(): BundleFinding[] {
    const precedence = rulePrecedence();
    const stages = ruleStage();
    const rank = (stage: number, code: string): [number, number] => {
      const order = STAGE_ORDERS.get(stage) ?? [];
      const slot = order.indexOf(code);
      if (slot >= 0) {
        return [slot, 0];
      }
      const rules = order.indexOf(RULES);
      const value = precedence.get(code);
      if (rules >= 0 && value !== undefined) {
        return [rules, value];
      }
      return [order.length, 0];
    };
    const keyed = this.items.map(([foundAt, finding], position) => {
      const stage = stages.get(finding.code) ?? foundAt;
      const [slot, sub] = rank(stage, finding.code);
      return { key: [stage, slot, sub, position], finding };
    });
    keyed.sort((a, b) => {
      for (let index = 0; index < 4; index += 1) {
        const difference = (a.key[index] as number) - (b.key[index] as number);
        if (difference !== 0) {
          return difference;
        }
      }
      return 0;
    });
    return keyed.map((item) => item.finding);
  }
}

function invalidReport(...findings: BundleFinding[]): BundleReport {
  return {
    verdict: "invalid",
    envelopeChecks: [],
    bindingChecks: [],
    causalStatus: "not-analyzed",
    effects: [],
    findings,
    verificationProfile: REFERENCE_PROFILE,
    acceptedCurrentTrustFailure: false,
    register: null,
    scope: { established: [], notEstablished: [], reasons: {}, checks: {} },
    trustDependencies: [],
    checksRun: {},
    objectSets: {},
    evaluationTime: null,
    unresolvedPredecessorIds: [],
    completionAfterWindow: false,
  };
}

function nanos(value: string): bigint {
  return instantNanoseconds(value);
}

function nodes(value: JsonValue, budget: number): number {
  let count = 0;
  const stack: JsonValue[] = [value];
  while (stack.length > 0) {
    const item = stack.pop() as JsonValue;
    count += 1;
    if (count > budget) {
      return count;
    }
    if (isObject(item)) {
      stack.push(...Object.values(item));
    } else if (isArray(item)) {
      stack.push(...item);
    }
  }
  return count;
}

/** `message_id` when it is a non-empty string, else `object_id` when it is a string. */
function identifierOf(payload: JsonObject): string | null {
  const messageId = textAt(payload, "message_id");
  if (messageId !== undefined && messageId !== "") {
    return messageId;
  }
  return textAt(payload, "object_id") ?? null;
}

function kindOf(payload: JsonObject): string {
  for (const member of ["message_type", "event_type"]) {
    const value = textAt(payload, member);
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return "unknown";
}

function purposeOf(payload: JsonObject, observation: boolean): string | undefined {
  const protocol = textAt(payload, "protocol");
  if (protocol === "DCMP-2") {
    const kind = textAt(payload, "message_type");
    if (kind === "decision_request") {
      return PURPOSE_DECISION_REQUEST;
    }
    if (kind === "decision_response") {
      return PURPOSE_DECISION_RESPONSE;
    }
  }
  if (protocol === "EBMP-2") {
    return observation ? PURPOSE_OBSERVATION : PURPOSE_EVIDENCE_EVENT;
  }
  return undefined;
}

function objectTime(payload: JsonObject): string | undefined {
  const protocol = textAt(payload, "protocol");
  if (protocol === "DCMP-2") {
    return textAt(payload, "issued_at");
  }
  if (protocol === "EBMP-2") {
    return textAt(payload, "observed_at");
  }
  return undefined;
}

function principalOf(payload: JsonObject): string | undefined {
  return textAt(payload, textAt(payload, "protocol") === "DCMP-2" ? "issuer" : "producer", "id");
}

function signatureIds(envelope: JsonValue): string[] {
  const signatures = get(envelope, "signatures");
  if (!isArray(signatures)) {
    return [];
  }
  return signatures.flatMap((signature) => {
    const keyId = get(signature, "key_id");
    return isObject(signature) && typeof keyId === "string" ? [keyId] : [];
  });
}

function referenceMatches(policy: TrustPolicy, reference: JsonValue | undefined): boolean {
  return pythonEquals(policy.reference() as unknown as JsonValue, reference ?? null);
}

function historyProblem(policy: TrustPolicy, history: readonly TrustPolicy[]): BundleFinding | undefined {
  const seen = new Set([policy.digest]);
  for (const older of history) {
    if (!(older instanceof TrustPolicy) || older.policyId !== policy.policyId || older.epoch >= policy.epoch || seen.has(older.digest)) {
      return issue(POLICY_INVALID, "history must hold distinct earlier versions of this policy");
    }
    seen.add(older.digest);
  }
  return undefined;
}

function keyTimeStatus(key: TrustedKey, policy: TrustPolicy, at: string): string {
  const instant = nanos(at);
  if (policy.revocations.some((revocation) => revocation.keyId === key.keyId && instant >= nanos(revocation.effectiveAt))) {
    return REVOKED;
  }
  if (instant < nanos(key.validFrom)) {
    return EXPIRED;
  }
  if (key.validUntil !== undefined && instant >= nanos(key.validUntil)) {
    return EXPIRED;
  }
  return "valid";
}

/** The `effective_at` of the current policy's revocation of `keyId`, or null (TP1-006). */
function revokedEffectiveAt(current: TrustPolicy, keyId: string, publicKey?: Uint8Array): string | null {
  // A revocation matches the dependency by key identifier, or by public key when the current
  // policy lists the same key material under another identifier (TP1-006); the earliest counts.
  const material = publicKey === undefined ? undefined : toHex(publicKey);
  let earliest: string | null = null;
  for (const revocation of current.revocations) {
    const listed = current.key(revocation.keyId);
    const matches = revocation.keyId === keyId || (material !== undefined && listed !== undefined && toHex(listed.publicKey) === material);
    if (matches && (earliest === null || nanos(revocation.effectiveAt) < nanos(earliest))) {
      earliest = revocation.effectiveAt;
    }
  }
  return earliest;
}

/**
 * TP1-006, the second part of historical validity: the caller's current policy holds a revocation
 * of the key identifier, or of the same public key under another identifier, effective at or
 * before the dependency's own time `at`, whatever reason it gives.
 */
function compromisedBefore(current: TrustPolicy | undefined, keyId: string, at: string, publicKey?: Uint8Array): boolean {
  const effective = current === undefined ? null : revokedEffectiveAt(current, keyId, publicKey);
  return effective !== null && nanos(effective) <= nanos(at);
}

/** What a signing key must be for: its purpose and its principal (TP1-004, TP1-005). */
interface Role {
  readonly purpose: string;
  readonly principal: string | undefined;
}

/**
 * The status of one signature entry's key (IE1-040, step 6 (a) to (c); TP1-004 to TP1-006): the key
 * acceptable in `policy` for the entry's suite, `role.purpose` and `role.principal`, and for current
 * status the same public key as in `original`; then not revoked at `at` under `policy`, nor under
 * `compromise` (the current policy, for historical validity) effective at or before `at`; then
 * within its validity interval.
 */
function keyStatus(signature: JsonObject, policy: TrustPolicy, role: Role, at: string, original?: TrustPolicy, compromise?: TrustPolicy): string {
  const keyId = signature["key_id"] as string;
  const key = policy.key(keyId);
  if (key === undefined) {
    return POLICY_INVALID;
  }
  if (original !== undefined) {
    const old = original.key(keyId);
    if (old === undefined || toHex(old.publicKey) !== toHex(key.publicKey)) {
      return POLICY_INVALID;
    }
  }
  if (key.suiteId !== signature["suite_id"] || !key.purposes.includes(role.purpose) || key.principal !== role.principal) {
    return POLICY_INVALID;
  }
  const status = keyTimeStatus(key, policy, at);
  if (status !== REVOKED && compromisedBefore(compromise, keyId, at, key.publicKey)) {
    return REVOKED;
  }
  return status;
}

/** The envelope's status from its keys' statuses: any unacceptable key, then revoked, then expired. */
function combined(statuses: readonly string[]): string {
  for (const status of [POLICY_INVALID, REVOKED, EXPIRED]) {
    if (statuses.includes(status)) {
      return status;
    }
  }
  return "valid";
}

/**
 * Check every signer, counted or not (TP1-004, TP1-005), in the order of IE1-040, step 6: every key
 * acceptable for the object's suite, purpose and principal, and for current status the same public
 * key as at signing; then no key revoked at its time; then every key within its validity interval.
 * `timeOf` gives each key's time (IE1-034); `compromise` is the current policy, whose revocations
 * reach historical validity (TP1-006).
 */
function signerStatus(envelope: JsonObject, payload: JsonObject, policy: TrustPolicy, purpose: string, timeOf: (keyId: string) => string, original?: TrustPolicy, compromise?: TrustPolicy): string {
  const signatures = envelope["signatures"] as JsonObject[];
  const role = { purpose, principal: principalOf(payload) };
  return combined(signatures.map((signature) => keyStatus(signature, policy, role, timeOf(signature["key_id"] as string), original, compromise)));
}

function checkSignature(envelope: JsonObject, policy: TrustPolicy, payload: JsonObject, at: string, signedPolicy?: TrustPolicy, keyTimes?: ReadonlyMap<string, string>): [string, ReadonlySet<string>] {
  const timePolicy = textAt(payload, "integrity_policy", "verification_time_policy");
  const expected = textAt(payload, "protocol") === "DCMP-2" ? "ecl.time.issued-at.v1" : "ecl.time.observed-at.v1";
  if (timePolicy !== expected) {
    return [POLICY_INVALID, new Set()];
  }
  try {
    let context: VerificationContext = policy.verificationContext(at, timePolicy);
    if (signedPolicy !== undefined) {
      context = {
        ...context,
        trustPolicyId: signedPolicy.policyId,
        trustPolicyVersion: signedPolicy.version,
        trustPolicyDigest: signedPolicy.digest,
        trustPolicyEpoch: signedPolicy.epoch,
      };
    }
    const result = verifyEnvelope(envelope, policy.keyring(), context, keyTimes);
    return ["valid", new Set(result.validKeyIds)];
  } catch (error) {
    // The error code of INTEGRITY-ENVELOPE-1, IE1-040.
    if (error instanceof IntegrityError) {
      return [error.code, new Set()];
    }
    if (error instanceof TrustPolicyError) {
      return [INTEGRITY_INVALID, new Set()];
    }
    throw error;
  }
}

/** The SHA-256 digest object of the bytes a signature entry's `signature` encodes, or undefined. */
function signatureDigest(signature: JsonValue): JsonObject | undefined {
  const text = get(signature, "signature");
  const decoded = typeof text === "string" ? fromCanonicalBase64(text) : undefined;
  return decoded === undefined ? undefined : { algorithm: "ecl.digest.sha-256.v1", value: sha256Hex(decoded) };
}

/** Whether one signature entry verifies with its key in `policy` (IE1-040, step 6 (d) and (e)). */
function signatureVerifies(signature: JsonObject, policy: TrustPolicy, message: Uint8Array): boolean {
  const key = policy.key(signature["key_id"] as string);
  const text = signature["signature"];
  const bytes = typeof text === "string" ? fromCanonicalBase64(text) : undefined;
  if (key === undefined || bytes === undefined) {
    return false;
  }
  try {
    return verifySignature(key.suiteId, key.publicKey, message, bytes);
  } catch (error) {
    if (error instanceof SignatureEncodingError) {
      return false;
    }
    throw error;
  }
}

/**
 * IE1-033 and IE1-034: the positions, in envelope order, of the envelope signatures that `covered`
 * names, or undefined when an entry names no signature of the envelope with its `key_id`, suite
 * and signature digest, or the entries are not in the envelope's order or name one signature twice.
 */
function coveredSignatures(covered: JsonValue | undefined, envelope: JsonObject): number[] | undefined {
  const listed = get(covered ?? null, "signatures");
  const signatures = get(envelope, "signatures");
  if (!isArray(listed) || listed.length === 0 || !isArray(signatures)) {
    return undefined;
  }
  const positions: number[] = [];
  for (const item of listed) {
    const position = signatures.findIndex(
      (signature) =>
        isObject(signature) &&
        pythonEquals(get(signature, "key_id"), get(item, "key_id")) &&
        pythonEquals(get(signature, "suite_id"), get(item, "suite")) &&
        pythonEquals(signatureDigest(signature) ?? null, get(item, "signature_digest")),
    );
    if (position < 0 || (positions.length > 0 && position <= (positions[positions.length - 1] as number))) {
      return undefined;
    }
    positions.push(position);
  }
  return positions;
}

/** One trusted-time countersignature of an envelope, as IE1-032 to IE1-034 and TP1-006 judge it. */
interface Countersignature {
  readonly counterId: string | null;
  /** The attested time, when the attestation's payload states one (also for F08). */
  readonly attested: string | undefined;
  readonly valid: boolean;
  /** The positions of the envelope signatures that it covers, when it is valid. */
  readonly covers: readonly number[];
  readonly dependencies: readonly Omit<TrustDependency, "index">[];
}

/**
 * IE1-032 to IE1-034 and TP1-006 on one countersignature: the attestation binds the envelope's
 * payload type, payload digest and the signatures it covers; it is verified under the policy
 * version it names at its attested time; and each of its keys is a time authority's then, under
 * that version, and not revoked by the current policy effective at or before the attested time.
 * Each signature entry of the attestation is a trust dependency, whose current status is its key's
 * at `now` under the current policy (TP1-006).
 */
function evaluateCountersignature(entry: JsonValue, envelope: JsonObject, payload: JsonObject, versions: readonly TrustPolicy[], current: TrustPolicy, now: string): Countersignature {
  const counterId = isString(get(entry, "counter_id")) ? (get(entry, "counter_id") as string) : null;
  const attestation = get(entry, "attestation");
  const signatures = isObject(attestation) && isArray(get(attestation, "signatures")) ? (get(attestation, "signatures") as JsonValue[]) : [];
  let statement: JsonValue = null;
  if (isObject(attestation) && get(attestation, "payload_type") === TIME_ATTESTATION_TYPE) {
    try {
      statement = decodeCanonicalJsonPayload(attestation);
    } catch (error) {
      if (!(error instanceof IntegrityError)) {
        throw error;
      }
    }
  }
  const attestedText = isObject(statement) ? textAt(statement, "issued_at") : undefined;
  const attested = attestedText !== undefined && isInstant(attestedText) ? attestedText : undefined;
  const issuer = isObject(statement) ? textAt(statement, "issuer", "id") : undefined;
  const reference = isObject(statement) ? objectAt(statement, "integrity_policy", "trust_policy") : undefined;
  const version = reference === undefined ? undefined : versions.find((item) => referenceMatches(item, reference));
  const role = { purpose: PURPOSE_TRUSTED_TIME, principal: issuer };
  // Each signature entry of the attestation: historically valid with the countersignature (at its
  // attested time), or trusted-time-invalid with it; now, under the current policy, with the
  // public key of the version that the attestation names.
  const statuses: string[] = [];
  const dependencies = signatures.filter(isObject).map((signature) => {
    const keyId = isString(get(signature, "key_id")) ? (get(signature, "key_id") as string) : "";
    const suite = isString(get(signature, "suite_id")) ? (get(signature, "suite_id") as string) : "";
    statuses.push(version === undefined || attested === undefined ? TRUSTED_TIME_INVALID : keyStatus(signature, version, role, attested, undefined, current));
    return {
      role: "time-authority" as const,
      counterId,
      keyId,
      suite,
      at: attested ?? null,
      historicalPolicyVersion: version?.version ?? null,
      historical: "valid",
      currentPolicyVersion: current.version,
      revokedEffectiveAt: revokedEffectiveAt(current, keyId, version?.key(keyId)?.publicKey),
      current: version === undefined ? POLICY_INVALID : keyStatus(signature, current, role, now, version),
    };
  });
  const invalid = (): Countersignature => ({
    counterId,
    attested,
    valid: false,
    covers: [],
    dependencies: dependencies.map((dependency) => ({ ...dependency, at: null, historical: TRUSTED_TIME_INVALID })),
  });
  if (get(entry, "claim") !== TRUSTED_TIME_CLAIM || !isObject(attestation) || !isObject(statement) || !eclSchemas().isValid(TIME_ATTESTATION_SCHEMA, statement)) {
    return invalid();
  }
  const covered = get(statement, "covered");
  const covers = coveredSignatures(covered, envelope);
  const own = objectTime(payload);
  if (
    covers === undefined ||
    !pythonEquals(get(covered ?? null, "media_type"), get(envelope, "payload_type") ?? null) ||
    !pythonEquals(get(covered ?? null, "digest"), get(envelope, "payload_digest") ?? null) ||
    !pythonEquals(get(statement, "attestation_id"), get(entry, "counter_id")) ||
    !pythonEquals(get(statement, "claim"), get(entry, "claim")) ||
    issuer === undefined ||
    issuer === principalOf(payload) ||
    attested === undefined ||
    own === undefined ||
    nanos(own) > nanos(attested) ||
    textAt(statement, "integrity_policy", "verification_time_policy") !== "ecl.time.issued-at.v1" ||
    version === undefined ||
    statuses.some((status) => status !== "valid")
  ) {
    return invalid();
  }
  try {
    verifyEnvelope(attestation, version.keyring(), version.verificationContext(attested, "ecl.time.issued-at.v1"));
  } catch (error) {
    if (error instanceof IntegrityError || error instanceof TrustPolicyError) {
      return invalid();
    }
    throw error;
  }
  // Every key that signed the attestation is a dependency, counted or not: one whose signature
  // does not verify is historically invalid with the integrity code, while IE1-040 step 7, from
  // the signatures that count, keeps the attestation valid (TP1-006).
  const message = signingInput(TIME_ATTESTATION_TYPE, decodePayload(attestation));
  const signed = signatures.filter(isObject);
  return {
    counterId,
    attested,
    valid: true,
    covers,
    dependencies: dependencies.map((dependency, position) => (signatureVerifies(signed[position] as JsonObject, version, message) ? dependency : { ...dependency, historical: INTEGRITY_INVALID })),
  };
}

/** Where verifyChecked records the checks of `registries/scope-checks.json` as they run. */
class Ledger {
  private readonly ranAt = new Map<string, Set<number>>();
  private readonly failedAt = new Map<string, Set<number>>();

  ran(check: string, index: number, held = true): void {
    const ran = this.ranAt.get(check) ?? new Set<number>();
    ran.add(index);
    this.ranAt.set(check, ran);
    if (!held) {
      const failed = this.failedAt.get(check) ?? new Set<number>();
      failed.add(index);
      this.failedAt.set(check, failed);
    }
  }

  private readonly members = new Map<string, Set<number>>();

  /** `index` is an object of the object set `set` (`registries/scope-checks.json`). */
  member(set: string, index: number | undefined): void {
    if (index === undefined) {
      return;
    }
    const members = this.members.get(set) ?? new Set<number>();
    members.add(index);
    this.members.set(set, members);
  }

  sets(): Record<string, number[]> {
    const out: Record<string, number[]> = {};
    for (const [set, members] of this.members) {
      out[set] = [...members].sort((a, b) => a - b);
    }
    return out;
  }

  record(): Record<string, CheckRecord> {
    const out: Record<string, CheckRecord> = {};
    for (const [check, ran] of this.ranAt) {
      out[check] = { ran: [...ran].sort((a, b) => a - b), failed: [...(this.failedAt.get(check) ?? [])].sort((a, b) => a - b) };
    }
    return out;
  }
}

/** The checks that evaluating one envelope's trust makes (`registries/scope-checks.json`). */
const TRUST_CHECKS = ["time-not-after-evaluation", "historical-signers", "current-compromise-knowledge", "trusted-time-countersignatures"];

function evaluateEnvelope(
  envelope: JsonObject,
  payload: JsonObject,
  index: number,
  observation: boolean,
  currentPolicy: TrustPolicy,
  versions: readonly TrustPolicy[],
  now: string,
  findings: Sink,
  requireTrustedTime: boolean,
  ledger: Ledger,
): [EnvelopeCheck, ReadonlySet<string>, TrustDependency[]] {
  const identifier = identifierOf(payload);
  const kind = kindOf(payload);
  const signers = signatureIds(envelope);
  const signatures = isArray(envelope["signatures"]) ? (envelope["signatures"] as JsonObject[]) : [];
  // Each signature entry as a dependency that was not evaluated, with the status given.
  const unevaluated = (status: string, named?: TrustPolicy): TrustDependency[] =>
    signatures.filter(isObject).map((signature) => {
      const keyId = isString(get(signature, "key_id")) ? (get(signature, "key_id") as string) : "";
      return {
        index,
        role: "signer",
        counterId: null,
        keyId,
        suite: isString(get(signature, "suite_id")) ? (get(signature, "suite_id") as string) : "",
        at: null,
        historicalPolicyVersion: named?.version ?? null,
        historical: status,
        currentPolicyVersion: currentPolicy.version,
        revokedEffectiveAt: revokedEffectiveAt(currentPolicy, keyId, named?.key(keyId)?.publicKey),
        current: status,
      };
    });
  const invalid = objectFindings(payload);
  ledger.ran("object-schema", index);
  ledger.ran("object-semantics", index);
  if (invalid.length > 0) {
    findings.push(...invalid.map((item) => issue(item.ruleId, `object ${index}: ${item.path}: ${item.message}`)));
    // EBMP2-068, stage 3: an object that fails its schema is schema-invalid; one that satisfies it
    // but fails a semantic rule is semantic-invalid, which ranks after the rules, so that the
    // object's own primary finding (DCMP2-043) leads.
    const status = invalid.some((item) => item.ruleId === SCHEMA_INVALID) ? SCHEMA_INVALID : SEMANTIC_INVALID;
    return [{ index, objectId: identifier, kind, signerKeyIds: signers, historical: status, current: status, historicalPolicyVersion: null, trustedTime: null }, new Set(), unevaluated(status)];
  }
  const purpose = purposeOf(payload, observation);
  const at = objectTime(payload);
  const reference = objectAt(payload, "integrity_policy", "trust_policy");
  const version = versions.find((item) => referenceMatches(item, reference));
  if (purpose === undefined || at === undefined || version === undefined) {
    return [
      { index, objectId: identifier, kind, signerKeyIds: signers, historical: POLICY_INVALID, current: POLICY_INVALID, historicalPolicyVersion: null, trustedTime: null },
      new Set(),
      unevaluated(POLICY_INVALID, version),
    ];
  }
  let signedIds: ReadonlySet<string> = new Set();
  let historical: string;
  let current: string;
  let trusted: string | undefined;
  let dependencies: TrustDependency[];
  try {
    const entries = get(envelope, "countersignatures");
    const counters = (isArray(entries) ? entries : []).map((entry) => evaluateCountersignature(entry, envelope, payload, versions, currentPolicy, now));
    // IE1-034: each covered signature at the earliest attested time of the countersignatures that
    // cover it, every other signature at the object's own time.
    const times: string[] = signatures.map(() => at);
    const covered = signatures.map(() => false);
    for (const counter of counters) {
      if (!counter.valid || counter.attested === undefined) {
        continue;
      }
      for (const position of counter.covers) {
        if (!covered[position] || nanos(counter.attested) < nanos(times[position] as string)) {
          times[position] = counter.attested;
        }
        covered[position] = true;
      }
    }
    const keyTimes = new Map<string, string>();
    signatures.forEach((signature, position) => {
      const keyId = signature["key_id"] as string;
      // A key that signs twice (under two suites) at two times is taken at the object's own time.
      keyTimes.set(keyId, keyTimes.has(keyId) && keyTimes.get(keyId) !== times[position] ? at : (times[position] as string));
    });
    const timeOf = (keyId: string): string => keyTimes.get(keyId) ?? at;
    const used = times.filter((_, position) => covered[position]);
    trusted = used.length === 0 ? undefined : used.reduce((earliest, time) => (nanos(time) < nanos(earliest) ? time : earliest));
    const allCovered = counters.length > 0 && covered.every((item) => item);
    if (counters.some((counter) => !counter.valid)) {
      // IE1-034: no attested time is used when one countersignature is not valid.
      trusted = undefined;
    }
    if (nanos(at) > nanos(now) || counters.some((counter) => counter.attested !== undefined && nanos(counter.attested) > nanos(now))) {
      // EBMP2-057 (F08): evidence cannot be later than the instant at which it is verified.
      historical = CLOCK_REGRESSED;
    } else if (counters.some((counter) => !counter.valid)) {
      historical = TRUSTED_TIME_INVALID;
    } else if (requireTrustedTime && !allCovered) {
      // IE1-035: every signature entry needs a countersignature that covers it.
      historical = TRUSTED_TIME_REQUIRED;
    } else {
      historical = signerStatus(envelope, payload, version, purpose, timeOf, undefined, currentPolicy);
      if (historical === "valid") {
        [historical, signedIds] = checkSignature(envelope, version, payload, at, undefined, keyTimes);
      }
    }
    current = signerStatus(envelope, payload, currentPolicy, purpose, () => now, version);
    if (current === "valid") {
      [current] = checkSignature(envelope, currentPolicy, payload, now, version);
    }
    // TP1-006: each signer at its own time, under the named version with the current policy's
    // revocations, its signature verified with that key; and now, under the current policy.
    // A status that is the envelope's and no one signer's is each signer's.
    const envelopeWide = historical === CLOCK_REGRESSED || historical === TRUSTED_TIME_INVALID || historical === TRUSTED_TIME_REQUIRED;
    const role = { purpose, principal: principalOf(payload) };
    const message = signingInput(envelope["payload_type"] as string, decodePayload(envelope));
    dependencies = signatures.filter(isObject).map((signature) => {
      const keyId = signature["key_id"] as string;
      const own = timeOf(keyId);
      let status = envelopeWide ? historical : keyStatus(signature, version, role, own, undefined, currentPolicy);
      if (status === "valid" && !signatureVerifies(signature, version, message)) {
        status = INTEGRITY_INVALID;
      }
      return {
        index,
        role: "signer" as const,
        counterId: null,
        keyId,
        suite: signature["suite_id"] as string,
        // Not evaluated when the envelope's status was decided for the whole envelope.
        at: envelopeWide ? null : own,
        historicalPolicyVersion: version.version,
        historical: status,
        currentPolicyVersion: currentPolicy.version,
        revokedEffectiveAt: revokedEffectiveAt(currentPolicy, keyId, version.key(keyId)?.publicKey),
        current: keyStatus(signature, currentPolicy, role, now, version),
      };
    });
    for (const counter of counters) {
      dependencies.push(...counter.dependencies.map((dependency) => ({ index, ...dependency })));
    }
    for (const check of TRUST_CHECKS) {
      ledger.ran(check, index);
    }
    ledger.ran("trusted-time-coverage", index, allCovered);
    ledger.ran("current-status", index, dependencies.every((dependency) => dependency.current === "valid") && current === "valid");
  } catch (error) {
    // The reference reports a value it cannot read here as schema-invalid for both statuses.
    if (!(error instanceof InstantError)) {
      throw error;
    }
    historical = SCHEMA_INVALID;
    current = SCHEMA_INVALID;
    dependencies = unevaluated(SCHEMA_INVALID, version);
  }
  const signingKeys = new Set<string>();
  for (const keyId of signedIds) {
    const key = version.key(keyId);
    if (key !== undefined) {
      signingKeys.add(`${key.suiteId}:${toHex(key.publicKey)}`);
    }
  }
  return [
    { index, objectId: identifier, kind, signerKeyIds: signers, historical, current, historicalPolicyVersion: version.version, trustedTime: trusted ?? null },
    signingKeys,
    dependencies,
  ];
}

function attemptKey(payload: JsonObject, event = false): AttemptKey | undefined {
  const actionId = textAt(payload, event ? "event" : "action", "action_id");
  const workflowId = textAt(payload, "workflow", "workflow_id");
  const workflow = objectAt(payload, "workflow");
  const attempt = workflow === undefined ? undefined : get(workflow, "attempt");
  if (actionId === undefined || workflowId === undefined || !isInteger(attempt)) {
    return undefined;
  }
  return JSON.stringify([actionId, workflowId, attempt]);
}

function runBinding(name: string, check: () => void, checks: BindingCheck[], findings: Sink): boolean {
  try {
    check();
  } catch (error) {
    if (error instanceof BindingError) {
      checks.push({ name, passed: false, code: error.code });
      findings.push(issue(error.code, `${name} does not bind`));
      return false;
    }
    throw error;
  }
  checks.push({ name, passed: true, code: null });
  return true;
}

function referenceDigestMatches(reference: JsonObject, value: JsonObject): boolean {
  return pythonEquals(get(reference, "digest"), { algorithm: "ecl.digest.sha-256.v1", value: objectDigest(value) });
}

function checkAuthorityDigest(event: Entry, response: Entry, findings: Sink): void {
  const reference = objectAt(event.payload, "event", "authority");
  if (reference === undefined) {
    return;
  }
  const authorization = objectAt(response.payload, "authorization");
  if (authorization === undefined || !referenceDigestMatches(reference, authorization)) {
    findings.push(issue(DIGEST_MISMATCH, "event authority digest does not match the grant"));
  }
}

function checkEventMessageReferences(entries: readonly Entry[], pairs: Pairs, checks: BindingCheck[], findings: Sink, ledger: Ledger): void {
  const responses = new Map<string, Entry>();
  for (const entry of pairs.responses.values()) {
    const identifier = identifierOf(entry.payload);
    if (identifier !== null) {
      responses.set(identifier, entry);
    }
  }
  for (const entry of entries) {
    if (entry.observation || textAt(entry.payload, "protocol") !== "EBMP-2") {
      continue;
    }
    for (const [field, targets] of [["request", pairs.requests], ["decision", responses]] as const) {
      const reference = objectAt(entry.payload, "event", field);
      if (reference === undefined) {
        continue;
      }
      ledger.ran("event-binding", entry.index);
      const uri = get(reference, "uri");
      const target = typeof uri === "string" ? targets.get(uri) : undefined;
      const name = `${field}-reference:${entry.index}`;
      if (target === undefined) {
        checks.push({ name, passed: false, code: DECISION_BINDING_INVALID });
        findings.push(issue(DECISION_BINDING_INVALID, `event ${field} has no message`));
        continue;
      }
      const eventWorkflow = objectAt(entry.payload, "workflow") ?? {};
      const targetWorkflow = objectAt(target.payload, "workflow") ?? {};
      if (["workflow_id", "root_trace_id", "attempt"].some((member) => !pythonEquals(get(eventWorkflow, member), get(targetWorkflow, member)))) {
        checks.push({ name, passed: false, code: DECISION_BINDING_INVALID });
        findings.push(issue(DECISION_BINDING_INVALID, `event ${field} belongs to another workflow`));
        continue;
      }
      if (Object.prototype.hasOwnProperty.call(reference, "digest") && !referenceDigestMatches(reference, target.payload)) {
        checks.push({ name, passed: false, code: DIGEST_MISMATCH });
        findings.push(issue(DIGEST_MISMATCH, `event ${field} digest does not match`));
        continue;
      }
      checks.push({ name, passed: true, code: null });
      if (field === "decision" && entry.check.kind === "decision_recorded") {
        const event = objectAt(entry.payload, "event") ?? {};
        const contentName = `decision-content:${entry.index}`;
        if (!pythonEquals(get(event, "outcome"), get(target.payload, "outcome")) || !pythonEquals(get(event, "policy"), get(target.payload, "policy"))) {
          checks.push({ name: contentName, passed: false, code: DECISION_BINDING_INVALID });
          findings.push(issue(DECISION_BINDING_INVALID, "decision event contradicts its response"));
        } else {
          checks.push({ name: contentName, passed: true, code: null });
        }
      }
    }
  }
}

/**
 * EBMP2-066: the execution events of one action attempt (`event.action_id`, `workflow.workflow_id`,
 * `workflow.attempt`) carry one `event.attempt_id`, and one attempt identifier names one such
 * attempt. One finding reports the first conflict.
 */
function checkAttemptIdentity(main: readonly Entry[], findings: Sink): void {
  const byKey = new Map<AttemptKey, string>();
  const byAttempt = new Map<string, AttemptKey>();
  for (const entry of main) {
    const payload = entry.payload;
    if (textAt(payload, "protocol") !== "EBMP-2" || textAt(payload, "event", "kind") !== "execution") {
      continue;
    }
    const key = attemptKey(payload, true);
    const attemptId = textAt(payload, "event", "attempt_id");
    if (key === undefined || attemptId === undefined) {
      continue;
    }
    if (!byKey.has(key)) {
      byKey.set(key, attemptId);
    }
    if (!byAttempt.has(attemptId)) {
      byAttempt.set(attemptId, key);
    }
    if (byKey.get(key) !== attemptId || byAttempt.get(attemptId) !== key) {
      findings.push(issue(DECISION_BINDING_INVALID, "execution events of one attempt carry different attempt identifiers"));
      return;
    }
  }
}

/** An ECL instant in nanoseconds, or null for a value that is not one (left to the schema rules). */
function instantOrNull(value: JsonValue | undefined): bigint | null {
  try {
    return instantNanoseconds(value);
  } catch (error) {
    if (error instanceof InstantError) {
      return null;
    }
    throw error;
  }
}

/** The value of each occurrence of one extension whose value is an object, in order. */
function extensionValues(value: JsonObject, identifier: string): JsonObject[] {
  const extensions = get(value, "extensions");
  if (!isArray(extensions)) {
    return [];
  }
  const found: JsonObject[] = [];
  for (const extension of extensions) {
    const item = isObject(extension) ? get(extension, "value") : undefined;
    if (isObject(extension) && get(extension, "id") === identifier && isObject(item)) {
      found.push(item);
    }
  }
  return found;
}

/** EBMP2-073: the uses an authorization allows: 1 for `single_use`, else `max_uses` when it has one. */
function useLimit(response: JsonObject): number | null {
  const authorization = objectAt(response, "authorization");
  if (authorization === undefined) {
    return null;
  }
  if (get(authorization, "use_policy") === "single_use") {
    return 1;
  }
  const uses = get(authorization, "max_uses");
  return isInteger(uses) ? uses : null;
}

/**
 * EBMP2-073: for each authorization, the `authority_consumed` events in state `consumed` that bind
 * its response give use counts from 1 to the uses it allows, no two alike, and are no more than it
 * allows. Findings of stage 7 of EBMP2-068.
 */
function checkUseCounts(consumed: ReadonlyArray<readonly [Entry, Entry]>, findings: Sink): void {
  const byAuthorization = new Map<string, Array<readonly [Entry, Entry]>>();
  for (const [event, response] of consumed) {
    const identifier = textAt(event.payload, "event", "authorization_id");
    if (identifier !== undefined) {
      const listed = byAuthorization.get(identifier) ?? [];
      listed.push([event, response]);
      byAuthorization.set(identifier, listed);
    }
  }
  for (const events of byAuthorization.values()) {
    const limit = useLimit((events[0] as readonly [Entry, Entry])[1].payload);
    const counts: number[] = [];
    for (const [event] of events) {
      const count = get(objectAt(event.payload, "event") ?? {}, "use_count");
      if (!isInteger(count)) {
        continue;
      }
      if (count < 1 || (limit !== null && count > limit)) {
        findings.push(issue(DECISION_BINDING_INVALID, `envelope ${event.index}: the use count is outside the authorization's use policy`));
      }
      counts.push(count);
    }
    if (new Set(counts).size !== counts.length) {
      findings.push(issue(DECISION_BINDING_INVALID, "two consumptions of one authorization record one use"));
    }
    if (limit !== null && events.length > limit) {
      findings.push(issue(DECISION_BINDING_INVALID, "an authorization is consumed more often than its use policy allows"));
    }
  }
}

/**
 * EBMP2-072: whether a terminal event records, in the MCP binding, that the gateway observed after
 * its write that the authorization's `valid_until` had passed.
 */
function releasedAfterValidUntil(terminal: JsonObject): boolean {
  return extensionValues(terminal, MCP_BINDING).some((value) => get(value, "released_after_valid_until") === true);
}

/**
 * EBMP2-072: whether a terminal event records, in the MCP binding, a `forward_completed_at` at or
 * after the authorization's `valid_until`: the server's answer came late, which is not a finding
 * about the release.
 */
function completedAfterWindow(terminal: JsonObject, response: JsonObject): boolean {
  const end = instantOrNull(textAt(response, "authorization", "valid_until"));
  if (end === null) {
    return false;
  }
  for (const value of extensionValues(terminal, MCP_BINDING)) {
    const completed = instantOrNull(get(value, "forward_completed_at"));
    if (completed !== null && completed >= end) {
      return true;
    }
  }
  return false;
}

/**
 * EBMP2-071: the release guard an `execution_released` event declares, in nanoseconds, or null when
 * the event does not carry it as an integer (its schema then refuses it).
 */
function releaseGuardNs(event: JsonObject): bigint | null {
  const value = get(objectAt(event, "event") ?? {}, "release_guard_ms");
  return typeof value === "number" && Number.isInteger(value) ? BigInt(value) * 1_000_000n : null;
}

/**
 * EBMP2-075: when the request carries the MCP binding, each occurrence of it in an execution event
 * carries every member of the request's value with the same value, and a `succeeded` or `failed`
 * terminal event binds the server's response by its digest.
 */
function mcpBindingProblem(event: JsonObject, request: JsonObject): string | undefined {
  const call = extensionValues(request, MCP_BINDING)[0];
  if (call === undefined) {
    return undefined;
  }
  const recorded = extensionValues(event, MCP_BINDING);
  for (const value of recorded) {
    if (Object.keys(call).some((member) => !has(value, member) || !pythonEquals(get(value, member), get(call, member)))) {
      return "the event's MCP binding names another call than its request";
    }
  }
  const state = textAt(event, "event", "state");
  if (textAt(event, "event_type") === "execution_terminal" && state !== undefined && MCP_RESPONSE_STATES.has(state) && !recorded.some((value) => has(value, "response_digest"))) {
    return "the terminal event binds no server response";
  }
  return undefined;
}

/**
 * EBMP2-078 and DCMP-2 DCMP2-056: each request that carries `continues` continues a request of the
 * bundle that a `challenge` response answered, on an approval of that request: the objects that
 * `continues` names, when the bundle holds them, are that request, its `challenge` response and an
 * `intervention` event that approves it; the continuation keeps the continued request's workflow
 * and root trace, has a greater attempt and the same action, actor, subject and requested
 * authority; it lists the response and the approval among its causal predecessors by identifier
 * and digest; when the continuation's own response is an `admit`, the approval is signed only by
 * keys with the approval purpose, none bound to the request's actor, and, when it states
 * `expires_at`, expires after that response was evaluated; and no two requests
 * continue one response. Findings of stage 5,
 * `ecl.error.decision-binding-invalid.v1`. Every check whose objects the bundle holds is made: a
 * named object that the bundle does not hold exempts no other check, leaves the causal closure
 * incomplete (EBMP2-059, EBMP2-078) and keeps `bindings`, whose object set names it, out of
 * `established` (EBMP2-076): returns whether one is missing.
 */
function checkContinuations(entries: readonly Entry[], findings: Sink, ledger: Ledger, versions: readonly TrustPolicy[]): boolean {
  let missing = false;
  const objects = new Map<string, Entry>();
  for (const entry of entries) {
    const identifier = identifierOf(entry.payload);
    if (identifier !== null && !objects.has(identifier)) {
      objects.set(identifier, entry);
    }
  }
  const continued = new Set<string>();
  // Every decision request, also one that pairing refuses (a continuation in its continued
  // request's attempt repeats that attempt).
  for (const request of entries) {
    if (request.observation || request.check.kind !== "decision_request") {
      continue;
    }
    const continues = objectAt(request.payload, "continues");
    if (continues === undefined) {
      continue;
    }
    ledger.ran("continuation-history", request.index);
    const fail = (message: string): void => {
      findings.push(issue(DECISION_BINDING_INVALID, `envelope ${request.index}: the continuation ${message}`));
    };
    const requestId = textAt(continues, "request_id");
    const responseId = textAt(continues, "response_id");
    const approvalId = textAt(continues, "approval_id");
    const prior = requestId === undefined ? undefined : objects.get(requestId);
    const response = responseId === undefined ? undefined : objects.get(responseId);
    const approval = approvalId === undefined ? undefined : objects.get(approvalId);
    if (prior === undefined || response === undefined || approval === undefined) {
      // An object of the item's set that the bundle does not hold: the check cannot hold over the
      // whole set, whatever the checks of the objects it holds give.
      missing = true;
      ledger.ran("continuation-history", request.index, false);
    }
    // The continuation with the objects that it names (the request-response-pairs set): the
    // continuation check covers them; the other binding checks have nothing more to check there.
    for (const named of [prior, response, approval]) {
      if (named !== undefined) {
        ledger.member("request-response-pairs", named.index);
        for (const check of ["pairing", "continuation-history", "response-binding", "event-binding", "outcome-reasons"]) {
          ledger.ran(check, named.index);
        }
      }
    }
    if (responseId !== undefined) {
      if (continued.has(responseId)) {
        fail("continues a response that another request continues");
      }
      continued.add(responseId);
    }
    if (prior !== undefined) {
      if (prior.check.kind !== "decision_request" || prior.observation) {
        fail("names as its continued request an object that is not a decision request");
      } else {
        const workflow = objectAt(request.payload, "workflow") ?? {};
        const priorWorkflow = objectAt(prior.payload, "workflow") ?? {};
        const attempt = get(workflow, "attempt");
        const priorAttempt = get(priorWorkflow, "attempt");
        if (!pythonEquals(get(workflow, "workflow_id"), get(priorWorkflow, "workflow_id")) || !pythonEquals(get(workflow, "root_trace_id"), get(priorWorkflow, "root_trace_id"))) {
          fail("is not in the continued request's workflow and root trace");
        }
        if (!isInteger(attempt) || !isInteger(priorAttempt) || attempt <= priorAttempt) {
          fail("does not have a greater attempt than the continued request");
        }
        for (const member of ["action", "actor", "subject", "authority_request"]) {
          if (!pythonEquals(get(request.payload, member) ?? null, get(prior.payload, member) ?? null)) {
            fail(`changes the continued request's ${member}`);
          }
        }
      }
    }
    if (response !== undefined) {
      if (response.check.kind !== "decision_response" || response.observation || textAt(response.payload, "request_id") !== requestId || textAt(response.payload, "outcome") !== "challenge") {
        fail("names as its challenge an object that is not the challenge response to the continued request");
      }
    }
    if (approval !== undefined) {
      const event = objectAt(approval.payload, "event") ?? {};
      if (
        textAt(approval.payload, "protocol") !== "EBMP-2" ||
        get(event, "kind") !== "intervention" ||
        get(event, "operation") !== "approve" ||
        requestId === undefined ||
        get(event, "target_id") !== requestId
      ) {
        fail("names as its approval an object that is not an approval of the continued request");
      }
      // When the continuation's own response admits it (DCMP2-057: a deny or a new challenge is
      // the correct answer to an approval that is not acceptable), the approval rests on the
      // approval service's keys, none of them the requesting actor's, as EBMP2-070 condition 5 asks
      // of an approval record, and is still in force when that response is evaluated.
      const own = textAt(request.payload, "message_id");
      const answer = entries.find((entry) => !entry.observation && entry.check.kind === "decision_response" && own !== undefined && textAt(entry.payload, "request_id") === own);
      if (answer !== undefined && textAt(answer.payload, "outcome") === "admit") {
        const keys = signerKeys(approval, versions);
        if (keys.length === 0 || keys.some((key) => !key.purposes.includes(PURPOSE_APPROVAL))) {
          fail("names an approval signed by a key without the approval purpose");
        }
        const actor = textAt(request.payload, "actor", "id");
        if (actor !== undefined && keys.some((key) => key.principal === actor)) {
          fail("names an approval signed by a key of the request's actor");
        }
        const expires = instantOrNull(get(event, "expires_at"));
        const evaluated = instantOrNull(get(answer.payload, "evaluated_at"));
        if (has(event, "expires_at") && expires !== null && evaluated !== null && !(expires > evaluated)) {
          fail("rests on an approval that expired before its response was evaluated");
        }
      }
    }
    // DCMP2-056: the response and the approval are causal predecessors, by identifier and digest.
    const predecessors = get(objectAt(request.payload, "workflow") ?? {}, "causal_predecessors");
    const listed = (isArray(predecessors) ? predecessors : []).filter(isObject);
    for (const [name, identifier, held] of [
      ["challenge response", responseId, response],
      ["approval", approvalId, approval],
    ] as const) {
      const reference = listed.find((item) => identifier !== undefined && get(item, "id") === identifier);
      if (reference === undefined || (held !== undefined && !referenceDigestMatches(reference, held.payload))) {
        fail(`does not list its ${name} among its causal predecessors with its digest`);
      }
    }
  }
  return missing;
}

/** Pairing, request-response binding and event binding: stages 5 to 7 of EBMP2-068. */
function pairMain(entries: readonly Entry[], checks: BindingCheck[], found: Findings, skew: number, ledger: Ledger): Pairs {
  const pairing = found.at(STAGE_PAIRING);
  const requestsBinding = found.at(STAGE_REQUESTS);
  const events = found.at(STAGE_EVENTS);
  const main = entries.filter((entry) => !entry.observation);
  const requests = new Map<string, Entry>();
  const byAction = new Map<AttemptKey, Entry>();
  const responses = new Map<string, Entry>();
  const eventRequest = new Map<number, Entry>();
  const eventResponse = new Map<number, Entry | undefined>();
  const consumed = new Set<AttemptKey>();
  const released = new Set<AttemptKey>();
  const terminal = new Set<AttemptKey>();
  const boundReleases = new Set<number>();
  const releasedKeys = new Set<AttemptKey>();
  let releaseRecorded = false;
  let completionAfterWindow = false;
  // EBMP2-073: each authority_consumed event in state consumed that binds its response.
  const uses: Array<readonly [Entry, Entry]> = [];

  for (const entry of main) {
    if (PAIRED_KINDS.has(entry.check.kind)) {
      // Pairing considers each of these objects, and the binding checks each pair it makes; an
      // object with nothing to check under a binding rule (a request without `continues` under
      // EBMP2-078, an event under DCMP2-044) holds under it.
      ledger.member("request-response-pairs", entry.index);
      for (const check of ["pairing", "continuation-history", "response-binding", "event-binding", "outcome-reasons"]) {
        ledger.ran(check, entry.index);
      }
    }
  }
  for (const entry of main) {
    if (entry.check.kind !== "decision_request") {
      continue;
    }
    const identifier = identifierOf(entry.payload);
    const key = attemptKey(entry.payload);
    if (identifier === null || key === undefined) {
      pairing.push(issue(SCHEMA_INVALID, "a request lacks an identity or action"));
      continue;
    }
    if (requests.has(identifier) || byAction.has(key)) {
      pairing.push(issue(DECISION_BINDING_INVALID, "requests repeat an identity or action"));
      continue;
    }
    requests.set(identifier, entry);
    byAction.set(key, entry);
  }

  for (const entry of main) {
    if (entry.check.kind !== "decision_response") {
      continue;
    }
    const requestId = textAt(entry.payload, "request_id");
    const request = requests.get(requestId ?? "");
    if (requestId === undefined || request === undefined) {
      pairing.push(issue(DECISION_BINDING_INVALID, "a response has no request"));
      continue;
    }
    if (responses.has(requestId)) {
      pairing.push(issue(DECISION_BINDING_INVALID, "a request has multiple responses"));
      continue;
    }
    responses.set(requestId, entry);
    runBinding(`response:${entry.index}`, () => checkResponseBinding(request.payload, entry.payload, skew), checks, requestsBinding);
    ledger.ran("response-binding", entry.index);
    ledger.ran("response-binding", request.index);
  }

  checkAttemptIdentity(main, pairing);

  for (const entry of main) {
    const payload = entry.payload;
    if (textAt(payload, "protocol") !== "EBMP-2") {
      continue;
    }
    const kind = entry.check.kind;
    if (kind === "authority_issued" || kind === "authority_consumed") {
      const authorizationId = textAt(payload, "event", "authorization_id");
      const matches = [...responses.values()].filter((response) => textAt(response.payload, "authorization", "authorization_id") === authorizationId);
      const response = matches[0];
      if (matches.length !== 1 || response === undefined) {
        pairing.push(issue(DECISION_BINDING_INVALID, "an authority event has no unique response"));
        continue;
      }
      const requestId = textAt(response.payload, "request_id");
      const request = requests.get(requestId ?? "");
      if (request === undefined) {
        pairing.push(issue(DECISION_BINDING_INVALID, "an authority event has no request"));
        continue;
      }
      eventRequest.set(entry.index, request);
      eventResponse.set(entry.index, response);
      ledger.ran("event-binding", entry.index);
      const passed = runBinding(`authority:${entry.index}`, () => checkAuthorityEventBinding(entry.payload, response.payload), checks, events);
      checkAuthorityDigest(entry, response, events);
      const key = attemptKey(request.payload);
      if (passed && key !== undefined && entry.check.historical === "valid" && textAt(payload, "event", "state") === "consumed") {
        consumed.add(key);
      }
      if (passed && kind === "authority_consumed" && textAt(payload, "event", "state") === "consumed") {
        uses.push([entry, response]);
      }
      continue;
    }
    if (kind !== "execution_released" && kind !== "execution_terminal") {
      continue;
    }
    releaseRecorded = releaseRecorded || kind === "execution_released";
    const key = attemptKey(payload, true);
    const request = key === undefined ? undefined : byAction.get(key);
    if (request === undefined) {
      pairing.push(issue(DECISION_BINDING_INVALID, "an execution event has no request"));
      continue;
    }
    const requestId = identifierOf(request.payload);
    const pairedResponse = responses.get(requestId ?? "");
    eventRequest.set(entry.index, request);
    eventResponse.set(entry.index, pairedResponse);
    ledger.ran("event-binding", entry.index);
    const passed = runBinding(
      `execution:${entry.index}`,
      () => checkEventBinding(entry.payload, request.payload, pairedResponse === undefined ? undefined : pairedResponse.payload),
      checks,
      events,
    );
    if (pairedResponse !== undefined) {
      checkAuthorityDigest(entry, pairedResponse, events);
    }
    if (passed) {
      // EBMP2-075: an event that carries the MCP binding names the call its request bound.
      const problem = mcpBindingProblem(payload, request.payload);
      if (problem !== undefined) {
        events.push(issue(DECISION_BINDING_INVALID, `envelope ${entry.index}: ${problem}`));
      }
    }
    if (key !== undefined && kind === "execution_terminal") {
      terminal.add(key);
      if (passed && pairedResponse !== undefined) {
        // EBMP2-072: a terminal event that records that the release completed after the
        // authorization's valid_until; a late answer from the server is information.
        ledger.ran("release-window", entry.index);
        if (releasedAfterValidUntil(payload)) {
          events.push(issue(EXPIRED, `envelope ${entry.index}: the terminal event records that the release completed after the authorization's valid_until`));
        }
        if (completedAfterWindow(payload, pairedResponse.payload)) {
          completionAfterWindow = true;
        }
      }
    }
    if (kind === "execution_released") {
      if (key !== undefined) {
        releasedKeys.add(key);
      }
      // EBMP2-050: the release, compared with its attempt's request and response.
      for (const index of [entry.index, request.index, pairedResponse?.index]) {
        ledger.member("released-attempts", index);
        if (index !== undefined) {
          ledger.ran("release-window", index);
        }
      }
    }
    if (key !== undefined && passed && kind === "execution_released") {
      released.add(key);
      boundReleases.add(entry.index);
      const authorization = pairedResponse === undefined ? undefined : objectAt(pairedResponse.payload, "authorization");
      const start = authorization === undefined ? undefined : textAt(authorization, "valid_from");
      const end = authorization === undefined ? undefined : textAt(authorization, "valid_until");
      const observed = textAt(payload, "observed_at");
      const guard = releaseGuardNs(payload);
      // EBMP2-050 and EBMP2-071: the release is observed no earlier than valid_from, and the
      // observation plus the declared release guard is earlier than valid_until.
      if (start === undefined || end === undefined || observed === undefined || guard === null || !(nanos(start) <= nanos(observed)) || !(nanos(observed) + guard < nanos(end))) {
        events.push(issue(EXPIRED, "the release, with its declared release guard, lies outside the authorization's validity window"));
      }
    }
  }

  // `released-attempts` holds each released attempt's terminal events too (EBMP2-072).
  for (const entry of main) {
    const key = entry.check.kind === "execution_terminal" ? attemptKey(entry.payload, true) : undefined;
    if (key !== undefined && releasedKeys.has(key)) {
      ledger.member("released-attempts", entry.index);
    }
  }
  checkUseCounts(uses, events);

  for (const entry of main) {
    if (entry.check.kind !== "execution_terminal") {
      continue;
    }
    const key = attemptKey(entry.payload, true);
    const state = textAt(entry.payload, "event", "state");
    if (key === undefined || state === undefined || !NON_RELEASE.has(state)) {
      continue;
    }
    const event = objectAt(entry.payload, "event") ?? {};
    if (consumed.has(key) || released.has(key) || Object.prototype.hasOwnProperty.call(event, "authority") || truthy(get(event, "side_effects"))) {
      events.push(issue(DECISION_BINDING_INVALID, "a non-release terminal contradicts authority use or release"));
    }
  }
  return { requests, responses, eventRequest, eventResponse, consumed, released, terminal, boundReleases, releaseRecorded, completionAfterWindow };
}

type ObligationKey = string;

function obligationKey(identifier: string, kind: string): ObligationKey {
  return JSON.stringify([identifier, kind]);
}

/**
 * EBMP2-070 on one decision response: the obligations it leaves to Enforcement before the release,
 * by (`obligation_id`, `type`), in order and each once: each obligation whose `satisfaction` is
 * `before_release`, and a witness result whose `outcome` is `required_before_release`, named by
 * the `uri` of its reference and the type `ecl.obligation.verify-witness.v1`; every obligation it
 * carries, the witness result included; whether it carries an obligation to be met during or
 * after execution (EBMP2-076); and the value of each obligation it carries, the witness's URI for
 * the witness result.
 */
function obligationKeys(response: JsonObject): [ObligationKey[], Set<ObligationKey>, boolean, Map<ObligationKey, JsonValue | undefined>] {
  const required: ObligationKey[] = [];
  const carried = new Set<ObligationKey>();
  const values = new Map<ObligationKey, JsonValue | undefined>();
  let postRelease = false;
  const obligations = get(response, "obligations");
  for (const item of isArray(obligations) ? obligations : []) {
    if (!isObject(item)) {
      continue;
    }
    const identifier = get(item, "id");
    const kind = get(item, "type");
    if (!isString(identifier) || !isString(kind)) {
      continue;
    }
    const key = obligationKey(identifier, kind);
    carried.add(key);
    if (!values.has(key)) {
      values.set(key, get(item, "value"));
    }
    const satisfaction = get(item, "satisfaction");
    if (satisfaction === "before_release") {
      if (!required.includes(key)) {
        required.push(key);
      }
    } else if (isString(satisfaction) && POST_RELEASE.has(satisfaction)) {
      postRelease = true;
    }
  }
  for (const value of extensionValues(response, COUPLING)) {
    const witness = get(value, "witness_result");
    const reference = isObject(witness) ? get(witness, "reference") : undefined;
    const uri = isObject(reference) ? get(reference, "uri") : undefined;
    if (isObject(witness) && get(witness, "outcome") === "required_before_release" && isString(uri)) {
      const key = obligationKey(uri, WITNESS_OBLIGATION_TYPE);
      carried.add(key);
      if (!values.has(key)) {
        values.set(key, uri);
      }
      if (!required.includes(key)) {
        required.push(key);
      }
    }
  }
  return [required, carried, postRelease, values];
}

/**
 * The `source` that the response's witness result names for `witness`, if it names one: the issuer
 * that a verify-witness obligation names (EBMP2-070, condition b).
 */
function witnessSource(response: JsonObject, witness: string): string | undefined {
  for (const value of extensionValues(response, COUPLING)) {
    const result = get(value, "witness_result");
    if (!isObject(result)) {
      continue;
    }
    const reference = get(result, "reference");
    const uri = isObject(reference) ? get(reference, "uri") : undefined;
    const source = get(result, "source");
    if (uri === witness && isString(source)) {
      return source;
    }
  }
  return undefined;
}

/**
 * Whether an event carries `ecl.ext.obligation-discharge.v1`, and each entry of it that is an
 * object, with the index of its extension and its position in `obligations`.
 */
function discharges(event: JsonObject): [boolean, Array<[number, number, JsonObject]>] {
  const extensions = get(event, "extensions");
  let present = false;
  const found: Array<[number, number, JsonObject]> = [];
  (isArray(extensions) ? extensions : []).forEach((extension, index) => {
    if (!isObject(extension) || get(extension, "id") !== OBLIGATION_DISCHARGE) {
      return;
    }
    present = true;
    const value = get(extension, "value");
    const listed = isObject(value) ? get(value, "obligations") : undefined;
    (isArray(listed) ? listed : []).forEach((item, position) => {
      if (isObject(item)) {
        found.push([index, position, item]);
      }
    });
  });
  return [present, found];
}

/**
 * What the conditions of EBMP2-070 compare an entry with: the bound release's request and
 * response, the release's observation and declared guard, the response's issue time, the response
 * clock-skew allowance and the request's actor.
 */
interface Release {
  readonly request: JsonObject;
  readonly response: JsonObject;
  readonly observed: bigint | null;
  readonly guard: bigint | null;
  readonly issued: bigint | null;
  readonly skewSeconds: number;
  readonly actor: string | undefined;
}

/** The release plus its declared release guard, before which every proof must be fresh. */
function deadlineOf(release: Release): bigint | null {
  return release.observed === null || release.guard === null ? null : release.observed + release.guard;
}

/** A condition that an entry fails: the finding code, the path below the entry and a message. */
type DischargeProblem = [string, string, string];

/**
 * Conditions 2 to 4 of EBMP2-070 and the freshness of a recorded `fresh_until` on one entry that
 * names an obligation of the response, each checked on members present with the types the value
 * schema gives them, as the reference's `_discharge_problems`.
 */
function dischargeProblems(item: JsonObject, release: Release): DischargeProblem[] {
  const problems: DischargeProblem[] = [];
  const result = get(item, "result");
  if (isString(result) && result !== "satisfied") {
    problems.push([DISCHARGE_RULE, "/result", "records an obligation that was not met"]);
  }
  const checked = instantOrNull(get(item, "checked_at"));
  if (checked !== null && release.observed !== null && checked > release.observed) {
    problems.push([DISCHARGE_RULE, "/checked_at", "was checked after the release was observed"]);
  }
  if (checked !== null && release.issued !== null && checked < release.issued - BigInt(Math.max(release.skewSeconds, 0)) * 1_000_000_000n) {
    problems.push([DISCHARGE_RULE, "/checked_at", "was checked before the decision was issued"]);
  }
  const proof = get(item, "proof");
  if (isObject(proof)) {
    const obtained = instantOrNull(get(proof, "obtained_at"));
    if (obtained !== null && checked !== null && obtained > checked) {
      problems.push([DISCHARGE_RULE, "/proof/obtained_at", "has a proof obtained after it was checked"]);
    }
  }
  // EBMP2-070, freshness: the release plus its declared guard comes before `fresh_until`.
  const fresh = instantOrNull(get(item, "fresh_until"));
  const deadline = deadlineOf(release);
  if (fresh !== null && deadline !== null && !(deadline < fresh)) {
    problems.push([OBLIGATION_UNPROVEN, "/fresh_until", "is not later than the release plus its declared release guard"]);
  }
  return problems;
}

/**
 * The principals that the trust-policy version an object names binds to the keys that signed its
 * envelope (EBMP2-070, condition b).
 */
function signerKeys(entry: Entry, versions: readonly TrustPolicy[]): TrustedKey[] {
  const reference = get(objectAt(entry.payload, "integrity_policy") ?? {}, "trust_policy");
  const version = versions.find((item) => referenceMatches(item, reference));
  const keys: TrustedKey[] = [];
  if (version === undefined) {
    return keys;
  }
  for (const keyId of signatureIds(entry.envelope)) {
    const key = version.key(keyId);
    if (key !== undefined) {
      keys.push(key);
    }
  }
  return keys;
}

/**
 * Whether the decision names an issuer for the obligation (EBMP2-070, condition b): a verify-witness
 * obligation names the `source` of its witness result, when the response gives one; an approval
 * obligation's issuer is the approval service, which the trust policy marks with the approval
 * purpose; an obligation of any other type names none. When none is named, the issuer test is not
 * made and the scope item is not established (EBMP2-076, `issuer-not-named`).
 */
function issuerNamed(key: ObligationKey, value: JsonValue | undefined, response: JsonObject): boolean {
  const kind = (JSON.parse(key) as [string, string])[1];
  if (kind === APPROVAL_OBLIGATION_TYPE) {
    return true;
  }
  if (kind === WITNESS_OBLIGATION_TYPE) {
    return isString(value) && witnessSource(response, value) !== undefined;
  }
  return false;
}

/**
 * EBMP2-070, condition d: a causal predecessor of the proof names the decision request by its
 * `message_id` and its digest.
 */
function namesTheRequest(proof: JsonObject, request: JsonObject): boolean {
  const workflow = objectAt(proof, "workflow");
  const predecessors = workflow === undefined ? undefined : get(workflow, "causal_predecessors");
  const identifier = textAt(request, "message_id");
  return (isArray(predecessors) ? predecessors : []).some((predecessor) => isObject(predecessor) && get(predecessor, "id") === identifier && referenceDigestMatches(predecessor, request));
}

/**
 * Conditions a to e of EBMP2-070 on a carried proof: the object of the bundle that the entry names
 * by reference, whose digest the entry records, as the reference's `_proof_problems`: (a) the
 * object is a valid envelope under the trust policy; (b) the trust policy binds its signing keys
 * to the issuer the obligation names, when it names one, and never to the requesting actor; (c)
 * the object is of a type the obligation admits, and never a decision message; (d) a causal
 * predecessor names the decision request with its digest, and an approval's `target_id` is the
 * request; (e) the object is fresh at the release plus its declared guard, by the bound the
 * object declares, and the recorded `fresh_until` is not later than that bound. For an approval
 * obligation the issuer test of (b) is that every signing key holds the approval purpose.
 */
function proofProblems(item: JsonObject, key: ObligationKey, value: JsonValue | undefined, proof: Entry, release: Release, versions: readonly TrustPolicy[]): DischargeProblem[] {
  const path = "/proof/reference";
  if (proof.check.historical !== "valid") {
    return [[OBLIGATION_UNPROVEN, path, "names a proof whose envelope is not valid under the trust policy"]];
  }
  const problems: DischargeProblem[] = [];
  const payload = proof.payload;
  const kind = (JSON.parse(key) as [string, string])[1];
  const witness = kind === WITNESS_OBLIGATION_TYPE && isString(value) ? value : undefined;
  // (b) The signers, as the trust policy binds the keys.
  const keys = signerKeys(proof, versions);
  const principals = new Set(keys.map((key) => key.principal));
  const issuer = witness === undefined ? undefined : witnessSource(release.response, witness);
  if (issuer !== undefined && !(principals.size === 1 && principals.has(issuer))) {
    problems.push([OBLIGATION_UNPROVEN, path, "names a proof not signed by the issuer the obligation names"]);
  }
  if (release.actor !== undefined && principals.has(release.actor)) {
    problems.push([OBLIGATION_UNPROVEN, path, "names a proof that the requesting actor signed"]);
  }
  if (kind === APPROVAL_OBLIGATION_TYPE && textAt(payload, "event_type") === "human_intervention" && (keys.length === 0 || keys.some((key) => !key.purposes.includes(PURPOSE_APPROVAL)))) {
    // The approval service's keys hold the approval purpose (MG1-013): any other trusted producer
    // of evidence events, the enforcement point itself among them, could otherwise sign an
    // approval of its own request.
    problems.push([OBLIGATION_UNPROVEN, path, "names an approval record signed by a key without the approval purpose"]);
  }
  // (c) The type the obligation admits.
  if (textAt(payload, "protocol") !== "EBMP-2") {
    problems.push([OBLIGATION_UNPROVEN, path, "names a decision message as a proof"]);
    return problems;
  }
  const eventType = textAt(payload, "event_type");
  const event = objectAt(payload, "event") ?? {};
  if (kind === WITNESS_OBLIGATION_TYPE) {
    if (eventType !== "verification") {
      problems.push([OBLIGATION_UNPROVEN, path, "names a proof of a type the obligation does not admit"]);
    } else {
      if (textAt(event, "subject", "uri") !== witness) {
        problems.push([OBLIGATION_UNPROVEN, path, "names a witness result of another witness"]);
      }
      if (get(event, "decision") !== "pass") {
        problems.push([OBLIGATION_UNPROVEN, path, "names a witness result that did not pass"]);
      }
    }
  } else if (kind === APPROVAL_OBLIGATION_TYPE) {
    if (eventType !== "human_intervention") {
      problems.push([OBLIGATION_UNPROVEN, path, "names a proof of a type the obligation does not admit"]);
    } else {
      const approver = isObject(value) ? get(value, "approver") : undefined;
      if (get(event, "operation") !== "approve") {
        problems.push([OBLIGATION_UNPROVEN, path, "names an intervention that does not approve"]);
      }
      if (!isString(approver) || textAt(event, "actor", "id") !== approver) {
        problems.push([OBLIGATION_UNPROVEN, path, "names an approval by an approver other than the one the obligation names"]);
      }
    }
  }
  // (d) The binding to this exchange.
  if (eventType === "human_intervention" && get(event, "target_id") !== textAt(release.request, "message_id")) {
    problems.push([OBLIGATION_UNPROVEN, path, "names an approval of another request"]);
  }
  if (!namesTheRequest(payload, release.request)) {
    problems.push([OBLIGATION_UNPROVEN, path, "names a proof whose causal predecessors do not name this request with its digest"]);
  }
  // (e) Freshness by the bound the proof declares: an intervention expires at `expires_at`.
  const bound = eventType === "human_intervention" ? instantOrNull(get(event, "expires_at")) : null;
  const deadline = deadlineOf(release);
  if (bound !== null && deadline !== null) {
    if (!(deadline < bound)) {
      problems.push([OBLIGATION_UNPROVEN, path, "names a proof that expired before the release plus its declared release guard"]);
    }
    const fresh = instantOrNull(get(item, "fresh_until"));
    if (fresh !== null && fresh > bound) {
      problems.push([OBLIGATION_UNPROVEN, "/fresh_until", "is later than the bound the proof declares"]);
    }
  }
  return problems;
}

/**
 * EBMP2-070 on each `execution_released` event that binds its request and response, as the
 * reference's `_check_obligation_discharge`: the obligations its response leaves to Enforcement
 * before the release each have a consistent discharge, no entry names an obligation the response
 * does not carry or names one twice, and each proof that the bundle carries passes conditions a
 * to e. Findings belong to stage 8 of EBMP2-068. Returns whether the rule applied to a release
 * whose response leaves an obligation to Enforcement, whether such a response carries an
 * obligation to be met during or after execution, whether an entry's proof is not an object of
 * the bundle, and whether the decision names no issuer for an obligation whose proof is carried
 * (EBMP2-076).
 */
function checkObligationDischarge(entries: readonly Entry[], pairs: Pairs, findings: Sink, versions: readonly TrustPolicy[], skewSeconds: number, ledger: Ledger): [boolean, boolean, boolean, boolean] {
  const objects = new Map<string, Entry>();
  for (const entry of entries) {
    const identifier = identifierOf(entry.payload);
    if (identifier !== null) {
      objects.set(identifier, entry);
    }
  }
  let applied = false;
  let postRelease = false;
  let uncarried = false;
  let unnamed = false;
  for (const entry of entries) {
    if (entry.observation || !pairs.boundReleases.has(entry.index)) {
      continue;
    }
    const response = pairs.eventResponse.get(entry.index);
    const request = pairs.eventRequest.get(entry.index);
    if (response === undefined || request === undefined) {
      continue;
    }
    // The released attempt (`released-attempts`): the release, its request and response, and the
    // attempt's terminal events, which have nothing more to discharge.
    const releasedKey = attemptKey(entry.payload, true);
    const terminals = entries.filter((other) => !other.observation && other.check.kind === "execution_terminal" && releasedKey !== undefined && attemptKey(other.payload, true) === releasedKey);
    for (const index of [entry.index, request.index, response.index, ...terminals.map((other) => other.index)]) {
      ledger.ran("obligation-discharge", index);
    }
    ledger.ran("obligation-proofs", entry.index);
    const [required, carried, post, values] = obligationKeys(response.payload);
    postRelease = postRelease || post;
    applied = applied || required.length > 0;
    const [present, discharged] = discharges(entry.payload);
    if (discharged.length > 0) {
      // `discharge-entries`: each entry of the discharge on a release, with the proof it names.
      ledger.member("discharge-entries", entry.index);
    }
    if (required.length > 0 && !present) {
      findings.push(issue(DISCHARGE_RULE, `object ${entry.index}: the release rests on obligations left to Enforcement and records no discharge`));
      continue;
    }
    const release: Release = {
      request: request.payload,
      response: response.payload,
      observed: instantOrNull(get(entry.payload, "observed_at")),
      guard: releaseGuardNs(entry.payload),
      issued: instantOrNull(get(response.payload, "issued_at")),
      skewSeconds,
      actor: textAt(request.payload, "actor", "id"),
    };
    const named = new Set<ObligationKey>();
    for (const [index, position, item] of discharged) {
      const path = `object ${entry.index}: /extensions/${index}/value/obligations/${position}`;
      const identifier = get(item, "obligation_id");
      const kind = get(item, "type");
      if (!isString(identifier) || !isString(kind)) {
        continue;
      }
      const key = obligationKey(identifier, kind);
      if (!carried.has(key)) {
        findings.push(issue(DISCHARGE_RULE, `${path}: names an obligation the response does not carry`));
        continue;
      }
      if (named.has(key)) {
        findings.push(issue(DISCHARGE_RULE, `${path}: names an obligation that another entry names`));
        continue;
      }
      named.add(key);
      const problems = dischargeProblems(item, release);
      const proof = get(item, "proof");
      const reference = isObject(proof) ? get(proof, "reference") : undefined;
      const carriedProof = isString(reference) ? objects.get(reference) : undefined;
      const digest = isObject(proof) ? get(proof, "digest") : undefined;
      if (carriedProof !== undefined) {
        ledger.member("discharge-entries", carriedProof.index);
        ledger.ran("obligation-proofs", carriedProof.index);
      }
      if (carriedProof === undefined) {
        // The proof is not an object of the bundle: not an ECL object that the verifier can
        // check (EBMP2-076, `proof-not-ecl-object`).
        uncarried = true;
      } else if (isObject(digest) && !pythonEquals(digest, { algorithm: "ecl.digest.sha-256.v1", value: objectDigest(carriedProof.payload) })) {
        problems.push([DISCHARGE_RULE, "/proof/digest", "names an object of the bundle by another digest"]);
      } else {
        if (!issuerNamed(key, values.get(key), release.response)) {
          // The decision names no issuer, so the issuer test of condition b is not made and the
          // proofs are not reported verified (EBMP2-076, `issuer-not-named`).
          unnamed = true;
        }
        problems.push(...proofProblems(item, key, values.get(key), carriedProof, release, versions));
      }
      for (const [code, suffix, message] of problems) {
        findings.push(issue(code, `${path}${suffix}: ${message}`));
      }
    }
    for (const key of required) {
      if (!named.has(key)) {
        findings.push(issue(DISCHARGE_RULE, `object ${entry.index}: an obligation left to Enforcement has no discharge`));
      }
    }
  }
  return [applied, postRelease, uncarried, unnamed];
}

function reasonOf(entry: Entry, response: Entry | undefined, findings: Sink): string | null {
  const state = textAt(entry.payload, "event", "state");
  const extensions = get(entry.payload, "extensions");
  const matching = isArray(extensions) ? extensions.filter((extension) => isObject(extension) && pythonEquals(get(extension, "id"), OUTCOME_REASON)) : [];
  if (matching.length > 1) {
    findings.push(issue(SEMANTIC_INVALID, "a terminal has multiple outcome reasons"));
  }
  const first = matching[0];
  if (first !== undefined) {
    const value = get(first, "value");
    const code = isObject(value) ? get(value, "code") : undefined;
    if (!isObject(value) || Object.keys(value).length !== 1 || !Object.prototype.hasOwnProperty.call(value, "code") || typeof code !== "string" || !activeErrorCodes().has(code)) {
      findings.push(issue(SEMANTIC_INVALID, "a terminal has an invalid outcome reason"));
      return null;
    }
    if (state === "succeeded") {
      findings.push(issue(SEMANTIC_INVALID, "a succeeded terminal has an outcome reason"));
    }
    return code;
  }
  const outcome = response === undefined ? undefined : textAt(response.payload, "outcome");
  if (state === "expired_before_release" || (state === "denied" && (outcome === undefined || outcome === "admit"))) {
    findings.push(issue(SEMANTIC_INVALID, "a terminal is missing its required outcome reason"));
  }
  if (state !== undefined && NON_RELEASE.has(state) && response !== undefined) {
    const reasons = get(response.payload, "reasons");
    if (isArray(reasons) && reasons.length > 0 && isObject(reasons[0])) {
      const code = get(reasons[0], "code");
      return typeof code === "string" ? code : null;
    }
  }
  return null;
}

function disjoint(left: ReadonlySet<string>, right: ReadonlySet<string>): boolean {
  for (const item of left) {
    if (right.has(item)) {
      return false;
    }
  }
  return true;
}

/**
 * EBMP2-061: whether every side effect of a `succeeded` terminal has an observation that
 * corroborates it: a historically valid `verification` event with decision `pass` whose subject has
 * the side effect's `uri` and digest, that names the terminal among its causal predecessors by
 * `object_id` and digest, that has the terminal's workflow, root trace and attempt, observed no
 * earlier than the terminal, by another principal, signed only with key material disjoint from the
 * terminal's. The caller asks only when the bundle's causal closure is complete.
 */
function corroborated(terminalEntry: Entry, observations: readonly Entry[]): boolean {
  const event = objectAt(terminalEntry.payload, "event") ?? {};
  const effects = get(event, "side_effects");
  if (!isArray(effects) || effects.length === 0 || terminalEntry.signingKeys.size === 0) {
    return false;
  }
  const terminalAt = textAt(terminalEntry.payload, "observed_at");
  const producer = principalOf(terminalEntry.payload);
  const terminalWorkflow = objectAt(terminalEntry.payload, "workflow");
  const terminalId = textAt(terminalEntry.payload, "object_id");
  if (terminalAt === undefined || producer === undefined || terminalWorkflow === undefined || terminalId === undefined) {
    return false;
  }
  const namesTerminal = (payload: JsonObject): boolean => {
    const predecessors = get(objectAt(payload, "workflow") ?? {}, "causal_predecessors");
    return (isArray(predecessors) ? predecessors : []).some((predecessor) => isObject(predecessor) && get(predecessor, "id") === terminalId && referenceDigestMatches(predecessor, terminalEntry.payload));
  };
  const sameContext = (payload: JsonObject): boolean => {
    const workflow = objectAt(payload, "workflow") ?? {};
    return ["workflow_id", "root_trace_id", "attempt"].every((member) => has(workflow, member) && pythonEquals(get(workflow, member), get(terminalWorkflow, member)));
  };
  for (const effect of effects) {
    if (!isObject(effect) || !isObject(get(effect, "digest"))) {
      return false;
    }
    let matched = false;
    for (const observation of observations) {
      const payload = observation.payload;
      const subject = objectAt(payload, "event", "subject");
      const observedAt = textAt(payload, "observed_at");
      if (
        observation.check.historical === "valid" &&
        observation.signingKeys.size > 0 &&
        disjoint(terminalEntry.signingKeys, observation.signingKeys) &&
        observation.check.kind === "verification" &&
        textAt(payload, "event", "decision") === "pass" &&
        subject !== undefined &&
        pythonEquals(get(subject, "uri"), get(effect, "uri")) &&
        pythonEquals(get(subject, "digest"), get(effect, "digest")) &&
        principalOf(payload) !== producer &&
        namesTerminal(payload) &&
        sameContext(payload) &&
        observedAt !== undefined &&
        nanos(observedAt) >= nanos(terminalAt)
      ) {
        matched = true;
        break;
      }
    }
    if (!matched) {
      return false;
    }
  }
  return true;
}

function effectsOf(entries: readonly Entry[], pairs: Pairs, findings: Sink, closureComplete: boolean, ledger: Ledger): EffectEvidence[] {
  const observations = entries.filter((entry) => entry.observation);
  const result: EffectEvidence[] = [];
  for (const entry of entries) {
    if (entry.observation || entry.check.kind !== "execution_terminal") {
      continue;
    }
    const payload = entry.payload;
    const actionIdText = textAt(payload, "event", "action_id");
    const actionId = actionIdText === undefined || actionIdText === "" ? "" : actionIdText;
    const stateText = textAt(payload, "event", "state");
    const state = stateText === undefined || stateText === "" ? "unknown" : stateText;
    const key = attemptKey(payload, true);
    const response = pairs.eventResponse.get(entry.index);
    const authority =
      key !== undefined && pairs.consumed.has(key)
        ? "consumed"
        : response !== undefined && textAt(response.payload, "outcome") === "admit"
          ? "issued-unused"
          : "none";
    let level: EffectEvidence["level"] = entry.check.historical !== "valid" ? "none" : "issuer-asserted";
    if (level === "issuer-asserted" && state === "succeeded" && closureComplete && corroborated(entry, observations)) {
      level = "corroborated";
    }
    ledger.ran("corroborating-observation", entry.index, level === "corroborated");
    ledger.ran("outcome-reasons", entry.index);
    const reason = reasonOf(entry, response, findings);
    result.push({ actionId, state, level, authority, reason });
  }
  return result;
}

/**
 * DCMP2-053 in the evidence: each decision response carries its decision basis; no input whose
 * source is the request's actor is recorded as `verifiable`, and the request was not received
 * before it was issued, less the response clock-skew allowance (DCMP2-047); and a basis agrees
 * with the register when the caller supplies one. These are findings of stage 3 of EBMP2-068,
 * ranked by their precedence.
 */
function checkDecisionBases(entries: readonly Entry[], findings: Sink, register: JsonObject | null, skew: number, ledger: Ledger): void {
  // The one-way rule has something to check only in a decision response; it holds for the others.
  for (const entry of entries) {
    ledger.ran("decision-basis-one-way", entry.index);
  }
  const requests = new Map<string, JsonObject>();
  for (const entry of entries) {
    const identifier = textAt(entry.payload, "message_id");
    // As the reference's dict comprehension: a later request with the same identifier wins.
    if (!entry.observation && textAt(entry.payload, "protocol") === "DCMP-2" && textAt(entry.payload, "message_type") === "decision_request" && identifier !== undefined) {
      requests.set(identifier, entry.payload);
    }
  }
  for (const entry of entries) {
    const payload = entry.payload;
    if (entry.observation || textAt(payload, "protocol") !== "DCMP-2" || textAt(payload, "message_type") !== "decision_response") {
      continue;
    }
    ledger.member("decision-responses", entry.index);
    ledger.ran("decision-basis-present", entry.index);
    if (register !== null) {
      ledger.ran("decision-basis-register", entry.index);
    }
    const found = basisValues(payload);
    if (found.length === 0) {
      findings.push(issue(REQUIRED_RULE, `object ${entry.index}: /extensions: the decision response records no decision basis`));
      continue;
    }
    const requestId = textAt(payload, "request_id");
    const request = requestId === undefined ? undefined : requests.get(requestId);
    if (found.length !== 1 || request === undefined) {
      continue;
    }
    const [index, value] = found[0] as [number, JsonValue | undefined];
    if (!isObject(value)) {
      continue;
    }
    for (const [path, message] of requestProblems(value, request, skew)) {
      findings.push(issue(DECISION_BASIS_RULE, `object ${entry.index}: /extensions/${index}/value${path}: ${message}`));
    }
    if (register === null) {
      continue;
    }
    const action = get(request, "action");
    const actionClass = isObject(action) ? get(action, "action_class") : undefined;
    for (const [path, message] of registerProblems(value, register, actionClass, get(payload, "evaluated_at"))) {
      findings.push(issue(REGISTER_RULE, `object ${entry.index}: /extensions/${index}/value${path}: ${message}`));
    }
  }
}

function verifyChecked(source: JsonValue, policy: TrustPolicy, now: string, history: readonly TrustPolicy[], skew: number, acceptCurrentTrustFailure: boolean, requireTrustedTime: boolean, register: JsonObject | null): BundleReport {
  if (!(policy instanceof TrustPolicy)) {
    return invalidReport(issue(POLICY_INVALID, "the current trust policy is not loaded"));
  }
  const problem = historyProblem(policy, history);
  if (problem !== undefined) {
    return invalidReport(problem);
  }
  if (!isObject(source)) {
    return invalidReport(issue(SCHEMA_INVALID, "the evidence bundle is not a JSON object"));
  }
  const envelopes = get(source, "envelopes");
  const observations = Object.prototype.hasOwnProperty.call(source, "observations") ? source["observations"] : [];
  if (!isArray(envelopes) || !isArray(observations)) {
    return invalidReport(issue(SCHEMA_INVALID, "envelopes and observations must be arrays"));
  }
  if (envelopes.length > MAX_ENVELOPES) {
    return invalidReport(issue(RESOURCE_LIMIT, `envelopes exceed the ${MAX_ENVELOPES} entry limit`));
  }
  if (observations.length > MAX_OBSERVATIONS) {
    return invalidReport(issue(RESOURCE_LIMIT, `observations exceed the ${MAX_OBSERVATIONS} entry limit`));
  }
  if (!eclSchemas().isValid(BUNDLE_SCHEMA, source)) {
    return invalidReport(issue(SCHEMA_INVALID, "the evidence bundle does not satisfy its schema"));
  }
  const findings = new Findings();
  const checks: EnvelopeCheck[] = [];
  const bindings: BindingCheck[] = [];
  const decoded: Array<[number, boolean, JsonObject, JsonObject]> = [];
  let nodeCount = 0;
  const budgetExceeded = (): BundleReport => {
    findings.add(STAGE_PAYLOADS, issue(RESOURCE_LIMIT, `decoded payloads exceed the ${MAX_TOTAL_PAYLOAD_NODES} node budget`));
    return {
      verdict: "invalid",
      envelopeChecks: [...checks],
      bindingChecks: [],
      causalStatus: "not-analyzed",
      effects: [],
      findings: findings.ordered(),
      verificationProfile: REFERENCE_PROFILE,
      acceptedCurrentTrustFailure: false,
      register: null,
      scope: { established: [], notEstablished: [], reasons: {}, checks: {} },
      trustDependencies: [],
      checksRun: {},
      objectSets: {},
      evaluationTime: null,
      unresolvedPredecessorIds: [],
      completionAfterWindow: false,
    };
  };
  const all: Array<[boolean, JsonValue]> = [...envelopes.map((value) => [false, value] as [boolean, JsonValue]), ...observations.map((value) => [true, value] as [boolean, JsonValue])];
  for (let index = 0; index < all.length; index += 1) {
    const [isObservation, envelope] = all[index] as [boolean, JsonValue];
    let payload: JsonValue;
    // EBMP2-062: each payload is parsed with the nodes that remain of the bundle's budget as its
    // value budget, so that no payload is built beyond the budget (IE1-029; EBMP2-068, stage 2).
    try {
      payload = decodeCanonicalJsonPayload(envelope, Math.max(MAX_TOTAL_PAYLOAD_NODES - nodeCount, 1));
      if (!isObject(payload)) {
        throw new IntegrityError("signed payload is not an object");
      }
    } catch (error) {
      if (error instanceof PayloadNodeBudgetError) {
        return budgetExceeded();
      }
      if (!(error instanceof IntegrityError)) {
        throw error;
      }
      // A declared limit that the strict parse of the payload reaches is a resource limit; any
      // other failure leaves it outside canonical strict JSON (IE1-040, step 3).
      const code = error.code === RESOURCE_LIMIT ? RESOURCE_LIMIT : INTEGRITY_INVALID;
      checks.push({ index, objectId: null, kind: "unknown", signerKeyIds: signatureIds(envelope), historical: code, current: code, historicalPolicyVersion: null, trustedTime: null });
      findings.add(STAGE_PAYLOADS, issue(code, `envelope ${index} has an invalid payload`));
      continue;
    }
    nodeCount += nodes(payload, MAX_TOTAL_PAYLOAD_NODES - nodeCount);
    if (nodeCount > MAX_TOTAL_PAYLOAD_NODES) {
      return budgetExceeded();
    }
    decoded.push([index, isObservation, envelope as JsonObject, payload]);
  }
  const ledger = new Ledger();
  const versions = [policy, ...history];
  const entries: Entry[] = [];
  const dependencies: TrustDependency[] = [];
  const seenIds = new Set<string>();
  for (const [index, isObservation, envelope, payload] of decoded) {
    ledger.ran("envelope-integrity", index);
    for (const set of ["bundle-objects", "trust-dependencies", "object-signatures"]) {
      ledger.member(set, index);
    }
    const [check, signingKeys, found] = evaluateEnvelope(envelope, payload, index, isObservation, policy, versions, now, findings.at(STAGE_OBJECTS), requireTrustedTime, ledger);
    dependencies.push(...found);
    checks.push(check);
    entries.push({ index, observation: isObservation, envelope, payload, check, signingKeys });
    if (check.historical === SCHEMA_INVALID || check.historical === SEMANTIC_INVALID) {
      // The object's own schema or semantic rules refuse it, and their findings are listed; its
      // signatures were not evaluated, so this is a finding of stage 3, not one about the signers.
      findings.add(STAGE_OBJECTS, issue(check.historical, `envelope ${index} holds an object that fails its schema or semantic rules`));
    } else if (check.historical !== "valid") {
      // Any other status is the signers', a finding of stage 4.
      findings.add(STAGE_SIGNERS, issue(check.historical, `envelope ${index} is not historically valid`));
    }
    if (check.objectId !== null) {
      if (seenIds.has(check.objectId)) {
        findings.add(STAGE_OBJECTS, issue("ecl.rule.bundle-object-identifiers-unique.v1", "message or object identifier is duplicated"));
      }
      seenIds.add(check.objectId);
    }
    ledger.ran("identifiers-unique", index);
    if (isObservation && (textAt(payload, "protocol") !== "EBMP-2" || check.kind !== "verification")) {
      findings.add(STAGE_OBJECTS, issue(SEMANTIC_INVALID, "an observation is not a verification event"));
    }
    ledger.ran("observation-kind", index);
  }
  checkDecisionBases(entries, findings.at(STAGE_OBJECTS), register, skew, ledger);
  const pairs = pairMain(entries, bindings, findings, skew, ledger);
  const continuationMissing = checkContinuations(entries, findings.at(STAGE_PAIRING), ledger, versions);
  checkEventMessageReferences(entries, pairs, bindings, findings.at(STAGE_EVENTS), ledger);
  const [dischargeApplied, postRelease, uncarried, unnamed] = checkObligationDischarge(entries, pairs, findings.at(STAGE_CAUSAL), versions, skew, ledger);
  // EBMP2-059: one causal graph over every object of the bundle, the DCMP-2 messages and the
  // observations among them, with no external predecessor: each object is identified by its
  // `message_id` (DCMP-2) or `object_id` (EBMP-2), and EBMP2-077 applies to each edge.
  const analysis = analyzeBundle(
    entries.map((entry) => entry.payload),
    [],
    undefined,
    undefined,
    { identify: (record) => (textAt(record, "protocol") === "DCMP-2" ? get(record, "message_id") : get(record, "object_id")), causalContext: true },
  );
  findings.at(STAGE_CAUSAL).push(...analysis.findings.map((item) => issue(item.ruleId, `causal graph: ${item.path}: ${item.message}`)));
  for (const entry of entries) {
    for (const check of ["predecessor-digests", "graph-acyclic", "causal-context", "sequence-monotonic", "state-transitions"]) {
      ledger.ran(check, entry.index);
    }
    ledger.ran("predecessors-resolved", entry.index, analysis.unresolvedPredecessorIds.length === 0 && !continuationMissing);
  }
  // EBMP2-055 and EBMP2-074 run for every attempt whose own objects the bundle holds, whatever the
  // closure (EBMP2-059: an absent object exempts no other check). They stay silent only for an
  // attempt whose own objects (its request, the response to it, the authority events of that
  // response and its execution events) name an unresolved predecessor, which could be the
  // consumption or the release they look for.
  const unresolved = new Set(analysis.unresolvedPredecessorIds);
  const namesUnresolved = (entry: Entry): boolean => {
    const predecessors = get(objectAt(entry.payload, "workflow") ?? {}, "causal_predecessors");
    return (isArray(predecessors) ? predecessors : []).some((item) => isObject(item) && typeof get(item, "id") === "string" && unresolved.has(get(item, "id") as string));
  };
  const attemptObjects = new Map<AttemptKey, Entry[]>();
  const addTo = (key: AttemptKey | undefined, entry: Entry | undefined): void => {
    if (key !== undefined && entry !== undefined) {
      attemptObjects.set(key, [...(attemptObjects.get(key) ?? []), entry]);
    }
  };
  for (const request of pairs.requests.values()) {
    const key = attemptKey(request.payload);
    addTo(key, request);
    addTo(key, pairs.responses.get(identifierOf(request.payload) ?? ""));
  }
  for (const entry of entries) {
    if (entry.observation) {
      continue;
    }
    const kind = entry.check.kind;
    if (kind === "authority_issued" || kind === "authority_consumed") {
      const request = pairs.eventRequest.get(entry.index);
      addTo(request === undefined ? undefined : attemptKey(request.payload), entry);
    } else if (textAt(entry.payload, "protocol") === "EBMP-2" && textAt(entry.payload, "event", "kind") === "execution") {
      addTo(attemptKey(entry.payload, true), entry);
    }
  }
  const silent = (key: AttemptKey | undefined): boolean => key === undefined || (attemptObjects.get(key) ?? []).some(namesUnresolved);
  for (const entry of entries) {
    const keys = [...attemptObjects.entries()].filter(([, objects]) => objects.includes(entry)).map(([key]) => key);
    ledger.ran("attempt-authority-consumed", entry.index, !keys.some(silent));
  }
  for (const entry of entries) {
    if (entry.observation || entry.check.kind !== "execution_terminal") {
      continue;
    }
    if (textAt(entry.payload, "event", "state") !== "succeeded") {
      continue;
    }
    const key = attemptKey(entry.payload, true);
    if (silent(key)) {
      continue;
    }
    if (key === undefined || !pairs.consumed.has(key) || !pairs.released.has(key)) {
      findings.add(STAGE_CAUSAL, issue(DECISION_BINDING_INVALID, "a succeeded attempt lacks consumed authority or release evidence"));
    }
  }
  // EBMP2-074: a release of single-use authority has its consumption recorded, whatever the
  // terminal state of its attempt.
  for (const entry of entries) {
    if (entry.observation || !pairs.boundReleases.has(entry.index)) {
      continue;
    }
    const key = attemptKey(entry.payload, true);
    const response = pairs.eventResponse.get(entry.index);
    if (key !== undefined && !silent(key) && !pairs.consumed.has(key) && response !== undefined && textAt(response.payload, "authorization", "use_policy") === "single_use") {
      findings.add(STAGE_CAUSAL, issue(DECISION_BINDING_INVALID, `envelope ${entry.index}: a release of single-use authority has no recorded consumption`));
    }
  }
  let missingTerminal = false;
  // A terminal is required of each request; every other object has nothing to check here.
  for (const entry of entries) {
    if (entry.check.kind !== "decision_request") {
      ledger.ran("terminal-per-request", entry.index);
    }
  }
  for (const request of pairs.requests.values()) {
    const key = attemptKey(request.payload);
    const open = key !== undefined && !pairs.terminal.has(key);
    missingTerminal = missingTerminal || open;
    ledger.ran("terminal-per-request", request.index, !open);
  }
  const causalStatus = (missingTerminal || continuationMissing) && analysis.status === "complete" ? "incomplete" : analysis.status;
  const effects = effectsOf(entries, pairs, findings.at(STAGE_REASONS), causalStatus === "complete", ledger);
  let verdict: Verdict = findings.size > 0 || causalStatus === "indeterminate" ? "invalid" : causalStatus !== "complete" ? "incomplete" : "verified";
  let accepted = false;
  // EBMP2-060: every trust dependency's current status, a time authority's among them.
  if (verdict === "verified" && (checks.some((check) => check.current !== "valid") || dependencies.some((dependency) => dependency.current !== "valid"))) {
    if (acceptCurrentTrustFailure) {
      accepted = true;
    } else {
      verdict = CURRENT_TRUST_FAILED;
    }
  }
  return {
    verdict,
    envelopeChecks: [...checks].sort((a, b) => a.index - b.index),
    bindingChecks: bindings,
    causalStatus,
    effects,
    findings: findings.ordered(),
    verificationProfile: REFERENCE_PROFILE,
    acceptedCurrentTrustFailure: accepted,
    register: null,
    // The conditional items of the scope that apply to this bundle, and the stated reasons that
    // keep an item out of `established`; `reportScope` places them.
    trustDependencies: dependencies.sort((a, b) => a.index - b.index),
    checksRun: ledger.record(),
    objectSets: ledger.sets(),
    evaluationTime: now,
    unresolvedPredecessorIds: [...analysis.unresolvedPredecessorIds],
    scope: {
      established: [],
      checks: {},
      notEstablished: [...(dischargeApplied ? SCOPE_DISCHARGE : []), ...(postRelease ? [SCOPE_POST_RELEASE] : [])],
      reasons: {
        ...(pairs.releaseRecorded ? {} : { [SCOPE_RELEASE]: REASON_NO_RELEASE }),
        // Both reasons true, the report gives `proof-not-ecl-object`: a proof that is not carried
        // was not checked at all.
        ...(dischargeApplied && uncarried ? { [SCOPE_PROOFS]: REASON_PROOF_NOT_ECL_OBJECT } : dischargeApplied && unnamed ? { [SCOPE_PROOFS]: REASON_ISSUER_NOT_NAMED } : {}),
      },
    },
    completionAfterWindow: pairs.completionAfterWindow,
  };
}

/**
 * The checks of `registries/scope-checks.json`, in its order. A verifier reports for each
 * established item the checks that it ran for the item, in this order.
 */
export const SCOPE_CHECK_ORDER: readonly string[] = [
  "envelope-integrity",
  "time-not-after-evaluation",
  "historical-signers",
  "current-compromise-knowledge",
  "trusted-time-countersignatures",
  "trusted-time-coverage",
  "current-status",
  "object-schema",
  "object-semantics",
  "observation-kind",
  "identifiers-unique",
  "decision-basis-present",
  "decision-basis-one-way",
  "decision-basis-register",
  "pairing",
  "continuation-history",
  "response-binding",
  "event-binding",
  "release-window",
  "predecessors-resolved",
  "predecessor-digests",
  "graph-acyclic",
  "causal-context",
  "sequence-monotonic",
  "state-transitions",
  "terminal-per-request",
  "attempt-authority-consumed",
  "obligation-discharge",
  "obligation-proofs",
  "outcome-reasons",
  "corroborating-observation",
];

/**
 * `registries/scope-checks.json`, `items`: the object set of each item that a verifier can
 * establish and the checks that must hold over it, in the order of SCOPE_CHECK_ORDER.
 */
export const SCOPE_ITEM_CHECKS: Readonly<Record<string, { readonly objectSet: string; readonly checks: readonly string[] }>> = {
  "envelope-signatures": { objectSet: "trust-dependencies", checks: ["envelope-integrity", "time-not-after-evaluation", "historical-signers", "current-compromise-knowledge", "trusted-time-countersignatures"] },
  "current-trust": { objectSet: "trust-dependencies", checks: ["current-status"] },
  "trusted-time": { objectSet: "object-signatures", checks: ["historical-signers", "current-compromise-knowledge", "trusted-time-countersignatures", "trusted-time-coverage"] },
  "object-rules": { objectSet: "bundle-objects", checks: ["object-schema", "object-semantics", "observation-kind", "identifiers-unique", "decision-basis-one-way"] },
  "decision-basis-recorded": { objectSet: "decision-responses", checks: ["decision-basis-present"] },
  "decision-basis-register": { objectSet: "decision-responses", checks: ["decision-basis-register"] },
  bindings: { objectSet: "request-response-pairs", checks: ["pairing", "continuation-history", "response-binding", "event-binding", "outcome-reasons"] },
  "release-within-authority": { objectSet: "released-attempts", checks: ["release-window"] },
  "causal-completeness": {
    objectSet: "bundle-objects",
    checks: ["identifiers-unique", "predecessors-resolved", "predecessor-digests", "graph-acyclic", "causal-context", "sequence-monotonic", "state-transitions", "terminal-per-request", "attempt-authority-consumed"],
  },
  "prerelease-obligations-discharge-recorded": { objectSet: "released-attempts", checks: ["obligation-discharge"] },
  "prerelease-obligations-proofs-verified": { objectSet: "discharge-entries", checks: ["obligation-proofs"] },
};

/**
 * The `index` values of the objects of an object set of `registries/scope-checks.json` in a report,
 * as its verification found them: every object for the bundle's objects, its trust dependencies and
 * its signatures (`object-signatures`: an object without a countersignature fails the trusted-time
 * coverage check); the decision responses; each request with its paired response and events and each
 * continuation with the objects it names; each `execution_released` event with its attempt's
 * request and response; and each such event that carries a discharge with the proofs it names.
 */
export function scopeObjects(report: BundleReport, objectSet: string): number[] {
  return [...(report.objectSets[objectSet] ?? [])].sort((a, b) => a - b);
}

/**
 * Whether every check that `item` requires ran over the item's whole object set and held there,
 * by the report's record of the checks it ran (EBMP2-076): the checks and objects behind the item,
 * or undefined when a check did not run over an object of the set or did not hold for one.
 */
function itemChecks(report: BundleReport, item: string): ScopeChecks | undefined {
  const required = SCOPE_ITEM_CHECKS[item];
  if (required === undefined) {
    return undefined;
  }
  const objects = scopeObjects(report, required.objectSet).sort((a, b) => a - b);
  for (const check of required.checks) {
    const record = report.checksRun[check];
    if (objects.length === 0) {
      // A check with nothing to check in the item's object set holds (EBMP2-076).
      continue;
    }
    if (record === undefined || objects.some((index) => !record.ran.includes(index) || record.failed.includes(index))) {
      return undefined;
    }
  }
  return { checks: [...required.checks], objects };
}

/**
 * EBMP2-076: the scope of a report's verdict, from the report alone, as the reference's
 * `report_scope`. `established` holds the checks that the verifier made and that held: none for an
 * `invalid` report or one without an evaluated envelope, and none whose required checks
 * (`registries/scope-checks.json`) did not all run and hold over the item's whole object set; for
 * each, `checks` names those checks and the objects they covered. `notEstablished` holds the other
 * items that apply and the statements that no verification establishes. The conditional items that
 * apply are those already in the report's scope, so the function gives the same scope again for a
 * report whose verdict another check has changed, as for an offline package (IE1-022).
 */
export function reportScope(report: BundleReport): ReportScope {
  const applies = new Set([...report.scope.established, ...report.scope.notEstablished]);
  const reasons: Record<string, string> = { ...report.scope.reasons };
  const discharge = applies.has(SCOPE_DISCHARGE[0] as string);
  const postRelease = applies.has(SCOPE_POST_RELEASE);
  const checks = report.envelopeChecks;
  const established = new Set<string>();
  if (checks.length > 0 && (report.verdict === "verified" || report.verdict === CURRENT_TRUST_FAILED || report.verdict === "incomplete")) {
    for (const item of ["envelope-signatures", "object-rules", "bindings"]) {
      established.add(item);
    }
    if (!(SCOPE_RELEASE in reasons)) {
      established.add(SCOPE_RELEASE);
    }
    if (
      (report.verdict === "verified" || report.verdict === "incomplete") &&
      checks.every((check) => check.current === "valid") &&
      report.trustDependencies.every((dependency) => dependency.current === "valid")
    ) {
      established.add("current-trust");
    }
    if (checks.every((check) => check.trustedTime !== null)) {
      established.add("trusted-time");
    }
    established.add("decision-basis-recorded");
    if (report.register !== null) {
      established.add("decision-basis-register");
    }
    if (report.verdict !== "incomplete") {
      established.add("causal-completeness");
    }
    if (discharge) {
      established.add(SCOPE_DISCHARGE[0] as string);
      if (!(SCOPE_PROOFS in reasons)) {
        established.add(SCOPE_PROOFS);
      }
    }
  }
  // TP1-006: an item that rests on trust dependencies is established only when each of them is
  // historically valid, a counted or uncounted signature that does not verify among the reasons:
  // envelope-signatures over the signers of envelopes and observations, trusted-time over the
  // signers of the attestations.
  for (const [item, role] of [
    ["envelope-signatures", "signer"],
    ["trusted-time", "time-authority"],
  ] as const) {
    if (report.trustDependencies.some((dependency) => dependency.role === role && dependency.historical !== "valid")) {
      established.delete(item);
    }
  }
  // The claim-to-check map: an item stays established only when its checks ran and held.
  const behind: Record<string, ScopeChecks> = {};
  for (const item of [...established]) {
    const found = itemChecks(report, item);
    if (found === undefined) {
      established.delete(item);
    } else {
      behind[item] = found;
    }
  }
  const items = [...SCOPE_CHECKS, ...SCOPE_NEVER].filter(
    (item) =>
      !CONDITIONAL_SCOPE.has(item) ||
      (SCOPE_DISCHARGE.includes(item) && discharge) ||
      (item === SCOPE_POST_RELEASE && postRelease) ||
      (item === SCOPE_REGISTER && report.register !== null),
  );
  const kept: Record<string, string> = {};
  for (const item of items) {
    if (item in reasons && !established.has(item)) {
      kept[item] = reasons[item] as string;
    }
  }
  const listed = items.filter((item) => established.has(item));
  return {
    established: listed,
    notEstablished: items.filter((item) => !established.has(item)),
    reasons: kept,
    checks: Object.fromEntries(listed.map((item) => [item, behind[item] as ScopeChecks])),
  };
}

/**
 * `registries/scope-checks.json`, `evidence_levels`: the items that a report must establish for an
 * effect to be `corroborated` (EBMP2-061).
 */
export const CORROBORATION_ITEMS: readonly string[] = ["envelope-signatures", "causal-completeness"];

/**
 * The report with the scope of its verdict (EBMP2-076), and its evidence levels decided after the
 * scope: `corroborated` only when the scope establishes CORROBORATION_ITEMS, else
 * `issuer-asserted` (an `invalid` report establishes nothing, so it never reports `corroborated`);
 * and its unresolved predecessors listed only when the verdict is `incomplete`.
 */
export function withScope(report: BundleReport): BundleReport {
  const scope = reportScope(report);
  const supported = CORROBORATION_ITEMS.every((item) => scope.established.includes(item));
  const effects = supported ? report.effects : report.effects.map((effect) => (effect.level === "corroborated" ? { ...effect, level: "issuer-asserted" as const } : effect));
  // EBMP2-076: the unresolved predecessors are listed only in an incomplete report.
  const unresolvedPredecessorIds = report.verdict === "incomplete" ? report.unresolvedPredecessorIds : [];
  return { ...report, scope, effects, unresolvedPredecessorIds };
}

function validNow(now: unknown): string {
  if (typeof now !== "string" || !NOW.test(now)) {
    throw new RangeError("now must be RFC 3339 UTC with 0, 3 or 6 fractional digits");
  }
  if (!isInstant(now)) {
    throw new RangeError("now is not a calendar-valid UTC instant");
  }
  return now;
}

/**
 * Verify signatures, bindings, causality and effects of a signed evidence bundle under the
 * reference verification profile. `policy` is the caller's current trust policy; `history` holds
 * exact earlier versions of it. Invalid bundle data is reported, never thrown; an invalid `now`,
 * clock-skew allowance or flag throws RangeError.
 */
export function verifyBundle(bundle: JsonValue, policy: TrustPolicy, options: VerifyBundleOptions): BundleReport {
  const now = validNow(options.now);
  const skew = options.responseClockSkewSeconds ?? 0;
  if (!Number.isInteger(skew) || skew < 0) {
    throw new RangeError("the response clock-skew allowance is a non-negative integer of seconds");
  }
  const requireTrustedTime = options.requireTrustedTime ?? false;
  if (typeof requireTrustedTime !== "boolean") {
    throw new RangeError("requireTrustedTime is a boolean");
  }
  const register = options.register ?? null;
  if (register !== null && (!isObject(register) || registerUsageProblems(register).length > 0)) {
    throw new RangeError("the register does not satisfy its schema or ecl.rule.register-declarations-consistent.v1");
  }
  let report: BundleReport;
  try {
    report = verifyChecked(bundle, policy, now, options.history ?? [], skew, options.acceptCurrentTrustFailure === true, requireTrustedTime, register as JsonObject | null);
  } catch (error) {
    if (error instanceof UnsupportedSuiteError) {
      throw error;
    }
    const name = error instanceof Error ? error.name : "Error";
    report = invalidReport(issue(SEMANTIC_INVALID, `bundle verification could not be completed: ${name}`));
  }
  return withScope({
    ...report,
    // Every report states the evaluation time it used, an invalid one included.
    evaluationTime: now,
    verificationProfile: requireTrustedTime ? TRUSTED_TIME_PROFILE : REFERENCE_PROFILE,
    register: register === null ? null : registerReference(register as JsonObject),
  });
}

/** The distinct finding codes of a report, sorted. */
export function findingCodes(report: BundleReport): string[] {
  return [...new Set(report.findings.map((finding) => finding.code))].sort();
}

/**
 * The finding identifiers of a report in the order of EBMP2-068, each once, the primary first: for
 * an invalid bundle the codes of its findings; for an incomplete bundle without findings the
 * causal-closure code; for a bundle whose trust has failed now, the current statuses that are not
 * valid, in the order of stage 4 (EBMP2-060).
 */
export function reportedIdentifiers(report: BundleReport): string[] {
  if (report.verdict === CURRENT_TRUST_FAILED) {
    // EBMP2-060: the current statuses of the trust dependencies, a time authority's among them.
    const rank = (code: string): number => (SIGNER_ORDER.includes(code) ? SIGNER_ORDER.indexOf(code) : SIGNER_ORDER.length);
    const statuses = [...new Set([...report.envelopeChecks.map((check) => check.current), ...report.trustDependencies.map((dependency) => dependency.current)].filter((status) => status !== "valid"))];
    return statuses.sort((a, b) => rank(a) - rank(b) || (a < b ? -1 : a > b ? 1 : 0));
  }
  const codes = [...new Set(report.findings.map((finding) => finding.code))];
  if (report.verdict === "incomplete" && codes.length === 0) {
    return [CAUSAL_CLOSURE_INCOMPLETE];
  }
  return codes;
}

/** The primary finding (EBMP2-060, EBMP2-068, IE1-022), or null when verified. */
export function primaryFinding(report: BundleReport): string | null {
  // An expired offline package has its own finding before any bundle current statuses.
  if (report.verdict === CURRENT_TRUST_FAILED && report.findings.length > 0) {
    return report.findings[0]!.code;
  }
  return reportedIdentifiers(report)[0] ?? null;
}

/**
 * The JSON names of the report members that this round adds and whose names area A's text gives
 * (EBMP2-057 evaluation time, EBMP-2 section 4 unresolved predecessors): kept in one place.
 */
export const REPORT_MEMBER_NAMES = {
  evaluationTime: "evaluation_time",
  unresolvedPredecessorIds: "unresolved_predecessor_ids",
} as const;

/** The report in the JSON shape of the reference's `ecl-verify --json`. */
export function reportToJson(report: BundleReport): JsonObject {
  return {
    verdict: report.verdict,
    primary: primaryFinding(report),
    envelope_checks: report.envelopeChecks.map((check) => ({
      index: check.index,
      object_id: check.objectId,
      kind: check.kind,
      signer_key_ids: [...check.signerKeyIds],
      historical: check.historical,
      current: check.current,
      historical_policy_version: check.historicalPolicyVersion,
      trusted_time: check.trustedTime,
    })),
    binding_checks: report.bindingChecks.map((check) => ({ name: check.name, passed: check.passed, code: check.code })),
    causal_status: report.causalStatus,
    effects: report.effects.map((effect) => ({
      action_id: effect.actionId,
      state: effect.state,
      level: effect.level,
      authority: effect.authority,
      reason: effect.reason,
    })),
    findings: report.findings.map((finding) => `${finding.code}: ${finding.message}`),
    verification_profile: report.verificationProfile,
    accepted_current_trust_failure: report.acceptedCurrentTrustFailure,
    register: report.register,
    scope: {
      established: [...report.scope.established],
      not_established: [...report.scope.notEstablished],
      reasons: { ...report.scope.reasons },
      checks: Object.fromEntries(Object.entries(report.scope.checks).map(([item, behind]) => [item, { checks: [...behind.checks], objects: [...behind.objects] }])),
    },
    trust_dependencies: report.trustDependencies.map((dependency) => ({
      index: dependency.index,
      role: dependency.role,
      counter_id: dependency.counterId,
      key_id: dependency.keyId,
      suite: dependency.suite,
      at: dependency.at,
      historical_policy_version: dependency.historicalPolicyVersion,
      historical: dependency.historical,
      current_policy_version: dependency.currentPolicyVersion,
      revoked_effective_at: dependency.revokedEffectiveAt,
      current: dependency.current,
    })),
    completion_after_window: report.completionAfterWindow,
    [REPORT_MEMBER_NAMES.evaluationTime]: report.evaluationTime,
    [REPORT_MEMBER_NAMES.unresolvedPredecessorIds]: [...report.unresolvedPredecessorIds],
  };
}
