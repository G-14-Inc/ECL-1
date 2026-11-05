/**
 * Offline verification of an ECL offline package (OFFLINE-VERIFICATION-1) as the evidence bundle it
 * carries (IE1-021, IE1-022), with the reference's verdicts and findings
 * (`ecl_reference.package_verification.verify_offline_package`).
 *
 * A package is an `ecl.zip.store.v1` archive: `manifest.json` and the artifacts it names, each
 * bound by role, size and SHA-256 digest. Its `envelope` and `observation` artifacts are the
 * envelopes and observations of one evidence bundle, its `payload` artifacts are their canonical
 * payloads, and the rest is material the producer used: evidence, never a trust anchor. The bundle
 * is verified under the trust policy, earlier policy versions and evaluation time that the caller
 * supplies, exactly as `verifyBundle` verifies any bundle; the caller's options are passed to it
 * unchanged, so an option that the bundle verifier gains reaches the package's bundle without a
 * change here.
 *
 * `verifyOfflinePackage` makes the checks of IE1-022 in order and reports the verdict of EBMP2-060
 * and the error code of the first that fails:
 *
 * 1. the archive is in `ecl.zip.store.v1` form (`readStoredZip`), or `invalid`, semantic-invalid;
 * 2. it holds `manifest.json`, or `incomplete`, causal-closure-incomplete;
 * 3. the manifest is strict JSON that satisfies its schema, with valid `created_at` and
 *    `expires_at` instants and a SHA-256 digest in every artifact entry and reference, or
 *    `invalid`, schema-invalid;
 * 4. its artifact paths could be the entry names of one such archive together with
 *    `manifest.json`, and it names every other member, or `invalid`, semantic-invalid;
 * 5. `expires_at` is later than `created_at`, or `invalid`, expired;
 * 6. every artifact the archive holds has its manifest size and digest, or `invalid`,
 *    integrity-invalid;
 * 7. every `envelope` and `observation` artifact is a strict JSON object, or `invalid`,
 *    schema-invalid;
 * 8. every `payload` artifact is the payload of one of them, or `invalid`, integrity-invalid;
 * 9. when the package carries an envelope, the bundle is not `invalid`, or `invalid` with the
 *    bundle's findings;
 * 10. every artifact the manifest names or IE1-021 requires, and the payload of every packaged
 *     envelope and observation, is present, and there is an envelope, or `incomplete`,
 *     causal-closure-incomplete;
 * 11. the bundle is not `incomplete`, or `incomplete` with the bundle's findings.
 *
 * Otherwise the package has its bundle's verdict, except that a package whose `expires_at` is not
 * later than the evaluation time is `current-trust-failed`, with the expired code, where its bundle
 * is `verified`. Times are compared to the microsecond, as the reference compares them. A package
 * that exceeds a declared limit of the verifier (IE1-028) is `invalid` with
 * `ecl.error.resource-limit-exceeded.v1` at the check that meets the limit: the archive's limits at
 * check 1, the strict JSON parser's limits at checks 3 and 7, and the artifact count and path bytes
 * at check 4.
 */

import { sha256Hex, utf8 } from "../crypto/bytes.js";
import { reportedIdentifiers, verifyBundle, withScope, CURRENT_TRUST_FAILED, CAUSAL_CLOSURE_INCOMPLETE } from "../evidence/verify.js";
import type { BundleFinding, BundleReport, Verdict, VerifyBundleOptions } from "../evidence/verify.js";
import { loadPolicyBytes, loadRegister, VerifierInputError } from "../evidence/bytes.js";
import type { BytesOptions } from "../evidence/bytes.js";
import { decodePayload, IntegrityError } from "../integrity/envelope.js";
import { parseStrictJson, StrictJsonError } from "../json/strict.js";
import { get, isArray, isObject } from "../json/value.js";
import type { JsonObject, JsonValue } from "../json/value.js";
import { eclSchemas } from "../schema/validator.js";
import { InstantError, instantMicroseconds } from "../time.js";
import { TrustPolicy } from "../trust/policy.js";
import { ArchiveRefusal, checkLimits, DEFAULT_OFFLINE_RESOURCE_LIMITS, fileAndDirectory, foldAscii, isEntryName, readStoredZip } from "./zip.js";
import type { OfflineResourceLimits } from "./zip.js";

export const MANIFEST_NAME = "manifest.json";
export const MANIFEST_SCHEMA = "https://externalcontrollayer.ai/ns/schema/offline-verification-package/1";
/** The media type of an offline package (OFFLINE-VERIFICATION-1). */
export const PACKAGE_MEDIA_TYPE = "application/vnd.ecl.bundle+zip";
/** The error of a declared limit (IE1-028), which IE1-022 gives a package over a limit. */
export const RESOURCE_LIMIT = "ecl.error.resource-limit-exceeded.v1";
const SCHEMA_INVALID = "ecl.error.schema-invalid.v1";
const SEMANTIC_INVALID = "ecl.error.semantic-invalid.v1";
const INTEGRITY_INVALID = "ecl.error.integrity-invalid.v1";
const EXPIRED = "ecl.error.expired.v1";
const SHA_256 = "ecl.digest.sha-256.v1";
/** The roles of which IE1-021 requires at least one artifact. */
const REQUIRED_ROLES = ["envelope", "payload", "registry_snapshot", "revocation_snapshot", "time_evidence", "trust_policy", "verification_key"];
/** The artifact roles whose envelopes form the package's bundle, and the member each fills. */
const EVIDENCE_ROLES = new Map<string, "envelopes" | "observations">([
  ["envelope", "envelopes"],
  ["observation", "observations"],
]);
/** The manifest references whose artifacts IE1-021 requires, with the role of each artifact. */
const REFERENCE_ROLES: ReadonlyArray<readonly [string, string]> = [
  ["trust_policy", "trust_policy"],
  ["revocation_snapshot", "revocation_snapshot"],
  ["registry_snapshots", "registry_snapshot"],
  ["time_evidence", "time_evidence"],
];

/** The caller's inputs: the bundle verifier's options, passed to it unchanged, and the limits. */
export interface VerifyOfflinePackageOptions extends VerifyBundleOptions {
  /** The verifier's declared resource limits (IE1-028); the reference's when absent. */
  readonly limits?: OfflineResourceLimits;
}

function issue(code: string, message: string): BundleFinding {
  return { code, message };
}

function references(manifest: JsonObject): Array<[string, JsonValue]> {
  const found: Array<[string, JsonValue]> = [];
  for (const [member, role] of REFERENCE_ROLES) {
    const value = manifest[member] as JsonValue;
    for (const item of isArray(value) ? value : [value]) {
      found.push([role, item]);
    }
  }
  return found;
}

function strictJson(data: Uint8Array, name: string): { value: JsonValue } | { finding: BundleFinding } {
  try {
    return { value: parseStrictJson(data) };
  } catch (error) {
    if (error instanceof StrictJsonError) {
      return { finding: issue(error.kind === "budget" ? RESOURCE_LIMIT : SCHEMA_INVALID, `${name} is not strict JSON: ${error.message}`) };
    }
    throw error;
  }
}

/** Why the manifest fails check 3, or undefined. */
function manifestProblem(manifest: JsonValue): string | undefined {
  if (!isObject(manifest) || !eclSchemas().isValid(MANIFEST_SCHEMA, manifest)) {
    return `${MANIFEST_NAME} does not satisfy ${MANIFEST_SCHEMA}`;
  }
  try {
    instantMicroseconds(manifest["created_at"]);
    instantMicroseconds(manifest["expires_at"]);
  } catch (error) {
    if (error instanceof InstantError) {
      return "created_at or expires_at is not a valid instant";
    }
    throw error;
  }
  for (const item of manifest["artifacts"] as JsonObject[]) {
    if (get(item["digest"], "algorithm") !== SHA_256) {
      return `artifact ${String(item["path"])} has no ${SHA_256} digest`;
    }
  }
  for (const [role, reference] of references(manifest)) {
    if (get(get(reference, "digest"), "algorithm") !== SHA_256) {
      return `a ${role} reference has no ${SHA_256} digest`;
    }
  }
  return undefined;
}

/**
 * Check 4: why the manifest's artifact paths are not entry names that one archive could hold
 * together with `manifest.json`, and whether that is a declared limit; undefined when they are.
 */
function pathProblem(artifacts: readonly JsonObject[], limits: OfflineResourceLimits): BundleFinding | undefined {
  if (artifacts.length > limits.maxMemberCount) {
    return issue(RESOURCE_LIMIT, "offline package artifact count exceeds the verifier budget");
  }
  const seen = new Set<string>();
  const aliases = new Set<string>();
  for (const item of artifacts) {
    const path = item["path"] as string;
    if (utf8(path).length > limits.maxPathBytes) {
      return issue(RESOURCE_LIMIT, "an artifact path exceeds the verifier budget");
    }
    if (!isEntryName(path)) {
      return issue(SEMANTIC_INVALID, `unsafe package path: ${JSON.stringify(path)} is not an ecl.zip.store.v1 entry name`);
    }
    const alias = foldAscii(path);
    if (alias === MANIFEST_NAME) {
      return issue(SEMANTIC_INVALID, `the manifest names ${MANIFEST_NAME}, or an alias of it, as an artifact`);
    }
    if (seen.has(path) || aliases.has(alias)) {
      return issue(SEMANTIC_INVALID, `duplicate package path: ${path}`);
    }
    seen.add(path);
    aliases.add(alias);
  }
  const conflict = fileAndDirectory([...seen, MANIFEST_NAME].sort());
  if (conflict !== undefined) {
    return issue(SEMANTIC_INVALID, `package path is both a file and a directory: ${conflict}`);
  }
  return undefined;
}

/**
 * The verdict of an offline package under the caller's trust policy at `options.now`. `policy`
 * and the options are the caller's inputs to `verifyBundle`, which receives them unchanged;
 * nothing the package carries replaces them. Package data is reported, never thrown. An invalid
 * caller argument throws RangeError before the package is read, whatever it holds: an `archive`
 * that is not bytes, invalid `limits`, and every option that `verifyBundle` refuses.
 */
export function verifyOfflinePackage(archive: Uint8Array, policy: TrustPolicy, options: VerifyOfflinePackageOptions): BundleReport {
  if (!(archive instanceof Uint8Array)) {
    throw new RangeError("an offline package is bytes");
  }
  const { limits: given, ...bundleOptions } = options;
  const limits = checkLimits(given ?? DEFAULT_OFFLINE_RESOURCE_LIMITS);
  // The bundle verifier checks the caller's options itself, before it reads a bundle: it throws
  // RangeError for one it refuses, and otherwise reports this empty bundle as invalid. Its report
  // carries what the options give every report (the verification profile among them), so the
  // package's own refusals start from it.
  const base = verifyBundle({}, policy, bundleOptions);
  // EBMP2-076: the scope follows the package's verdict.
  const failed = (verdict: Verdict, findings: BundleFinding[]): BundleReport => withScope({ ...base, verdict, findings });
  // 1. The container profile, within the verifier's limits.
  let members: Map<string, Uint8Array>;
  try {
    members = new Map(readStoredZip(archive, limits).map((member) => [member.name, member.data]));
  } catch (error) {
    if (error instanceof ArchiveRefusal) {
      return failed("invalid", [issue(error.limit ? RESOURCE_LIMIT : SEMANTIC_INVALID, error.message)]);
    }
    throw error;
  }
  // 2. The manifest.
  const manifestBytes = members.get(MANIFEST_NAME);
  if (manifestBytes === undefined) {
    return failed("incomplete", [issue(CAUSAL_CLOSURE_INCOMPLETE, `there is no ${MANIFEST_NAME}`)]);
  }
  // 3. Strict JSON, its schema, its times and SHA-256 digests.
  const parsed = strictJson(manifestBytes, MANIFEST_NAME);
  if ("finding" in parsed) {
    return failed("invalid", [parsed.finding]);
  }
  const problem = manifestProblem(parsed.value);
  if (problem !== undefined) {
    return failed("invalid", [issue(SCHEMA_INVALID, problem)]);
  }
  const manifest = parsed.value as JsonObject;
  const artifacts = manifest["artifacts"] as JsonObject[];
  // 4. Entry names that one archive could hold with the manifest, naming exactly the other members.
  const unsafe = pathProblem(artifacts, limits);
  if (unsafe !== undefined) {
    return failed("invalid", [unsafe]);
  }
  const listed = new Set(artifacts.map((item) => item["path"] as string));
  const unnamed = [...members.keys()].filter((name) => name !== MANIFEST_NAME && !listed.has(name)).sort();
  if (unnamed.length > 0) {
    return failed("invalid", [issue(SEMANTIC_INVALID, `the archive holds a member the manifest does not name: ${unnamed[0] as string}`)]);
  }
  // 5. The package's validity interval, to the microsecond.
  const createdAt = instantMicroseconds(manifest["created_at"]);
  const expiresAt = instantMicroseconds(manifest["expires_at"]);
  if (expiresAt <= createdAt) {
    return failed("invalid", [issue(EXPIRED, "the package expires no later than it was created")]);
  }
  const expired = instantMicroseconds(options.now) >= expiresAt;
  // 6. Size and digest of every artifact the archive holds; check 1 bounded them by the limits.
  const carried = new Map<string, Uint8Array>();
  const absent: string[] = [];
  for (const item of artifacts) {
    const path = item["path"] as string;
    const data = members.get(path);
    if (data === undefined) {
      absent.push(path);
      continue;
    }
    if (item["size_bytes"] !== data.length) {
      return failed("invalid", [issue(INTEGRITY_INVALID, `the size of ${path} differs from its manifest entry`)]);
    }
    if (get(item["digest"], "value") !== sha256Hex(data)) {
      return failed("invalid", [issue(INTEGRITY_INVALID, `the digest of ${path} differs from its manifest entry`)]);
    }
    carried.set(path, data);
  }
  // 7. The evidence bundle: the envelope and observation artifacts.
  const bundle: { schema_version: string; envelopes: JsonValue[]; observations?: JsonValue[] } = { schema_version: "ecl_evidence_bundle_v1", envelopes: [] };
  const payloads = new Set<string>();
  for (const item of artifacts) {
    const member = EVIDENCE_ROLES.get(item["role"] as string);
    const data = carried.get(item["path"] as string);
    if (member === undefined || data === undefined) {
      continue;
    }
    const envelope = strictJson(data, item["path"] as string);
    if ("finding" in envelope) {
      return failed("invalid", [envelope.finding]);
    }
    if (!isObject(envelope.value)) {
      return failed("invalid", [issue(SCHEMA_INVALID, `${String(item["path"])} is not a JSON object`)]);
    }
    (bundle[member] ??= []).push(envelope.value);
    try {
      payloads.add(sha256Hex(decodePayload(envelope.value)));
    } catch (error) {
      // The bundle verifier refuses an envelope whose payload does not decode (check 9).
      if (!(error instanceof IntegrityError)) {
        throw error;
      }
    }
  }
  // 8. Every payload artifact is the payload of a packaged envelope or observation.
  const roles = new Map<string, Set<string>>();
  for (const item of artifacts) {
    if (carried.has(item["path"] as string)) {
      const role = item["role"] as string;
      const digests = roles.get(role) ?? new Set<string>();
      digests.add(get(item["digest"], "value") as string);
      roles.set(role, digests);
    }
  }
  const stray = [...(roles.get("payload") ?? [])].filter((digest) => !payloads.has(digest)).sort();
  if (stray.length > 0) {
    return failed("invalid", [issue(INTEGRITY_INVALID, `a payload artifact is no packaged envelope's payload: sha256 ${stray[0] as string}`)]);
  }
  // 9. The bundle, under the caller's trust policy, history and evaluation time.
  let report: BundleReport | undefined;
  if (bundle.envelopes.length > 0) {
    report = verifyBundle(bundle as unknown as JsonValue, policy, bundleOptions);
    if (report.verdict === "invalid") {
      return report;
    }
  }
  // 10. The material IE1-021 requires, every payload, and at least one envelope.
  const missing = absent.map((path) => `the archive lacks ${path}, which the manifest names`);
  for (const role of REQUIRED_ROLES) {
    if (!roles.has(role)) {
      missing.push(`no artifact has the required role ${role}`);
    }
  }
  for (const [role, reference] of references(manifest)) {
    if (!(roles.get(role) ?? new Set()).has(get(get(reference, "digest"), "value") as string)) {
      missing.push(`the ${role} artifact that the manifest references is not carried`);
    }
  }
  const carriedPayloads = roles.get("payload") ?? new Set<string>();
  for (const digest of [...payloads].filter((item) => !carriedPayloads.has(item)).sort()) {
    missing.push(`the payload of a packaged envelope is not carried: sha256 ${digest}`);
  }
  if (report === undefined) {
    missing.push("the package carries no envelope");
    return failed(
      "incomplete",
      missing.map((message) => issue(CAUSAL_CLOSURE_INCOMPLETE, message)),
    );
  }
  if (missing.length > 0) {
    return withScope({ ...report, verdict: "incomplete", findings: [...missing.map((message) => issue(CAUSAL_CLOSURE_INCOMPLETE, message)), ...report.findings] });
  }
  // 11. The bundle's own closure, then its verdict.
  if (report.verdict === "incomplete") {
    return report;
  }
  if (expired && report.verdict === "verified") {
    return withScope({ ...report, verdict: CURRENT_TRUST_FAILED, findings: [...report.findings, issue(EXPIRED, `the package expired at ${String(manifest["expires_at"])}`)] });
  }
  return report;
}

/**
 * A package report's identifiers in order, each once, the primary first, as the runner's `package`
 * stage reports them (IE1-022, EBMP2-068; the reference's `reported_package_identifiers`): the
 * codes of its findings in the order of the checks that gave them; for a `current-trust-failed`
 * package, after the expired code of a package that has expired, the current status of each
 * envelope that is not valid, in the order of stage 4 of EBMP2-068; and for an `incomplete`
 * package without findings the causal-closure code.
 */
export function packageIdentifiers(report: BundleReport): string[] {
  const codes = [...new Set(report.findings.map((finding) => finding.code))];
  if (report.verdict === CURRENT_TRUST_FAILED) {
    return [...codes, ...reportedIdentifiers(report).filter((code) => !codes.includes(code))];
  }
  if (report.verdict === "incomplete" && codes.length === 0) {
    return [CAUSAL_CLOSURE_INCOMPLETE];
  }
  return codes;
}

/** The options of `verifyPackageBytes`: those of `verifyBundleBytes`, and the limits. */
export interface PackageBytesOptions extends BytesOptions {
  readonly limits?: OfflineResourceLimits;
}

/**
 * Verify a package file against a trust policy file and earlier versions of it, with the trust
 * policy byte limit of TP1-007. Input that cannot be verified at all (a malformed trust policy, an
 * invalid evaluation time or option) is a VerifierInputError; the package itself is always
 * reported.
 */
export function verifyPackageBytes(archive: Uint8Array, trustPolicy: Uint8Array, options: PackageBytesOptions): { report: BundleReport; policy: TrustPolicy } {
  const policy = loadPolicyBytes(trustPolicy, "trust policy");
  const history = (options.history ?? []).map((data) => loadPolicyBytes(data, "trust policy history"));
  // A register is loaded as verifyBundleBytes loads it (its byte limit, strict JSON and the
  // register schema), before the package is read.
  const register = options.register === undefined ? undefined : loadRegister(options.register);
  const checked = checkLimits(options.limits ?? DEFAULT_OFFLINE_RESOURCE_LIMITS);
  try {
    const report = verifyOfflinePackage(archive, policy, {
      now: options.now,
      history,
      acceptCurrentTrustFailure: options.acceptCurrentTrustFailure === true,
      requireTrustedTime: options.requireTrustedTime === true,
      ...(register === undefined ? {} : { register }),
      limits: checked,
    });
    return { report, policy };
  } catch (error) {
    if (error instanceof RangeError) {
      throw new VerifierInputError(`invalid evaluation time or option: ${error.message}`);
    }
    throw error;
  }
}
