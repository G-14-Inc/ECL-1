/**
 * The shared-corpus runner for this library (Node.js only): it evaluates every vector that
 * `conformance/shared-corpus.json` names, stage by stage, as conformance/README.md defines the
 * stages, and writes a cross-implementation report (version 2) with one raw evidence file per
 * vector, each bound to its report row by its digest. Expected results are read only to state
 * whether each was met; they never enter an evaluation.
 */

import { lstatSync, mkdirSync, openSync, readFileSync, readdirSync, statSync, writeSync, closeSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { sha256Hex, utf8 } from "../crypto/bytes.js";
import { analyzeBundle } from "../bundle/causal.js";
import { canonicalize } from "../json/canonical.js";
import { parseStrictJson, StrictJsonError } from "../json/strict.js";
import type { StrictJsonLimits } from "../json/strict.js";
import { get, isArray, isObject, pythonEquals, textAt } from "../json/value.js";
import type { JsonObject, JsonValue } from "../json/value.js";
import { decodeCanonicalJsonPayload, IntegrityError, verifyEnvelope } from "../integrity/envelope.js";
import { bindingFindings } from "../bindings/index.js";
import { loadExportKeys } from "../bindings/otel.js";
import type { ExportKey } from "../bindings/otel.js";
import { evaluateDocument } from "../documents/documents.js";
import { recordSchemas } from "../schema/validator.js";
import { SemanticValidator } from "../semantic/rules.js";
import { validateSafeStateProfile } from "../semantic/safe-state.js";
import { MAX_TRUST_POLICY_BYTES, TrustPolicy, TrustPolicyError } from "../trust/policy.js";
import { loadRegister, MAX_REGISTER_BYTES } from "../evidence/bytes.js";
import { reportedIdentifiers, verifyBundle } from "../evidence/verify.js";
import type { BundleReport } from "../evidence/verify.js";
import { packageIdentifiers, verifyOfflinePackage } from "../offline/package.js";

/**
 * The capabilities of the shared corpus that this library implements, every one that the corpus
 * declares: among them the binding profiles' rules, the decision-basis rule, the claim and
 * assessment document stage, one version of an extension per object, the extension rules on
 * documents, one role per key, binding inputs that agree with the decision basis, keyed
 * OpenTelemetry digests and offline package verification (IE1-021, IE1-022). A capability the
 * corpus declares and this list lacks is reported unsupported for each of its vectors, never as a
 * pass.
 */
export const CAPABILITIES = [
  "strict-json",
  "canonical-digest",
  "semantic-rules",
  "safe-state-profile-rules",
  "schema-validation",
  "trust-policy-load",
  "envelope-signature-verification",
  "evidence-bundle-verification",
  "control-extension-rules",
  "binding-profile-rules",
  "decision-basis-rule",
  "document-validation",
  "extension-version-rule",
  "document-extension-rules",
  "key-role-separation",
  "binding-basis-agreement-rule",
  "otel-export-keyed-digests",
  "offline-package-verification",
] as const;

export const DISCLOSURE =
  "Same-operator implementation diversity, not an independent implementation or assessment. The TypeScript library is maintained in this repository by the maintainers of the Python reference; it does not import or call the reference.";

const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024;
const SCHEMA_INVALID = "ecl.error.schema-invalid.v1";
/** The registered rules of strict input (IE1-002, IE1-037). */
const STRICT_RULES = ["ecl.rule.json-strict-syntax.v1", "ecl.rule.json-no-duplicate-members.v1", "ecl.rule.json-restricted-numbers.v1"];

export interface CorpusVector {
  readonly id: string;
  readonly path: string;
  readonly stage: string;
  readonly expected: "pass" | "fail";
  readonly expected_primary_id?: string;
  readonly expected_secondary_ids: readonly string[];
  readonly expected_canonical_sha256?: string;
  readonly expected_verdict?: string;
  readonly schema?: string;
  readonly trust_policy_path?: string;
  readonly trust_policy_history_paths?: readonly string[];
  readonly evaluated_at?: string;
  readonly require_trusted_time?: boolean;
  /** Verify with the caller's acceptance of a current trust failure (EBMP2-060). */
  readonly accept_current_trust_failure?: boolean;
  /** The scope the verdict must have: the two lists of EBMP2-076 and their reasons. */
  readonly expected_scope?: { readonly established: readonly string[]; readonly not_established: readonly string[]; readonly reasons: Readonly<Record<string, string>> };
  /** The evidence level that each listed action's terminal effects must have (EBMP2-061). */
  readonly expected_effects?: readonly { readonly action_id: string; readonly level: string }[];
  /** The predecessors that the report must list as unresolved, compared as a set (EBMP2-076). */
  readonly expected_unresolved_predecessor_ids?: readonly string[];
  /** A Consequential Action Register to check each decision basis against (DCMP2-053). */
  readonly register_path?: string;
  /** The declared limits under which the Parse step reads the artifact (IE1-028, IE1-037). */
  readonly strict_json_limits?: { readonly max_bytes: number; readonly max_depth: number; readonly max_nodes: number };
}

/** The budgets of the Parse step: the vector's declared limits, or this library's own. */
function parseLimits(vector: CorpusVector): StrictJsonLimits {
  const limits = vector.strict_json_limits;
  return limits === undefined ? {} : { maxBytes: limits.max_bytes, maxDepth: limits.max_depth, maxNodes: limits.max_nodes };
}

/** Read a repository file without following symlinks, within the artifact budget. */
export function readArtifact(root: string, relativePath: string): Uint8Array {
  if (relativePath === "" || relativePath.startsWith("/") || relativePath.includes("\\") || relativePath.split("/").some((part) => part === "" || part === "." || part === "..")) {
    throw new Error(`unsafe artifact path: ${relativePath}`);
  }
  let current = root;
  for (const part of relativePath.split("/")) {
    current = join(current, part);
    if (lstatSync(current).isSymbolicLink()) {
      throw new Error(`artifact symlink: ${relativePath}`);
    }
  }
  const info = statSync(current);
  if (!info.isFile() || info.size > MAX_ARTIFACT_BYTES) {
    throw new Error(`artifact budget or type: ${relativePath}`);
  }
  return new Uint8Array(readFileSync(current));
}

function readJson(root: string, path: string): JsonObject {
  const value = parseStrictJson(readArtifact(root, path));
  if (!isObject(value)) {
    throw new Error(`${path}: root must be an object`);
  }
  return value;
}

/** Python's json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True). */
export function pythonCompactJson(value: JsonValue): string {
  if (isArray(value)) {
    return "[" + value.map(pythonCompactJson).join(",") + "]";
  }
  if (isObject(value)) {
    return (
      "{" +
      Object.keys(value)
        .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
        .map((key) => JSON.stringify(key) + ":" + pythonCompactJson(value[key] as JsonValue))
        .join(",") +
      "}"
    );
  }
  return JSON.stringify(value);
}

/** The digest that binds a clean source export: the reference report verifier's construction. */
export function sourceTreeDigest(root: string): { digest: string; files: number } {
  const entries: Array<{ path: string; sha256: string; size_bytes: number }> = [];
  const walk = (directory: string): void => {
    for (const name of readdirSync(directory)) {
      const path = join(directory, name);
      const info = lstatSync(path);
      if (info.isSymbolicLink()) {
        throw new Error("source symlink");
      }
      if (info.isDirectory()) {
        if (name === ".git") {
          throw new Error("source must be a clean export");
        }
        walk(path);
      } else if (info.isFile()) {
        const data = readFileSync(path);
        entries.push({ path: relative(root, path).split(sep).join("/"), sha256: sha256Hex(new Uint8Array(data)), size_bytes: data.length });
      } else {
        throw new Error("source is not regular");
      }
    }
  };
  walk(root);
  entries.sort((a, b) => Buffer.compare(Buffer.from(a.path, "utf8"), Buffer.from(b.path, "utf8")));
  return { digest: sha256Hex(utf8(pythonCompactJson(entries as unknown as JsonValue))), files: entries.length };
}

/** The reference runner's choice of a primary identifier and the sorted secondary ones. */
export function selectFindings(observed: readonly string[], precedence: ReadonlyMap<string, number>, errors: ReadonlySet<string>): [string | null, string[]] {
  const findings = new Set(observed);
  const errorIds = new Set([SCHEMA_INVALID, ...errors]);
  const unknown = [...findings].filter((id) => !precedence.has(id) && !errorIds.has(id));
  if (unknown.length > 0) {
    throw new Error(`unregistered findings: ${JSON.stringify(unknown.sort())}`);
  }
  const byPrecedence = (ids: string[]): string => ids.reduce((best, id) => ((precedence.get(id) as number) < (precedence.get(best) as number) ? id : best));
  const strict = [...findings].filter((id) => STRICT_RULES.includes(id));
  let primary: string;
  if (strict.length > 0) {
    primary = byPrecedence(strict);
  } else if (findings.has(SCHEMA_INVALID)) {
    primary = SCHEMA_INVALID;
  } else {
    const reported = [...findings].filter((id) => errorIds.has(id));
    if (reported.length > 1) {
      throw new Error("ambiguous interface errors: a vector must have one loader or integrity error");
    }
    if (reported.length === 1) {
      primary = reported[0] as string;
    } else if (findings.size > 0) {
      primary = byPrecedence([...findings]);
    } else {
      return [null, []];
    }
  }
  findings.delete(primary);
  return [primary, [...findings].sort()];
}

/**
 * The primary finding of a signed bundle, alone or carried in an offline package: the first of its
 * identifiers, in the order of EBMP2-068 (and of IE1-022's checks for a package). No secondary
 * finding is reported.
 */
export function selectBundleFinding(observed: readonly string[], precedence: ReadonlyMap<string, number>, errors: ReadonlySet<string>): [string | null, string[]] {
  const unknown = observed.filter((id) => !precedence.has(id) && !errors.has(id) && id !== SCHEMA_INVALID);
  if (unknown.length > 0) {
    throw new Error(`unregistered findings: ${JSON.stringify([...new Set(unknown)].sort())}`);
  }
  return [observed[0] ?? null, []];
}

function strictFailureId(error: StrictJsonError): string {
  // The finding of the first check of IE1-037 that failed: a rule, or a declared limit's error.
  return error.ruleId;
}

function loadPolicyFile(root: string, path: string): TrustPolicy {
  const data = readArtifact(root, path);
  return TrustPolicy.load(data.subarray(0, MAX_TRUST_POLICY_BYTES + 1));
}

/** The published test export keys that a suite's manifest names (OTEL-EVIDENCE-EXPORT-1, OE1-010). */
export function loadSuiteExportKeys(root: string, path: string): Map<string, ExportKey> {
  return loadExportKeys(readArtifact(root, path).subarray(0, MAX_TRUST_POLICY_BYTES + 1));
}

/** Context shared by the vectors of one run. */
export interface EvaluationContext {
  readonly root: string;
  readonly semantics: SemanticValidator;
  readonly trustPolicy?: TrustPolicy;
  /** The export keys of the vector's suite, when its manifest names a key file. */
  readonly exportKeys?: ReadonlyMap<string, ExportKey>;
  readonly verdicts: Map<string, string>;
  /** Receives, by vector identifier, the scope and evidence levels of a signed bundle's report. */
  readonly scopes?: Map<string, ObservedScope>;
}

/** The scope of a report (EBMP2-076) and the evidence level of each effect (EBMP2-061). */
export interface ObservedScope {
  readonly scope: { readonly established: readonly string[]; readonly not_established: readonly string[]; readonly reasons: Readonly<Record<string, string>> };
  readonly effects: readonly { readonly action_id: string; readonly level: string }[];
  readonly unresolved_predecessor_ids: readonly string[];
}

function observedScope(report: BundleReport): ObservedScope {
  return {
    scope: { established: [...report.scope.established], not_established: [...report.scope.notEstablished], reasons: { ...report.scope.reasons } },
    effects: report.effects.map((effect) => ({ action_id: effect.actionId, level: effect.level })),
    unresolved_predecessor_ids: [...report.unresolvedPredecessorIds],
  };
}

/**
 * Whether a signed bundle's scope and evidence levels are those its vector names, when it names
 * them, as the reference runner compares them: the scope's lists and reasons exactly, for each
 * listed action every reported level of its terminal effects, and the unresolved predecessor
 * identifiers as a set.
 */
export function scopeMatches(vector: CorpusVector, observed: ObservedScope | undefined): boolean {
  if (vector.expected_scope === undefined && vector.expected_effects === undefined && vector.expected_unresolved_predecessor_ids === undefined) {
    return true;
  }
  if (observed === undefined) {
    return false;
  }
  if (vector.expected_scope !== undefined && !pythonEquals(observed.scope as unknown as JsonValue, vector.expected_scope as unknown as JsonValue)) {
    return false;
  }
  if (vector.expected_unresolved_predecessor_ids !== undefined) {
    const reported = new Set(observed.unresolved_predecessor_ids);
    const expected = new Set(vector.expected_unresolved_predecessor_ids);
    if (reported.size !== expected.size || [...expected].some((identifier) => !reported.has(identifier))) {
      return false;
    }
  }
  for (const expected of vector.expected_effects ?? []) {
    const levels = new Set(observed.effects.filter((item) => item.action_id === expected.action_id).map((item) => item.level));
    if (levels.size !== 1 || !levels.has(expected.level)) {
      return false;
    }
  }
  return true;
}

/** The identifiers one vector yields, as the reference runner computes them. */
export function observedForVector(vector: CorpusVector, context: EvaluationContext): string[] {
  const { root } = context;
  const data = readArtifact(root, vector.path);
  if (vector.stage === "trust-policy") {
    try {
      TrustPolicy.load(data.subarray(0, MAX_TRUST_POLICY_BYTES + 1));
    } catch (error) {
      if (error instanceof TrustPolicyError) {
        return [error.code];
      }
      throw error;
    }
    return [];
  }
  if (vector.stage === "package") {
    // An offline package is an archive, so the stage reads bytes, not strict JSON (IE1-022). Its
    // bundle is verified under the same caller inputs as an evidence-bundle vector's.
    const policy = loadPolicyFile(root, vector.trust_policy_path as string);
    const history = (vector.trust_policy_history_paths ?? []).map((path) => loadPolicyFile(root, path));
    const register = vector.register_path === undefined ? undefined : loadRegister(readArtifact(root, vector.register_path).subarray(0, MAX_REGISTER_BYTES + 1));
    const report = verifyOfflinePackage(data, policy, {
      now: vector.evaluated_at as string,
      history,
      acceptCurrentTrustFailure: vector.accept_current_trust_failure === true,
      requireTrustedTime: vector.require_trusted_time === true,
      ...(register === undefined ? {} : { register }),
    });
    context.verdicts.set(vector.id, report.verdict);
    return packageIdentifiers(report);
  }
  let value: JsonValue;
  try {
    value = parseStrictJson(data, parseLimits(vector));
  } catch (error) {
    if (error instanceof StrictJsonError) {
      return [strictFailureId(error)];
    }
    throw error;
  }
  switch (vector.stage) {
    case "strict-json":
      return [];
    case "canonical":
      return sha256Hex(canonicalize(value)) === vector.expected_canonical_sha256 ? [] : ["ecl.error.canonicalization-mismatch.v1"];
    case "bundle": {
      const records = get(value, "records");
      if (!isObject(value) || !isArray(records)) {
        return [SCHEMA_INVALID];
      }
      const analysis = analyzeBundle(records);
      const found = [...new Set(analysis.findings.map((item) => item.ruleId))].sort();
      if (found.length === 0 && analysis.status !== "complete") {
        return ["ecl.error.causal-closure-incomplete.v1"];
      }
      return found;
    }
    case "evidence-bundle": {
      const policy = loadPolicyFile(root, vector.trust_policy_path as string);
      const history = (vector.trust_policy_history_paths ?? []).map((path) => loadPolicyFile(root, path));
      const register = vector.register_path === undefined ? undefined : loadRegister(readArtifact(root, vector.register_path).subarray(0, MAX_REGISTER_BYTES + 1));
      const report = verifyBundle(value, policy, {
        now: vector.evaluated_at as string,
        history,
        acceptCurrentTrustFailure: vector.accept_current_trust_failure === true,
        requireTrustedTime: vector.require_trusted_time === true,
        ...(register === undefined ? {} : { register }),
      });
      context.verdicts.set(vector.id, report.verdict);
      context.scopes?.set(vector.id, observedScope(report));
      return reportedIdentifiers(report);
    }
    default:
      break;
  }
  if (!isObject(value)) {
    return [SCHEMA_INVALID];
  }
  if (vector.stage === "document") {
    // A claim or assessment document: strict parsing, its declared schema, and the registered
    // rules whose `applies_to` names its type (the extension rules for a work intent).
    return [...new Set(evaluateDocument(vector.schema as string, value, recordSchemas(), context.semantics).map((item) => item.ruleId))].sort();
  }
  const schemaErrors = recordSchemas().errors(vector.schema as string, value, 1);
  if (vector.stage === "binding") {
    // A binding profile's checker reads only records its schema accepts.
    if (schemaErrors.length > 0) {
      return [SCHEMA_INVALID];
    }
    return [...new Set(bindingFindings(value, context.exportKeys).map((item) => item.ruleId))].sort();
  }
  if (vector.stage === "envelope") {
    if (schemaErrors.length > 0) {
      return [SCHEMA_INVALID];
    }
    const trust = context.trustPolicy;
    if (trust === undefined) {
      throw new Error("envelope suite requires a caller-supplied trust-policy artifact");
    }
    try {
      const payload = decodeCanonicalJsonPayload(value);
      if (!isObject(payload)) {
        throw new Error("envelope payload is not an object");
      }
      const dcmp = textAt(payload, "protocol") === "DCMP-2";
      const at = get(payload, dcmp ? "issued_at" : "observed_at");
      if (typeof at !== "string") {
        return [SCHEMA_INVALID];
      }
      verifyEnvelope(value, trust.keyring(), trust.verificationContext(at, dcmp ? "ecl.time.issued-at.v1" : "ecl.time.observed-at.v1"));
    } catch (error) {
      if (error instanceof IntegrityError) {
        return [error.code];
      }
      throw error;
    }
    return [];
  }
  const findings = vector.stage === "safe-state-profile" ? validateSafeStateProfile(value) : context.semantics.validate(value);
  const semanticIds = [...new Set(findings.map((item) => item.ruleId))].sort();
  if (vector.stage === "semantic") {
    return [...semanticIds, ...(schemaErrors.length > 0 ? [SCHEMA_INVALID] : [])];
  }
  return [...(schemaErrors.length > 0 ? [SCHEMA_INVALID] : []), ...semanticIds];
}

interface Manifest {
  readonly suite: string;
  readonly schema_version: string;
  readonly trust_policy_path?: string;
  readonly export_keys_path?: string;
  readonly vectors: readonly CorpusVector[];
}

/** One vector's result row of the cross-implementation report. */
export interface ResultRow {
  id: string;
  suite: string;
  artifact_sha256: string;
  expected: string;
  status: "met" | "not-met" | "unsupported";
  observed_primary_id?: string | null;
  observed_secondary_ids: string[];
  unsupported_capability?: string;
  raw_result_sha256?: string;
}

export interface RunSummary {
  readonly vector_count: number;
  readonly counts: Record<string, number>;
  readonly decision: "pass" | "fail";
  readonly verdict_checks: number;
  readonly verdict_mismatches: readonly string[];
  readonly secondary_mismatches: readonly string[];
  readonly relationship_disclosure: string;
}

function encode(value: unknown): string {
  return JSON.stringify(value);
}

function registeredErrors(root: string): Set<string> {
  const entries = readJson(root, "registries/error-codes.json")["entries"] as JsonObject[];
  return new Set(entries.filter((entry) => entry["status"] === "active").map((entry) => entry["id"] as string));
}

function precedenceOf(root: string): Map<string, number> {
  const entries = readJson(root, "registries/semantic-rules.json")["entries"] as JsonObject[];
  const map = new Map<string, number>();
  for (const entry of entries) {
    if (entry["status"] !== "active") {
      continue;
    }
    const value = get(get(entry, "attributes"), "precedence");
    if (typeof value !== "number" || map.has(entry["id"] as string) || [...map.values()].includes(value)) {
      throw new Error("semantic precedence is missing, duplicate or invalid");
    }
    map.set(entry["id"] as string, value);
  }
  return map;
}

/**
 * Run the complete shared corpus from `root`, write the report to `reportPath` and its raw
 * evidence beside it, and return a summary. `sourceRoot` is the clean source export the report
 * binds; `revision` is the repository revision it was taken from.
 */
export function runCorpus(root: string, revision: string, reportPath: string, sourceRoot: string, runtime: string): RunSummary {
  const corpus = readJson(root, "conformance/shared-corpus.json");
  if (corpus["schema_version"] !== "ecl_shared_corpus_v1" || corpus["version"] !== 1) {
    throw new Error("unsupported corpus identity");
  }
  const candidate = corpus["candidate_version"] as string;
  const required = corpus["required_capabilities"] as string[];
  const optional = corpus["optional_capabilities"] as string[];
  for (const capability of required) {
    if (!(CAPABILITIES as readonly string[]).includes(capability)) {
      throw new Error(`missing required capability: ${capability}`);
    }
  }
  const capabilities = (CAPABILITIES as readonly string[]).filter((capability) => required.includes(capability) || optional.includes(capability));
  const manifestPaths = ["conformance/manifest.json", ...readdirSync(join(root, "conformance/suites")).sort().map((suite) => `conformance/suites/${suite}/manifest.json`)];
  const vectors = new Map<string, { vector: CorpusVector; suite: string; trustPolicy: string | undefined; exportKeys: string | undefined }>();
  for (const path of manifestPaths) {
    const manifest = readJson(root, path) as unknown as Manifest;
    if (manifest.schema_version !== "ecl_conformance_vector_manifest_v3") {
      throw new Error("manifest must be v3");
    }
    for (const vector of manifest.vectors) {
      if (vectors.has(vector.id)) {
        throw new Error("duplicate manifest vector ID");
      }
      vectors.set(vector.id, { vector, suite: manifest.suite, trustPolicy: manifest.trust_policy_path, exportKeys: manifest.export_keys_path });
    }
  }
  const declared = corpus["vectors"] as Array<{ suite: string; id: string; capability: string }>;
  if (declared.length !== vectors.size) {
    throw new Error("corpus does not cover every vector");
  }
  const precedence = precedenceOf(root);
  const errors = registeredErrors(root);
  const semantics = new SemanticValidator();
  const policies = new Map<string, TrustPolicy>();
  const keyFiles = new Map<string, Map<string, ExportKey>>();
  const verdicts = new Map<string, string>();
  const evidenceDirectory = reportPath.replace(/\.[^./]*$/, "") + "-evidence";
  const evidenceName = evidenceDirectory.split("/").pop() as string;
  mkdirSync(evidenceDirectory, { mode: 0o700 });
  const results: ResultRow[] = [];
  const evidence: Array<{ path: string; sha256: string }> = [];
  const counts: Record<string, number> = { met: 0, "not-met": 0, unsupported: 0 };
  const verdictMismatches: string[] = [];
  const secondaryMismatches: string[] = [];
  let verdictChecks = 0;
  let allMet = true;
  declared.forEach((item, index) => {
    const found = vectors.get(item.id);
    if (found === undefined || found.suite !== item.suite) {
      throw new Error("corpus ID or suite differs from manifests");
    }
    const { vector, trustPolicy, exportKeys } = found;
    const data = readArtifact(root, vector.path);
    const row: ResultRow = { id: item.id, suite: item.suite, artifact_sha256: sha256Hex(data), expected: vector.expected, status: "met", observed_secondary_ids: [] };
    if (!capabilities.includes(item.capability)) {
      if (!optional.includes(item.capability)) {
        throw new Error(`missing required capability: ${item.capability}`);
      }
      row.status = "unsupported";
      row.unsupported_capability = item.capability;
    } else {
      let policy: TrustPolicy | undefined;
      if (trustPolicy !== undefined) {
        policy = policies.get(trustPolicy) ?? loadPolicyFile(root, trustPolicy);
        policies.set(trustPolicy, policy);
      }
      let keys: Map<string, ExportKey> | undefined;
      if (exportKeys !== undefined) {
        keys = keyFiles.get(exportKeys) ?? loadSuiteExportKeys(root, exportKeys);
        keyFiles.set(exportKeys, keys);
      }
      const scopes = new Map<string, ObservedScope>();
      const context: EvaluationContext = {
        root,
        semantics,
        verdicts,
        scopes,
        ...(policy === undefined ? {} : { trustPolicy: policy }),
        ...(keys === undefined ? {} : { exportKeys: keys }),
      };
      const observed = observedForVector(vector, context);
      // A signed bundle's primary finding is the first identifier, in the order of EBMP2-068, and a
      // bundle has no required secondary findings.
      const signed = vector.stage === "evidence-bundle" || vector.stage === "package";
      const [primary, secondary] = signed ? selectBundleFinding(observed, precedence, errors) : selectFindings(observed, precedence, errors);
      row.observed_primary_id = primary;
      row.observed_secondary_ids = secondary;
      // EBMP2-076 and EBMP2-061: a vector that names the scope or the evidence levels of its
      // verdict is met only with them.
      const met = (vector.expected === "pass" ? primary === null : primary === vector.expected_primary_id) && scopeMatches(vector, scopes.get(vector.id));
      row.status = met ? "met" : "not-met";
      if (!met) {
        allMet = false;
      }
      if (met && vector.expected === "fail" && encode([...secondary].sort()) !== encode([...vector.expected_secondary_ids].sort())) {
        secondaryMismatches.push(item.id);
      }
      if (vector.expected_verdict !== undefined) {
        verdictChecks += 1;
        if (verdicts.get(vector.id) !== vector.expected_verdict) {
          verdictMismatches.push(item.id);
        }
      }
    }
    const { raw_result_sha256: _omit, ...unbound } = row;
    void _omit;
    const raw = encode({ schema_version: "ecl_external_vector_raw_result_v2", implementation_revision: revision, result: unbound }) + "\n";
    const relativePath = `${evidenceName}/${String(index).padStart(4, "0")}.json`;
    const descriptor = openSync(join(evidenceDirectory, `${String(index).padStart(4, "0")}.json`), "wx", 0o600);
    writeSync(descriptor, raw);
    closeSync(descriptor);
    row.raw_result_sha256 = sha256Hex(utf8(raw));
    evidence.push({ path: relativePath, sha256: row.raw_result_sha256 });
    results.push(row);
    counts[row.status] = (counts[row.status] ?? 0) + 1;
  });
  const source = sourceTreeDigest(sourceRoot);
  const decision = allMet ? "pass" : "fail";
  // The verification-time policy of each stage that a declared capability evaluates (IE1-023), as
  // conformance/README.md fixes them.
  const timePolicies: Record<string, string[]> = {};
  if (capabilities.includes("envelope-signature-verification")) {
    timePolicies["envelope"] = ["ecl.time.issued-at.v1", "ecl.time.observed-at.v1"];
  }
  if (capabilities.includes("evidence-bundle-verification")) {
    timePolicies["evidence-bundle"] = ["ecl.verification-profile.reference-trusted-time.v1", "ecl.verification-profile.reference.v1"];
  }
  if (capabilities.includes("offline-package-verification")) {
    timePolicies["package"] = ["ecl.verification-profile.reference-trusted-time.v1", "ecl.verification-profile.reference.v1"];
  }
  const report = {
    schema_version: "ecl_cross_implementation_report_v2",
    candidate_version: candidate,
    profile_version: "2",
    decision,
    implementation: {
      name: "ECL TypeScript library",
      version: candidate,
      source_repository: "packages/ecl-ts",
      source_revision: revision,
      source_tree_sha256: source.digest,
      language: "TypeScript",
      runtime,
      maintainer: "ECL repository maintainers",
      relationship_disclosure: DISCLOSURE,
      imports_ecl_reference: false,
      capabilities,
    },
    suite: {
      id: `ecl-1-v${candidate}-shared`,
      manifest_sha256: sha256Hex(readArtifact(root, "conformance/shared-corpus.json")),
      vector_count: results.length,
      corpus_version: corpus["version"],
    },
    network_used: false,
    time_policies: timePolicies,
    vector_results: results,
    evidence,
    limitations: [
      "ML-DSA-65 envelope signatures are not implemented; trust policy version 1 cannot hold such keys, and a keyring built by hand with one makes verification fail with UnsupportedSuiteError instead of a verdict.",
      DISCLOSURE,
    ],
    claim_boundary: "cross-implementation-replay-only-not-independent-assessment",
  };
  const descriptor = openSync(reportPath, "wx", 0o600);
  writeSync(descriptor, encode(report) + "\n");
  closeSync(descriptor);
  return {
    vector_count: results.length,
    counts,
    decision,
    verdict_checks: verdictChecks,
    verdict_mismatches: verdictMismatches,
    secondary_mismatches: secondaryMismatches,
    relationship_disclosure: DISCLOSURE,
  };
}
