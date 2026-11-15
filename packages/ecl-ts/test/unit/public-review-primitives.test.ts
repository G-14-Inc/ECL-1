/** Focused regressions for the adjudicated public-review primitive repairs. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import type { JsonObject, JsonValue } from "../../src/json/value.js";
import { SemanticValidator } from "../../src/semantic/rules.js";
import { objectFindings } from "../../src/semantic/object.js";
import { objectDigest } from "../../src/json/canonical.js";
import { isAbsoluteUri } from "../../src/schema/formats.js";
import { SchemaSet, recordSchemas } from "../../src/schema/validator.js";
import { isInstant, instantNanoseconds } from "../../src/time.js";
import { loadRegister, VerifierInputError } from "../../src/evidence/bytes.js";
import { bindingFindings, BINDING_PROFILES } from "../../src/bindings/index.js";
import { evaluateDocument } from "../../src/documents/documents.js";
import { IntegrityError, verifyEnvelope } from "../../src/integrity/envelope.js";
import type { VerificationContext, VerificationKey } from "../../src/integrity/envelope.js";
import { bytes, json } from "./helpers.js";
import { signEnvelope, ED25519 } from "./builders.js";

const UNIQUE = "ecl.rule.extension-identifiers-unique.v1";
const UNKNOWN = "ecl.rule.unknown-critical-extension-rejected.v1";
const NAMESPACE = "ecl.rule.extension-namespace-allocated.v1";
const VERSION = "ecl.rule.extension-single-version.v1";
const POLICY = "ecl.rule.integrity-threshold-consistent.v1";
const VALUE = "ecl.rule.extension-value-valid.v1";
const TAG = "com.example.audit-tag.v1";
const semantics = new SemanticValidator();
const request = (): JsonObject => json("conformance/vectors/dcmp-2/valid-decision-request.json");
const occurrence = (id = TAG, version: JsonValue = 1, critical: JsonValue = false): JsonObject => ({ id, version, critical, value: {} });
const rules = (value: JsonObject): Set<string> => new Set(semantics.validate(value).map((f) => f.ruleId));

test("ROOT-025: object limits use the declared parser profile", () => {
  for (const [depth, width] of [[0, 0], [20, 0], [40, 0], [130, 0], [0, 10_001]]) {
    let parameters: JsonObject = { values: Array(width).fill(0) };
    for (let level = 0; level < depth!; level++) parameters = { nested: parameters };
    const value = request();
    const action = value["action"] as JsonObject;
    action["parameters"] = parameters;
    (action["parameters_digest"] as JsonObject)["value"] = objectDigest(parameters);
    assert.deepEqual(objectFindings(value), [], `${depth}/${width}`);
  }
  for (const limits of [{ maxNodes: 1 }, { maxDepth: 1 }]) {
    assert.deepEqual(objectFindings(request(), undefined, undefined, limits).map((f) => f.ruleId), ["ecl.error.resource-limit-exceeded.v1"]);
  }
  // Count the root, its array, and the scalar leaf; depth starts at zero.
  assert.ok(!objectFindings({ a: [0] }, undefined, undefined, { maxDepth: 2, maxNodes: 3 }).some((f) => f.ruleId === "ecl.error.resource-limit-exceeded.v1"));
  assert.equal(objectFindings({ a: [0] }, undefined, undefined, { maxDepth: 1, maxNodes: 3 })[0]?.ruleId, "ecl.error.resource-limit-exceeded.v1");
  assert.equal(objectFindings({ a: [0] }, undefined, undefined, { maxDepth: 2, maxNodes: 2 })[0]?.ruleId, "ecl.error.resource-limit-exceeded.v1");
  assert.equal(objectFindings(request(), undefined, undefined, { maxDepth: Number.NaN })[0]?.ruleId, "ecl.error.configuration-invalid.v1");
});

test("ROOT-016/027: reserved authority and typed extension findings", () => {
  for (const id of ["https://externalcontrollayer.ai/audit", "HTTPS://EXTERNALCONTROLLAYER.AI/audit", "https://user@externalcontrollayer.ai:443/audit", "ecl.unallocated.v1"]) {
    assert.ok(rules({ ...request(), extensions: [occurrence(id)] }).has(NAMESPACE), id);
  }
  for (const id of [TAG, "urn:example:audit:v1", "https://externalcontrollayer.ai@example.com/audit"]) {
    assert.equal(rules({ ...request(), extensions: [occurrence(id)] }).size, 0, id);
  }
  assert.deepEqual(rules({ ...request(), extensions: [null, occurrence(TAG, true), occurrence(), occurrence(), occurrence("urn:example:unknown", 1, true)] }), new Set([UNIQUE, UNKNOWN]));
  assert.equal(rules({ ...request(), extensions: [occurrence(TAG, true), occurrence(), occurrence("urn:example:unknown", 1, "false")] }).size, 0);
  for (const policy of [{ required: true }, { threshold: 1 }]) {
    assert.ok(!rules({ ...request(), integrity_policy: policy }).has(POLICY));
  }
  assert.ok(rules({ ...request(), integrity_policy: { required: true, threshold: 0, eligible_key_ids: null } }).has(POLICY));
});

test("ROOT-026: brackets are limited to enclosing the IP literal", () => {
  for (const uri of ["https://user[info]@[::1]/profile", "https://[v1.[a]/profile", "https://[::1]:[80]/profile"]) {
    assert.equal(isAbsoluteUri(uri), false, uri);
  }
  for (const uri of ["https://[::1]/profile", "https://user:info@[::1]:80/profile", "https://[v1.a]/profile", "https://[fe80::1%25eth0]/profile"]) {
    assert.equal(isAbsoluteUri(uri), true, uri);
  }
});

test("ROOT-027: malformed coupling outcomes retain a typed blocker finding", () => {
  for (const outcome of [[], {}]) {
    const value = json("conformance/suites/aarm-binding/aarm-valid-allow-released.json")["response"] as JsonObject;
    (value["extensions"] as JsonObject[]).push({ id: "ecl.ext.consequence-coupling.v1", version: 1, critical: false,
      value: { budget_result: { outcome }, blocker_reason: "ecl.reason.denied.v1" } });
    const found = semantics.validate(value);
    assert.ok(found.some((f) => f.ruleId === VALUE));
    assert.ok(found.some((f) => f.ruleId === "ecl.rule.coupling-results-permit-admit.v1" && f.path.endsWith("/blocker_reason")));
    assert.ok(!found.some((f) => f.ruleId === "ecl.error.schema-invalid.v1"));
  }
});

test("ROOT-024: inconsistent register refusal carries its structured rule", () => {
  loadRegister(bytes("conformance/suites/document-coverage/register-valid-published-example.json"));
  assert.throws(() => loadRegister(bytes("conformance/suites/document-coverage/register-invalid-derivation-cycle.json")),
    (error: unknown) => error instanceof VerifierInputError && error.code === "ecl.rule.register-declarations-consistent.v1");
});

function completeBinding(path: string): JsonObject {
  if (!path.startsWith("mcp-gateway/")) return json("conformance/suites/" + path);
  const value = json("conformance/suites/mcp-gateway/mcp-valid-forwarded-release-order.json");
  const state = { status: "current", reference: { uri: "urn:example:control-snapshot:mcp-repair", digest: { algorithm: "ecl.digest.sha-256.v1", value: "a".repeat(64) } },
    fresh_until: "2026-09-30T09:01:00.000000Z", halt: false, quarantine: false, revoked: false };
  value["release_observations"] = {
    initial: { observed_at: "2026-09-30T09:00:00.200000Z", control_state: structuredClone(state) },
    final: { observed_at: "2026-09-30T09:00:00.300000Z", control_state: structuredClone(state) },
  };
  return value;
}

test("ROOT-056: binding records with malformed classes return registered findings", () => {
  for (const path of ["aarm-binding/aarm-valid-allow-released.json", "acs-binding/acs-valid-allow-released.json", "mcp-gateway/mcp-valid-forwarded-on-admit.json"]) {
    const original = completeBinding(path);
    assert.deepEqual(bindingFindings(original), [], path);
    for (const inputClass of [[], {}, "review_invalid_class"]) {
      const value = structuredClone(original);
      const response = (path.startsWith("mcp-") ? (value["decision"] as JsonObject)["response"] : value["response"]) as JsonObject;
      const basis = (response["extensions"] as JsonObject[]).find((e) => e["id"] === "ecl.ext.decision-basis.v1")!["value"] as JsonObject;
      (basis["inputs"] as JsonObject[])[0]!["class"] = inputClass;
      assert.equal(recordSchemas().isValid(BINDING_PROFILES.get(value["schema_version"] as string)!.schema, value), true);
      assert.ok(bindingFindings(value).some((f) => f.ruleId === VALUE || f.message.includes(VALUE)), path);
    }
  }
});

test("ROOT-070: exact calendar bounds and nanosecond ordering", () => {
  for (const instant of ["2026-10-00T00:00:00Z", "2026-01-00T00:00:00Z", "2025-02-29T00:00:00Z", "2026-04-31T00:00:00Z"]) {
    assert.equal(isInstant(instant), false, instant);
    assert.throws(() => instantNanoseconds(instant));
  }
  for (const instant of ["2026-09-30T00:00:00Z", "2024-02-29T00:00:00Z", "2000-02-29T00:00:00Z"]) assert.ok(isInstant(instant));
  assert.equal(instantNanoseconds("2026-01-01T00:00:00.000000002Z") - instantNanoseconds("2026-01-01T00:00:00.000000001Z"), 1n);
});

test("ROOT-074: incident URI pattern uses the complete ECMA whitespace set", () => {
  const incident = json("schemas/ecl-incident-scenario-v1.schema.json");
  const uri = (incident["$defs"] as JsonObject)["uri"]!;
  const schemas = new SchemaSet([["urn:example:incident-uri", uri]]);
  for (const [char, expected] of [["x", true], [" ", false], ["\u0085", true], ["\u00a0", false], ["\u2028", false], ["\ufeff", false]] as const) {
    assert.equal(schemas.isValid("urn:example:incident-uri", "urn:example:" + char), expected);
  }
});

const signer = { keyId: "urn:example:key:public-review", seed: new Uint8Array(32).fill(44) };
const context: VerificationContext = { trustPolicyId: "urn:example:policy:review", trustPolicyVersion: "1", trustPolicyDigest: "ab".repeat(32), trustPolicyEpoch: 1,
  evaluatedAt: "2026-11-09T00:00:00Z", verificationTimePolicy: "ecl.time.issued-at.v1", revocationPolicy: "ecl.revocation.offline-bundle.v1", allowedSuites: [ED25519], prohibitedSuites: [], revocations: [] };
const key: VerificationKey = { keyId: signer.keyId, suiteId: ED25519, publicKey: ed25519.getPublicKey(signer.seed), trustPolicyIds: [], purposes: [], validFrom: undefined, validUntil: undefined, rolePurposes: ["ecl.purpose.decision-request.v1"] };
const keyring = new Map([[key.keyId, key]]);
function signedPayload(): JsonObject {
  return { ...request(), integrity_policy: { required: true, threshold: 1, accepted_suites: [ED25519], eligible_key_ids: [], required_key_ids: [],
    verification_time_policy: context.verificationTimePolicy, revocation_policy: context.revocationPolicy,
    trust_policy: { id: context.trustPolicyId, version: "1", epoch: 1, digest: { algorithm: "ecl.digest.sha-256.v1", value: context.trustPolicyDigest } } } };
}
const sign = (payload = signedPayload()): JsonObject => signEnvelope(payload, "application/vnd.ecl.dcmp+json", [signer]);
const verify = (envelope: JsonObject): unknown => verifyEnvelope(envelope, keyring, context);
const refused = (envelope: JsonObject, code: string): void => assert.throws(() => verify(envelope), (error: unknown) => error instanceof IntegrityError && error.code === code);

test("ROOT-015/032: optional policy lists and unknown DCMP purpose", () => {
  verify(sign());
  for (const member of ["eligible_key_ids", "required_key_ids"]) {
    const value = signedPayload();
    const policy = value["integrity_policy"] as JsonObject;
    delete policy[member];
    verify(sign(value));
    for (const invalid of [null, "", [signer.keyId, signer.keyId], [1]]) {
      policy[member] = invalid;
      refused(sign(value), "ecl.error.signature-policy-invalid.v1");
    }
  }
  for (const kind of [undefined, "review_unknown", "control"]) {
    const value = signedPayload();
    if (kind === undefined) delete value["message_type"]; else value["message_type"] = kind;
    refused(sign(value), "ecl.error.signature-policy-invalid.v1");
  }
});

test("ROOT-071: standalone outer extensions and stage precedence", () => {
  const base = sign();
  verify({ ...base, extensions: [occurrence()] });
  for (const [extensions, code] of [
    [[occurrence(TAG, 1, true)], UNKNOWN], [[occurrence(), occurrence()], UNIQUE], [[occurrence(), occurrence(TAG, 2)], VERSION],
    [[occurrence(), occurrence(), occurrence("urn:example:unknown", 1, true)], UNKNOWN],
  ] as const) {
    const target: JsonObject = { ...base, extensions: [...extensions] };
    assert.equal(target["payload"], base["payload"]);
    assert.equal(target["signatures"], base["signatures"]);
    refused(target, code);
  }
  const badDigest = { ...base, payload_digest: { algorithm: "ecl.digest.sha-256.v1", value: "00".repeat(32) }, extensions: [occurrence(TAG, 1, true)] };
  refused(badDigest, "ecl.error.integrity-invalid.v1");
  refused({ ...badDigest, signatures: Array(33).fill((base["signatures"] as JsonObject[])[0]!) }, "ecl.error.resource-limit-exceeded.v1");
  const value = signedPayload();
  (value["integrity_policy"] as JsonObject)["required"] = false;
  refused({ ...sign(value), extensions: [occurrence(TAG, 1, true)] }, UNKNOWN);
});

test("ROOT-081: work-intent document filtering keeps integrity-policy findings", () => {
  const policy = signedPayload()["integrity_policy"] as JsonObject;
  const cases: Array<[JsonObject | undefined, string[]]> = [[undefined, []], [policy, []], [{ ...policy, threshold: 0 }, [POLICY]],
    [{ ...policy, eligible_key_ids: ["urn:example:key:eligible"], required_key_ids: ["urn:example:key:required"] }, [POLICY]]];
  for (const [current, expected] of cases) {
    const value = json("conformance/suites/document-coverage/work-intent-valid.json");
    if (current !== undefined) value["integrity_policy"] = current;
    assert.deepEqual(evaluateDocument("https://externalcontrollayer.ai/ns/schema/work-intent/1", value).map((f) => f.ruleId), expected);
  }
  const value = json("conformance/suites/document-coverage/work-intent-valid.json");
  value["extensions"] = [occurrence(TAG, 1, true)];
  assert.deepEqual(evaluateDocument("https://externalcontrollayer.ai/ns/schema/work-intent/1", value).map((f) => f.ruleId), [UNKNOWN]);
});
