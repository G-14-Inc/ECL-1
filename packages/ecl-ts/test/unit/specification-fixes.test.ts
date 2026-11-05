import assert from "node:assert/strict";
import { test } from "node:test";
import {
  IntegrityError,
  SIGNATURE_POLICY_INVALID,
  SemanticValidator,
  TrustPolicy,
  TrustPolicyError,
  aarm,
  canonicalize,
  decodeCanonicalJsonPayload,
  documentRuleFindings,
  evaluateDocument,
  roleConflict,
  sha256Hex,
  toBase64,
  verifyEnvelope,
} from "../../src/index.js";
import type { JsonObject, JsonValue } from "../../src/index.js";
import { basisProblems } from "../../src/bindings/common.js";
import { bytes, json, suite } from "./helpers.js";

const WORK_INTENT = "https://externalcontrollayer.ai/ns/schema/work-intent/1";

function extension(id: string, version: JsonValue, critical = false): JsonObject {
  return { id, version, critical, value: {} };
}

function pathsOf(findings: ReadonlyArray<{ ruleId: string; path: string }>, rule: string): string[] {
  return findings.filter((item) => item.ruleId === rule).map((item) => item.path);
}

test("XR1-010: two versions of one extension conflict, known or not; the same version twice is XR1-009's", () => {
  const validator = new SemanticValidator();
  const value: JsonObject = {
    extensions: [
      extension("com.example.tag.v1", 1),
      extension("https://example.com/ext/v1", 1),
      extension("com.example.tag.v1", 1),
      extension("com.example.tag.v1", 7),
      { id: "com.example.tag.v1", version: true, critical: false, value: {} },
    ],
  };
  const findings = validator.validate(value);
  assert.deepEqual(pathsOf(findings, "ecl.rule.extension-single-version.v1"), ["/extensions/3"]);
  assert.deepEqual(pathsOf(findings, "ecl.rule.extension-identifiers-unique.v1"), ["/extensions/2", "/extensions/4"]);
  const composable = new SemanticValidator(undefined, undefined, undefined, undefined, ["com.example.tag.v1"]);
  assert.deepEqual(pathsOf(composable.validate(value), "ecl.rule.extension-single-version.v1"), []);
  const malformed = validator.validate({ extensions: "x" });
  assert.ok(malformed.some((item) => item.ruleId === "ecl.error.schema-invalid.v1" && item.message.startsWith("extension versions semantic check")));
});

test("the extension rules apply to a work intent at the document stage, with or without its schema", () => {
  const intent: JsonObject = {
    protocol: "ECL-WI-1",
    extensions: [extension("com.example.tag.v1", 1), extension("com.example.tag.v1", 2), extension("ecl.ext.unknown.v1", 1, true)],
  };
  const findings = evaluateDocument(WORK_INTENT, intent);
  assert.deepEqual([...new Set(findings.map((item) => item.ruleId))].sort(), [
    "ecl.error.schema-invalid.v1",
    "ecl.rule.extension-namespace-allocated.v1",
    "ecl.rule.extension-single-version.v1",
    "ecl.rule.unknown-critical-extension-rejected.v1",
  ]);
  assert.deepEqual(documentRuleFindings({ extensions: intent["extensions"] as JsonValue }), []);
  for (const vector of [...suite("document-coverage"), ...suite("extension-rules")].filter((item) => item.stage === "document")) {
    const found = [...new Set(evaluateDocument(vector.schema as string, json(vector.path)).map((item) => item.ruleId))].sort();
    const expected = vector.expected === "pass" ? [] : [vector.expected_primary_id as string, ...vector.expected_secondary_ids].sort();
    assert.deepEqual(found, expected, vector.id);
  }
});

test("TP1-009: a trust-policy key holds one role; the evidence-event purpose is no role", () => {
  assert.deepEqual(roleConflict(["ecl.purpose.decision-request.v1", "ecl.purpose.evidence-event.v1"]), []);
  assert.deepEqual(roleConflict(["ecl.purpose.trusted-time.v1", "ecl.purpose.decision-request.v1"]), ["ecl.purpose.decision-request.v1", "ecl.purpose.trusted-time.v1"]);
  for (const vector of suite("key-roles").filter((item) => item.stage === "trust-policy")) {
    if (vector.expected === "pass") {
      TrustPolicy.load(bytes(vector.path));
    } else {
      assert.throws(() => TrustPolicy.load(bytes(vector.path)), (error: unknown) => error instanceof TrustPolicyError && error.code === vector.expected_primary_id, vector.id);
    }
  }
});

test("TP1-010: a decision request or response counts only under a key of its role, when the keyring comes from a trust policy", () => {
  const policy = TrustPolicy.load(bytes("conformance/suites/key-roles/trust-policy.json"));
  const verify = (path: string, keyring = policy.keyring()): string => {
    const envelope = json(path);
    const payload = decodeCanonicalJsonPayload(envelope) as JsonObject;
    try {
      verifyEnvelope(envelope, keyring, policy.verificationContext(payload["issued_at"] as string, "ecl.time.issued-at.v1"));
      return "verified";
    } catch (error) {
      if (error instanceof IntegrityError) {
        return error.code;
      }
      throw error;
    }
  };
  for (const vector of suite("key-roles").filter((item) => item.stage === "envelope")) {
    assert.equal(verify(vector.path), vector.expected === "pass" ? "verified" : vector.expected_primary_id, vector.id);
  }
  const byHand = new Map([...policy.keyring()].map(([id, key]) => [id, { ...key, rolePurposes: [] }]));
  assert.equal(verify("conformance/suites/key-roles/key-roles-invalid-response-by-requester-key.json", byHand), "verified");
});

test("IE1-040, step 4: a trust-policy digest that is not an object, of any type, is refused as signature-policy-invalid", () => {
  const policy = TrustPolicy.load(bytes("conformance/suites/envelope/trust-policy.json"));
  const envelope = json("conformance/suites/envelope/envelope-valid-ed25519-signed.json");
  const payload = decodeCanonicalJsonPayload(envelope) as JsonObject;
  const context = policy.verificationContext(payload["issued_at"] as string, "ecl.time.issued-at.v1");
  for (const digest of ["abc", 1, true, [1]] as JsonValue[]) {
    // The valid envelope's payload with its trust-policy digest replaced, re-encoded with its
    // payload digest recomputed; the signature no longer matches, but step 4 refuses first.
    const changed = JSON.parse(JSON.stringify(payload)) as JsonObject;
    ((changed["integrity_policy"] as JsonObject)["trust_policy"] as JsonObject)["digest"] = digest;
    const encoded = canonicalize(changed);
    const document: JsonObject = { ...envelope, payload: toBase64(encoded), payload_digest: { algorithm: "ecl.digest.sha-256.v1", value: sha256Hex(encoded) } };
    assert.throws(
      () => verifyEnvelope(document, policy.keyring(), context),
      (error: unknown) => error instanceof IntegrityError && error.code === SIGNATURE_POLICY_INVALID && error.message === "trust policy digest suite is unsupported",
      JSON.stringify(digest),
    );
  }
});

test("AB1-013 and AC1-012: a record's inputs, without the profile's member, equal the entries of its response's decision basis", () => {
  const digest = (fill: string): JsonObject => ({ algorithm: "ecl.digest.sha-256.v1", value: fill.repeat(64) });
  const entry = (name: string, inputClass = "verifiable", fill = "a"): JsonObject => ({
    input: `urn:example:input:${name}`,
    class: inputClass,
    required: false,
    status: "available",
    effect: "none",
    reference: { uri: `urn:example:value:${name}`, digest: digest(fill) },
  });
  const record = (inputs: JsonValue[], ...bases: JsonValue[][]): JsonObject => ({
    inputs,
    response: {
      extensions: bases.map((inputsOfBasis) => ({
        id: "ecl.ext.decision-basis.v1",
        version: 1,
        critical: true,
        value: { register: { uri: "urn:example:register:bindings", digest: digest("9") }, inputs: inputsOfBasis },
      })),
    },
  });
  const problems = (value: JsonObject): Array<[string, string]> => basisProblems(value, "aarm_requirement").map(([path, message]) => [path, message]);
  assert.deepEqual(problems(record([entry("policy"), { ...entry("score", "judgment", "b"), aarm_requirement: "R3" }], [entry("score", "judgment", "b"), entry("policy")])), []);
  assert.deepEqual(problems(record([entry("policy"), entry("score", "judgment")], [entry("policy", "verifiable", "c"), { ...entry("score"), effect: "restricts" }])), [
    ["/inputs/0/reference", "the reference is not the one the response records"],
    ["/inputs/1/class", "the class is not the one the response records"],
    ["/inputs/1/effect", "the effect is not the one the response records"],
  ]);
  const unavailable: JsonObject = { ...entry("balance"), status: "unavailable" };
  delete unavailable["reference"];
  assert.deepEqual(problems(record([{ ...unavailable }], [unavailable])), []);
  assert.deepEqual(problems(record([entry("balance")], [unavailable])), [
    ["/inputs/0/reference", "the reference is not the one the response records"],
    ["/inputs/0/status", "the status is not the one the response records"],
  ]);
  assert.deepEqual(problems(record([entry("policy")], [{ ...entry("policy"), source: "urn:example:system-of-record:payments" }])), [["/inputs/0/source", "the source is not the one the response records"]]);
  assert.deepEqual(problems(record([entry("policy"), entry("score")], [entry("policy"), entry("other")])), [
    ["/inputs/1/input", "the response's decision basis does not record this input"],
    ["/response/extensions/0/value/inputs/1/input", "the record does not list this input"],
  ]);
  assert.deepEqual(problems(record([entry("policy")], [entry("policy"), entry("policy")])), [["/inputs/0/input", "the response's decision basis records this input more than once"]]);
  assert.deepEqual(problems(record([entry("policy"), entry("policy")], [entry("policy")])), [["/inputs/1/input", "the record lists this input more than once"]]);
  assert.deepEqual(problems(record([])), []);
  assert.deepEqual(problems(record([entry("policy")])), [["/inputs/0/input", "the response's decision basis does not record this input"]]);
  assert.deepEqual(problems(record([entry("policy")], [entry("policy")], [entry("policy")])), [["/response/extensions", "the response records its decision basis more than once"]]);
  const noArray = record([entry("policy")], [entry("policy")]);
  (((noArray["response"] as JsonObject)["extensions"] as JsonObject[])[0] as JsonObject)["value"] = { inputs: "policy" };
  assert.deepEqual(problems(noArray), [["/response/extensions/0/value/inputs", "the decision basis has no inputs array"]]);
  assert.deepEqual(problems(record([], [{ class: "verifiable" }])), [["/response/extensions/0/value/inputs/0", "the decision-basis entry names no input"]]);
  assert.deepEqual(problems({ inputs: [entry("policy")] }), []);
  // A boolean never equals a number, as in the reference's comparison.
  assert.deepEqual(problems(record([{ ...entry("policy"), required: 0 }], [entry("policy")])), [["/inputs/0/required", "the required is not the one the response records"]]);
  // Every JSON member remains an own member while the profile-only marker is removed.
  const withMagicMember = (): JsonObject => {
    const value = entry("policy");
    Object.defineProperty(value, "__proto__", { value: { retained: true }, enumerable: true, writable: true, configurable: true });
    return value;
  };
  assert.deepEqual(problems(record([withMagicMember()], [withMagicMember()])), []);
  assert.equal(aarm.BASIS_RULE, "ecl.rule.aarm-inputs-match-basis.v1");
});
