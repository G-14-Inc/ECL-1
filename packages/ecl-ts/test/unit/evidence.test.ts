import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  CURRENT_TRUST_FAILED,
  DECISION_BASIS_REGISTER_RULE,
  DECISION_BASIS_REQUIRED_RULE,
  MAX_BUNDLE_BYTES,
  MAX_REGISTER_BYTES,
  REFERENCE_PROFILE,
  TRUSTED_TIME_PROFILE,
  TrustPolicy,
  VerifierInputError,
  describeCode,
  describeVerdict,
  loadRegister,
  parseStrictJson,
  registerDigest,
  registerReference,
  registerSchemaProblems,
  reportedIdentifiers,
  verifyBundle,
  verifyBundleBytes,
  reportToJson,
} from "../../src/index.js";
import type { JsonObject } from "../../src/index.js";
import { actorSourceProblems, registerProblems, requestProblems } from "../../src/evidence/decision-basis.js";
import { analyzeBundle } from "../../src/bundle/causal.js";
import { ruleStage } from "../../src/registry/registries.js";
import { bytes, repoRoot, suite } from "./helpers.js";

const NOW = "2026-10-01T00:00:00Z";
const FIXTURES = "conformance/fixtures/evidence";

test("the signed fixtures: verdicts and evidence levels", () => {
  const expected: Record<string, [string, string]> = {
    succeeded: ["verified", "issuer-asserted"],
    denied: ["verified", "issuer-asserted"],
    tampered: ["invalid", "none"],
    corroborated: ["verified", "corroborated"],
  };
  for (const [name, [verdict, level]] of Object.entries(expected)) {
    const { report } = verifyBundleBytes(bytes(`${FIXTURES}/${name}.json`), bytes(`${FIXTURES}/trust-policy.json`), { now: NOW });
    assert.equal(report.verdict, verdict, name);
    assert.equal(report.effects[0]?.level, level, name);
    assert.equal(report.verificationProfile, REFERENCE_PROFILE);
  }
});

test("a current trust failure is reported, or accepted only when the caller says so", () => {
  const vector = suite("evidence-bundle").find((item) => item.id === "bundle-current-trust-failed-revoked-after-use");
  assert.ok(vector !== undefined);
  const policy = TrustPolicy.load(bytes(vector.trust_policy_path as string));
  const history = (vector.trust_policy_history_paths ?? []).map((path) => TrustPolicy.load(bytes(path)));
  const bundle = parseStrictJson(bytes(vector.path));
  const report = verifyBundle(bundle, policy, { now: NOW, history });
  assert.equal(report.verdict, CURRENT_TRUST_FAILED);
  assert.deepEqual(reportedIdentifiers(report), ["ecl.error.revoked.v1"]);
  assert.ok(report.envelopeChecks.every((check) => check.historical === "valid"));
  const accepted = verifyBundle(bundle, policy, { now: NOW, history, acceptCurrentTrustFailure: true });
  assert.equal(accepted.verdict, "verified");
  assert.equal(accepted.acceptedCurrentTrustFailure, true);
  // Without the earlier version the evidence names, the signer cannot be historically valid.
  assert.equal(verifyBundle(bundle, policy, { now: NOW }).verdict, "invalid");
});

test("trusted time: the profile is named, and a bundle without countersignatures is refused", () => {
  const valid = suite("evidence-bundle").find((item) => item.id === "bundle-valid-succeeded");
  assert.ok(valid !== undefined);
  const policy = TrustPolicy.load(bytes(valid.trust_policy_path as string));
  const report = verifyBundle(parseStrictJson(bytes(valid.path)), policy, { now: NOW, requireTrustedTime: true });
  assert.equal(report.verificationProfile, TRUSTED_TIME_PROFILE);
  assert.equal(report.verdict, "invalid");
  assert.ok(report.envelopeChecks.every((check) => check.historical === "ecl.error.trusted-time-required.v1"));
});

test("invalid caller arguments throw; malformed bundles are reported", () => {
  const policy = TrustPolicy.load(bytes(`${FIXTURES}/trust-policy.json`));
  for (const now of ["2026-10-01T00:00:00.1Z", "2026-02-30T00:00:00Z", "yesterday", "2026-10-01T00:00:00+00:00"]) {
    assert.throws(() => verifyBundle({}, policy, { now }), RangeError, now);
  }
  assert.throws(() => verifyBundle({}, policy, { now: NOW, responseClockSkewSeconds: -1 }), RangeError);
  for (const bundle of [null, [], "x", {}, { envelopes: [] }, { schema_version: "ecl_evidence_bundle_v1", envelopes: [{}] }]) {
    const report = verifyBundle(bundle, policy, { now: NOW });
    assert.equal(report.verdict, "invalid");
    assert.deepEqual(report.findings.map((finding) => finding.code), ["ecl.error.schema-invalid.v1"]);
  }
});

test("byte limits come before parsing (TP1-007)", () => {
  const policy = bytes(`${FIXTURES}/trust-policy.json`);
  const big = new Uint8Array(MAX_BUNDLE_BYTES + 1).fill(0x20);
  assert.throws(() => verifyBundleBytes(big, policy, { now: NOW }), VerifierInputError);
  assert.throws(() => verifyBundleBytes(new Uint8Array([0xff]), policy, { now: NOW }), VerifierInputError);
  assert.throws(() => verifyBundleBytes(bytes(`${FIXTURES}/succeeded.json`), new Uint8Array(256 * 1024 + 1), { now: NOW }), VerifierInputError);
  assert.throws(() => verifyBundleBytes(bytes(`${FIXTURES}/succeeded.json`), new TextEncoder().encode("{}"), { now: NOW }), VerifierInputError);
});

test("every code the suites expect has a plain explanation", () => {
  for (const verdict of ["verified", "invalid", "incomplete", "current-trust-failed"] as const) {
    assert.ok(describeVerdict(verdict).text.length > 40);
  }
  for (const vector of suite("evidence-bundle")) {
    const code = vector.expected_primary_id;
    if (code !== undefined) {
      const explanation = describeCode(code);
      assert.notEqual(explanation.title, "", code);
      assert.doesNotMatch(explanation.text, /—/, code);
    }
  }
  assert.match(describeCode("ecl.rule.bundle-causal-graph-acyclic.v1").text, /acyclic/);
});

test("the report keeps the reference's JSON shape", async () => {
  const { reportToJson } = await import("../../src/index.js");
  const { report } = verifyBundleBytes(bytes(`${FIXTURES}/succeeded.json`), bytes(`${FIXTURES}/trust-policy.json`), { now: NOW });
  const value = reportToJson(report) as JsonObject;
  assert.deepEqual(Object.keys(value).sort(), [
    "accepted_current_trust_failure",
    "binding_checks",
    "causal_status",
    "completion_after_window",
    "effects",
    "envelope_checks",
    "evaluation_time",
    "findings",
    "primary",
    "register",
    "scope",
    "trust_dependencies",
    "unresolved_predecessor_ids",
    "verdict",
    "verification_profile",
  ]);
  assert.equal(value["primary"], null);
  assert.equal(value["register"], null);
});

test("DCMP2-053: the verifier requires the decision basis of every decision response", () => {
  const plain = suite("evidence-bundle").find((item) => item.id === "bundle-invalid-missing-decision-basis");
  assert.ok(plain !== undefined);
  const policy = TrustPolicy.load(bytes(plain.trust_policy_path as string));
  const bundle = parseStrictJson(bytes(plain.path));
  const report = verifyBundle(bundle, policy, { now: NOW });
  assert.equal(report.verdict, "invalid");
  assert.deepEqual(reportedIdentifiers(report), [DECISION_BASIS_REQUIRED_RULE]);
  assert.match(report.findings[0]?.message ?? "", /^object \d+: \/extensions: the decision response records no decision basis$/);
  const fromBytes = verifyBundleBytes(bytes(plain.path), bytes(plain.trust_policy_path as string), { now: NOW });
  assert.equal(fromBytes.report.verdict, "invalid");
  assert.deepEqual(reportedIdentifiers(fromBytes.report), [DECISION_BASIS_REQUIRED_RULE]);
});

test("DCMP2-053: a decision basis is checked against the register the caller supplies", () => {
  const matched = suite("evidence-bundle").find((item) => item.id === "bundle-valid-decision-basis-matches-register");
  assert.ok(matched !== undefined && matched.register_path !== undefined);
  const policy = TrustPolicy.load(bytes(matched.trust_policy_path as string));
  const bundle = parseStrictJson(bytes(matched.path));
  const register = loadRegister(bytes(matched.register_path)) as JsonObject;
  const report = verifyBundle(bundle, policy, { now: NOW, register });
  assert.equal(report.verdict, "verified");
  assert.deepEqual(report.register, registerReference(register));
  assert.equal((report.register?.["digest"] as JsonObject)["value"], registerDigest(register)["value"]);
  const other = loadRegister(bytes("conformance/suites/evidence-bundle/register-version-2.json"));
  const refused = verifyBundle(bundle, policy, { now: NOW, register: other });
  assert.equal(refused.verdict, "invalid");
  assert.deepEqual(reportedIdentifiers(refused), [DECISION_BASIS_REGISTER_RULE]);
  // A register that its schema refuses is a caller error, from bytes and as a value.
  const broken = structuredClone(register);
  delete (broken["entries"] as JsonObject[])[0]?.["decision_inputs"];
  assert.ok(registerSchemaProblems(broken).length > 0);
  assert.throws(() => verifyBundle(bundle, policy, { now: NOW, register: broken }), RangeError);
  const text = new TextEncoder().encode(JSON.stringify(broken));
  assert.throws(() => verifyBundleBytes(bytes(matched.path), bytes(matched.trust_policy_path as string), { now: NOW, register: text }), /malformed register: the register does not satisfy its schema/);
  assert.throws(() => loadRegister(new Uint8Array(MAX_REGISTER_BYTES + 1).fill(0x20)), VerifierInputError);
  assert.throws(() => loadRegister(new TextEncoder().encode("{")), /malformed register: the register is not strict JSON/);
});

// The register rule, times against the register, the same primary finding inside a
// bundle as alone (EBMP2-068), the stage of each bundle rule, and the command's register line.

const SEMANTIC_INVALID = "ecl.error.semantic-invalid.v1";
const REFUSED_REGISTER = "conformance/suites/document-coverage/register-invalid-action-class-declared-twice.json";

function run(id: string): ReturnType<typeof verifyBundle> {
  const vector = suite("evidence-bundle").find((item) => item.id === id);
  assert.ok(vector !== undefined, id);
  const policy = TrustPolicy.load(bytes(vector.trust_policy_path as string));
  const register = vector.register_path === undefined ? undefined : (loadRegister(bytes(vector.register_path)) as JsonObject);
  return verifyBundle(parseStrictJson(bytes(vector.path)), policy, { now: NOW, ...(register === undefined ? {} : { register }) });
}

test("DCMP2-053: times are checked against the register's deadlines and maximum ages", () => {
  assert.equal(run("bundle-valid-decision-basis-times-within-register").verdict, "verified");
  const cases: Array<[string, RegExp]> = [
    ["bundle-invalid-decision-basis-input-after-deadline", /\/obtained_at: the input was obtained after its declared deadline$/],
    ["bundle-invalid-decision-basis-value-older-than-maximum-age", /\/value_at: the input's value is older than its declared maximum age$/],
    ["bundle-invalid-decision-basis-hidden-derivation", /\/derived_from: the inputs it is computed from are not the ones the register declares$/],
  ];
  for (const [id, message] of cases) {
    const report = run(id);
    assert.equal(report.verdict, "invalid", id);
    assert.deepEqual(reportedIdentifiers(report), [DECISION_BASIS_REGISTER_RULE], id);
    assert.match(report.findings[0]?.message ?? "", message, id);
  }
  assert.equal(run("bundle-valid-decision-basis-declared-derivation").verdict, "verified");
});

test("DCMP2-053: a register that breaks the register declarations rule is a usage error", () => {
  assert.throws(
    () => loadRegister(bytes(REFUSED_REGISTER)),
    (error: unknown) =>
      error instanceof VerifierInputError &&
      error.message === "malformed register: the register breaks ecl.rule.register-declarations-consistent.v1: /entries/1/action_class_id: the register declares this action class more than once",
  );
  const vector = suite("evidence-bundle").find((item) => item.id === "bundle-valid-decision-basis-matches-register");
  assert.ok(vector !== undefined);
  const policy = TrustPolicy.load(bytes(vector.trust_policy_path as string));
  const register = parseStrictJson(bytes(REFUSED_REGISTER)) as JsonObject;
  assert.throws(() => verifyBundle(parseStrictJson(bytes(vector.path)), policy, { now: NOW, register }), RangeError);
});

test("EBMP2-068: an object has the same primary finding inside a bundle as alone", () => {
  for (const [id, code] of [
    ["bundle-invalid-admit-on-judgment", "ecl.rule.decision-basis-one-way.v1"],
    ["bundle-invalid-negative-budget-debit", "ecl.rule.budget-debit-non-negative.v1"],
  ] as const) {
    const report = run(id);
    assert.equal(report.verdict, "invalid", id);
    assert.equal(report.findings[0]?.code, code, id);
    const refused = report.envelopeChecks.filter((check) => check.historical !== "valid");
    assert.deepEqual(
      refused.map((check) => check.historical),
      [SEMANTIC_INVALID],
      id,
    );
    assert.ok(report.findings.some((finding) => finding.code === SEMANTIC_INVALID), id);
    assert.ok(!report.findings.some((finding) => finding.code === "ecl.error.schema-invalid.v1"), id);
  }
});

test("EBMP2-068: each bundle rule names its stage in the registry", () => {
  assert.deepEqual(Object.fromEntries([...ruleStage()].sort()), {
    "ecl.rule.bundle-causal-context-consistent.v1": 8,
    "ecl.rule.bundle-causal-graph-acyclic.v1": 8,
    "ecl.rule.bundle-causal-sequence-monotonic.v1": 8,
    "ecl.rule.bundle-object-identifiers-unique.v1": 3,
    "ecl.rule.bundle-predecessor-digest-valid.v1": 8,
    "ecl.rule.decision-basis-matches-register.v1": 3,
    "ecl.rule.decision-basis-required.v1": 3,
    "ecl.rule.execution-state-transition-valid.v1": 8,
    "ecl.rule.prerelease-obligations-discharged.v1": 8,
  });
});

test("the command says whether it checked the decision basis against a register", (context) => {
  const cli = fileURLToPath(new URL("../../src/cli/ecl-verify.js", import.meta.url));
  if (!existsSync(cli)) {
    context.skip("the command is not built");
    return;
  }
  const suiteDir = "conformance/suites/evidence-bundle";
  const base = [cli, join(repoRoot(), suiteDir, "bundle-valid-decision-basis-matches-register.json"), "--trust-policy", join(repoRoot(), suiteDir, "trust-policy.json"), "--now", NOW];
  const plain = spawnSync(process.execPath, base, { encoding: "utf8" });
  assert.equal(plain.status, 0, plain.stderr);
  assert.match(plain.stdout, /^decision-basis register: none; declared classes not checked against a register$/m);
  const registerPath = join(repoRoot(), suiteDir, "register.json");
  const checked = spawnSync(process.execPath, [...base, "--register", registerPath], { encoding: "utf8" });
  assert.equal(checked.status, 0, checked.stderr);
  const digest = registerDigest(loadRegister(bytes(`${suiteDir}/register.json`)) as JsonObject)["value"] as string;
  assert.ok(checked.stdout.includes(`decision-basis register: urn:example:register:bundle sha256:${digest}`), checked.stdout);
  const refused = spawnSync(process.execPath, [...base, "--register", join(repoRoot(), REFUSED_REGISTER)], { encoding: "utf8" });
  assert.equal(refused.status, 2);
  assert.match(refused.stderr, /malformed register: the register breaks ecl\.rule\.register-declarations-consistent\.v1: \/entries\/1\/action_class_id/);
});

test("DCMP2-053: with the request in hand, an input whose source is the requesting actor is not verifiable", () => {
  const report = run("bundle-invalid-verifiable-input-from-actor");
  assert.equal(report.verdict, "invalid");
  assert.deepEqual(
    report.findings.map((finding) => [finding.code, finding.message]),
    [["ecl.rule.decision-basis-one-way.v1", "object 1: /extensions/0/value/inputs/0/class: an input whose source is the requesting actor cannot be verifiable"]],
  );
  const request: JsonObject = { actor: { id: "urn:example:agent:test-1" } };
  const entry = (inputClass: string, source: string): JsonObject => ({ input: `urn:example:input:${source}`, class: inputClass, required: false, status: "unavailable", effect: "none", source });
  const value: JsonObject = { inputs: [entry("verifiable", "URN:example:agent:test-1"), entry("judgment", "urn:example:agent:test-1"), entry("verifiable", "urn:example:agent:test-2")] };
  assert.deepEqual(actorSourceProblems(value, request), [["/inputs/0/class", "an input whose source is the requesting actor cannot be verifiable"]]);
  for (const other of [{}, { actor: "urn:example:agent:test-1" }, { actor: { id: 7 } }] as JsonObject[]) {
    assert.deepEqual(actorSourceProblems(value, other), []);
  }
  assert.deepEqual(actorSourceProblems({ inputs: "not a list" }, request), []);
  // The case of a percent-encoding's hexadecimal digits, and of an https URI's host, does not make
  // another name; a source under the actor does.
  for (const [actor, source] of [
    ["urn:example:agent:test%2d1", "urn:example:agent:test%2D1"],
    ["https://agents.example/test-1", "https://AGENTS.EXAMPLE/test-1"],
  ] as const) {
    assert.deepEqual(actorSourceProblems({ inputs: [entry("verifiable", source)] }, { actor: { id: actor } }), [["/inputs/0/class", "an input whose source is the requesting actor cannot be verifiable"]]);
  }
  assert.deepEqual(actorSourceProblems({ inputs: [entry("verifiable", "urn:example:agent:test-1:tools")] }, request), []);
});

test("DCMP2-053: with the request in hand, the request was not received before it was issued", () => {
  const report = run("bundle-invalid-decision-basis-received-before-issued");
  assert.equal(report.verdict, "invalid");
  assert.deepEqual(
    report.findings.map((finding) => [finding.code, finding.message]),
    [["ecl.rule.decision-basis-one-way.v1", "object 1: /extensions/0/value/received_at: the request was received before it was issued"]],
  );
  const request: JsonObject = { actor: { id: "urn:example:agent:test-1" }, issued_at: "2026-09-29T10:00:00.000000Z" };
  assert.deepEqual(requestProblems({ inputs: [], received_at: "2026-09-28T10:00:00.000000Z" }, request), [["/received_at", "the request was received before it was issued"]]);
  assert.deepEqual(requestProblems({ inputs: [], received_at: "2026-09-29T10:00:00.000000Z" }, request), []);
  const early: JsonObject = { inputs: [], received_at: "2026-09-29T09:59:59.500000Z" };
  assert.notDeepEqual(requestProblems(early, request), []);
  assert.deepEqual(requestProblems(early, request, 1), []);
});

test("DCMP2-053: a source is compared with the declared source as input names are", () => {
  const register = loadRegister(bytes("conformance/suites/evidence-bundle/register.json")) as JsonObject;
  const entries = register["entries"] as JsonObject[];
  const declared = ((entries[0] as JsonObject)["decision_inputs"] as JsonObject[]).map((item) => ({
    input: item["input"] as string,
    class: item["class"] as string,
    required: item["required"] as boolean,
    status: "unavailable",
    effect: "none",
    source: item["source"] as string,
  }));
  const actionClass = (entries[0] as JsonObject)["action_class_id"] as string;
  const value: JsonObject = { register: registerReference(register), inputs: declared };
  assert.deepEqual(registerProblems(value, register, actionClass), []);
  const variant = structuredClone(value);
  const first = (variant["inputs"] as JsonObject[])[0] as JsonObject;
  first["source"] = "URN:" + (first["source"] as string).slice(4);
  assert.deepEqual(registerProblems(variant, register, actionClass), []);
  first["source"] = (declared[0]?.source as string) + "-other";
  assert.deepEqual(registerProblems(variant, register, actionClass), [["/inputs/0/source", "the source is not the one the register declares"]]);
  delete first["source"];
  assert.deepEqual(registerProblems(variant, register, actionClass), [["/inputs/0/source", "the source is not the one the register declares"]]);
});

test("EBMP2-070: a release records a discharge of each obligation left to Enforcement, as the reference reports it", () => {
  const expected: Record<string, Array<[string, string]>> = {
    "bundle-invalid-prerelease-approval-unmet": [["ecl.rule.prerelease-obligations-discharged.v1", "object 3: the release rests on obligations left to Enforcement and records no discharge"]],
    "bundle-invalid-prerelease-witness-unmet": [["ecl.rule.prerelease-obligations-discharged.v1", "object 3: the release rests on obligations left to Enforcement and records no discharge"]],
    "bundle-invalid-prerelease-obligations-partly-discharged": [["ecl.rule.prerelease-obligations-discharged.v1", "object 3: an obligation left to Enforcement has no discharge"]],
    "bundle-invalid-discharge-of-obligation-not-carried": [["ecl.rule.prerelease-obligations-discharged.v1", "object 3: /extensions/0/value/obligations/3: names an obligation the response does not carry"]],
    "bundle-invalid-discharge-checked-after-release": [["ecl.rule.prerelease-obligations-discharged.v1", "object 3: /extensions/0/value/obligations/0/checked_at: was checked after the release was observed"]],
    "bundle-invalid-discharge-checked-before-decision": [["ecl.rule.prerelease-obligations-discharged.v1", "object 3: /extensions/0/value/obligations/0/checked_at: was checked before the decision was issued"]],
    "bundle-invalid-discharge-proof-obtained-after-check": [["ecl.rule.prerelease-obligations-discharged.v1", "object 3: /extensions/0/value/obligations/0/proof/obtained_at: has a proof obtained after it was checked"]],
    "bundle-invalid-discharge-entry-duplicated": [["ecl.rule.prerelease-obligations-discharged.v1", "object 3: /extensions/0/value/obligations/3: names an obligation that another entry names"]],
    "bundle-invalid-discharge-proof-digest-of-bundle-object": [["ecl.rule.prerelease-obligations-discharged.v1", "object 3: /extensions/0/value/obligations/0/proof/digest: names an object of the bundle by another digest"]],
  };
  for (const [id, findings] of Object.entries(expected)) {
    const report = run(id);
    assert.equal(report.verdict, "invalid", id);
    assert.deepEqual(report.findings.map((finding) => [finding.code, finding.message]), findings, id);
  }
  const discharged = run("bundle-valid-prerelease-obligations-discharged");
  assert.equal(discharged.verdict, "verified");
  assert.ok(discharged.scope.established.includes("prerelease-obligations-discharge-recorded"));
  assert.ok(discharged.scope.notEstablished.includes("prerelease-obligations-met"));
  // The proofs are not objects of the bundle, so they are not verified, with the reason stated.
  assert.ok(discharged.scope.notEstablished.includes("prerelease-obligations-proofs-verified"));
  assert.deepEqual(discharged.scope.reasons, { "prerelease-obligations-proofs-verified": "proof-not-ecl-object" });
});

// A proof that is an object of the bundle is checked there, as the reference
// checks it, and the entry's `fresh_until` must lie after the release plus its release guard.
test("EBMP2-070: carried proofs are verified, and each failing condition is reported as the reference reports it", () => {
  const carried = run("bundle-valid-prerelease-proofs-carried");
  assert.equal(carried.verdict, "verified", JSON.stringify(carried.findings));
  assert.ok(carried.scope.established.includes("prerelease-obligations-proofs-verified"));
  assert.ok(carried.scope.established.indexOf("prerelease-obligations-discharge-recorded") < carried.scope.established.indexOf("prerelease-obligations-proofs-verified"));
  assert.deepEqual(carried.scope.reasons, {});
  for (const id of ["bundle-valid-prerelease-proofs-not-carried", "bundle-valid-discharge-uncarried-proof-digest-not-checked"]) {
    const report = run(id);
    assert.equal(report.verdict, "verified", id);
    assert.deepEqual(report.scope.reasons, { "prerelease-obligations-proofs-verified": "proof-not-ecl-object" }, id);
  }
  for (const id of ["bundle-valid-discharge-issuer-label-is-actor", "bundle-valid-discharge-issuer-label-percent-encoded", "bundle-valid-discharge-issuer-mislabeled"]) {
    const report = run(id);
    assert.equal(report.verdict, "verified", id);
    assert.ok(report.scope.established.includes("prerelease-obligations-proofs-verified"), id);
  }
  // EBMP2-076: the decision names no issuer for the witness obligation, so the issuer test is not
  // made and the proofs are reported not verified; the bundle verifies.
  const unnamed = run("bundle-valid-discharge-witness-source-not-named");
  assert.equal(unnamed.verdict, "verified", JSON.stringify(unnamed.findings));
  assert.deepEqual(unnamed.scope.reasons, { "prerelease-obligations-proofs-verified": "issuer-not-named" });
  const entry = "object 4: /extensions/0/value/obligations";
  const unproven = "ecl.error.obligation-unproven.v1";
  const expected: Record<string, string[]> = {
    "bundle-invalid-discharge-approval-signed-without-approval-purpose": [`${entry}/0/proof/reference: names an approval record signed by a key without the approval purpose`],
    "bundle-invalid-discharge-proof-not-from-named-source": [`${entry}/1/proof/reference: names a proof not signed by the issuer the obligation names`, `${entry}/2/proof/reference: names a proof not signed by the issuer the obligation names`],
    "bundle-invalid-discharge-proof-of-another-type": [`${entry}/0/proof/reference: names a proof of a type the obligation does not admit`],
    "bundle-invalid-discharge-witness-result-of-another-witness": [`${entry}/1/proof/reference: names a witness result of another witness`, `${entry}/2/proof/reference: names a witness result of another witness`],
    "bundle-invalid-discharge-approval-by-another-approver": [`${entry}/0/proof/reference: names an approval by an approver other than the one the obligation names`],
    "bundle-invalid-discharge-approval-rejects": [`${entry}/0/proof/reference: names an intervention that does not approve`],
    "bundle-invalid-discharge-proof-is-the-decision-response": [`${entry}/0/proof/reference: names a decision message as a proof`],
    "bundle-invalid-discharge-approval-of-another-request": [`${entry}/0/proof/reference: names an approval of another request`],
    "bundle-invalid-discharge-proof-expired-at-release": [`${entry}/0/fresh_until: is not later than the release plus its declared release guard`, `${entry}/0/proof/reference: names a proof that expired before the release plus its declared release guard`],
    "bundle-invalid-discharge-fresh-until-beyond-proof-bound": [`${entry}/0/fresh_until: is later than the bound the proof declares`],
  };
  for (const [id, messages] of Object.entries(expected)) {
    const report = run(id);
    assert.equal(report.verdict, "invalid", id);
    assert.deepEqual(
      report.findings.map((finding) => [finding.code, finding.message]),
      messages.map((message) => [unproven, message]),
      id,
    );
    assert.deepEqual(report.scope.established, [], id);
  }
  const actorSigned = suite("evidence-bundle").find((item) => item.id === "bundle-invalid-discharge-proof-signed-by-actor");
  assert.ok(actorSigned !== undefined);
  const history = (actorSigned.trust_policy_history_paths ?? []).map((path) => TrustPolicy.load(bytes(path)));
  const signedByActor = verifyBundle(parseStrictJson(bytes(actorSigned.path)), TrustPolicy.load(bytes(actorSigned.trust_policy_path as string)), { now: NOW, history });
  assert.deepEqual(
    signedByActor.findings.map((finding) => [finding.code, finding.message]),
    [1, 2].map((position) => [unproven, `${entry}/${position}/proof/reference: names a proof that the requesting actor signed`]),
  );
  const envelope = run("bundle-invalid-discharge-proof-envelope-invalid");
  assert.equal(envelope.findings[0]?.code, "ecl.error.signature-policy-invalid.v1");
  assert.ok(envelope.findings.some((finding) => finding.code === unproven && finding.message.endsWith("names a proof whose envelope is not valid under the trust policy")));
  const stale = run("bundle-invalid-discharge-uncarried-proof-stale");
  assert.deepEqual(stale.findings.map((finding) => [finding.code, finding.message]), [[unproven, "object 3: /extensions/0/value/obligations/0/fresh_until: is not later than the release plus its declared release guard"]]);
  assert.equal(run("bundle-valid-discharge-uncarried-proof-fresh").verdict, "verified");
  assert.equal(run("bundle-invalid-discharge-result-not-satisfied").findings[0]?.code, "ecl.rule.extension-value-valid.v1");
  assert.ok(run("bundle-valid-post-release-obligation").scope.notEstablished.includes("post-release-obligations-met"));
});

test("EBMP2-072 to EBMP2-075: recorded forwards, use counts, single-use releases and the MCP binding", () => {
  const expected: Record<string, [string, string]> = {
    "bundle-invalid-mcp-released-after-valid-until": ["ecl.error.expired.v1", "envelope 4: the terminal event records that the release completed after the authorization's valid_until"],
    "bundle-invalid-release-guard-reaches-valid-until": ["ecl.error.expired.v1", "the release, with its declared release guard, lies outside the authorization's validity window"],
    "bundle-invalid-mcp-terminal-names-another-call": ["ecl.error.decision-binding-invalid.v1", "envelope 4: the event's MCP binding names another call than its request"],
    "bundle-invalid-mcp-success-without-response-digest": ["ecl.error.decision-binding-invalid.v1", "envelope 4: the terminal event binds no server response"],
    "bundle-invalid-use-count-beyond-policy": ["ecl.error.decision-binding-invalid.v1", "envelope 2: the use count is outside the authorization's use policy"],
    "bundle-invalid-single-use-consumed-twice": ["ecl.error.decision-binding-invalid.v1", "two consumptions of one authorization record one use"],
    "bundle-invalid-single-use-release-without-consumption": ["ecl.error.decision-binding-invalid.v1", "envelope 2: a release of single-use authority has no recorded consumption"],
  };
  for (const [id, [code, message]] of Object.entries(expected)) {
    const report = run(id);
    assert.equal(report.verdict, "invalid", id);
    assert.deepEqual([report.findings[0]?.code, report.findings[0]?.message], [code, message], id);
  }
  const within = run("bundle-valid-mcp-forward-within-authority");
  assert.equal(within.verdict, "verified");
  assert.equal(within.completionAfterWindow, false);
  // The release plus its guard is tested, and a late answer is information.
  assert.equal(run("bundle-valid-release-guard-inside-window").verdict, "verified");
  const late = run("bundle-valid-mcp-forward-completed-after-valid-until");
  assert.equal(late.verdict, "verified", JSON.stringify(late.findings));
  assert.equal(late.completionAfterWindow, true);
  assert.ok(late.scope.established.includes("release-within-authority"));
  assert.equal(run("bundle-invalid-mcp-released-after-valid-until").completionAfterWindow, false);
});

test("EBMP2-076: every report carries the scope of its verdict, in the order of the table", () => {
  const verified = run("bundle-valid-succeeded");
  assert.deepEqual(verified.scope, {
    established: ["envelope-signatures", "current-trust", "object-rules", "decision-basis-recorded", "bindings", "release-within-authority", "causal-completeness"],
    // The register item applies only when the caller supplied a register.
    notEstablished: ["trusted-time", "recorded-times-true", "effects-occurred", "deployment-assessed", "statements-true"],
    reasons: {},
    checks: verified.scope.checks,
  });
  // Each established item names the checks of registries/scope-checks.json behind it.
  assert.deepEqual(Object.keys(verified.scope.checks), [...verified.scope.established]);
  assert.deepEqual(verified.scope.checks["causal-completeness"]?.checks, [
    "identifiers-unique",
    "predecessors-resolved",
    "predecessor-digests",
    "graph-acyclic",
    "causal-context",
    "sequence-monotonic",
    "state-transitions",
    "terminal-per-request",
    "attempt-authority-consumed",
  ]);
  // A bundle that records no release says so, with the reason stated.
  const cancelled = run("bundle-valid-cancelled-after-consumption");
  assert.equal(cancelled.verdict, "verified");
  assert.ok(cancelled.scope.notEstablished.includes("release-within-authority"));
  assert.deepEqual(cancelled.scope.reasons, { "release-within-authority": "no-release-recorded" });
  assert.deepEqual(reportToJson(cancelled)["scope"], {
    established: [...cancelled.scope.established],
    not_established: [...cancelled.scope.notEstablished],
    reasons: { "release-within-authority": "no-release-recorded" },
    checks: Object.fromEntries(Object.entries(cancelled.scope.checks).map(([item, behind]) => [item, { checks: [...behind.checks], objects: [...behind.objects] }])),
  });
  assert.equal(reportToJson(cancelled)["completion_after_window"], false);
  const invalid = run("bundle-invalid-prerelease-approval-unmet");
  assert.deepEqual(invalid.scope, {
    established: [],
    notEstablished: [
      "envelope-signatures",
      "current-trust",
      "trusted-time",
      "object-rules",
      "decision-basis-recorded",
      "bindings",
      "release-within-authority",
      "causal-completeness",
      "prerelease-obligations-discharge-recorded",
      "prerelease-obligations-proofs-verified",
      "prerelease-obligations-met",
      "recorded-times-true",
      "effects-occurred",
      "deployment-assessed",
      "statements-true",
    ],
    reasons: {},
    checks: {},
  });
  const incomplete = run("bundle-incomplete-no-terminal");
  assert.equal(incomplete.verdict, "incomplete");
  assert.ok(!incomplete.scope.established.includes("causal-completeness"));
  assert.ok(incomplete.scope.notEstablished.includes("causal-completeness"));
  const vector = suite("evidence-bundle").find((item) => item.id === "bundle-current-trust-failed-revoked-after-use");
  assert.ok(vector !== undefined);
  const history = (vector.trust_policy_history_paths ?? []).map((path) => TrustPolicy.load(bytes(path)));
  const failedNow = verifyBundle(parseStrictJson(bytes(vector.path)), TrustPolicy.load(bytes(vector.trust_policy_path as string)), { now: NOW, history });
  assert.equal(failedNow.verdict, CURRENT_TRUST_FAILED);
  assert.ok(failedNow.scope.established.includes("causal-completeness"));
  assert.ok(failedNow.scope.notEstablished.includes("current-trust"));
});

// EBMP2-062 and IE1-029: the payload node budget bounds what is built. IE1-028: the record limits
// of the causal analysis are integers of at least 1.
test("EBMP2-062: a payload beyond the remaining node budget is refused before its later defects", () => {
  const bundle = parseStrictJson(bytes(`${FIXTURES}/succeeded.json`)) as JsonObject;
  const first = (bundle["envelopes"] as JsonObject[])[0] as JsonObject;
  const raw = Buffer.from(`{"unrecognized":[${new Array(100_500).fill("0").join(",")}],"zz":1,"zz":2}`, "utf8");
  first["payload"] = raw.toString("base64");
  first["payload_digest"] = { algorithm: "ecl.digest.sha-256.v1", value: createHash("sha256").update(raw).digest("hex") };
  bundle["envelopes"] = [first];
  const policy = TrustPolicy.load(bytes(`${FIXTURES}/trust-policy.json`));
  const report = verifyBundle(bundle, policy, { now: NOW });
  assert.equal(report.verdict, "invalid");
  assert.deepEqual(reportedIdentifiers(report), ["ecl.error.resource-limit-exceeded.v1"]);
  assert.deepEqual(report.envelopeChecks, []);
});

test("IE1-028: a causal analysis limit that is not an integer of at least 1 is refused", () => {
  for (const value of [Number.NaN, Number.POSITIVE_INFINITY, 2.5, 0, -1]) {
    assert.throws(() => analyzeBundle([], [], value, 1), /integers of at least 1/);
    assert.throws(() => analyzeBundle([], [], 1, value), /integers of at least 1/);
  }
  assert.doesNotThrow(() => analyzeBundle([], [], 1, 1));
});
