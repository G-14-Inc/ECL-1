/**
 * The causal graph over every object of a bundle (EBMP2-059, EBMP2-061, EBMP2-077), time
 * attestations that bind the signatures they attest (IE1-033 to IE1-035), current compromise
 * knowledge over every trust dependency (TP1-006, EBMP2-060), evidence later than the evaluation
 * time (EBMP2-057), and the checks behind each established scope item (EBMP2-076,
 * `registries/scope-checks.json`). The bundles are signed with the repository's test keys.
 */

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseStrictJson, reportToJson, reportedIdentifiers, TrustPolicy, verifyBundle } from "../../src/index.js";
import type { BundleReport, JsonObject, JsonValue, VerifyBundleOptions } from "../../src/index.js";
import { decodeCanonicalJsonPayload } from "../../src/integrity/envelope.js";
import { canonicalize } from "../../src/json/canonical.js";
import { sha256Hex } from "../../src/crypto/bytes.js";
import { CORROBORATION_ITEMS, reportScope, SCOPE_CHECK_ORDER, SCOPE_CHECKS, SCOPE_ITEM_CHECKS, SCOPE_NEVER, scopeObjects } from "../../src/evidence/verify.js";
import { countersign, covered, resign, seed, signEnvelope } from "./builders.js";
import type { Signer } from "./builders.js";
import { bytes, json } from "./helpers.js";

const CASES = "packages/ecl-ts/test/fixtures/verifier-cases";
const NOW = "2026-09-29T10:00:02Z";
const EBMP = "application/vnd.ecl.ebmp+json";
const OBSERVER: Signer = { keyId: "urn:example:key:bundle-observer", seed: seed(3) };
const AGENT: Signer = { keyId: "urn:example:key:bundle-agent", seed: seed(0) };
const TIME_AUTHORITY: Signer = { keyId: "urn:example:key:bundle-time-authority", seed: seed(6) };
const TIME_ISSUER = "urn:example:time-authority:bundle";

const DIGEST_RULE = "ecl.rule.bundle-predecessor-digest-valid.v1";
const CONTEXT_RULE = "ecl.rule.bundle-causal-context-consistent.v1";
const INCOMPLETE = "ecl.error.causal-closure-incomplete.v1";
const TRUSTED_TIME_INVALID = "ecl.error.trusted-time-invalid.v1";
const CLOCK_REGRESSED = "ecl.error.clock-regressed.v1";

function policy(name: string): TrustPolicy {
  return TrustPolicy.load(bytes(`${CASES}/${name}.json`));
}

function bundle(name: string): JsonObject {
  return parseStrictJson(bytes(`${CASES}/${name}.json`)) as JsonObject;
}

function payloadOf(envelope: JsonValue): JsonObject {
  return decodeCanonicalJsonPayload(envelope) as JsonObject;
}

function verifyObservation(value: JsonObject, options: Partial<VerifyBundleOptions> = {}): BundleReport {
  return verifyBundle(value, policy("observation-policy"), { now: NOW, ...options });
}

/** The observation bundle with its observation's payload changed by `change` and signed again. */
function withObservation(change: (payload: JsonObject) => void): JsonObject {
  const value = bundle("valid-observation");
  const observations = value["observations"] as JsonObject[];
  const payload = structuredClone(payloadOf(observations[0] as JsonObject)) as JsonObject;
  change(payload);
  return { ...value, observations: [signEnvelope(payload, EBMP, [OBSERVER])] };
}

function digestOf(value: JsonValue): JsonObject {
  return { algorithm: "ecl.digest.sha-256.v1", value: sha256Hex(canonicalize(value)) };
}

/** The checks of each established item are its registered checks, over its whole object set. */
function assertClaimsBacked(report: BundleReport): void {
  assert.deepEqual(Object.keys(report.scope.checks), [...report.scope.established]);
  for (const item of report.scope.established) {
    const required = SCOPE_ITEM_CHECKS[item];
    assert.ok(required !== undefined, item);
    assert.deepEqual(report.scope.checks[item]?.checks, required.checks, item);
    assert.deepEqual(report.scope.checks[item]?.objects, scopeObjects(report, required.objectSet), item);
  }
}

test("EBMP2-059: an observation's predecessors are checked like every other object's", () => {
  const valid = verifyObservation(bundle("valid-observation"));
  assert.equal(valid.verdict, "verified");
  assert.equal(valid.causalStatus, "complete");
  assert.equal(valid.effects[0]?.level, "corroborated");
  assert.ok(valid.scope.established.includes("causal-completeness"));
  assertClaimsBacked(valid);
  assert.deepEqual(valid.scope.checks["causal-completeness"]?.objects, [0, 1, 2, 3, 4, 5]);

  // A predecessor the bundle does not hold leaves the closure incomplete, and nothing corroborates.
  const missing = verifyObservation(bundle("missing-observation-predecessor"));
  assert.equal(missing.verdict, "incomplete");
  assert.deepEqual(reportedIdentifiers(missing), [INCOMPLETE]);
  assert.equal(missing.effects[0]?.level, "issuer-asserted");
  assert.ok(!missing.scope.established.includes("causal-completeness"));
  assert.ok(missing.scope.notEstablished.includes("causal-completeness"));

  // A predecessor the bundle holds, named by another digest, is a defect of the graph.
  const digest = verifyObservation(bundle("wrong-observation-predecessor-digest"));
  assert.equal(digest.verdict, "invalid");
  assert.deepEqual(reportedIdentifiers(digest), [DIGEST_RULE]);
  assert.deepEqual(digest.scope.established, []);

  // An observation of attempt 99 with an unrelated root trace names the terminal of attempt 1.
  const context = verifyObservation(bundle("observation-wrong-attempt"));
  assert.equal(context.verdict, "invalid");
  assert.deepEqual(reportedIdentifiers(context), [CONTEXT_RULE]);
  assert.deepEqual(context.scope.established, []);
});

test("EBMP2-077 and EBMP2-061: the context of each edge, and corroboration of the exact terminal and attempt", () => {
  // An unrelated root trace alone is a defect of the edge.
  const trace = verifyObservation(withObservation((payload) => ((payload["workflow"] as JsonObject)["root_trace_id"] = "urn:example:trace:other")));
  assert.deepEqual(reportedIdentifiers(trace), [CONTEXT_RULE]);
  // A later attempt may follow an earlier one: the edge is valid, but it corroborates nothing.
  const later = verifyObservation(withObservation((payload) => ((payload["workflow"] as JsonObject)["attempt"] = 2)));
  assert.equal(later.verdict, "verified", JSON.stringify(later.findings));
  assert.equal(later.effects[0]?.level, "issuer-asserted");
  // A predecessor in the same workflow with a greater attempt than its successor is not.
  const earlier = verifyObservation(withObservation((payload) => ((payload["workflow"] as JsonObject)["attempt"] = 0)));
  assert.deepEqual(reportedIdentifiers(earlier), [CONTEXT_RULE]);
  // An observation in another workflow that is not its parent.
  const workflow = verifyObservation(withObservation((payload) => ((payload["workflow"] as JsonObject)["workflow_id"] = "urn:example:workflow:other")));
  assert.deepEqual(reportedIdentifiers(workflow), [CONTEXT_RULE]);
  // A legitimate message predecessor: the observation names the decision request by id and digest.
  const value = bundle("valid-observation");
  const request = payloadOf((value["envelopes"] as JsonValue[])[0] as JsonValue);
  const named = verifyObservation(
    withObservation((payload) => {
      (payload["workflow"] as JsonObject)["causal_predecessors"] = [{ id: request["message_id"] as string, digest: digestOf(request), relation: "ecl.relation.follows.v1" }];
    }),
  );
  assert.equal(named.verdict, "verified", JSON.stringify(named.findings));
  assert.equal(named.causalStatus, "complete");
  // It does not name the terminal, so it does not corroborate the terminal's effect.
  assert.equal(named.effects[0]?.level, "issuer-asserted");
  // The same identifier in envelopes and observations.
  const response = payloadOf((value["envelopes"] as JsonValue[])[1] as JsonValue);
  const duplicate = verifyObservation(withObservation((payload) => (payload["object_id"] = response["message_id"] as string)));
  assert.equal(duplicate.verdict, "invalid");
  assert.equal(reportedIdentifiers(duplicate)[0], "ecl.rule.bundle-object-identifiers-unique.v1");
  // A cycle through the observation: the observation names itself.
  const cycle = verifyObservation(
    withObservation((payload) => {
      const predecessors = (payload["workflow"] as JsonObject)["causal_predecessors"] as JsonObject[];
      predecessors.push({ id: payload["object_id"] as string, digest: { algorithm: "ecl.digest.sha-256.v1", value: "0".repeat(64) }, relation: "ecl.relation.follows.v1" });
    }),
  );
  assert.equal(cycle.verdict, "invalid");
  assert.ok(reportedIdentifiers(cycle).includes("ecl.rule.bundle-causal-graph-acyclic.v1"), JSON.stringify(cycle.findings));
});

test("EBMP2-057: evidence later than the evaluation time is clock-regressed, not verified", () => {
  const report = verifyObservation(bundle("valid-observation"), { now: "2026-09-01T00:00:00Z" });
  assert.equal(report.verdict, "invalid");
  // The primary finding; an attempt whose events are not valid also lacks its consumed authority.
  assert.equal(reportedIdentifiers(report)[0], CLOCK_REGRESSED);
  assert.ok(report.envelopeChecks.every((check) => check.historical === CLOCK_REGRESSED));
  assert.deepEqual(report.scope.established, []);
  // An object time equal to the evaluation time is not later: the last object is observed at
  // 10:00:00.5 and the bundle verifies at that instant.
  assert.equal(verifyObservation(bundle("valid-observation"), { now: "2026-09-29T10:00:00.500000Z" }).verdict, "verified");
  // An attested time later than the evaluation time is clock-regressed too.
  const timed = attested(bundle("timed-bundle"));
  const early = verifyBundle(timed, policy("timed-policy-v2-valid"), { now: "2026-09-29T10:00:00.500000Z", history: [policy("timed-policy-v1")] });
  assert.equal(early.verdict, "invalid");
  assert.equal(reportedIdentifiers(early)[0], CLOCK_REGRESSED);
});

/** Each envelope of the timed bundle countersigned again, under IE1-033 as it now stands. */
function attested(value: JsonObject, change?: (envelope: JsonObject, position: number) => JsonObject): JsonObject {
  const envelopes = (value["envelopes"] as JsonObject[]).map((envelope, position) => {
    const entry = (envelope["countersignatures"] as JsonObject[])[0] as JsonObject;
    const statement = payloadOf(entry["attestation"] as JsonObject);
    const { countersignatures: _dropped, ...bare } = envelope;
    const plain = { ...bare, envelope_artifact_version: 1 } as JsonObject;
    const prepared = change === undefined ? plain : change(plain, position);
    return countersign(prepared, {
      authority: TIME_AUTHORITY,
      issuer: TIME_ISSUER,
      issuedAt: statement["issued_at"] as string,
      trustPolicy: (statement["integrity_policy"] as JsonObject)["trust_policy"] as JsonObject,
      attestationId: entry["counter_id"] as string,
    });
  });
  return { ...value, envelopes };
}

function verifyTimed(value: JsonObject, current: string, options: Partial<VerifyBundleOptions> = {}): BundleReport {
  return verifyBundle(value, policy(current), { now: NOW, history: [policy("timed-policy-v1")], requireTrustedTime: true, ...options });
}

test("IE1-033 to IE1-035: an attestation binds the signatures it attests", () => {
  const timed = attested(bundle("timed-bundle"));
  const valid = verifyTimed(timed, "timed-policy-v2-valid");
  assert.equal(valid.verdict, "verified", JSON.stringify(valid.findings));
  assert.ok(valid.scope.established.includes("trusted-time"));
  assert.ok(valid.scope.established.includes("current-trust"));
  assertClaimsBacked(valid);
  // Each object's signer and its time authority are trust dependencies, at their own times.
  assert.equal(valid.trustDependencies.length, 10);
  const authority = valid.trustDependencies.find((dependency) => dependency.role === "time-authority");
  assert.equal(authority?.keyId, TIME_AUTHORITY.keyId);
  assert.equal(authority?.at, "2026-09-29T10:00:00.900000Z");
  assert.equal(authority?.historicalPolicyVersion, "1");
  assert.equal(authority?.currentPolicyVersion, "2");
  const signer = valid.trustDependencies.find((dependency) => dependency.role === "signer");
  assert.equal(signer?.at, "2026-09-29T10:00:00.900000Z");
  assert.deepEqual(Object.keys((reportToJson(valid)["trust_dependencies"] as JsonObject[])[0] as JsonObject).sort(), [
    "at",
    "counter_id",
    "current",
    "current_policy_version",
    "historical",
    "historical_policy_version",
    "index",
    "key_id",
    "revoked_effective_at",
    "role",
    "suite",
  ]);

  // The substitution: an attestation over a placeholder signature, then a valid signature put in
  // its place. The payload and its digest are the same; the signature is not the one attested.
  const substituted = attested(bundle("timed-bundle"), (envelope, position) =>
    position === 0 ? { ...envelope, signatures: [{ ...(envelope["signatures"] as JsonObject[])[0], signature: Buffer.alloc(64, 7).toString("base64") }] } : envelope,
  );
  const first = (substituted["envelopes"] as JsonObject[])[0] as JsonObject;
  const swapped: JsonObject = { ...substituted, envelopes: [{ ...resign(first, [AGENT]), countersignatures: first["countersignatures"] as JsonValue }, ...(substituted["envelopes"] as JsonObject[]).slice(1)] };
  for (const accept of [false, true]) {
    const report = verifyTimed(swapped, "timed-policy-v2-valid", { acceptCurrentTrustFailure: accept });
    assert.equal(report.verdict, "invalid", `accept=${String(accept)}`);
    assert.equal(reportedIdentifiers(report)[0], TRUSTED_TIME_INVALID);
    assert.equal(report.envelopeChecks[0]?.historical, TRUSTED_TIME_INVALID);
  }
  // A changed key identifier or suite in what the attestation covers.
  for (const member of ["key_id", "suite"]) {
    const changed = attested(bundle("timed-bundle"));
    const envelope = (changed["envelopes"] as JsonObject[])[1] as JsonObject;
    const cover = covered(envelope);
    ((cover["signatures"] as JsonObject[])[0] as JsonObject)[member] = member === "key_id" ? "urn:example:key:bundle-ep" : "ecl.sig.ecdsa-p256-sha256.v1";
    const statement = payloadOf(((envelope["countersignatures"] as JsonObject[])[0] as JsonObject)["attestation"] as JsonObject);
    const { countersignatures: _dropped, ...bare } = envelope;
    const recountersigned = countersign({ ...bare, envelope_artifact_version: 1 } as JsonObject, {
      authority: TIME_AUTHORITY,
      issuer: TIME_ISSUER,
      issuedAt: statement["issued_at"] as string,
      trustPolicy: (statement["integrity_policy"] as JsonObject)["trust_policy"] as JsonObject,
      attestationId: statement["attestation_id"] as string,
      covered: cover,
    });
    const envelopes = [...(changed["envelopes"] as JsonObject[])];
    envelopes[1] = recountersigned;
    const report = verifyTimed({ ...changed, envelopes }, "timed-policy-v2-valid");
    assert.equal(reportedIdentifiers(report)[0], TRUSTED_TIME_INVALID, member);
  }
  // Two attestation chains: each is verified on its own, and the earliest covering time is used.
  const twice = attested(bundle("timed-bundle"));
  const envelopes = [...(twice["envelopes"] as JsonObject[])];
  const firstEnvelope = envelopes[0] as JsonObject;
  const statement = payloadOf(((firstEnvelope["countersignatures"] as JsonObject[])[0] as JsonObject)["attestation"] as JsonObject);
  envelopes[0] = countersign(firstEnvelope, {
    authority: TIME_AUTHORITY,
    issuer: TIME_ISSUER,
    issuedAt: "2026-09-29T10:00:00.050000Z",
    trustPolicy: (statement["integrity_policy"] as JsonObject)["trust_policy"] as JsonObject,
    attestationId: "urn:example:time-attestation:second",
  });
  const both = verifyTimed({ ...twice, envelopes }, "timed-policy-v2-valid");
  assert.equal(both.verdict, "verified", JSON.stringify(both.findings));
  assert.equal(both.envelopeChecks[0]?.trustedTime, "2026-09-29T10:00:00.050000Z");
  // One of them invalid (a time authority the bundle's own signer stands in for) makes it invalid.
  envelopes[0] = countersign(firstEnvelope, {
    authority: AGENT,
    issuer: TIME_ISSUER,
    issuedAt: "2026-09-29T10:00:00.050000Z",
    trustPolicy: (statement["integrity_policy"] as JsonObject)["trust_policy"] as JsonObject,
    attestationId: "urn:example:time-attestation:second",
  });
  assert.equal(reportedIdentifiers(verifyTimed({ ...twice, envelopes }, "timed-policy-v2-valid"))[0], TRUSTED_TIME_INVALID);
});

test("TP1-006: compromise knowledge in the current policy reaches every trust dependency", () => {
  const timed = attested(bundle("timed-bundle"));
  for (const accept of [false, true]) {
    // The time authority's key is revoked from 09:00, before its attestations at about 10:00.
    const earlier = verifyTimed(timed, "timed-policy-v2-retroactively-revoked", { acceptCurrentTrustFailure: accept });
    assert.equal(earlier.verdict, "invalid", `accept=${String(accept)}`);
    assert.equal(reportedIdentifiers(earlier)[0], TRUSTED_TIME_INVALID);
    assert.ok(earlier.envelopeChecks.every((check) => check.historical === TRUSTED_TIME_INVALID));
    assert.deepEqual(earlier.scope.established, []);
    const authority = earlier.trustDependencies.find((dependency) => dependency.role === "time-authority");
    // The time authority's signature is the dependency that fails: its countersignature is not
    // valid, and the current policy's revocation that made it so is named.
    assert.equal(authority?.historical, TRUSTED_TIME_INVALID);
    assert.equal(authority?.at, null);
    assert.equal(authority?.revokedEffectiveAt, "2026-09-29T09:00:00Z");
    assert.equal(authority?.current, "ecl.error.revoked.v1");
  }
  // Revoked after its attestations, or absent from the current policy: the attested time stays
  // valid, and the time authority's current status fails current trust.
  for (const [current, status] of [
    ["timed-policy-v2-revoked", "ecl.error.revoked.v1"],
    ["timed-policy-v2-removed", "ecl.error.signature-policy-invalid.v1"],
  ] as const) {
    const report = verifyTimed(timed, current);
    assert.equal(report.verdict, "current-trust-failed", current);
    assert.deepEqual(reportedIdentifiers(report), [status], current);
    assert.ok(report.envelopeChecks.every((check) => check.historical === "valid" && check.current === "valid"), current);
    assert.ok(report.scope.established.includes("trusted-time"), current);
    assert.ok(!report.scope.established.includes("current-trust"), current);
    const waived = verifyTimed(timed, current, { acceptCurrentTrustFailure: true });
    assert.equal(waived.verdict, "verified", current);
    assert.equal(waived.acceptedCurrentTrustFailure, true, current);
    assert.ok(waived.scope.notEstablished.includes("current-trust"), current);
    assertClaimsBacked(waived);
  }
  // An evidence signer revoked in the current policy from before its object's time, while the
  // version the object names still accepts it: not historically valid, whatever the waiver.
  const document = parseStrictJson(bytes(`${CASES}/timed-policy-v2-valid.json`)) as JsonObject;
  const revoking = TrustPolicy.load(
    new TextEncoder().encode(JSON.stringify({ ...document, revocations: [{ key_id: AGENT.keyId, effective_at: "2026-09-29T09:00:00Z", reason: "compromised" }] })),
  );
  for (const accept of [false, true]) {
    const report = verifyBundle(timed, revoking, { now: NOW, history: [policy("timed-policy-v1")], acceptCurrentTrustFailure: accept });
    assert.equal(report.verdict, "invalid");
    assert.equal(reportedIdentifiers(report)[0], "ecl.error.revoked.v1");
    assert.equal(report.envelopeChecks[0]?.historical, "ecl.error.revoked.v1");
  }
});

test("EBMP2-076: no item is established unless every check it requires ran and held over its whole object set", () => {
  const report = verifyObservation(bundle("valid-observation"));
  assert.ok(report.scope.established.length > 0);
  for (const item of report.scope.established) {
    const required = SCOPE_ITEM_CHECKS[item];
    assert.ok(required !== undefined);
    for (const check of required.checks) {
      const record = report.checksRun[check];
      assert.ok(record !== undefined, `${item}: ${check}`);
      // The check did not run over one object of the set: the item is not established.
      const objects = scopeObjects(report, required.objectSet);
      const skipped = { ...report, checksRun: { ...report.checksRun, [check]: { ran: record.ran.filter((index) => index !== objects[0]), failed: [] } } };
      assert.ok(!reportScope(skipped).established.includes(item), `${item}: ${check} skipped`);
      // The check did not run at all.
      const { [check]: _absent, ...rest } = report.checksRun;
      assert.ok(!reportScope({ ...report, checksRun: rest }).established.includes(item), `${item}: ${check} absent`);
      // The check ran and did not hold for one object.
      const failed = { ...report, checksRun: { ...report.checksRun, [check]: { ran: record.ran, failed: [objects[0] as number] } } };
      assert.ok(!reportScope(failed).established.includes(item), `${item}: ${check} failed`);
    }
  }
  // The JSON report names, for each established item, its checks and objects.
  const scope = reportToJson(report)["scope"] as JsonObject;
  assert.deepEqual(Object.keys(scope["checks"] as JsonObject), [...report.scope.established]);
});

/** The payloads of DCMP2-056's wire example, each signed with the test key of its role. */
function continuationBundle(change: (payloads: Record<string, JsonObject>) => JsonObject[] | undefined = () => undefined): JsonObject {
  const example = parseStrictJson(bytes(`${CASES}/continuation-payloads.json`)) as JsonObject;
  const payloads: Record<string, JsonObject> = {};
  for (const name of ["continued_request", "challenge_response", "approval", "continuation_request"]) {
    payloads[name] = structuredClone(example[name]) as JsonObject;
  }
  const extra = change(payloads) ?? [];
  const signer: Record<string, Signer> = {
    continued_request: AGENT,
    challenge_response: { keyId: "urn:example:key:bundle-decision", seed: seed(1) },
    approval: { keyId: "urn:example:key:bundle-approval-service", seed: seed(50) },
    continuation_request: AGENT,
  };
  const envelopes = Object.entries(payloads).map(([name, payload]) =>
    signEnvelope(payload, payload["protocol"] === "DCMP-2" ? "application/vnd.ecl.dcmp+json" : EBMP, [signer[name] as Signer]),
  );
  return { schema_version: "ecl_evidence_bundle_v1", envelopes: [...envelopes, ...extra.map((payload) => signEnvelope(payload, "application/vnd.ecl.dcmp+json", [AGENT]))] };
}

/** The findings of EBMP2-078 in a report: those that name the continuation. */
function continuationFindings(report: BundleReport): string[] {
  return report.findings.filter((finding) => finding.message.includes(": the continuation ")).map((finding) => `${finding.code}: ${finding.message.split(": the continuation ")[1] as string}`);
}

test("EBMP2-078: a continuation names its continued request, the challenge and the approval, and changes nothing else", () => {
  const verify = (value: JsonObject): BundleReport => verifyObservation(value);
  const BINDING = "ecl.error.decision-binding-invalid.v1";
  // The wire example's continuation: no finding of EBMP2-078 (its other objects are not a
  // complete history, and the example's challenge names a trust policy this test does not hold).
  assert.deepEqual(continuationFindings(verify(continuationBundle())), []);
  const cases: Array<[string, (payloads: Record<string, JsonObject>) => JsonObject[] | undefined, string]> = [
    ["another response", (p) => void (((p["continuation_request"] as JsonObject)["continues"] as JsonObject)["response_id"] = (p["continued_request"] as JsonObject)["message_id"] as string), "names as its challenge an object that is not the challenge response to the continued request"],
    ["another approval", (p) => void (((p["continuation_request"] as JsonObject)["continues"] as JsonObject)["approval_id"] = (p["challenge_response"] as JsonObject)["message_id"] as string), "names as its approval an object that is not an approval of the continued request"],
    ["not an approval", (p) => void (((p["approval"] as JsonObject)["event"] as JsonObject)["operation"] = "reject"), "names as its approval an object that is not an approval of the continued request"],
    ["same attempt", (p) => void (((p["continuation_request"] as JsonObject)["workflow"] as JsonObject)["attempt"] = 1), "does not have a greater attempt than the continued request"],
    ["another workflow", (p) => void (((p["continuation_request"] as JsonObject)["workflow"] as JsonObject)["workflow_id"] = "urn:example:workflow:other"), "is not in the continued request's workflow and root trace"],
    ["another subject", (p) => void (((p["continuation_request"] as JsonObject)["subject"] as JsonObject)["id"] = "urn:example:tenant:other"), "changes the continued request's subject"],
    ["another authority request", (p) => void (((p["continuation_request"] as JsonObject)["authority_request"] as JsonObject)["requested_validity_seconds"] = 30), "changes the continued request's authority_request"],
    [
      "two continuations",
      (p) => {
        const second = structuredClone(p["continuation_request"]) as JsonObject;
        second["message_id"] = "https://externalcontrollayer.ai/ns/message/sha256/" + "e".repeat(64);
        (second["workflow"] as JsonObject)["attempt"] = 3;
        return [second];
      },
      "continues a response that another request continues",
    ],
  ];
  for (const [name, change, message] of cases) {
    assert.ok(continuationFindings(verify(continuationBundle(change))).includes(`${BINDING}: ${message}`), `${name}: ${JSON.stringify(continuationFindings(verify(continuationBundle(change))))}`);
  }
  // A named object that the bundle does not hold is an unresolved predecessor, not a finding here.
  const without = continuationBundle();
  const missing = verify({ ...without, envelopes: (without["envelopes"] as JsonObject[]).filter((_, position) => position !== 2) });
  assert.deepEqual(continuationFindings(missing), []);
  // Two responses to one request are refused as before.
  const twice = continuationBundle((p) => [{ ...(p["challenge_response"] as JsonObject), message_id: "https://externalcontrollayer.ai/ns/message/sha256/" + "d".repeat(64) }]);
  assert.ok(verify(twice).findings.some((finding) => finding.code === BINDING && finding.message === "a request has multiple responses"));
});

test("registries/scope-checks.json: the verifier's checks, items, object sets and required checks are the registry's", () => {
  const registry = json("registries/scope-checks.json");
  assert.deepEqual((registry["checks"] as JsonObject[]).map((check) => check["id"]), [...SCOPE_CHECK_ORDER]);
  const items = registry["items"] as JsonObject[];
  // Every item of the EBMP2-076 table, in table order: the checked items, then the statements.
  assert.deepEqual(items.map((item) => item["item"]), [...SCOPE_CHECKS, ...SCOPE_NEVER]);
  const checked = Object.fromEntries(items.filter((item) => item["established"] === "checked").map((item) => [item["item"] as string, { objectSet: item["object_set"], checks: item["required_checks"] }]));
  assert.deepEqual(checked, { ...SCOPE_ITEM_CHECKS });
  for (const item of items.filter((entry) => entry["established"] === "never")) {
    assert.ok(SCOPE_NEVER.includes(item["item"] as string), item["item"] as string);
  }
  // The items that the corroborated level requires (EBMP2-061).
  const levels = registry["evidence_levels"] as JsonObject[];
  assert.deepEqual(levels.find((level) => level["level"] === "corroborated")?.["requires_items"], [...CORROBORATION_ITEMS]);
  // Each required check is a registered check, in the registry's order.
  for (const [item, required] of Object.entries(SCOPE_ITEM_CHECKS)) {
    const positions = required.checks.map((check) => SCOPE_CHECK_ORDER.indexOf(check));
    assert.ok(positions.every((position, at) => position >= 0 && (at === 0 || position > (positions[at - 1] as number))), item);
  }
});

test("EBMP2-076: the register item applies when the caller supplies a register, and only then", () => {
  const folder = "conformance/suites/evidence-bundle";
  const value = parseStrictJson(bytes(`${folder}/bundle-valid-decision-basis-matches-register.json`));
  const trust = TrustPolicy.load(bytes(`${folder}/trust-policy.json`));
  const register = parseStrictJson(bytes(`${folder}/register.json`));
  const without = verifyBundle(value, trust, { now: "2026-10-01T00:00:00Z" });
  assert.equal(without.verdict, "verified");
  assert.ok(![...without.scope.established, ...without.scope.notEstablished].includes("decision-basis-register"));
  const checked = verifyBundle(value, trust, { now: "2026-10-01T00:00:00Z", register });
  assert.equal(checked.verdict, "verified");
  assert.ok(checked.scope.established.includes("decision-basis-register"));
  assert.deepEqual(checked.scope.checks["decision-basis-register"]?.checks, ["decision-basis-register"]);
});
