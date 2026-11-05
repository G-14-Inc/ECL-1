/**
 * Each claim of a report rests on checks that ran over every object it names, computed here from
 * the bundle itself and from `registries/scope-checks.json`, not from the verifier's own record:
 * an absent object exempts no check (EBMP2-059, EBMP2-078) and keeps out of `established` every
 * item whose object set names it (EBMP2-076); evidence levels follow the scope (EBMP2-061);
 * continuations name their response and approval among their predecessors and rest on an
 * approval in force (EBMP2-078); revocations reach a key re-listed under another identifier
 * (TP1-006); every report states its evaluation time and an incomplete one its unresolved
 * predecessors.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { parseStrictJson, reportToJson, reportedIdentifiers, TrustPolicy, verifyBundle } from "../../src/index.js";
import type { BundleReport, JsonObject, JsonValue } from "../../src/index.js";
import { decodeCanonicalJsonPayload } from "../../src/integrity/envelope.js";
import { REPORT_MEMBER_NAMES } from "../../src/evidence/verify.js";
import { countersign, publicKey, resign, seed, signEnvelope } from "./builders.js";
import type { Signer } from "./builders.js";
import { bytes, json, repoRoot } from "./helpers.js";

const CASES = "packages/ecl-ts/test/fixtures/verifier-cases";
const SUITE_POLICY = "conformance/suites/evidence-bundle/trust-policy.json";
const NOW = "2026-10-01T00:00:00Z";
const DCMP = "application/vnd.ecl.dcmp+json";
const EBMP = "application/vnd.ecl.ebmp+json";
const BINDING = "ecl.error.decision-binding-invalid.v1";
const AGENT: Signer = { keyId: "urn:example:key:bundle-agent", seed: seed(0) };
const EP: Signer = { keyId: "urn:example:key:bundle-ep", seed: seed(2) };
const OBSERVER: Signer = { keyId: "urn:example:key:bundle-observer", seed: seed(3) };
const TIME_AUTHORITY: Signer = { keyId: "urn:example:key:bundle-time-authority", seed: seed(6) };
const COMMAND = fileURLToPath(new URL("../../src/cli/ecl-verify.js", import.meta.url));

function bundle(name: string): JsonObject {
  return parseStrictJson(bytes(`${CASES}/${name}.json`)) as JsonObject;
}

function payloadOf(envelope: JsonValue): JsonObject {
  return decodeCanonicalJsonPayload(envelope) as JsonObject;
}

function objectsOf(value: JsonObject): JsonValue[] {
  return [...(value["envelopes"] as JsonValue[]), ...((value["observations"] as JsonValue[] | undefined) ?? [])];
}

function idOf(payload: JsonObject): string {
  return (payload["message_id"] ?? payload["object_id"]) as string;
}

function verifySuite(value: JsonObject): BundleReport {
  return verifyBundle(value, TrustPolicy.load(bytes(SUITE_POLICY)), { now: NOW });
}

/** The (action, workflow, attempt) of a request, or of an execution event. */
function attemptOf(payload: JsonObject): string {
  const workflow = payload["workflow"] as JsonObject;
  const action = ((payload["action"] ?? payload["event"]) as JsonObject)["action_id"];
  return JSON.stringify([action, workflow["workflow_id"], workflow["attempt"]]);
}

/**
 * The object sets of `registries/scope-checks.json`, computed from the bundle as its definitions
 * read, without the verifier.
 */
function objectSets(value: JsonObject): Record<string, number[]> {
  const payloads = objectsOf(value).map(payloadOf);
  const indexes = payloads.map((_, index) => index);
  const kind = (payload: JsonObject): string => (payload["message_type"] ?? payload["event_type"]) as string;
  const observations = (value["envelopes"] as JsonValue[]).length;
  const inEnvelopes = (index: number): boolean => index < observations;
  const byId = new Map(payloads.map((payload, index) => [idOf(payload), index]));
  const requests = indexes.filter((index) => kind(payloads[index] as JsonObject) === "decision_request");
  const responses = indexes.filter((index) => kind(payloads[index] as JsonObject) === "decision_response");
  const pairs = new Set(indexes.filter((index) => inEnvelopes(index) && ["decision_request", "decision_response", "authority_issued", "authority_consumed", "execution_released", "execution_terminal"].includes(kind(payloads[index] as JsonObject))));
  for (const index of requests) {
    const continues = (payloads[index] as JsonObject)["continues"] as JsonObject | undefined;
    for (const member of ["request_id", "response_id", "approval_id"]) {
      const named = continues === undefined ? undefined : byId.get(continues[member] as string);
      if (named !== undefined) {
        pairs.add(named);
      }
    }
  }
  const released = new Set<number>();
  const discharges = new Set<number>();
  for (const index of indexes.filter((item) => inEnvelopes(item) && kind(payloads[item] as JsonObject) === "execution_released")) {
    const attempt = attemptOf(payloads[index] as JsonObject);
    released.add(index);
    for (const other of indexes.filter((item) => inEnvelopes(item))) {
      const payload = payloads[other] as JsonObject;
      if ((kind(payload) === "decision_request" || kind(payload) === "execution_terminal") && attemptOf(payload) === attempt) {
        released.add(other);
        if (kind(payload) === "decision_request") {
          for (const response of responses) {
            if ((payloads[response] as JsonObject)["request_id"] === payload["message_id"]) {
              released.add(response);
            }
          }
        }
      }
    }
    for (const extension of ((payloads[index] as JsonObject)["extensions"] as JsonObject[] | undefined) ?? []) {
      const entries = extension["id"] === "ecl.ext.obligation-discharge.v1" ? (((extension["value"] as JsonObject)["obligations"] as JsonObject[] | undefined) ?? []) : [];
      if (entries.length > 0) {
        discharges.add(index);
      }
      for (const entry of entries) {
        const proof = entry["proof"] as JsonObject | undefined;
        const named = proof === undefined ? undefined : byId.get(proof["reference"] as string);
        if (named !== undefined) {
          discharges.add(named);
        }
      }
    }
  }
  const sorted = (set: Iterable<number>): number[] => [...set].sort((a, b) => a - b);
  return {
    "bundle-objects": indexes,
    "trust-dependencies": indexes,
    "object-signatures": indexes,
    "decision-responses": responses,
    "request-response-pairs": sorted(pairs),
    "released-attempts": sorted(released),
    "discharge-entries": sorted(discharges),
  };
}

/** Every established item names the registry's required checks over the whole object set. */
function assertBacked(value: JsonObject, report: BundleReport): void {
  const registry = json("registries/scope-checks.json");
  const items = new Map((registry["items"] as JsonObject[]).map((item) => [item["item"] as string, item]));
  const sets = objectSets(value);
  assert.ok(report.scope.established.length > 0);
  for (const item of report.scope.established) {
    const entry = items.get(item) as JsonObject;
    assert.deepEqual(report.scope.checks[item]?.checks, entry["required_checks"], item);
    assert.deepEqual(report.scope.checks[item]?.objects, sets[entry["object_set"] as string], item);
  }
}

test("EBMP2-076: the objects behind each established item are the registry's object sets, as the bundle holds them", () => {
  for (const name of ["valid-observation", "continuation-history", "prerelease-proofs-carried"]) {
    const value = bundle(name);
    const report = name === "valid-observation" ? verifyBundle(value, TrustPolicy.load(bytes(`${CASES}/observation-policy.json`)), { now: "2026-09-29T10:00:02Z" }) : verifySuite(value);
    assert.equal(report.verdict, "verified", `${name}: ${JSON.stringify(report.findings)}`);
    assertBacked(value, report);
  }
  // The discharge entries are the release that carries them and the proofs they name.
  const proofs = verifySuite(bundle("prerelease-proofs-carried"));
  assert.ok(proofs.scope.established.includes("prerelease-obligations-proofs-verified"));
  assert.ok((proofs.scope.checks["prerelease-obligations-proofs-verified"]?.objects.length ?? 0) >= 2);
});

/** The continuation history with `change` applied to its payloads, each signed again with its own key. */
function history(change: (payloads: JsonObject[]) => JsonObject[] | void): JsonObject {
  const value = bundle("continuation-history");
  const envelopes = value["envelopes"] as JsonObject[];
  const payloads = envelopes.map((envelope) => structuredClone(payloadOf(envelope)) as JsonObject);
  const result = change(payloads) ?? payloads;
  const keyOf = new Map(envelopes.map((envelope) => [idOf(payloadOf(envelope)), (envelope["signatures"] as JsonObject[])[0]?.["key_id"] as string]));
  const seeds: Record<string, Signer> = {
    "urn:example:key:bundle-agent": AGENT,
    "urn:example:key:bundle-decision": { keyId: "urn:example:key:bundle-decision", seed: seed(1) },
    "urn:example:key:bundle-ep": EP,
    "urn:example:key:bundle-approval-service": { keyId: "urn:example:key:bundle-approval-service", seed: seed(50) },
  };
  return {
    ...value,
    envelopes: result.map((payload) => signEnvelope(payload, payload["protocol"] === "DCMP-2" ? DCMP : EBMP, [seeds[keyOf.get(idOf(payload)) ?? "urn:example:key:bundle-agent"] as Signer])),
  };
}

function indexOfKind(payloads: JsonObject[], kind: string, nth = 0): number {
  return payloads.map((payload, index) => [payload, index] as const).filter(([payload]) => (payload["message_type"] ?? payload["event_type"]) === kind)[nth]?.[1] as number;
}

test("EBMP2-078: an absent named object exempts no other check, and keeps bindings out of established", () => {
  const valid = verifySuite(bundle("continuation-history"));
  assert.equal(valid.verdict, "verified");
  assert.ok(valid.scope.established.includes("bindings"));
  // The approval left out: the closure is incomplete and bindings, whose set names it, is not established.
  const approvalAbsent = history((payloads) => payloads.filter((payload) => payload["event_type"] !== "human_intervention"));
  const absent = verifySuite(approvalAbsent);
  assert.equal(absent.verdict, "incomplete", JSON.stringify(absent.findings));
  assert.ok(absent.scope.notEstablished.includes("bindings"));
  assert.ok(!absent.scope.established.includes("bindings"));
  // A continuation that changes the continued request's subject, its approval absent: invalid.
  const subject = verifySuite(bundle("continuation-changes-subject-approval-absent"));
  assert.equal(subject.verdict, "invalid");
  assert.equal(reportedIdentifiers(subject)[0], BINDING);
  assert.ok(subject.findings.some((finding) => finding.message.endsWith("the continuation changes the continued request's subject")));
  // A second continuation of one challenge that names an approval the bundle does not hold.
  const second = history((payloads) => {
    const continuation = payloads[indexOfKind(payloads, "decision_request", 1)] as JsonObject;
    const again = structuredClone(continuation) as JsonObject;
    again["message_id"] = "https://externalcontrollayer.ai/ns/message/sha256/" + "e".repeat(64);
    (again["workflow"] as JsonObject)["attempt"] = 3;
    (again["continues"] as JsonObject)["approval_id"] = "https://externalcontrollayer.ai/ns/receipt/sha256/" + "f".repeat(64);
    return [...payloads, again];
  });
  const twice = verifySuite(second);
  assert.equal(twice.verdict, "invalid");
  assert.ok(twice.findings.some((finding) => finding.code === BINDING && finding.message.endsWith("continues a response that another request continues")), JSON.stringify(twice.findings));
});

test("EBMP2-078: the continuation lists its response and approval, and rests on an approval in force by an approval key", () => {
  const findingsOf = (report: BundleReport): string[] => report.findings.filter((finding) => finding.message.includes(": the continuation ")).map((finding) => finding.message.split(": the continuation ")[1] as string);
  assert.deepEqual(findingsOf(verifySuite(bundle("continuation-history"))), []);
  // The approval and the response not listed among the continuation's causal predecessors.
  for (const [member, message] of [
    ["approval_id", "does not list its approval among its causal predecessors with its digest"],
    ["response_id", "does not list its challenge response among its causal predecessors with its digest"],
  ] as const) {
    const report = verifySuite(
      history((payloads) => {
        const continuation = payloads[indexOfKind(payloads, "decision_request", 1)] as JsonObject;
        const named = (continuation["continues"] as JsonObject)[member];
        const workflow = continuation["workflow"] as JsonObject;
        workflow["causal_predecessors"] = (workflow["causal_predecessors"] as JsonObject[]).filter((item) => item["id"] !== named);
      }),
    );
    assert.equal(report.verdict, "invalid");
    assert.ok(findingsOf(report).includes(message), `${member}: ${JSON.stringify(findingsOf(report))}`);
  }
  // The approval signed by a key without the approval purpose (re-signed: its payload is unchanged).
  const value = bundle("continuation-history");
  const envelopes = [...(value["envelopes"] as JsonObject[])];
  const approval = envelopes.findIndex((envelope) => payloadOf(envelope)["event_type"] === "human_intervention");
  envelopes[approval] = resign(envelopes[approval] as JsonObject, [EP]);
  const purpose = verifySuite({ ...value, envelopes });
  assert.equal(purpose.verdict, "invalid");
  assert.ok(findingsOf(purpose).includes("names an approval signed by a key without the approval purpose"));
  // The approval expired before the continuation's response was evaluated.
  const expired = verifySuite(
    history((payloads) => {
      const event = (payloads[indexOfKind(payloads, "human_intervention")] as JsonObject)["event"] as JsonObject;
      event["expires_at"] = "2026-09-29T10:00:00.050000Z";
    }),
  );
  assert.equal(expired.verdict, "invalid");
  assert.ok(findingsOf(expired).includes("rests on an approval that expired before its response was evaluated"), JSON.stringify(findingsOf(expired)));
});

test("EBMP2-061: corroborated only when the report establishes envelope-signatures and causal-completeness", () => {
  const policy = TrustPolicy.load(bytes(`${CASES}/observation-policy.json`));
  const value = bundle("valid-observation");
  assert.equal(verifyBundle(value, policy, { now: "2026-09-29T10:00:02Z" }).effects[0]?.level, "corroborated");
  // An invalid countersignature on the decision request: the terminal and the observation are
  // valid, but the report establishes nothing, so the effect is not corroborated.
  const envelopes = [...(value["envelopes"] as JsonObject[])];
  const request = envelopes[0] as JsonObject;
  envelopes[0] = countersign(request, {
    authority: TIME_AUTHORITY,
    issuer: "urn:example:time-authority:bundle",
    issuedAt: "2026-09-29T10:00:00.900000Z",
    trustPolicy: policy.reference() as unknown as JsonObject,
    attestationId: "urn:example:time-attestation:unregistered",
  });
  const entry = ((envelopes[0] as JsonObject)["countersignatures"] as JsonObject[])[0] as JsonObject;
  entry["claim"] = "ecl.claim.unregistered.v1";
  const report = verifyBundle({ ...value, envelopes }, policy, { now: "2026-09-29T10:00:02Z" });
  assert.equal(report.verdict, "invalid");
  assert.equal(reportedIdentifiers(report)[0], "ecl.error.trusted-time-invalid.v1");
  assert.deepEqual(report.scope.established, []);
  assert.equal(report.envelopeChecks[5]?.historical, "valid");
  assert.equal(report.envelopeChecks[4]?.historical, "valid");
  assert.equal(report.effects[0]?.level, "issuer-asserted");
});

test("trusted-time: every signature of every object covered, under any profile; one uncountersigned object keeps it out", () => {
  const value = bundle("timed-bundle");
  const v1 = TrustPolicy.load(bytes(`${CASES}/timed-policy-v1.json`));
  const envelopes = (value["envelopes"] as JsonObject[]).map((envelope, position) => {
    // Without its countersignatures an envelope is at its first artifact version (member absent).
    const { countersignatures: _dropped, envelope_artifact_version: _version, ...plain } = envelope;
    return position === 0 ? countersign(plain, { authority: TIME_AUTHORITY, issuer: "urn:example:time-authority:bundle", issuedAt: "2026-09-29T10:00:00.900000Z", trustPolicy: v1.reference() as unknown as JsonObject }) : plain;
  });
  const report = verifyBundle({ ...value, envelopes }, TrustPolicy.load(bytes(`${CASES}/timed-policy-v2-valid.json`)), { now: "2026-09-29T10:00:02Z", history: [v1] });
  assert.equal(report.verdict, "verified", JSON.stringify(report.findings));
  assert.equal(report.envelopeChecks[0]?.trustedTime, "2026-09-29T10:00:00.900000Z");
  assert.ok(report.scope.notEstablished.includes("trusted-time"));
  assert.ok(!report.scope.established.includes("trusted-time"));
});

test("TP1-006: a revocation reaches a key re-listed under another identifier", () => {
  const document = parseStrictJson(bytes(`${CASES}/observation-policy.json`)) as JsonObject;
  const renamed = "urn:example:key:bundle-observer-renamed";
  const keys = (document["keys"] as JsonObject[]).map((key) => (key["key_id"] === OBSERVER.keyId ? { ...key, key_id: renamed } : key));
  assert.ok(keys.some((key) => key["key_id"] === renamed && key["public_key"] === publicKey(OBSERVER)));
  const current = TrustPolicy.load(
    new TextEncoder().encode(JSON.stringify({ ...document, version: "2", epoch: (document["epoch"] as number) + 1, keys, revocations: [{ key_id: renamed, effective_at: "2026-09-29T09:00:00Z", reason: "compromised" }] })),
  );
  const history = [TrustPolicy.load(bytes(`${CASES}/observation-policy.json`))];
  for (const accept of [false, true]) {
    const report = verifyBundle(bundle("valid-observation"), current, { now: "2026-09-29T10:00:02Z", history, acceptCurrentTrustFailure: accept });
    assert.equal(report.verdict, "invalid", `accept=${String(accept)}`);
    assert.equal(report.envelopeChecks[5]?.historical, "ecl.error.revoked.v1");
    const observer = report.trustDependencies.find((dependency) => dependency.index === 5);
    assert.equal(observer?.revokedEffectiveAt, "2026-09-29T09:00:00Z");
  }
});

test("every report states its evaluation time; an incomplete one lists its unresolved predecessors", () => {
  const policy = TrustPolicy.load(bytes(`${CASES}/observation-policy.json`));
  const missing = verifyBundle(bundle("missing-observation-predecessor"), policy, { now: "2026-09-29T10:00:02Z" });
  assert.equal(missing.verdict, "incomplete");
  assert.deepEqual(missing.unresolvedPredecessorIds, ["urn:example:absent-record"]);
  const value = reportToJson(missing);
  assert.equal(value[REPORT_MEMBER_NAMES.evaluationTime], "2026-09-29T10:00:02Z");
  assert.deepEqual(value[REPORT_MEMBER_NAMES.unresolvedPredecessorIds], ["urn:example:absent-record"]);
  const invalid = verifyBundle({}, policy, { now: "2026-09-29T10:00:02Z" });
  assert.equal(invalid.verdict, "invalid");
  assert.equal(invalid.evaluationTime, "2026-09-29T10:00:02Z");
  assert.deepEqual(verifyBundle(bundle("valid-observation"), policy, { now: "2026-09-29T10:00:02Z" }).unresolvedPredecessorIds, []);
  // The command's text output prints the evaluation time, the primary of a failing verdict, the
  // checks behind each established item and each trust dependency.
  const folder = mkdtempSync(join(tmpdir(), "ecl-text-"));
  try {
    const path = join(folder, "bundle.json");
    writeFileSync(path, bytes(`${CASES}/missing-observation-predecessor.json`));
    const result = spawnSync(process.execPath, [COMMAND, path, "--trust-policy", join(repoRoot(), CASES, "observation-policy.json"), "--now", "2026-09-29T10:00:02Z"], { encoding: "utf8" });
    assert.equal(result.status, 3, result.stderr);
    assert.match(result.stdout, /^primary: ecl\.error\.causal-closure-incomplete\.v1$/m);
    assert.match(result.stdout, /^evaluation-time: 2026-09-29T10:00:02Z$/m);
    assert.match(result.stdout, /^checks bindings: pairing,continuation-history,response-binding,event-binding,outcome-reasons objects=0,1,2,3,4$/m);
    assert.match(result.stdout, /^dependency 5: role=signer key=urn:example:key:bundle-observer counter=- at=2026-09-29T10:00:00\.500000Z /m);
    assert.match(result.stdout, /^unresolved-predecessor: urn:example:absent-record$/m);
  } finally {
    rmSync(folder, { recursive: true, force: true });
  }
});

const OBSERVATION_POLICY = `${CASES}/observation-policy.json`;
const AT = "2026-09-29T10:00:02Z";

function verifyCase(name: string, policyName: string, options: { now?: string; requireTrustedTime?: boolean; register?: string } = {}): BundleReport {
  return verifyBundle(bundle(name), TrustPolicy.load(bytes(`${CASES}/${policyName}.json`)), {
    now: options.now ?? AT,
    requireTrustedTime: options.requireTrustedTime === true,
    ...(options.register === undefined ? {} : { register: parseStrictJson(bytes(`${CASES}/${options.register}.json`)) }),
  });
}

test("EBMP2-055 and EBMP2-074 run for every attempt whose own objects the bundle holds, whatever the closure", () => {
  // The release names the response and no object names a consumption: invalid.
  const bare = verifyCase("release-without-consumption", "observation-policy");
  assert.equal(bare.verdict, "invalid");
  assert.equal(reportedIdentifiers(bare)[0], BINDING);
  // The same with an unrelated absent predecessor named by the observation: still invalid, as if
  // nothing were absent; the unresolved predecessor is not listed in an invalid report.
  const unrelated = verifyCase("release-without-consumption-absent-predecessor", "observation-policy");
  assert.equal(unrelated.verdict, "invalid", JSON.stringify(unrelated.findings));
  assert.equal(reportedIdentifiers(unrelated)[0], BINDING);
  assert.ok(unrelated.findings.some((finding) => finding.message.includes("lacks consumed authority") || finding.message.includes("single-use authority has no recorded consumption")));
  assert.deepEqual(unrelated.unresolvedPredecessorIds, []);
  // The consumption left out where the release names it as its predecessor: the attempt's own
  // object names the absent object, so the checks are silent and the bundle is incomplete.
  const value = bundle("valid-observation");
  const envelopes = (value["envelopes"] as JsonObject[]).filter((envelope) => payloadOf(envelope)["event_type"] !== "authority_consumed");
  const consumed = payloadOf((value["envelopes"] as JsonObject[]).find((envelope) => payloadOf(envelope)["event_type"] === "authority_consumed") as JsonObject);
  const own = verifyBundle({ ...value, envelopes }, TrustPolicy.load(bytes(OBSERVATION_POLICY)), { now: AT });
  assert.equal(own.verdict, "incomplete", JSON.stringify(own.findings));
  assert.deepEqual(own.findings, []);
  assert.deepEqual(own.unresolvedPredecessorIds, [consumed["object_id"]]);
});

test("TP1-006: a signature that does not verify makes its dependency invalid; envelope-signatures and trusted-time rest on their dependencies", () => {
  // A second signature on the terminal, uncounted (threshold 1), whose bytes do not verify.
  const terminal = verifyCase("terminal-extra-signature-not-verifying", "terminal-extra-signature-policy");
  assert.equal(terminal.verdict, "verified");
  assert.ok(terminal.trustDependencies.some((dependency) => dependency.role === "signer" && dependency.historical === "ecl.error.integrity-invalid.v1"));
  assert.ok(terminal.scope.notEstablished.includes("envelope-signatures"));
  assert.equal(terminal.effects[0]?.level, "issuer-asserted");
  // A second time-authority signature that does not verify on each attestation.
  const attestation = verifyCase("attestation-extra-signature-not-verifying", "attestation-extra-signature-policy", { requireTrustedTime: true });
  assert.equal(attestation.verdict, "verified");
  assert.ok(attestation.trustDependencies.some((dependency) => dependency.role === "time-authority" && dependency.historical === "ecl.error.integrity-invalid.v1"));
  assert.ok(attestation.scope.notEstablished.includes("trusted-time"));
  assert.ok(attestation.scope.established.includes("envelope-signatures"));
});

test("TP1-006: a dependency not evaluated, its envelope's status decided for the whole envelope, has no time", () => {
  const report = verifyBundle(bundle("valid-observation"), TrustPolicy.load(bytes(OBSERVATION_POLICY)), { now: "2026-09-01T00:00:00Z" });
  assert.ok(report.envelopeChecks.every((check) => check.historical === "ecl.error.clock-regressed.v1"));
  assert.ok(report.trustDependencies.length > 0 && report.trustDependencies.every((dependency) => dependency.at === null));
});

test("EBMP2-076: an empty object set holds: the decision-basis items over a bundle with no decision response", () => {
  const withRegister = verifyCase("no-decision-response", "no-decision-response-policy", { register: "no-decision-response-register" });
  assert.equal(withRegister.verdict, "incomplete");
  for (const item of ["decision-basis-recorded", "decision-basis-register"]) {
    assert.ok(withRegister.scope.established.includes(item), item);
    assert.deepEqual(withRegister.scope.checks[item]?.objects, [], item);
  }
  const without = verifyCase("no-decision-response", "no-decision-response-policy");
  assert.ok(without.scope.established.includes("decision-basis-recorded"));
  assert.ok(![...without.scope.established, ...without.scope.notEstablished].includes("decision-basis-register"));
});

test("EBMP2-078: the approval's purpose, actor and expiry are checked when the continuation is admitted", () => {
  // A continuation denied on an expired approval is correct evidence.
  const denied = verifyBundle(bundle("continuation-denied-on-expired-approval"), TrustPolicy.load(bytes(SUITE_POLICY)), { now: NOW });
  assert.equal(denied.verdict, "verified", JSON.stringify(denied.findings));
  // An admitted continuation on an approval signed by a key bound to the request's actor.
  const self = verifyBundle(bundle("continuation-approval-signed-by-actor"), TrustPolicy.load(bytes(`${CASES}/actor-approval-key-policy.json`)), { now: NOW });
  assert.equal(self.verdict, "invalid");
  assert.equal(reportedIdentifiers(self)[0], BINDING);
  assert.ok(self.findings.some((finding) => finding.message.endsWith("names an approval signed by a key of the request's actor")), JSON.stringify(self.findings));
});

test("object-signatures: every envelope countersigned and the observation not keeps trusted-time out", () => {
  const document = parseStrictJson(bytes(OBSERVATION_POLICY)) as JsonObject;
  const v1 = TrustPolicy.load(bytes(OBSERVATION_POLICY));
  const timeKey = { key_id: TIME_AUTHORITY.keyId, suite_id: "ecl.sig.ed25519.v1", public_key: publicKey(TIME_AUTHORITY), principal: "urn:example:time-authority:bundle", purposes: ["ecl.purpose.trusted-time.v1"], valid_from: "2026-01-01T00:00:00Z" };
  const v2 = TrustPolicy.load(new TextEncoder().encode(JSON.stringify({ ...document, version: "2", epoch: (document["epoch"] as number) + 1, keys: [...(document["keys"] as JsonObject[]), timeKey] })));
  const value = bundle("valid-observation");
  const attest = (envelope: JsonObject): JsonObject =>
    countersign(envelope, { authority: TIME_AUTHORITY, issuer: "urn:example:time-authority:bundle", issuedAt: "2026-09-29T10:00:00.900000Z", trustPolicy: v2.reference() as unknown as JsonObject });
  for (const also of [false, true]) {
    const countersigned = {
      ...value,
      envelopes: (value["envelopes"] as JsonObject[]).map(attest),
      observations: (value["observations"] as JsonObject[]).map((envelope) => (also ? attest(envelope) : envelope)),
    };
    const report = verifyBundle(countersigned, v2, { now: AT, history: [v1] });
    assert.equal(report.verdict, "verified", JSON.stringify(report.findings));
    assert.equal(report.scope.established.includes("trusted-time"), also, `observation countersigned: ${String(also)}`);
    if (also) {
      assert.deepEqual(report.scope.checks["trusted-time"]?.objects, [0, 1, 2, 3, 4, 5]);
    }
  }
});

test("bindings: a response binding that fails is a finding, and bindings is not established", () => {
  // The request issued later than its response: the response's binding (DCMP2-044 to DCMP2-051)
  // runs and fails, whatever the verifier records.
  const value = bundle("valid-observation");
  const envelopes = [...(value["envelopes"] as JsonObject[])];
  const request = structuredClone(payloadOf(envelopes[0] as JsonObject)) as JsonObject;
  request["issued_at"] = "2026-09-29T10:00:00.150000Z";
  envelopes[0] = signEnvelope(request, DCMP, [AGENT]);
  const report = verifyBundle({ ...value, envelopes }, TrustPolicy.load(bytes(OBSERVATION_POLICY)), { now: AT });
  assert.equal(report.verdict, "invalid");
  const response = report.bindingChecks.find((check) => check.name === "response:1");
  assert.ok(response !== undefined && !response.passed && response.code !== null, JSON.stringify(report.bindingChecks));
  assert.ok(report.findings.some((finding) => finding.code === response.code && finding.message === "response:1 does not bind"));
  assert.ok(!report.scope.established.includes("bindings"));
});
