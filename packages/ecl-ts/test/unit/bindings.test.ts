import assert from "node:assert/strict";
import { test } from "node:test";
import {
  BINDING_RULES,
  JcsError,
  JoseError,
  PyJsonError,
  acs,
  b64url,
  b64urlDecode,
  bindingFindings,
  decodeJws,
  evaluateBindingRecord,
  jcsCanonicalize,
  jcsDigest,
  jcsNumber,
  mcp,
  oauth,
  otel,
  parsePyJson,
  pyEquals,
  thumbprint,
  toPy,
  verifyDpop,
  verifyJws,
} from "../../src/index.js";
import type { JsonObject, JsonValue, PyObject } from "../../src/index.js";
import { ContentError, ONE_WAY_RULE, decodeContent, decodedRecord, digestOf, messageFindings, modificationBasisProblems, modificationProblems, newRequestProblems } from "../../src/bindings/common.js";
import { pySameJson } from "../../src/bindings/pyjson.js";
import { aarm } from "../../src/index.js";
import { actorSourceProblems } from "../../src/evidence/decision-basis.js";
import { oneWayProblems } from "../../src/semantic/rules.js";
import { rulesApplyingTo } from "../../src/registry/registries.js";
import { verifyEd25519Jose } from "../../src/bindings/jose.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { urlsplit, urlunsplit } from "../../src/schema/formats.js";
import { bytes, hex, json, suite } from "./helpers.js";
import { encodeContent } from "./producer-fixtures.js";

const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

function double(bits: string): number {
  return new DataView(hex(bits).buffer).getFloat64(0, false);
}

test("RFC 8785: the number samples of Appendix B, string escapes and UTF-16 member order", () => {
  const samples: Array<[string, string]> = [
    ["0000000000000000", "0"],
    ["8000000000000000", "0"],
    ["0000000000000001", "5e-324"],
    ["8000000000000001", "-5e-324"],
    ["7fefffffffffffff", "1.7976931348623157e+308"],
    ["ffefffffffffffff", "-1.7976931348623157e+308"],
    ["4340000000000000", "9007199254740992"],
    ["c340000000000000", "-9007199254740992"],
    ["4430000000000000", "295147905179352830000"],
    ["44b52d02c7e14af5", "9.999999999999997e+22"],
    ["44b52d02c7e14af6", "1e+23"],
    ["44b52d02c7e14af7", "1.0000000000000001e+23"],
    ["444b1ae4d6e2ef4e", "999999999999999700000"],
    ["444b1ae4d6e2ef4f", "999999999999999900000"],
    ["444b1ae4d6e2ef50", "1e+21"],
    ["3eb0c6f7a0b5ed8c", "9.999999999999997e-7"],
    ["3eb0c6f7a0b5ed8d", "0.000001"],
    ["41b3de4355555553", "333333333.3333332"],
    ["41b3de4355555554", "333333333.33333325"],
    ["41b3de4355555555", "333333333.3333333"],
    ["41b3de4355555556", "333333333.3333334"],
    ["41b3de4355555557", "333333333.33333343"],
    ["becbf647612f3696", "-0.0000033333333333333333"],
    ["43143ff3c1cb0959", "1424953923781206.2"],
  ];
  for (const [bits, expected] of samples) {
    assert.equal(jcsNumber(double(bits)), expected, bits);
  }
  assert.throws(() => jcsNumber(Number.NaN), JcsError);
  assert.throws(() => jcsNumber(Number.POSITIVE_INFINITY), JcsError);
  // Section 3.2.3: names are ordered by their UTF-16 code units, so U+1F600 (a surrogate pair)
  // comes after U+20AC and before U+FB33, which code-point order would put before it.
  const ordered = {
    "\u20ac": "Euro Sign",
    "\r": "Carriage Return",
    "\ufb33": "Hebrew Letter Dalet With Dagesh",
    "1": "One",
    "\ud83d\ude00": "Emoji: Grinning Face",
    "\u0080": "Control",
    "\u00f6": "Latin Small Letter O With Diaeresis",
  };
  assert.equal(
    text(jcsCanonicalize(ordered)),
    '{"\\r":"Carriage Return","1":"One","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis","\u20ac":"Euro Sign","\ud83d\ude00":"Emoji: Grinning Face","\ufb33":"Hebrew Letter Dalet With Dagesh"}',
  );
  assert.equal(text(jcsCanonicalize(["\u0007\u001f\"\\/", 1.5, -0, 1e21])), '["\\u0007\\u001f\\"\\\\/",1.5,0,1e+21]');
  assert.throws(() => jcsCanonicalize("\ud800"), JcsError);
  let deep: JsonValue = 1;
  for (let level = 0; level < 257; level += 1) {
    deep = [deep];
  }
  assert.throws(() => jcsCanonicalize(deep), JcsError);
  assert.equal(jcsCanonicalize((deep as JsonValue[])[0] as JsonValue).length, 256 * 2 + 1);
});

test("parsePyJson reads JSON as Python's json.loads reads it: doubles, constants, exact integers and repeated names", () => {
  const value = parsePyJson(' {"a": 1, "b": 1.0, "c": 1e2, "d": NaN, "e": -Infinity, "f": 123456789012345678901234567890, "g": "\\ud800x", "h": [true, null]} ') as PyObject;
  assert.equal(value["a"], 1n);
  assert.equal(value["b"], 1);
  assert.equal(value["c"], 100);
  assert.ok(Number.isNaN(value["d"]));
  assert.equal(value["e"], Number.NEGATIVE_INFINITY);
  assert.equal(value["f"], 123456789012345678901234567890n);
  assert.equal(value["g"], "\ud800x");
  assert.deepEqual(value["h"], [true, null]);
  assert.equal(parsePyJson('"\\ud83d\\ude00"'), "😀");
  assert.equal(parsePyJson("1e400"), Number.POSITIVE_INFINITY);
  for (const bad of ['{"a":1,"a":2}', "\ufeff{}", '"\u0001"', "[1,]", "{} x", "01", "1.", "-", "nul", '"\\x"', '"\\u12"', "[1 2]", '{"a" 1}', "{1:2}", ""]) {
    assert.throws(() => parsePyJson(bad), PyJsonError, JSON.stringify(bad));
  }
  let nested = "1";
  for (let level = 0; level < 5000; level += 1) {
    nested = "[" + nested + "]";
  }
  assert.ok(Array.isArray(parsePyJson(nested)));
});

test("Python equality across integers, doubles and booleans", () => {
  assert.ok(pyEquals(1n, 1));
  assert.ok(pyEquals(true, 1n));
  assert.ok(pyEquals(toPy({ a: [1, "x"] }), { a: [1, "x"] }));
  assert.ok(pyEquals({ a: [1.0, "x"] }, toPy({ a: [1, "x"] })));
  assert.ok(!pyEquals(9007199254740993n, 9007199254740992));
  assert.ok(pyEquals(9007199254740992n, 9007199254740992));
  assert.ok(!pyEquals(Number.NaN, Number.NaN));
  assert.ok(!pyEquals("1", 1n));
  assert.ok(!pyEquals(null, false));
  assert.ok(pyEquals(undefined, null));
});

test("base64url is canonical and unpadded", () => {
  assert.equal(b64url(new Uint8Array([0xfb, 0xff])), "-_8");
  assert.deepEqual([...b64urlDecode("-_8")], [0xfb, 0xff]);
  for (const bad of ["-_9", "a", "ab==", "a+b/", "ab c"]) {
    assert.throws(() => b64urlDecode(bad), JoseError, bad);
  }
});

test("RFC 8037: the Ed25519 thumbprint and signature examples of Appendix A", () => {
  const jwk = { crv: "Ed25519", kty: "OKP", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" };
  assert.equal(thumbprint(jwk), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
  const signingInput = new TextEncoder().encode("eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc");
  const signature = b64urlDecode("hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg");
  const key = b64urlDecode(jwk.x);
  assert.equal(verifyEd25519Jose(key, signingInput, signature), true);
  const changed = new Uint8Array(signature);
  changed[0] = (changed[0] as number) ^ 1;
  assert.equal(verifyEd25519Jose(key, signingInput, changed), false);
});

function record(path: string): JsonObject {
  return json(path);
}

function issuerKeys(value: JsonObject): Map<string, PyObject> {
  const keys = new Map<string, PyObject>();
  for (const key of ((value["issuer_keys"] as JsonObject)["keys"] as JsonObject[])) {
    keys.set(key["kid"] as string, toPy(key) as PyObject);
  }
  return keys;
}

test("OAUTH-AUTHORITY-1 tokens: verified under the configured keys, header keys and none refused, and any ES256 s accepted", () => {
  const valid = record("conformance/suites/oauth-authority/oauth-valid-dpop-es256-accepted.json");
  const token = valid["token"] as string;
  const keys = issuerKeys(valid);
  const [header, claims] = verifyJws(token, keys);
  assert.equal(header["alg"], "ES256");
  assert.equal(claims["iss"], "https://as.example.com");
  assert.equal(typeof claims["iat"], "bigint");
  // JOSE does not require the low s of ECL-IE-1: n - s verifies too.
  const parts = token.split(".") as [string, string, string];
  const signature = b64urlDecode(parts[2]);
  const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  let s = 0n;
  for (const byte of signature.subarray(32)) {
    s = (s << 8n) | BigInt(byte);
  }
  let high = order - s;
  const flipped = new Uint8Array(signature);
  for (let index = 63; index >= 32; index -= 1) {
    flipped[index] = Number(high & 0xffn);
    high >>= 8n;
  }
  assert.ok(verifyJws(`${parts[0]}.${parts[1]}.${b64url(flipped)}`, keys));
  assert.throws(() => verifyJws(token, new Map()), (error: unknown) => error instanceof JoseError && error.reason === "kid");
  for (const [name, reason] of [
    ["oauth-invalid-alg-none-accepted", "algorithm"],
    ["oauth-invalid-header-key-accepted", "key-header"],
  ] as const) {
    const value = record(`conformance/suites/oauth-authority/${name}.json`);
    assert.throws(() => verifyJws(value["token"], issuerKeys(value)), (error: unknown) => error instanceof JoseError && error.reason === reason, name);
  }
  const [, proofClaims, key] = verifyDpop((valid["presentation"] as JsonObject)["dpop_proof"]);
  assert.equal(proofClaims["htm"], "POST");
  const confirmation = decodeJws(token).claims["cnf"] as PyObject;
  assert.equal(key, confirmation["jkt"]);
});

test("OA1-007: a JWS segment is strict JSON and alg is a name of the declared set", () => {
  const valid = record("conformance/suites/oauth-authority/oauth-valid-dpop-es256-accepted.json");
  const [first, second, third] = (valid["token"] as string).split(".") as [string, string, string];
  const segment = (text: string): string => b64url(new TextEncoder().encode(text));
  const header = new TextDecoder().decode(b64urlDecode(first));
  for (const claims of ['{"iat":1.5}', '{"iat":1e3}', '{"iat":-0}', '{"iat":9007199254740992}', '{"a":"\\ud800"}', '{"a":1,"a":1}', "\ufeff{}", "[1]", '{"iat":' + "9".repeat(5000) + "}"]) {
    assert.throws(() => decodeJws(`${first}.${segment(claims)}.${third}`), (error: unknown) => error instanceof JoseError && error.reason === "malformed", claims);
  }
  assert.equal(decodeJws(`${first}.${segment('{"a":"\\ud83d\\ude00"}')}.${third}`).claims["a"], "\u{1f600}");
  for (const alg of ['["ES256"]', '{"a":"ES256"}', "1", "null"]) {
    const changed = header.replace('"ES256"', alg);
    assert.throws(() => verifyJws(`${segment(changed)}.${second}.${third}`, issuerKeys(valid)), (error: unknown) => error instanceof JoseError && error.reason === "algorithm", alg);
  }
});

test("OA1-011: a refusal names the code of the first check of the presentation table that fails", () => {
  const valid = record("conformance/suites/oauth-authority/oauth-valid-dpop-es256-accepted.json");
  assert.deepEqual(oauth.refusalProblems(valid), []);
  const later = record("conformance/suites/oauth-authority/oauth-valid-first-cause-refused.json");
  const problems = oauth.refusalProblems(later);
  assert.ok(problems.length > 0);
  assert.equal(((later["result"] as JsonObject)["error"] as string), problems[0]?.[2]);
  assert.deepEqual(oauth.check(later), []);
  const other = structuredClone(later);
  (other["result"] as JsonObject)["error"] = "ecl.error.replay.v1";
  assert.deepEqual(
    oauth.check(other).map((item) => [item.ruleId, item.path]),
    [[oauth.REFUSAL_RULE, "/result/error"]],
  );
});

test("OA1-004 and OA1-001: a DPoP jti of 1 to 256 characters, and the iss, client_id and jti strings of RFC 9068", () => {
  const valid = record("conformance/suites/oauth-authority/oauth-valid-dpop-es256-accepted.json");
  const encode = (value: JsonObject): string => b64url(new TextEncoder().encode(JSON.stringify(value)));
  // The proof re-signed with another jti under the holder's published test key (seed bytes 2 to 33).
  const seed = Uint8Array.from({ length: 32 }, (_, index) => index + 2);
  const [proofHeader, proofClaims] = ((valid["presentation"] as JsonObject)["dpop_proof"] as string).split(".") as [string, string, string];
  const header = JSON.parse(text(b64urlDecode(proofHeader))) as JsonObject;
  const claims = JSON.parse(text(b64urlDecode(proofClaims))) as JsonObject;
  const withJti = (jti: string): JsonObject => {
    const signingInput = `${encode(header)}.${encode({ ...claims, jti })}`;
    const signature = ed25519.sign(new TextEncoder().encode(signingInput), seed);
    const changed = structuredClone(valid);
    (changed["presentation"] as JsonObject)["dpop_proof"] = `${signingInput}.${b64url(signature)}`;
    return changed;
  };
  const refused = [["/presentation/dpop_proof", "the proof carries no jti string of 1 to 256 characters", oauth.INTEGRITY_INVALID]];
  for (const jti of ["", "j".repeat(257), "\u{1f600}".repeat(257)]) {
    const value = withJti(jti);
    assert.deepEqual(oauth.presentationChecks(value), refused, String([...jti].length));
    const asReplay = structuredClone(value);
    asReplay["result"] = { accepted: false, error: oauth.REPLAY };
    assert.deepEqual(oauth.check(asReplay).map((item) => [item.ruleId, item.path]), [[oauth.REFUSAL_RULE, "/result/error"]]);
  }
  for (const jti of ["j", "j".repeat(256), "\u{1f600}".repeat(256)]) {
    const value = withJti(jti);
    assert.deepEqual(oauth.presentationChecks(value), [], String([...jti].length));
    (value["presentation"] as JsonObject)["seen_dpop_jti"] = [jti];
    assert.deepEqual(oauth.presentationChecks(value).map((item) => item[2]), [oauth.REPLAY]);
  }
  // RFC 9068, Section 2.2: the issuer's side reports a token without iss, client_id or jti as a
  // string. The issuer's checks do not verify the signature, so the token keeps its own.
  const [tokenHeader, tokenClaims, tokenSignature] = (valid["token"] as string).split(".") as [string, string, string];
  const issued = JSON.parse(text(b64urlDecode(tokenClaims))) as JsonObject;
  const request = valid["request"] as JsonObject;
  const response = valid["response"] as JsonObject;
  assert.deepEqual(oauth.issueProblems(request, response, valid["token"] as string, 300), []);
  for (const name of ["client_id", "iss", "jti"]) {
    for (const replacement of [undefined, null, 7]) {
      const changed: JsonObject = { ...issued };
      if (replacement === undefined) {
        delete changed[name];
      } else {
        changed[name] = replacement;
      }
      const token = `${tokenHeader}.${encode(changed)}.${tokenSignature}`;
      assert.deepEqual(oauth.issueProblems(request, response, token, 300), [[`/token/${name}`, `the token carries no ${name} string, which RFC 9068 requires`]], `${name} ${String(replacement)}`);
    }
  }
  const withoutJti = record("conformance/suites/oauth-authority/oauth-invalid-token-without-jti.json");
  assert.deepEqual(oauth.check(withoutJti).map((item) => [item.ruleId, item.path]), [[oauth.ISSUE_RULE, "/token/jti"]]);
});

test("the htu of a presented URI is Python's urlunsplit without query and fragment", () => {
  const cases: Array<[string, string]> = [
    ["https://rs.example.com/payments/transfers?x=1#y", "https://rs.example.com/payments/transfers"],
    ["HTTPS://RS.example.com", "https://RS.example.com"],
    ["urn:example:a?b", "urn:example:a"],
    ["https:/path", "https:///path"],
    ["file:relative", "file:relative"],
  ];
  for (const [uri, expected] of cases) {
    const parts = urlsplit(uri);
    assert.ok(parts !== undefined, uri);
    assert.equal(urlunsplit(parts.scheme, parts.netloc, parts.path, "", ""), expected, uri);
  }
});

test("ACS-BINDING-1: the effective parameters of a modify, and the session chain", () => {
  const argumentsValue = { amount: 10, memo: { text: "secret", tag: "t" }, to: "acct-1" };
  assert.deepEqual(acs.effectiveParameters(argumentsValue, { parameter_overrides: { amount: 5 } }), { amount: 5, memo: { text: "secret", tag: "t" }, to: "acct-1" });
  assert.deepEqual(acs.effectiveParameters(argumentsValue, { redactions: [{ path: "/memo/text" }] }), { amount: 10, memo: { text: "[REDACTED]", tag: "t" }, to: "acct-1" });
  assert.deepEqual(acs.effectiveParameters(argumentsValue, { modified_content: '{"to":"acct-2"}' }), { to: "acct-2" });
  for (const forbidden of [
    { modified_content: "{}", redactions: [] },
    { modified_content: "[1]" },
    { modified_content: '{"a":1.5}' },
    { redactions: [{ path: "/memo/text" }], parameter_overrides: { memo: {} } },
    { redactions: [{ path: "/missing" }] },
    { redactions: [{ path: "memo" }] },
    { redactions: [], parameter_overrides: {} },
    { redactions: null },
    "not an object",
  ] as JsonValue[]) {
    assert.equal(acs.effectiveParameters(argumentsValue, forbidden), null, JSON.stringify(forbidden));
  }
  const valid = record("conformance/suites/acs-binding/acs-valid-allow-released.json");
  const chain = valid["chain"] as JsonObject[];
  assert.ok(chain.length > 0);
  for (const entry of chain) {
    assert.equal(acs.entryHash(entry), entry["entry_hash"]);
  }
  assert.deepEqual(acs.chainProblems(chain), []);
  const rewritten = record("conformance/suites/acs-binding/acs-invalid-chain-rewritten.json");
  assert.ok(acs.chainProblems(rewritten["chain"] as JsonObject[]).length > 0);
});

test("MCP-GATEWAY-1: the terminal state of each server response, and the error of each refusal", () => {
  assert.equal(mcp.terminalState(null), "unknown");
  assert.equal(mcp.terminalState({ jsonrpc: "2.0", id: 1, error: { code: -1, message: "x" } }), "failed");
  assert.equal(mcp.terminalState({ jsonrpc: "2.0", id: 1, result: { isError: true } }), "failed");
  assert.equal(mcp.terminalState({ jsonrpc: "2.0", id: 1, result: {} }), "succeeded");
  assert.equal(mcp.terminalState({ jsonrpc: "2.0", id: 1, result: { resultType: "input_required" } }), "unknown");
  assert.equal(mcp.terminalState({ jsonrpc: "2.0", id: 1, result: { resultType: null } }), "unknown");
  for (const [name, cause] of [
    ["mcp-valid-denied-refused", "denied"],
    ["mcp-valid-held-refused", "held"],
    ["mcp-valid-challenged-refused", "challenged"],
    ["mcp-valid-decision-unavailable-refused", "decision-unavailable"],
    ["mcp-valid-decision-invalid-refused", "decision-invalid"],
    ["mcp-valid-authorization-expired-refused", "authorization-unusable"],
    ["mcp-valid-unmapped-tool-refused", "not-mapped"],
    ["mcp-valid-changed-tool-refused", "unreviewed-change"],
  ] as const) {
    const value = record(`conformance/suites/mcp-gateway/${name}.json`);
    assert.equal(mcp.refusalCause(value)?.[0], cause, name);
    const returned = value["returned"] as JsonObject;
    assert.equal((returned["error"] as JsonObject)["code"], mcp.ERRORS.get(cause), name);
  }
});

test("MG1-010 and MG1-012: a server error with a table code is recoded, and content outside the profile is encoded", () => {
  assert.deepEqual(mcp.returnedFor({ jsonrpc: "2.0", id: 7, error: { code: -31004, message: "busy", data: 1 } }), {
    jsonrpc: "2.0",
    id: 7,
    error: { code: mcp.SERVER_ERROR_CODE, message: "busy", data: 1 },
  });
  const other = { jsonrpc: "2.0", id: 7, error: { code: -32000, message: "busy" } };
  assert.deepEqual(mcp.returnedFor(other), other);
  const content = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "t", arguments: { weight: 0.5, big: 9007199254740992 } } };
  const held = encodeContent(content) as JsonObject;
  assert.deepEqual(Object.keys(held), ["rfc8785"]);
  assert.deepEqual(decodeContent(held), content);
  const plain = { a: 1 };
  assert.equal(encodeContent(plain), plain);
  assert.equal(decodeContent(plain), plain);
  for (const bad of ["not base64", "e30", "e31=", "WyJ4Il0=", "eyJhIjoxfQ==", "eyJhIjogMC41fQ==", "eyJhIjowLjUsImEiOjAuNX0="]) {
    assert.throws(() => decodeContent({ rfc8785: bad }), ContentError, bad);
  }
  assert.throws(() => decodeContent({ rfc8785: 1 }), ContentError);
  const forwarded = record("conformance/suites/mcp-gateway/mcp-valid-forwarded-on-admit.json");
  const odd = { jsonrpc: "2.0", id: 1, method: ["tools/call", 0.5], params: { x: 0.5 } };
  const changed = structuredClone(forwarded);
  changed["call"] = encodeContent(odd);
  (changed["forwarded"] as JsonObject)["request"] = encodeContent(odd);
  // The record schema refuses a method that is not a string in either form (MG1-012);
  // refusalCause reads the decoded record without that check and does not throw.
  assert.deepEqual(rulesAndPaths(mcp.check(changed)), ["ecl.error.schema-invalid.v1 /call", "ecl.error.schema-invalid.v1 /forwarded/request"]);
  delete changed["forwarded"];
  assert.deepEqual(mcp.refusalCause(changed), ["not-mapped", "ecl.error.binding-unsupported.v1", null]);
});

test("OE1-005, OE1-003 and OE1-008: declared identifiers, observed time and severity text", () => {
  const value = record("conformance/suites/otel-export/otel-valid-request-exported.json");
  const object = value["object"] as JsonObject;
  for (const name of otel.DECLARED_ONLY) {
    assert.equal(otel.logAttributes(object).has(name), false, name);
  }
  const declared = otel.logAttributes(object, null, null, otel.DECLARED_ONLY);
  assert.equal(declared.get("ecl.actor.id"), ((object["actor"] as JsonObject)["id"] as string));
  const deny = record("conformance/suites/otel-export/otel-valid-deny-response-exported.json");
  assert.deepEqual(otel.check(deny), []);
  const text = structuredClone(deny);
  (text["log_record"] as JsonObject)["severityText"] = "WARNING";
  assert.deepEqual(otel.check(text).map((item) => item.ruleId), [otel.SEVERITY_RULE]);
  const early = structuredClone(deny);
  (early["log_record"] as JsonObject)["observedTimeUnixNano"] = "0";
  assert.deepEqual(otel.check(early).map((item) => item.ruleId), [otel.MATCH_RULE]);
  const long = structuredClone(deny);
  (long["log_record"] as JsonObject)["observedTimeUnixNano"] = "9".repeat(5000);
  assert.deepEqual(otel.check(long).map((item) => item.ruleId), [otel.MATCH_RULE]);
});

test("OTEL-EVIDENCE-EXPORT-1: attributes and severity of an exported object", () => {
  const value = record("conformance/suites/otel-export/otel-valid-deny-response-exported.json");
  const object = value["object"] as JsonObject;
  assert.equal(otel.severity(object), otel.WARN);
  const attributes = otel.logAttributes(object);
  assert.equal(attributes.get("ecl.decision.outcome"), "deny");
  assert.equal(attributes.get("ecl.export.profile"), otel.PROFILE);
  for (const name of attributes.keys()) {
    assert.ok(otel.TABLE.has(name), name);
  }
  assert.equal(otel.eventName(object), "ecl.dcmp.decision_response");
});

test("every binding vector: the record schema first, then the profile's rules", () => {
  const rules = new Set(BINDING_RULES);
  const dcmpRules = rulesApplyingTo("DCMP-2");
  assert.equal(rules.size, 30);
  let checked = 0;
  for (const name of ["aarm-binding", "acs-binding", "binding-basis", "mcp-gateway", "otel-export", "oauth-authority"]) {
    const keysPath = json(`conformance/suites/${name}/manifest.json`)["export_keys_path"];
    const keys = typeof keysPath === "string" ? otel.loadExportKeys(bytes(keysPath)) : new Map<string, otel.ExportKey>();
    for (const vector of suite(name).filter((item) => item.stage === "binding")) {
      checked += 1;
      const value = json(vector.path);
      const found = [...new Set(evaluateBindingRecord(vector.schema as string, value, undefined, keys).map((item) => item.ruleId))].sort();
      if (vector.expected === "pass") {
        assert.deepEqual(found, [], vector.id);
      } else {
        assert.deepEqual(found, [vector.expected_primary_id as string, ...vector.expected_secondary_ids].sort(), vector.id);
        if (vector.expected_primary_id !== "ecl.error.schema-invalid.v1") {
          // A record's embedded decision response is held to DCMP2-053 under the response's own
          // rule, and each DCMP-2 message it holds to the semantic rules of DCMP-2, none of which
          // is one of the profiles' (AB1-013, AC1-012, MG1-007).
          assert.ok(found.every((rule) => rules.has(rule) || rule === ONE_WAY_RULE || dcmpRules.has(rule)), vector.id);
        }
      }
    }
  }
  assert.ok(checked >= 130, String(checked));
  assert.deepEqual(
    bindingFindings({ schema_version: "something else" }).map((item) => item.ruleId),
    ["ecl.error.schema-invalid.v1"],
  );
});

test("OE1-004 and OE1-010: no digest without an export key, keyed digests with one", () => {
  const object = json("conformance/suites/otel-export/otel-valid-deny-response-exported.json")["object"] as JsonObject;
  const plain = otel.logAttributes(object);
  for (const name of otel.KEYED) {
    assert.equal(plain.has(name), false, name);
  }
  const key = otel.exportKey("urn:example:export-key:test", new Uint8Array(32).fill(107));
  const keyed = otel.logAttributes(object, null, key);
  assert.equal(keyed.get(otel.KEY_ID), key.keyId);
  assert.equal(keyed.get(otel.OBJECT_DIGEST), otel.keyedDigest(key, object));
  assert.notEqual(keyed.get(otel.OBJECT_DIGEST), otel.unkeyedDigests(object).get(otel.OBJECT_DIGEST));
  for (const name of keyed.keys()) {
    assert.ok(otel.TABLE.has(name), name);
  }
  const valid = (key: string): string => `{"schema_version":"ecl_otel_export_keys_v1","keys":[{"key_id":"urn:k","key":"${key}"}]}`;
  assert.equal(otel.loadExportKeys(valid("A".repeat(43) + "=")).get("urn:k")?.key.length, 32);
  for (const document of [
    '{"schema_version":"ecl_otel_export_keys_v1","keys":[]}',
    valid("A".repeat(42) + "=="),
    valid("A".repeat(42) + "B="),
    valid("A".repeat(43) + "=").replace('"urn:k"', '""'),
    valid("A".repeat(43) + "=").replace('"urn:k"', "1"),
    valid("A".repeat(43) + "=").replace("]}", "],\"x\":1}"),
    '{"schema_version":"ecl_otel_export_keys_v1","keys":[{"key_id":"urn:k","key":"' + "A".repeat(43) + '="},{"key_id":"urn:k","key":"' + "A".repeat(43) + '="}]}',
    "[]",
  ]) {
    assert.throws(() => otel.loadExportKeys(document), otel.ExportKeyError, document);
  }
});

function vectorValue(name: string, identifier: string): JsonObject {
  const found = suite(name).find((item) => item.id === identifier);
  assert.ok(found !== undefined, identifier);
  return json(found.path);
}

function copied(value: JsonObject): JsonObject {
  return JSON.parse(JSON.stringify(value)) as JsonObject;
}

function rulesAndPaths(found: ReadonlyArray<{ ruleId: string; path: string }>): string[] {
  return [...new Set(found.map((item) => `${item.ruleId} ${item.path}`))].sort();
}

test("AC1-004: a deterministic Guardian decision that a hook point carried is never verifiable", () => {
  assert.equal(acs.guardianClass("deterministic", [], "hook"), "actor_supplied");
  assert.equal(acs.guardianClass("deterministic", ["verifiable"], "hook"), "actor_supplied");
  assert.equal(acs.guardianClass("deterministic", [], null), "actor_supplied");
  assert.equal(acs.guardianClass("deterministic", [], "direct"), "verifiable");
  assert.equal(acs.guardianClass("deterministic", ["verifiable"], "signed"), "verifiable");
  assert.equal(acs.guardianClass("deterministic", ["judgment"], "signed"), "judgment");
  for (const channel of acs.CHANNELS) {
    assert.equal(acs.guardianClass(null, [], channel), "judgment");
    assert.equal(acs.guardianClass("composite", [], channel), "judgment");
  }
  const valid = vectorValue("acs-binding", "acs-valid-allow-released");
  assert.deepEqual(acs.check(valid), []);
  const signed = copied(valid);
  (signed["guardian"] as JsonObject)["channel"] = "signed";
  assert.deepEqual(acs.check(signed), []);
  const hooked = copied(valid);
  (hooked["guardian"] as JsonObject)["channel"] = "hook";
  assert.deepEqual(rulesAndPaths(acs.check(hooked)), [`${acs.JUDGMENT_RULE} /inputs/1/class`]);
});

test("AC1-012: a DCMP-2 rule that a held message fails is reported once, at the message's place", () => {
  const value = vectorValue("acs-binding", "acs-invalid-request-negative-debit");
  assert.deepEqual(rulesAndPaths(acs.check(value)), ["ecl.rule.budget-debit-non-negative.v1 /request"]);
  const twice = copied(value);
  const extensions = (twice["response"] as JsonObject)["extensions"] as JsonObject[];
  extensions.push(copied(extensions[0] as JsonObject), copied(extensions[0] as JsonObject));
  const found = messageFindings(twice, ["response"]).filter((item) => item.ruleId === "ecl.rule.extension-identifiers-unique.v1");
  assert.deepEqual(found.map((item) => item.path), ["/response"]);
});

test("AC1-004: a response that records the Guardian decision marks exactly one input", () => {
  const valid = vectorValue("acs-binding", "acs-valid-allow-released");
  const unmarked = copied(valid);
  delete ((unmarked["inputs"] as JsonObject[])[1] as JsonObject)["guardian"];
  assert.deepEqual(rulesAndPaths(acs.check(unmarked)), [`${acs.JUDGMENT_RULE} /inputs`]);
  const twice = copied(valid);
  ((twice["inputs"] as JsonObject[])[0] as JsonObject)["guardian"] = true;
  assert.ok(rulesAndPaths(acs.check(twice)).includes(`${acs.JUDGMENT_RULE} /inputs/1/guardian`));
});

test("AB1-006: the judgment-source role lists the AARM decision exactly once, as an R4 input", () => {
  const valid = vectorValue("aarm-binding", "aarm-valid-judgment-source-admit");
  assert.deepEqual(aarm.check(valid), []);
  const unlabelled = vectorValue("aarm-binding", "aarm-invalid-judgment-source-decision-unlabelled");
  assert.deepEqual(rulesAndPaths(aarm.check(unlabelled)), [`${aarm.JUDGMENT_RULE} /inputs`]);
  const decisionLayer = copied(unlabelled);
  decisionLayer["role"] = "decision-layer";
  assert.deepEqual(aarm.check(decisionLayer), []);
});

test("MG1-004 and MG1-005: the decision request binds the complete params, and the forward is exactly the call", () => {
  const valid = vectorValue("mcp-gateway", "mcp-valid-forwarded-on-admit");
  assert.deepEqual(mcp.check(valid), []);
  const task = copied(valid);
  (((task["forwarded"] as JsonObject)["request"] as JsonObject)["params"] as JsonObject)["task"] = { ttl: 86400000 };
  assert.deepEqual(rulesAndPaths(mcp.check(task)), [`${mcp.FORWARD_RULE} /forwarded/request/params`]);
  const added = copied(valid);
  ((added["forwarded"] as JsonObject)["request"] as JsonObject)["trace"] = "gateway-1";
  assert.deepEqual(rulesAndPaths(mcp.check(added)), [`${mcp.FORWARD_RULE} /forwarded/request`]);
  const unbound = copied(valid);
  for (const holder of [unbound["call"] as JsonObject, (unbound["forwarded"] as JsonObject)["request"] as JsonObject]) {
    ((holder["params"] as JsonObject)["_meta"] as JsonObject)["io.example/effect-mode"] = "live-production";
  }
  assert.deepEqual(rulesAndPaths(mcp.check(unbound)), [
    `${mcp.FORWARD_RULE} /forwarded/request/params`,
    `${mcp.REQUEST_RULE} /decision_request/extensions`,
  ].sort());
});

test("AB1-013, AC1-012 and MG1-007: an embedded response is held to DCMP2-053 at the response's own paths", () => {
  const cases: Array<[string, string, (value: JsonObject) => Array<{ ruleId: string; path: string }>]> = [
    ["binding-basis", "aarm-basis-invalid-admit-required-input-unavailable", aarm.check],
    ["binding-basis", "aarm-basis-invalid-verifiable-derived-from-judgment", aarm.check],
    ["binding-basis", "aarm-basis-invalid-modification-admitted-on-judgment", aarm.check],
    ["binding-basis", "acs-basis-invalid-admit-required-input-unavailable", acs.check],
    ["mcp-gateway", "mcp-invalid-admit-on-judgment-forwarded", mcp.check],
    ["binding-basis", "aarm-basis-invalid-admit-after-verifiable-only-deny", aarm.check],
    ["binding-basis", "aarm-basis-invalid-input-obtained-after-decision", aarm.check],
    ["binding-basis", "acs-basis-invalid-received-after-decision", acs.check],
  ];
  for (const [name, identifier, check] of cases) {
    const value = vectorValue(name, identifier);
    const found = check(value);
    assert.deepEqual([...new Set(found.map((item) => item.ruleId))], [ONE_WAY_RULE], identifier);
    const expected: string[] = [];
    for (const path of [["response"], ["modification_response"], ["decision", "response"]]) {
      let response: JsonValue | undefined = value;
      for (const step of path) {
        response = response !== null && typeof response === "object" && !Array.isArray(response) ? (response as JsonObject)[step] : undefined;
      }
      if (response === undefined || response === null || typeof response !== "object" || Array.isArray(response)) {
        continue;
      }
      const object = response as JsonObject;
      ((object["extensions"] as JsonObject[] | undefined) ?? []).forEach((entry, index) => {
        if (entry["id"] === "ecl.ext.decision-basis.v1") {
          for (const [where] of oneWayProblems(entry["value"] as JsonObject, object["outcome"] === "admit", object["outcome"], object["evaluated_at"])) {
            expected.push(`/${path.join("/")}/extensions/${index}/value${where}`);
          }
        }
      });
    }
    assert.ok(expected.length > 0, identifier);
    assert.deepEqual([...new Set(found.map((item) => item.path))].sort(), [...new Set(expected)].sort(), identifier);
  }
});

test("AC1-012 and MG1-007: an input from the requesting actor recorded verifiable is refused with the record's request", () => {
  const cases: Array<[string, string, (value: JsonObject) => Array<{ ruleId: string; path: string }>, string, string[]]> = [
    ["binding-basis", "acs-basis-invalid-verifiable-input-from-actor", acs.check, "request", ["response"]],
    ["mcp-gateway", "mcp-invalid-verifiable-input-from-actor", mcp.check, "decision_request", ["decision", "response"]],
  ];
  for (const [name, identifier, check, requestName, responsePath] of cases) {
    const value = vectorValue(name, identifier);
    const found = check(value);
    assert.deepEqual([...new Set(found.map((item) => item.ruleId))], [ONE_WAY_RULE], identifier);
    let response: JsonValue | undefined = value;
    for (const step of responsePath) {
      response = (response as JsonObject)[step];
    }
    const object = response as JsonObject;
    const expected: string[] = [];
    ((object["extensions"] as JsonObject[] | undefined) ?? []).forEach((entry, index) => {
      if (entry["id"] === "ecl.ext.decision-basis.v1") {
        const basis = entry["value"] as JsonObject;
        assert.deepEqual(oneWayProblems(basis, object["outcome"] === "admit", object["outcome"], object["evaluated_at"]), [], identifier);
        for (const [where] of actorSourceProblems(basis, value[requestName] as JsonObject)) {
          expected.push(`/${responsePath.join("/")}/extensions/${index}/value${where}`);
        }
      }
    });
    assert.ok(expected.length > 0, identifier);
    assert.deepEqual([...new Set(found.map((item) => item.path))].sort(), [...new Set(expected)].sort(), identifier);
  }
});

function basisOf(response: JsonObject): JsonObject {
  const entry = (response["extensions"] as JsonObject[]).find((item) => item["id"] === "ecl.ext.decision-basis.v1");
  assert.ok(entry !== undefined);
  return entry["value"] as JsonObject;
}

test("AB1-013 and AC1-012: the modification response records the record's inputs with their declarations", () => {
  const valid = vectorValue("acs-binding", "acs-valid-modify-new-request");
  assert.deepEqual(modificationBasisProblems(valid), []);
  assert.deepEqual(acs.check(valid), []);
  const prefix = "/modification_response/extensions/0/value";
  const change = (edit: (inputs: JsonObject[], basis: JsonObject) => void): string[] => {
    const value = copied(valid);
    const basis = basisOf(value["modification_response"] as JsonObject);
    edit(basis["inputs"] as JsonObject[], basis);
    return modificationBasisProblems(value).map(([path]) => path);
  };
  // The new decision's status, effect and reference are its own; names and sources compare as
  // input names are.
  assert.deepEqual(change((inputs) => {
    (inputs[0] as JsonObject)["effect"] = "none";
    (inputs[1] as JsonObject)["effect"] = "supports";
    (inputs[0] as JsonObject)["input"] = "URN:example:input:records-policy";
    (inputs[1] as JsonObject)["source"] = "URN:Example:source:acs-guardian-decision";
  }), []);
  assert.deepEqual(change((inputs) => { (inputs[1] as JsonObject)["class"] = "judgment"; }), [`${prefix}/inputs/1/class`]);
  assert.deepEqual(change((inputs) => { (inputs[0] as JsonObject)["required"] = false; }), [`${prefix}/inputs/0/required`]);
  assert.deepEqual(change((inputs) => { (inputs[0] as JsonObject)["source"] = "urn:example:source:elsewhere"; }), [`${prefix}/inputs/0/source`]);
  assert.deepEqual(change((inputs) => { (inputs[1] as JsonObject)["derived_from"] = ["urn:example:input:records-policy"]; }), [`${prefix}/inputs/1/derived_from`]);
  assert.deepEqual(change((inputs) => { delete (inputs[1] as JsonObject)["derived_from"]; }), []);
  assert.deepEqual(change((inputs) => { inputs.pop(); }), [`${prefix}/inputs`]);
  assert.deepEqual(change((_, basis) => { (basis["register"] as JsonObject)["version"] = "2026-10-01"; }), [`${prefix}/register`]);
  // AB1-013 and AC1-012: the register reference is carried member for
  // member, so the same register without its optional version, or with a member added, differs.
  assert.deepEqual(change((_, basis) => { delete (basis["register"] as JsonObject)["version"]; }), [`${prefix}/register`]);
  assert.deepEqual(change((_, basis) => { (basis["register"] as JsonObject)["media_type"] = "application/json"; }), [`${prefix}/register`]);
  for (const [name, identifier] of [
    ["acs-binding", "acs-invalid-modification-upgrades-session-context"],
    ["acs-binding", "acs-invalid-modification-drops-required-input"],
    ["acs-binding", "acs-invalid-modification-records-other-inputs"],
    ["aarm-binding", "aarm-invalid-modification-drops-required-input"],
  ] as const) {
    const value = vectorValue(name, identifier);
    const check = name === "acs-binding" ? acs.check : aarm.check;
    const rule = name === "acs-binding" ? acs.BASIS_RULE : aarm.BASIS_RULE;
    assert.deepEqual([...new Set(check(value).map((item) => item.ruleId))], [rule], identifier);
  }
});

test("AB1-004 and AC1-005: the new request of a modification describes the original's action", () => {
  const valid = vectorValue("acs-binding", "acs-valid-modify-new-request");
  const original = valid["request"] as JsonObject;
  const modified = valid["modification_request"] as JsonObject;
  const parameters = (modified["action"] as JsonObject)["parameters"] as JsonObject;
  assert.deepEqual(modificationProblems(original, modified, parameters), []);
  const cases: Array<[string, string, JsonValue, string]> = [
    ["action", "operation", "records.delete", "modification_request/action/operation"],
    ["action", "action_class", "ecl.action.financial-transfer.v1", "modification_request/action/action_class"],
    ["action", "risk_class", "ecl.risk.low.v1", "modification_request/action/risk_class"],
    ["actor", "id", "urn:example:agent:other", "modification_request/actor"],
    ["subject", "id", "urn:example:tenant:other", "modification_request/subject"],
    ["authority_request", "requested_validity_seconds", 3600, "modification_request/authority_request"],
    ["integrity_policy", "threshold", 2, "modification_request/integrity_policy"],
  ];
  for (const [memberName, name, replacement, path] of cases) {
    const changed = copied(modified);
    (changed[memberName] as JsonObject)[name] = replacement;
    assert.deepEqual(modificationProblems(original, changed, parameters).map(([where]) => where), [path], `${memberName} ${name}`);
  }
  const own = copied(modified);
  own["issued_at"] = "2026-09-30T09:00:00.160000Z";
  own["extensions"] = [];
  (own["workflow"] as JsonObject)["sequence"] = 9;
  assert.deepEqual(modificationProblems(original, own, parameters), []);
  for (const [name, identifier] of [
    ["acs-binding", "acs-invalid-modify-other-action-class"],
    ["acs-binding", "acs-invalid-modify-other-target"],
    ["aarm-binding", "aarm-invalid-modify-other-operation"],
    ["aarm-binding", "aarm-invalid-modify-other-actor"],
  ] as const) {
    const value = vectorValue(name, identifier);
    const check = name === "acs-binding" ? acs.check : aarm.check;
    const rule = name === "acs-binding" ? acs.MODIFICATION_RULE : aarm.MODIFICATION_RULE;
    assert.deepEqual([...new Set(check(value).map((item) => item.ruleId))], [rule], identifier);
  }
});

test("AC1-004: a Guardian decision's derived_from names are compared as input names are", () => {
  const value = vectorValue("acs-binding", "acs-valid-guardian-derived-from-case-variant");
  assert.deepEqual(acs.check(value), []);
  const unknown = copied(value);
  for (const holder of [(unknown["inputs"] as JsonObject[])[1] as JsonObject, (basisOf(unknown["response"] as JsonObject)["inputs"] as JsonObject[])[1] as JsonObject]) {
    holder["derived_from"] = ["URN:example:input:records-polic"];
  }
  assert.ok(rulesAndPaths(acs.check(unknown)).includes(`${acs.JUDGMENT_RULE} /inputs/1/derived_from/0`));
});

test("MG1-007: a response that the gateway refused and keeps as evidence is not held to DCMP-2", () => {
  const held = vectorValue("mcp-gateway", "mcp-valid-decision-invalid-holds-refused-response");
  assert.deepEqual(mcp.check(held), []);
  const answered = vectorValue("mcp-gateway", "mcp-valid-forwarded-on-admit");
  const response = answered["decision"] as JsonObject;
  const extensions = (response["response"] as JsonObject)["extensions"] as JsonObject[];
  extensions.push({ id: "ecl.ext.outcome-reason.v1", version: 1, critical: false, value: { unexpected: true } });
  extensions.sort((left, right) => String(left["id"]).localeCompare(String(right["id"])));
  assert.ok(mcp.check(answered).some((item) => item.ruleId === "ecl.rule.extension-value-valid.v1"));
});

test("AB1-004 and AC1-005: only a modification has a new request", () => {
  const members: Array<readonly string[]> = [["modification_request", "modification_response"], ["modification_request"], ["modification_response"]];
  for (const [name, check, rule, modify, others] of [
    ["acs-binding", acs.check, acs.MODIFICATION_RULE, "acs-valid-modify-new-request", ["acs-valid-allow-released", "acs-valid-deny", "acs-valid-ask-allow-timeout-challenged", "acs-valid-defer-held", "acs-valid-decision-failure-denied", "acs-valid-late-decision-denied"]],
    ["aarm-binding", aarm.check, aarm.MODIFICATION_RULE, "aarm-valid-modify-new-request", ["aarm-valid-allow-released", "aarm-valid-deny-recorded", "aarm-valid-defer-held", "aarm-valid-step-up-challenged", "aarm-valid-judgment-source-admit"]],
  ] as const) {
    const modified = vectorValue(name, modify);
    for (const identifier of others) {
      const value = vectorValue(name, identifier);
      assert.deepEqual(newRequestProblems(value), [], identifier);
      for (const held of members) {
        const changed = copied(value);
        for (const member of held) {
          changed[member] = copied(modified[member] as JsonObject);
        }
        const paths = check(changed).filter((item) => item.ruleId === rule).map((item) => item.path);
        assert.deepEqual([...new Set(paths)].sort(), held.map((member) => "/" + member).sort(), `${identifier} ${held.join(" ")}`);
      }
    }
  }
  for (const [name, identifier] of [
    ["acs-binding", "acs-invalid-new-request-without-modify"],
    ["aarm-binding", "aarm-invalid-new-request-without-modify"],
  ] as const) {
    const value = vectorValue(name, identifier);
    const check = name === "acs-binding" ? acs.check : aarm.check;
    const rule = name === "acs-binding" ? acs.MODIFICATION_RULE : aarm.MODIFICATION_RULE;
    assert.deepEqual(rulesAndPaths(check(value)), [`${rule} /modification_request`, `${rule} /modification_response`], identifier);
    for (const member of ["modification_request", "modification_response", "release"]) {
      delete value[member];
    }
    assert.deepEqual(check(value), [], identifier);
  }
});

test("AB1-004 and AC1-005: a modification that ends in deny with no new request releases nothing", () => {
  for (const [name, identifier] of [
    ["acs-binding", "acs-valid-modify-new-request"],
    ["aarm-binding", "aarm-valid-modify-new-request"],
  ] as const) {
    const value = vectorValue(name, identifier);
    const check = name === "acs-binding" ? acs.check : aarm.check;
    const rule = name === "acs-binding" ? acs.MODIFICATION_RULE : aarm.MODIFICATION_RULE;
    const response = copied(value["modification_response"] as JsonObject);
    for (const member of ["modification_request", "modification_response", "release"]) {
      delete value[member];
    }
    assert.deepEqual(check(value), [], identifier);
    value["modification_response"] = response;
    assert.ok(rulesAndPaths(check(value)).includes(`${rule} /modification_response`), identifier);
  }
});

test("AB1-004 and AC1-005: the new request carries the modified parameters as the same JSON", () => {
  const original: JsonObject = { message_id: "urn:example:message:o", action: { parameters: { a: 1 } } };
  for (const [effective, carried] of [[true, 1], [false, 0], [1, true]] as const) {
    const modified: JsonObject = { message_id: "urn:example:message:m", action: { parameters: { dry_run: carried } } };
    const paths = modificationProblems(original, modified, { dry_run: effective }).map(([path]) => path);
    assert.ok(paths.includes("modification_request/action/parameters"), `${effective} ${carried}`);
  }
});

test("the reference's same_json on values as Python holds them: a boolean never equals a number", () => {
  assert.ok(pySameJson(1n, 1n));
  assert.ok(!pySameJson(true, 1n));
  assert.ok(!pySameJson(false, 0n));
  assert.ok(!pySameJson(1, 1n));
  assert.ok(pySameJson(toPy({ a: [1, "x"] }), { a: [1n, "x"] }));
  assert.ok(!pySameJson(toPy({ a: [1, "x"] }), { a: [true, "x"] }));
  assert.ok(!pySameJson(Number.NaN, Number.NaN));
  assert.ok(pySameJson(undefined, null));
});

test("MG1-004 and MG1-005: the decision request and the forward are compared as the same JSON values", () => {
  const rebound = (value: JsonObject): JsonObject => {
    const request = value["decision_request"] as JsonObject;
    const response = (value["decision"] as JsonObject)["response"] as JsonObject;
    for (const item of (response["workflow"] as JsonObject)["causal_predecessors"] as JsonObject[]) {
      if (item["relation"] === "ecl.relation.responds-to.v1") {
        item["digest"] = digestOf(request) as JsonObject;
      }
    }
    (response["authorization"] as JsonObject)["scope_digest"] = digestOf({ request_id: request["message_id"] as string, action: request["action"] as JsonObject }) as JsonObject;
    return value;
  };
  const bindingOf = (value: JsonObject): JsonObject =>
    ((((value["decision_request"] as JsonObject)["extensions"] as JsonObject[]).find((item) => item["id"] === mcp.BINDING_EXTENSION) as JsonObject)["value"] as JsonObject);
  const valid = vectorValue("mcp-gateway", "mcp-valid-forwarded-on-admit");
  const value = copied(valid);
  const params = (value["call"] as JsonObject)["params"] as JsonObject;
  (params["arguments"] as JsonObject)["draft"] = true;
  (value["forwarded"] as JsonObject)["request"] = copied(value["call"] as JsonObject);
  bindingOf(value)["params_digest"] = jcsDigest(params);
  const action = (value["decision_request"] as JsonObject)["action"] as JsonObject;
  action["parameters"] = { ...(params["arguments"] as JsonObject), draft: 1 };
  action["parameters_digest"] = digestOf(action["parameters"]) as JsonObject;
  const found = rulesAndPaths(mcp.check(rebound(value)));
  assert.ok(found.includes(`${mcp.REQUEST_RULE} /decision_request/action/parameters`), found.join("; "));
  assert.ok(found.includes(`${mcp.FORWARD_RULE} /forwarded/request/params/arguments`), found.join("; "));
  for (const [inParams, name, written, bound] of [
    [true, "name", 1, true],
    [false, "method", 0, false],
  ] as const) {
    const changed = copied(valid);
    const call = changed["call"] as JsonObject;
    (inParams ? (call["params"] as JsonObject) : call)[name] = written;
    (changed["forwarded"] as JsonObject)["request"] = copied(call);
    bindingOf(changed)[name === "name" ? "tool" : "method"] = bound;
    bindingOf(changed)["params_digest"] = jcsDigest(call["params"] as JsonObject);
    const where = inParams ? `/forwarded/request/params/${name}` : `/forwarded/request/${name}`;
    assert.ok(rulesAndPaths(mcp.check(rebound(changed))).includes(`${mcp.FORWARD_RULE} ${where}`), name);
  }
});

test("OE1-003, OE1-004 and OE1-010: each attribute in the AnyValue kind the table gives, and a string key identifier", () => {
  const keys = otel.loadExportKeys(bytes(json("conformance/suites/otel-export/manifest.json")["export_keys_path"] as string));
  const valid = vectorValue("otel-export", "otel-valid-admit-response-exported");
  assert.deepEqual(otel.check(valid, keys), []);
  const withAttribute = (value: JsonObject, key: string, item: JsonObject): JsonObject => {
    const changed = copied(value);
    const log = changed["log_record"] as JsonObject;
    log["attributes"] = [...(log["attributes"] as JsonObject[]).filter((entry) => entry["key"] !== key), { key, value: item }];
    return changed;
  };
  const messages = (value: JsonObject): string[] => [...new Set(otel.check(value, keys).map((item) => item.message))].sort();
  assert.deepEqual(messages(withAttribute(valid, "ecl.decision.outcome", { bytesValue: "admit" })), ["ecl.decision.outcome is not the object's value"]);
  for (const item of [{ boolValue: true }, { intValue: "5" }, { bytesValue: "k1" }]) {
    assert.ok(messages(withAttribute(valid, otel.KEY_ID, item)).includes(`${otel.KEY_ID} is not the identifier of a key`), JSON.stringify(item));
  }
  // A string that names a key the caller does not hold is not compared, as OE1-010 intends.
  const unknown = withAttribute(valid, otel.KEY_ID, { stringValue: "urn:example:export-key:unknown" });
  assert.deepEqual(otel.check(unknown, keys), []);
  const digest = otel.unkeyedDigests(valid["object"] as JsonObject).get(otel.OBJECT_DIGEST) as string;
  assert.deepEqual(messages(withAttribute(unknown, otel.OBJECT_DIGEST, { stringValue: digest })), [`${otel.OBJECT_DIGEST} is a digest that needs no export key`]);
  // Under a key the caller does not hold, a digest is still the stringValue of an HMAC in
  // lowercase hexadecimal, so the SHA-256 that needs no key is refused in any other kind or form. The
  // check of OE1-004 reads the attribute in its own kind.
  assert.deepEqual(messages(withAttribute(unknown, otel.OBJECT_DIGEST, { bytesValue: digest })), [`${otel.OBJECT_DIGEST} is not an HMAC in lowercase hexadecimal`]);
  const raw = Buffer.from(digest, "hex").toString("base64");
  for (const item of [
    { bytesValue: raw },
    { arrayValue: { values: [{ stringValue: digest }] } },
    { kvlistValue: { values: [{ key: "sha256", value: { stringValue: digest } }] } },
    { boolValue: true },
    { stringValue: digest.toUpperCase() },
  ]) {
    assert.ok(messages(withAttribute(unknown, otel.OBJECT_DIGEST, item as JsonObject)).includes(`${otel.OBJECT_DIGEST} is not an HMAC in lowercase hexadecimal`), JSON.stringify(item));
  }
  // A response has no parameters digest, so a record of it that carries one copies nothing, under a key
  // the caller does not hold as under one it holds: here the request's, which needs no key.
  const request = vectorValue("otel-export", "otel-valid-request-exported")["object"] as JsonObject;
  const requestDigest = otel.unkeyedDigests(request).get(otel.PARAMETERS_DIGEST) as string;
  assert.deepEqual(messages(withAttribute(unknown, otel.PARAMETERS_DIGEST, { stringValue: requestDigest })), [`${otel.PARAMETERS_DIGEST} copies nothing in the object`]);
  // A repeated attribute key hides the earlier attribute from every comparison.
  const deny = vectorValue("otel-export", "otel-valid-deny-response-exported");
  assert.deepEqual(otel.check(deny, keys), []);
  const repeated = copied(deny);
  const log = repeated["log_record"] as JsonObject;
  log["attributes"] = [{ key: "ecl.decision.outcome", value: { stringValue: "admit" } }, ...(log["attributes"] as JsonObject[])];
  assert.deepEqual(messages(repeated), ["an attribute key is repeated"]);
});

test("OE1-003, OE1-004 and OE1-010: rows apply to the objects they name, and a keyed parameters digest and a fixed64 observed time are required", () => {
  const keys = otel.loadExportKeys(bytes(json("conformance/suites/otel-export/manifest.json")["export_keys_path"] as string));
  const messages = (value: JsonObject): string[] => [...new Set(otel.check(value, keys).map((item) => item.message))].sort();
  const withAttribute = (value: JsonObject, key: string, item: JsonObject | null): JsonObject => {
    const changed = copied(value);
    const log = changed["log_record"] as JsonObject;
    const kept = (log["attributes"] as JsonObject[]).filter((entry) => entry["key"] !== key);
    log["attributes"] = item === null ? kept : [...kept, { key, value: item }];
    return changed;
  };
  // OE1-010: under a key the caller does not hold, the keyed parameters digest of a request is still carried.
  const request = vectorValue("otel-export", "otel-valid-request-exported");
  const unknown = withAttribute(request, otel.KEY_ID, { stringValue: "urn:example:export-key:unknown" });
  assert.deepEqual(otel.check(unknown, keys), []);
  assert.deepEqual(messages(withAttribute(unknown, otel.PARAMETERS_DIGEST, null)), [`${otel.KEY_ID} is named without the keyed ${otel.PARAMETERS_DIGEST}`]);
  assert.deepEqual(messages(withAttribute(request, otel.PARAMETERS_DIGEST, null)), [`${otel.PARAMETERS_DIGEST} is not the object's value`]);
  // A challenge carries its request's identifier (OE1-004); a control message carries no decision's safe state.
  const challenge = vectorValue("otel-export", "otel-valid-challenge-exported");
  assert.deepEqual(otel.check(challenge, keys), []);
  assert.equal(otel.logAttributes(challenge["object"] as JsonObject).get(otel.REQUEST_ID), (challenge["object"] as JsonObject)["request_id"]);
  assert.deepEqual(messages(withAttribute(challenge, otel.REQUEST_ID, null)), [`${otel.REQUEST_ID} is not the object's value`]);
  const halt = vectorValue("otel-export", "otel-valid-halt-control-exported");
  assert.deepEqual(otel.check(halt, keys), []);
  assert.equal(otel.logAttributes(halt["object"] as JsonObject).has("ecl.decision.safe_state"), false);
  const safeState = (halt["object"] as JsonObject)["safe_state"] as string;
  assert.deepEqual(messages(withAttribute(halt, "ecl.decision.safe_state", { stringValue: safeState })), ["ecl.decision.safe_state copies nothing in the object"]);
  // A request event carries the identifier of the request it holds (OE1-004).
  const received = vectorValue("otel-export", "otel-valid-request-event-exported");
  assert.deepEqual(otel.check(received, keys), []);
  assert.deepEqual(messages(withAttribute(received, otel.REQUEST_ID, null)), [`${otel.REQUEST_ID} is not the object's value`]);
  // OE1-007: the observed time is a fixed64.
  const admit = copied(vectorValue("otel-export", "otel-valid-admit-response-exported"));
  (admit["log_record"] as JsonObject)["observedTimeUnixNano"] = (2n ** 64n - 1n).toString();
  assert.deepEqual(otel.check(admit, keys), []);
  (admit["log_record"] as JsonObject)["observedTimeUnixNano"] = (2n ** 64n).toString();
  assert.deepEqual(messages(admit), ["not a fixed64 time"]);
});

test("MG1-005 and MG1-006: a forward and a refusal carry the call's id as the same JSON value and presence", () => {
  // The record schema refuses an id of true or null in either form, so these records are held as
  // themselves and checked directly.
  for (const [callId, carried] of [[1, true], [null, undefined]] as const) {
    const forwarded = vectorValue("mcp-gateway", "mcp-valid-forwarded-on-admit");
    (forwarded["call"] as JsonObject)["id"] = callId;
    const request = (forwarded["forwarded"] as JsonObject)["request"] as JsonObject;
    if (carried === undefined) {
      delete request["id"];
    } else {
      request["id"] = carried;
    }
    assert.ok(rulesAndPaths(mcp.check(forwarded)).includes(`${mcp.FORWARD_RULE} /forwarded/request/id`), String(callId));
    const refused = vectorValue("mcp-gateway", "mcp-valid-denied-refused");
    (refused["call"] as JsonObject)["id"] = callId;
    const returned = refused["returned"] as JsonObject;
    if (carried === undefined) {
      delete returned["id"];
    } else {
      returned["id"] = carried;
    }
    assert.ok(rulesAndPaths(mcp.check(refused)).includes(`${mcp.REFUSAL_RULE} /returned/id`), String(callId));
  }
});

test("MG1-012: decoded content satisfies the definition of the same content held as itself", () => {
  const valid = vectorValue("mcp-gateway", "mcp-valid-float-content-forwarded");
  const [decoded, problems] = decodedRecord(valid, mcp.CONTENT_PATHS);
  assert.deepEqual(problems, []);
  assert.deepEqual(mcp.decodedContentProblems(valid, decoded), []);
  const cases: Array<[string[], JsonObject, string]> = [
    [["call"], { id: null }, "jsonRpcRequest"],
    [["call"], { jsonrpc: "1.0" }, "jsonRpcRequest"],
    [["forwarded", "request"], { id: true }, "jsonRpcRequest"],
    [["server_response"], { result: 0.5 }, "jsonRpcResponse"],
    [["returned"], { id: { n: 1 } }, "jsonRpcResponse"],
    [["tool_definition"], { name: "" }, "toolDefinition"],
  ];
  for (const [path, change, name] of cases) {
    const value = copied(valid);
    let parent = value;
    for (const step of path.slice(0, -1)) {
      parent = parent[step] as JsonObject;
    }
    let content = decoded as JsonValue;
    for (const step of path) {
      content = (content as JsonObject)[step] as JsonValue;
    }
    const changed: JsonObject = { ...copied(content as JsonObject), ...change };
    const last = path[path.length - 1] as string;
    if (last === "call" || last === "request") {
      changed["params"] = { ...(changed["params"] as JsonObject), _meta: { "example.org/sampling": 0.5 } };
    }
    parent[last] = encodeContent(changed);
    assert.deepEqual(Object.keys(parent[last] as JsonObject), ["rfc8785"], path.join("/"));
    const found = mcp.check(value);
    assert.deepEqual(rulesAndPaths(found), [`ecl.error.schema-invalid.v1 /${path.join("/")}`], path.join("/"));
    assert.ok(found[0]?.message.includes(`does not satisfy ${name}`), path.join("/"));
  }
});

test("MG1-004 and MG1-006: a call whose arguments are null is refused as not mapped, also under a fixed target", () => {
  // A null is not an absent member: arguments that are null are not an object, as arguments that
  // are a string are not, so the call is refused with -31007 rather than decided without arguments.
  const refused = vectorValue("mcp-gateway", "mcp-valid-null-arguments-refused");
  assert.equal(((refused["call"] as JsonObject)["params"] as JsonObject)["arguments"], null);
  assert.ok("target_uri" in (refused["mapping"] as JsonObject));
  assert.deepEqual(mcp.refusalCause(refused), ["not-mapped", "ecl.error.binding-unsupported.v1", null]);
  assert.deepEqual(rulesAndPaths(mcp.check(refused)), []);
  const absent = copied(refused);
  delete ((absent["call"] as JsonObject)["params"] as JsonObject)["arguments"];
  assert.notEqual(mcp.refusalCause(absent)?.[0], "not-mapped");
});
