import assert from "node:assert/strict";
import { test } from "node:test";
import { DECISION_BASIS, DECISION_BASIS_RULE, SemanticValidator, objectFindings } from "../../src/index.js";
import type { JsonObject, JsonValue } from "../../src/index.js";
import { REGISTER_DOCUMENT_RULE, inputKey, oneWayProblems, registerDocumentProblems } from "../../src/semantic/rules.js";
import { json } from "./helpers.js";

const ADMIT = "conformance/vectors/dcmp-2/valid-decision-response-admit.json";
const VALUE_RULE = "ecl.rule.extension-value-valid.v1";
const PAYEE = "urn:example:input:payee-allow-list";
const MANDATE = "urn:example:input:principal-transfer-mandate";
const ANOMALY = "urn:example:input:transfer-anomaly-score";
const JUSTIFICATION = "urn:example:input:agent-justification";

function digest(fill: string): JsonObject {
  return { algorithm: "ecl.digest.sha-256.v1", value: fill.repeat(64) };
}

/** Two verifiable inputs support the action; a judgment and the agent's own claim do not. */
function inputs(): JsonObject[] {
  return [
    { input: PAYEE, class: "verifiable", required: true, status: "available", effect: "supports", reference: { uri: "urn:example:record:payee-allow-list-v12", digest: digest("1") }, source: "urn:example:system-of-record:vendor-master" },
    { input: MANDATE, class: "verifiable", required: true, status: "available", effect: "supports", reference: { uri: "urn:example:mandate:ap-clerk-transfers", digest: digest("2") }, source: "urn:example:identity-provider:corporate" },
    { input: ANOMALY, class: "judgment", required: false, status: "available", effect: "none", reference: { uri: "urn:example:score:transfer-anomaly-0001", digest: digest("3") }, source: "urn:example:detector:transfer-anomaly" },
    { input: JUSTIFICATION, class: "actor_supplied", required: false, status: "available", effect: "none", reference: { uri: "urn:example:statement:justification-1", digest: digest("4") }, source: "urn:example:agent:payments-1" },
  ];
}

function changed(records: JsonObject[], identifier: string, changes: Record<string, JsonValue | undefined>): JsonObject[] {
  return records.map((item) => {
    if (item["input"] !== identifier) {
      return item;
    }
    const copy: JsonObject = { ...item };
    for (const [key, value] of Object.entries(changes)) {
      if (value === undefined) {
        delete copy[key];
      } else {
        copy[key] = value;
      }
    }
    return copy;
  });
}

const REGISTER: JsonObject = { uri: "urn:example:register:payments", digest: digest("9") };

function withBasis(response: JsonObject, records: JsonValue, register: JsonValue | null = REGISTER): JsonObject {
  const others = (response["extensions"] as JsonObject[]).filter((item) => item["id"] !== DECISION_BASIS);
  const value: JsonObject = register === null ? { inputs: records } : { register, inputs: records };
  const extensions = [...others, { id: DECISION_BASIS, version: 1, critical: true, value }];
  extensions.sort((a, b) => ((a["id"] as string) < (b["id"] as string) ? -1 : 1));
  return { ...response, extensions };
}

function admit(): JsonObject {
  return json(ADMIT);
}

function notAdmitted(outcome: string): JsonObject {
  const response = { ...admit(), outcome, obligations: [], reasons: [{ code: "ecl.reason.native-policy-disposition.v1" }] } as JsonObject;
  delete response["authorization"];
  response["extensions"] = (response["extensions"] as JsonObject[]).filter((item) => item["id"] !== "ecl.ext.consequence-coupling.v1");
  return response;
}

function rule(value: JsonObject): Array<[string, string]> {
  return new SemanticValidator()
    .validate(value)
    .filter((item) => item.ruleId === DECISION_BASIS_RULE)
    .map((item) => [item.path, item.message]);
}

test("an admit resting on verifiable inputs has no finding", () => {
  assert.deepEqual(objectFindings(withBasis(admit(), inputs())), []);
});

test("an admit supported by a restricting-only input is refused", () => {
  for (const [identifier, position] of [
    [ANOMALY, 2],
    [JUSTIFICATION, 3],
  ] as const) {
    const found = rule(withBasis(admit(), changed(inputs(), identifier, { effect: "supports" })));
    assert.deepEqual(
      found.map(([path]) => path),
      [`/extensions/1/value/inputs/${position}/effect`],
    );
    assert.match((found[0] as [string, string])[1], /can only make an outcome stricter/);
  }
});

test("an admit without a supporting verifiable input is refused", () => {
  const records = changed(changed(inputs(), PAYEE, { effect: "none" }), MANDATE, { effect: "none" });
  assert.deepEqual(rule(withBasis(admit(), records)), [["/extensions/1/value/inputs", "an admit records no verifiable input that supports it"]]);
});

test("a required input that was not available blocks an admit, and an optional one does not", () => {
  for (const status of ["unavailable", "late", "malformed"]) {
    const required = changed(inputs(), MANDATE, { status, effect: "none", reference: undefined });
    assert.deepEqual(
      rule(withBasis(admit(), required)).map(([path]) => path),
      ["/extensions/1/value/inputs/1/status"],
      status,
    );
    const optional = changed(inputs(), ANOMALY, { status, effect: "none", reference: undefined });
    assert.deepEqual(objectFindings(withBasis(admit(), optional)), [], status);
  }
});

test("an input that was not available supports no outcome", () => {
  const records = changed(inputs(), PAYEE, { status: "late", reference: undefined });
  assert.deepEqual(
    rule(withBasis(admit(), records))
      .map(([path]) => path)
      .sort(),
    ["/extensions/1/value/inputs/0/effect", "/extensions/1/value/inputs/0/status"],
  );
});

test("a judgment may make an outcome stricter, and supports no outcome", () => {
  for (const outcome of ["hold", "deny"]) {
    assert.deepEqual(objectFindings(withBasis(notAdmitted(outcome), changed(inputs(), ANOMALY, { effect: "restricts" }))), [], outcome);
  }
  const unavailable = changed(inputs(), MANDATE, { status: "unavailable", effect: "restricts", reference: undefined });
  assert.deepEqual(objectFindings(withBasis(notAdmitted("deny"), unavailable)), []);
  for (const outcome of ["hold", "deny", "challenge"]) {
    const response = notAdmitted(outcome);
    if (outcome === "challenge") {
      response["challenge_id"] = "https://externalcontrollayer.ai/ns/challenge/example-001";
    }
    assert.deepEqual(
      rule(withBasis(response, changed(inputs(), ANOMALY, { effect: "supports" }))).map(([path]) => path),
      ["/extensions/0/value/inputs/2/effect"],
      outcome,
    );
  }
});

test("the value schema comes first, and a malformed record yields findings, never an exception", () => {
  const records = changed(inputs(), PAYEE, { reference: { uri: "urn:example:record:payee-allow-list" } });
  assert.deepEqual(
    objectFindings(withBasis(admit(), records)).map((item) => item.ruleId),
    [VALUE_RULE],
  );
  for (const value of [{ inputs: "not a list" }, { inputs: ["not an object", 7, null] }, { inputs: [{ class: "judgment" }] }, {}] as JsonValue[]) {
    const response = admit();
    (response["extensions"] as JsonValue[]).push({ id: DECISION_BASIS, version: 1, critical: true, value });
    const found = objectFindings(response);
    assert.ok(found.length > 0);
    assert.ok(!found.some((item) => item.message.includes("could not be completed") || item.message.includes("rejected malformed input")));
  }
  // An unhashable class is malformed input for the whole check, as in the reference.
  const unhashable = changed(inputs(), ANOMALY, { effect: "supports", class: ["judgment"] });
  assert.deepEqual(
    new SemanticValidator()
      .validate(withBasis(admit(), unhashable))
      .filter((item) => item.message.startsWith("decision basis semantic check"))
      .map((item) => item.ruleId),
    ["ecl.error.schema-invalid.v1"],
  );
});

test("a request or an event carrying the extension is not judged as a decision", () => {
  const request = json("conformance/vectors/dcmp-2/valid-decision-request.json");
  assert.deepEqual(rule(withBasis(request, changed(inputs(), ANOMALY, { effect: "supports" }))), []);
});

test("an input listed twice is refused, even when one of its entries is harmless", () => {
  const second: JsonObject = { ...(inputs()[2] as JsonObject), class: "verifiable", effect: "supports" };
  assert.deepEqual(rule(withBasis(admit(), [...inputs(), second])), [["/extensions/1/value/inputs/4/input", "the record lists this input more than once"]]);
});

function derived(name: string, inputClass: string, sources: string[]): JsonObject {
  return { input: name, class: inputClass, required: false, status: "available", effect: "none", reference: { uri: `${name}:value`, digest: digest("5") }, source: `${name}:source`, derived_from: sources };
}

test("an input computed from an input that is not verifiable cannot be verifiable", () => {
  const found = rule(withBasis(admit(), [...inputs(), derived("urn:example:input:risk-tier", "verifiable", [ANOMALY])]));
  assert.deepEqual(
    found.map(([path]) => path),
    ["/extensions/1/value/inputs/4/class"],
  );
  assert.match((found[0] as [string, string])[1], /cannot be verifiable/);
  const check = derived("urn:example:input:payee-check", "verifiable", [PAYEE, MANDATE]);
  const tier = derived("urn:example:input:risk-tier", "judgment", [ANOMALY, JUSTIFICATION]);
  assert.deepEqual(objectFindings(withBasis(admit(), [...inputs(), check, tier])), []);
  const unknown = derived("urn:example:input:payee-check", "verifiable", [PAYEE, "urn:example:input:x"]);
  assert.deepEqual(
    rule(withBasis(admit(), [...inputs(), unknown])).map(([path]) => path),
    ["/extensions/1/value/inputs/4/derived_from/1"],
  );
});

test("a record without inputs may end in a deny but never in an admit", () => {
  assert.deepEqual(objectFindings(withBasis(notAdmitted("deny"), [])), []);
  assert.deepEqual(
    rule(withBasis(admit(), [])).map(([, message]) => message),
    ["an admit records no verifiable input that supports it"],
  );
});

test("a record names its register by reference and digest", () => {
  for (const register of [null, { uri: "urn:example:register:payments" }]) {
    assert.deepEqual(
      objectFindings(withBasis(admit(), inputs(), register)).map((item) => item.ruleId),
      [VALUE_RULE],
    );
  }
});

// Derivations followed through other inputs, cycles, input names compared by key, the
// verifiable-only outcome, the times of an input, and the register rule.

const LATE = "urn:example:input:sanctions-list";
const CHALLENGE_ID = "https://externalcontrollayer.ai/ns/challenge/example-001";

function lateInput(name: string = LATE): JsonObject {
  return { input: name, class: "verifiable", required: false, status: "late", effect: "none", source: "urn:example:system-of-record:sanctions" };
}

function responseFor(outcome: string): JsonObject {
  if (outcome === "admit") {
    return admit();
  }
  const response = notAdmitted(outcome);
  if (outcome === "challenge") {
    response["challenge_id"] = CHALLENGE_ID;
  }
  return response;
}

function basisIndex(response: JsonObject): number {
  return (response["extensions"] as JsonObject[]).findIndex((item) => item["id"] === DECISION_BASIS);
}

function basisValue(response: JsonObject): JsonObject {
  return (response["extensions"] as JsonObject[])[basisIndex(response)]?.["value"] as JsonObject;
}

test("input names compare after the case normalization of RFC 3986 and RFC 8141, in ASCII only", () => {
  const cases: Array<[string, string]> = [
    ["URN:Example:input:Payee", "urn:example:input:Payee"],
    ["urn:example:input:payee", "urn:example:input:payee"],
    ["HTTPS://Example.org/Input", "https://example.org/Input"],
    ["https://User@Agents.Example:8443/A?Q#F", "https://User@agents.example:8443/A?Q#F"],
    ["https://Agents.Example", "https://agents.example"],
    ["ftp://Example.org/Input", "ftp://Example.org/Input"],
    ["Urn:EXAMPLE", "urn:EXAMPLE"],
    ["urn:example:agent:test%2d1", "urn:example:agent:test%2D1"],
    ["https://Host.Example/a%2fb%c3%a9", "https://host.example/a%2Fb%C3%A9"],
    ["no-scheme%7e", "no-scheme%7E"],
    ["urn:example:%zz%4", "urn:example:%zz%4"],
    ["no-scheme", "no-scheme"],
    [":leading-colon", ":leading-colon"],
    ["URN:\u0130X:a", "urn:\u0130x:a"],
  ];
  for (const [name, key] of cases) {
    assert.equal(inputKey(name), key, name);
  }
});

test("an input listed twice under a case variant of its URN is refused", () => {
  const variant: JsonObject = { ...(inputs()[0] as JsonObject), input: PAYEE.replace("urn:example:", "URN:Example:"), effect: "none" };
  assert.deepEqual(rule(withBasis(admit(), [...inputs(), variant])), [["/extensions/1/value/inputs/4/input", "the record lists this input more than once"]]);
  // The rest of a name is compared as written: this names another input.
  const other: JsonObject = { ...variant, input: PAYEE.replace("payee", "Payee") };
  assert.deepEqual(rule(withBasis(admit(), [...inputs(), other])), []);
});

test("an input computed from a late input, directly or through other inputs, cannot support an outcome", () => {
  const check: JsonObject = { ...derived("urn:example:input:payee-check", "verifiable", [LATE]), effect: "supports" };
  assert.deepEqual(rule(withBasis(admit(), [...inputs(), lateInput(), check])), [
    ["/extensions/1/value/inputs/5/effect", "an input computed from an input that was not available cannot support an outcome"],
  ]);
  const screen = derived("urn:example:input:sanctions-screen", "verifiable", [LATE]);
  const through: JsonObject = { ...derived("urn:example:input:payee-check", "verifiable", [screen["input"] as string]), effect: "supports" };
  assert.deepEqual(
    rule(withBasis(admit(), [...inputs(), lateInput(), screen, through])).map(([path]) => path),
    ["/extensions/1/value/inputs/6/effect"],
  );
});

test("an admit cannot rest on a required input computed from a late input, and a deny may", () => {
  const check: JsonObject = { ...derived("urn:example:input:payee-check", "verifiable", [LATE]), required: true };
  assert.deepEqual(rule(withBasis(admit(), [...inputs(), lateInput(), check])), [
    ["/extensions/1/value/inputs/5/status", "an admit cannot proceed while a required input is computed from an input that was not available"],
  ]);
  assert.deepEqual(objectFindings(withBasis(notAdmitted("deny"), [...inputs(), lateInput(), { ...check, effect: "restricts" }])), []);
});

test("no input is computed from itself", () => {
  const first = derived("urn:example:input:a", "judgment", ["urn:example:input:b"]);
  const second = derived("urn:example:input:b", "judgment", ["URN:example:input:a"]);
  assert.deepEqual(rule(withBasis(admit(), [...inputs(), first, second])), [
    ["/extensions/1/value/inputs/4/derived_from", "the input is computed from itself through other inputs"],
    ["/extensions/1/value/inputs/5/derived_from", "the input is computed from itself through other inputs"],
  ]);
  const itself = derived("urn:example:input:a", "judgment", ["urn:Example:input:a"]);
  assert.deepEqual(rule(withBasis(admit(), [...inputs(), itself])), [["/extensions/1/value/inputs/4/derived_from/0", "the record lists no other input with this name"]]);
});

test("the outcome is at least as strict as the recorded verifiable-only outcome", () => {
  const cases: Array<[string, string, boolean]> = [
    ["deny", "challenge", true],
    ["deny", "hold", true],
    ["hold", "challenge", true],
    ["challenge", "admit", true],
    ["deny", "deny", false],
    ["hold", "deny", false],
    ["admit", "admit", false],
    ["admit", "hold", false],
  ];
  for (const [recorded, outcome, refused] of cases) {
    // An input supports only a verifiable-only admit (ECL1N-0181, DCMP2-053).
    const value = withBasis(responseFor(outcome), recorded === "admit" ? inputs() : unsupported(inputs()));
    basisValue(value)["verifiable_only_outcome"] = recorded;
    if (refused) {
      assert.ok(
        rule(value).some(([path, message]) => path === `/extensions/${basisIndex(value)}/value/verifiable_only_outcome` && message === `the outcome '${outcome}' is less strict than the verifiable-only outcome '${recorded}'`),
        `${recorded} ${outcome}`,
      );
    } else {
      assert.deepEqual(objectFindings(value), [], `${recorded} ${outcome}`);
    }
  }
  // A caller without the response's outcome does not compare outcomes.
  const response = withBasis(responseFor("hold"), unsupported(inputs()));
  const value = basisValue(response);
  value["verifiable_only_outcome"] = "deny";
  assert.deepEqual(oneWayProblems(value, false), []);
  assert.deepEqual(oneWayProblems(value, false, response["outcome"], response["evaluated_at"]), [["/verifiable_only_outcome", "the outcome 'hold' is less strict than the verifiable-only outcome 'deny'"]]);
});

function unsupported(records: JsonObject[]): JsonObject[] {
  return records.map((item) => ({ ...item, effect: "none" }));
}

test("no input supports an outcome whose verifiable-only outcome is not admit", () => {
  for (const recorded of ["challenge", "hold", "deny"]) {
    // A deny whose verifiable-only outcome is deny while two inputs support it: the rule reports
    // each supporting input, and a record whose inputs have no effect passes.
    const value = withBasis(responseFor("deny"), inputs());
    basisValue(value)["verifiable_only_outcome"] = recorded;
    assert.deepEqual(
      rule(value),
      [0, 1].map((position) => [`/extensions/${basisIndex(value)}/value/inputs/${position}/effect`, `no input supports an outcome whose verifiable-only outcome is '${recorded}'`]),
      recorded,
    );
    const quiet = withBasis(responseFor("deny"), unsupported(inputs()));
    basisValue(quiet)["verifiable_only_outcome"] = recorded;
    assert.deepEqual(objectFindings(quiet), [], recorded);
  }
});

test("a verifiable-only admit rests on a verifiable input and on no missing required one", () => {
  // A verifiable-only admit while the required input is unavailable and no input supports it: the
  // rule reports both conditions.
  const records = changed(changed(inputs(), MANDATE, { status: "unavailable", reference: undefined, effect: "none" }), PAYEE, { effect: "none" });
  const value = withBasis(responseFor("deny"), records);
  basisValue(value)["verifiable_only_outcome"] = "admit";
  assert.deepEqual(rule(value), [
    [`/extensions/${basisIndex(value)}/value/inputs/1/status`, "a verifiable-only admit cannot have a required verifiable input that was not available"],
    [`/extensions/${basisIndex(value)}/value/verifiable_only_outcome`, "a verifiable-only admit records no verifiable input that supports it"],
  ]);
  const valid = withBasis(responseFor("deny"), inputs());
  basisValue(valid)["verifiable_only_outcome"] = "admit";
  assert.deepEqual(objectFindings(valid), []);
});

test("a required judgment or actor_supplied input does not change the verifiable-only outcome", () => {
  for (const identifier of [ANOMALY, JUSTIFICATION]) {
    const records = changed(inputs(), identifier, { required: true, status: "unavailable", reference: undefined, effect: "none" });
    for (const outcome of ["deny", "hold", "challenge"]) {
      const value = withBasis(responseFor(outcome), records);
      basisValue(value)["verifiable_only_outcome"] = "admit";
      assert.deepEqual(objectFindings(value), [], `${identifier} ${outcome}`);
    }
    // The decision itself cannot be an admit while the required input is unavailable.
    const admitted = withBasis(responseFor("admit"), records);
    basisValue(admitted)["verifiable_only_outcome"] = "admit";
    assert.ok(rule(admitted).length > 0, identifier);
  }
});

// The admit vector's response was evaluated at 2026-07-27T04:30:00.090000Z.
const RECEIVED = "2026-07-27T04:30:00.010000Z";
const OBTAINED = "2026-07-27T04:30:00.050000Z";
const AFTER_DECISION = "2026-07-27T04:30:00.100000Z";
const VALUED = "2026-07-27T04:29:00Z";

/**
 * The admit with `records` and `received_at`; each available input that gives no time gets both,
 * since a record that gives `received_at` times every available input.
 */
function timed(records: JsonObject[], received: string | null = RECEIVED): JsonObject {
  const value = withBasis(admit(), records);
  if (received !== null) {
    basisValue(value)["received_at"] = received;
    for (const item of basisValue(value)["inputs"] as JsonObject[]) {
      if (item["status"] === "available") {
        item["obtained_at"] ??= OBTAINED;
        item["value_at"] ??= VALUED;
      }
    }
  }
  return value;
}

test("a record that gives when the request was received times every available input", () => {
  // A record that gives received_at while three of its available inputs lack obtained_at or
  // value_at: the rule reports each of those inputs.
  const value = withBasis(admit(), changed(changed(inputs(), PAYEE, { obtained_at: OBTAINED, value_at: VALUED }), MANDATE, { obtained_at: OBTAINED }));
  basisValue(value)["received_at"] = RECEIVED;
  const message = "a record that gives when the request was received gives when each available input was obtained and the time its value describes";
  assert.deepEqual(
    rule(value),
    [1, 2, 3].map((position) => [`/extensions/1/value/inputs/${position}`, message]),
  );
  assert.deepEqual(objectFindings(timed(changed(inputs(), ANOMALY, { status: "unavailable", reference: undefined }))), []);
});

test("a value describes no time after the input was obtained or after the decision", () => {
  // An input whose value_at is an hour after the decision and after its own obtained_at: the rule
  // reports both.
  const found = rule(timed(changed(inputs(), PAYEE, { obtained_at: OBTAINED, value_at: "2026-07-27T05:30:00.090000Z" })));
  assert.deepEqual(found, [
    ["/extensions/1/value/inputs/0/value_at", "the input's value describes a time after it was obtained"],
    ["/extensions/1/value/inputs/0/value_at", "the input's value describes a time after the decision"],
  ]);
  assert.deepEqual(objectFindings(timed(changed(inputs(), PAYEE, { obtained_at: OBTAINED, value_at: OBTAINED }))), []);
});

test("the times of an input: obtained before the decision, after the request was received", () => {
  const records = changed(changed(inputs(), PAYEE, { obtained_at: OBTAINED, value_at: VALUED }), MANDATE, { obtained_at: OBTAINED, value_at: OBTAINED });
  assert.deepEqual(objectFindings(timed(records)), []);
  assert.deepEqual(rule(timed(changed(inputs(), PAYEE, { obtained_at: AFTER_DECISION }))), [["/extensions/1/value/inputs/0/status", "an input obtained after the decision was not available"]]);
  const lateAnomaly = changed(inputs(), ANOMALY, { status: "late", reference: undefined, obtained_at: AFTER_DECISION });
  assert.deepEqual(objectFindings(timed(lateAnomaly)), []);
  assert.deepEqual(rule(timed(changed(inputs(), PAYEE, { obtained_at: OBTAINED }), null)), [
    ["/extensions/1/value/received_at", "a record that gives when an input was obtained gives when the request was received"],
  ]);
  assert.deepEqual(rule(timed(inputs(), AFTER_DECISION)), [["/extensions/1/value/received_at", "the request was received after the decision"]]);
  assert.deepEqual(
    objectFindings(timed(changed(inputs(), PAYEE, { obtained_at: "yesterday" }))).map((item) => item.ruleId),
    [VALUE_RULE],
  );
});

function bundleRegister(): JsonObject {
  return json("conformance/suites/evidence-bundle/register.json");
}

function declarations(register: JsonObject): JsonObject[] {
  return ((register["entries"] as JsonObject[])[0] as JsonObject)["decision_inputs"] as JsonObject[];
}

test("a register declares each action class and each input of a class once", () => {
  const register = bundleRegister();
  assert.deepEqual(registerDocumentProblems(register), []);
  const twice = structuredClone(register);
  (twice["entries"] as JsonObject[]).push(structuredClone((twice["entries"] as JsonObject[])[0] as JsonObject));
  assert.deepEqual(registerDocumentProblems(twice), [["/entries/1/action_class_id", "the register declares this action class more than once"]]);
  const variant = structuredClone(register);
  const declared = declarations(variant);
  const first = declared[0] as JsonObject;
  declared.push({ ...first, input: (first["input"] as string).replace("urn:example:", "URN:EXAMPLE:") });
  assert.deepEqual(registerDocumentProblems(variant), [[`/entries/0/decision_inputs/${declared.length - 1}/input`, "the register declares this input more than once for the action class"]]);
});

test("a register declares each derivation consistently", () => {
  const register = bundleRegister();
  const names = declarations(register).map((item) => item["input"] as string);
  const classes = declarations(register).map((item) => item["class"] as string);
  const verifiable = classes.indexOf("verifiable");
  const otherVerifiable = classes.indexOf("verifiable", verifiable + 1);
  const judgment = classes.indexOf("judgment");
  assert.ok(verifiable >= 0 && otherVerifiable > verifiable && judgment >= 0);
  const cases: Array<[Record<number, string[]>, Array<[string, string]>]> = [
    [{ [judgment]: [names[verifiable] as string, names[otherVerifiable] as string] }, []],
    [{ [judgment]: ["urn:example:input:bundle:elsewhere"] }, [[`/entries/0/decision_inputs/${judgment}/derived_from/0`, "the register declares no other input of the action class with this name"]]],
    [{ [verifiable]: [names[judgment] as string] }, [[`/entries/0/decision_inputs/${verifiable}/class`, "an input computed from an input of class 'judgment' cannot be verifiable"]]],
    [
      { [verifiable]: [names[otherVerifiable] as string], [otherVerifiable]: [names[verifiable] as string] },
      [
        [`/entries/0/decision_inputs/${verifiable}/derived_from`, "the input is computed from itself through other inputs"],
        [`/entries/0/decision_inputs/${otherVerifiable}/derived_from`, "the input is computed from itself through other inputs"],
      ],
    ],
  ];
  for (const [derivations, expected] of cases) {
    const changedRegister = structuredClone(register);
    for (const [position, sources] of Object.entries(derivations)) {
      (declarations(changedRegister)[Number(position)] as JsonObject)["derived_from"] = sources;
    }
    assert.deepEqual(registerDocumentProblems(changedRegister), expected, JSON.stringify(derivations));
  }
});

test("the register rule applies to a register document, and the published register passes it", () => {
  const published = json("profiles/examples/claims/action-register.json");
  assert.ok((published["entries"] as JsonObject[]).some((entry) => ((entry["decision_inputs"] as JsonObject[] | undefined) ?? []).some((item) => "derived_from" in item)));
  assert.deepEqual(new SemanticValidator().validate(published), []);
  const twice = bundleRegister();
  (twice["entries"] as JsonObject[]).push(structuredClone((twice["entries"] as JsonObject[])[0] as JsonObject));
  assert.deepEqual(
    new SemanticValidator().validate(twice).map((item) => [item.ruleId, item.path]),
    [[REGISTER_DOCUMENT_RULE, "/entries/1/action_class_id"]],
  );
});
