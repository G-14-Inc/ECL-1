// Schema-derived producer types. Robert F. Tilley Jr.; G-14, Inc.
import assert from "node:assert/strict";
import { test } from "node:test";
import type { BindingOauthPresentationPublicJwk } from "../../src/generated/types.js";
import type { JsonValue } from "../../src/json/value.js";
import { recordSchemas } from "../../src/schema/validator.js";

// Ordinary JWK metadata is explicitly allowed by the publicJwk schema.
const publicKey: BindingOauthPresentationPublicJwk = {
  kid: "urn:example:key:public", kty: "OKP", crv: "Ed25519", x: "AQ",
  alg: "EdDSA", use: "sig", key_ops: ["verify"],
};
const jsonValue: JsonValue = publicKey;
// @ts-expect-error an open object's declared kid still has its string type
const wrongKnownMember: BindingOauthPresentationPublicJwk = { kid: 1, kty: "OKP", crv: "Ed25519", x: "AQ" };

test("generated public-key shape permits metadata while runtime schema rejects private material", () => {
  const schema = "https://externalcontrollayer.ai/ns/schema/binding/oauth-presentation/1#/$defs/publicJwk";
  assert.equal(recordSchemas().isValid(schema, jsonValue), true);
  assert.equal(recordSchemas().isValid(schema, { ...publicKey, d: "private-value" }), false);
  assert.equal(recordSchemas().isValid(schema, wrongKnownMember), false);
});
