/**
 * The checkers of the five ECL binding profiles: AARM-BINDING-1, ACS-BINDING-1, MCP-GATEWAY-1,
 * OTEL-EVIDENCE-EXPORT-1 and OAUTH-AUTHORITY-1, with RFC 8785 (`jcs.ts`) and compact JWS
 * (`jose.ts`) beneath them.
 *
 * `bindingFindings` dispatches on a record's `schema_version` and returns the findings of that
 * profile's registered rules. Like the reference's checkers, it reads only a record that its
 * schema has accepted: `evaluateBindingRecord` is the conformance runner's `binding` stage
 * (strict parsing done, then the record's schema, then the profile's rules). A record of no
 * binding profile yields one schema finding. The export keys a caller holds
 * (OTEL-EVIDENCE-EXPORT-1, OE1-010) go to the OpenTelemetry checker, which compares a record's
 * keyed digests only under a key it is given.
 */

import { isObject } from "../json/value.js";
import type { JsonObject, JsonValue } from "../json/value.js";
import { SCHEMA_INVALID, sortFindings } from "../semantic/rules.js";
import type { Finding } from "../semantic/rules.js";
import { recordSchemas } from "../schema/validator.js";
import type { SchemaSet } from "../schema/validator.js";
import * as aarm from "./aarm.js";
import * as acs from "./acs.js";
import * as mcp from "./mcp.js";
import * as oauth from "./oauth.js";
import * as otel from "./otel.js";

/** Each binding profile's record version, with its checker and its record schema. */
export const BINDING_PROFILES: ReadonlyMap<string, { readonly schema: string; readonly check: (record: JsonObject) => Finding[] }> = new Map([
  [aarm.EXCHANGE_VERSION, { schema: aarm.EXCHANGE_SCHEMA, check: aarm.check }],
  [acs.EXCHANGE_VERSION, { schema: acs.EXCHANGE_SCHEMA, check: acs.check }],
  [mcp.EXCHANGE_VERSION, { schema: mcp.EXCHANGE_SCHEMA, check: mcp.check }],
  [otel.EXPORT_VERSION, { schema: otel.EXPORT_SCHEMA, check: otel.check }],
  [oauth.PRESENTATION_VERSION, { schema: oauth.PRESENTATION_SCHEMA, check: oauth.check }],
]);

/** The registered rules of the five profiles, in each profile's order. */
export const BINDING_RULES: readonly string[] = [
  ...aarm.RULES.map(([rule]) => rule),
  ...acs.RULES.map(([rule]) => rule),
  ...mcp.RULES.map(([rule]) => rule),
  ...otel.RULES.map(([rule]) => rule),
  ...oauth.ISSUER_RULES.map(([rule]) => rule),
  ...oauth.ACCEPTANCE_RULES.map(([rule]) => rule),
  ...oauth.REFUSAL_RULES.map(([rule]) => rule),
];

/**
 * The findings of the binding profile whose record `value` is, sorted by rule and path. `exportKeys`
 * are the OpenTelemetry export keys the caller holds, by identifier.
 */
export function bindingFindings(value: JsonValue, exportKeys: ReadonlyMap<string, otel.ExportKey> = new Map()): Finding[] {
  const version = isObject(value) ? value["schema_version"] : undefined;
  const profile = typeof version === "string" ? BINDING_PROFILES.get(version) : undefined;
  if (profile === undefined || !isObject(value)) {
    return [{ ruleId: SCHEMA_INVALID, path: "/schema_version", message: "not a binding profile record" }];
  }
  return sortFindings(version === otel.EXPORT_VERSION ? otel.check(value, exportKeys) : profile.check(value));
}

/**
 * The runner's `binding` stage for a parsed record and the schema the vector names: one
 * schema finding when the value is not an object or fails that schema, else the profile's
 * findings, under the OpenTelemetry export keys the caller holds.
 */
export function evaluateBindingRecord(
  schema: string,
  value: JsonValue,
  schemas: SchemaSet = recordSchemas(),
  exportKeys: ReadonlyMap<string, otel.ExportKey> = new Map(),
): Finding[] {
  if (!isObject(value)) {
    return [{ ruleId: SCHEMA_INVALID, path: "/", message: "a binding record is a JSON object" }];
  }
  const errors = schemas.errors(schema, value, 1);
  if (errors.length > 0) {
    const error = errors[0] as { path: string; keyword: string; message: string };
    return [{ ruleId: SCHEMA_INVALID, path: error.path, message: `${error.keyword}: ${error.message}` }];
  }
  return bindingFindings(value, exportKeys);
}

export { aarm, acs, mcp, oauth, otel };
export { JcsError, jcsCanonicalize, jcsDigest, jcsNumber } from "./jcs.js";
export { JoseError, b64url, b64urlDecode, decodeJws, verifyJws, verifyDpop, thumbprint, tokenHash, ACCESS_TYPE, DPOP_TYPE } from "./jose.js";
export { parsePyJson, PyJsonError, pyEquals, toPy } from "./pyjson.js";
export type { PyObject, PyValue } from "./pyjson.js";
