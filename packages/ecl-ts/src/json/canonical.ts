/**
 * Canonical JSON: RFC 8785 (JSON Canonicalization Scheme) under the restricted ECL profile
 * (IE1-001, IE1-002). Members are ordered by their UTF-16 code units, strings use the shortest
 * escapes, and numbers are integers within the exact interoperable range, so the number
 * serialization of RFC 8785 reduces to the decimal integer.
 */

import { sha256Hex, utf8 } from "../crypto/bytes.js";
import { MAX_JSON_BYTES, MAX_SAFE_INTEGER, RESOURCE_LIMIT, RESTRICTED_NUMBERS, STRICT_SYNTAX, StrictJsonError, checkLimits, containsInvalidScalar, containsLoneSurrogate } from "./strict.js";
import type { JsonValue } from "./value.js";

/**
 * A value that cannot be canonical ECL JSON. `ruleId` is the registered finding of the strict JSON
 * profile that the value breaks (IE1-037): `ecl.rule.json-restricted-numbers.v1` for a number
 * outside the profile, `ecl.error.resource-limit-exceeded.v1` for a value beyond a declared
 * budget, and `ecl.rule.json-strict-syntax.v1` for anything else that is not a JSON value, an
 * array hole or `undefined` among them.
 */
export class CanonicalizationError extends Error {
  readonly ruleId: string;

  constructor(message: string, ruleId: string = STRICT_SYNTAX) {
    super(message);
    this.name = "CanonicalizationError";
    this.ruleId = ruleId;
  }
}

const ESCAPES: Record<string, string> = {
  '"': '\\"',
  "\\": "\\\\",
  "\b": "\\b",
  "\f": "\\f",
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
};

function quote(value: string): string {
  if (containsLoneSurrogate(value)) {
    throw new CanonicalizationError("lone Unicode surrogate is prohibited");
  }
  if (containsInvalidScalar(value)) {
    throw new CanonicalizationError("a Unicode noncharacter is prohibited");
  }
  let out = '"';
  let start = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code === 0x22 || code === 0x5c) {
      out += value.slice(start, index);
      const character = value[index] as string;
      out += ESCAPES[character] ?? "\\u" + code.toString(16).padStart(4, "0");
      start = index + 1;
    }
  }
  return out + value.slice(start) + '"';
}

/**
 * Whether `value` is a plain object: its prototype is null or a realm's `Object.prototype` (a
 * null-prototype object used as a prototype is not one: the members it holds would be dropped).
 */
function plainObject(value: object): boolean {
  if (Object.prototype.toString.call(value) !== "[object Object]") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value) as Record<string, unknown> | null;
  if (prototype === null || prototype === Object.prototype) {
    return true;
  }
  if (Object.getPrototypeOf(prototype) !== null || !Object.prototype.hasOwnProperty.call(prototype, "constructor")) {
    return false;
  }
  const constructor = prototype["constructor"];
  return typeof constructor === "function" && constructor.prototype === prototype && constructor.name === "Object";
}

function serialize(value: JsonValue, parts: string[]): void {
  if (value === null) {
    parts.push("null");
  } else if (value === true) {
    parts.push("true");
  } else if (value === false) {
    parts.push("false");
  } else if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new CanonicalizationError("floating-point values are prohibited", RESTRICTED_NUMBERS);
    }
    if (Math.abs(value) > MAX_SAFE_INTEGER) {
      throw new CanonicalizationError(`integer exceeds exact interoperable range: ${value}`, RESTRICTED_NUMBERS);
    }
    // Object.is distinguishes -0, which JSON cannot carry exactly: it serializes as 0.
    parts.push(Object.is(value, -0) ? "0" : String(value));
  } else if (typeof value === "string") {
    parts.push(quote(value));
  } else if (Array.isArray(value)) {
    // Every position, holes included: a hole or `undefined` is no JSON value, so the array is
    // refused rather than written with a missing element or shortened (`[,1]`, `[1]`).
    // An array carries its positions and nothing else: a named member would be dropped.
    if (Object.keys(value).some((key) => !/^(?:0|[1-9][0-9]*)$/.test(key))) {
      throw new CanonicalizationError("an array with a member that is not a position is not a JSON array");
    }
    parts.push("[");
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.prototype.hasOwnProperty.call(value, index)) {
        throw new CanonicalizationError(`array position ${index} is a hole, which is not a JSON value`);
      }
      const item = value[index];
      if (item === undefined) {
        throw new CanonicalizationError(`array position ${index} is undefined, which is not a JSON value`);
      }
      if (index > 0) {
        parts.push(",");
      }
      serialize(item, parts);
    }
    parts.push("]");
  } else if (typeof value === "object") {
    // A JSON object is a plain object, of any realm: a Date, Map, Set, typed array or class
    // instance would be written as its own enumerable members, which is not the value it holds.
    if (!plainObject(value)) {
      throw new CanonicalizationError("only plain objects are JSON objects");
    }
    const names = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    parts.push("{");
    names.forEach((name, index) => {
      const member = value[name];
      if (member === undefined) {
        throw new CanonicalizationError(`member ${JSON.stringify(name)} is undefined, which is not a JSON value`);
      }
      if (index > 0) {
        parts.push(",");
      }
      parts.push(quote(name), ":");
      serialize(member, parts);
    });
    parts.push("}");
  } else {
    throw new CanonicalizationError(`unsupported value type for canonical JSON: ${typeof value}`);
  }
}

/** The canonical bytes of `value`. Throws CanonicalizationError outside the profile. */
export function canonicalize(value: JsonValue): Uint8Array {
  try {
    checkLimits(value);
  } catch (error) {
    if (error instanceof StrictJsonError) {
      throw new CanonicalizationError(error.message, error.ruleId);
    }
    throw error;
  }
  const parts: string[] = [];
  serialize(value, parts);
  const result = utf8(parts.join(""));
  if (result.length > MAX_JSON_BYTES) {
    throw new CanonicalizationError("canonical JSON output exceeds the byte budget", RESOURCE_LIMIT);
  }
  return result;
}

/**
 * The canonical text of `value`. A value that is not JSON (an array hole, `undefined`, a function,
 * a symbol, a bigint, a non-plain object) is refused with CanonicalizationError; any text this
 * returns parses under the strict parser to the value given, with -0 read as 0 (RFC 8785).
 */
export function canonicalText(value: JsonValue): string {
  return new TextDecoder().decode(canonicalize(value));
}

/** The lowercase hexadecimal SHA-256 digest of the canonical bytes (`ecl.digest.sha-256.v1`). */
export function objectDigest(value: JsonValue): string {
  return sha256Hex(canonicalize(value));
}

/** The `ecl.digest.sha-256.v1` digest object of a value. */
export function digestObject(value: JsonValue): { algorithm: string; value: string } {
  return { algorithm: "ecl.digest.sha-256.v1", value: objectDigest(value) };
}
