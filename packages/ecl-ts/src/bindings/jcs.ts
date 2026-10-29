/**
 * RFC 8785 (JSON Canonicalization Scheme) for the content that the binding profiles bind by digest
 * but that ECL does not make: MCP tool definitions, input responses, request state and responses,
 * ACS context entries and modifications, and AARM receipts.
 *
 * ECL's own objects keep the restricted profile of `json/canonical.ts` (IE1-001), which refuses
 * floating-point numbers. Bound content can carry them, so this serializer implements all of
 * RFC 8785:
 *
 * - a number is an IEEE 754 double written as ECMAScript's Number.prototype.toString writes it
 *   (section 3.2.2.3); an integer beyond 2^53 in magnitude is the nearest double, as a parser
 *   that reads it rounds it;
 * - a string keeps every character except the quotation mark, the reverse solidus and the
 *   controls U+0000 to U+001F, which take the short escapes or `\u00xx` in lower case
 *   (section 3.2.2.2);
 * - object members are ordered by the UTF-16 code units of their names (section 3.2.3).
 *
 * A lone surrogate, NaN, an infinity and nesting deeper than 256 levels have no canonical form.
 * For values the strict parser produces, the result is the restricted canonical form.
 */

import { sha256Hex, utf8 } from "../crypto/bytes.js";
import { containsLoneSurrogate } from "../json/strict.js";
import type { JsonValue } from "../json/value.js";

/** A value with no RFC 8785 canonical form. */
export class JcsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JcsError";
  }
}

export const DIGEST_SUITE = "ecl.digest.sha-256.v1";
const MAX_DEPTH = 256;
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
    throw new JcsError("a lone surrogate has no canonical form");
  }
  let out = '"';
  let start = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code === 0x22 || code === 0x5c) {
      out += value.slice(start, index);
      out += ESCAPES[value[index] as string] ?? "\\u" + code.toString(16).padStart(4, "0");
      start = index + 1;
    }
  }
  return out + value.slice(start) + '"';
}

/** ECMAScript's Number.prototype.toString of a finite double (RFC 8785 section 3.2.2.3). */
export function jcsNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw new JcsError("NaN and the infinities have no JSON form");
  }
  return String(value);
}

function serialize(value: JsonValue, depth: number, parts: string[]): void {
  if (depth > MAX_DEPTH) {
    throw new JcsError(`the value nests deeper than ${MAX_DEPTH} levels`);
  }
  if (value === null) {
    parts.push("null");
  } else if (value === true) {
    parts.push("true");
  } else if (value === false) {
    parts.push("false");
  } else if (typeof value === "number") {
    parts.push(jcsNumber(value));
  } else if (typeof value === "string") {
    parts.push(quote(value));
  } else if (Array.isArray(value)) {
    parts.push("[");
    value.forEach((item, index) => {
      if (index > 0) {
        parts.push(",");
      }
      serialize(item, depth + 1, parts);
    });
    parts.push("]");
  } else if (typeof value === "object") {
    const names = Object.keys(value);
    for (const name of names) {
      if (containsLoneSurrogate(name)) {
        throw new JcsError("a lone surrogate has no canonical form");
      }
    }
    names.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    parts.push("{");
    names.forEach((name, index) => {
      if (index > 0) {
        parts.push(",");
      }
      parts.push(quote(name), ":");
      serialize(value[name] as JsonValue, depth + 1, parts);
    });
    parts.push("}");
  } else {
    throw new JcsError(`no JSON form for a value of type ${typeof value}`);
  }
}

/** The RFC 8785 canonical UTF-8 bytes of a JSON value. Throws JcsError. */
export function jcsCanonicalize(value: JsonValue): Uint8Array {
  const parts: string[] = [];
  serialize(value, 0, parts);
  return utf8(parts.join(""));
}

/** The `ecl.digest.sha-256.v1` digest object of the RFC 8785 bytes of `value`. Throws JcsError. */
export function jcsDigest(value: JsonValue): { algorithm: string; value: string } {
  return { algorithm: DIGEST_SUITE, value: sha256Hex(jcsCanonicalize(value)) };
}
