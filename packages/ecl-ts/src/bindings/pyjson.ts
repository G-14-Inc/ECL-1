/**
 * JSON values as Python holds them, and `parsePyJson`, which reads JSON text as Python's
 * `json.loads` (its C scanner) reads it with a hook that refuses a repeated member name. That is
 * not the strict profile of ECL objects: a number with a fraction or an exponent is a double (and
 * may overflow to an infinity), NaN, Infinity and -Infinity are accepted, an integer of any size
 * is exact, and a `\u` escape may leave a lone surrogate in a string. Raw control characters in a
 * string, a byte-order mark and anything after the value are refused. The JOSE code reads a JWS
 * segment under the strict profile instead (OA1-007, `jose.ts`).
 *
 * The values keep Python's two kinds of number apart: an integer is a `bigint` and a double is a
 * `number`. `toPy` turns a strictly parsed ECL value, whose numbers are all integers, into the same
 * form, `pyEquals` is Python's `==` across the two, and `pySameJson` is the reference's
 * `same_json`, under which a boolean never equals a number.
 */

import { PythonValueError } from "../semantic/python.js";
import type { JsonValue } from "../json/value.js";

/** A JSON value as Python holds it: integers are `bigint`, doubles are `number`. */
export type PyValue = null | boolean | bigint | number | string | PyValue[] | PyObject;
export interface PyObject {
  [key: string]: PyValue;
}

/** Text that Python's `json.loads` refuses, or an object that repeats a member name. */
export class PyJsonError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PyJsonError";
  }
}

/** Python 3.12 refuses to convert an integer of more digits than this (ValueError). */
const MAX_INTEGER_DIGITS = 4300;
const WHITESPACE = new Set([0x20, 0x09, 0x0a, 0x0d]);
const SIMPLE_ESCAPES: Record<string, string> = {
  '"': '"',
  "\\": "\\",
  "/": "/",
  b: "\b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
};

function defineMember(target: PyObject, name: string, value: PyValue): void {
  Object.defineProperty(target, name, { value, enumerable: true, writable: true, configurable: true });
}

function isDigit(code: number): boolean {
  return code >= 0x30 && code <= 0x39;
}

function hexValue(code: number): number {
  if (code >= 0x30 && code <= 0x39) {
    return code - 0x30;
  }
  if (code >= 0x61 && code <= 0x66) {
    return code - 0x61 + 10;
  }
  if (code >= 0x41 && code <= 0x46) {
    return code - 0x41 + 10;
  }
  return -1;
}

type Frame = { readonly kind: "array"; readonly items: PyValue[] } | { readonly kind: "object"; readonly pairs: Array<[string, PyValue]>; key: string };

/** Parse JSON text the way the reference parses a JWS segment. Throws PyJsonError. */
export function parsePyJson(text: string): PyValue {
  if (text.charCodeAt(0) === 0xfeff) {
    throw new PyJsonError("Unexpected UTF-8 BOM");
  }
  let index = 0;
  const skip = (): void => {
    while (index < text.length && WHITESPACE.has(text.charCodeAt(index))) {
      index += 1;
    }
  };

  const parseString = (): string => {
    // `index` is just after the opening quotation mark.
    let out = "";
    let start = index;
    for (;;) {
      if (index >= text.length) {
        throw new PyJsonError("Unterminated string");
      }
      const code = text.charCodeAt(index);
      if (code === 0x22) {
        out += text.slice(start, index);
        index += 1;
        return out;
      }
      if (code < 0x20) {
        throw new PyJsonError("Invalid control character");
      }
      if (code !== 0x5c) {
        index += 1;
        continue;
      }
      out += text.slice(start, index);
      index += 1;
      if (index >= text.length) {
        throw new PyJsonError("Unterminated string");
      }
      const escape = text[index] as string;
      if (escape !== "u") {
        const mapped = SIMPLE_ESCAPES[escape];
        if (mapped === undefined) {
          throw new PyJsonError("Invalid \\escape");
        }
        out += mapped;
        index += 1;
        start = index;
        continue;
      }
      // Four hexadecimal digits. A high surrogate followed by an escaped low surrogate is one
      // character in Python, and the same two code units here; any other surrogate stays lone.
      if (index + 5 >= text.length) {
        throw new PyJsonError("Invalid \\uXXXX escape");
      }
      let unit = 0;
      for (let digit = 1; digit <= 4; digit += 1) {
        const value = hexValue(text.charCodeAt(index + digit));
        if (value < 0) {
          throw new PyJsonError("Invalid \\uXXXX escape");
        }
        unit = (unit << 4) | value;
      }
      index += 5;
      out += String.fromCharCode(unit);
      if (unit >= 0xd800 && unit <= 0xdbff && index + 6 < text.length && text[index] === "\\" && text[index + 1] === "u") {
        let low = 0;
        for (let digit = 2; digit <= 5; digit += 1) {
          const value = hexValue(text.charCodeAt(index + digit));
          if (value < 0) {
            throw new PyJsonError("Invalid \\uXXXX escape");
          }
          low = (low << 4) | value;
        }
        if (low >= 0xdc00 && low <= 0xdfff) {
          out += String.fromCharCode(low);
          index += 6;
        }
      }
      start = index;
    }
  };

  const parseNumber = (): PyValue => {
    const begin = index;
    if (text.charCodeAt(index) === 0x2d) {
      index += 1;
      if (index >= text.length) {
        throw new PyJsonError("Expecting value");
      }
    }
    const first = text.charCodeAt(index);
    if (first >= 0x31 && first <= 0x39) {
      index += 1;
      while (index < text.length && isDigit(text.charCodeAt(index))) {
        index += 1;
      }
    } else if (first === 0x30) {
      index += 1;
    } else {
      throw new PyJsonError("Expecting value");
    }
    let float = false;
    if (index < text.length - 1 && text.charCodeAt(index) === 0x2e && isDigit(text.charCodeAt(index + 1))) {
      float = true;
      index += 2;
      while (index < text.length && isDigit(text.charCodeAt(index))) {
        index += 1;
      }
    }
    if (index < text.length - 1 && (text[index] === "e" || text[index] === "E")) {
      const exponentStart = index;
      index += 1;
      if (index < text.length - 1 && (text[index] === "-" || text[index] === "+")) {
        index += 1;
      }
      while (index < text.length && isDigit(text.charCodeAt(index))) {
        index += 1;
      }
      if (isDigit(text.charCodeAt(index - 1))) {
        float = true;
      } else {
        index = exponentStart;
      }
    }
    const literal = text.slice(begin, index);
    if (float) {
      return Number(literal);
    }
    const digits = literal.startsWith("-") ? literal.length - 1 : literal.length;
    if (digits > MAX_INTEGER_DIGITS) {
      throw new PythonValueError("Exceeds the limit (4300 digits) for integer string conversion");
    }
    return BigInt(literal);
  };

  const startsWith = (word: string): boolean => text.startsWith(word, index);

  /** The scalar at `index`, or undefined when a container starts there. */
  const scalar = (): PyValue | undefined => {
    if (index >= text.length) {
      throw new PyJsonError("Expecting value");
    }
    switch (text[index]) {
      case '"':
        index += 1;
        return parseString();
      case "{":
      case "[":
        return undefined;
      case "n":
        if (startsWith("null")) {
          index += 4;
          return null;
        }
        break;
      case "t":
        if (startsWith("true")) {
          index += 4;
          return true;
        }
        break;
      case "f":
        if (startsWith("false")) {
          index += 5;
          return false;
        }
        break;
      case "N":
        if (startsWith("NaN")) {
          index += 3;
          return Number.NaN;
        }
        break;
      case "I":
        if (startsWith("Infinity")) {
          index += 8;
          return Number.POSITIVE_INFINITY;
        }
        break;
      case "-":
        if (startsWith("-Infinity")) {
          index += 9;
          return Number.NEGATIVE_INFINITY;
        }
        break;
      default:
        break;
    }
    return parseNumber();
  };

  /** Read `"name":` and the whitespace after it; `index` is then at the member's value. */
  const memberName = (): string => {
    if (text[index] !== '"') {
      throw new PyJsonError("Expecting property name enclosed in double quotes");
    }
    index += 1;
    const name = parseString();
    skip();
    if (text[index] !== ":") {
      throw new PyJsonError("Expecting ':' delimiter");
    }
    index += 1;
    skip();
    return name;
  };

  const close = (frame: Frame): PyValue => {
    if (frame.kind === "array") {
      return frame.items;
    }
    const object: PyObject = {};
    const seen = new Set<string>();
    for (const [name, value] of frame.pairs) {
      if (seen.has(name)) {
        throw new PyJsonError("a JWS segment repeats a member name");
      }
      seen.add(name);
      defineMember(object, name, value);
    }
    return object;
  };

  // An explicit stack: a token of 16 KiB can nest thousands of levels, beyond a safe call depth.
  const stack: Frame[] = [];
  let result: PyValue = null;
  skip();
  reading: for (;;) {
    // A value starts at `index`.
    let value = scalar();
    if (value === undefined) {
      const opening = text[index];
      index += 1;
      skip();
      if (opening === "[") {
        if (text[index] !== "]") {
          stack.push({ kind: "array", items: [] });
          continue;
        }
        index += 1;
        value = [];
      } else {
        if (text[index] !== "}") {
          stack.push({ kind: "object", pairs: [], key: memberName() });
          continue;
        }
        index += 1;
        value = {};
      }
    }
    // A value is complete: give it to its container, then read what follows it there.
    for (;;) {
      const frame = stack[stack.length - 1];
      if (frame === undefined) {
        result = value;
        break reading;
      }
      if (frame.kind === "array") {
        frame.items.push(value);
      } else {
        frame.pairs.push([frame.key, value]);
      }
      skip();
      const character = text[index];
      if (character === ",") {
        index += 1;
        skip();
        if (frame.kind === "object") {
          frame.key = memberName();
        }
        continue reading;
      }
      if (character !== (frame.kind === "array" ? "]" : "}")) {
        throw new PyJsonError("Expecting ',' delimiter");
      }
      index += 1;
      stack.pop();
      value = close(frame);
    }
  }
  skip();
  if (index !== text.length) {
    throw new PyJsonError("Extra data");
  }
  return result;
}

/** A strictly parsed ECL value in the form of `PyValue`: every number is an integer. */
export function toPy(value: JsonValue | undefined): PyValue {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value === "number") {
    return BigInt(value);
  }
  if (typeof value === "boolean" || typeof value === "string") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(toPy);
  }
  const object: PyObject = {};
  for (const name of Object.keys(value)) {
    defineMember(object, name, toPy(value[name]));
  }
  return object;
}

function isPyObject(value: PyValue | undefined): value is PyObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Python's `==`: a boolean is the integer 0 or 1, an integer equals a double only when the double
 * is finite and has exactly its value, NaN equals nothing, a string equals only a string, and
 * lists and dicts compare member by member. An absent member reads as None.
 */
export function pyEquals(left: PyValue | undefined, right: PyValue | undefined): boolean {
  const a = left === undefined ? null : left;
  const b = right === undefined ? null : right;
  const numeric = (value: PyValue): boolean => typeof value === "boolean" || typeof value === "bigint" || typeof value === "number";
  if (numeric(a) || numeric(b)) {
    if (!numeric(a) || !numeric(b)) {
      return false;
    }
    if (typeof a === "number" && typeof b === "number") {
      return a === b;
    }
    if (typeof a === "number" || typeof b === "number") {
      const float = (typeof a === "number" ? a : b) as number;
      const other = typeof a === "number" ? b : a;
      const integer = typeof other === "boolean" ? (other ? 1n : 0n) : (other as bigint);
      return Number.isInteger(float) && BigInt(float) === integer;
    }
    const x = typeof a === "boolean" ? (a ? 1n : 0n) : (a as bigint);
    const y = typeof b === "boolean" ? (b ? 1n : 0n) : (b as bigint);
    return x === y;
  }
  if (a === null || b === null) {
    return a === b;
  }
  if (typeof a === "string" || typeof b === "string") {
    return a === b;
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) {
      return false;
    }
    return a.every((item, position) => pyEquals(item, b[position]));
  }
  if (isPyObject(a) && isPyObject(b)) {
    const names = Object.keys(a);
    if (names.length !== Object.keys(b).length) {
      return false;
    }
    return names.every((name) => Object.prototype.hasOwnProperty.call(b, name) && pyEquals(a[name], b[name]));
  }
  return false;
}

/**
 * The reference's `same_json` on values as Python holds them: two values of the same Python type
 * that are equal, so a boolean never equals a number and an integer never equals a double. An
 * absent member reads as None, as with `pyEquals`.
 */
export function pySameJson(left: PyValue | undefined, right: PyValue | undefined): boolean {
  const a = left === undefined ? null : left;
  const b = right === undefined ? null : right;
  if (a === null || b === null) {
    return a === b;
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) {
      return false;
    }
    return a.every((item, position) => pySameJson(item, b[position]));
  }
  if (isPyObject(a) || isPyObject(b)) {
    if (!isPyObject(a) || !isPyObject(b)) {
      return false;
    }
    const names = Object.keys(a);
    if (names.length !== Object.keys(b).length) {
      return false;
    }
    return names.every((name) => Object.prototype.hasOwnProperty.call(b, name) && pySameJson(a[name], b[name]));
  }
  return typeof a === typeof b && a === b;
}

/** Python's `value in a_list`: equality with any item. */
export function pyIn(value: PyValue | undefined, list: readonly PyValue[]): boolean {
  return list.some((item) => pyEquals(item, value));
}
