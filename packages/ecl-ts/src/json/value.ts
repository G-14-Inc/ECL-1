/**
 * JSON values as the strict parser produces them, and the few comparisons the ECL rules need.
 *
 * The reference implementation is Python, and several rules compare values with Python's own
 * semantics (where `true == 1`), while JSON Schema compares them with `bool` and `int` kept apart.
 * Both comparisons are here, named for what they mirror, so that every rule states which one it
 * uses. Members are always read as own properties: a parsed object never answers for a key such as
 * `constructor` or `__proto__` that it does not hold.
 */

export type JsonPrimitive = null | boolean | number | string;
export type JsonArray = JsonValue[];
export interface JsonObject {
  [key: string]: JsonValue;
}
export type JsonValue = JsonPrimitive | JsonArray | JsonObject;

const hasOwnProperty = Object.prototype.hasOwnProperty;

/** True for a JSON object: a non-null, non-array object. */
export function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** True for a JSON array. */
export function isArray(value: unknown): value is JsonArray {
  return Array.isArray(value);
}

/** True for a string. */
export function isString(value: unknown): value is string {
  return typeof value === "string";
}

/** True for an integer number, never a boolean (Python's `type(x) is int`). */
export function isInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value);
}

/** Python's `isinstance(x, int)`: an integer or a boolean, since `bool` subclasses `int` there. */
export function isPythonInt(value: unknown): value is number | boolean {
  return isInteger(value) || typeof value === "boolean";
}

/** Whether `object` holds `key` as its own member. */
export function has(object: JsonObject, key: string): boolean {
  return hasOwnProperty.call(object, key);
}

/** The own member `key` of `value` when `value` is an object, else undefined (Python `dict.get`). */
export function get(value: unknown, key: string): JsonValue | undefined {
  if (!isObject(value) || !hasOwnProperty.call(value, key)) {
    return undefined;
  }
  return value[key];
}

/** The member at `path` when every step is an object holding the next key. */
export function getPath(value: unknown, ...path: string[]): JsonValue | undefined {
  let found: unknown = value;
  for (const step of path) {
    found = get(found, step);
    if (found === undefined) {
      return undefined;
    }
  }
  return found as JsonValue;
}

/** The string at `path`, or undefined when it is absent or not a string. */
export function textAt(value: unknown, ...path: string[]): string | undefined {
  const found = getPath(value, ...path);
  return typeof found === "string" ? found : undefined;
}

/** The object at `path`, or undefined when it is absent or not an object. */
export function objectAt(value: unknown, ...path: string[]): JsonObject | undefined {
  const found = getPath(value, ...path);
  return isObject(found) ? found : undefined;
}

/** The own keys of an object, in insertion order. */
export function keys(object: JsonObject): string[] {
  return Object.keys(object);
}

/** Python truthiness of a JSON value: null, false, 0, "", [] and {} are false. */
export function truthy(value: JsonValue | undefined): boolean {
  if (value === undefined || value === null || value === false) {
    return false;
  }
  if (typeof value === "number") {
    return value !== 0;
  }
  if (typeof value === "string") {
    return value.length > 0;
  }
  if (Array.isArray(value)) {
    return value.length > 0;
  }
  if (typeof value === "object") {
    return Object.keys(value).length > 0;
  }
  return true;
}

/**
 * Python's `==` on JSON values: numbers and booleans compare by value (`true == 1`), strings only
 * with strings, arrays element by element and objects by their key sets and values.
 */
export function pythonEquals(left: JsonValue | undefined, right: JsonValue | undefined): boolean {
  // An absent member reads as None in Python, the same as null.
  if (left === undefined) {
    left = null;
  }
  if (right === undefined) {
    right = null;
  }
  const leftNumeric = typeof left === "number" || typeof left === "boolean";
  const rightNumeric = typeof right === "number" || typeof right === "boolean";
  if (leftNumeric || rightNumeric) {
    return leftNumeric && rightNumeric && Number(left) === Number(right);
  }
  return structuralEquals(left, right, pythonEquals);
}

/**
 * JSON Schema equality as python-jsonschema implements it: like Python's `==`, except that a
 * boolean never equals a number.
 */
export function schemaEquals(left: JsonValue | undefined, right: JsonValue | undefined): boolean {
  if (left === undefined || right === undefined) {
    return left === right;
  }
  if (typeof left === "boolean" || typeof right === "boolean") {
    return left === right;
  }
  if (typeof left === "number" || typeof right === "number") {
    return left === right;
  }
  return structuralEquals(left, right, schemaEquals);
}

function structuralEquals(
  left: JsonValue,
  right: JsonValue,
  equals: (a: JsonValue, b: JsonValue) => boolean,
): boolean {
  if (left === null || right === null) {
    return left === right;
  }
  if (typeof left === "string" || typeof right === "string") {
    return left === right;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) {
      return false;
    }
    return left.every((item, index) => equals(item, right[index] as JsonValue));
  }
  if (typeof left === "object" && typeof right === "object") {
    const leftKeys = Object.keys(left);
    if (leftKeys.length !== Object.keys(right).length) {
      return false;
    }
    return leftKeys.every(
      (key) => hasOwnProperty.call(right, key) && equals(left[key] as JsonValue, right[key] as JsonValue),
    );
  }
  return false;
}

/** A type error with Python's meaning: an operation was given a value it cannot handle. */
export class PythonTypeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PythonTypeError";
  }
}

/**
 * Python's `value in a_set_of_strings`. An object or array is unhashable in Python, so the test
 * raises there; it raises here too, and the caller handles it as the reference does.
 */
export function inStringSet(value: JsonValue | undefined, set: ReadonlySet<string>): boolean {
  if (value !== undefined && value !== null && typeof value === "object") {
    throw new PythonTypeError("unhashable type in a set membership test");
  }
  return typeof value === "string" && set.has(value);
}

/** Python's `value in a_list`, which compares with `==`. */
export function inList(value: JsonValue | undefined, list: readonly JsonValue[]): boolean {
  return list.some((item) => pythonEquals(item, value));
}

/**
 * Compare two strings by Unicode code point, as Python orders `str`. JavaScript's own `<`
 * compares UTF-16 code units, which orders characters outside the Basic Multilingual Plane
 * before some inside it.
 */
export function compareCodePoints(left: string, right: string): number {
  const a = left[Symbol.iterator]();
  const b = right[Symbol.iterator]();
  for (;;) {
    const x = a.next();
    const y = b.next();
    if (x.done || y.done) {
      return x.done && y.done ? 0 : x.done ? -1 : 1;
    }
    const cx = x.value.codePointAt(0) as number;
    const cy = y.value.codePointAt(0) as number;
    if (cx !== cy) {
      return cx < cy ? -1 : 1;
    }
  }
}

/** Compare two strings by UTF-16 code unit, the RFC 8785 member order. */
export function compareCodeUnits(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

/** The number of Unicode code points in a string (Python's `len`, JSON Schema's length). */
export function codePointLength(value: string): number {
  let count = 0;
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff && index + 1 < value.length) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        index += 1;
      }
    }
    count += 1;
  }
  return count;
}

/** Python's `repr` of a string, used where the reference orders values by their `str`. */
export function pythonRepr(value: JsonValue): string {
  if (value === null) {
    return "None";
  }
  if (value === true) {
    return "True";
  }
  if (value === false) {
    return "False";
  }
  if (typeof value === "number") {
    return String(value);
  }
  if (typeof value === "string") {
    return pythonStringRepr(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(pythonRepr).join(", ") + "]";
  }
  return (
    "{" +
    Object.keys(value)
      .map((key) => pythonStringRepr(key) + ": " + pythonRepr(value[key] as JsonValue))
      .join(", ") +
    "}"
  );
}

/** Python's `str` of a JSON value: a string is itself, anything else its `repr`. */
export function pythonStr(value: JsonValue | undefined): string {
  if (value === undefined) {
    return "None";
  }
  return typeof value === "string" ? value : pythonRepr(value);
}

const NON_PRINTABLE = /[\p{C}\p{Z}]/u;

function pythonStringRepr(value: string): string {
  const quote = value.includes("'") && !value.includes('"') ? '"' : "'";
  let out = quote;
  for (const character of value) {
    const code = character.codePointAt(0) as number;
    if (character === quote || character === "\\") {
      out += "\\" + character;
    } else if (character === "\t") {
      out += "\\t";
    } else if (character === "\n") {
      out += "\\n";
    } else if (character === "\r") {
      out += "\\r";
    } else if (code < 0x20 || code === 0x7f) {
      out += "\\x" + code.toString(16).padStart(2, "0");
    } else if (code < 0x7f) {
      out += character;
    } else if (character !== " " && NON_PRINTABLE.test(character)) {
      if (code <= 0xff) {
        out += "\\x" + code.toString(16).padStart(2, "0");
      } else if (code <= 0xffff) {
        out += "\\u" + code.toString(16).padStart(4, "0");
      } else {
        out += "\\U" + code.toString(16).padStart(8, "0");
      }
    } else {
      out += character;
    }
  }
  return out + quote;
}
