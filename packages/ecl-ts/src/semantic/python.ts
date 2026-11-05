/**
 * Python semantics that the reference's semantic checks rely on, for values that the schema would
 * refuse but that the checks still read: membership tests on arbitrary values, iteration of a
 * value that is not a list, and the integer parsing of digit strings. Where Python raises, these
 * raise MalformedInputError, which a check reports as the reference does (a schema-invalid
 * finding for the whole check).
 */

import { inStringSet, isObject, pythonEquals, PythonTypeError, pythonStr } from "../json/value.js";
import type { JsonValue } from "../json/value.js";
import { CanonicalizationError } from "../json/canonical.js";
import { InstantError } from "../time.js";

export { PythonTypeError } from "../json/value.js";

/** A value Python refuses with ValueError (for example `int()` of an unparsable string). */
export class PythonValueError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PythonValueError";
  }
}

/** A missing member read with `value[key]`, which raises KeyError in Python. */
export class PythonKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PythonKeyError";
  }
}

/** Whether an error mirrors one of the exceptions the reference's checks turn into a finding. */
export function isMalformedInputError(error: unknown): boolean {
  return (
    error instanceof PythonTypeError ||
    error instanceof PythonValueError ||
    error instanceof PythonKeyError ||
    error instanceof InstantError ||
    error instanceof CanonicalizationError
  );
}

/** `value[key]` on an object: the member, or PythonKeyError when it is absent. */
export function item(value: JsonValue | undefined, key: string): JsonValue {
  if (!isObject(value)) {
    throw new PythonTypeError("value is not subscriptable by a string");
  }
  if (!Object.prototype.hasOwnProperty.call(value, key)) {
    throw new PythonKeyError(key);
  }
  return value[key] as JsonValue;
}

/** `needle in set_of_strings`: an unhashable needle raises, as in Python. */
export function inSet(needle: JsonValue | undefined, set: ReadonlySet<string>): boolean {
  return inStringSet(needle, set);
}

/**
 * `needle in container` for a string needle: a substring test in a string, a key test in an
 * object, an equality test in a list. Anything else is not iterable, and Python raises.
 */
export function contains(container: JsonValue | undefined, needle: string): boolean {
  if (typeof container === "string") {
    return container.includes(needle);
  }
  if (Array.isArray(container)) {
    return container.some((entry) => pythonEquals(entry, needle));
  }
  if (isObject(container)) {
    return Object.prototype.hasOwnProperty.call(container, needle);
  }
  throw new PythonTypeError("argument is not iterable");
}

/**
 * `for x in value` for a value Python can iterate: a list's items, a string's characters, an
 * object's keys. Anything else raises.
 */
export function iterate(value: JsonValue | undefined): JsonValue[] {
  if (Array.isArray(value)) {
    return value;
  }
  if (typeof value === "string") {
    return [...value];
  }
  if (isObject(value)) {
    return Object.keys(value);
  }
  throw new PythonTypeError("value is not iterable");
}

/** A hashable key for Python set semantics, where `1`, `1` and `true` are one element. */
export function hashKey(value: JsonValue | undefined): string {
  if (value === undefined || value === null) {
    return "none";
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return "n:" + String(Number(value));
  }
  if (typeof value === "string") {
    return "s:" + value;
  }
  throw new PythonTypeError("unhashable type");
}

/** Python's `set(items)`, raising for an unhashable item. */
export function pythonSet(items: JsonValue[]): Set<string> {
  return new Set(items.map(hashKey));
}

// Characters for which Python's str.isdigit() holds but str.isdecimal() does not, so int() refuses
// them (Unicode 15.0, the reference interpreter's database).
const DIGIT_NOT_DECIMAL: ReadonlyArray<readonly [number, number]> = [
  [0xb2, 0xb3], [0xb9, 0xb9], [0x1369, 0x1371], [0x19da, 0x19da], [0x2070, 0x2070], [0x2074, 0x2079],
  [0x2080, 0x2089], [0x2460, 0x2468], [0x2474, 0x247c], [0x2488, 0x2490], [0x24ea, 0x24ea],
  [0x24f5, 0x24fd], [0x24ff, 0x24ff], [0x2776, 0x277e], [0x2780, 0x2788], [0x278a, 0x2792],
  [0x10a40, 0x10a43], [0x10e60, 0x10e68], [0x11052, 0x1105a], [0x1f100, 0x1f10a],
];
const DECIMAL = /^\p{Nd}$/u;

function isDigitNotDecimal(code: number): boolean {
  return DIGIT_NOT_DECIMAL.some(([low, high]) => code >= low && code <= high);
}

/** Python's `text.isdigit()`. */
export function isDigitString(text: string): boolean {
  if (text === "") {
    return false;
  }
  for (const character of text) {
    const code = character.codePointAt(0) as number;
    if (!DECIMAL.test(character) && !isDigitNotDecimal(code)) {
      return false;
    }
  }
  return true;
}

/** The value of a decimal digit: decimal digits come in aligned runs of 10 from zero. */
function decimalValue(character: string): number {
  let code = character.codePointAt(0) as number;
  let start = code;
  while (DECIMAL.test(String.fromCodePoint(start - 1))) {
    start -= 1;
  }
  code -= start;
  return code % 10;
}

/** Python's `int(text)` for a string that `isDigitString` accepts; raises where Python raises. */
export function parseDigits(text: string): number {
  const characters = [...text];
  if (characters.length > 4300) {
    throw new PythonValueError("exceeds the limit for integer string conversion");
  }
  let value = 0;
  for (const character of characters) {
    if (isDigitNotDecimal(character.codePointAt(0) as number)) {
      throw new PythonValueError("invalid literal for int()");
    }
    value = value * 10 + decimalValue(character);
  }
  return value;
}

/** Python's `str(value)`. */
export function str(value: JsonValue | undefined): string {
  return pythonStr(value);
}
