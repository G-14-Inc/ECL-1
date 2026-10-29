/**
 * Strict JSON input (INTEGRITY-ENVELOPE-1 section 1, IE1-001 to IE1-004 and IE1-037).
 *
 * Input is UTF-8 without a byte-order mark. Numbers are integers within the exact interoperable
 * range (|n| <= 2^53 - 1), never fractions, exponents, `-0` or the constants NaN and Infinity.
 * An object never repeats a member name, and no string or member name holds a surrogate code
 * point or a noncharacter. The parser also enforces finite budgets: 64 MiB of input, 256 levels
 * of nesting and one million values.
 *
 * The checks run in the order of IE1-037, and the first that fails decides the one finding: the
 * byte budget; UTF-8, the byte-order mark and the grammar (a grammar error stops the parse); the
 * nesting and value budgets; the Unicode scalar values of every string and member name; repeated
 * member names; numbers. A defect of the last four kinds is noted while the whole text is read
 * and reported only after the checks before it pass, so the values of a repeated member name are
 * checked too and the position of a defect in the text never decides the finding.
 *
 * The parse is one pass that counts values and nesting as it reads them (IE1-029). While the input
 * is within the budgets it builds the value; at the first value beyond a budget it drops what it
 * has built and reads the rest of the text for the grammar alone, keeping only the kind of each
 * open container, so the memory that a refusal costs follows the budgets, not the size of the
 * input. Bytes are parsed as bytes: they are checked as UTF-8 a slice at a time, and only the
 * strings of a value being built are decoded, so no decoded copy of the input is made. Each budget
 * must be a safe integer of at least 1 (IE1-028): NaN, an infinity, a fraction and any value that
 * is not a number are refused before the input is read.
 */

import type { JsonArray, JsonObject, JsonValue } from "./value.js";

export const MAX_SAFE_INTEGER = 9007199254740991;
/**
 * The declared limits of the strict parser (IE1-028): encoded bytes, nesting depth counted from 0
 * for the top-level value, and values. A caller may configure others, each an exact positive
 * integer within its ceiling; any other configured limit is refused before any input is read.
 */
export const MAX_JSON_BYTES = 64 * 1024 * 1024;
export const MAX_JSON_DEPTH = 256;
export const MAX_JSON_NODES = 1_000_000;
export const MAX_JSON_BYTES_CEILING = 2_147_483_647;
export const MAX_JSON_DEPTH_CEILING = 4_096;
export const MAX_JSON_NODES_CEILING = 100_000_000;
/**
 * The nesting depth (the top-level value at 0) to which the grammar check reads an input that is
 * beyond the budgets: a value nested deeper than this and than the nesting budget ends the check
 * with a resource-limit refusal (IE1-037, check 2). The reference has the same bound
 * (`ecl_reference.canonical.GRAMMAR_NESTING_BOUND`).
 */
export const GRAMMAR_NESTING_BOUND = 10_000;
/** UTF-8 input is checked in slices of this many bytes, so the check holds no decoded copy of it. */
const UTF8_SLICE = 64 * 1024;

/** Why strict input was refused. */
export type StrictJsonErrorKind =
  | "duplicate-member"
  | "number"
  | "constant"
  | "syntax"
  | "encoding"
  | "byte-order-mark"
  | "surrogate"
  | "noncharacter"
  | "budget"
  | "configuration";

/**
 * The registered findings of IE1-037: three rules, the error of a declared limit, and the error of
 * a configured limit that is not an exact positive integer within its ceiling (IE1-028).
 */
export const STRICT_SYNTAX = "ecl.rule.json-strict-syntax.v1";
export const DUPLICATE_MEMBERS = "ecl.rule.json-no-duplicate-members.v1";
export const RESTRICTED_NUMBERS = "ecl.rule.json-restricted-numbers.v1";
export const RESOURCE_LIMIT = "ecl.error.resource-limit-exceeded.v1";
export const CONFIGURATION_INVALID = "ecl.error.configuration-invalid.v1";

const RULES: Record<StrictJsonErrorKind, string> = {
  "duplicate-member": DUPLICATE_MEMBERS,
  number: RESTRICTED_NUMBERS,
  constant: STRICT_SYNTAX,
  syntax: STRICT_SYNTAX,
  encoding: STRICT_SYNTAX,
  "byte-order-mark": STRICT_SYNTAX,
  surrogate: STRICT_SYNTAX,
  noncharacter: STRICT_SYNTAX,
  budget: RESOURCE_LIMIT,
  configuration: CONFIGURATION_INVALID,
};

/** A refusal of strict JSON input. `ruleId` is the registered finding that the refusal names. */
export class StrictJsonError extends Error {
  readonly kind: StrictJsonErrorKind;
  readonly ruleId: string;
  readonly offset: number | undefined;

  constructor(kind: StrictJsonErrorKind, message: string, offset?: number) {
    super(message);
    this.name = "StrictJsonError";
    this.kind = kind;
    this.ruleId = RULES[kind];
    this.offset = offset;
  }
}

/**
 * Budgets for one parse. Each must be an exact integer from 1 to its ceiling; an absent one
 * (`undefined`) is the default. `null` is not absent: it is a configuration error.
 */
export interface StrictJsonLimits {
  maxBytes?: number;
  maxDepth?: number;
  maxNodes?: number;
}

const CEILINGS: Readonly<Record<string, number>> = { maxBytes: MAX_JSON_BYTES_CEILING, maxDepth: MAX_JSON_DEPTH_CEILING, maxNodes: MAX_JSON_NODES_CEILING };

/**
 * A configured budget (IE1-028): an exact integer from 1 to the ceiling of the limit. NaN, which no
 * comparison refuses, the infinities, which every input is below, fractions, null, strings and
 * every other value that is not a number are refused, never compared, so that no configuration
 * turns a finite budget into none; so is a value above the ceiling. The refusal is the
 * configuration-error code, `ecl.error.configuration-invalid.v1`.
 */
function checkedLimit(name: string, value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw new StrictJsonError("configuration", `strict JSON limit ${name} must be an integer of at least 1, not ${typeof value === "number" ? String(value) : value === null ? "null" : typeof value}`);
  }
  const ceiling = CEILINGS[name] ?? MAX_JSON_NODES_CEILING;
  if (value > ceiling) {
    throw new StrictJsonError("configuration", `strict JSON limit ${name} must be at most ${ceiling}, its ceiling`);
  }
  return value;
}

/** The configured budget when one is given, else the declared default (`undefined` alone is absent). */
function limitOrDefault(name: string, value: unknown, fallback: number): number {
  return value === undefined ? fallback : checkedLimit(name, value);
}

const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Check 2's encoding: `input` is UTF-8, decoded a slice at a time and never held whole. */
function checkUtf8(input: Uint8Array): void {
  let ascii = true;
  for (let index = 0; index < input.length && ascii; index += 1) {
    ascii = (input[index] as number) < 0x80;
  }
  if (ascii) {
    return;
  }
  const slices = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  try {
    for (let start = 0; start < input.length; start += UTF8_SLICE) {
      // A sequence cut at the end of a slice is completed by the next one.
      slices.decode(input.subarray(start, Math.min(start + UTF8_SLICE, input.length)), { stream: true });
    }
    slices.decode();
  } catch {
    throw new StrictJsonError("encoding", "strict JSON input is not UTF-8");
  }
}

/**
 * Parse strict JSON from bytes (UTF-8) or from a string. Throws StrictJsonError.
 * Every member is defined as an own property, so a name such as `__proto__` is an ordinary
 * member and never reaches a prototype.
 */
export function parseStrictJson(input: Uint8Array | string, limits: StrictJsonLimits = {}): JsonValue {
  const given: StrictJsonLimits = typeof limits === "object" && limits !== null ? limits : {};
  const maxBytes = limitOrDefault("maxBytes", given.maxBytes, MAX_JSON_BYTES);
  const maxDepth = limitOrDefault("maxDepth", given.maxDepth, MAX_JSON_DEPTH);
  const maxNodes = limitOrDefault("maxNodes", given.maxNodes, MAX_JSON_NODES);
  let parser: Parser;
  if (typeof input === "string") {
    if (utf8Length(input, maxBytes) > maxBytes) {
      throw new StrictJsonError("budget", "strict JSON input exceeds the byte budget");
    }
    if (hasLoneSurrogate(input)) {
      throw new StrictJsonError("encoding", "strict JSON input is not valid Unicode");
    }
    if (input.charCodeAt(0) === 0xfeff) {
      throw new StrictJsonError("byte-order-mark", "strict JSON input begins with a byte-order mark");
    }
    parser = new Parser(input, undefined, maxDepth, maxNodes);
  } else {
    if (input.length > maxBytes) {
      throw new StrictJsonError("budget", "strict JSON input exceeds the byte budget");
    }
    checkUtf8(input);
    if (input[0] === 0xef && input[1] === 0xbb && input[2] === 0xbf) {
      throw new StrictJsonError("byte-order-mark", "strict JSON input begins with a byte-order mark");
    }
    parser = new Parser(undefined, input, maxDepth, maxNodes);
  }
  const value = parser.parseDocument();
  // IE1-037, checks 3 to 6, in order, over every value the text holds.
  if (parser.budget !== undefined) {
    throw parser.budget;
  }
  if (parser.scalar !== undefined) {
    throw parser.scalar;
  }
  if (parser.duplicate !== undefined) {
    throw parser.duplicate;
  }
  if (parser.number !== undefined) {
    throw parser.number;
  }
  return value as JsonValue;
}

function utf8Length(text: string, stopAbove: number): number {
  let length = 0;
  for (let index = 0; index < text.length && length <= stopAbove; index += 1) {
    const unit = text.charCodeAt(index);
    if (unit < 0x80) {
      length += 1;
    } else if (unit < 0x800) {
      length += 2;
    } else if (unit >= 0xd800 && unit <= 0xdbff) {
      length += 4;
      index += 1;
    } else {
      length += 3;
    }
  }
  return length;
}

/** Whether a code point is one of the 66 Unicode noncharacters (IE1-002). */
function isNoncharacter(code: number): boolean {
  return (code >= 0xfdd0 && code <= 0xfdef) || (code & 0xfffe) === 0xfffe;
}

/** The refusal of a string or member name that holds a lone surrogate or a noncharacter. */
function scalarProblem(text: string): StrictJsonError | undefined {
  for (let index = 0; index < text.length; index += 1) {
    const unit = text.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return new StrictJsonError("surrogate", "lone Unicode surrogate is prohibited");
      }
      const code = 0x10000 + ((unit - 0xd800) << 10) + (next - 0xdc00);
      if (isNoncharacter(code)) {
        return new StrictJsonError("noncharacter", `Unicode noncharacter U+${code.toString(16).toUpperCase()} is prohibited`);
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return new StrictJsonError("surrogate", "lone Unicode surrogate is prohibited");
    } else if (isNoncharacter(unit)) {
      return new StrictJsonError("noncharacter", `Unicode noncharacter U+${unit.toString(16).toUpperCase().padStart(4, "0")} is prohibited`);
    }
  }
  return undefined;
}

function hasLoneSurrogate(text: string): boolean {
  for (let index = 0; index < text.length; index += 1) {
    const unit = text.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return true;
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

interface Frame {
  container: JsonObject | JsonArray;
  isObject: boolean;
  /** For objects: the member names in order, to find a repeated one when the object closes. */
  names: string[];
  pendingKey: string | undefined;
}

const NODE_BUDGET = "JSON value exceeds the canonical node budget";
/** The message of a refusal at the declared value budget, by which a caller that passes a
 * remaining budget as `maxNodes` tells that refusal from the others (EBMP2-062). */
export const NODE_BUDGET_MESSAGE = NODE_BUDGET;
const NESTING_BUDGET = "JSON value exceeds the canonical nesting budget";

/**
 * One parse over a string or over UTF-8 bytes. Every delimiter of the grammar is ASCII, and the
 * bytes of a multi-byte UTF-8 sequence are all above 0x7F, so the grammar reads the same code
 * values in both; only the strings of a value being built are decoded.
 */
class Parser {
  private readonly text: string | undefined;
  private readonly bytes: Uint8Array | undefined;
  private readonly length: number;
  private readonly maxDepth: number;
  private readonly maxNodes: number;
  /** The parser's own nesting bound for the grammar check (IE1-037, check 2). */
  private readonly bound: number;
  private index = 0;
  /** True while the input is within the budgets and values are built. */
  private building = true;
  /** Every value read so far, containers included (IE1-037, check 3). */
  private nodes = 0;
  /** The first budget the input exceeds (check 3). */
  budget: StrictJsonError | undefined;
  /** The first string or member name that holds an invalid scalar value (check 4). */
  scalar: StrictJsonError | undefined;
  /** The first repeated member name (check 5). */
  duplicate: StrictJsonError | undefined;
  /** The first number outside the restricted profile (check 6). */
  number: StrictJsonError | undefined;

  constructor(text: string | undefined, bytes: Uint8Array | undefined, maxDepth: number, maxNodes: number) {
    this.text = text;
    this.bytes = bytes;
    this.length = text !== undefined ? text.length : (bytes as Uint8Array).length;
    this.maxDepth = maxDepth;
    this.maxNodes = maxNodes;
    this.bound = Math.max(GRAMMAR_NESTING_BOUND, maxDepth);
  }

  /** The code value at `index`: a UTF-16 code unit or a byte; NaN past the end. */
  private code(index: number): number {
    if (this.text !== undefined) {
      return this.text.charCodeAt(index);
    }
    return index < this.length ? ((this.bytes as Uint8Array)[index] as number) : NaN;
  }

  /** The text from `start` to `end`, which begin and end at ASCII positions. */
  private piece(start: number, end: number): string {
    if (this.text !== undefined) {
      return this.text.slice(start, end);
    }
    return decoder.decode((this.bytes as Uint8Array).subarray(start, end));
  }

  /** Whether the ASCII word `word` is at the current position. */
  private at(word: string): boolean {
    for (let offset = 0; offset < word.length; offset += 1) {
      if (this.code(this.index + offset) !== word.charCodeAt(offset)) {
        return false;
      }
    }
    return true;
  }

  /** A string read from the text, noting its first invalid scalar value. */
  private checkedString(): string {
    const value = this.readString();
    if (this.scalar === undefined) {
      this.scalar = scalarProblem(value);
    }
    return value;
  }

  /** The value of the document, or undefined once the input is beyond a budget. */
  parseDocument(): JsonValue | undefined {
    this.skipWhitespace();
    const value = this.parseValue();
    this.skipWhitespace();
    if (this.index !== this.length) {
      throw this.syntax("extra data after the JSON value");
    }
    return value;
  }

  private syntax(message: string): StrictJsonError {
    return new StrictJsonError("syntax", `invalid strict JSON: ${message}`, this.index);
  }

  private skipWhitespace(): void {
    for (;;) {
      const c = this.code(this.index);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) {
        this.index += 1;
      } else {
        return;
      }
    }
  }

  /**
   * An iterative parse: nesting depth never consumes the JavaScript call stack. `kinds` holds the
   * open containers for the grammar (true for an object); `frames` holds the containers being
   * built while the input is within the budgets, and is dropped at the first value beyond one.
   */
  private parseValue(): JsonValue | undefined {
    const kinds: boolean[] = [];
    let frames: Frame[] = [];
    for (;;) {
      // A value begins at the current position, nested in the open containers.
      this.skipWhitespace();
      const depth = kinds.length;
      this.nodes += 1;
      if (this.building && (this.nodes > this.maxNodes || depth > this.maxDepth)) {
        this.budget = new StrictJsonError("budget", this.nodes > this.maxNodes ? NODE_BUDGET : NESTING_BUDGET, this.index);
        this.building = false;
        frames = [];
      }
      if (depth > this.bound) {
        throw new StrictJsonError("budget", "strict JSON nesting exceeds the parser's bound", this.index);
      }
      let value: JsonValue | undefined;
      const c = this.code(this.index);
      if (c === 0x7b /* { */ || c === 0x5b /* [ */) {
        const isObject = c === 0x7b;
        this.index += 1;
        this.skipWhitespace();
        if (this.code(this.index) === (isObject ? 0x7d : 0x5d)) {
          this.index += 1;
          value = isObject ? {} : [];
        } else {
          kinds.push(isObject);
          const frame: Frame | undefined = this.building ? { container: isObject ? {} : [], isObject, names: [], pendingKey: undefined } : undefined;
          if (frame !== undefined) {
            frames.push(frame);
          }
          if (isObject) {
            const key = this.readKey();
            if (frame !== undefined) {
              frame.pendingKey = key;
            }
          }
          continue;
        }
      } else {
        value = this.parseScalar();
      }
      // Attach the value, closing containers that end here.
      for (;;) {
        if (kinds.length === 0) {
          return value;
        }
        const isObject = kinds[kinds.length - 1] as boolean;
        const frame = this.building ? (frames[frames.length - 1] as Frame) : undefined;
        if (frame !== undefined) {
          if (isObject) {
            const key = frame.pendingKey as string;
            frame.names.push(key);
            Object.defineProperty(frame.container, key, {
              value,
              enumerable: true,
              writable: true,
              configurable: true,
            });
          } else {
            (frame.container as JsonArray).push(value as JsonValue);
          }
        }
        this.skipWhitespace();
        const next = this.code(this.index);
        if (next === 0x2c /* , */) {
          this.index += 1;
          if (isObject) {
            this.skipWhitespace();
            const key = this.readKey();
            if (frame !== undefined) {
              frame.pendingKey = key;
            }
          }
          break;
        }
        if (isObject ? next === 0x7d : next === 0x5d) {
          this.index += 1;
          kinds.pop();
          if (frame !== undefined) {
            frames.pop();
            if (isObject && this.duplicate === undefined) {
              this.duplicate = repeatedName(frame.names);
            }
            value = frame.container;
          } else {
            value = undefined;
          }
          continue;
        }
        throw this.syntax(isObject ? "expecting ',' or '}'" : "expecting ',' or ']'");
      }
    }
  }

  private readKey(): string {
    if (this.code(this.index) !== 0x22 /* " */) {
      throw this.syntax("expecting a property name enclosed in double quotes");
    }
    const key = this.building ? this.checkedString() : this.skipString();
    this.skipWhitespace();
    if (this.code(this.index) !== 0x3a /* : */) {
      throw this.syntax("expecting ':' delimiter");
    }
    this.index += 1;
    return key;
  }

  private parseScalar(): JsonValue | undefined {
    const c = this.code(this.index);
    if (c === 0x22 /* " */) {
      return this.building ? this.checkedString() : this.skipString();
    }
    if (this.at("null")) {
      this.index += 4;
      return null;
    }
    if (this.at("true")) {
      this.index += 4;
      return true;
    }
    if (this.at("false")) {
      this.index += 5;
      return false;
    }
    if (this.at("NaN") || this.at("Infinity") || this.at("-Infinity")) {
      throw new StrictJsonError("constant", "non-JSON numeric constant is prohibited", this.index);
    }
    if (c === 0x2d || (c >= 0x30 && c <= 0x39)) {
      return this.readNumber();
    }
    throw this.syntax("expecting a value");
  }

  private readNumber(): number | undefined {
    const start = this.index;
    let index = start;
    if (this.code(index) === 0x2d) {
      index += 1;
    }
    const firstDigit = this.code(index);
    if (!(firstDigit >= 0x30 && firstDigit <= 0x39)) {
      throw this.syntax("expecting a value");
    }
    if (firstDigit === 0x30) {
      index += 1;
    } else {
      while (isDigit(this.code(index))) {
        index += 1;
      }
    }
    let fractional = false;
    if (this.code(index) === 0x2e /* . */ && isDigit(this.code(index + 1))) {
      fractional = true;
      index += 2;
      while (isDigit(this.code(index))) {
        index += 1;
      }
    }
    const e = this.code(index);
    if (e === 0x65 || e === 0x45) {
      let after = index + 1;
      const sign = this.code(after);
      if (sign === 0x2b || sign === 0x2d) {
        after += 1;
      }
      if (isDigit(this.code(after))) {
        fractional = true;
        index = after;
        while (isDigit(this.code(index))) {
          index += 1;
        }
      }
    }
    this.index = index;
    if (!this.building) {
      return undefined;
    }
    const raw = this.piece(start, index);
    let problem: string | undefined;
    if (fractional) {
      problem = `floating-point JSON numbers are prohibited by the ECL profile: ${raw.slice(0, 40)}`;
    } else if (raw === "-0") {
      problem = "negative zero is prohibited";
    } else {
      const digits = raw.startsWith("-") ? raw.slice(1) : raw;
      if (digits.length > 16 || Math.abs(Number(raw)) > MAX_SAFE_INTEGER) {
        problem = `integer exceeds exact interoperable range: ${raw.slice(0, 40)}`;
      }
    }
    if (problem !== undefined) {
      if (this.number === undefined) {
        this.number = new StrictJsonError("number", problem, start);
      }
      return 0;
    }
    return Number(raw);
  }

  /** The end of the escape at `index` (a backslash), or -1 when it is not a valid escape. */
  private escapeEnd(index: number): number {
    const escape = this.code(index + 1);
    if (escape === 0x22 || escape === 0x5c || escape === 0x2f || escape === 0x62 || escape === 0x66 || escape === 0x6e || escape === 0x72 || escape === 0x74) {
      return index + 2;
    }
    if (escape === 0x75 && this.hex4(index + 2) >= 0) {
      return index + 6;
    }
    return -1;
  }

  /** The string at the current position, read for the grammar alone: nothing is decoded or kept. */
  private skipString(): string {
    let index = this.index + 1;
    for (;;) {
      if (index >= this.length) {
        this.index = index;
        throw this.syntax("unterminated string");
      }
      const c = this.code(index);
      if (c === 0x22 /* " */) {
        this.index = index + 1;
        return "";
      }
      if (c < 0x20) {
        this.index = index;
        throw this.syntax("invalid control character in a string");
      }
      if (c !== 0x5c /* \ */) {
        index += 1;
        continue;
      }
      const next = this.escapeEnd(index);
      if (next < 0) {
        this.index = index;
        throw this.syntax(this.code(index + 1) === 0x75 ? "invalid \\uXXXX escape" : "invalid escape");
      }
      index = next;
    }
  }

  private readString(): string {
    let index = this.index + 1;
    let out = "";
    let chunkStart = index;
    for (;;) {
      if (index >= this.length) {
        this.index = index;
        throw this.syntax("unterminated string");
      }
      const c = this.code(index);
      if (c === 0x22 /* " */) {
        out += this.piece(chunkStart, index);
        this.index = index + 1;
        return out;
      }
      if (c < 0x20) {
        this.index = index;
        throw this.syntax("invalid control character in a string");
      }
      if (c !== 0x5c /* \ */) {
        index += 1;
        continue;
      }
      out += this.piece(chunkStart, index);
      const escape = this.code(index + 1);
      switch (escape) {
        case 0x22:
          out += '"';
          break;
        case 0x5c:
          out += "\\";
          break;
        case 0x2f:
          out += "/";
          break;
        case 0x62:
          out += "\b";
          break;
        case 0x66:
          out += "\f";
          break;
        case 0x6e:
          out += "\n";
          break;
        case 0x72:
          out += "\r";
          break;
        case 0x74:
          out += "\t";
          break;
        case 0x75: {
          const unit = this.hex4(index + 2);
          if (unit < 0) {
            this.index = index;
            throw this.syntax("invalid \\uXXXX escape");
          }
          index += 6;
          // A high surrogate escape joins a following low surrogate escape, as in the reference.
          if (unit >= 0xd800 && unit <= 0xdbff && this.code(index) === 0x5c && this.code(index + 1) === 0x75) {
            const low = this.hex4(index + 2);
            if (low < 0) {
              this.index = index;
              throw this.syntax("invalid \\uXXXX escape");
            }
            if (low >= 0xdc00 && low <= 0xdfff) {
              out += String.fromCharCode(unit, low);
              index += 6;
              chunkStart = index;
              continue;
            }
          }
          out += String.fromCharCode(unit);
          chunkStart = index;
          continue;
        }
        default:
          this.index = index;
          throw this.syntax("invalid escape");
      }
      index += 2;
      chunkStart = index;
    }
  }

  /** The value of four hexadecimal digits at `start`, or -1. */
  private hex4(start: number): number {
    if (start + 4 > this.length) {
      return -1;
    }
    let value = 0;
    for (let index = start; index < start + 4; index += 1) {
      const c = this.code(index);
      let digit: number;
      if (c >= 0x30 && c <= 0x39) {
        digit = c - 0x30;
      } else if (c >= 0x61 && c <= 0x66) {
        digit = c - 0x61 + 10;
      } else if (c >= 0x41 && c <= 0x46) {
        digit = c - 0x41 + 10;
      } else {
        return -1;
      }
      value = value * 16 + digit;
    }
    return value;
  }
}

function isDigit(c: number): boolean {
  return c >= 0x30 && c <= 0x39;
}

function repeatedName(names: string[]): StrictJsonError | undefined {
  const seen = new Set<string>();
  for (const name of names) {
    if (seen.has(name)) {
      return new StrictJsonError("duplicate-member", `duplicate JSON object member: ${JSON.stringify(name)}`);
    }
    seen.add(name);
  }
  return undefined;
}

/**
 * The budgets and the string profile of a value handed to the canonicalizer, as the reference
 * checks them: depth counts containers around a value (the root is at 0), nodes count every
 * value, and no string, key included, holds a lone surrogate or a noncharacter.
 */
export function checkLimits(value: JsonValue, maxDepth = MAX_JSON_DEPTH, maxNodes = MAX_JSON_NODES): void {
  checkedLimit("maxDepth", maxDepth);
  checkedLimit("maxNodes", maxNodes);
  const stack: Array<[JsonValue, number]> = [[value, 0]];
  let nodes = 0;
  while (stack.length > 0) {
    const [current, depth] = stack.pop() as [JsonValue, number];
    nodes += 1;
    if (nodes > maxNodes) {
      throw new StrictJsonError("budget", "JSON value exceeds the canonical node budget");
    }
    if (depth > maxDepth) {
      throw new StrictJsonError("budget", "JSON value exceeds the canonical nesting budget");
    }
    if (typeof current === "string") {
      const problem = scalarProblem(current);
      if (problem !== undefined) {
        throw problem;
      }
    } else if (Array.isArray(current)) {
      // Each position is a value: the length is counted against the budget before any position is
      // read, so that a sparse array of any length is refused at once (IE1-029).
      if (current.length > maxNodes - nodes) {
        throw new StrictJsonError("budget", "JSON value exceeds the canonical node budget");
      }
      for (const item of current) {
        stack.push([item, depth + 1]);
      }
    } else if (current !== null && typeof current === "object") {
      const keys = Object.keys(current);
      if (keys.length > maxNodes - nodes) {
        throw new StrictJsonError("budget", "JSON value exceeds the canonical node budget");
      }
      for (const key of keys) {
        const problem = scalarProblem(key);
        if (problem !== undefined) {
          throw problem;
        }
        stack.push([current[key] as JsonValue, depth + 1]);
      }
    }
  }
}

/** Whether a string holds a lone surrogate, which no ECL string may hold. */
export function containsLoneSurrogate(value: string): boolean {
  return hasLoneSurrogate(value);
}

/** Whether a string holds a lone surrogate or a noncharacter, which no ECL string may hold. */
export function containsInvalidScalar(value: string): boolean {
  return scalarProblem(value) !== undefined;
}
