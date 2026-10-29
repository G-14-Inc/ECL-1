/**
 * Compact JWS, JWKs and JWK thumbprints, as OAUTH-AUTHORITY-1 needs them: JWS (RFC 7515) signed
 * with ES256 or EdDSA (RFC 7518, RFC 8037), public JWKs for P-256 and Ed25519, RFC 7638
 * thumbprints, and the checks a verifier makes before it trusts a header (RFC 8725 sections 2
 * and 3, OA1-007).
 *
 * A verifier takes keys only from the key set its caller configures: a header that carries or
 * points to a key (`jwk`, `jku`, `x5u`, `x5c`) is refused, as are `none`, every symmetric
 * algorithm, an unknown `kid` and any `crit` member. A DPoP proof (RFC 9449) is the exception: its
 * header carries the public key that the proof is checked with, and the caller then compares that
 * key's thumbprint with the token's `cnf.jkt`.
 *
 * Each segment is read under the strict JSON profile of ECL objects (IE1-002, OA1-007): a segment
 * that repeats a member name, holds a number with a fraction or an exponent, an integer beyond the
 * exact interoperable range, a non-JSON constant, a lone surrogate or a byte-order mark, or that
 * is not a JSON object, is malformed. So a time claim is always an integer. An `alg` that is not
 * one of the declared asymmetric set's names, a list or an object included, is refused.
 *
 * A signature is checked as the reference's backend checks a JOSE signature: an ES256 signature
 * is r || s, each from 1 to n - 1, of any s; an EdDSA signature has S below the group order and
 * satisfies the cofactorless equation, and the public key is decoded as RFC 8032 decoders
 * commonly decode it. The stricter key rules of ECL-IE-1 (`crypto/signatures.ts`) are for ECL's
 * own evidence signatures and do not apply to a token that another system signs.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { concat, equalBytes, fromCanonicalBase64, sha256, sha512, toBase64, utf8 } from "../crypto/bytes.js";
import { p256KeyProblem } from "../crypto/signatures.js";
import { parseStrictJson, StrictJsonError } from "../json/strict.js";
import { codePointLength } from "../json/value.js";
import type { JsonValue } from "../json/value.js";
import { PythonValueError } from "../semantic/python.js";
import { pyEquals, toPy } from "./pyjson.js";
import type { PyObject, PyValue } from "./pyjson.js";

export const ES256 = "ES256";
export const EDDSA = "EdDSA";
export const ALGORITHMS: ReadonlySet<string> = new Set([ES256, EDDSA]);
export const ACCESS_TYPE = "at+jwt";
export const DPOP_TYPE = "dpop+jwt";
export const KEY_HEADERS: readonly string[] = ["jwk", "jku", "x5u", "x5c"];
export const MAX_TOKEN_BYTES = 16 * 1024;

const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const EdPoint = ed25519.Point;
const BASE64URL = /^[A-Za-z0-9_-]*$/;

/** A token, proof or key that is malformed or does not verify. `reason` names the check. */
export class JoseError extends Error {
  readonly reason: string;

  constructor(reason: string, message: string) {
    super(message);
    this.name = "JoseError";
    this.reason = reason;
  }
}

/** A public key read from a JWK. */
interface PublicKey {
  readonly kind: "p256" | "ed25519";
  readonly raw: Uint8Array;
}

function own(value: PyObject, name: string): PyValue | undefined {
  return Object.prototype.hasOwnProperty.call(value, name) ? value[name] : undefined;
}

/** Whether a PyValue is a JSON object (a dict). */
export function isPyObject(value: PyValue | undefined): value is PyObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Base64url without padding (RFC 7515 section 2). */
export function b64url(data: Uint8Array): string {
  return toBase64(data).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The bytes of unpadded base64url text, refusing any other alphabet or a non-canonical tail. */
export function b64urlDecode(text: string): Uint8Array {
  if (!BASE64URL.test(text) || text.length % 4 === 1) {
    throw new JoseError("malformed", "the text is not unpadded base64url");
  }
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  const data = fromCanonicalBase64(padded);
  if (data === undefined) {
    throw new JoseError("malformed", "the base64url text is not in canonical form");
  }
  return data;
}

/** The UTF-8 bytes of text that Python can encode: a lone surrogate raises, as there. */
function encodable(text: string): Uint8Array {
  for (let index = 0; index < text.length; index += 1) {
    const unit = text.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new PythonValueError("surrogates not allowed");
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new PythonValueError("surrogates not allowed");
    }
  }
  return utf8(text);
}

/** A string as Python's `json.dumps(..., ensure_ascii=False)` writes it. */
function jsonString(value: string): string {
  let out = '"';
  for (const character of value) {
    const code = character.codePointAt(0) as number;
    if (character === '"') {
      out += '\\"';
    } else if (character === "\\") {
      out += "\\\\";
    } else if (character === "\n") {
      out += "\\n";
    } else if (character === "\r") {
      out += "\\r";
    } else if (character === "\t") {
      out += "\\t";
    } else if (character === "\b") {
      out += "\\b";
    } else if (character === "\f") {
      out += "\\f";
    } else if (code < 0x20) {
      out += "\\u" + code.toString(16).padStart(4, "0");
    } else {
      out += character;
    }
  }
  return out + '"';
}

/** The JSON object of one segment, read under the strict JSON profile (IE1-002, OA1-007). */
function segmentObject(segment: string): PyObject {
  let value: JsonValue;
  try {
    value = parseStrictJson(b64urlDecode(segment));
  } catch (error) {
    if (error instanceof StrictJsonError) {
      const message = error.kind === "duplicate-member" ? "a JWS segment repeats a member name" : "a JWS segment is not strict JSON";
      throw new JoseError("malformed", message);
    }
    throw error;
  }
  const object = toPy(value);
  if (!isPyObject(object)) {
    throw new JoseError("malformed", "a JWS segment is not a JSON object");
  }
  return object;
}

/** The decoded parts of a compact JWS: header, claims, signing input and signature. */
export interface DecodedJws {
  readonly header: PyObject;
  readonly claims: PyObject;
  readonly signingInput: Uint8Array;
  readonly signature: Uint8Array;
}

/** The header, the claims, the signing input and the signature of a compact JWS, unverified. */
export function decodeJws(token: unknown): DecodedJws {
  if (typeof token !== "string" || codePointLength(token) > MAX_TOKEN_BYTES) {
    throw new JoseError("malformed", "the token is not a compact JWS within the size limit");
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new JoseError("malformed", "a compact JWS has three segments");
  }
  const [first, second, third] = parts as [string, string, string];
  const header = segmentObject(first);
  const claims = segmentObject(second);
  const signature = b64urlDecode(third);
  return { header, claims, signingInput: utf8(first + "." + second), signature };
}

function checkedHeader(header: PyObject, expectedType: string): string {
  const algorithm = own(header, "alg");
  if (typeof algorithm !== "string" || !ALGORITHMS.has(algorithm)) {
    throw new JoseError("algorithm", "the algorithm is not in the declared asymmetric set");
  }
  if (!pyEquals(own(header, "typ"), expectedType)) {
    throw new JoseError("type", `the header's typ is not ${expectedType}`);
  }
  if (own(header, "crit") !== undefined) {
    throw new JoseError("crit", "the header has a crit member this verifier does not understand");
  }
  return algorithm;
}

function coordinate(jwk: PyObject, name: string, size: number): Uint8Array {
  const value = own(jwk, name);
  const data = typeof value === "string" ? b64urlDecode(value) : new Uint8Array(0);
  if (data.length !== size) {
    throw new JoseError("key", `the JWK member ${name} is not ${size} bytes of base64url`);
  }
  return data;
}

function publicKey(jwk: PyObject): PublicKey {
  if (own(jwk, "d") !== undefined) {
    throw new JoseError("key", "a verification key must not carry private key material");
  }
  if (pyEquals(own(jwk, "kty"), "EC") && pyEquals(own(jwk, "crv"), "P-256")) {
    const x = coordinate(jwk, "x", 32);
    const y = coordinate(jwk, "y", 32);
    const raw = concat(new Uint8Array([4]), x, y);
    if (p256KeyProblem(raw) !== undefined) {
      throw new JoseError("key", "the JWK is not a point on P-256");
    }
    return { kind: "p256", raw };
  }
  if (pyEquals(own(jwk, "kty"), "OKP") && pyEquals(own(jwk, "crv"), "Ed25519")) {
    return { kind: "ed25519", raw: coordinate(jwk, "x", 32) };
  }
  throw new JoseError("key", "the JWK is neither a P-256 nor an Ed25519 public key");
}

function bigEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

function littleEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index] as number);
  }
  return value;
}

/** ES256 over `message` with r || s; any s from 1 to n - 1 is accepted, as JOSE accepts it. */
function verifyEs256(publicKeyRaw: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  const r = bigEndian(signature.subarray(0, 32));
  const s = bigEndian(signature.subarray(32, 64));
  if (r === 0n || s === 0n || r >= P256_ORDER || s >= P256_ORDER) {
    return false;
  }
  try {
    return p256.verify(signature, message, publicKeyRaw, { prehash: true, lowS: false, format: "compact" });
  } catch {
    return false;
  }
}

/**
 * EdDSA (Ed25519) as RFC 8032 decoders commonly verify it: S below the group order, the public
 * key decoded with its y reduced modulo p (a non-canonical encoding of a point is that point),
 * and [S]B - [k]A encoded and compared with R, k being SHA-512(R || A || M) of the key's bytes.
 */
export function verifyEd25519Jose(publicKeyRaw: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (publicKeyRaw.length !== 32 || signature.length !== 64) {
    return false;
  }
  const rBytes = signature.subarray(0, 32);
  const s = littleEndian(signature.subarray(32, 64));
  if (s >= L) {
    return false;
  }
  let a;
  try {
    a = EdPoint.fromBytes(publicKeyRaw, true);
  } catch {
    return false;
  }
  const k = littleEndian(sha512(concat(rBytes, publicKeyRaw, message))) % L;
  const sB = s === 0n ? EdPoint.ZERO : EdPoint.BASE.multiplyUnsafe(s);
  const kA = k === 0n ? EdPoint.ZERO : a.multiplyUnsafe(k);
  return equalBytes(sB.subtract(kA).toBytes(), rBytes);
}

function verifySignature(algorithm: string, jwk: PyObject, signingInput: Uint8Array, signature: Uint8Array): void {
  const key = publicKey(jwk);
  if (algorithm === ES256 && key.kind === "p256") {
    if (signature.length !== 64) {
      throw new JoseError("signature", "an ES256 signature is not 64 bytes");
    }
    if (!verifyEs256(key.raw, signingInput, signature)) {
      throw new JoseError("signature", "the signature does not verify");
    }
    return;
  }
  if (algorithm === EDDSA && key.kind === "ed25519") {
    if (!verifyEd25519Jose(key.raw, signingInput, signature)) {
      throw new JoseError("signature", "the signature does not verify");
    }
    return;
  }
  throw new JoseError("algorithm", "the algorithm does not match the key type");
}

/**
 * The header and claims of a token signed by one of `keys` (by `kid`), after every check of
 * OA1-007. Throws JoseError.
 */
export function verifyJws(token: unknown, keys: ReadonlyMap<string, PyObject>, expectedType: string = ACCESS_TYPE): [PyObject, PyObject] {
  const { header, claims, signingInput, signature } = decodeJws(token);
  const algorithm = checkedHeader(header, expectedType);
  if (KEY_HEADERS.some((name) => own(header, name) !== undefined)) {
    throw new JoseError("key-header", "the header carries or points to a key");
  }
  const kid = own(header, "kid");
  const key = typeof kid === "string" ? keys.get(kid) : undefined;
  if (key === undefined) {
    throw new JoseError("kid", "the header names no configured key");
  }
  verifySignature(algorithm, key, signingInput, signature);
  return [header, claims];
}

/** The header, claims and key thumbprint of a DPoP proof checked with the key it carries. */
export function verifyDpop(proof: unknown): [PyObject, PyObject, string] {
  const { header, claims, signingInput, signature } = decodeJws(proof);
  const algorithm = checkedHeader(header, DPOP_TYPE);
  const jwk = own(header, "jwk");
  if (!isPyObject(jwk) || ["jku", "x5u", "x5c"].some((name) => own(header, name) !== undefined)) {
    throw new JoseError("key-header", "a DPoP proof carries exactly its public key in jwk");
  }
  verifySignature(algorithm, jwk, signingInput, signature);
  return [header, claims, thumbprint(jwk)];
}

/** The RFC 7638 SHA-256 thumbprint of a public P-256 or Ed25519 JWK, in base64url. */
export function thumbprint(jwk: PyObject): string {
  const kty = own(jwk, "kty");
  const names = pyEquals(kty, "EC") ? ["crv", "kty", "x", "y"] : ["crv", "kty", "x"];
  if (!(pyEquals(kty, "EC") || pyEquals(kty, "OKP")) || !names.every((name) => typeof own(jwk, name) === "string")) {
    throw new JoseError("key", "a thumbprint needs an EC or OKP public key with its members");
  }
  const text = "{" + names.map((name) => jsonString(name) + ":" + jsonString(own(jwk, name) as string)).join(",") + "}";
  return b64url(sha256(encodable(text)));
}

/** The `ath` of RFC 9449: base64url SHA-256 of the token's ASCII bytes. */
export function tokenHash(token: string): string {
  for (let index = 0; index < token.length; index += 1) {
    if (token.charCodeAt(index) > 0x7f) {
      throw new PythonValueError("the token is not ASCII");
    }
  }
  return b64url(sha256(utf8(token)));
}
