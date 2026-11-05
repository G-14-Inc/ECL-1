/**
 * The signature suites of ECL-IE-1 that a trust policy can hold.
 *
 * Ed25519 (`ecl.sig.ed25519.v1`, IE1-016, TP1-008): the signature's S must be below the group
 * order L, and the cofactorless equation [S]B = R + [k]A must hold, with k the little-endian
 * SHA-512 of R || A || M reduced modulo L. It is checked as the reference's backend checks it:
 * [S]B - [k]A is encoded and compared with the signature's R bytes. A cofactored equation, which
 * the ZIP-215 default of some libraries uses, accepts signatures this profile refuses, so it is
 * never used. A public key must be the canonical encoding of a curve point of large order.
 *
 * ECDSA P-256 with SHA-256 (`ecl.sig.ecdsa-p256-sha256.v1`, IE1-017): the signature is minimally
 * encoded ASN.1 DER and its s is at most n/2; anything else is refused before the curve check.
 *
 * The point arithmetic is @noble/curves 2.3.0, the release audited by Trail of Bits in August
 * 2026; the verification rules are written here.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { concat, equalBytes, sha512 } from "./bytes.js";

export const ED25519_SUITE = "ecl.sig.ed25519.v1";
export const P256_SUITE = "ecl.sig.ecdsa-p256-sha256.v1";
export const MLDSA65_SUITE = "ecl.sig.ml-dsa-65.v1";

const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const P = 2n ** 255n - 19n;
const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_FIELD = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;

const EdPoint = ed25519.Point;

/** A signature or key that the suite's encoding rules refuse outright (an integrity failure). */
export class SignatureEncodingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SignatureEncodingError";
  }
}

/** A suite this library recognizes but does not implement. */
export class UnsupportedSuiteError extends Error {
  readonly suiteId: string;

  constructor(suiteId: string) {
    super(`signature suite ${suiteId} is not implemented by this library`);
    this.name = "UnsupportedSuiteError";
    this.suiteId = suiteId;
  }
}

function littleEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index] as number);
  }
  return value;
}

function bigEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

/**
 * Why an Ed25519 public key is refused, or undefined when it is acceptable: 32 bytes, a canonical
 * encoding (y below p, no x of 0 with the sign bit set), on the curve, and not of small order.
 */
export function ed25519KeyProblem(raw: Uint8Array): string | undefined {
  if (raw.length !== 32) {
    return `a public key for ${ED25519_SUITE} is 32 bytes, not ${raw.length}`;
  }
  const y = littleEndian(raw) & ((1n << 255n) - 1n);
  if (y >= P) {
    return "the public key is not a canonical Ed25519 encoding: y is not below p";
  }
  let point;
  try {
    point = EdPoint.fromBytes(raw, false);
  } catch {
    const sign = ((raw[31] as number) & 0x80) !== 0;
    return sign && (y === 1n || y === P - 1n)
      ? "the public key is not a point on Ed25519: x is 0 and the sign bit is 1"
      : "the public key is not a point on Ed25519";
  }
  if (point.isSmallOrder()) {
    return "the public key is a point of small order on Ed25519: a signature made without a private key verifies under it";
  }
  return undefined;
}

/** Ed25519 verification under the cofactorless equation; false for any failure. */
export function verifyEd25519(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) {
    return false;
  }
  const rBytes = signature.subarray(0, 32);
  const s = littleEndian(signature.subarray(32, 64));
  if (s >= L) {
    return false;
  }
  let a;
  try {
    a = EdPoint.fromBytes(publicKey, false);
  } catch {
    return false;
  }
  const k = littleEndian(sha512(concat(rBytes, publicKey, message))) % L;
  const sB = s === 0n ? EdPoint.ZERO : EdPoint.BASE.multiplyUnsafe(s);
  const kA = k === 0n ? EdPoint.ZERO : a.multiplyUnsafe(k);
  const check = sB.subtract(kA);
  return equalBytes(check.toBytes(), rBytes);
}

/**
 * Why a P-256 public key is refused, or undefined: 65 bytes, the uncompressed SEC 1 form
 * (0x04 || x || y), coordinates below p, on the curve.
 */
export function p256KeyProblem(raw: Uint8Array): string | undefined {
  if (raw.length !== 65) {
    return `a public key for ${P256_SUITE} is 65 bytes, not ${raw.length}`;
  }
  if (raw[0] !== 0x04 || bigEndian(raw.subarray(1, 33)) >= P256_FIELD || bigEndian(raw.subarray(33, 65)) >= P256_FIELD) {
    return "the public key is not a point on P-256";
  }
  try {
    p256.Point.fromBytes(raw);
  } catch {
    return "the public key is not a point on P-256";
  }
  return undefined;
}

function derLength(der: Uint8Array, offset: number): [number, number] {
  const first = der[offset];
  if (first === undefined) {
    throw new SignatureEncodingError("ECDSA signature is not minimally encoded DER");
  }
  if (first < 0x80) {
    return [first, offset + 1];
  }
  const count = first & 0x7f;
  if (count === 0 || count > 2 || offset + 1 + count > der.length) {
    throw new SignatureEncodingError("ECDSA signature is not minimally encoded DER");
  }
  let length = 0;
  for (let index = 0; index < count; index += 1) {
    length = length * 256 + (der[offset + 1 + index] as number);
  }
  if (length < 0x80 || (count === 2 && length < 0x100) || (der[offset + 1] as number) === 0) {
    throw new SignatureEncodingError("ECDSA signature is not minimally encoded DER");
  }
  return [length, offset + 1 + count];
}

function derInteger(der: Uint8Array, offset: number): [bigint, number] {
  if (der[offset] !== 0x02) {
    throw new SignatureEncodingError("ECDSA signature is not minimally encoded DER");
  }
  const [length, start] = derLength(der, offset + 1);
  const end = start + length;
  if (length === 0 || end > der.length) {
    throw new SignatureEncodingError("ECDSA signature is not minimally encoded DER");
  }
  const first = der[start] as number;
  if ((first & 0x80) !== 0) {
    throw new SignatureEncodingError("ECDSA signature is not minimally encoded DER");
  }
  if (first === 0 && length > 1 && ((der[start + 1] as number) & 0x80) === 0) {
    throw new SignatureEncodingError("ECDSA signature is not minimally encoded DER");
  }
  return [bigEndian(der.subarray(start, end)), end];
}

/** The (r, s) of a minimally encoded DER ECDSA-Sig-Value; SignatureEncodingError otherwise. */
export function parseDerSignature(der: Uint8Array): { r: bigint; s: bigint } {
  if (der[0] !== 0x30) {
    throw new SignatureEncodingError("ECDSA signature is not minimally encoded DER");
  }
  const [length, start] = derLength(der, 1);
  if (start + length !== der.length) {
    throw new SignatureEncodingError("ECDSA signature is not minimally encoded DER");
  }
  const [r, afterR] = derInteger(der, start);
  const [s, afterS] = derInteger(der, afterR);
  if (afterS !== der.length) {
    throw new SignatureEncodingError("ECDSA signature is not minimally encoded DER");
  }
  return { r, s };
}

function fixed32(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let rest = value;
  for (let index = 31; index >= 0; index -= 1) {
    out[index] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
}

/**
 * ECDSA P-256 verification. Throws SignatureEncodingError for non-minimal DER or a high s
 * (IE1-017); returns false when the signature does not verify.
 */
export function verifyP256(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  const { r, s } = parseDerSignature(signature);
  if (s > P256_ORDER / 2n) {
    throw new SignatureEncodingError("ECDSA signature is not low-S");
  }
  if (r === 0n || s === 0n || r >= P256_ORDER || s >= P256_ORDER) {
    return false;
  }
  const compact = concat(fixed32(r), fixed32(s));
  try {
    return p256.verify(compact, message, publicKey, { prehash: true, lowS: true, format: "compact" });
  } catch {
    return false;
  }
}

/** Why a public key is refused under its suite, or undefined when the key is acceptable. */
export function publicKeyProblem(suiteId: string, raw: Uint8Array): string | undefined {
  if (suiteId === ED25519_SUITE) {
    return ed25519KeyProblem(raw);
  }
  if (suiteId === P256_SUITE) {
    return p256KeyProblem(raw);
  }
  return `${suiteId} is not supported by trust policy v1 (Ed25519 and ECDSA P-256)`;
}

/**
 * Verify `signature` over `message` under a key of `suiteId`. Returns false when the signature
 * does not verify; throws SignatureEncodingError for an encoding the suite refuses outright,
 * UnsupportedSuiteError for ML-DSA-65, and an Error for an unknown suite.
 */
export function verifySignature(suiteId: string, publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (suiteId === ED25519_SUITE) {
    return verifyEd25519(publicKey, message, signature);
  }
  if (suiteId === P256_SUITE) {
    return verifyP256(publicKey, message, signature);
  }
  if (suiteId === MLDSA65_SUITE) {
    throw new UnsupportedSuiteError(suiteId);
  }
  throw new SignatureEncodingError(`unsupported signature suite: ${suiteId}`);
}
