/**
 * Byte helpers: SHA-2 digests (from @noble/hashes), hexadecimal, UTF-8 and the
 * canonical standard base64 that ECL-IE-1 requires (IE1-005).
 */

import { sha256 as nobleSha256, sha512 as nobleSha512 } from "@noble/hashes/sha2.js";

const encoder = new TextEncoder();

/** The UTF-8 bytes of a string. */
export function utf8(text: string): Uint8Array {
  return encoder.encode(text);
}

/** The SHA-256 digest of `data`. */
export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

/** The SHA-512 digest of `data`. */
export function sha512(data: Uint8Array): Uint8Array {
  return nobleSha512(data);
}

const HEX = "0123456789abcdef";

/** Lowercase hexadecimal. */
export function toHex(data: Uint8Array): string {
  let out = "";
  for (const byte of data) {
    out += HEX[byte >> 4] + (HEX[byte & 15] as string);
  }
  return out;
}

/** The lowercase hexadecimal SHA-256 digest of `data`. */
export function sha256Hex(data: Uint8Array): string {
  return toHex(sha256(data));
}

/** Concatenate byte arrays. */
export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Byte-for-byte equality. */
export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] as number) ^ (right[index] as number);
  }
  return difference === 0;
}

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const DECODE = new Int16Array(128).fill(-1);
for (let index = 0; index < ALPHABET.length; index += 1) {
  DECODE[ALPHABET.charCodeAt(index)] = index;
}

/** Standard base64 with padding (RFC 4648 section 4). */
export function toBase64(data: Uint8Array): string {
  let out = "";
  let index = 0;
  for (; index + 2 < data.length; index += 3) {
    const n = ((data[index] as number) << 16) | ((data[index + 1] as number) << 8) | (data[index + 2] as number);
    out += (ALPHABET[(n >> 18) & 63] as string) + ALPHABET[(n >> 12) & 63] + ALPHABET[(n >> 6) & 63] + ALPHABET[n & 63];
  }
  const rest = data.length - index;
  if (rest === 1) {
    const n = (data[index] as number) << 16;
    out += (ALPHABET[(n >> 18) & 63] as string) + ALPHABET[(n >> 12) & 63] + "==";
  } else if (rest === 2) {
    const n = ((data[index] as number) << 16) | ((data[index + 1] as number) << 8);
    out += (ALPHABET[(n >> 18) & 63] as string) + ALPHABET[(n >> 12) & 63] + ALPHABET[(n >> 6) & 63] + "=";
  }
  return out;
}

/**
 * The bytes of canonical standard base64, or undefined for any other text. Canonical means the
 * text is exactly what `toBase64` returns for those bytes: padded, with zero pad bits and no
 * whitespace (the reference decodes strictly and then re-encodes to compare).
 */
export function fromCanonicalBase64(text: string): Uint8Array | undefined {
  if (text.length % 4 !== 0) {
    return undefined;
  }
  const padding = text.endsWith("==") ? 2 : text.endsWith("=") ? 1 : 0;
  const body = text.length - padding;
  const out = new Uint8Array((text.length / 4) * 3 - padding);
  let bits = 0;
  let value = 0;
  let written = 0;
  for (let index = 0; index < body; index += 1) {
    const code = text.charCodeAt(index);
    const digit = code < 128 ? (DECODE[code] as number) : -1;
    if (digit < 0) {
      return undefined;
    }
    value = (value << 6) | digit;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (written < out.length) {
        out[written] = (value >> bits) & 0xff;
      }
      written += 1;
    }
  }
  if (written !== out.length) {
    return undefined;
  }
  return toBase64(out) === text ? out : undefined;
}
