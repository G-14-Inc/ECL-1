/** Test fixture builders. These functions are absent from the verifier runtime package. */
import { crc32, isEntryName } from "../../src/offline/zip.js";
import type { ZipMember } from "../../src/offline/zip.js";
import { digestOf, ENCODED } from "../../src/bindings/common.js";
import { jcsCanonicalize } from "../../src/bindings/jcs.js";
import { toBase64 } from "../../src/crypto/bytes.js";
import type { JsonObject, JsonValue } from "../../src/json/value.js";

const LOCAL_SIGNATURE = 0x04034b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const END_SIGNATURE = 0x06054b50;
const PROFILE_VERSION = 20;
const PROFILE_MADE_BY = (3 << 8) | PROFILE_VERSION;
const PROFILE_DOS_DATE = (1 << 5) | 1;
const PROFILE_MODE = 0o100644;
const PROFILE_EXTERNAL = PROFILE_MODE * 0x10000;

class Writer {
  readonly bytes: number[] = [];

  u16(value: number): this {
    this.bytes.push(value & 0xff, (value >>> 8) & 0xff);
    return this;
  }

  u32(value: number): this {
    this.bytes.push(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
    return this;
  }

  raw(data: Uint8Array): this {
    for (const byte of data) {
      this.bytes.push(byte);
    }
    return this;
  }
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (left[index] as number) - (right[index] as number);
    if (difference !== 0) {
      return difference;
    }
  }
  return left.length - right.length;
}

/**
 * The `ecl.zip.store.v1` archive of `members` (entry names and bytes), sorted by the bytes of
 * their names: what an `ecl.zip.store.v1` producer writes (IE1-031). Names must be entry names.
 */
export function writeStoredZip(members: readonly ZipMember[]): Uint8Array {
  const encoder = new TextEncoder();
  const sorted = members
    .map((member) => {
      if (!isEntryName(member.name)) {
        throw new RangeError(`not an ecl.zip.store.v1 entry name: ${JSON.stringify(member.name)}`);
      }
      return { nameBytes: encoder.encode(member.name), data: member.data };
    })
    .sort((left, right) => compareBytes(left.nameBytes, right.nameBytes));
  const output = new Writer();
  const central = new Writer();
  for (const member of sorted) {
    const offset = output.bytes.length;
    const crc = crc32(member.data);
    output
      .u32(LOCAL_SIGNATURE)
      .u16(PROFILE_VERSION)
      .u16(0)
      .u16(0)
      .u16(0)
      .u16(PROFILE_DOS_DATE)
      .u32(crc)
      .u32(member.data.length)
      .u32(member.data.length)
      .u16(member.nameBytes.length)
      .u16(0)
      .raw(member.nameBytes)
      .raw(member.data);
    central
      .u32(CENTRAL_SIGNATURE)
      .u16(PROFILE_MADE_BY)
      .u16(PROFILE_VERSION)
      .u16(0)
      .u16(0)
      .u16(0)
      .u16(PROFILE_DOS_DATE)
      .u32(crc)
      .u32(member.data.length)
      .u32(member.data.length)
      .u16(member.nameBytes.length)
      .u16(0)
      .u16(0)
      .u16(0)
      .u16(0)
      .u32(PROFILE_EXTERNAL)
      .u32(offset)
      .raw(member.nameBytes);
  }
  const directoryOffset = output.bytes.length;
  output.raw(Uint8Array.from(central.bytes)).u32(END_SIGNATURE).u16(0).u16(0).u16(sorted.length).u16(sorted.length).u32(central.bytes.length).u32(directoryOffset).u16(0);
  return Uint8Array.from(output.bytes);
}

/**
 * Bound content as a record holds it (MG1-012): the value itself when it lies within the
 * restricted canonical profile (IE1-001), and otherwise `{"rfc8785": <canonical base64 of its
 * RFC 8785 bytes>}`. Throws JcsError when the value has no RFC 8785 form either.
 */
export function encodeContent(value: JsonValue): JsonValue {
  if (digestOf(value) !== null) {
    return value;
  }
  const encoded: JsonObject = {};
  Object.defineProperty(encoded, ENCODED, { value: toBase64(jcsCanonicalize(value)), enumerable: true, writable: true, configurable: true });
  return encoded;
}
