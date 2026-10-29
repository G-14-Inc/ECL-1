/**
 * A strict reader of `ecl.zip.store.v1` archives (INTEGRITY-ENVELOPE-1 section 8, IE1-028 to
 * IE1-031), over bytes, with no decompression and no dependency: it runs the same in Node.js and in
 * a browser.
 *
 * The profile fixes every byte of an archive except the member data, so the reader accepts an
 * archive only when its bytes equal the profile encoding of its members' names, CRC-32 values and
 * sizes. It refuses everything else as a departure from the profile, and an archive over one of
 * the verifier's declared limits as a limit refusal, in the order the reference
 * (`ecl_reference.offline.verify_zip_members`) applies them:
 *
 * 1. the archive's bytes against `maxArchiveBytes`;
 * 2. the end record and the central directory, read as a ZIP reader reads them: a structure that
 *    cannot be read, or an archive comment, departs from the profile;
 * 3. the member count against `maxMemberCount`, then, member by member in directory order, the
 *    encryption flag, the declared size against `maxEntryUncompressedBytes`, the running total
 *    against `maxTotalUncompressedBytes` and the declared compression ratio against
 *    `maxCompressionRatio`;
 * 4. member by member: a NUL in the name, the name's stored bytes against `maxPathBytes`, the entry
 *    name rule, aliases, the fixed metadata and encoding, the order of names, the local header and
 *    the CRC-32 of the data;
 * 5. a name that is also a parent directory of another, after ASCII case folding;
 * 6. the exact profile encoding of the whole archive.
 *
 * The reader reads no ZIP64 record or extra field beyond its structure, since the profile has
 * none, and it never decompresses: a compressed member departs from the profile before its data is
 * read.
 */

/** The declared resource limits of an offline-package verifier (IE1-028). */
export interface OfflineResourceLimits {
  /** The archive's bytes. */
  readonly maxArchiveBytes: number;
  /** The archive's members, and the manifest's artifacts. */
  readonly maxMemberCount: number;
  /** The declared size of one member. */
  readonly maxEntryUncompressedBytes: number;
  /** The declared sizes of all members together. */
  readonly maxTotalUncompressedBytes: number;
  /** A member's declared size over its stored size. */
  readonly maxCompressionRatio: number;
  /** The bytes of one entry name or artifact path. */
  readonly maxPathBytes: number;
}

/** The reference verifier's limits (`ecl_reference.offline.DEFAULT_OFFLINE_RESOURCE_LIMITS`). */
export const DEFAULT_OFFLINE_RESOURCE_LIMITS: OfflineResourceLimits = Object.freeze({
  maxArchiveBytes: 1024 * 1024 * 1024,
  maxMemberCount: 100_000,
  maxEntryUncompressedBytes: 512 * 1024 * 1024,
  maxTotalUncompressedBytes: 4 * 1024 * 1024 * 1024,
  maxCompressionRatio: 1_000,
  maxPathBytes: 4_096,
});

const LIMIT_NAMES = ["maxArchiveBytes", "maxMemberCount", "maxEntryUncompressedBytes", "maxTotalUncompressedBytes", "maxCompressionRatio", "maxPathBytes"] as const;

/** `limits` when every limit is a finite positive integer (IE1-028); otherwise RangeError. */
export function checkLimits(limits: unknown): OfflineResourceLimits {
  if (typeof limits !== "object" || limits === null) {
    throw new RangeError("the offline resource limits are an object");
  }
  for (const name of LIMIT_NAMES) {
    const value = (limits as Record<string, unknown>)[name];
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
      throw new RangeError(`the offline resource limit ${name} is a positive integer`);
    }
  }
  return limits as OfflineResourceLimits;
}

/** An archive refused at the first check of IE1-022: outside the profile, or over a limit. */
export class ArchiveRefusal extends Error {
  /** True when the archive exceeds a declared limit of the verifier (IE1-028). */
  readonly limit: boolean;

  constructor(message: string, limit = false) {
    super(message);
    this.name = "ArchiveRefusal";
    this.limit = limit;
  }
}

/** One member of an archive in profile form: its entry name and its bytes. */
export interface ZipMember {
  readonly name: string;
  readonly data: Uint8Array;
}

/** The POSIX portable filename characters, of which every entry name component consists. */
export const PORTABLE_NAME_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
const PORTABLE = new Set(PORTABLE_NAME_CHARACTERS);
const DEVICE_NAMES = new Set(["con", "prn", "aux", "nul", ..."0123456789".split("").flatMap((digit) => [`com${digit}`, `lpt${digit}`])]);

/** ASCII lower case: the form under which two entry names are aliases. */
export function foldAscii(name: string): string {
  return name.replace(/[A-Z]+/g, (letters) => letters.toLowerCase());
}

function portableComponent(part: string): boolean {
  if (part === "" || part === "." || part === ".." || part.endsWith(".")) {
    return false;
  }
  for (const character of part) {
    if (!PORTABLE.has(character)) {
      return false;
    }
  }
  const stem = part.split(".", 1)[0] as string;
  return !DEVICE_NAMES.has(foldAscii(stem));
}

/**
 * Whether `name` is an entry name of `ecl.zip.store.v1`: components separated by `/`, each of the
 * POSIX portable filename characters, none `.` or `..`, none ending in `.`, and none a Windows
 * device name (CON, PRN, AUX, NUL, COM0 to COM9, LPT0 to LPT9) in any letter case before its first
 * `.`. The rule needs no Unicode table, so it gives the same result on every platform.
 */
export function isEntryName(name: string): boolean {
  return name.split("/").every(portableComponent);
}

/** A name that, after ASCII case folding, is also a parent directory of another name. */
export function fileAndDirectory(names: readonly string[]): string | undefined {
  const folded = new Set(names.map(foldAscii));
  for (const name of names) {
    const parts = foldAscii(name).split("/");
    for (let depth = 1; depth < parts.length; depth += 1) {
      const parent = parts.slice(0, depth).join("/");
      if (folded.has(parent)) {
        return parent;
      }
    }
  }
  return undefined;
}

const LOCAL_SIGNATURE = 0x04034b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const END_SIGNATURE = 0x06054b50;
const ZIP64_LOCATOR_SIGNATURE = 0x07064b50;
const LOCAL_SIZE = 30;
const CENTRAL_SIZE = 46;
const END_SIZE = 22;
const MAX_COMMENT = 0xffff;
const MAX_EXTRACT_VERSION = 63;
const PROFILE_VERSION = 20;
const PROFILE_MADE_BY = (3 << 8) | PROFILE_VERSION;
const PROFILE_DOS_DATE = (1 << 5) | 1;
const PROFILE_MODE = 0o100644;
const PROFILE_EXTERNAL = PROFILE_MODE * 0x10000;

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
})();

/** The CRC-32 of ZIP (ISO 3309, as zlib computes it). */
export function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc = (CRC_TABLE[(crc ^ byte) & 0xff] as number) ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function u16(data: Uint8Array, offset: number): number {
  return (data[offset] as number) | ((data[offset + 1] as number) << 8);
}

function u32(data: Uint8Array, offset: number): number {
  return ((data[offset] as number) | ((data[offset + 1] as number) << 8) | ((data[offset + 2] as number) << 16)) + (data[offset + 3] as number) * 0x1000000;
}

function u64(data: Uint8Array, offset: number): number {
  return u32(data, offset) + u32(data, offset + 4) * 0x100000000;
}

function signatureAt(data: Uint8Array, offset: number, signature: number): boolean {
  return offset >= 0 && offset + 4 <= data.length && u32(data, offset) === signature;
}

const utf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const NO_BYTES = new Uint8Array(0);

function latin1(data: Uint8Array): string {
  let text = "";
  for (const byte of data) {
    text += String.fromCharCode(byte);
  }
  return text;
}

function isUtf8(data: Uint8Array): boolean {
  try {
    utf8Decoder.decode(data);
    return true;
  } catch {
    return false;
  }
}

interface DirectoryEntry {
  readonly nameBytes: Uint8Array;
  readonly name: string;
  readonly madeBy: number;
  readonly extractVersion: number;
  readonly flags: number;
  readonly method: number;
  readonly time: number;
  readonly date: number;
  readonly crc: number;
  readonly compressedSize: number;
  readonly fileSize: number;
  readonly extraLength: number;
  readonly commentLength: number;
  readonly disk: number;
  readonly internal: number;
  readonly external: number;
  readonly headerOffset: number;
}

function profileDeparture(message: string): ArchiveRefusal {
  return new ArchiveRefusal(`archive is not in its ecl.zip.store.v1 encoding: ${message}`);
}

/** The end record: where it is, its fields, and the comment a ZIP reader takes after it. */
function endRecord(data: Uint8Array): { position: number; directorySize: number; directoryOffset: number; comment: Uint8Array } {
  const length = data.length;
  if (length < END_SIZE) {
    throw profileDeparture("no end of central directory record");
  }
  let position = -1;
  let comment: Uint8Array = new Uint8Array(0);
  if (signatureAt(data, length - END_SIZE, END_SIGNATURE) && u16(data, length - 2) === 0) {
    position = length - END_SIZE;
  } else {
    const start = Math.max(length - MAX_COMMENT - END_SIZE, 0);
    for (let offset = length - 4; offset >= start; offset -= 1) {
      if (signatureAt(data, offset, END_SIGNATURE)) {
        position = offset;
        break;
      }
    }
    if (position < 0 || position + END_SIZE > length) {
      throw profileDeparture("no end of central directory record");
    }
    comment = data.subarray(position + END_SIZE, Math.min(length, position + END_SIZE + u16(data, position + 20)));
  }
  if (signatureAt(data, position - 20, ZIP64_LOCATOR_SIGNATURE)) {
    throw profileDeparture("a ZIP64 record");
  }
  return { position, directorySize: u32(data, position + 12), directoryOffset: u32(data, position + 16), comment };
}

/**
 * The central directory entries, read as a ZIP reader reads them. Every entry is read and its
 * structure checked, but only the first `keep` are kept, so an archive that holds more members
 * than the member limit costs no more memory than the limit (IE1-029); `count` is the number of
 * entries the directory holds.
 */
function directory(data: Uint8Array, keep: number): { entries: DirectoryEntry[]; count: number; concat: number } {
  const end = endRecord(data);
  const concat = end.position - end.directorySize - end.directoryOffset;
  const start = end.directoryOffset + concat;
  if (start < 0) {
    throw profileDeparture("the central directory has a negative offset");
  }
  if (end.comment.length > 0) {
    throw profileDeparture("an archive comment");
  }
  const stop = start + end.directorySize;
  const entries: DirectoryEntry[] = [];
  let count = 0;
  let offset = start;
  let total = 0;
  while (total < end.directorySize) {
    if (offset + CENTRAL_SIZE > stop || u32(data, offset) !== CENTRAL_SIGNATURE) {
      throw profileDeparture("a truncated or unreadable central directory entry");
    }
    const nameLength = u16(data, offset + 28);
    const extraLength = u16(data, offset + 30);
    const commentLength = u16(data, offset + 32);
    const flags = u16(data, offset + 8);
    const nameStart = offset + CENTRAL_SIZE;
    const kept = count < keep;
    // An entry beyond the limit is only checked, so no view of its name is made unless the check needs one.
    const nameBytes = kept || flags & 0x800 ? data.subarray(nameStart, Math.min(stop, nameStart + nameLength)) : NO_BYTES;
    let name = "";
    if (flags & 0x800) {
      if (!isUtf8(nameBytes)) {
        throw profileDeparture("a name flagged as UTF-8 that is not UTF-8");
      }
      if (kept) {
        name = utf8Decoder.decode(nameBytes);
      }
    } else if (kept) {
      // Bytes above 0x7f decode to characters outside the portable set in any reading, so they
      // are kept as Latin-1 characters and refused by the entry name rule.
      name = latin1(nameBytes);
    }
    const extraStart = Math.min(stop, nameStart + nameLength);
    const extra = kept || extraLength > 0 ? data.subarray(extraStart, Math.min(stop, extraStart + extraLength)) : NO_BYTES;
    const commentStart = Math.min(stop, extraStart + extraLength);
    const commentEnd = Math.min(stop, commentStart + commentLength);
    const extractVersion = data[offset + 6] as number;
    if (extractVersion > MAX_EXTRACT_VERSION) {
      throw profileDeparture("an unsupported extraction version");
    }
    let compressedSize = u32(data, offset + 20);
    let fileSize = u32(data, offset + 24);
    let headerOffset = u32(data, offset + 42);
    // The extra fields' structure, and the sizes a ZIP64 field gives where a size is saturated.
    for (let at = 0; extra.length - at >= 4; ) {
      const kind = u16(extra, at);
      const size = u16(extra, at + 2);
      if (size + 4 > extra.length - at) {
        throw profileDeparture("a corrupt extra field");
      }
      if (kind === 0x0001) {
        let field = at + 4;
        const fieldEnd = at + 4 + size;
        const next = (): number => {
          if (field + 8 > fieldEnd) {
            throw profileDeparture("a corrupt ZIP64 extra field");
          }
          const value = u64(extra, field);
          field += 8;
          return value;
        };
        if (fileSize === 0xffffffff) {
          fileSize = next();
        }
        if (compressedSize === 0xffffffff) {
          compressedSize = next();
        }
        if (headerOffset === 0xffffffff) {
          headerOffset = next();
        }
      }
      at += size + 4;
    }
    count += 1;
    total += CENTRAL_SIZE + nameLength + extraLength + commentLength;
    if (!kept) {
      offset = commentEnd;
      continue;
    }
    entries.push({
      nameBytes,
      name,
      madeBy: u16(data, offset + 4),
      extractVersion,
      flags,
      method: u16(data, offset + 10),
      time: u16(data, offset + 12),
      date: u16(data, offset + 14),
      crc: u32(data, offset + 16),
      compressedSize,
      fileSize,
      extraLength: extra.length,
      commentLength: commentEnd - commentStart,
      disk: u16(data, offset + 34),
      internal: u16(data, offset + 36),
      external: u32(data, offset + 38),
      headerOffset: headerOffset + concat,
    });
    offset = commentEnd;
  }
  return { entries, count, concat };
}

function bytesEqual(data: Uint8Array, offset: number, expected: Uint8Array): boolean {
  if (offset < 0 || offset + expected.length > data.length) {
    return false;
  }
  for (let index = 0; index < expected.length; index += 1) {
    if (data[offset + index] !== expected[index]) {
      return false;
    }
  }
  return true;
}

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

/** Why the archive departs from the exact profile encoding of `members`, or undefined. */
function layoutProblem(data: Uint8Array, members: ReadonlyArray<{ nameBytes: Uint8Array; crc: number; size: number }>): string | undefined {
  if (members.length > 0xffff) {
    return "more members than the end record can count";
  }
  const central = new Writer();
  let offset = 0;
  for (const member of members) {
    const local = new Writer()
      .u32(LOCAL_SIGNATURE)
      .u16(PROFILE_VERSION)
      .u16(0)
      .u16(0)
      .u16(0)
      .u16(PROFILE_DOS_DATE)
      .u32(member.crc)
      .u32(member.size)
      .u32(member.size)
      .u16(member.nameBytes.length)
      .u16(0)
      .raw(member.nameBytes);
    if (offset > 0xffffffff || !bytesEqual(data, offset, Uint8Array.from(local.bytes))) {
      return "a local header is not at its profile offset or not in profile form";
    }
    central
      .u32(CENTRAL_SIGNATURE)
      .u16(PROFILE_MADE_BY)
      .u16(PROFILE_VERSION)
      .u16(0)
      .u16(0)
      .u16(0)
      .u16(PROFILE_DOS_DATE)
      .u32(member.crc)
      .u32(member.size)
      .u32(member.size)
      .u16(member.nameBytes.length)
      .u16(0)
      .u16(0)
      .u16(0)
      .u16(0)
      .u32(PROFILE_EXTERNAL)
      .u32(offset)
      .raw(member.nameBytes);
    offset += local.bytes.length + member.size;
  }
  if (offset > 0xffffffff || central.bytes.length > 0xffffffff) {
    return "the archive is too large for the end record";
  }
  const tail = Uint8Array.from(
    new Writer().raw(Uint8Array.from(central.bytes)).u32(END_SIGNATURE).u16(0).u16(0).u16(members.length).u16(members.length).u32(central.bytes.length).u32(offset).u16(0).bytes,
  );
  if (offset + tail.length !== data.length || !bytesEqual(data, offset, tail)) {
    return "the central directory and end record are not the profile encoding, or bytes follow";
  }
  return undefined;
}

/**
 * The members of an archive in exact `ecl.zip.store.v1` form, in archive order. Anything else is
 * an ArchiveRefusal: `limit` is true when the archive exceeds one of `limits`. Invalid `limits`
 * throw RangeError.
 */
export function readStoredZip(data: Uint8Array, limits: OfflineResourceLimits): ZipMember[] {
  checkLimits(limits);
  if (data.length > limits.maxArchiveBytes) {
    throw new ArchiveRefusal("archive size exceeds the verifier budget", true);
  }
  const { entries, count } = directory(data, limits.maxMemberCount);
  if (count > limits.maxMemberCount) {
    throw new ArchiveRefusal("archive member count exceeds the verifier budget", true);
  }
  let total = 0;
  for (const entry of entries) {
    if (entry.flags & 0x1) {
      throw profileDeparture(`an encrypted member: ${entry.name}`);
    }
    if (entry.fileSize > limits.maxEntryUncompressedBytes) {
      throw new ArchiveRefusal(`archive member exceeds the verifier budget: ${entry.name}`, true);
    }
    total += entry.fileSize;
    if (total > limits.maxTotalUncompressedBytes) {
      throw new ArchiveRefusal("archive expansion exceeds the verifier budget", true);
    }
    if (entry.fileSize > 0 && BigInt(entry.fileSize) > BigInt(Math.max(entry.compressedSize, 1)) * BigInt(limits.maxCompressionRatio)) {
      throw new ArchiveRefusal(`archive member compression ratio exceeds the verifier budget: ${entry.name}`, true);
    }
  }
  const seen = new Set<string>();
  const members: Array<{ name: string; nameBytes: Uint8Array; crc: number; size: number; data: Uint8Array }> = [];
  let prior: Uint8Array | undefined;
  for (const entry of entries) {
    if (entry.name.includes("\u0000")) {
      throw profileDeparture(`a name with a NUL character: ${JSON.stringify(entry.name)}`);
    }
    if (entry.nameBytes.length > limits.maxPathBytes) {
      throw new ArchiveRefusal("archive member name exceeds the verifier budget", true);
    }
    if (!isEntryName(entry.name)) {
      throw profileDeparture(`a name that is not an entry name: ${JSON.stringify(entry.name)}`);
    }
    const alias = foldAscii(entry.name);
    if (seen.has(alias)) {
      throw profileDeparture(`a duplicate member: ${entry.name}`);
    }
    seen.add(alias);
    if (
      entry.external !== PROFILE_EXTERNAL ||
      entry.madeBy !== PROFILE_MADE_BY ||
      entry.extractVersion !== PROFILE_VERSION ||
      entry.disk !== 0 ||
      entry.internal !== 0 ||
      entry.date !== PROFILE_DOS_DATE ||
      entry.time !== 0 ||
      entry.method !== 0 ||
      entry.flags !== 0 ||
      entry.extraLength !== 0 ||
      entry.commentLength !== 0
    ) {
      throw profileDeparture(`member metadata or encoding outside the profile: ${entry.name}`);
    }
    if (prior !== undefined && compareBytes(entry.nameBytes, prior) < 0) {
      throw profileDeparture("entries are not in the bytewise order of their names");
    }
    prior = entry.nameBytes;
    const local = entry.headerOffset;
    if (local < 0 || local + LOCAL_SIZE > data.length || u32(data, local) !== LOCAL_SIGNATURE) {
      throw profileDeparture(`an unreadable local header: ${entry.name}`);
    }
    const localName = data.subarray(local + LOCAL_SIZE, Math.min(data.length, local + LOCAL_SIZE + u16(data, local + 26)));
    if (compareBytes(localName, entry.nameBytes) !== 0) {
      throw profileDeparture(`the local and central names differ: ${entry.name}`);
    }
    const start = local + LOCAL_SIZE + u16(data, local + 26) + u16(data, local + 28);
    const size = Math.min(entry.compressedSize, entry.fileSize);
    if (size > 0 && start + size > data.length) {
      throw profileDeparture(`the data of a member is truncated: ${entry.name}`);
    }
    const content = size > 0 ? data.subarray(start, start + size) : new Uint8Array(0);
    if (crc32(content) !== entry.crc || entry.compressedSize < entry.fileSize) {
      throw profileDeparture(`the CRC-32 or size of a member does not hold: ${entry.name}`);
    }
    members.push({ name: entry.name, nameBytes: entry.nameBytes, crc: entry.crc, size: entry.fileSize, data: content });
  }
  const conflict = fileAndDirectory(members.map((member) => member.name));
  if (conflict !== undefined) {
    throw profileDeparture(`a member is both a file and a directory: ${conflict}`);
  }
  const problem = layoutProblem(data, members);
  if (problem !== undefined) {
    throw profileDeparture(problem);
  }
  return members.map((member) => ({ name: member.name, data: member.data }));
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
