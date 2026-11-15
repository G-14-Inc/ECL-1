import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ArchiveRefusal,
  CURRENT_TRUST_FAILED,
  DEFAULT_OFFLINE_RESOURCE_LIMITS,
  REFERENCE_PROFILE,
  TRUSTED_TIME_PROFILE,
  TrustPolicy,
  VerifierInputError,
  crc32,
  foldAscii,
  isEntryName,
  packageIdentifiers,
  readStoredZip,
  verifyOfflinePackage,
  verifyPackageBytes,
} from "../../src/index.js";
import type { OfflineResourceLimits, ZipMember } from "../../src/index.js";
import { bytes, suite } from "./helpers.js";
import { writeStoredZip } from "./producer-fixtures.js";

const SUITE = "conformance/suites/offline-package";
const NOW = "2026-10-01T00:00:00Z";
const RESOURCE_LIMIT = "ecl.error.resource-limit-exceeded.v1";
const SEMANTIC_INVALID = "ecl.error.semantic-invalid.v1";
const text = new TextEncoder();

function policy(path = `${SUITE}/trust-policy.json`): TrustPolicy {
  return TrustPolicy.load(bytes(path));
}

function valid(): Uint8Array {
  return bytes(`${SUITE}/package-valid-verified.zip`);
}

function limits(changes: Partial<OfflineResourceLimits>): OfflineResourceLimits {
  return { ...DEFAULT_OFFLINE_RESOURCE_LIMITS, ...changes };
}

function refusal(data: Uint8Array, given: OfflineResourceLimits = DEFAULT_OFFLINE_RESOURCE_LIMITS): ArchiveRefusal {
  try {
    readStoredZip(data, given);
  } catch (error) {
    if (error instanceof ArchiveRefusal) {
      return error;
    }
    throw error;
  }
  assert.fail("the archive was accepted");
}

test("every package vector gets the reference's verdict and identifiers", () => {
  const vectors = suite("offline-package");
  assert.ok(vectors.length >= 15);
  for (const vector of vectors) {
    const report = verifyOfflinePackage(bytes(vector.path), policy(vector.trust_policy_path), {
      now: vector.evaluated_at as string,
      history: (vector.trust_policy_history_paths ?? []).map((path) => policy(path)),
    });
    assert.equal(report.verdict, vector.expected_verdict, vector.id);
    const identifiers = packageIdentifiers(report);
    if (vector.expected === "pass") {
      assert.deepEqual(identifiers, [], vector.id);
    } else {
      assert.ok(identifiers.includes(vector.expected_primary_id as string), `${vector.id}: ${identifiers.join(" ")}`);
    }
  }
});

test("the reader returns the members of a profile archive and its writer builds the same bytes", () => {
  const data = valid();
  const members = readStoredZip(data, DEFAULT_OFFLINE_RESOURCE_LIMITS);
  assert.equal(members[0]?.name, "evidence/envelope-01-payload.json");
  assert.ok(members.some((member) => member.name === "manifest.json"));
  assert.deepEqual(writeStoredZip(members), data);
  // Every name is in bytewise order, and the writer sorts names it is given out of order.
  assert.deepEqual(writeStoredZip([...members].reverse()), data);
});

test("any single byte changed in a profile archive's headers is refused", () => {
  const data = writeStoredZip([
    { name: "a.json", data: text.encode("{}") },
    { name: "b/c.json", data: text.encode("[]") },
  ]);
  assert.equal(readStoredZip(data, DEFAULT_OFFLINE_RESOURCE_LIMITS).length, 2);
  // Each member's data follows its 30-byte local header and its name; every other byte is fixed.
  const first = 30 + "a.json".length;
  const second = first + 2 + 30 + "b/c.json".length;
  const dataBytes = new Set([first, first + 1, second, second + 1]);
  for (let position = 0; position < data.length; position += 1) {
    for (const bit of [0, 3, 7]) {
      const changed = Uint8Array.from(data);
      changed[position] = (changed[position] as number) ^ (1 << bit);
      if (dataBytes.has(position)) {
        // A changed data byte keeps the layout and breaks the CRC-32.
        assert.equal(refusal(changed).limit, false, `data ${position}`);
        continue;
      }
      let refused = false;
      try {
        readStoredZip(changed, DEFAULT_OFFLINE_RESOURCE_LIMITS);
      } catch (error) {
        assert.ok(error instanceof ArchiveRefusal);
        refused = true;
      }
      assert.ok(refused, `byte ${position} bit ${bit}`);
    }
  }
  const prepended = new Uint8Array([0x23, 0x21, ...data]);
  assert.equal(refusal(prepended).limit, false);
  assert.equal(refusal(new Uint8Array([...data, 0])).limit, false);
  assert.equal(refusal(new Uint8Array(0)).limit, false);
  assert.equal(refusal(text.encode("not an archive")).limit, false);
});

test("entry names: the POSIX portable characters, compared after ASCII case folding", () => {
  for (const name of ["a.json", "evidence/envelope-01.json", ".hidden/x_y-z.1", "console.json", "com10.json", "A/B/C"]) {
    assert.ok(isEntryName(name), name);
  }
  for (const name of [
    "",
    "/a.json",
    "a//b.json",
    "a/",
    "./a.json",
    "../a.json",
    "a/../b.json",
    "trailing.",
    "a./b.json",
    "con",
    "NUL.txt",
    "a/Com1.json",
    "lpt9",
    "café.json",
    "a b.json",
    "a+b.json",
    "a:b.json",
    "a\\b.json",
    "~a.json",
    "control\u0001.json",
  ]) {
    assert.ok(!isEntryName(name), JSON.stringify(name));
    const archive = new Uint8Array(writeStoredZipUnchecked([{ name, data: text.encode("{}") }]));
    assert.equal(refusal(archive).limit, false, JSON.stringify(name));
  }
  assert.equal(foldAscii("Docs/README.MD"), "docs/readme.md");
  assert.equal(foldAscii("É.json"), "É.json");
  for (const names of [["A.json", "a.json"], ["Dir/File.json", "dir/file.json"], ["docs", "Docs/a.json"], ["a", "a/b.json"]]) {
    const archive = writeStoredZipUnchecked(names.map((name) => ({ name, data: text.encode("{}") })));
    assert.equal(refusal(archive).limit, false, names.join(" "));
  }
  assert.throws(() => writeStoredZip([{ name: "café.json", data: new Uint8Array(0) }]), RangeError);
});

test("metadata outside the profile, encryption, a comment and compression are refused", () => {
  const base = writeStoredZip([{ name: "a.json", data: text.encode("{}") }]);
  // Offsets of the central directory entry: after the 30-byte local header, the name and the data.
  const central = 30 + 6 + 2;
  const cases: Array<[string, number, number]> = [
    ["local flags: encrypted", 6, 0x01],
    ["local flags: data descriptor", 6, 0x08],
    ["local flags: UTF-8", 7, 0x08],
    ["local method", 8, 0x08],
    ["local time", 10, 0x01],
    ["central made-by", central + 5, 0x00],
    ["central flags: UTF-8", central + 9, 0x08],
    ["central method: deflated", central + 10, 0x08],
    ["central date", central + 14, 0x5a],
    ["central internal attributes", central + 36, 0x01],
    ["central mode: executable", central + 40, 0xed],
  ];
  for (const [name, offset, value] of cases) {
    const changed = Uint8Array.from(base);
    changed[offset] = value;
    assert.equal(refusal(changed).limit, false, name);
  }
  // An archive comment: the end record's comment length and the comment.
  const commented = new Uint8Array([...base.subarray(0, base.length - 2), 4, 0, ...text.encode("note")]);
  assert.match(refusal(commented).message, /archive comment/);
});

test("the declared limits are refused as limits, before other checks of the members", () => {
  const data = valid();
  const members = readStoredZip(data, DEFAULT_OFFLINE_RESOURCE_LIMITS);
  assert.ok(refusal(data, limits({ maxArchiveBytes: data.length - 1 })).limit);
  assert.ok(refusal(data, limits({ maxMemberCount: members.length - 1 })).limit);
  const largest = Math.max(...members.map((member) => member.data.length));
  assert.ok(refusal(data, limits({ maxEntryUncompressedBytes: largest - 1 })).limit);
  const total = members.reduce((sum, member) => sum + member.data.length, 0);
  assert.ok(refusal(data, limits({ maxTotalUncompressedBytes: total - 1 })).limit);
  const longest = Math.max(...members.map((member) => member.name.length));
  assert.ok(refusal(data, limits({ maxPathBytes: longest - 1 })).limit);
  readStoredZip(data, limits({ maxArchiveBytes: data.length, maxMemberCount: members.length, maxEntryUncompressedBytes: largest, maxTotalUncompressedBytes: total, maxPathBytes: longest }));
  // A deflated member whose declared size is over the ratio is refused before it is read.
  const bomb = Uint8Array.from(writeStoredZip([{ name: "bomb.bin", data: new Uint8Array(10) }]));
  bomb[8] = 8; // local method: deflated
  bomb[30 + 8 + 10 + 10] = 8; // central method: deflated
  new DataView(bomb.buffer).setUint32(30 + 8 + 10 + 24, 5_000, true); // central uncompressed size
  assert.ok(refusal(bomb, limits({ maxCompressionRatio: 10 })).limit);
  assert.equal(refusal(bomb).limit, false);
  // A limit takes precedence over a later departure from the profile.
  const misnamed = writeStoredZipUnchecked([{ name: "a b.json", data: new Uint8Array(100) }]);
  assert.ok(refusal(misnamed, limits({ maxEntryUncompressedBytes: 10 })).limit);
  assert.throws(() => readStoredZip(data, limits({ maxMemberCount: 0 })), RangeError);
});

test("a package over a limit is invalid with the limit error at the check that meets it", () => {
  const data = valid();
  const check1 = verifyOfflinePackage(data, policy(), { now: NOW, limits: limits({ maxArchiveBytes: 100 }) });
  assert.equal(check1.verdict, "invalid");
  assert.deepEqual(packageIdentifiers(check1), [RESOURCE_LIMIT]);
  // Check 4: the archive's names are short, but the manifest names a long path it does not hold.
  const members = readStoredZip(data, DEFAULT_OFFLINE_RESOURCE_LIMITS);
  const manifest = JSON.parse(new TextDecoder().decode(members.find((member) => member.name === "manifest.json")?.data)) as {
    artifacts: Array<Record<string, unknown>>;
  };
  manifest.artifacts.push({ ...manifest.artifacts[0], path: `material/${"x".repeat(80)}.json`, role: "trust_root" });
  const longPath = writeStoredZip(members.map((member) => (member.name === "manifest.json" ? { name: member.name, data: text.encode(JSON.stringify(manifest)) } : member)));
  const check4 = verifyOfflinePackage(longPath, policy(), { now: NOW, limits: limits({ maxPathBytes: 64 }) });
  assert.equal(check4.verdict, "invalid");
  assert.deepEqual(packageIdentifiers(check4), [RESOURCE_LIMIT]);
  // Without the lower limit the same package lacks that artifact.
  assert.equal(verifyOfflinePackage(longPath, policy(), { now: NOW }).verdict, "incomplete");
});

test("the bundle verifier's options reach the package's bundle unchanged", () => {
  const data = valid();
  const revoked = policy(`${SUITE}/trust-policy-revoked-after-use.json`);
  const failed = verifyOfflinePackage(data, revoked, { now: NOW, history: [policy()] });
  assert.equal(failed.verdict, CURRENT_TRUST_FAILED);
  const accepted = verifyOfflinePackage(data, revoked, { now: NOW, history: [policy()], acceptCurrentTrustFailure: true });
  assert.equal(accepted.verdict, "verified");
  assert.equal(accepted.acceptedCurrentTrustFailure, true);
  const trusted = verifyOfflinePackage(data, policy(), { now: NOW, requireTrustedTime: true });
  assert.equal(trusted.verdict, "invalid");
  assert.equal(trusted.verificationProfile, TRUSTED_TIME_PROFILE);
  assert.ok(packageIdentifiers(trusted).includes("ecl.error.trusted-time-required.v1"));
  // A refusal of the package itself names the profile that the options ask for, as the bundle
  // verifier's report would.
  const early = verifyOfflinePackage(text.encode("not an archive"), policy(), { now: NOW, requireTrustedTime: true });
  assert.deepEqual(packageIdentifiers(early), [SEMANTIC_INVALID]);
  assert.equal(early.verificationProfile, TRUSTED_TIME_PROFILE);
  assert.equal(verifyOfflinePackage(text.encode("x"), policy(), { now: NOW }).verificationProfile, REFERENCE_PROFILE);
});

test("caller arguments are checked before the package is read, whatever it holds", () => {
  for (const data of [valid(), text.encode("not an archive")]) {
    assert.throws(() => verifyOfflinePackage(data, policy(), { now: "2026-10-01T00:00:00.5Z" }), RangeError);
    assert.throws(() => verifyOfflinePackage(data, policy(), { now: NOW, responseClockSkewSeconds: -1 }), RangeError);
    assert.throws(() => verifyOfflinePackage(data, policy(), { now: NOW, limits: limits({ maxPathBytes: 0.5 }) }), RangeError);
  }
  assert.throws(() => verifyOfflinePackage([1, 2] as unknown as Uint8Array, policy(), { now: NOW }), RangeError);
});

test("verifyPackageBytes loads the trust policy files and refuses unusable input", () => {
  const { report } = verifyPackageBytes(valid(), bytes(`${SUITE}/trust-policy.json`), { now: NOW });
  assert.equal(report.verdict, "verified");
  assert.throws(() => verifyPackageBytes(valid(), text.encode("{}"), { now: NOW }), VerifierInputError);
  assert.throws(() => verifyPackageBytes(valid(), bytes(`${SUITE}/trust-policy.json`), { now: "yesterday" }), /invalid evaluation time/);
});

test("CRC-32 is ZIP's", () => {
  assert.equal(crc32(new Uint8Array(0)), 0);
  assert.equal(crc32(text.encode("123456789")), 0xcbf43926);
});

/**
 * An archive in the profile's encoding of `members`, in the order given and with the names given,
 * flagged as UTF-8 when not ASCII: what a producer that ignored the entry name rule would write.
 */
function writeStoredZipUnchecked(members: readonly ZipMember[]): Uint8Array {
  const out: number[] = [];
  const central: number[] = [];
  const u16 = (target: number[], value: number): void => {
    target.push(value & 0xff, (value >>> 8) & 0xff);
  };
  const u32 = (target: number[], value: number): void => {
    target.push(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
  };
  for (const member of members) {
    const name = text.encode(member.name);
    const offset = out.length;
    const crc = crc32(member.data);
    const flags = name.some((byte) => byte > 0x7f) ? 0x800 : 0;
    for (const target of [out, central]) {
      u32(target, target === out ? 0x04034b50 : 0x02014b50);
      if (target === central) {
        u16(target, (3 << 8) | 20);
      }
      u16(target, 20);
      u16(target, flags);
      u16(target, 0);
      u16(target, 0);
      u16(target, 0x21);
      u32(target, crc);
      u32(target, member.data.length);
      u32(target, member.data.length);
      u16(target, name.length);
      u16(target, 0);
      if (target === central) {
        u16(target, 0);
        u16(target, 0);
        u16(target, 0);
        u32(target, 0o100644 * 0x10000);
        u32(target, offset);
      }
      target.push(...name);
    }
    out.push(...member.data);
  }
  const directoryOffset = out.length;
  out.push(...central);
  u32(out, 0x06054b50);
  u16(out, 0);
  u16(out, 0);
  u16(out, members.length);
  u16(out, members.length);
  u32(out, central.length);
  u32(out, directoryOffset);
  u16(out, 0);
  return Uint8Array.from(out);
}
