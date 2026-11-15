import assert from "node:assert/strict";
import { test } from "node:test";
import { DEFAULT_OFFLINE_RESOURCE_LIMITS, readStoredZip } from "../../src/offline/zip.js";

test("IE1-028 archive-byte ceilings are checked before input is inspected", () => {
  for (const maxArchiveBytes of [2_147_483_648, Number.MAX_SAFE_INTEGER]) {
    let inspected = false;
    const input = { get length(): number { inspected = true; throw new Error("input inspected"); } };
    assert.throws(
      () => readStoredZip(input as unknown as Uint8Array, { ...DEFAULT_OFFLINE_RESOURCE_LIMITS, maxArchiveBytes }),
      (error: unknown) => error instanceof RangeError && error.message.includes("maxArchiveBytes"),
    );
    assert.equal(inspected, false);
  }
});

test("the archive-byte ceiling itself permits a valid tiny archive", () => {
  const empty = new Uint8Array(22);
  empty.set([0x50, 0x4b, 0x05, 0x06]);
  assert.deepEqual(readStoredZip(empty, { ...DEFAULT_OFFLINE_RESOURCE_LIMITS, maxArchiveBytes: 2_147_483_647 }), []);
});
