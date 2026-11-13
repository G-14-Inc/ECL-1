/** A refused, unread package still has the ordinary invalid report (IE1-028). */
import { verifyBundleBytes } from "../src/evidence/bytes.js";
import type { BytesOptions } from "../src/evidence/bytes.js";
import { RESOURCE_LIMIT, withScope } from "../src/evidence/verify.js";

export function oversizedPackageReport(trustPolicy: Uint8Array, options: BytesOptions, bytes: number, limit: number) {
  if (!Number.isSafeInteger(bytes) || bytes <= limit || !Number.isSafeInteger(limit) || limit < 1) {
    throw new RangeError("an oversized package must exceed a positive byte limit");
  }
  // Reuse caller-input validation and the empty report's profile/metadata; no
  // package bytes are read and no envelope or bundle check is represented as run.
  const { report: base, policy } = verifyBundleBytes(new TextEncoder().encode("{}"), trustPolicy, options);
  const report = withScope({
    ...base,
    verdict: "invalid",
    findings: [{ code: RESOURCE_LIMIT, message: `offline package size ${bytes} exceeds the browser archive limit ${limit}; refused before reading its contents` }],
  });
  return { report, policy };
}
