#!/usr/bin/env node
/**
 * ecl-verify-ts: offline verification of a signed ECL evidence bundle or an offline package, with
 * the interface of the reference's `ecl-verify`.
 *
 *   ecl-verify-ts BUNDLE --trust-policy FILE [--trust-policy-history FILE]... [--now RFC3339]
 *                 [--accept-current-trust-failure] [--require-trusted-time] [--register FILE] [--json]
 *
 * A decision response without `ecl.ext.decision-basis.v1` makes the bundle invalid (DCMP2-053);
 * `--register` checks each decision basis against a Consequential Action Register.
 *
 * A file that begins with the bytes `PK` is verified as an offline package (OFFLINE-VERIFICATION-1,
 * IE1-022) of at most 1 GiB, the declared archive limit, under the same inputs; any other file is a
 * JSON evidence bundle of at most 1 MiB.
 *
 * Exit status: 0 verified, 1 invalid, 2 usage error, 3 incomplete, 4 current trust failed
 * (EBMP2-060). A usage error is reported on standard error in one line, as the reference's
 * `ecl-verify` reports it: `error: CODE: MESSAGE` when the refusal has a registered code (every
 * refusal of an input file above its byte limit is `ecl.error.resource-limit-exceeded.v1`,
 * TP1-007), and `error: MESSAGE` otherwise.
 */

import { closeSync, fstatSync, openSync, readSync, statSync } from "node:fs";
import { oversizedInput, verifyBundleBytes, VerifierInputError } from "../evidence/bytes.js";
import { primaryFinding, reportToJson, SCOPE_TEXT } from "../evidence/verify.js";
import type { BundleReport } from "../evidence/verify.js";
import { canonicalText } from "../json/canonical.js";
import { MAX_TRUST_POLICY_BYTES } from "../trust/policy.js";
import { MAX_BUNDLE_BYTES, MAX_REGISTER_BYTES } from "../evidence/bytes.js";
import { verifyPackageBytes } from "../offline/package.js";
import { DEFAULT_OFFLINE_RESOURCE_LIMITS } from "../offline/zip.js";
import { nowInstant } from "../time.js";

/** An offline package is read up to the verifier's declared archive limit (IE1-028). */
const MAX_PACKAGE_BYTES = DEFAULT_OFFLINE_RESOURCE_LIMITS.maxArchiveBytes;

const EXIT: Record<string, number> = { verified: 0, invalid: 1, incomplete: 3, "current-trust-failed": 4 };

const USAGE =
  "usage: ecl-verify-ts BUNDLE --trust-policy FILE [--trust-policy-history FILE]... [--now RFC3339] " +
  "[--accept-current-trust-failure] [--require-trusted-time] [--register FILE] [--json]\n";

/**
 * The first `count` bytes of a file, or the whole file when it is shorter. Nothing past them is read,
 * whatever the file's size says: a pipe or a device has none, and a file can grow while it is read.
 */
function readAtMost(path: string, count: number): Uint8Array {
  const descriptor = openSync(path, "r");
  try {
    let data = new Uint8Array(Math.min(count, Math.max(fstatSync(descriptor).size + 1, 64 * 1024)));
    let total = 0;
    for (;;) {
      if (total === data.length) {
        if (total === count) {
          break;
        }
        const grown = new Uint8Array(Math.min(count, data.length * 2));
        grown.set(data);
        data = grown;
      }
      const read = readSync(descriptor, data, total, data.length - total, null);
      if (read === 0) {
        break;
      }
      total += read;
    }
    return data.subarray(0, total);
  } finally {
    closeSync(descriptor);
  }
}

/** A file of at most `limit` bytes, refused after reading one byte more than the limit (IE1-029). */
function readLimited(path: string, limit: number, kind: string, label: string): Uint8Array {
  let data: Uint8Array;
  try {
    data = readAtMost(path, limit + 1);
  } catch (error) {
    throw new VerifierInputError(`cannot read ${kind} file (${error instanceof Error ? error.name : "Error"})`);
  }
  if (data.length > limit) {
    throw oversizedInput(kind, label);
  }
  return data;
}

/** Whether the evidence file is an offline package: an archive begins with `PK`. */
function isPackage(path: string): boolean {
  const head = Buffer.alloc(2);
  let read = 0;
  try {
    const descriptor = openSync(path, "r");
    try {
      read = readSync(descriptor, head, 0, 2, 0);
    } finally {
      closeSync(descriptor);
    }
  } catch (error) {
    throw new VerifierInputError(`cannot read bundle file (${error instanceof Error ? error.name : "Error"})`);
  }
  return read === 2 && head[0] === 0x50 && head[1] === 0x4b;
}

/** An offline package file, refused unread above the declared archive limit. */
function readPackage(path: string): Uint8Array {
  let size: number;
  try {
    size = statSync(path).size;
  } catch (error) {
    throw new VerifierInputError(`cannot read offline package file (${error instanceof Error ? error.name : "Error"})`);
  }
  if (size > MAX_PACKAGE_BYTES) {
    throw oversizedInput("offline package", "1 GiB");
  }
  return readLimited(path, MAX_PACKAGE_BYTES, "offline package", "1 GiB");
}

function human(report: BundleReport, currentVersion: string): string {
  // EBMP2-076: what the verdict does not establish comes with the verdict, then what it does.
  const lines = [`verdict: ${report.verdict}`];
  // EBMP2-060: the primary finding of a verdict other than verified, the failing current status
  // of a trust dependency for current-trust-failed among them.
  const primary = primaryFinding(report);
  if (primary !== null) {
    lines.push(`primary: ${primary}`);
  }
  for (const item of report.scope.notEstablished) {
    const reason = report.scope.reasons[item];
    lines.push(`not-established: ${item}: ${SCOPE_TEXT[item] ?? ""}${reason === undefined ? "" : ` (reason: ${reason})`}`);
  }
  for (const item of report.scope.established) {
    lines.push(`established: ${item}: ${SCOPE_TEXT[item] ?? ""}`);
  }
  // EBMP2-076: the checks that ran for each established item and the objects they covered.
  for (const item of report.scope.established) {
    const behind = report.scope.checks[item];
    lines.push(`checks ${item}: ${(behind?.checks ?? []).join(",")} objects=${(behind?.objects ?? []).join(",") || "-"}`);
  }
  lines.push(`verification-profile: ${report.verificationProfile}`);
  lines.push(`evaluation-time: ${report.evaluationTime ?? "-"}`);
  if (report.acceptedCurrentTrustFailure) {
    lines.push("accepted: current trust failure, by --accept-current-trust-failure");
  }
  if (report.register !== null) {
    const digest = report.register["digest"] as { value: string };
    lines.push(`decision-basis register: ${String(report.register["uri"])} sha256:${digest.value}`);
  } else {
    lines.push("decision-basis register: none; declared classes not checked against a register");
  }
  for (const check of report.envelopeChecks) {
    lines.push(
      `envelope ${check.index}: kind=${check.kind} signers=${check.signerKeyIds.join(",") || "-"} ` +
        `historical=${check.historical} current=${check.current} ` +
        `historical-policy=${check.historicalPolicyVersion ?? "-"} current-policy=${currentVersion} ` +
        `trusted-time=${check.trustedTime ?? "-"}`,
    );
  }
  // TP1-006: each trust dependency, with the policy versions and the revocation it used.
  for (const item of report.trustDependencies) {
    lines.push(
      `dependency ${item.index}: role=${item.role} key=${item.keyId} counter=${item.counterId ?? "-"} at=${item.at ?? "-"} ` +
        `historical-policy=${item.historicalPolicyVersion ?? "-"} historical=${item.historical} current-policy=${item.currentPolicyVersion} ` +
        `revoked-effective-at=${item.revokedEffectiveAt ?? "-"} current=${item.current}`,
    );
  }
  for (const check of report.bindingChecks) {
    lines.push(`binding ${check.name}: ${check.passed ? "pass" : (check.code ?? "fail")}`);
  }
  lines.push(`causal: ${report.causalStatus}`);
  for (const identifier of report.unresolvedPredecessorIds) {
    lines.push(`unresolved-predecessor: ${identifier}`);
  }
  // EBMP2-072: a server answer that arrived after the authorization's window is information.
  lines.push(`completion-after-window: ${report.completionAfterWindow ? "true" : "false"}`);
  for (const effect of report.effects) {
    lines.push(`effect ${effect.actionId}: state=${effect.state} level=${effect.level} authority=${effect.authority} reason=${effect.reason ?? "-"}`);
  }
  for (const finding of report.findings) {
    lines.push(`finding: ${finding.code}: ${finding.message}`);
  }
  return lines.join("\n") + "\n";
}

function main(argv: string[]): number {
  let bundlePath: string | undefined;
  let policyPath: string | undefined;
  const historyPaths: string[] = [];
  let now: string | undefined;
  let accept = false;
  let requireTrustedTime = false;
  let registerPath: string | undefined;
  let json = false;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index] as string;
    if (arg === "--trust-policy") {
      policyPath = argv[++index];
    } else if (arg === "--trust-policy-history") {
      const path = argv[++index];
      if (path !== undefined) {
        historyPaths.push(path);
      }
    } else if (arg === "--now") {
      now = argv[++index];
    } else if (arg === "--accept-current-trust-failure") {
      accept = true;
    } else if (arg === "--require-trusted-time") {
      requireTrustedTime = true;
    } else if (arg === "--register") {
      registerPath = argv[++index];
      if (registerPath === undefined) {
        process.stderr.write(USAGE);
        return 2;
      }
    } else if (arg === "--json") {
      json = true;
    } else if (arg === "-h" || arg === "--help") {
      process.stdout.write(USAGE);
      return 0;
    } else if (bundlePath === undefined && !arg.startsWith("-")) {
      bundlePath = arg;
    } else {
      process.stderr.write(USAGE);
      return 2;
    }
  }
  if (bundlePath === undefined || policyPath === undefined) {
    process.stderr.write(USAGE);
    return 2;
  }
  try {
    const policyBytes = readLimited(policyPath, MAX_TRUST_POLICY_BYTES, "trust policy", "256 KiB");
    const history = historyPaths.map((path) => readLimited(path, MAX_TRUST_POLICY_BYTES, "trust policy history", "256 KiB"));
    const registerBytes = registerPath === undefined ? undefined : readLimited(registerPath, MAX_REGISTER_BYTES, "register", "1 MiB");
    const options = {
      now: now ?? nowInstant(),
      history,
      acceptCurrentTrustFailure: accept,
      requireTrustedTime,
      ...(registerBytes === undefined ? {} : { register: registerBytes }),
    };
    // An offline package (IE1-022) is verified under the same inputs as a bundle.
    const { report, policy } = isPackage(bundlePath)
      ? verifyPackageBytes(readPackage(bundlePath), policyBytes, options)
      : verifyBundleBytes(readLimited(bundlePath, MAX_BUNDLE_BYTES, "bundle", "1 MiB"), policyBytes, options);
    process.stdout.write(json ? canonicalText(reportToJson(report)) + "\n" : human(report, policy.version));
    return EXIT[report.verdict] as number;
  } catch (error) {
    if (error instanceof VerifierInputError) {
      // The registered code of the refusal comes first when there is one (TP1-007).
      process.stderr.write(`error: ${error.code === undefined ? "" : `${error.code}: `}${error.message}\n`);
      return 2;
    }
    throw error;
  }
}

process.exitCode = main(process.argv.slice(2));
