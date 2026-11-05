# ECL TypeScript library

This package reads, checks and verifies ECL-1 objects in TypeScript and
JavaScript. It runs the same in Node.js 22 and in a browser and makes no network
request. It holds the offline verifier of ECL-1 Version 1.0: the command
`ecl-verify-ts` and the library that the browser verifier
([web/verifier](../../web/verifier/README.md)) runs. On every vector of the
conformance tests that its capabilities cover, it reports the expected result:
the expected pass or fail, the expected primary and secondary findings, and the
expected verdict for each evidence bundle and offline package.

The package provides verification. ZIP and content fixture builders live under
`test/` and are excluded from the runtime build.

## What it covers

- Strict JSON parsing within the declared limits of IE1-028, and RFC 8785 canonical JSON
  restricted to integers, with SHA-256 digests.
- Types for DCMP-2, EBMP-2, the integrity envelope, the evidence bundle and the
  trust policy, generated from the repository's schemas, and runtime validation
  against those schemas (JSON Schema Draft 2020-12).
- The semantic rules of DCMP-2, EBMP-2, the registered control extensions
  (the one-way rule for a recorded decision basis, DCMP2-053, among them), the
  extension rules of EXTENSION-REGISTRY-1 (one version of an extension per
  object, XR1-010, among them), the adapter binding and the safe-state profile.
- The records of the five binding profiles (AARM-BINDING-1, ACS-BINDING-1,
  MCP-GATEWAY-1, OTEL-EVIDENCE-EXPORT-1 and OAUTH-AUTHORITY-1): each record's
  schema, then the profile's 28 registered rules, with RFC 8785 for the content
  they bind and compact JWS for OAuth access tokens and DPoP proofs (ES256 and
  EdDSA, RFC 7638 thumbprints). An AARM or ACS record's inputs are compared with
  the decision basis of its response, and with that of a modification's
  response, which records them with their declarations (AB1-013, AC1-012), and
  an OpenTelemetry record's digests are checked as HMAC-SHA-256 under the
  export keys the caller holds, read from an `ecl_otel_export_keys_v1` file
  (OE1-004, OE1-010).
- The claim and assessment documents, checked against their schemas, and a work
  intent also against the extension rules (XR1-006, XR1-009, XR1-010, XR1-017).
- ECL-IE-1 envelopes: the DSSE v1 pre-authentication encoding, Ed25519 and
  ECDSA P-256 signatures with the profile's edge rules, and the integrity policy
  bound inside the payload.
- Trust policies (TRUST-POLICY-1), whose keys each hold one role (TP1-009),
  with envelope verification that counts a decision request or response only
  under a key of its role (TP1-010), and offline verification of signed evidence
  bundles, with the verdicts `verified`, `invalid`, `incomplete` and
  `current-trust-failed` and plain-language explanations of each finding. The
  bundle verifier checks the recorded discharge of the obligations a decision
  leaves to enforcement before the release and, for each proof the bundle
  carries, its signatures, issuer, type, binding and freshness (EBMP2-070),
  the release with its declared guard against the window (EBMP2-050) and the
  release a terminal event records (EBMP2-072), and every report carries
  `scope`, the checks that held and what the verdict does not establish
  (EBMP2-076), with the reason of each item the table names one for and the
  member `completionAfterWindow`, such as that the enforcement point checked
  and released as its events record or that the effects happened: a verified
  bundle's records are signed, bound and complete, and their statements remain
  their producers' statements.
- Offline packages (OFFLINE-VERIFICATION-1): a strict reader and writer of the
  `ecl.zip.store.v1` archive, over bytes and without decompression, and the
  checks of IE1-022 in order, which give a package the verdict of the evidence
  bundle it carries or the error of the first check it fails. Entry names are
  the POSIX portable filename characters, compared after ASCII case folding, so
  no Unicode table is involved.

ML-DSA-65 signatures are recognized and refused as unsupported.

## Using it

```ts
import { readFileSync } from "node:fs";
import { verifyBundleBytes } from "ecl-ts";

const { report } = verifyBundleBytes(readFileSync("bundle.json"), readFileSync("trust-policy.json"), {
  now: "2026-10-01T00:00:00Z",
});
console.log(report.verdict);
```

`now` is the evaluation time: the instant at which the verifier evaluates the
current status of every trust dependency, which every report states
(`evaluationTime`, `evaluation_time` in the JSON report). It is not an as-of cutoff:
Version 1.0 does not report what a bundle established at an earlier instant,
and evidence whose own or attested time is later than `now` is invalid with
`ecl.error.clock-regressed.v1` (EBMP2-057). An `incomplete` report lists the
predecessors it could not resolve (`unresolvedPredecessorIds`,
`unresolved_predecessor_ids`). Each established item of `scope` names, in `scope.checks`, the
checks of `registries/scope-checks.json` that ran and held for it and the
objects they covered (EBMP2-076). Pass earlier
versions of the trust policy as `history` when the evidence names them. Set
`acceptCurrentTrustFailure` only after deciding to rely on evidence signed by a
key that the current trust policy no longer accepts; the report then records the
acceptance.

The command `ecl-verify-ts` (`dist/cli/ecl-verify.js`) takes a bundle or an
offline package, `--trust-policy FILE`, and optionally earlier trust-policy
versions (`--trust-policy-history FILE`, repeated), the evaluation time
(`--now`), `--accept-current-trust-failure`, `--require-trusted-time`, a
Consequential Action Register (`--register FILE`) and `--json`. Its exit
status is 0 for `verified`, 1 for `invalid`, 3 for `incomplete`, 4 for
`current-trust-failed` and 2 for a usage error (EBMP2-060).
It verifies a file that begins with the bytes `PK` as an offline package of at
most 1 GiB, the declared archive limit, and any other file as a JSON evidence
bundle of at most 1 MiB. A usage error is one line on standard error,
`error: CODE: MESSAGE` when the refusal has a registered code and
`error: MESSAGE` otherwise, as the reference's `ecl-verify` writes it. A file
over its byte limit (a trust
policy over 256 KiB, a bundle or register over 1 MiB, a package over 1 GiB) is
refused before it is parsed with `ecl.error.resource-limit-exceeded.v1`
(TP1-007). `verifyBundleBytes` and `verifyPackageBytes` give that code as the
`code` of their `VerifierInputError` for a trust policy, history version,
register or bundle over its limit; `verifyPackageBytes` reports an archive over
one of its declared limits (IE1-028) as an `invalid` report whose finding is
`ecl.error.resource-limit-exceeded.v1`, not as a `VerifierInputError`.

### What the evidence verifier applies

`verifyBundle`, `verifyBundleBytes`, `ecl-verify-ts` and the browser verifier
apply the reference verification profile,
`ecl.verification-profile.reference.v1` (EBMP2-057 to EBMP2-062):

- the schema of the bundle and of each signed payload, and each payload's
  semantic rules, among them the one-way rule for a recorded decision basis
  (`ecl.rule.decision-basis-one-way.v1`, DCMP2-053), which also refuses an
  input recorded as `verifiable` whose source is the actor of the response's
  request;
- each envelope's signatures, under the trust-policy version that the object
  names at its own time and under the current trust policy at the evaluation
  time; an object or attested time later than the evaluation time is
  `ecl.error.clock-regressed.v1` (EBMP2-057);
- each trusted-time countersignature: its attestation binds the payload and the
  signatures it covers (`covered.signatures`), and each covered signature is
  evaluated at its attested time, every other one at the object's own time
  (IE1-032 to IE1-035);
- every trust dependency, the keys of the time authorities included: a key
  that the current trust policy revokes, under its identifier or under another identifier
  for the same public key, from a time at or before the dependency's own time
  is not historically valid, and each dependency's current status is reported
  in `trust_dependencies` and decides `current-trust-failed` (TP1-006,
  EBMP2-060); a signature that does not verify, counted or not, makes its
  dependency historically invalid with `ecl.error.integrity-invalid.v1` and
  keeps `envelope-signatures` (for an envelope or observation) or
  `trusted-time` (for an attestation) out of `established`, without changing
  the verdict;
- the pairing and binding of requests, responses and events, a continuation
  after a challenge (EBMP2-078), one causal graph over every object of the
  bundle, the DCMP-2 messages and the observations included (EBMP2-059,
  EBMP2-077), and the evidence level of each effect, which is `corroborated`
  only when the report establishes `envelope-signatures` and
  `causal-completeness` and an observation names the terminal event by
  identifier and digest in its workflow, root trace and attempt (EBMP2-061);
  an object that a causal predecessor or `continues` names and that the bundle
  does not hold exempts no check of the objects it does hold (a release without
  a recorded consumption is invalid whatever else is absent, unless the
  attempt's own objects name the absent object), and keeps out of
  `established` every item whose objects name it;
- that every decision response carries its decision basis
  (`ecl.rule.decision-basis-required.v1`);
- when the caller supplies a Consequential Action Register (`--register FILE`,
  or the `register` option, which `loadRegister` reads), that each decision
  basis names that register version and lists exactly the inputs that it
  declares for the request's action class, with their declared derivations,
  and that no input it records as available was late by its recorded times
  (`ecl.rule.decision-basis-matches-register.v1`). A register that fails its
  schema or `ecl.rule.register-declarations-consistent.v1`, for example one
  that declares an action class twice, is refused as a usage error.

A verified bundle does not show that its statements are true. Without a
register the verifier cannot tell whether a decision consulted an input that
the register does not declare, and with one it still cannot see an input that a
decision consulted and did not record. It compares a decision with its
verifiable-only outcome only when the record states that outcome, since
computing it needs the policy (ECL1N-0179).

### Verifying an offline package

An offline package is verified with `verifyOfflinePackage`, or from files with
`verifyPackageBytes`:

```ts
import { readFileSync } from "node:fs";
import { verifyPackageBytes } from "ecl-ts";

const { report } = verifyPackageBytes(readFileSync("evidence.zip"), readFileSync("trust-policy.json"), {
  now: "2026-10-01T00:00:00Z",
});
console.log(report.verdict);
```

The trust policy, earlier versions and evaluation time are yours, never the
package's: the trust policy, keys and snapshots inside a package are evidence
(IE1-022). Every option of `verifyBundle` is passed to the package's bundle
unchanged, so the decision basis is required and a register applies exactly as
for a bundle on its own, and `limits` declares the verifier's resource limits
(IE1-028), the declared defaults when absent. A package over a limit is `invalid` with
`ecl.error.resource-limit-exceeded.v1`. `readStoredZip` reads the archive itself.

### Checking a binding record

A binding profile's record is checked with `evaluateBindingRecord`, which
applies the record's schema and then the profile's rules, as the `binding`
stage of the conformance tests does
([conformance/README.md](../../conformance/README.md)):

```ts
import { readFileSync } from "node:fs";
import { evaluateBindingRecord, parseStrictJson } from "ecl-ts";

const record = parseStrictJson(readFileSync("exchange.json"));
for (const finding of evaluateBindingRecord(
  "https://externalcontrollayer.ai/ns/schema/binding/mcp-gateway-exchange/1",
  record,
)) {
  console.log(finding.ruleId, finding.path, finding.message);
}
```

On the few records that their schema accepts but that the profile's rules
cannot read, the library throws `PythonTypeError` or `PythonValueError` rather
than reporting a finding. Pass the export keys that `otel.loadExportKeys` reads as the last
argument of `evaluateBindingRecord` to check keyed OpenTelemetry digests.
`evaluateDocument` is the `document` stage for a claim or assessment
document.

## Building and testing

```
npm ci
npm run build
npm test
```

`npm ci` installs exactly the versions in `package-lock.json`, and `.npmrc`
turns off dependency install scripts. The runtime dependencies are
`@noble/curves` and `@noble/hashes` (MIT); the others are build and test tools.

After the build:

- `npm test` runs the unit tests, which read the vectors of the conformance
  tests from this repository;
- `npm run test:browser` runs the browser verifier's tests in Chromium, through
  playwright-core (set `PLAYWRIGHT_BROWSERS_PATH` to a directory that holds the
  Chromium build it expects);
- `node scripts/check-corpus.mjs` runs `ecl-verify-ts` on every vector of the
  `evidence-bundle` and `package` stages and on the sample evidence in
  `conformance/fixtures/evidence/`, and compares each verdict and exit status
  with the expected one;
- `node scripts/build-verifier.mjs --check` checks that the browser verifier's
  script, `web/verifier/verifier.js`, equals a fresh build from `web/app.ts`
  and `src/`; `npm run verifier:build` writes it.

The files in `src/generated/` are generated from the repository's schemas and
registries; do not edit them by hand. The binding-record and document schemas
are in `record-schemas.ts`, apart from the wire schemas and the offline package
manifest, so that the browser verifier carries only what it needs.

## Rights

Copyright 2026 G-14, Inc. Licensed under the Apache License, Version 2.0
(`LICENSE`); the package declares `Apache-2.0`. G-14's patent pledge for
implementations of ECL-1 is in the repository's `PATENTS.md`; G-14 has patents
pending. Its dependencies `@noble/curves` and `@noble/hashes` keep the MIT
License.

The canonical JSON report includes `primary`: the registered identifier of the
primary finding, or `null` for `verified`. An `incomplete` report names
`ecl.error.causal-closure-incomplete.v1`; `current-trust-failed` names the first
failing current status in the standard's order, with package expiry first for an
expired offline package. This agrees with the text report's `primary:` line.
