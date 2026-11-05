# Browser verifier

`index.html` verifies, in a web browser, a signed ECL-1 evidence bundle or an
offline package (OFFLINE-VERIFICATION-1) that carries one, against a trust policy
that you choose. Open it from disk (a `file://` address) or serve the folder;
`verifier.js` must stay next to it.

The page reads the files you choose in the browser and makes no network
request. Its content security policy allows only its own script and its own
inline style, forbids every connection, form submission and embedded content,
and requires Trusted Types, so the script cannot write HTML from strings.

The result shows the verdict with an explanation and, right after it, what the
verdict does not establish, each item with the reason the table of EBMP2-076
names for it, and what the verifier checked and found to hold (the report's
`scope`, EBMP2-076), with a note when the server's answer arrived after the
authorization's window (`completion_after_window`); then the status of each
envelope when it was
signed and at the evaluation time, each binding check, the evidence level of
each effect, and the report in the JSON shape of `ecl-verify-ts --json`.
The page runs the TypeScript library in
[packages/ecl-ts](../../packages/ecl-ts/README.md), so it reaches the same
verdicts as the command `ecl-verify-ts`.

A file that begins with the bytes `PK` is read as an offline package, a ZIP file
of at most 16 MiB, which is the page's declared archive limit; every other file
is read as a JSON evidence bundle of at most 1 MiB. A larger file is refused
without being read, and the page names the registered code
`ecl.error.resource-limit-exceeded.v1` (TP1-007). The page checks a package's
archive and manifest in the order of IE1-022 and then verifies the evidence
bundle it carries under the trust policy you choose. The trust policy, keys and
snapshots inside a package are evidence, never trust, so a package signed only
with keys of its own trust policy is invalid under yours.

## What it applies

The page applies the reference verification profile,
`ecl.verification-profile.reference.v1`:

- the schema of the bundle and of each signed payload, and each payload's
  semantic rules, among them the one-way rule for a recorded decision basis
  (`ecl.rule.decision-basis-one-way.v1`, DCMP2-053), which also refuses an
  input recorded as `verifiable` whose source is the actor of the response's
  request;
- each envelope's signatures, under the trust-policy version that the object
  names at its own time and under your trust policy at the evaluation
  time; an object or attested time later than the evaluation time is
  `ecl.error.clock-regressed.v1` (EBMP2-057);
- each trusted-time countersignature: its attestation binds the payload and the
  signatures it covers (`covered.signatures`), and each covered signature is
  evaluated at its attested time, every other one at the object's own time
  (IE1-032 to IE1-035);
- every trust dependency, the keys of the time authorities included: a key
  that your trust policy revokes, under its identifier or under another identifier
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
- that each release whose decision left obligations to enforcement before the
  release records a discharge of each one, taken from the signed response, and
  that each proof the bundle carries is a valid ECL object under the trust
  policy, signed by the issuer the obligation names, of a type the obligation
  admits, bound to the exchange and fresh at the release
  (`ecl.rule.prerelease-obligations-discharged.v1`, EBMP2-070); that each
  release, with its declared release guard added, lies inside the
  authorization's window and that no terminal event records a release after it
  (EBMP2-050, EBMP2-072), a server's answer after the window being shown as
  information, not a finding; the use counts of consumed authority, the
  consumption of single-use authority and the MCP binding of the events
  (EBMP2-073 to EBMP2-075);
- that every decision response carries its decision basis
  (`ecl.rule.decision-basis-required.v1`);
- when you choose a Consequential Action Register file, that each decision
  basis names that register version and lists exactly the inputs that it
  declares for the request's action class, with their declared derivations,
  and that no input it records as available was late by its recorded times
  (`ecl.rule.decision-basis-matches-register.v1`). A register that fails its
  schema or `ecl.rule.register-declarations-consistent.v1`, for example one
  that declares an action class twice, is refused. Without a register, the
  summary says that the declared classes were not checked against one.

The records of a bundle make different claims: the authorization in a decision
response says what an action may do and under which conditions, the
enforcement point's events say what it checked and released, and a terminal
event or an observer's record says what happened. A verified bundle shows that
these records are signed, bound and complete, not that their statements are
true, and the page lists, beside every verdict, the statements that no
verification establishes: that the enforcement point checked and released as
its events record, that the recorded times are the true times, that the effects
happened, that the deployment has been assessed, and, when they apply, that the
obligations were met. A recorded discharge is the enforcement point's
statement: of a proof that the bundle carries, the page checks only the
signatures and the digest, not what the proof shows. Without a register the page cannot tell whether a decision consulted an input that the
register does not declare, and with one it still cannot see an input that a
decision consulted and did not record. It compares a decision with its
verifiable-only outcome only when the record states that outcome, since
computing it needs the policy.

## Files

- `index.html`: the page, its styles and its content security policy.
- `verifier.js`: a generated script. `packages/ecl-ts/scripts/build-verifier.mjs`
  bundles `packages/ecl-ts/web/app.ts` and the library with esbuild into one
  classic script, because browsers refuse module scripts on pages opened from
  disk. The script carries the MIT notices of the two `@noble` packages it
  includes. Do not edit it; run `npm run verifier:build` in `packages/ecl-ts`,
  which also updates the style hash in the page's policy.

## Tests

`npm run test:browser`, run in `packages/ecl-ts` after its build, opens the page
from disk in Chromium (through playwright-core; set `PLAYWRIGHT_BROWSERS_PATH`
to a directory that holds the Chromium build it expects). The tests verify every evidence-bundle and
offline-package vector through the page and check the explanations, keyboard use
and visible focus, names for assistive technology, input errors, a 320-pixel-wide
window and text contrast in light and dark color schemes. Each test fails if the browser
requests anything other than the page and its script. The page has not been
tested in other browsers.

## Rights

Copyright 2026 G-14, Inc. The page and its script are licensed under the
Apache License, Version 2.0 ([LICENSE](../../LICENSE),
[LICENSING](../../LICENSING.md)); G-14's patent pledge is in
[PATENTS](../../PATENTS.md), and G-14 has patents pending. The `@noble/curves`
and `@noble/hashes` code inside the script keeps the MIT License, whose full
notice the script carries.
