# ECL-1 Version 1.0 release notes

ECL-1 Version 1.0 (release `ECL-1-1.0`) is the first published version of
ECL-1, the External Control Layer Standard. It is maintained by G-14, Inc.,
and its development continues in the open in the ECL-1 Working Group
([README](README.md#taking-part)).

## What Version 1.0 holds

- The core standard, ECL-1 Version 1.0, with its seven companion protocols and
  ten normative profiles at the versions that
  [release/VERSION_SET.json](release/VERSION_SET.json) binds: DCMP-2 and
  EBMP-2 at 2.0, and every other companion at 1.0. The
  [README](README.md#the-document-set) lists each document.
- The JSON Schemas and registries that implementations and verifiers agree on.
- The conformance tests with their expected results, the assessment procedures
  for every requirement, and sample evidence.
- Offline verifiers in TypeScript, Python and Go, and a browser verifier, with
  their tests, a shared corpus runner and an implementer report checker. The
  [quickstart](docs/quickstart.md) uses only this package.
- The guides for buyers, implementers, assessors and the builders of agents,
  tools and gateways.

## What changed from the last release candidate

Version 1.0 follows Release Candidate 6 (RC-6). The requirement changes are
listed in [CHANGELOG.md](CHANGELOG.md), from the requirement ledger. The
requirements whose text changed are DCMP2-053, EBMP2-055, EBMP2-057, EBMP2-059,
EBMP2-060, EBMP2-061, EBMP2-062, EBMP2-068, EBMP2-074, EBMP2-076, ECL1N-0159, IE1-033, IE1-034,
IE1-035, TP1-006 and TP1-007; DCMP2-056, DCMP2-057, EBMP2-077 and EBMP2-078 are
new; none was retired. The changes to the verification rules and the
continuation contract below are normative changes from RC-6.

- Every object of a signed evidence bundle is a node of its causal graph, a
  normative change from RC-6 (EBMP2-059, EBMP2-061, EBMP2-076 and the new
  EBMP2-077). RC-6 applied the causal rules to the events, so an observation's
  predecessor references could go unchecked while the report established
  `causal-completeness` and an effect was `corroborated`. Now the DCMP-2
  messages, the EBMP-2 events and the observations are all checked: each
  predecessor is an object of the bundle with the digest that names it,
  identifiers are unique across `envelopes` and `observations`, and a
  predecessor shares its successor's root trace and is in its workflow with an
  attempt no greater, or in its parent workflow (new rule
  `ecl.rule.bundle-causal-context-consistent.v1`). An effect is `corroborated`
  only when the report establishes `envelope-signatures` and
  `causal-completeness` and an observation names the terminal event by
  identifier and digest and has its workflow, trace and attempt, so an `invalid`
  report never has a `corroborated` effect. An object that a causal predecessor
  reference or `continues` names and the bundle does not hold exempts no other
  check, and every report carries `unresolved_predecessor_ids`, non-empty only
  when the verdict is `incomplete`. EBMP2-055 and EBMP2-074, which applied only
  to a causally complete bundle, now apply to every attempt whatever the closure
  of the rest of the bundle, except an attempt whose own objects name a
  predecessor that the bundle does not hold, so a release without a consumption
  is `invalid` even when an unrelated predecessor is absent. A producer of
  observations lists the terminal event that an observation corroborates among
  its causal predecessors, and every producer gives a record a sequence greater
  than that of each predecessor it names in the same workflow; a verifier checks
  the predecessors of every object.
- A time attestation binds the signatures it attests, a normative change from
  RC-6 (IE1-033 to IE1-035). The attestation's `covered` member carries the
  required list `signatures`, each `{key_id, suite, signature_digest}` with the
  SHA-256 digest of the signature bytes, in the envelope's order. An attested
  time applies only to a signature the attestation covers; a signature that no
  attestation covers is evaluated at the object's own time, and under the
  trusted-time profile is refused with `ecl.error.trusted-time-required.v1`;
  an attestation that names a signature the envelope does not carry, such as a
  signature replaced after a key's compromise, is invalid with
  `ecl.error.trusted-time-invalid.v1`. Version 1.0 defines no archive renewal.
  A time authority computes and lists the signature digests; a producer obtains
  the attestation after the signatures it should cover; a verifier evaluates
  each signature at the time that IE1-034 gives it.
- Later compromise knowledge reaches every trust dependency, a normative change
  from RC-6 (TP1-006, IE1-034, EBMP2-060, ECL1N-0159). A signing key of an
  object or of a time attestation is historically valid only when it is valid
  under the policy version its object names and the caller's current policy
  holds no revocation, effective at or before the dependency's time, of a key
  with its key identifier or its public key; every key that signed anything in
  the bundle is a dependency, counted or not, and a signature that does not
  verify makes its dependency historically invalid, which keeps the items that
  rest on it out of the report's established scope without changing the
  verdict; only a revocation carries later
  knowledge of a compromise, so a later retirement, expiry or removal does not
  make it historically invalid. Current
  status is evaluated and reported for every dependency, a time authority's key
  included, with the policy versions and the revocation used, and the
  acceptance of a current trust failure never changes an `invalid` or
  `incomplete` verdict. A verifier applies the current policy's revocations to
  every dependency; a claimant revokes a compromised key from the earliest
  suspected time, as ECL1N-0159 already required. Each dependency's `at` is
  the time at which its signer was evaluated, or `null` when it was not
  evaluated, including when the envelope's status was decided first.
- The evaluation time is not an as-of cutoff, a normative change from RC-6
  (EBMP2-057, EBMP2-068, EBMP2-076). An object of the bundle, in `envelopes` or
  `observations`, whose own time, or an attested time, is later than the
  evaluation time is not historically valid, with
  `ecl.error.clock-regressed.v1`, the first finding of stage 4; Version 1.0
  defines no as-of assessment, and every report states the evaluation time it
  used in `evaluation_time`. A caller passes the instant at which it verifies.
- Continuation after a challenge has one contract, a normative change from
  RC-6 (the new DCMP2-056, DCMP2-057 and EBMP2-078). A continuation is a new
  request of a later attempt for the same action, actor, subject and requested
  authority, which names in the new optional member `continues` the request it
  continues, the challenge response and the approval event, and lists the last
  two among its causal predecessors; the continued request keeps its one
  response; the Decision Layer evaluates the continuation afresh and does not
  admit it on a late, expired, revoked or already used approval; one bundle
  holds the whole history, and a verifier checks each continuation, among other
  things that it lists the challenge and the approval among its causal
  predecessors by identifier and digest and, when its response is an `admit`,
  that the approval's signing keys hold `ecl.purpose.approval.v1`, that none of
  them is bound to the request's actor, and that the approval's `expires_at`,
  when present, is later than that response's `evaluated_at`; a continuation
  answered with a `deny` or a new `challenge` is correct evidence.
  [protocols/examples/dcmp-2-continuation.json](protocols/examples/dcmp-2-continuation.json)
  is the wire example. A producer that continued under the original request
  identifier issues a new request with `continues`.
- A verifier's report names the checks behind its scope, a normative change
  from RC-6 (EBMP2-076). The new registry
  [registries/scope-checks.json](registries/scope-checks.json) lists, for each
  scope item and for the `corroborated` level, its object set, the checks that
  must hold over it, the trust knowledge they use and the waivers that it
  permits; a waiver changes the verdict only. A verifier establishes an item
  only when every listed check ran over the whole object set and held, and never
  when the set names an object that the bundle does not hold, and reports, for
  each established item, the checks and the objects. The
  `decision-basis-recorded` item no longer depends on a caller option, and
  `decision-basis-register` applies only when the caller supplies a register.

- Two requirements are reworded so that they name no implementation, with
  their scope unchanged from RC-6: EBMP2-062 gives its limits as an example, and
  TP1-007 keeps its obligations on every verifier interface, to enforce its
  declared byte limits before parsing and to refuse an input over a declared
  limit, and states the figures of 256 KiB and 1 MiB as the declared limits of
  the verifier published with ECL-1 rather than as an obligation on a named
  tool.
- The designations carry no candidate suffix: "ECL-1 Version 1.0", DCMP-2 2.0,
  EBMP-2 2.0 and 1.0 for the other companions. A claim names these versions, as
  Section 7.7 of the standard requires.
- The informative annex of the core standard that described the editor's own
  test deployment is removed. No requirement referred to it.
- The texts are licensed openly, with a royalty-free patent pledge
  ([README](README.md#rights)), and the ECL-1 Working Group is open to anyone.
- A signed payload whose trust-policy digest is not an object is refused with
  `ecl.error.signature-policy-invalid.v1` by the TypeScript and Go verifiers,
  as the Python reference and INTEGRITY-ENVELOPE-1 IE1-040 (step 4) already
  required; the envelope suite gains the vector
  `envelope-invalid-policy-digest-string-for-object` for the case.
- The accommodation for evidence made before the decision basis was required
  is withdrawn, a normative change from RC-6: no such evidence passes the 2.0
  schema, so a 2.0 decision response without `ecl.ext.decision-basis.v1` is
  rejected with `ecl.rule.decision-basis-required.v1` by every verifier.
  DCMP2-053 loses the clause that excused a verifier whose caller declared
  older evidence, and the ledger records it as changed in 1.0. Callers remove
  the option: `--no-require-decision-basis` and `--require-decision-basis` are
  gone from `ecl-verify-ts` (a usage error), the library option
  `requireDecisionBasis` and the report member `decision_basis_required` are
  gone, the browser verifier no longer offers "Require a decision basis", and
  the conformance manifests no longer carry `require_decision_basis`; the
  vector `bundle-valid-predates-decision-basis` is withdrawn
  (`bundle-invalid-missing-decision-basis` covers the case). The vector total
  is 953 in Version 1.0, including the three OAuth obligation-boundary cases.
- The public Python package `ecl-verify` and the Go module `go/crosscheck` verify
  evidence without a service or account. They are implementations maintained by
  the same operator as the TypeScript verifier; agreement among them is a
  cross-check, not an independent assessment. Producer and service APIs are
  outside the verifier runtimes. The separately labeled bounded teaching example
  uses public wire examples and published test keys; it supplies no production
  producer API, administrative separation or deployment conformance claim.
- The Python verifier and package workspaces use `cryptography` 50.0.2, which
  contains the upstream fix for CVE-2026-69247. The affected upstream PKCS#7
  decryption API is not used by the verifier. The Go verifier requires Go
  1.26.10 or later and is qualified with Go 1.27.3, replacing the unsupported
  Go 1.24.6 toolchain. These dependency and toolchain changes alter no ECL-1
  requirement, wire value, finding or verdict.
- The implementer report checker reads the top-level report and every raw
  result with the bounded strict-JSON parser. It refuses repeated member names
  and inputs over 64 MiB before schema validation and before reading an
  over-limit file in full. The accepted report format is unchanged.
- The reference MCP gateway orders concurrent contenders for one authorization
  until the winning request is written or refused. This prevents replay-refusal
  evidence work from using the winner's 250 ms release guard, while opening the
  lane at the write so an upstream reply does not hold later contenders. The
  guard, protocol obligations and wire values are unchanged.
- The emergency-control conformance checks distinguish a signed fail-closed
  `dependency-unavailable` result from the halt behavior they are measuring.
  They validate and count a bounded number of those results, but still require
  ten committed effects and three fresh post-ack `emergency-halt` denials;
  repeated dependency loss leaves the check incomplete. A lost action reply or
  HTTP 503 unknown outcome is reconciled under its original idempotency key
  while the unaffected streams continue. A verified expiry before release also
  leaves the exercise incomplete. For transport diagnosis, the pilot HTTP
  client logs only the failed exchange phase, exception class and elapsed
  milliseconds, and its server logs only the failed connection phase and
  exception class.
- The pilot HTTPS client and server wait for an active deadline-abort callback
  to finish before releasing its socket. This prevents a cancelled watchdog
  from acting on a descriptor that another connection has reused. Configured
  deadlines, byte limits and denial/evidence requirements are unchanged.
- The public schema set contains the formats used by public documents, data and
  code. Five unused or superseded formats remain in the platform package:
  `ecl-conformance-result-v1`, `ecl-conformance-vector-manifest-v2`,
  `ecl-requirement-coverage-v1`, `ecl-requirement-coverage-v2` and
  `ecl-requirement-evaluation-catalog-v1`. The result-v2 and legacy implementer
  report formats used by the public runner and report checker remain public.
- The implementer report profile (`conformance/EXTERNAL_IMPLEMENTATION_PROFILE.md`)
  and the formal models with their runner and results (`formal/`) are public.
  The scenario files and their schema are public; the scenario runner and its
  adapter instructions are in the maintainer's platform package.
- The three informative guides, CONFORMANCE-CLAIMS-1, DEPLOYMENT-PROFILES-1 and
  OFFLINE-VERIFICATION-1, are outside the version set by design: they state no
  requirement and carry no version of their own.
- The browser verifier's script, `web/verifier/verifier.js`, is rebuilt from
  the changed library (SHA-256
  `096945d19748d30d6e17b52e50a0ac1f375559d6dc740c09d59c0b28bcf8f5c1`, 660,357
  bytes), and the page names `ecl-verify-ts` as the command whose library it
  runs.

### Wire values that changed

An implementation or an exporter that followed RC-6 changes the values below.
Every other wire value is unchanged from RC-6: apart from the semantic rule and
the four fields that the registry changes below list, no error code, extension,
field, media type, algorithm suite, operational value, protocol value, semantic
rule, term or vocabulary entry was added, changed or retired.

- The time attestation
  ([schemas/ecl-time-attestation-v1.schema.json](schemas/ecl-time-attestation-v1.schema.json)):
  `covered` requires the new member `signatures` (above). The `schema_version`
  `ecl_time_attestation_v1` and the schema's `$id` are unchanged. An
  attestation without the member fails the schema, so a time authority that
  followed RC-6 adds it.
- DCMP-2 ([schemas/dcmp-2.schema.json](schemas/dcmp-2.schema.json)): a decision
  request may carry the new optional member `continues`, with `request_id`,
  `response_id` and `approval_id` (above). A request without it is unchanged.

- OTEL-EVIDENCE-EXPORT-1: the `profile` constant of an export record
  ([schemas/ecl-binding-otel-export-v1.schema.json](schemas/ecl-binding-otel-export-v1.schema.json))
  and the value of the `ecl.export.profile` attribute of every exported log
  record are `OTEL-EVIDENCE-EXPORT-1/1.0`; RC-6 had
  `OTEL-EVIDENCE-EXPORT-1/1.0-rc.1`. An exporter writes the new value in both
  places. A record that carries the RC-6 value fails the export record's
  schema, which fixes the constant.
- DCMP-2 and EBMP-2: the wire `schema_version` of every message and record is
  `2.0`; RC-6 had `2.0-rc.2`. A producer writes `2.0`. The schemas, the vectors
  and the sample evidence carry it, and the signed samples are signed again. A
  verifier that follows Version 1.0 refuses a message or record that carries
  `2.0-rc.2` at its schema stage with `ecl.error.schema-invalid.v1`, so
  evidence made under RC-6 does not verify under Version 1.0.
- The conformance artifacts: `candidate_version` is `1.0` in a vector manifest,
  a conformance result and a cross-implementation report; RC-6 had `1.0-rc.6`.
  The suite identifiers are `ecl-1-v1.0-<suite>` for the eighteen suites and
  `ecl-1-v1.0-shared` for the shared corpus; RC-6 had `ecl-1-v1.0-rc.6-<suite>`
  and `ecl-1-v1.0-rc.6-shared`. A report against the shared corpus names the
  new identifiers.
- The review disposition log
  ([schemas/ecl-review-disposition-log-v1.schema.json](schemas/ecl-review-disposition-log-v1.schema.json)):
  a comment's `channel` is `public` or `private-security`, and a disposition's
  `decided_by` is `editors`, `chair` or `maintainer`, as the governance of
  Version 1.0 names them; RC-6 also allowed the channel `invited` and named the
  deciders `editor`, `publishing-authority` and `appeals-panel`.
- The conformance vector manifest schema
  ([schemas/ecl-conformance-vector-manifest-v3.schema.json](schemas/ecl-conformance-vector-manifest-v3.schema.json)):
  the optional row field `require_decision_basis` of the `evidence-bundle` and
  `package` stages is removed with the accommodation it switched (above). No
  vector of Version 1.0 carries it, and a corpus runner reads no such field.

Two constants keep a candidate suffix, unchanged from RC-6: the
`schema_version` of a work-intent document, `ECL-WI-1`
([schemas/ecl-work-intent-v1.schema.json](schemas/ecl-work-intent-v1.schema.json)),
and the `package_version` of an offline verification package
([schemas/ecl-offline-verification-package-v1.schema.json](schemas/ecl-offline-verification-package-v1.schema.json))
are `1.0-rc.1`.

### Registry changes

- Each value registry (algorithm suites, error codes, extensions, fields, media
  types, operational values, protocol values, schema wire values, semantic
  rules, terms and vocabulary) carries the `status` `active`; RC-6 marked each
  `draft`.
- The registry of schema wire values
  ([registries/schema-wire-values.json](registries/schema-wire-values.json))
  records the `schema_version` value `2.0` of DCMP-2 and of EBMP-2 as two new
  entries and marks the two entries for `2.0-rc.2` as superseded in 1.0, each
  naming its successor; the registry catalog
  ([registries/registry-catalog.json](registries/registry-catalog.json))
  reflects the four entries.
- The semantic-rules registry adds `ecl.rule.bundle-causal-context-consistent.v1`
  (stage 8, precedence 225), and the fields registry adds the four fields of
  the DCMP-2 member `continues`; the registry catalog reflects them. The
  descriptions of `ecl.error.clock-regressed.v1`,
  `ecl.error.trusted-time-invalid.v1`, `ecl.error.trusted-time-required.v1`,
  `ecl.rule.decision-basis-required.v1` and `ecl.claim.trusted-time.v1` say what
  the changes above give them;
  their identifiers and attributes are unchanged. No other entry of a value
  registry was added, changed or retired.
- The new registry [registries/scope-checks.json](registries/scope-checks.json)
  and its schema
  [schemas/ecl-scope-checks-v1.schema.json](schemas/ecl-scope-checks-v1.schema.json)
  hold the claim-to-check map of EBMP2-076.
- The compiled requirement registry and the requirement metadata name no test
  of the maintainer's own implementation: their test references are the
  conformance references of this package.

## Signing, and how the release is identified

Version 1.0 is not signed. The maintainer, G-14, Inc., authorized its
publication and release on 16 October 2026 and did not authorize signing. Under
[governance/RELEASE_POLICY.md](governance/RELEASE_POLICY.md) a release is signed
only once the maintainer has approved a signing identity and production key
custody, with a documented key identity, purpose, validity, revocation, custody,
threshold and verification procedure, and never with a test or developer key;
no signing identity or key custody has been approved. As that policy requires
of a release published without a signature, Version 1.0 is identified by the
SHA-256 digests of its archive, `ecl-1-1.0.zip`, and of its release manifest,
`ecl-1-1.0-manifest.json`, which the maintainer publishes with the release.
The manifest names every file of the archive with its size and its SHA-256
digest, and the digest of the archive, so that a copy of the archive or of any
file in it can be checked against the manifest. Once the maintainer approves a
signing identity and production key custody, a later release can carry a
signature made under them, with the documented key identity, purpose,
validity, revocation, custody, threshold and verification procedure that the
policy requires.

## The release manifest

The release manifest, `ecl-1-1.0-manifest.json`, is published with the archive
and carries:

- `schema_version`: `ecl_standard_release_manifest_v1`, the builder's manifest
  schema.
- `release_id`: `ECL-1-1.0`.
- `designation`: `ECL-1 Version 1.0`.
- `version`: `1.0`.
- `versions`: the version set ([release/VERSION_SET.json](release/VERSION_SET.json)):
  the standard, every companion with its version and, for DCMP-2 and EBMP-2,
  the wire `schema_version` and its schema, and the reference package's name
  and version.
- `container_profile`: `ecl.zip.store.v1`, the archive profile that the archive
  is checked against.
- `archive`: the `path` (`ecl-1-1.0.zip`) and the `sha256` of the archive.
- `files`: every member of the archive with its `path`, `size_bytes` and
  `sha256`, in archive order.
- `authorization`: `publication_authorized: true`, `release_authorized: true`,
  `signing_authorized: false`, `authorized_on: 2026-10-16`.

The manifest carries nothing else: no source commit, no excluded directory or
count, no allowlist, no included count, no package name, no notice text, no
list of generated members, no status flag or label, and no copy of the
maintainer's authorization record.

## Official distribution channels

The Version 1.0 archive, manifest, checksums and verifier SBOMs attached to the
Version 1.0 GitHub release and linked from the
[ECL-1 release page](https://externalcontrollayer.ai/ecl-1) are the release
artifacts. A Python or TypeScript package-registry distribution is official
only when both of those pages link to it and identify its exact version. A
namesake package on a registry is not an ECL-1 release artifact by name alone;
compare its published digest and contents with the release record before
installing it.

## Implementation and contribution entry points

[Start here](docs/start-here.md) connects verification, a runnable bounded
workflow, integration, assessment and contribution. The public workflow emits
newly bound admitted/denied test-key bundles; its simulation also exercises
holds, action changes, replay, expiry and lost proof. Its limits are explicit.
The public check command and CI need no private platform. Python report output is UTF-8/LF across text-stream
settings, and Git preserves the committed fixture bytes on Windows checkout. Contributions that
need an unpublished generator use the documented editor-assisted regeneration
path. `CITATION.cff` supplies versioned citation metadata without an invented
DOI or publication date; it credits Robert F. Tilley Jr. as author and G-14,
Inc. as maintainer. Repository, people, contacts and final publication
remain subject to the maintainer's actual release procedure.

The public CI definition runs both the support-floor and qualification profiles
on Ubuntu, and runs the qualification profile on qualified Windows and macOS
runners. The same public check command covers the Python, TypeScript and Go
verifiers on each row.

## Review status

Release preparation included reviews using AI systems, with their results
triaged as editorial and engineering input. This release does not claim an
independent human security review, independent assessment, certification or
validation on that basis. G-14 maintains final Version 1.0 with this review
status disclosed. The applicable release checks and artifact-bound
authorization remain required by [governance/RELEASE_POLICY.md](governance/RELEASE_POLICY.md).
Comments are open at any time ([governance/PUBLIC_REVIEW.md](governance/PUBLIC_REVIEW.md));
report security problems privately ([SECURITY.md](SECURITY.md)).

## Assessor independence

No implementation of ECL-1 has been assessed against Version 1.0, independently
or otherwise, and the implementers registry
([community/implementers.yaml](community/implementers.yaml)) is empty at
publication. The maintainer appoints no assessors and attests no conformance;
an assessment is independent only as
[governance/ASSESSOR_INDEPENDENCE.md](governance/ASSESSOR_INDEPENDENCE.md)
defines it, and a listing in the registry is self-declared
([governance/CONFORMANCE_CLAIMS.md](governance/CONFORMANCE_CLAIMS.md)). The
maintainer did not authorize certification, independent assessment or a
production-readiness claim for Version 1.0, and no implementation, the
maintainer's own included, is certified, independently assessed or
production-proven under it.

## Limitations, and what Version 1.0 does not claim

Every version of ECL-1 states at least these limitations
([governance/CHARTER.md](governance/CHARTER.md), section 15):

- A verified evidence bundle shows what its producer signed and that it has not
  changed since, under the verifier's trust policy. It does not show that its
  statements are true, and an effect counts as corroborated only when a
  separately keyed party confirms it.
- "Every path" in a claim means every path within the claim's declared and
  assessed boundary, not every path that could exist.
- A listing in the implementers registry is self-declared, and an assessment
  is independent only as
  [governance/ASSESSOR_INDEPENDENCE.md](governance/ASSESSOR_INDEPENDENCE.md)
  defines it.

Section 1.2 of the standard states the scope and the limitations of Version
1.0, and the coverage denominator
([conformance/coverage-denominator.json](conformance/coverage-denominator.json))
lists the three units that the conformance tests exclude, each with its reason.
Publication makes ECL-1 Version 1.0 available to implement, assess and cite. It
does not certify, assess or endorse any implementation: a conformance claim is
self-declared by its implementer and listed as such, and an independent
assessment is listed only when an implementer provides one
([README](README.md#conformance)). "ECL-1 compliant" on its own is not a claim,
and ECL-1 has no certification mark
([governance/TRADEMARKS_AND_MARKS.md](governance/TRADEMARKS_AND_MARKS.md)).
G-14 confirms completion of its legal review of the licenses and patent
pledge. Later revisions remain subject to [PATENTS.md](PATENTS.md), section 11.

## Open issues and errata

[standard/ISSUES.md](standard/ISSUES.md) records the normative questions raised
against the text, with their resolutions. At publication it records seven:
all seven are resolved in the requirements and assessment procedures. The
20 October clarifications distinguish source authority from causal influence,
require meaningful human approval, narrow the OAuth profile to obligation-free
admits, define a legal-conflict procedure and preserve the single-power
independence prohibition at every class. Five retention requirements,
ECL1N-0195 through ECL1N-0199, are added. The published patent pledge records the legal-review status;
these technical dispositions supply no legal opinion or independent assessment. No erratum has been published for
Version 1.0: its errata index, in [governance/ERRATA.md](governance/ERRATA.md),
is empty at publication, and an accepted erratum is published there under the
procedure that document describes.

## Informative metadata

Some informative members name files of the maintainer's own tooling, which
this package does not hold: the `source.generator` member of the vector
manifests, the `generator` member of `registries/guarantee-trace.json`, the
header of the generated TypeScript sources, the justifications in
`conformance/coverage-denominator.json`, which name the maintainer's checks
(such as `make spec-check`) and tests, and the platform rule of
`licenses/license-map.json`. They record how a file was made or classified;
nothing in this package needs those files, and no check of the package reads
them. The version set names the public Python verifier's package metadata,
which this package holds.

## Reporting problems

The Python verifier checks bracketed IP-literal hosts directly across supported
Python patch levels. It does not rely on the URL parser to reject a bracketed
DNS name. The public check command reports failing Python vector identifiers
before returning failure. The public CI pins official actions that use Node 24;
checkout credentials are not persisted and workflow permissions are read-only.

Report an error in a text, a schema, a vector or the verifier as an issue in
this repository; accepted errata are published under
[governance/ERRATA.md](governance/ERRATA.md). Report a security problem
privately, as [SECURITY.md](SECURITY.md) describes.
