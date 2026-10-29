# ECL Integrity Envelope 1

Version: 1.0
Status: normative companion of ECL-1 Version 1.0, a published version
Schemas: `schemas/ecl-integrity-envelope-v1.schema.json`,
`schemas/ecl-time-attestation-v1.schema.json`

This protocol is ECL Integrity Envelope 1, published as the document
`INTEGRITY-ENVELOPE-1`. An envelope it defines carries the `envelope_version`
`ECL-IE-1` and is called an ECL-IE-1 envelope; its requirements carry the prefix
`IE1`.

Requirement identifiers are allocated in the order requirements were added and
never reused, so a later identifier appears among earlier ones where its subject
belongs: IE1-037 and IE1-038 follow IE1-004, and IE1-039 and IE1-040 are in
section 11.

## 1. Security goal

The envelope authenticates payload bytes and payload type under a trust policy
declared inside the signed payload. It is designed for offline verification and
algorithm transition without allowing untrusted envelope metadata to weaken
the signed policy.

**IE1-001** — A signed ECL JSON payload MUST first satisfy the restricted ECL
canonical JSON profile.

**IE1-002** — The JSON profile MUST conform to I-JSON (RFC 7493) and RFC 8785
behavior, including I-JSON's prohibition of surrogate code points and
noncharacters in strings and member names, subject to these additional
restrictions: floating-point values are prohibited, negative zero is
prohibited, integers are limited to the exact interoperable range, and
duplicate members are prohibited. The noncharacters are U+FDD0 to U+FDEF and
the last two code points of each of the 17 Unicode planes (U+FFFE, U+FFFF,
U+1FFFE, U+1FFFF and so on to U+10FFFF).

**IE1-003** — Decimal quantities, currency, durations, integers outside the
exact range, and other precision-sensitive values MUST use registered string
representations.

**IE1-004** — A consumer MUST apply the verified RFC 8785 erratum relevant to
negative zero (Errata ID 7920) and MUST reject rather than normalize ambiguous
input.

A strict parser can meet several defects in one input. The checks below have a
fixed order, so that every conforming parser refuses the same input with the
same finding whatever the position of each defect in the text.

**IE1-037** — A consumer MUST refuse a configured limit that IE1-028 does not
allow before it reads any input, as a configuration error and never as the
finding of a check below. It MUST check strict JSON input in this order, and
MUST refuse input that fails a check with that check's finding and no other,
unless the protocol that reads the input names another error for the refusal
(IE1-040 for the payload of an envelope, TRUST-POLICY-1 TP1-002 and TP1-007 for
a trust-policy document):

1. its size in bytes is within the consumer's declared limit (IE1-028), or the finding is `ecl.error.resource-limit-exceeded.v1`;
2. it is UTF-8 without a byte order mark and is exactly one JSON value under the grammar of RFC 8259, which excludes the constants `NaN`, `Infinity` and `-Infinity`, or the finding is `ecl.rule.json-strict-syntax.v1`; a consumer MAY end this check at a value nested deeper than both 10,000 levels and its declared nesting limit, and the finding is then `ecl.error.resource-limit-exceeded.v1`;
3. its nesting depth, counted from 0 for the top-level value, and its number of values are within the consumer's declared limits, or the finding is `ecl.error.resource-limit-exceeded.v1`;
4. every string and member name, after escapes are decoded, holds only Unicode scalar values that are not noncharacters (IE1-002), or the finding is `ecl.rule.json-strict-syntax.v1`;
5. no object repeats a member name, after escapes are decoded, or the finding is `ecl.rule.json-no-duplicate-members.v1`;
6. every number is an integer within the exact interoperable range, written without a fraction, an exponent or a negative zero, or the finding is `ecl.rule.json-restricted-numbers.v1`.

Checks 3 to 6 read every value of the input, including each value of a repeated
member name. The limits are each consumer's own (IE1-028), so whether an input
near a limit passes check 1 or check 3 can differ between consumers; the order
of the other checks does not.

Check 2 comes before check 3 wherever each defect lies in the text: an input
that goes beyond a nesting or value limit and departs from the grammar only
later in the text has the finding of check 2. A consumer keeps this order
without building an oversized value (IE1-029): it counts values and nesting as
it parses, drops what it has built at the first value beyond a limit, and reads
the rest of the text for check 2 alone, keeping only the kind of each open
container. Every consumer completes check 2 on an input nested no deeper than
10,000 levels, so the finding of such an input does not depend on the parser.

Input that passes these checks is then validated against its schema. The ECL
schemas are JSON Schema documents of draft 2020-12, and two of its keywords
need a convention that every validator shares.

**IE1-038** — A validator MUST evaluate the `pattern` keyword of an ECL schema
as an ECMA-262 regular expression that may match anywhere in the string unless
the pattern anchors it, so that `$` matches only at the end of the string, never
before a final line terminator, and `.` matches no line terminator. It MUST
treat the `format` keyword as an assertion for the two formats that the ECL
schemas use, and a string satisfies them as follows:

1. `date-time`: the string matches the pattern of `rfc3339Utc` in the common schema (`schemas/ecl-common-v1.schema.json`) and names a date from 0001-01-01 to 9999-12-31 that exists in the Gregorian calendar;
2. `uri`: every character is an ASCII letter or digit or one of ``-._~:/?#[]@!$&'()*+,;=%``; every `%` is followed by two hexadecimal digits; the string begins with a scheme (a letter followed by letters, digits, `+`, `-` and `.`) and `:`; the characters after that `:` up to the first `?` or `#` are neither empty nor exactly `//`; and when those characters begin with `//`, the authority that follows, up to the next `/`, holds `[` or `]` only around an IP literal: after its last `@` the authority begins with `[` and holds a `]`, the characters between that `[` and the first `]` are an IPv6 address in the text form of RFC 4291 section 2.2 (with no leading zero in an octet of an embedded IPv4 address), optionally followed by `%` and one or more characters other than `%`, or are a lowercase `v`, one or more hexadecimal digits, `.` and one or more characters, and any characters after that `]` begin with `:`.

The ECL schemas give every member that carries a format the type `string`, so
a value of another type fails the schema whatever a validator does with its
format.

## 2. Payload digest and logical identity

**IE1-005** — The envelope MUST carry the payload bytes as canonical base64,
payload media type, and payload digest.

**IE1-006** — The verifier MUST recompute the payload digest before signature
policy evaluation.

**IE1-007** — SHA-256 is the ECL v1 universal digest floor. Profiles MAY require
an additional registered digest but MUST NOT remove SHA-256 without a
versioned core transition.

**IE1-008** — A logical protocol identifier and canonical content digest
together identify an immutable object version. Systems MUST report conflicting
digests rather than selecting one silently.

## 3. Signing input

The signing input is the DSSE v1 pre-authentication encoding:

`"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload`

Lengths are the decimal octet lengths of the immediately following byte
strings.

**IE1-009** — Signers and verifiers MUST compute this domain-separated input
over the exact payload type and decoded payload bytes.

**IE1-010** — A signature valid for one payload type MUST NOT validate for
another payload type.

**IE1-011** — A verifier MUST NOT re-serialize a parsed payload before
signature verification. The verifier MUST verify the transported canonical
bytes and then separately prove that those bytes are canonical.

## 4. Payload-bound policy

The signed payload carries:

- the `required` flag, which states whether integrity applies;
- accepted suite identifiers;
- eligible key identifiers, when bounded;
- required key identifiers, when any signer is mandatory;
- signature threshold;
- trust-policy identifier, version, digest, and epoch;
- verification-time policy;
- revocation policy.

**IE1-012** — Envelope fields MUST NOT weaken the payload-bound policy.

**IE1-013** — The threshold MUST be an integer, MUST be at least one when
integrity is required, MUST be zero when integrity is declared optional, and
MUST NOT be lower than the number of mandatory signers; when the policy lists
eligible keys, every mandatory signer MUST be one of them. A consumer MUST
reject a payload-bound policy that fails any of these conditions with
`ecl.rule.integrity-threshold-consistent.v1`.

These are the only conditions of that rule. An empty list of eligible keys
leaves the eligible keys unbounded, so mandatory signers need no eligible list.
A threshold higher than the number of eligible keys, or a key whose suite the
policy does not accept, is not a consistency failure: no envelope can then meet
the policy, and verification refuses each one under IE1-040.

**IE1-014** — Each valid signer MUST count at most once toward threshold,
independent of duplicate signature entries.

**IE1-015** — A key MUST be acceptable under the trust policy, eligible-key
set, suite binding, validity interval, usage constraint, and revocation policy
before its signature counts.

## 5. Initial suite registry

The initial registry includes:

- `ecl.sig.ed25519.v1`
- `ecl.sig.ecdsa-p256-sha256.v1`
- `ecl.sig.ml-dsa-65.v1`

**IE1-016** — Ed25519 encoding and verification MUST follow RFC 8032.

**IE1-017** — ECDSA P-256 signatures MUST use minimally encoded ASN.1 DER and a
low-S value. Non-minimal or high-S signatures MUST be rejected.

**IE1-018** — ML-DSA-65 use MUST follow FIPS 204, read with the potential
updates (errata) that NIST lists for it, and MUST be explicitly enabled by
profile and trust policy. The
`ecl.sig.ml-dsa-65.v1` suite signs the exact DSSE v1 pre-authentication input
as the FIPS 204 external message with an empty ML-DSA context. Implementations
MUST reject any other public-key or signature length, MUST bind provider and
backend identity to conformance evidence, and MUST pass a source-locked NIST
ACVP ML-DSA-65 verification case plus a mutation rejection before enabling
the suite.

**IE1-019** — A post-quantum signature MUST NOT silently replace a required
classical signature during a transition. Hybrid or threshold policy MUST state
whether both, either, or a specified quorum is required.

**IE1-020** — Recognition of an algorithm name is not trust. Unregistered,
deprecated, prohibited, or policy-ineligible suites MUST NOT count.

## 6. Verification material and time

**IE1-021** — An offline package (OFFLINE-VERIFICATION-1) MUST carry one
signed evidence bundle (EBMP-2 section 11) and every certificate, raw public
key, trust root, registry snapshot, revocation statement, transparency proof,
timestamp, and policy artifact required to reproduce verification without a
network. The bundle's envelopes and observations are the package's `envelope`
and `observation` artifacts, and their canonical payloads are its `payload`
artifacts. The package MUST carry at least one artifact of each of the roles
`payload`, `envelope`, `trust_policy`, `verification_key`,
`revocation_snapshot`, `registry_snapshot` and `time_evidence`, and the
artifact whose digest each `trust_policy`, `revocation_snapshot`,
`registry_snapshots` and `time_evidence` reference of its manifest gives. The
bundle itself carries none of this material (TP1-001); IE1-022 states how a
verifier treats it.

**IE1-022** — Verification material that an envelope or an offline package
carries MUST be treated as evidence and MUST NOT automatically be treated as a
trust anchor. A verifier MUST verify an offline package under the trust
policy, the earlier versions of that policy and the evaluation time that its
caller supplies, never under a policy or time that the package carries. The
manifest is not authenticated: its `expires_at` is the producer's statement and
limits only a holder who does not change it. The verifier MUST make these
checks in order and report the verdict of EBMP2-060 and the error code that the
first check to fail gives; a package that exceeds a declared limit of the
verifier (IE1-028) is `invalid`, with `ecl.error.resource-limit-exceeded.v1`,
at the check that meets the limit:

1. the archive is in `ecl.zip.store.v1` form (IE1-030, IE1-031): `invalid`, `ecl.error.semantic-invalid.v1`;
2. the archive holds `manifest.json`: `incomplete`, `ecl.error.causal-closure-incomplete.v1`;
3. the manifest is strict JSON (IE1-002) that satisfies `https://externalcontrollayer.ai/ns/schema/offline-verification-package/1`, its `created_at` and `expires_at` are valid instants, and every artifact entry and every `trust_policy`, `revocation_snapshot`, `registry_snapshots` and `time_evidence` reference in it has an `ecl.digest.sha-256.v1` digest: `invalid`, `ecl.error.schema-invalid.v1`;
4. the manifest's artifact paths could be the entry names of one `ecl.zip.store.v1` archive together with `manifest.json` (IE1-030, IE1-031), and they name every other member of the archive: `invalid`, `ecl.error.semantic-invalid.v1`;
5. the manifest's `expires_at` is later than its `created_at`: `invalid`, `ecl.error.expired.v1`;
6. every artifact that the archive holds has the size and SHA-256 digest of its manifest entry: `invalid`, `ecl.error.integrity-invalid.v1`;
7. every `envelope` and `observation` artifact is strict JSON and a JSON object: `invalid`, `ecl.error.schema-invalid.v1`; these artifacts are the envelopes and observations of the package's evidence bundle;
8. every `payload` artifact is the payload of a packaged envelope or observation: `invalid`, `ecl.error.integrity-invalid.v1`;
9. when the package carries an envelope, its bundle, verified with the caller's inputs as EBMP2-057 to EBMP2-062 require, is not `invalid`: `invalid`, with the bundle's findings;
10. the archive holds every artifact that the manifest names or IE1-021 requires and the payload of every packaged envelope and observation, and the package carries an envelope: `incomplete`, `ecl.error.causal-closure-incomplete.v1`;
11. the bundle is not `incomplete`: `incomplete`, with the bundle's findings;
12. otherwise the package has its bundle's verdict and findings, except that a package whose `expires_at` is not later than the evaluation time is `current-trust-failed`, with `ecl.error.expired.v1`, where its bundle is `verified`.

**IE1-023** — Verification at issue time, observation time, trusted timestamp
time, current time, or another declared time are distinct policies. A verifier
MUST state which policy it applied.

**IE1-024** — A signature MUST NOT count, even when its cryptographic check
passes, if its key is not acceptable under the trust policy, suite, purpose or
policy context, or is revoked or outside its validity interval at the
evaluation time; an envelope whose counted signatures do not meet its threshold
or its required keys MUST NOT be reported as valid. A verifier MUST report such
an envelope with the error code that IE1-040 assigns.

## 7. Countersignature and transition

**IE1-025** — A countersignature, notarization, or timestamp MUST bind the
digest and media type of the exact object it covers and identify its distinct
claim.

**IE1-026** — Adding verification material or a countersignature creates a new
envelope version or bundle artifact; it MUST NOT change the signed payload.

**IE1-027** — Algorithm deprecation and emergency prohibition MUST be
registry-versioned, time-bounded, appealable, and reflected in offline trust
bundles.

## 8. Resource safety and deterministic containers

The ECL deterministic ZIP profile is `ecl.zip.store.v1`. It contains only
regular-file entries with the entry names defined below and no language-encoding
(UTF-8) flag, in bytewise order of their names, with the ZIP epoch
`1980-01-01T00:00:00Z`, Unix creator semantics, mode `0644`, empty entry and
archive comments, no extra fields, and the ZIP `stored` method. Directory,
link, device, encrypted, compressed, and data-descriptor entries are outside
this profile. An outer transport may compress the complete package, but that
wrapper is not the deterministic ECL package identity.

An entry name of `ecl.zip.store.v1` is a relative POSIX path of one or more
components separated by `/`. Each component consists of one or more characters
of the POSIX portable filename character set (`A` to `Z`, `a` to `z`, `0` to
`9`, `.`, `_` and `-`), is not `.` or `..`, does not end in `.`, and is not a
Windows device name (`CON`, `PRN`, `AUX`, `NUL`, `COM0` to `COM9`, `LPT0` to
`LPT9`) in any letter case, alone or before a `.`. Two entry names are aliases
when they are equal once each letter `A` to `Z` is replaced by the
corresponding letter `a` to `z`. An archive holds no two aliases, and no entry
name that is an alias of the leading components of another (such as `docs`
beside `Docs/a.json`). The artifact paths of an offline package's manifest are
entry names of its archive, and the paths of an offline package held as a
directory are entry names under the same rules (IE1-030). Entry names need no
Unicode normalization or case-folding table, so every verifier of the profile,
and every verifier of a package held as a directory, reaches the same result
whatever Unicode version its platform implements. In an offline package's
manifest, the `deterministic_assembly` value `utf8-nfc-posix-relative` of
`path_encoding_policy` names this entry-name rule, and the value
`utf8-bytewise-path` of `entry_order` names the bytewise order of entry names;
an entry name is ASCII, so its UTF-8 bytes are its ASCII bytes.

**IE1-028** — Every conforming parser, verifier, and offline-package processor
MUST operate under a declared profile of finite, positive resource limits
covering, as applicable, encoded input bytes, canonical JSON nesting and node
counts, envelope and signature counts, archive member counts, per-member and
total expanded bytes, compression ratio, and causal-record or predecessor
counts. Each limit MUST be an exact positive integer no greater than the ceiling
that this profile gives it: 4,096 for nesting depth, counted from 0 for the
top-level value, 100,000,000 for the number of values, and 2,147,483,647 for
encoded input bytes; an implementation MUST refuse a configured limit that is
not, such as `null`, a fraction, NaN, an infinity, a string, zero, a negative
number or a value above its ceiling, before it reads any input, as a
configuration error that it reports with `ecl.error.configuration-invalid.v1`
where it reports a code, and never as a finding about the input. A limit that a
configuration leaves out takes the implementation's declared default.
Conformance evidence MUST identify the exact limits applied. A profile MUST NOT
silently replace a finite limit with an unlimited value.

The libraries of this repository declare the same defaults for strict JSON input
in every lane: a nesting depth of 256, counted from 0 for the top-level value,
and 1,000,000 values; the byte limit is each lane's declared one (the reference
library's is 64 MiB). The ceilings above bound what a configuration can raise a
limit to, so a configured limit is the same number in every lane, and an input
at or beyond a ceiling has the same finding everywhere.

**IE1-029** — An implementation MUST enforce applicable resource limits before
unbounded allocation, decompression, recursive traversal, or cryptographic
work. It MUST use bounded or incremental processing where an input can exceed
the declared in-memory budget: it MUST stop reading an input from a file or a
stream once the input exceeds its byte limit, a strict JSON parser MUST NOT
build a value beyond its declared nesting and value limits (IE1-037), and an
archive reader MUST NOT hold more member entries than its member limit.
Malformed input or a resource-limit violation MUST fail closed with a stable
error classification and MUST NOT yield a partially verified artifact,
decision, or conformance result.

**IE1-030** — Archive and package processing MUST reject absolute paths,
platform drive paths, parent traversal, control characters, non-canonical
Unicode path aliases, duplicate paths after canonical normalization, links,
encrypted members, and non-regular members unless a stricter registered
profile defines and verifies their complete semantics. Filesystem verification
MUST also reject a path whose parent resolution crosses a link outside the
verified package root. The paths of an offline package held as a directory
MUST be entry names of `ecl.zip.store.v1` (section 8), no two of them aliases
and none an alias of the leading components of another.

**IE1-031** — A package format that claims deterministic construction MUST
define canonical entry names and order, timestamps, permissions, platform
attributes, encoding flags, storage method, container comments and extra
fields, and source-byte selection. An `ecl.zip.store.v1` producer rebuilding
the same declared inputs MUST produce byte-identical output, and a verifier
for that profile MUST reject entry names, container metadata or ordering that
depart from the rules above.

## 9. Trusted time

An object's own time (`issued_at` for DCMP-2, `observed_at` for EBMP-2) is asserted
by its signer, so a holder of a compromised key can date new evidence before the
key's revocation. A trusted-time countersignature is a separate time authority's
signed statement that the covered payload and the signatures it names existed no
later than an attested time, which a verifier can use in place of the asserted
one for those signatures. A statement about the payload alone would not do: a
signature made later over the same payload has the same payload digest.

**IE1-032** — A trusted-time countersignature MUST be an entry of the envelope's
`countersignatures` member with `counter_id`, `claim` set to
`ecl.claim.trusted-time.v1`, and `attestation`: an ECL-IE-1 envelope, without
countersignatures of its own, whose payload type is
`application/vnd.ecl.time-attestation+json` and whose payload satisfies
`https://externalcontrollayer.ai/ns/schema/time-attestation/1`. Adding one MUST
NOT change the covered envelope's payload, payload type, payload digest or
signatures, and the producer that adds it MUST increase
`envelope_artifact_version` by one (IE1-026). The increment is a producer
obligation: a verifier sees one envelope, not its predecessor, and does not
check it.

**IE1-033** — A time attestation MUST bind in `covered` the covered envelope's
payload type (`media_type`), its payload digest (`digest`) and the signatures
that it attests (`signatures`): for each signature entry of the envelope that it
covers, in the envelope's order, the entry's `key_id`, its `suite_id` as
`suite`, and as `signature_digest` the `ecl.digest.sha-256.v1` digest of the
signature bytes that the entry's `signature` encodes. It MUST carry the attested
time in `issued_at` and the time authority in `issuer`, MUST carry an
`attestation_id` equal to the entry's `counter_id`, and MUST be signed under its
own payload-bound integrity policy, with the verification-time policy
`ecl.time.issued-at.v1`, by keys whose trust-policy purpose is
`ecl.purpose.trusted-time.v1` and whose principal is the issuer. An attestation
attests that the covered payload and the covered signatures existed no later
than the attested time; it attests nothing about a signature that it does not
cover.

**IE1-034** — A verifier that evaluates a trusted-time countersignature MUST
verify the attestation under the trust-policy version the attestation names, at
its attested time, and MUST apply to each of its signing keys the revocations of
the caller's current trust policy (TRUST-POLICY-1 TP1-006). A countersignature
is invalid, and the covered envelope is not historically valid, with
`ecl.error.trusted-time-invalid.v1`, when its claim is not a registered
countersignature claim; when the attestation fails that verification, TP1-006,
IE1-032 or IE1-033; when an entry of `covered.signatures` names no signature
entry of the envelope with that `key_id`, that suite and that signature digest,
or the entries are not in the envelope's order or name one signature twice; when
its issuer (the attestation's `issuer.id`) is the covered object's own
principal, which is `issuer.id` for a DCMP-2 message and `producer.id` for an
EBMP-2 record; or when the covered object's own time is later than the attested
time. When every trusted-time countersignature of an envelope is valid, the
verifier MUST evaluate the historical validity of each signature that a
countersignature covers at the earliest attested time among the
countersignatures that cover it, and of each other signature at the object's own
time, and MUST report the time at which it evaluated each signature. A
signature that no countersignature covers, such as one added to the envelope
after the attestation, has no attested time; a signature replaced after the
attestation makes the countersignature invalid. The threshold of IE1-040 step 7
counts each signature as evaluated at the time this rule gives it. Version 1.0
defines no archive renewal: an attestation carries no countersignature of its
own (IE1-032), so a later attestation is one more countersignature, verified on
its own, and does not protect an earlier one.

Note (informative), countersignature and backdating: an evidence signer that a
revocation in the current policy, whatever its reason (TRUST-POLICY-1 TP1-006),
makes untrusted from a time between an object's own time and its attested time
makes a countersigned envelope not historically valid, while the same
envelope without a countersignature is only not acceptable now
(`current-trust-failed` in a bundle, EBMP-2 EBMP2-060). The difference is
intended. A trusted time is independent evidence; when it shows the signature
existing only after the compromise, the signer's earlier own time cannot be
relied on. Without a trusted time a verifier cannot detect backdating, and can
only report that the signer is not acceptable now.

**IE1-035** — A verification profile MAY require trusted time. Under such a
profile a verifier MUST refuse an envelope that carries no trusted-time
countersignature, or one of whose signature entries no trusted-time
countersignature covers, as not historically valid, with
`ecl.error.trusted-time-required.v1`. The registered profile
`ecl.verification-profile.reference-trusted-time.v1` is the reference
verification profile with this requirement.

**IE1-036** — A claim at `L3` or `L4` MUST meet ECL1N-0100 for its signed evidence
in one of two ways: a trusted-time countersignature on every signed evidence
object, verified under a verification profile that requires trusted time; or a
declared secure monotonic sequencing mechanism, stating its sequencing authority,
its observation points and the procedure by which a verifier checks the sequence
offline. A claim that uses neither MUST NOT be made at `L3` or `L4`.

## 10. Claim boundary

A valid envelope proves that accepted keys signed the typed payload bytes under
the evaluated policy. It does not by itself prove that the payload was true,
that the signer observed the external world correctly, that the signer was
independent, or that an action was safely executed.

## 11. Envelope verification

A verifier checks an envelope with three inputs: the envelope, the trust policy
that its caller supplies (TRUST-POLICY-1, never one that the envelope or a
bundle carries), and an evaluation time. Standalone verification takes the
evaluation time from its caller. Historical validity in a signed evidence
bundle (EBMP2-057), and the `envelope` stage of the conformance runner, use the
object's own time: `issued_at` for a DCMP-2 message and `observed_at` for an
EBMP-2 record, which the object's integrity policy names as
`ecl.time.issued-at.v1` or `ecl.time.observed-at.v1`. Current status in a bundle
uses the caller's current policy and evaluation time (TP1-006).

Each payload belongs to one component role, and only a key that holds the
purpose of that role signs it acceptably. The roles follow TRUST-POLICY-1: the
requester of a decision also answers its challenges, the decision point answers
a request with a response or a challenge, and the control plane issues control
messages.

**IE1-039** — A verifier MUST count a signature only under a key whose
trust-policy purposes include the purpose of the payload that this table
gives:

| Payload | Payload media type | Purpose of its signing key |
|---|---|---|
| DCMP-2 `decision_request` or `challenge_response` | `application/vnd.ecl.dcmp+json` | `ecl.purpose.decision-request.v1` |
| DCMP-2 `decision_response` or `challenge` | `application/vnd.ecl.dcmp+json` | `ecl.purpose.decision-response.v1` |
| DCMP-2 `control` | `application/vnd.ecl.dcmp+json` | `ecl.purpose.control.v1` |
| EBMP-2 record | `application/vnd.ecl.ebmp+json` | `ecl.purpose.evidence-event.v1` or `ecl.purpose.observation.v1` |
| Time attestation (section 9) | `application/vnd.ecl.time-attestation+json` | `ecl.purpose.trusted-time.v1` |

Standalone verification cannot tell an evidence event from an observation,
because both are EBMP-2 records; a bundle verifier tells them apart by where
the record sits in the bundle and requires the purpose of that place
(EBMP2-057, TP1-004).

**IE1-040** — A verifier MUST check an envelope in this order, and MUST refuse
an envelope at the first step it fails, with that step's error code:

1. the envelope satisfies its schema, or `ecl.error.schema-invalid.v1`;
2. its encoded payload, its number of signature entries and each encoded signature value are within the verifier's declared limits (IE1-028), or `ecl.error.resource-limit-exceeded.v1`;
3. the payload is canonical base64, its digest is the `ecl.digest.sha-256.v1` digest of the decoded bytes, the bytes are canonical strict JSON (IE1-001, IE1-011, IE1-037) whose value is an object with an `integrity_policy` object, and the payload media type and the payload's `protocol` name the same protocol (IE1-010), or `ecl.error.integrity-invalid.v1`; a declared limit that the strict parse reaches (IE1-037, checks 1 and 3) gives `ecl.error.resource-limit-exceeded.v1` instead;
4. the lists of the payload-bound policy are within the verifier's declared limits, or `ecl.error.resource-limit-exceeded.v1`; then the policy requires integrity, its threshold is at least one and not lower than the number of required keys, its key and suite lists are lists of distinct identifiers with at least one accepted suite, and its trust-policy reference, verification-time policy and revocation policy are those of the trust policy and evaluation the verifier applies, or `ecl.error.signature-policy-invalid.v1`;
5. every signature entry names a key and a suite, and no two entries name the same key and suite, or `ecl.error.integrity-invalid.v1`;
6. each signature entry is examined in turn: (a) the payload's policy accepts its suite, the trust policy allows the suite, the key is eligible when the policy lists eligible keys, the trust policy holds the key with that suite, and the key holds the purpose of the payload (IE1-039), or the signature does not count because its key is not acceptable; (b) the key is not revoked at the evaluation time, or the signature does not count because its key is revoked; (c) the evaluation time is within the key's validity interval, or the signature does not count because its key is expired or not yet valid; (d) the signature value is canonical base64, a P-256 signature is minimally encoded DER with a low S value (IE1-017) and an ML-DSA-65 signature is 3309 bytes long (IE1-018), or the verifier refuses the envelope with `ecl.error.integrity-invalid.v1`; (e) the signature verifies, for Ed25519 with S below the group order under the cofactorless equation (TP1-008), or it does not count because it does not verify;
7. the keys whose signatures count include every required key and number at least the threshold, or the error code is that of the earliest reason in step 6 that some signature has: a key that is not acceptable gives `ecl.error.signature-policy-invalid.v1`, a revoked key `ecl.error.revoked.v1`, a key outside its validity interval `ecl.error.expired.v1`, and a signature that does not verify `ecl.error.signature-policy-invalid.v1`; when no signature has any of these reasons, the error code is `ecl.error.threshold-not-met.v1`.

A signature that does not count does not make an envelope invalid while the
other signatures meet the policy (IE1-015). A bundle verifier is stricter: every
signature of a bundle's envelope, counted or not, passes steps 6 (a) to (c)
under the object's purpose and principal (TP1-004, TP1-005, EBMP2-057).
