# ECL Offline Verification Profile 1

Status: informative guide for ECL-1 Version 1.0, a published version. It states no
requirement of its own: every obligation it describes is allocated, with an ID, in
the core standard or a normative companion it cites.  
Profile identifier: `https://externalcontrollayer.ai/ns/profile/offline-verification/1`  
Manifest schema: `https://externalcontrollayer.ai/ns/schema/offline-verification-package/1`  
Media type: `application/vnd.ecl.bundle+zip`  
Container profile: `ecl.zip.store.v1`

## Purpose

An offline package lets a reader verify ECL evidence without a network path to
its producer or to any control plane: on a disconnected edge, in an air-gapped
or sovereign enclave, at a transfer station, in an assessor hand-off, or when
evidence is preserved for later. The normative rules are IE1-021 and IE1-022
of `INTEGRITY-ENVELOPE-1` (what a package carries and how a verifier treats
it), IE1-028 to IE1-031 (resource limits and the `ecl.zip.store.v1` container),
EBMP2-057 to EBMP2-062 of `EBMP-2` (verification of a signed evidence bundle
and its verdicts) and `TRUST-POLICY-1`. A package does not turn the material it
carries into a trust anchor, and it does not make its assertions true because
it is internally consistent.

## A package and its evidence bundle

A package is an `ecl.zip.store.v1` archive that holds `manifest.json` and the
artifacts the manifest names. The manifest binds each artifact by path, media
type, role, byte length and SHA-256 digest. A package carries exactly one
signed evidence bundle (EBMP-2 section 11), split into artifacts (IE1-021):

- each envelope of the bundle is an `envelope` artifact and each observation
  an `observation` artifact;
- the canonical payload of each is a `payload` artifact;
- the artifacts of the other roles (`trust_policy`, `verification_key`,
  `trust_root`, `revocation_snapshot`, `registry_snapshot`, `time_evidence`,
  `transparency_proof` and `conformance_result`) hold the material that the
  producer verified the bundle with.

IE1-021 requires at least one artifact of each of the roles `payload`,
`envelope`, `trust_policy`, `verification_key`, `revocation_snapshot`,
`registry_snapshot` and `time_evidence`, and the artifacts whose digests the
manifest's `trust_policy`, `revocation_snapshot`, `registry_snapshots` and
`time_evidence` references give. A bundle sent as JSON carries no trust root
(TP1-001); a package carries the producer's material beside its bundle, so that
a reader can see what the producer relied on.

## The caller's trust policy

A verifier takes three inputs from its caller: the current trust policy,
earlier versions of the same policy, and the evaluation time (TP1-001,
EBMP2-057). It verifies a package's bundle with those inputs, exactly as it
verifies a bundle that arrives as JSON. The trust policy, keys and snapshots in
the package are evidence (IE1-022). A reader can compare them with the policy
the caller holds, and a caller that decides, outside the package, to trust the
producer's policy supplies that policy as its own input. A package whose
evidence is signed with a key that only the package's own trust policy holds is
therefore `invalid`; the vector `package-invalid-carried-trust-is-evidence`
tests this.

## Verdicts

A package receives one of the four verdicts of EBMP2-060. IE1-022 lists the
checks in their order, with the error code of each, so that every verifier
gives the same verdict and code for the same package under the same declared
limits (IE1-028). Verifiers with different limits can disagree on a package
that exceeds the limits of only one of them: the browser verifier, for example,
reads an archive of at most 16 MiB, and the three verifier commands one of at
most 1 GiB. In summary:

| Verdict | When |
|---|---|
| `invalid` | The archive departs from `ecl.zip.store.v1`; the manifest is not strict JSON, fails its schema, lacks a SHA-256 digest, has a path that is not an entry name of the profile or that aliases another, leaves a member of the archive unnamed, or expires no later than it was created; an artifact's size or digest differs from the manifest; an `envelope` or `observation` artifact is not a JSON object; a `payload` artifact is the payload of no packaged envelope; or the bundle is `invalid`. |
| `incomplete` | The archive has no manifest; an artifact that the manifest names or IE1-021 requires is missing, or so is the payload of a packaged envelope; the package carries no envelope; or the bundle is `incomplete`. |
| `current-trust-failed` | The bundle is `current-trust-failed`, or the bundle is `verified` and the package's `expires_at` is not later than the evaluation time. |
| `verified` | None of the above. |

There is no fifth result. Missing material makes a package `incomplete`, and a
package is never reported as partly verified.

Nobody signs the manifest, so it is not authenticated (IE1-022). Its
`expires_at` is the producer's statement and limits only a holder who does not
change it: anyone who holds a package can extend its expiry. What the package
carries is authenticated only through the signatures of its evidence bundle,
which the verifier checks under the caller's trust policy.

## Deterministic container

`ecl.zip.store.v1` is the only deterministic ZIP profile of this version:

- entry names are relative POSIX paths whose components use only the POSIX
  portable filename characters (`A` to `Z`, `a` to `z`, `0` to `9`, `.`, `_`
  and `-`), and entries sort by the bytes of their names;
- absolute, drive, parent, empty-component, trailing-dot, device-name, link,
  encrypted and duplicate entries are rejected, and so are two names that are
  equal after ASCII case folding, or a name that so equals the leading
  components of another;
- only regular files with Unix creator semantics and mode `0644` are present;
- every timestamp is the ZIP epoch `1980-01-01T00:00:00Z`;
- no entry sets the language-encoding (UTF-8) flag;
- entry and archive comments and extra fields are empty;
- entries use ZIP storage without compression or data descriptors;
- the manifest itself is an ordinary profile-conforming entry.

The manifest's artifact paths are entry names of the archive under the same
rules (IE1-022, check 4). Section 8 of `INTEGRITY-ENVELOPE-1` defines entry
names. They need no Unicode table, so verifiers on different platforms, and
under different Unicode versions, accept and refuse the same archives. The
manifest's `path_encoding_policy` value `utf8-nfc-posix-relative` and
`entry_order` value `utf8-bytewise-path` name these rules. A package held as a
directory follows the same rules (IE1-030): its paths are entry names, compared
after ASCII case folding, so its result does not depend on the verifier's
platform either.

An outer transport can compress or segment the complete package. The receiver
first reconstructs and obtains, through a channel the receiver trusts, the
exact inner package bytes; the outer wrapper is not part of the deterministic
ECL package identity.

## Resource declaration

The verifier records its finite positive limits for encoded archive bytes,
member count, per-entry and total expanded bytes, compression ratio used to
reject non-profile input before extraction, path bytes, canonical JSON bytes,
nesting, nodes, signatures, and causal graph size. Limits are applied before
unbounded allocation, extraction, graph traversal, or cryptographic work. A
profile may lower or otherwise tune a finite bound for its deployment but
cannot silently remove it. A package that exceeds a limit is `invalid`, with
`ecl.error.resource-limit-exceeded.v1` (IE1-022). A limit can be one that no
package reaches: an `ecl.zip.store.v1` archive has no ZIP64 records, so its
end-of-central-directory record counts at most 65,535 members, and the member
limit of 100,000 that the conformance tests declare for the `package` stage is
never the check that refuses an archive.

## Conformance

The suite `conformance/suites/offline-package/` holds the package vectors; its
stage is `package`, and `conformance/README.md` states its input, steps and
output. Its capability, `offline-package-verification`, is optional, and an
implementation that declares it also declares `evidence-bundle-verification`.
The offline verifier implements the capability: `verifyOfflinePackage` of the
TypeScript package `packages/ecl-ts`, which the browser verifier also uses, and
the command `ecl-verify-ts`, which verifies a package as well as a bundle. A
file that begins with the bytes `PK` is read as a package of at most 1 GiB, the
command's declared archive limit, and is verified under the same inputs and
reported with the same output and exit statuses as a bundle. A larger file is a
usage error (exit status 2): the command refuses to read it, so it gets no
verdict, and in particular not `invalid` with
`ecl.error.resource-limit-exceeded.v1`.

## Air-gap transfer

Transfer media custody is evidence distinct from package integrity. A transfer
record binds source package digest, sender, receiver, media or channel
identity, dispatch and receipt observations, transformations, and destination
boundary. Dispatch alone is not receipt, and receipt alone is not successful
verification. Import into a native runtime requires current native policy
evaluation and effect authority.

## Claim boundary

A successful offline verification supports only the claims actually evaluated
against the included evidence and declared observation boundary. It is not a
live revocation check, an availability statement, an independent assessment,
an authorization to execute, or evidence that a later environment retained the
same state. Those claims require their own current evidence and authority.
