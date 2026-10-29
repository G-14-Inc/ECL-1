# ECL-1 release policy

This policy says how the maintainer, G-14, Inc., releases ECL-1 Version 1.0
and its later versions, patch versions and errata, and how a release is
withdrawn or superseded.

## Versions and release states

- A version is numbered as [CHANGE_CONTROL](CHANGE_CONTROL.md) says. Version
  1.0 is designated "ECL-1 Version 1.0", its version string is `1.0` and its
  release identifier is `ECL-1-1.0`. The companion protocols and profiles
  carry their own versions, which the version set binds
  (`release/VERSION_SET.json`).
- The release states are: the editors' draft, which is the work in progress in
  the public repository and never a release; a review draft, frozen at a tag
  for a public review window, for a minor or major version; a published
  version; and a superseded or withdrawn version. A state advances only
  through the maintainer's recorded authorization; passing tests do not
  advance it.

## Freeze inputs

Each release freezes:

- the sole normative source and the companion protocol and profile versions;
- schemas, registries, vectors, expected results, reference behavior, and
  profiles;
- governance decisions, the licenses and the patent pledge
  ([LICENSING](../LICENSING.md), [PATENTS](../PATENTS.md));
- source, dependency, and third-party provenance;
- open findings, external gates, and prohibited claims.

## Checks before a release

- atomic normative requirement and evaluation closure;
- schema, registry, semantic-rule, vector, and link integrity;
- intended-reason negative tests;
- offline and deterministic build reproduction;
- source manifest, SBOM, dependency lock, and third-party notices;
- current advisory scans of every exact dependency lock and the declared Go
  toolchain, with every finding fixed, excluded by a documented reachability
  analysis, or disclosed and accepted under this policy;
- a secret scan of the staged public repository and its history, with every
  finding classified and no unexplained credential or private value;
- a live third-party-link check, with every confirmed broken release-facing
  link fixed or disclosed, and a tested private security-reporting path;
- implementation compatibility evidence that privileges no implementation;
- for a minor or major version, the public review closed: every comment with
  a published disposition, every appeal closed and the disposition log
  published ([PUBLIC_REVIEW](PUBLIC_REVIEW.md));
- legal, rights, security-contact, outside-security-review and signing gates
  at the state where each applies.

An incomplete external gate is reported as incomplete or blocked, never pass.

## Two-person release rule

The release manager prepares the immutable release. A release reviewer with
no conflict rebuilds it from the frozen source and compares the manifest and
the archive digest. Both sign the checklist. Neither signature publishes the
release unless the maintainer separately authorizes it.

## Signatures

Release signatures use a documented key identity, purpose, validity,
revocation, custody, threshold, and verification procedure. Test keys and
developer keys cannot sign a release. A release is signed only once the
maintainer has approved a signing identity and production key custody. A
release published without a signature says so in its release notes, and is
identified by the SHA-256 digests of its archive and its manifest.

## Publication

The maintainer decides publication. A release is published in the public
repository at a tag, with its package, manifest and checksums, its release
notes, its change log, its errata index and the public verifier SBOMs generated
from the release's exact locks, and, for a minor or major version, the
disposition log of its public review. Publication also requires:

- the maintainer's recorded authorization for that version;
- every finding of the outside security review fixed, or disclosed in the
  release notes with its reason;
- no unresolved release-blocking finding;
- completed assessment only for claims that require it.

Version 1.0 is published by the maintainer's authorization without a public
review window. The windows of [PUBLIC_REVIEW](PUBLIC_REVIEW.md) apply to every
later minor and major version, and comments on Version 1.0 are open at any
time.

## Errata and patch versions

An erratum is published in the errata index of its version
([ERRATA](ERRATA.md)). A patch version collects corrective and editorial
changes and is published under this policy without a public review window.

## Withdrawal and supersession

The maintainer may withdraw or supersede a release for security, integrity,
legal, or conformance defects. The notice identifies affected versions,
reason, safe disposition, replacement if any, reassessment effect, and
original and replacement digests. Withdrawal never deletes history.
