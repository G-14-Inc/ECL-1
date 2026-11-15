# ECL-1 release policy

This policy says how the maintainer, G-14, Inc., releases ECL-1 Version 1.0
and its later versions, patch versions and errata, and how a release is
withdrawn or superseded.

## Version 1.0 release exception

On 5 November 2026, the maintainer waived these prepublication conditions for
Version 1.0: the two-person release rebuild and checklist signatures, and the
externally exercised email and GitHub private security-intake tests. Those
activities were not completed before publication. This exception takes precedence over the corresponding conditions
below for Version 1.0 only.

The exception does not change the standard's normative requirements,
implementation-assessment obligations, technical test results, review-status
disclosures or release-artifact integrity checks. Publication remains the
maintainer's decision. The general requirements below continue to apply to
later releases unless changed through the published change process.

## Correction-release exception: v1.0.1

On 9 November 2026, Robert F. Tilley Jr., for G-14, Inc., authorized a
one-time process exception for correction release `v1.0.1` of ECL-1
Version 1.0 and its Version 1 reference edition.
The exception permits its preparation and publication without completing:

- the separate second-person review of corrective changes;
- the two-person release rebuild and both release-checklist signatures;
- the corrective-erratum comment period and the charter-change discussion
  period for the corrections included in this release; and
- the externally exercised email and GitHub private security-intake tests.

For `v1.0.1` only, this exception takes precedence over the corresponding
conditions of this policy, [CHANGE_CONTROL](CHANGE_CONTROL.md),
[ERRATA](ERRATA.md), and [CHARTER](CHARTER.md) section 16 for the charter
classification correction identified in the release notes.

These activities are waived as prepublication conditions for this correction
release; the exception records no successful completion of them. The exception
itself alters no normative technical requirements, implementation-assessment duties,
recorded test results, compatibility obligations or the evidence required for
a conformance claim. It preserves the original release and its disclosures.
The general review and release rules continue to apply to later releases.
The final release manifest identifies the exact corrected files; publication
still requires the maintainer's authorization of those artifacts.

The [November 10, 2026 clarification](RELEASE-CLARIFICATION-2026-11-10.md)
preserves this exception and the historical correction ledger. Its per-entry
compatibility assessment identifies normative defect repairs that require
behavioral treatment under the clarified change-control policy; this exception
did not waive those compatibility obligations or retroactively approve a
classification. The clarification also records missing review and role
evidence without treating a waived step as completed.

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

- the maintainer's recorded authorization for that version and its exact final
  artifacts, identifying the decision date, publication scope and artifact
  digests; an earlier standing decision, process exception, file manifest or
  hosting-platform attestation does not by itself supply that record;
- every finding of the outside security review fixed, or disclosed in the
  release notes with its reason;
- no unresolved release-blocking finding;
- completed assessment only for claims that require it.

The original Version 1.0 release was published under the maintainer's
authorization without a public review window. The Version 1 public-review
draft and later minor and major versions follow
[PUBLIC_REVIEW](PUBLIC_REVIEW.md). Comments on published versions may be
submitted at any time.

## Errata and patch versions

An erratum is published in the errata index of its version
([ERRATA](ERRATA.md)). A patch version collects corrective and editorial
changes and is published under this policy without an additional version-wide
review window; its proposal comment and review periods still apply.

## Withdrawal and supersession

The maintainer may withdraw or supersede a release for security, integrity,
legal, or conformance defects. The notice identifies affected versions,
reason, safe disposition, replacement if any, reassessment effect, and
original and replacement digests. Withdrawal never deletes history.
