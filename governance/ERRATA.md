# ECL-1 errata process

This document says how an error in a published version of ECL-1 is reported,
classified, corrected and published. It is the procedure for the policy in
[ERRATA_AND_DISCLOSURE](ERRATA_AND_DISCLOSURE.md), which defines the defect
classes and the contents of an erratum record, and it uses the change classes
of [CHANGE_CONTROL](CHANGE_CONTROL.md). It applies to the standard, its
companion protocols and profiles, its schemas and registries, and the
conformance and replay suites published with them. The editors run it, and the
maintainer publishes the errata.

## What an erratum is

An erratum corrects a published text or artifact so that it says what it was
intended to say. It does not add or remove an obligation that an implementer
could have relied on. A correction that does is a new version, and follows the
versioning rules below instead.

## Report an error

- Report a suspected error with the "Report an erratum" issue form in the
  public repository, naming the document, section, requirement IDs and
  version. During a public review window, a comment on the draft under review
  is a public review comment instead ([PUBLIC_REVIEW](PUBLIC_REVIEW.md)).
- Report an error that could let an action bypass a control, forge or hide
  evidence, widen authority or produce a false conformance pass privately,
  under [SECURITY](SECURITY.md).

## Classify it

The editors record the defect class from ERRATA_AND_DISCLOSURE (editorial
erratum, technical erratum, security defect or conformance defect) and the
change class from CHANGE_CONTROL. Uncertainty is resolved toward the stricter
class, as CHANGE_CONTROL requires.

| Change class | How it is published | Version effect |
|---|---|---|
| Editorial: typing, formatting, a wrong cross-reference; no change in meaning or tests | Errata index | None; the next version folds it in |
| Corrective: restores behavior the text already intended | Errata index, with a regression vector or test where one can show the error | Folded into the next patch version or the next version, which the version set records |
| Additive, behavioral or breaking | Not an erratum | A new version under the change-control and versioning rules; a breaking change keeps the old behavior for at least 12 months (ECL1N-0088) |

The only exception to the 12-month window is the one ECL1N-0088 allows: an
emergency security fix that requires faster withdrawal. The security advisory
then states what is withdrawn, from which versions, why the window is
shortened, and what implementers should do.

## Review and approval

- Editorial errata: an editor and the automated checks.
- Corrective errata: an editor and a second reviewer, as CHANGE_CONTROL
  requires; no author approves their own erratum alone.
- A proposed corrective erratum is open for comment for at least 30 days, in
  its issue or pull request and with an announcement in the "Announcements"
  category of the discussions, before the editors decide it by rough
  consensus, unless it is a security fix under embargo.
- A conformance defect that could have produced a false pass blocks new claims
  that rely on the affected vectors until the erratum is approved. The notice
  says whether earlier claims need reassessment (ECL1N-0152) and names the
  listings of the implementers registry that the defect may affect
  ([CONFORMANCE_CLAIMS](CONFORMANCE_CLAIMS.md)).

## The erratum record and its identifier

Each erratum has an identifier of the form `ERR-<version>-<number>`, for
example `ERR-1.0-003`, which is never reused. Its record holds every field that
ERRATA_AND_DISCLOSURE requires: affected versions and artifacts, original and
corrected text or behavior, severity, compatibility effect, detection date,
decision date, tests, migration, and whether earlier claims need
reassessment. Requirement identifiers do not change because of an erratum;
the requirement ledger records the corrected text when the next version folds
the erratum in, and the change log names it.

## Publication

- The errata index for a version lists every approved erratum with its
  record, and is published next to that version with its own digest.
- Released bytes are never replaced. The original release, the erratum and any
  superseding version stay separately digest-addressable, as
  ERRATA_AND_DISCLOSURE requires.
- A claim names the errata it applies along with the core version and the
  version set (ECL1N-0087).
- The patent pledge covers the errata that G-14, Inc. publishes for a covered
  version ([PATENTS](../PATENTS.md), section 2).

## Errata index: Version 1.0

No erratum has been approved or published for Version 1.0. An approved erratum
of Version 1.0 is listed here with its identifier, `ERR-1.0-<number>`, and its
record.
