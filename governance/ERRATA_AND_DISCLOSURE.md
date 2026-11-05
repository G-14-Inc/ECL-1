# ECL-1 errata and defect-disclosure policy

This policy defines the defect classes of ECL-1 and what an erratum records.
The editors apply it, and the maintainer, G-14, Inc., publishes the errata.
The procedure that applies this policy is in `ERRATA.md`.

## Defect classes

- **Editorial erratum**: meaning and interoperability do not change.
- **Technical erratum**: released text or artifact is incorrect, ambiguous,
  inconsistent, or unreproducible.
- **Security defect**: exploitation could bypass control, forge or suppress
  evidence, widen authority, corrupt verification, or create unsafe recovery.
- **Conformance defect**: a claim, assessor rule, or vector can produce false
  assurance.

## Required erratum record

Each published erratum identifies affected versions and artifacts, original
and corrected behavior, severity, compatibility effect, detection date,
decision date, tests, migration, and whether prior claims require
reassessment. Errata never silently replace released bytes.

## Disclosure

Editorial and non-sensitive technical defects are public when accepted.
Security-sensitive details follow `SECURITY.md` and may be embargoed only for a
bounded remediation window. Embargo does not permit an affected release to be
represented as unaffected.

## Release effect

The table in `ERRATA.md` ("Classify it") states how each change class is
published and what it does to the version, so that the policy and the
procedure cannot disagree. A behavioral correction is never an erratum, even
when the earlier behavior was unintended. A defect capable of producing a false
conformance pass blocks new claims and may require withdrawal, reassessment,
or the review of affected listings in the implementers registry
(`CONFORMANCE_CLAIMS.md`).

## Historical integrity

The original release, erratum, superseding release, and decision record remain
individually digest-addressable. A current-view document may point to the
superseding version but must not erase the historical record.
