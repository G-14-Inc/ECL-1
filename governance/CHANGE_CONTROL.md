# ECL-1 change-control policy

This policy says how a change to ECL-1 is classed, reviewed and decided. The
editors apply it, and every class goes through the working group's decision
process: the editors propose, the working group discusses, and the editors
decide by rough consensus and record the reason ([CHARTER](CHARTER.md),
section 8).

## Change classes

| Class | Examples | Minimum effect | Discussion before the editors decide |
| --- | --- | --- | --- |
| Editorial | Typo, formatting, non-normative clarification | No semantic or test change | The pull request's review |
| Corrective | Implementation or generated-artifact repair to unchanged, unambiguous published requirements; textual clarification with no change to required or permitted behavior | Erratum or patch version; regression proof | At least 30 days, with an announcement, for a proposed corrective erratum ([ERRATA](ERRATA.md)); an embargoed security fix follows SECURITY |
| Additive | New optional field, profile, or non-critical allocation | Minor version, with positive and negative vectors | 14 days |
| Behavioral | Changed rule, default, error, criticality, or claim meaning | Minor version, with explicit compatibility review and versioned migration | 14 days, after an announcement in the "Announcements" category of the discussions |
| Breaking | Removed or renamed required surface, or widened or narrowed incompatible semantics | Major version; old identifiers never reused | 30 days, after an announcement |
| Emergency security | Time-sensitive change needed to prevent material harm | Embargoed two-person approval, bounded temporary action, later public record | None before the fix; the public record follows the embargo |

Classification follows semantic effect, not diff size or author label. Any
uncertainty is classified at the stricter class until resolved. A new minor or
major version also has a public review window before it is published: 30 days
for a minor version and 60 days for a major version
([PUBLIC_REVIEW](PUBLIC_REVIEW.md)). Patch versions and errata have no
additional version-wide review window; their proposal comment and review
periods still apply.

An observable implementation fix can be corrective when the old implementation
violated an unchanged, unambiguous requirement. Changing a normative rule,
default, required diagnostic, evidence classification or claim meaning is
behavioral even when it repairs a defect. Resolving contradictory requirements
also requires behavioral review: record the competing readings, the selected
behavior and the effect on implementations that followed either reading.
Unclear prior conformance does not establish compatibility. If the repair
removes behavior on which a previously conforming implementation could rely,
apply the breaking-change class and its migration requirements.

The [November 10, 2026 clarification](RELEASE-CLARIFICATION-2026-11-10.md)
applies this distinction to the preserved v1.0.1 record. It adds a compatibility
assessment without changing that release's historical label or inventing a
past compatibility waiver. Subsequent changes follow this classification and
the applicable review, versioning and migration process.

## Proposal contents

Every non-editorial proposal identifies:

- affected requirement, term, field, wire value, schema, registry, vector,
  profile, and implementation surfaces;
- compatibility class and affected versions;
- threat, safety, privacy, interoperability, and conformance-claim impacts;
- migration, deprecation, rollback, and evidence plan;
- positive and negative tests;
- whether the change alters the six-responsibility boundary.

## Required review

The historical [Version 1.0](RELEASE_POLICY.md#version-10-release-exception)
and [v1.0.1](RELEASE_POLICY.md#correction-release-exception-v101) exceptions
waived only their named steps. They neither record completion of those steps
nor waive compatibility obligations.

- Editorial: an editor and the automated checks.
- Corrective or additive: an editor and a second reviewer.
- Behavioral or breaking: the editors, a release reviewer with no conflict,
  compatibility evidence, the announcement and discussion period above, and
  the editors' decision by rough consensus with its reason recorded. A
  breaking change keeps the old behavior available for at least 12 months
  (ECL1N-0088).
- Emergency security: the security response lead and one other authorized
  reviewer with no conflict. Emergency approval expires at the recorded
  deadline and cannot silently become permanent. When the embargo ends, the
  change and its reason are published, and the change goes through the class
  it would otherwise have had.

No author self-approves the only review needed for a change.

## Compatibility and versioning

- Immutable identifiers are never reassigned.
- Additive changes cannot make a previously valid object invalid unless the
  prior behavior was a documented security defect.
- Unknown critical semantics fail closed; unknown non-critical semantics
  follow the declared preservation policy.
- A behavioral change updates all affected normative text, schemas,
  registries, vectors, reference behavior, claim grammar, and release metadata
  atomically.
- Deprecation and prohibition remain distinct. A deprecated feature continues
  to have defined behavior during its window; a prohibited feature must fail.
- A version is numbered major.minor, with a patch number for a patch version:
  a breaking change starts a major version, an additive or behavioral change
  a minor version, and a patch version only collects corrective and editorial
  changes.

## Source of truth and generated artifacts

The sole normative core is `standard/ECL-1_Standard.md`. Generated artifacts
never override it. A generated output is admissible only when its generator,
source inputs, and digests are recorded and reproduction yields the same
bytes.

## Merge and release admission

A change is merge-eligible only when its declared scope reconciles with the
actual diff, required tests pass, generated outputs are current, every commit
carries a sign-off ([CONTRIBUTING](CONTRIBUTING.md)), and no unresolved
blocking finding applies. Merge eligibility is not publication: releases follow
[RELEASE_POLICY](RELEASE_POLICY.md).
