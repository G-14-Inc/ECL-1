# ECL-1 assessor competence and independence policy

This policy says what makes an assessment of an ECL-1 claim competent and
independent. It does not appoint assessors. Neither the maintainer nor the
working group attests anyone's conformance: assessments are made by assessors
under this policy, and the implementers registry lists an assessment
separately from the self-declared claim when the implementer provides it
([CONFORMANCE_CLAIMS](CONFORMANCE_CLAIMS.md)). A result of G-14's own tests is
labelled as G-14's.

## Purpose

Assessment quality is separate from implementation quality and from
specification authorship. A technically strong internal review is still
internal. Tooling, model choice, or organizational labels do not create
independence.

## Required assessor record

For each assessment, record:

- assessor identity, organization, role, relevant competence, and methods;
- claimed level, System of Interest, boundary class, profiles, versions, and
  evidence period;
- financial, employment, implementation, advisory, hosting, reseller, and
  personal relationships with the claimant;
- whether the assessor authored the evaluated controls or evidence;
- safeguards, recusals, unresolved conflicts, and final independence class;
- assessment decision, findings, residual risk, and limitations.

## Disqualifying conflicts

Unless a stricter profile applies, an assessor is not independent for the
affected scope when the assessor:

- implemented or directly administered the evaluated control;
- prepared the claimant's decisive evidence or selected only the passing
  sample;
- is compensated contingently on a passing decision;
- reports through the same decision chain that owns the control outcome;
- holds a material undisclosed financial interest;
- cannot publish or communicate a failing result to the authorized recipient.

Separate personnel inside one organization may support a Class B claim only
when reporting, access, incentives, evidence selection, and decision authority
are demonstrably separated as required by the standard. A name change or
separate account is insufficient.

## Competence

The assessor team collectively covers:

- ECL normative and companion semantics;
- identity, delegated authority, policy, enforcement, and bypass analysis;
- cryptographic verification and key lifecycle;
- distributed causality, retries, partial outcomes, and safe states;
- evidence lifecycle, privacy, offline verification, and fleet behavior;
- the claimed deployment sector and applicable consequence model.

Competence gaps are disclosed and filled by a named specialist; they are not
silently treated as Not Applicable.

## Evidence control

The assessor chooses or approves samples, can reproduce the verifier without
claimant-controlled network dependencies, receives the Negative Boundary
Annex, and can issue a fail or indeterminate result. Missing material evidence
is not a pass.

## AI-assisted and internal review

AI tools may support evidence organization and bounded analysis, but the
record names the tool role and human accountability. AI-assisted review is an
internal pre-assessment and cannot satisfy the assessor independence of
Sections 7.8 and 7.11. Repeated model calls are not multiple independent
assessors.

## Conformance-mark boundary

An assessment report does not authorize a mark. ECL-1 has no certification
mark ([TRADEMARKS_AND_MARKS](TRADEMARKS_AND_MARKS.md)), and a certification
program would need a separately authorized certifying body that
confirms assessor eligibility, scope, currentness, open findings, and mark
terms. The specification repository cannot self-issue that authority.
