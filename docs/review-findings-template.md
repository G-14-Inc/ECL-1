# ECL-1 finding

Use this template for a finding about ECL-1 Version 1.0: about its texts, its
schemas, its conformance tests, its sample evidence or its offline verifier,
and for the findings of an assessment. A finding about the standard goes to the
ECL-1 repository as an issue; during a public review window it is a review
comment that receives a published disposition ([governance/PUBLIC_REVIEW.md](../governance/PUBLIC_REVIEW.md)).
A security finding is reported privately, as [SECURITY.md](../SECURITY.md)
describes, never in a public issue. The findings of an assessment of a claim go
to the party for whom the assessment was made.

| Field | Your input |
|---|---|
| Finding ID | FINDING-… |
| Title | Short observed defect |
| Severity | Critical / Important / Minor for a finding about the texts; `critical` / `major` / `minor` (ECL1N-0147) for a failed checklist item of a claim; with reason |
| Version identity | ECL-1 version and companion versions, and the digest of the release archive or manifest |
| Affected requirement | Requirement ID, checklist item, document and section, schema, vector or verifier file |
| Reviewer identity | Name, organization and relevant experience; for a public issue, what you choose to give |
| Credit | By name, by organization only, or not at all |
| Conflicts disclosure | Authorship, funding, employment, control and prior involvement, including any relationship to the claimant or to the maintainer |

## Reproduction steps

Give the exact environment, command, input and declared capabilities. Keep
sensitive material out of a public issue, and redact credentials.

## Observed versus expected

Quote a short necessary source fragment and explain the invariant it violates.
Distinguish an ambiguity in the text from a failure of running code.

## Evidence

Attach the minimal failing artifact, the output, the relevant vector or trace
and its digests. Record negative controls and whether the unchanged input
passes.

## Suggested disposition

Propose a bounded correction, and a check that would reject the original
defect. A finding does not certify anything or grant any status. You may
propose text in a pull request, under the contribution rules of
[governance/CONTRIBUTING.md](../governance/CONTRIBUTING.md); the editors decide
the disposition and record its reason.
