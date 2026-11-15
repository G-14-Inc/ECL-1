# ECL-1: External Control Layer Standard

**Version 1 — Public Review Draft**  
Authored and produced by **Robert F. Tilley Jr. and G-14, Inc.**

ECL-1 specifies how a control layer outside an AI system authorizes consequential
actions, enforces the authorized action at the point of effect, and records
evidence that others can verify. It covers actions such as changing a record,
issuing a payment, sending a message or operating equipment.

**Public review closes 11 January 2027 at 20:00 UTC.** Engineers, safety
professionals, security researchers, assessors and prospective implementers are
invited to examine the specification and its supporting tools.

**[Read the reference PDF](https://github.com/G-14-Inc/ECL-1/releases/download/v0.9.0/ECL-1-Version-1-Public-Review.pdf)**
· **[Download the source](https://github.com/G-14-Inc/ECL-1/releases/download/v0.9.0/ecl-1-0.9.0.zip)**
· **[Submit a review comment](https://github.com/G-14-Inc/ECL-1/issues/new?template=public-review-comment.yml)**
· **[Review dates and citation](PUBLIC-REVIEW.md)**

## What to examine

The draft defines the contract between a proposed action and its execution:
the authority required, the exact action permitted, the conditions for release,
the behavior when proof or services are unavailable, and the evidence retained
afterward. Its integration profiles connect that contract to existing systems.

Useful review contributions include ambiguous requirements, incompatible
implementations, verifier bypasses, missing test cases, impractical operational
duties and changes that would make assessment more reliable. Reproducible
examples and proposed wording are especially useful.

ECL-1 supports evidence for governance and assessment. A deployment's scope,
controls and applicable legal duties still determine its compliance obligations.

## Start with your task

| Task | Where to start |
|---|---|
| Understand the control contract | [Core standard](standard/ECL-1_Standard.md) |
| Review requirements and report findings | [Reviewer guide](docs/reviewer-guide.md) |
| Verify supplied evidence or run the teaching workflow | [Start here](docs/start-here.md) |
| Examine the interfaces and their design | [Design decisions](docs/review-design-decisions.md) |
| Inspect the model assumptions and recorded checks | [Formal guide](formal/README.md) |
| Understand the review process | [Review announcement](PUBLIC-REVIEW.md) |

The package contains 628 requirement entries across 18 requirement-bearing
documents, a shared corpus of 1,416 test vectors, verifier implementations,
formal model sources and recorded results. The reference edition brings together
the source documents and formal listings. The verifier capability tables and
model bounds define what each check covers.

## Take part

Use the [public review comment form](https://github.com/G-14-Inc/ECL-1/issues/new?template=public-review-comment.yml)
and identify the document, section and requirement IDs. Cite review package
`0.9.0`, frozen at tag [`v0.9.0`](https://github.com/G-14-Inc/ECL-1/tree/v0.9.0).
Each comment receives a published disposition under the
[review procedure](governance/PUBLIC_REVIEW.md).
Without a GitHub account, send comments to [ecl@g14.ai](mailto:ecl@g14.ai),
including how you wish to be credited.

Report exploitable vulnerabilities privately through
[the security reporting process](SECURITY.md).

## Open materials and citation

Text and documentation are available under CC BY 4.0; code and machine-readable
artifacts use Apache-2.0. The [license terms](LICENSING.md),
[third-party notices](licenses/THIRD_PARTY_NOTICES.md) and
[patent pledge](PATENTS.md) state their respective scope and conditions.

Cite Robert F. Tilley Jr. and G-14, Inc., *ECL-1: External Control Layer
Standard, Version 1 — Public Review Draft*, package `0.9.0`.
The [review announcement](PUBLIC-REVIEW.md) identifies the files and archived
record. Package `0.9.0` denotes the review release; Version 1 identifies the
standard and reference edition. The declared protocol and wire versions are
listed in [the version set](release/VERSION_SET.json).

[externalcontrollayer.ai](https://externalcontrollayer.ai) provides the project
overview. This repository is the continuing home for ECL-1.
