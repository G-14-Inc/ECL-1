# ECL-1 Version 1 — Public Review

Robert F. Tilley Jr. and G-14, Inc. invite public review of the External Control
Layer Standard and its supporting specifications, verifiers and test corpus.

The review opened **13 November 2026 at 20:00 UTC** and closes
**11 January 2027 at 20:00 UTC**, a period of 59 full days.

## Read and review

- [Reference PDF](https://github.com/G-14-Inc/ECL-1/releases/download/v0.9.0/ECL-1-Version-1-Public-Review.pdf)
- [Source archive](https://github.com/G-14-Inc/ECL-1/releases/download/v0.9.0/ecl-1-0.9.0.zip)
- [Source manifest](https://github.com/G-14-Inc/ECL-1/releases/download/v0.9.0/ecl-1-0.9.0-manifest.json)
- [Release record and archival citation](https://github.com/G-14-Inc/ECL-1/releases/tag/v0.9.0)
- [Reviewer guide](docs/reviewer-guide.md)

The review concerns requirements, protocols, schemas, verifiers, conformance
tests, formal models, integration guidance and the usability of the documents.
Please identify the document, section and requirement IDs, explain the problem
and its consequence, and provide a reproducer or proposed change where possible.

## Draft identity

The frozen review package is **`0.9.0`**, at tag
[`v0.9.0`](https://github.com/G-14-Inc/ECL-1/tree/v0.9.0).
The standard and reference edition remain **Version 1**. The
[version set](release/VERSION_SET.json) separately identifies the protocols,
wire formats and verifier packages.

The source manifest lists the size and SHA-256 of every archived source file.
The release record identifies the published PDF, archive and manifest and
provides the archival citation. Hashes identify files and detect differences;
they do not establish technical correctness.

The package contains 628 requirement entries across 18 requirement-bearing
documents and 1,416 shared corpus vectors. Its current formal record contains
58 TLC checks and 12 Tamarin checks with their documented expected outcomes.
Those outcomes include correct-model checks, deliberate counterexamples and
reachability witnesses. The [formal guide](formal/README.md) states the bounds
and assumptions for those results.

The source-build descriptor records preparation of the frozen files. The
release record records their publication. Future edits will use subsequent
draft identifiers; the published review tag and its files remain fixed.

## Comments and participation

Submit a [public review comment](https://github.com/G-14-Inc/ECL-1/issues/new?template=public-review-comment.yml).
Use `0.9.0` as the package under review. The form applies the `public-review`
label and lets you choose your credit in the disposition log. Without a GitHub
account, email [ecl@g14.ai](mailto:ecl@g14.ai) with the same information and
your chosen credit.

Send exploitable weaknesses privately through the
[security reporting process](SECURITY.md).

Review is asynchronous. Any working sessions, agendas and participation details
will be announced publicly in advance in the repository's Announcements category
and on the ECL-1 site.

Each comment receives a written disposition under the
[public-review procedure](governance/PUBLIC_REVIEW.md). The editors will publish
the disposition log. Adoption follows that procedure's comment, appeal and
further-review requirements.

## Review schedule and repository preparation

On 14 November 2026, G-14, Inc. moved the closing date from 12 January to
**11 January 2027 at 20:00 UTC**. The opening date remains unchanged, giving
this review 59 elapsed days. This is a one-time exception to the published
procedure's 60-day window and rule against shortening a review.

The `0.9.0` package establishes the fresh public repository. It carries forward
the requirements, wire formats, verification behavior and recorded formal
outcomes of the review opened on 13 November. Package labels, publication links
and derived file digests are updated for this repository preparation; the
review period is not restarted. Historical technical disclosures and their
archived source identities remain available in the
[release clarification](governance/RELEASE-CLARIFICATION-2026-11-10.md).

Authored and produced by **Robert F. Tilley Jr. and G-14, Inc.**
Project: [externalcontrollayer.ai](https://externalcontrollayer.ai).
