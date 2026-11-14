# ECL-1 Version 1 — Public Review

Robert F. Tilley Jr. and G-14, Inc. invite public review of the External Control
Layer Standard and its supporting specifications, verifiers and test corpus.

The review opens **13 November 2026, 20:00:00 UTC** and closes **11 January 2027, 20:00:00 UTC**,
a period of 59 full days. The draft is frozen throughout that period.

## Read and review

- [Reference PDF](https://github.com/G-14-Inc/ECL-1/releases/download/v1.0.2-review.1/ECL-1-Version-1-Public-Review.pdf)
- [Source archive and manifest](https://github.com/G-14-Inc/ECL-1/releases/tag/v1.0.2-review.1)
- [Permanent archived record](https://doi.org/10.5281/zenodo.24203567)
- [Reviewer guide](https://github.com/G-14-Inc/ECL-1/blob/v1.0.2-review.1/docs/reviewer-guide.md)
- [Changes since the earlier publications](https://github.com/G-14-Inc/ECL-1/blob/main/release/PUBLIC-REVIEW-CHANGES.md)

The review concerns requirements, protocols, schemas, verifiers, conformance
tests, formal models, integration guidance and the usability of the documents.
Please identify the document, section and requirement IDs, explain the problem
and its consequence, and provide a reproducer or proposed change where possible.

## Frozen draft identity

| Field | Value |
|---|---|
| Designation | ECL-1 Version 1 public review |
| Reference edition | Version 1 |
| Source build | `1.0.2-review.1` |
| Tag | [`v1.0.2-review.1`](https://github.com/G-14-Inc/ECL-1/tree/v1.0.2-review.1) |
| Commit | `ccdfe23e65ec0589798208b1bbc5501f3f0538d2` |
| Version set | [`release/VERSION_SET.json`](https://github.com/G-14-Inc/ECL-1/blob/v1.0.2-review.1/release/VERSION_SET.json) |
| Version-set SHA-256 | `af0063a7dcb44a88edf6daae8d8dadc15f53a331a7d6decda3147043636a9ae7` |
| Source-tree SHA-256 | `cc3171c3a84a718c4a2f97667d50b52031063f5dbfe43485747cfa85c63c46b2` |
| Manifest | `ecl-1-1.0.2-review.1-manifest.json` |
| Manifest SHA-256 | `49a6a7aacacb9865265a0761ee35f2627261e4f00b7a728bca70ab30f357d6e5` |
| Review issue label | `public-review` |
| Opens, UTC | `2026-11-13T20:00:00Z` |
| Closes, UTC | `2027-01-11T20:00:00Z` |

The frozen files record their preparation as a local candidate. This
announcement opens public review of those exact files. The reference edition
retains Version 1; the source-build identifier distinguishes this draft.

The package contains 628 requirement entries across 18 requirement-bearing
documents and 1,416 shared corpus vectors. Its current formal record contains
58 TLC checks and 12 Tamarin checks with their documented expected outcomes.
Those outcomes include correct-model checks, deliberate counterexamples and
reachability witnesses. The [formal guide](https://github.com/G-14-Inc/ECL-1/blob/v1.0.2-review.1/formal/README.md)
states the bounds and assumptions for those recorded results.

## Comments and participation

Submit a [Public review comment](https://github.com/G-14-Inc/ECL-1/issues/new?template=public-review-comment.yml).
Use `1.0.2-review.1` as the version under review. The form applies the
`public-review` label and lets you choose your credit in the disposition log.
Without a GitHub account, email [ecl@g14.ai](mailto:ecl@g14.ai) with the same
information and your chosen credit.

Send exploitable weaknesses privately through the
[security reporting process](https://github.com/G-14-Inc/ECL-1/blob/v1.0.2-review.1/SECURITY.md).

Review is asynchronous. No working sessions are scheduled at opening.
Any sessions, agendas and participation details will be announced publicly
in advance in the repository's Announcements category and on the ECL-1 site.

Each comment receives a written disposition under the
[public-review procedure](https://github.com/G-14-Inc/ECL-1/blob/v1.0.2-review.1/governance/PUBLIC_REVIEW.md).
The editors will publish the disposition log. Changes are made in a subsequent
editors' draft, preserving this frozen review. Adoption follows the procedure's
comment, appeal and further-review requirements.

## Review schedule amendment

On 14 November 2026, G-14, Inc. moved the closing date from 12 January to
**11 January 2027, 20:00 UTC**. The opening date remains 13 November 2026,
20:00 UTC, giving this review 59 elapsed days. This is a one-time exception to
the published procedure's 60-day window and rule against shortening a review.
The frozen draft and all other review procedures remain unchanged.

## File integrity

| File | Bytes | SHA-256 |
|---|---:|---|
| `ECL-1-Version-1-Public-Review.pdf` | 30,896,084 | `154fd36ae11f592fadcbf30ec4e6ec463a32fb9fca3d43ac56a67f45d3dddbbc` |
| `ecl-1-1.0.2-review.1.zip` | 14,400,174 | `a530b255195e744f8500d1cc8c3b70f7e0044b16258e29b5902a6a6a88cc112e` |
| `ecl-1-1.0.2-review.1-manifest.json` | 896,514 | `49a6a7aacacb9865265a0761ee35f2627261e4f00b7a728bca70ab30f357d6e5` |

The manifest lists the size and SHA-256 of every source file. Hashes identify
the files and detect differences; they do not establish technical correctness.

Authored and produced by **Robert F. Tilley Jr. and G-14, Inc.**
Project: [externalcontrollayer.ai](https://externalcontrollayer.ai).
