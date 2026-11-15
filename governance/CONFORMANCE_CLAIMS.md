# Claiming conformance to ECL-1

This document says how an implementer claims conformance to ECL-1 and how the
claim is listed in the implementers registry, `community/implementers.yaml`.
A claim is self-declared: the implementer makes it and answers for it. The
editors check that a submission is complete and list it as "self-declared".
The maintainer certifies nothing, and a listing is not an assessment
([CHARTER](CHARTER.md), sections 12 and 14).

## What a claim states

A conformance claim follows Section 7 of the standard. Its public statement
holds at least what Section 7.7 requires (ECL1N-0078):

- the System of Interest identifier or a bounded description of it;
- the claimed conformance level;
- the claim status: full conformance, conditional conformance or
  assessment-only;
- the claim boundary class;
- the achieved independence class;
- the ECL-1 core version and the companion version set;
- the applied correction release and errata, and the immutable identity of the
  source used (for example its source-archive SHA-256), as the
  [errata policy](ERRATA.md) and release record require;
- any deployment or sector profile invoked, with its version;
- the date of the most recent assessment, affirmation or evidence refresh;
- any material deployment or evidence limitation relevant to the claim;
- any mapping packet and residual-gap statement, if the claim asserts support
  for an external framework, which it then names with the packet identifier
  and the bounded obligation slice (ECL1N-0079).

A claim at L1 through L4 uses `full-system-mediation` or
`bounded-action-class-mediation`. A component or profile implementation report
has no overall ECL conformance level. It identifies the component and version,
the applicable requirements and their results, the named capabilities and
profile versions, the evidence, and explicit limitations. It cannot be used to
omit runtime requirements from an L1–L4 claim.

A `Class A` claim discloses that the control plane uses same-operator separated
controls (ECL1N-0076). A `Class B` or `Class C` claim identifies the separately
administered trust domain, its administrators and its controls (ECL1N-0143),
and a `Class C` claim also the externally independent authority (ECL1N-0144).
The wording below is an abbreviated example. Before use, replace "the declared
SoI" with its identifier or bounded description and identify the applicable
companion version set. The complete claim also supplies the trust-domain
information required above. This example identifies the historical v1.0.1
source; it is illustrative and reports no completed assessment.

> ECL-1 Version 1.0, L2, assessment-only, bounded-action-class-mediation,
> Class B independence, evidence refreshed 2027-01-15 for the declared SoI;
> assessment in progress. Uses DCMP-2 v2.0 / EBMP-2 v2.0, correction release
> v1.0.1 and ERR-1.0-001; source archive ecl-1-1.0.1.zip, SHA-256
> 6929cfcd3d6333385e48d804f8e4ad2f558e190cb5b810a9d505bd999333d969;
> production-equivalent=false.

An implementer may also publish the claim as a claim document that satisfies
`schemas/ecl-conformance-claim-v1.schema.json`
([CONFORMANCE-CLAIMS-1](../profiles/CONFORMANCE-CLAIMS-1.md)).

## The conformance report

A claim is listed with its conformance report: one document, published at a
stable `https` address, that gives two results, or links to them with the
SHA-256 digest of each file it links:

- **The conformance tests' results.** The implementer runs the conformance
  tests of the version it claims against its implementation, for the
  capabilities that the implementation declares
  ([the conformance tests](../conformance/README.md)), and records the result
  of every vector in a report that follows the conformance report template in
  `conformance/` and its schema in `schemas/`, bound to the digest of the
  shared corpus's exact index (`conformance/shared-corpus.json`).
- **The offline verifier's output on its evidence.** The implementer runs the
  offline verifier on evidence bundles that its implementation produced and
  publishes the verifier's output with the bundles or their digests. The
  verifier may be the [browser verifier](../web/verifier/README.md),
  `ecl-verify-ts` ([TypeScript](../packages/ecl-ts/README.md)), the
  [Go verifier](../go/crosscheck/README.md), or another implementation of
  `evidence-bundle-verification` (and `offline-package-verification` when
  packages are submitted). It uses the caller's trust policy, never a policy
  taken from the evidence. These are capability criteria, not a restriction
  to a programming language or user interface.

## How to be listed

1. Prepare the claim statement and the conformance report as above.
2. Open a pull request that adds one entry to `community/implementers.yaml`,
   in the format below, with `status` set to "self-declared". Every commit
   carries a sign-off ([CONTRIBUTING](CONTRIBUTING.md)). The pull request
   gives the SHA-256 digest of the conformance report, and states any
   relationship of the implementer with G-14, Inc. The editors fill in
   `listed` when they merge it.
3. Within 30 days, the editors check that the submission is complete:
   - the entry has every required field and satisfies the registry's schema,
     `community/implementers.schema.json`;
   - the claim states each element of Section 7.7, and names the version, the
     level and the claim boundary, identifies its applied correction release,
     errata and immutable source, and its level is the entry's `level`;
   - the conformance report can be fetched and matches the digest that the
     pull request gives;
   - the report covers the version claimed, gives a result for every vector
     of the capabilities it declares, and holds the verifier's output for the
     evidence it names.

   The editors do not check that the claim is true. They do not run or assess
   the implementation.
4. When the submission is complete, the editors merge it, and the entry is
   listed as "self-declared". When something is missing, they say what in the
   pull request. The pull request stays as the record of what was checked.

## Assessments

When the implementer provides an assessment of its claim by an assessor, the
entry lists it separately, as a link in its `assessment` field to the
assessment record. The pull request that adds the link gives the record's
SHA-256 digest, and the editors check that the record can be fetched and
matches it. A listed assessment remains the assessor's statement. It does not
make the claim certified, and the registry does not endorse the assessor
([ASSESSOR_INDEPENDENCE](ASSESSOR_INDEPENDENCE.md)).

## The maintainer's implementation

A claim for an implementation of G-14, Inc. is listed on the same terms as
any other. Its entry names G-14, Inc. as the organization, its pull request
states that G-14, Inc. maintains ECL-1 and provides its editors, and an editor
who did not prepare the submission checks it.

## Keeping a listing current

- The implementer updates its entry, by pull request, when its claim changes
  and after every reassessment that ECL1N-0152 requires.
- The editors may ask the implementer to refresh an entry whose claim date is
  older than the assessment interval that Section 7.8 sets for its level.
- An erratum that corrects a conformance defect names the listings it may
  affect ([ERRATA](ERRATA.md)), and their implementers review their claims.
- A listing names the version it claims. When a new version is published, the
  listing stays, for the version it names.

## Removal

- An implementer may remove its entry at any time, by pull request or issue.
- The editors remove an entry that is shown to be incomplete or misleading:
  when its conformance report can no longer be fetched or no longer matches
  its digest, when its claim lacks an element that Section 7.7 requires, when
  a refresh that the editors asked for has not come within 60 days, or when
  the claim or the listing is used to imply certification or endorsement. The
  editors first ask the implementer, in an issue, to correct the entry within
  30 days.
- A removal is recorded, with its reason, in the pull request that makes it,
  and it can be appealed under [APPEALS](APPEALS.md).

## What a listing means

A listing means that the editors found the submission complete when they
checked it. It does not mean that the claim is true or that the implementation
conforms, and it does not mean that G-14 or the working group certified,
assessed or endorsed anything, or that anything is safe or legally compliant
([TRADEMARKS_AND_MARKS](TRADEMARKS_AND_MARKS.md)).

## Entry format

`community/implementers.yaml` is a YAML file, and
`community/implementers.schema.json` is its schema. Each entry has these
fields, and only these:

| Field | What it holds |
| --- | --- |
| `name` | The implementation's name, with its version |
| `organization` | The organization, or the person, that makes the claim |
| `url` | The implementation's page |
| `claim` | The claim's public statement, as Section 7.7 requires it |
| `level` | The claimed level: `L1`, `L2`, `L3` or `L4` |
| `status` | Always `self-declared`; the claim status of Section 7.6 is part of the claim |
| `listed` | The date on which the editors listed the claim |
| `report` | The link to the conformance report |
| `assessment` | Optional: the link to an assessor's assessment record |

Write every value in double quotes, so that dates and levels stay strings.
This abbreviated structural example uses placeholder organizations, URLs,
dates and a claim statement that needs the SoI and companion-version details
described above:

```yaml
implementers:
  - name: "Example Gateway 2.3.1"
    organization: "Example Corp."
    url: "https://example.com/gateway"
    claim: "ECL-1 Version 1.0, L2, assessment-only, bounded-action-class-mediation, Class B independence, evidence refreshed 2027-01-15 for the declared SoI; assessment in progress. Uses DCMP-2 v2.0 / EBMP-2 v2.0, correction release v1.0.1 and ERR-1.0-001; source archive ecl-1-1.0.1.zip, SHA-256 6929cfcd3d6333385e48d804f8e4ad2f558e190cb5b810a9d505bd999333d969; production-equivalent=false."
    level: "L2"
    status: "self-declared"
    listed: "2027-01-27"
    report: "https://example.com/gateway/ecl-1/conformance-report.json"
```
