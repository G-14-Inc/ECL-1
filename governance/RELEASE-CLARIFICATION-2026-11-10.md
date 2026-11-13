# Historical release clarification — November 10, 2026

Authors and producers: Robert F. Tilley Jr.; G-14, Inc.

This clarification accompanies the proposed public review draft. It describes
the retained records for Version 1.0 and correction release v1.0.1. It does
not replace their archives, alter their published correction ledger, record
completion of waived work, or authorize a new release.

## Correction classification and compatibility

The preserved [v1.0.1 ledger](../release/CORRECTIONS-1.0.1.json) labels its
changes `corrective and editorial`. The
[per-entry compatibility assessment](../release/COMPATIBILITY-ASSESSMENT-1.0.1-2026-11-10.json)
examines all 53 changed requirement entries against their exact before and
after text: 21 editorial changes, 19 clarifications of existing rules, and
13 normative defect repairs. Each entry identifies its source, text digests,
rationale, compatibility effect and migration or reassessment action.

The 13 repairs change required behavior, diagnostics, evidence classification,
scoring defaults or gateway consumption and recovery rules. Under the
clarified [change-control policy](CHANGE_CONTROL.md), they require behavioral
review; a repair that removes previously conforming behavior also requires
breaking-change treatment. Some resolve contradictions in the original
requirements. Those contradictions do not establish compatibility, and this
assessment does not claim that every repair breaks every previously
conforming implementation.

The November 9 exception waived specified procedural steps; it expressly
preserved compatibility obligations. It supplies no retrospective waiver of
this classification conflict. The published patch label and original bytes
remain historical facts, while this clarification supplies the missing
itemized compatibility disclosure. Future changes follow the clarified
classification, review, versioning and migration rules. No patent-pledge or
other legal effect is inferred from the patch label.

## Review and role evidence

Outside technical security review, testing of private security-reporting
channels, and assessor independence are separate activities.

| Activity or role | Retained evidence for Version 1.0 and v1.0.1 |
| --- | --- |
| Outside technical security review | Completion, reviewer identity, scope and a review evidence locator are not established by the retained release records. This does not establish that no review occurred. The recorded exceptions do not name this activity as waived. |
| External email and GitHub private-reporting tests | Waived for Version 1.0 on November 5 and for v1.0.1 on November 9, 2026; not completed before those publications. Configuration evidence does not establish successful external intake. |
| Second-person release rebuild and checklist signatures | Waived for both releases; not recorded as completed. The v1.0.1 exception also waived separate second-person corrective review and the specified discussion periods. |
| Assessment of an implementation | No assessment was listed in the implementers registry at Version 1.0 publication. Release checks, outside security review and a registry listing do not supply an implementation assessment. |
| Maintainer | G-14, Inc., as recorded in the charter and release notes. Robert F. Tilley Jr. is identified as acting for G-14, Inc. in the November 9 exception. |
| Authors and producers | Robert F. Tilley Jr. and G-14, Inc. |
| Chair | The charter assigns the maintainer responsibility to provide the chair; the individual holder for each release is not established by the retained records. |
| Editors | `community/settings.yaml` names the team `@G-14-Inc/ecl-editors`; the individuals holding the role for each release are not established by that team name. |
| Security response lead | The charter requires a named lead and `community/settings.yaml` supplies the contact `ecl@g14.ai`; an individual's appointment to the lead role is not established by those records. |
| Release manager | The individual holder for each release is not established by the retained records. Authorship and publication authority do not by themselves establish that assignment. |
| Separate release reviewer | The required second-person activities were waived and unperformed as above; no person's completion of that role is established. |

The bounded exceptions and their precedence remain in
[RELEASE_POLICY](RELEASE_POLICY.md#version-10-release-exception) and its
[v1.0.1 exception](RELEASE_POLICY.md#correction-release-exception-v101).
Missing role evidence is disclosed, not filled by inferring appointments from
authorship, contact addresses or repository access.

## Standing decisions and final artifacts

The original manifest's `authorization.authorized_on: 2026-10-16` records an
earlier standing decision to release and publish without signing. It does not
identify a separate approval of the final November 5 artifacts after later
source changes. The November 5 and November 9 process exceptions identify
their respective scope; an exception to a release step is not itself evidence
of final-artifact approval.

The retained manifests establish these file identities:

| Release | Source archive | SHA-256 |
| --- | --- | --- |
| Original Version 1.0 | `ecl-1-1.0.zip` | `94b9afe0c60f2f92c911ec6a7cb2f1681a34ee1a79bbb67f4e097632af6a9927` |
| Correction v1.0.1 | `ecl-1-1.0.1.zip` | `6929cfcd3d6333385e48d804f8e4ad2f558e190cb5b810a9d505bd999333d969` |

The v1.0.1 manifest also names source commit
`6571979ec12556fcafd8a8e0c72503c1d8521eb8`. These records are supplied with the
historical [Version 1.0 release](https://github.com/G-14-Inc/ECL-1/releases/tag/v1.0)
and [v1.0.1 release](https://github.com/G-14-Inc/ECL-1/releases/tag/v1.0.1).

A distinct public final-artifact approval record, with an approval date and
scope bound to those digests, is not established by the retained evidence.
This is a traceability limitation, not a claim that publication lacked
maintainer authorization. No approval date or human signature is invented
here. The release policy continues to require a recorded approval of the exact
artifacts for a future publication.

A file-integrity manifest identifies bytes. GitHub's immutable-release
attestation is a hosting-platform statement about release identity. Neither
is a G-14 maintainer signature or a human approval record. The historical
releases carry no separate G-14 maintainer cryptographic signature.
