# ECL-1 public review

This document says how a public review of a new version of ECL-1 runs: when
one is held and for how long, how it is announced, where comments go, how
every comment gets a published disposition, how changes are versioned, and how
the dispositions are published. It applies to the standard, its companion
protocols and profiles, and the conformance and replay suites published with
them. The maintainer, G-14, Inc., runs each review; the editors write the
dispositions, deciding by rough consensus; the chair hears appeals
([CHARTER](CHARTER.md)).

## When a public review is held

- Each new minor version (for example 1.1) and each new major version (for
  example 2.0) has a public review window before it is published. The window
  lasts 30 days for a minor version and 60 days for a major version, counted
  from the day of the announcement. The maintainer may extend a window; it
  never shortens one.
- Errata and patch versions follow the change process
  ([CHANGE_CONTROL](CHANGE_CONTROL.md), [ERRATA](ERRATA.md)) and have no
  review window.
- This procedure applies from Version 1.0 on. Comments on a published version
  are welcome at any time as issues. They are answered under the change
  process, and a comment that leads to a change is carried into an erratum or
  into the next version.

## The review draft

- The review draft is frozen for the whole window. It is published in the
  public repository at a tag that the announcement names, with its manifest.
  Its designation, its version set (`release/VERSION_SET.json`) and the
  SHA-256 digest of its manifest are stated in the announcement, and every
  comment refers to that exact draft.
- The editors may correct a defect in the draft's packaging during the window
  only by publishing a new digest and extending the window so that at least
  half of its length remains after the correction: 15 days for a minor
  version and 30 days for a major version.

## The announcement

The maintainer announces each window on the ECL-1 site and in the
"Announcements" category of the repository's discussions. The announcement
states the draft's designation, version, tag and manifest digest; the opening
and closing dates; the label that the review's issues carry; the changes since
the previous version, with the draft's change log; and the working sessions
held during the window ([WORKING_GROUP](../community/WORKING_GROUP.md)).

## Where comments go

- A comment is a GitHub issue in the public repository, opened with the
  "Public review comment" issue form, which labels it for the review. A person
  without a GitHub account may send the comment to the working group's contact
  address, and an editor files it as an issue for them, with the credit they
  chose.
- A comment that describes an exploitable weakness goes privately to the
  security contact under [SECURITY](SECURITY.md). It receives a disposition in
  the same log, with its detail withheld until disclosure is allowed.
- A comment should name the document, the section and the requirement IDs it
  concerns, describe the problem, and propose a change where it can.
- Each commenter chooses how the disposition log credits them: by name, by
  organization only, or not at all. The log records only what the commenter
  chose; the issue itself shows the GitHub account that opened it.
- A comment that proposes text is a contribution and follows
  [CONTRIBUTING](CONTRIBUTING.md); a pull request with a sign-off is the
  clearest way to make one.

The log records each comment's channel as one of these values:

| Channel | Meaning |
|---|---|
| `public` | A GitHub issue in the public repository, or a comment that an editor filed as one |
| `private-security` | To the security contact |

## Dispositions

Every comment receives a written disposition. No comment is closed without
one, and no review draft becomes a release while a comment lacks one. Each
disposition has exactly one category:

| Category | Meaning | What the response must contain |
|---|---|---|
| `accepted` | The change is made as proposed. | The change made and where |
| `accepted-with-modification` | The problem is accepted and fixed in a different way. | The change made and why it differs from the proposal |
| `declined` | No change is made. | The reason |
| `deferred` | The comment is valid and will be addressed in a later version. | The version and the reason for deferring |
| `out-of-scope` | The comment concerns something ECL-1 leaves to other tools or documents. | Where the topic belongs |
| `duplicate` | The comment repeats another comment. | The comment whose disposition applies |
| `noted` | The comment gives information or support and asks for no change. | A short acknowledgment |
| `withdrawn` | The commenter withdrew the comment before a decision. | The date of withdrawal |

A disposition also records its change class, using the classes of
[CHANGE_CONTROL](CHANGE_CONTROL.md) (`editorial`, `corrective`, `additive`,
`behavioral` or `breaking`), whenever it changes the text; when it was decided;
and who decided it, as one of these values:

| Decided by | Meaning |
|---|---|
| `editors` | The editors, by rough consensus of the working group, with the reason recorded |
| `chair` | The chair, on an appeal under [APPEALS](APPEALS.md) |
| `maintainer` | G-14, Inc., as maintainer, overruling a recorded consensus for a legal or a security reason that it states in writing ([CHARTER](CHARTER.md), section 8) |

The editors publish each disposition as a reply in the comment's issue, and
label the issue with its category, before they close it. The commenter may say
whether they accept the disposition, and may appeal it under
[APPEALS](APPEALS.md). An appeal does not reopen the window.

The disposition log is a JSON document that satisfies
`schemas/ecl-review-disposition-log-v1.schema.json`; start from
[review-disposition-log-template.json](review-disposition-log-template.json).
The schema enforces the tables: an accepted comment names its changes and
change class, a deferred one names its target version, a duplicate names its
original, a comment that changes nothing names no change, and a record holds
only the credit that the commenter chose.

## Versioning the changes

- Changes are made in the editors' draft after the window closes, never in the
  frozen review draft.
- Every changed requirement is recorded in the change log, and the
  requirement ledger keeps every identifier: an identifier is never reused,
  and a removed requirement is retired, not deleted
  ([REGISTRY_POLICY](REGISTRY_POLICY.md)).
- A companion protocol or profile whose obligations change gets a new version
  in the version set, as the versioning policy requires.
- If the dispositions lead to a `behavioral` or `breaking` change, the changed
  text goes to a further public review limited to those changes: at least 15
  days for a minor version and at least 30 days for a major version.
  Editorial, corrective and additive changes do not need one.

## Publishing the dispositions

- Each disposition is public in its issue as soon as it is decided.
- The complete disposition log of a review is published in the repository
  with the version that the review concerned, and no later than that
  version's release.
- The log lists every comment received in the window, including withdrawn and
  duplicate ones, with its disposition and the change it led to.
- The release notes state the number of comments in each category and link
  the log.
- Withheld security detail is published when the disclosure process in
  [SECURITY](SECURITY.md) allows it; the log records the withholding until
  then.

## Ending the review

A review ends when every comment has a disposition, every appeal is closed,
the log is complete, no finding classed as critical remains open, and any
further review that behavioral or breaking changes required has closed. The
release record states the status of the outside security review separately;
the end of a review does not imply it.
