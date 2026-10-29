# Contributing to ECL-1

ECL-1 is maintained by G-14, Inc. and developed in the open by the ECL-1
Working Group ([CHARTER](CHARTER.md)). Anyone may contribute, through issues,
discussions and pull requests on the public repository. This document gives
the terms of every contribution and what a contribution needs.

## How to contribute

- **Raise a problem or propose a change:** open an issue with one of the
  repository's issue forms ("Propose a change", "Report an erratum", "Public
  review comment"), or start a discussion. The editors answer every issue.
- **Change the text, a schema, a vector or the code:** open a pull request.
  The pull request template asks for what the change needs (below).
- **Report a vulnerability:** privately, as [SECURITY](SECURITY.md) says,
  never in a public issue.
- **Be listed in the implementers registry:** open a pull request that adds an
  entry, as [CONFORMANCE_CLAIMS](CONFORMANCE_CLAIMS.md) says.
- **Join the working group:** see
  [WORKING_GROUP](../community/WORKING_GROUP.md). Joining is free, and it is
  not needed to contribute.

## The terms of a contribution

- **Developer Certificate of Origin.** Every commit carries a sign-off: a line
  at the end of the commit message, with the contributor's own name and an
  address at which they can be reached, by which the contributor certifies
  the statements of the Developer Certificate of Origin 1.1. [DCO.txt](DCO.txt)
  reproduces the certificate verbatim.

  ```text
  Signed-off-by: Contributor Name <contributor@example.org>
  ```

  `git commit -s` adds the line. A pull request whose commits do not all carry
  a valid sign-off is not merged.
- **Inbound terms equal outbound terms.** A contribution is licensed under the
  license of the files it changes: the Creative Commons Attribution 4.0
  International license for text and documentation, and the Apache License,
  Version 2.0 for code and machine-readable artifacts
  ([LICENSING](../LICENSING.md), [LICENSE-MATRIX](../licenses/LICENSE-MATRIX.md)).
  A new file takes the license of its class. The contributor keeps the
  copyright in the contribution.
- **The patent pledge.** By contributing, the contributor makes for its
  contributions the same patent pledge that G-14, Inc. makes for ECL-1
  ([PATENTS](../PATENTS.md), section 7).
- **No contributor license agreement.** There is nothing else to sign.

A person who contributes for an employer or another organization makes sure
that they may: the sign-off certifies that the contributor has the right to
submit the work under these terms.

Text proposed in an issue or a discussion carries no sign-off. Before the
editors carry such text into ECL-1, its author confirms in the issue that it
is offered under these terms (the issue forms have a box for this), or the
editors write the change in their own words; the pull request that carries it
credits the author.

## What a contribution needs

A contribution must:

- identify its author and the source of the work;
- disclose third-party text, code, data or vectors and their licenses, and any
  patent that the contributor knows to be implicated;
- declare the normative requirements it affects, its change class
  ([CHANGE_CONTROL](CHANGE_CONTROL.md)) and its compatibility;
- include tests and evidence appropriate to its change class;
- contain no secrets, customer data, credentials, or embargoed vulnerability
  details;
- accept review, revision, and recorded rejection under the change process.

## Normative changes

A normative proposal includes a problem statement, the exact text,
alternatives, security and interoperability analysis, migration, conformance
impact, and positive and negative vectors. Generated files are updated through
their recorded generator, not hand-edited as a substitute for source changes.
Use `python scripts/check_public.py` from the public package root, after the
quickstart's installation, for the public verifier and teaching-example checks.
It runs without the maintainer's private platform. If a recorded generator is
not in the public package, submit the source change and expected results; an
editor regenerates the artifacts and attaches the resulting diff and check
receipts for review before merge. Access to private tooling is not required
to propose or review that source change.

## Review and decisions

Authors do not satisfy the required independent or two-person review
themselves. Review focuses on semantics and evidence, not only style. The
editors decide by rough consensus of the working group and record the reason
in the pull request ([CHARTER](CHARTER.md), section 8); a decision can be
appealed under [APPEALS](APPEALS.md).

## Provenance

Every change keeps durable authorship and review records. Squash,
formatting, or generation cannot erase required third-party notices or change
who wrote a contribution.

## Conduct

The [participation code](CODE_OF_CONDUCT.md) applies in every space of the
working group.
