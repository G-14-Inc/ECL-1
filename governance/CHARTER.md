# ECL-1 Working Group charter

This charter says how ECL-1 is maintained and developed: who may take part,
who decides and how, and what the maintainer may and may not do. It is in
effect from the publication of ECL-1 Version 1.0.

## 1. Name and maintainer

ECL-1, the External Control Layer Standard, is maintained by G-14, Inc. ("the
maintainer") and developed in the open by the ECL-1 Working Group ("the
working group"), which this charter establishes. The standard is cited as
"ECL-1" or "ECL-1 Version 1.0", never "ECL-1.0"
([TRADEMARKS_AND_MARKS](TRADEMARKS_AND_MARKS.md)).

## 2. Purpose

The working group maintains ECL-1 so that every consequential action an AI
system takes can be controlled from outside that system, and so that the
control can be checked by a party that does not have to trust the system or
its operator.

## 3. Scope: the guarantee

The normative work of ECL-1 is limited to one guarantee and what an
implementation needs to provide and demonstrate it:

1. Every in-scope consequential action crosses an enforcement boundary that the
   governed AI system cannot bypass, under a decision that the governed AI
   system cannot change.
2. Any failure that leaves an action without required proof, including missing
   proof, an integrity failure, an ambiguous policy or an unavailable decision
   service, ends in denial, restricted mode or halt. It never ends in the
   action going ahead.
3. Each decision leaves tamper-evident evidence that a third party can check
   and, from `L2`, verify offline.
4. Inputs that are judgments (the output of a probabilistic model or a
   heuristic detector about meaning or risk), or that the governed AI system
   controls as assertions, may make a decision stricter but are never the
   reason an action is admitted. An admission rests on policy evaluated over
   `verifiable` inputs whose authority the governed system cannot alter or
   bypass. An admitted action may cause a state transition that this authority
   independently validates; storing or signing the system's own assertion
   alone supplies no independent authority (core Section 4.3).

Within that scope ECL-1 specifies the decision and evidence protocols, the
integrity envelope, timing and safe-state behavior, conformance claims and
levels, independence classes, assessment rules, the agent and tool integration
contract, and the binding profiles through which other tools connect to it.

## 4. Out of scope

ECL-1 does not standardize, and does not require:

- judging what an action means: intent alignment, semantic drift, anomaly and
  risk scoring. These are inputs to an ECL decision (for example the AARM
  requirements R2, R3 and R7), which may only make it stricter;
- model quality, conversation analytics, or the functions of a security
  information and event management system. ECL evidence is exported to these;
- containment substrates such as sandboxes, guardian or policy agents, and
  policy engines. These may be the source of a decision or an enforcement
  point, under ECL-1's rules;
- organizational governance systems, legal compliance interpretation and
  sector safety certification (ECL-1, Sections 2.7 and 2.10).

A proposal outside this scope is declined with an `out-of-scope` disposition
that names where the topic belongs.

## 5. What ECL-1 is, and what it is not

| Part | What it is |
|---|---|
| The core standard, its companion protocols and profiles, and the binding profiles | Normative |
| Schemas, registries and the requirement ledger | Normative machine-readable artifacts |
| The conformance tests with their expected results, the incident replay suite, the assessment procedures and checklist, and sample evidence | Test and assessment material |
| The agent and tool integration contract and the guides | Informative guidance |
| The offline verifier, for the browser and the command line | Informative tool |
| The implementers registry | A list of self-declared conformance claims; it certifies nothing |
| Errata, change records, public review dispositions and the notes of the working sessions | Records, published with each version or as they are made |

No implementation is normative or privileged, the maintainer's included, and
no requirement may depend on a product or service of G-14 or of anyone else.

## 6. Taking part

The working group is open to anyone, and taking part is free. A person joins
by signing up with a GitHub account, through the sign-up form on the ECL-1
site or the "ECL-1 Working Group sign-up" issue form of the public repository
([WORKING_GROUP](../community/WORKING_GROUP.md)). There is no
membership agreement and no fee. The only terms are the contribution terms of
[CONTRIBUTING](CONTRIBUTING.md), and they apply to what a participant
contributes.

Participants take part as individuals and state their affiliation, if they
have one, when they sign up. A participant may leave at any time, by saying so
in the sign-up issue or by writing to the working group's contact address.

The working group works in the open: in the issues, pull requests and
discussions of the public repository, and in public working sessions. Anyone
may read all of it, and anyone may open an issue or comment, whether or not
they have signed up. The editors weigh every comment made in these channels.

## 7. Roles

- **Maintainer:** G-14, Inc. It hosts the public repository, provides the
  editors and the chair, runs the public reviews, and publishes the releases
  and the errata. It holds the namespaces and the domain of ECL-1's
  identifiers ([REGISTRY_POLICY](REGISTRY_POLICY.md)), and it names the
  security response lead ([SECURITY](SECURITY.md)) and the release manager and
  release reviewer ([RELEASE_POLICY](RELEASE_POLICY.md)).
- **Chair:** provided by the maintainer. The chair convenes and runs the
  working sessions, publishes their schedule, agendas and notes, keeps the
  decision process of section 8, and hears appeals
  ([APPEALS](APPEALS.md)).
- **Editors:** provided by the maintainer. The editors maintain the single
  normative source and the artifacts generated from it, the registries and
  the requirement ledger; triage issues and pull requests; propose
  resolutions; decide by rough consensus and record the reason; prepare
  review drafts, releases, errata and disposition logs; and check the
  submissions to the implementers registry
  ([CONFORMANCE_CLAIMS](CONFORMANCE_CLAIMS.md)). An editor is never the second
  reviewer of the editor's own change.
- **Participants:** everyone who has signed up. Participants raise issues,
  discuss proposals, review drafts, contribute pull requests and take part in
  the working sessions and the public reviews.

Each published version records the people who held the roles for it. One
person may hold several roles, but may not satisfy alone a required
two-person, independence, appeal or conflict-review separation.

## 8. How decisions are made

- **The editors propose.** A proposal is an issue or a pull request that
  states the change, its change class ([CHANGE_CONTROL](CHANGE_CONTROL.md))
  and the editors' proposed resolution. Anyone may raise a problem or propose
  a change; the editors take it up as a proposal or answer it with a reason.
- **The working group discusses.** Discussion takes place in the issue or the
  pull request, in the repository's discussions and in the working sessions.
  A proposal stays open for discussion for at least the period that its change
  class requires. A conclusion reached in a session is written in the issue
  and stays open there for at least seven days, so that those who could not
  attend can answer.
- **The editors decide by rough consensus and record the reason.** Rough
  consensus means that the editors have considered every objection raised and
  that each one was either addressed or answered with a reason. It does not
  need every participant to agree, and it is not a vote. The editors write
  the decision and its reason in the issue or the pull request before they
  merge or close it.
- **Appeals** go to the chair, then to a public issue
  ([APPEALS](APPEALS.md)).
- **The maintainer may not overrule a recorded consensus**, except for a
  legal or a security reason, which it states in writing in the issue
  concerned. When the security reason is under embargo, the written statement
  is published when the embargo ends ([SECURITY](SECURITY.md)).
- A person with a material conflict on a question discloses it, and does not
  serve as the only reviewer of that question.

The maintainer, the chair and the editors may not, through this charter or any
decision under it:

- claim statutory, regulatory or accreditation authority;
- certify a system, or attest anyone's conformance;
- treat an implementation, the maintainer's own included, or the output of a
  model as normative;
- waive a requirement of ECL-1 through undocumented discretion;
- use the name ECL-1 to imply certification, safety or legal compliance.

## 9. Decision records

Normative, behavioral, registry, release and conformance decisions each have a
durable record, in the issue or the pull request concerned, that holds:

- the decision identifier, date, change class and affected versions;
- the proposal and the alternatives considered;
- the normative requirements and artifacts affected;
- the compatibility and security impact;
- the objections raised and how each was answered;
- the decision, its reason and who made it;
- the required migrations, deprecations, vectors and errata;
- the release in which it takes effect.

Private security detail may stay embargoed, but the record states in the end
the affected versions, the disposition and the reason for the embargo.

## 10. Working sessions

The working group meets in public working sessions. The chair publishes the
schedule on the ECL-1 site and in the repository's discussions, posts the
agenda at least seven days before each session and publishes the notes within
seven days after it. Anyone may attend. The notes record the topics, the views
expressed, the proposals made and the actions agreed, and they name the
attendees who agree to be named. A session decides nothing on its own: each
conclusion is confirmed in its issue (section 8).

## 11. Public review

Each new minor or major version of ECL-1 has a public review window before it
is published: 30 days for a minor version and 60 days for a major version.
The maintainer announces each window on the ECL-1 site. Comments are GitHub
issues in the public repository, and every comment gets a published
disposition ([PUBLIC_REVIEW](PUBLIC_REVIEW.md)). Errata and patch versions
follow the change process ([CHANGE_CONTROL](CHANGE_CONTROL.md),
[ERRATA](ERRATA.md)).

## 12. Interests

G-14, Inc. maintains ECL-1, provides its editors and its chair, and is developing a
commercial platform that implements ECL-1. That platform is not part of ECL-1 and has no
standing in it. Whether it meets a requirement is shown the same way as for
any implementation, a result of G-14's own tests is labelled as G-14's, and a
claim for it is listed in the implementers registry only as a self-declared
claim on the same terms as any other ([CONFORMANCE_CLAIMS](CONFORMANCE_CLAIMS.md)).

Participants state their affiliation when they sign up, and disclose a
material interest in a question in which they take part, such as an
implementation that they build or sell.

## 13. Intellectual property

- **Licenses.** The text and documentation of ECL-1 are licensed under
  CC BY 4.0, and its machine-readable artifacts and code under Apache-2.0
  ([LICENSING](../LICENSING.md)).
- **Patents.** G-14, Inc. pledges not to assert its Essential Claims against
  implementations of ECL-1 Version 1.0 and its companion specifications, to
  the extent that they conform to their normative requirements
  ([PATENTS](../PATENTS.md)). The texts say "patents pending", never
  "patented".
- **Contributions.** Contributions are made through issues, discussions and
  pull requests on the public repository. Every commit carries a Developer
  Certificate of Origin sign-off; inbound terms equal outbound terms; each
  contributor makes the same patent pledge for its contributions; there is no
  contributor license agreement ([CONTRIBUTING](CONTRIBUTING.md)).
- **Copyright.** Each contributor keeps the copyright in its contributions and
  licenses them under the licenses above. G-14, Inc. holds the copyright in
  its own.

## 14. Conformance claims, names and marks

- Conformance is self-declared. An implementer publishes its claim with its
  conformance report and asks to be listed in the implementers registry; the
  editors check that the submission is complete and list it as
  "self-declared". The maintainer certifies nothing. An assessor's assessment
  is listed separately when the implementer provides it
  ([CONFORMANCE_CLAIMS](CONFORMANCE_CLAIMS.md),
  [ASSESSOR_INDEPENDENCE](ASSESSOR_INDEPENDENCE.md)).
- "ECL-1" may be used descriptively. A conformance claim names the version,
  the level and the claim boundary, as Section 7.7 of the standard requires
  ([TRADEMARKS_AND_MARKS](TRADEMARKS_AND_MARKS.md)).

## 15. Transparency and limitations

Each published version includes its change record, its registry changes, its
known limitations and what it does not claim, the status of the outside
security review, its assessor-independence status and its exact release
manifest, and keeps its open issues (`standard/ISSUES.md`) and errata index
current. Non-public deliberation is allowed only for security, privacy, legal
or personnel reasons, and is recorded with a bounded rationale. Every version
states at least these limitations:

- a verified evidence bundle shows what its producer signed and that it has
  not changed since, under the verifier's trust policy; it does not show that
  its statements are true, and an effect counts as corroborated only when a
  separately keyed party confirms it;
- "every path" in a claim means every path within the claim's declared and
  assessed boundary, not every path that could exist;
- a listing in the implementers registry is self-declared, and an assessment
  is independent only as [ASSESSOR_INDEPENDENCE](ASSESSOR_INDEPENDENCE.md)
  defines it.

## 16. Changing this charter

A change to this charter is proposed as a pull request and announced on the
ECL-1 site. It stays open for discussion for at least 30 days, and the editors
decide it by rough consensus, recording the reason, as section 8 describes. A
change to the scope in sections 3 and 4 is also a behavioral change under
[CHANGE_CONTROL](CHANGE_CONTROL.md). The maintainer may not use a change to
this charter to overrule a recorded consensus, and no change rewrites the rules
or the evidence of an earlier release.
