# ECL-1 normative issues

This index preserves the questions and their dispositions. Issues 001 and 002
were resolved earlier. Issues 003 through 007 are resolved in this candidate's
requirements and assessment procedures as recorded below. A disposition is not
publication authorization, an outside assessment or a legal opinion.
Public comments and errata remain open under the governance process.

## ECL-ISSUE-001: Class B, "and" versus "or"

Status: **resolved: conjunctive.**

The Class B definition in Section 4.5 required control approval **and** evidence
verification in a separately administered trust domain; the Section 5.8 summary
said **or**. The conjunctive reading was adopted: both control approval and
evidence verification occur in a separately administered trust domain that the
governed AI system and its ordinary operators cannot unilaterally modify. Class C
builds on Class B: every Class B condition holds, and both functions are held by
an externally independent trust domain or authority.

Sections 4.5 and 5.8 now state the same rule; ECL1N-0142 to ECL1N-0144 and
checklist items IA-08 and IA-09 make it testable, and `L2` and `L3` claims, which
require Class B, can be made.

## ECL-ISSUE-002: Restricted mode for one action class's missing proof

Status: **resolved in the text of Version 1.0 by ECL1N-0191 to ECL1N-0193.**

The table of ECL1N-0146 (Section 8.8) gives "proof missing" as a trigger for
restricted mode. The text did not say whether a missing proof that one action
class requires places the whole deployment in restricted mode or only that
class, while the safe-state profile schema declares dispositions for each
action class, and `docs/availability.md` left the question to the assessor, so
that two assessors could reach different scopes for the same fault.

The text now distinguishes an action-class restriction from a deployment-wide
state (Section 4.2, Restricted Mode; Section 8.8). Under the claim's declared
dependency model (ECL1N-0192), a loss of required proof that only one action
class needs restricts that class, and the other classes continue only with
their own required proof and controls intact; the failure of a dependency that
several classes require restricts every class that requires it, directly or
through other dependencies; a critical integrity failure or an emergency control
activation brings the state that ECL1N-0146 gives it for the whole deployment,
which no action-class scope or local exception overrides; and a loss whose
scope cannot be established restricts the enclosing scope that the dependency
model declares, or the whole deployment where it declares none (ECL1N-0191). A
restriction ends only when required proof is obtained again after the fault and
the authorization that the mode definitions declare for lifting it is recorded,
and a deployment-wide state brought by an integrity failure or an emergency
activation ends only by a recorded control action (ECL1N-0193). Required proof
is never relabeled as advisory to keep a class outside the scope. Checklist
item EA-29 tests the rule. The availability guide, TIMING-SAFE-STATE-1 and
STRICT-FAILURE-1 state it in the same terms.

## ECL-ISSUE-003: A verifiable input and an input the actor can influence

Status: **resolved in the candidate requirements and assessment procedure.**

Resolution: Section 4.3 and ECL1N-0178 distinguish actor-controlled
assertions and bypassable validation from an independently validated state
transition. An admitted action can affect a provider balance or sensor without
making the authoritative observation actor-supplied. Source signatures do not
launder assertions; freshness, selection and completeness remain explicit.
EA-21 and the input cases in `docs/decision-examples.md` guide assessment.

Original question and requested scope (preserved for review):

The definition of a verifiable input (Section 4.3) and the one-way rule
(ECL1N-0178 to ECL1N-0182) keep an actor from turning its own assertion into
independent authority by storing, signing, summarizing or retrieving it. Read
strictly, the same words could also exclude a value that the actor changes only
through an admitted action, such as an independently kept bank balance, a budget
that another service debits, or a sensor reading of a state that the action
changed, although the actor cannot forge that record or bypass its rules.

A resolution is expected to define a verifiable input by who controls its
authenticity and its state transitions under a declared protocol; to distinguish
an actor that submits a request, causes a validated transition, chooses among
genuine observations or asserts the value directly; to keep the prohibition on
an actor-written field becoming trusted through a read; and to come with
examples that cover actor-written fields, independently debited budgets,
payment-provider balances, signed external mandates, sensors affected by the
action, stale snapshots, selective omission and transformed memories.

## ECL-ISSUE-004: What a person approving an action is shown

Status: **resolved in the candidate requirements and assessment procedure.**

Resolution: ECL1N-0174 and EA-17 require human-readable consequential
fields, complete parameters accessible to the approver, canonical action
binding, and a fresh approval after a consequential change. A digest supplements
rather than replaces the presentation. Display ambiguity, hidden fields,
localization and accessibility are covered in the assessment procedure.

Original question and requested scope (preserved for review):

ECL1N-0174 lets an approval presentation show the action's parameters or their
digest. A digest alone cannot show an amount, a currency, a recipient, a
deletion scope, an audience or a change of privilege that the parameters hold,
and a minimum review time (ECL1N-0175) does not repair a presentation that
leaves them out.

A resolution is expected to require a human-readable presentation of the
consequential fields of the action and their consequences, exactly bound to the
canonical action that is released, with the digest as a supplementary integrity
reference; to state how units, currency, rounding, account identity, resource
scope, truncation, localization and accessibility are presented and how display
relates to execution; to require a new approval when a consequential field
changes; and to come with tests of a harmless summary over a dangerous hidden
parameter, look-alike account names, an amount changed after approval and an
approved text whose destination changes.

## ECL-ISSUE-005: Obligations at an OAuth resource server

Status: **resolved in the candidate requirements and assessment procedure.**

Resolution: OA1-008 explicitly limits Version 1.0 to admits with an
empty obligations list. All three verifiers reject issuance carrying any
obligation; the private issuer also refuses it. Three negative corpus cases
cover before-release, during-execution and after-execution obligations. Fresh
proof retrieval and critical token-condition modes are not defined by this
version. Actions needing them use an appropriate DCMP-2 enforcement path.

Original question and requested scope (preserved for review):

OAUTH-AUTHORITY-1 lets a resource server enforce a verified `admit` without
processing DCMP-2 (OA1-008, OA1-011). An admit can depend on a fresh state proof
or another obligation that can only be met at release, and the profile does not
say how each such obligation reaches the resource server.

A resolution is expected to name the supported ways: the issuer meets the
obligation before it issues the token, where the obligation's validity window
allows it; a critical token condition that the resource server enforces; or a
fresh proof that the resource server obtains from a named authority at release;
to require that a token is not issued when the selected way cannot carry the
obligation; to state revocation, audience, action digest, proof freshness, clock
tolerance and failure behavior at each hop; and to come with tests of a state
change after issue, a policy change, a revoked grant, an expired proof, an
unreachable proof service, an unsupported critical condition and a resource
server that reads the token but cannot meet the obligation. A profile may
support only some of these ways, provided that it states its capability boundary
and that an obligation it does not support fails safely.

## ECL-ISSUE-006: Evidence retention and lawful erasure

Status: **resolved in the candidate requirements and assessment procedure.**

Resolution: ECL1N-0050 gives a recorded legal-conflict procedure with
qualified legal review, deadlines, minimization, lawful accountability records
and assessment consequences. ECL1N-0051, FR-113 and the lifecycle hold/precedence
rules use the same exception. Destroyed or unavailable evidence is not treated
as a complete original bundle. This resolves the technical precedence contract;
the published rights papers record the status of release rights review, and
qualified review determines legal applicability.

Original question and requested scope (preserved for review):

The retention floor of ECL1N-0050 and FR-113, with the lifecycle rules of
EVIDENCE-LIFECYCLE-1 (EL1-006, EL1-024, EL1-027), keeps evidence for at least the
longest applicable period, while an applicable legal obligation can require
content to be removed or minimized earlier. The text has no general procedure
for such a conflict, and whether a given conflict exists depends on the record,
its purpose and the applicable law.

A resolution is expected to rest on a legal review; to give a precedence rule
and a procedure for transforming evidence when a conflict is real, which keeps
the minimum lawful metadata and accountability evidence, records what was
destroyed or restricted and states how a verification claim changes when its
evidence is no longer available; to separate source content, personal
identifiers, operational metadata, cryptographic commitments and destruction
records, and not to call a digest anonymous by default; and to state roles,
authorization, contested requests, legal holds, the consequences for an
assessment, and how a verifier reports evidence that is unavailable on purpose
without claiming that the bundle is complete.

## ECL-ISSUE-007: The shared-root prohibition and the independence classes

Status: **resolved in the candidate requirements and assessment procedure.**

Resolution: FR-001's single-power prohibition remains intact at every
class. ECL1N-0056 requires a capability matrix including administrators and
host/hypervisor roots. Class A permits one operator, without permitting one
power to alter both planes. Co-location satisfies no class if its shared root
can alter both. Class B adds separate administration of both approval and
verification; Class C adds external independence. IA-01 tests the matrix.

Original question and requested scope (preserved for review):

FR-001 forbids a single credential, role, privilege domain or trust root that is
sufficient to alter both the governed AI system's behavior and the control
outcomes, while the independence classes of Section 4.5 and the packaging
constraints of Section 5.8 allow some shared hosting at Class A. Read side by
side, the general prohibition can seem stronger than the class allowances, and
the texts do not use the same terms for an actor's privileges, an
administrator's privileges, custody of a root of trust and a compromise of the
host.

A resolution is expected to publish, for each independence class, what the
actor can do, what an operator can change, what needs another administrator,
which credentials are separate and what a compromise of the host defeats, and to
make the general prohibition and the class allowances refer to the same
capabilities, keeping the existing disclosure and assessment obligations.
