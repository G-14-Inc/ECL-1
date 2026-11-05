# ECL AuthZEN Binding Profile 1

Requirement-IDs: compiled
Version: 1.0
Status: normative profile of ECL-1 Version 1.0, a published version

This profile specifies a policy-engine contribution to an ECL decision. The
guide `docs/authzen-binding.md` explains it and gives the exact capability table.
A native capability belongs to ECL's own path; its disposition assigns that
responsibility and does not assert that a deployment implements every operation.

An AuthZEN evaluation is a decision input and has no release boundary in the
sense of ECL1N-0185: it releases no action, and an action is released, if at
all, by an enforcement point on an ECL `admit` (AZB1-001).

**AZB1-001** — An AuthZEN permit MUST NOT create, widen, extend or revive ECL
authority, and the decision point MUST still apply its native grant, scope,
generation, halt, validity and use checks.

**AZB1-002** — A decision other than an unqualified JSON boolean true MUST NOT
contribute to admit; a permit qualified by a non-empty context MUST be denied
rather than flattened into an unqualified permit.

**AZB1-003** — A valid false decision MUST deny with
`ecl.reason.authzen-denied.v1`; qualified permits MUST deny with
`ecl.error.binding-unsupported.v1`; malformed, missing, non-boolean, unknown-member,
wrong-media-type or oversized responses MUST deny with
`ecl.error.dependency-response-invalid.v1`; redirects, non-success statuses,
truncated bodies, transport or TLS failures and total-deadline timeouts MUST deny
with `ecl.error.dependency-unavailable.v1`.

**AZB1-004** — The request mapping MUST be injective over ECL identifiers, MUST NOT
send raw identifiers whose character set the bound engines reject, and MUST
reject any DCMP-2 message type other than decision_request rather than approximate it.

**AZB1-005** — The client MUST NOT follow redirects, retry within a decision
attempt or discover endpoints, and MUST authenticate the server with TLS under
a caller-configured trust anchor unless plain HTTP is explicitly enabled for
loopback testing.

**AZB1-006** — A deployment MUST publish the binding's exact capability table with
each capability supported, native or unsupported, in which outcome-hold,
outcome-challenge, obligations, validity-window, use-policy, safe-state,
control-cancel, control-revoke, control-supersede, control-quarantine and
control-halt MUST be native responsibilities of ECL.

**AZB1-007** — A policy-service change MUST affect only subsequent evaluations;
outstanding authorizations MUST remain bounded by their validity windows, and
immediate effect MUST use ECL's own control path without a policy-service bypass.

**AZB1-008** — Deviations from the bound protocol's requirements MUST be declared
in binding documentation, including this binding's strict-JSON acceptance beyond
the I-JSON recommendation and denial of unknown response members.

An empty context does not qualify the boolean decision. A valid false is a
policy denial, not a transport failure. The additional check supplies no
authority, validity window, use policy or obligation. The table's native
responsibilities preserve cancel, revoke, supersede, quarantine, halt, hold and
challenge as ECL semantics; this binding supports neither batch evaluation nor
endpoint discovery. Outstanding authority staleness is bounded by its existing
window, not by polling the policy engine.

## Evidence

| Kind | What the citation establishes |
|---|---|
| Vectors | ECL object semantics separately from external engine behavior |
| Deployment tests | The decision point's client and its handling of the policy engine's responses |

Vectors check ECL objects, not an exchange with a policy engine. A claim of
this profile shows the client's behavior with tests of its own deployment: the
strict acceptance of AZB1-002 and AZB1-003, an injective mapping that refuses
what it cannot map (AZB1-004), the transport rules of AZB1-005, and the boundary
of AZB1-001, under which a permit never replaces a native check such as
revocation. The guide gives the exact capability table and the declared
deviations (AZB1-006, AZB1-008). These tests do not establish assessor
independence or a production deployment claim.
