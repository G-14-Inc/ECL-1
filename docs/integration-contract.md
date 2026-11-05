# Agent and tool integration contract

Status: informative guide for ECL-1 Version 1.0. It states no requirement of
its own: each statement restates a requirement of the core standard, a
companion protocol or a binding profile and cites it, and where the two differ
the requirement governs.

This guide is for the builders of the components that a control layer has to
control. For each kind of component it states what the component must expose to
the control layer and what it must not hold. It then states what a buyer's
verifier checks, which records stay apart, what a component may claim, and what
the guide does not cover.

## How to read this guide

A requirement applies at the level that Section 6.1 of the core standard gives
it; DCMP-2, EBMP-2 and INTEGRITY-ENVELOPE-1 apply to every claim
([ECL1N-0022](../render/ecl-1_standard.html#ECL1N-0022)), and a binding profile
to a claim that declares it (Section 3.5).

| Component | Its place in ECL-1 | Texts that apply |
|---|---|---|
| Agent or agent host | Part of the governed AI system, which implements no control responsibility ([ECL1N-0032](../render/ecl-1_standard.html#ECL1N-0032)) | Core standard; DCMP-2; ACS-BINDING-1 or AARM-BINDING-1 for its hooks |
| Tool server or Model Context Protocol (MCP) server | A point of effect; its execution of a forwarded call is the effect boundary ([MG1-014](../render/mcp-gateway-1.html#MG1-014)) | MCP-GATEWAY-1; TRANSACTIONAL-EFFECT-1 for a transactional store |
| Gateway at a tool boundary | An enforcement point, releasing each action at its release boundary ([ECL1N-0185](../render/ecl-1_standard.html#ECL1N-0185)) | MCP-GATEWAY-1; DCMP2-HTTP-1; TRUST-POLICY-1; EBMP-2 |
| OAuth resource server | An enforcement point whose acceptance of a token releases the action ([OA1-005](../render/oauth-authority-1.html#OA1-005)) | OAUTH-AUTHORITY-1 |
| Policy engine behind AuthZEN | The source of a decision input, releasing nothing ([AZB1-001](../render/authzen-binding-1.html#AZB1-001)) | AUTHZEN-BINDING-1 |
| OWASP Agent Control Standard (ACS) Guardian or AARM control plane | A decision source, or for AARM the Decision Layer ([AC1-003](../render/acs-binding-1.html#AC1-003), [AB1-001](../render/aarm-binding-1.html#AB1-001)) | ACS-BINDING-1; AARM-BINDING-1 |
| A buyer's verifier | Checks a signed evidence bundle offline under its caller's trust policy ([EBMP2-057](../render/ebmp-2.html#EBMP2-057)) | EBMP-2, section 11; TRUST-POLICY-1; OFFLINE-VERIFICATION-1 |

Requirement identifiers link to the rendered texts, and checklist items to their
tables in Section 11. Each worked example is an excerpt of a conformance vector
or fixture, cited by path: members are left out, and no value is changed.

## 1. The agent or agent host

The governed AI system is its models, the runtime that executes their outputs,
and every tool, plugin, memory store, credential and process that the runtime
can invoke, write or reconfigure, other than the components of the External
Control Layer (Section 4.1). An agent host is that runtime, so it must not be
able to rewrite, disable or bypass a control responsibility
([ECL1N-0032](../render/ecl-1_standard.html#ECL1N-0032),
[ECL1N-0046](../render/ecl-1_standard.html#ECL1N-0046)).

### What it exposes

- **A point where each consequential action is held.** Every in-scope action
  crosses the Enforcement Boundary before its effect
  ([ECL1N-0028](../render/ecl-1_standard.html#ECL1N-0028),
  [ECL1N-0033](../render/ecl-1_standard.html#ECL1N-0033)), so each route from
  the agent host to an effect passes an enforcement point outside its reach: a
  gateway in front of its tool servers
  ([MG1-001](../render/mcp-gateway-1.html#MG1-001)), a resource server that
  accepts only a token issued for one admit
  ([OA1-005](../render/oauth-authority-1.html#OA1-005),
  [OA1-008](../render/oauth-authority-1.html#OA1-008)), or an enforcement point
  to which a hook carries the decision
  ([AC1-002](../render/acs-binding-1.html#AC1-002),
  [AB1-010](../render/aarm-binding-1.html#AB1-010)). A path that reaches none of
  them is excluded and listed in the Negative Boundary Annex, and an omitted
  path makes the claim incomplete
  ([ECL1N-0011](../render/ecl-1_standard.html#ECL1N-0011),
  [ECL1N-0038](../render/ecl-1_standard.html#ECL1N-0038)).
- **Its capability inventory.** The Consequential Action Register is validated
  against the tool manifests, API permissions, delegated authority paths,
  workflow triggers and service bindings that the system can reach
  ([ECL1N-0008](../render/ecl-1_standard.html#ECL1N-0008),
  [FR-006](../render/ecl-1_standard.html#FR-006); checklist item
  [BC-01](../render/ecl-1_standard.html#1131-boundary-and-claim-controls)), and
  every model that can originate, transform or approve an action belongs to the
  declared system ([ECL1N-0015](../render/ecl-1_standard.html#ECL1N-0015)).
- **The identifiers of each request.** A decision request carries its message
  identifier, workflow, attempt, issuer and issue time
  ([DCMP2-004](../render/dcmp-2.html#DCMP2-004)), and names the actor, any
  distinct subject, the action, target, operation, parameter digest,
  constraints, risk class, evidence profile, requested audience, validity and
  use policy, and its expiry ([DCMP2-006](../render/dcmp-2.html#DCMP2-006));
  from `L2`, [FR-102](../render/ecl-1_standard.html#FR-102) states the minimum.
  One root trace identifier covers the chain from approval to effect, each
  effect has its own action identifier, and a child action keeps its parent link
  ([ECL1N-0013](../render/ecl-1_standard.html#ECL1N-0013),
  [ECL1N-0014](../render/ecl-1_standard.html#ECL1N-0014)).
- **Its version.** From `L2`, each change of model, system instructions or tool
  set is recorded with a version and digest, and each request names the version
  that made it ([ECL1N-0171](../render/ecl-1_standard.html#ECL1N-0171)), in
  `ecl.ext.runtime-configuration.v1`.

Behind an MCP gateway the agent host sends an ordinary MCP request: the gateway
takes the action class, operation and target from the reviewed mapping, never
from the request or a tool's annotations
([MG1-003](../render/mcp-gateway-1.html#MG1-003)), and the call's arguments
become the parameters ([MG1-004](../render/mcp-gateway-1.html#MG1-004)). An
agent host that signs DCMP-2 requests itself uses a key with the
decision-request purpose
([IE1-039](../render/integrity-envelope-1.html#IE1-039)) and no other role
([TP1-009](../render/trust-policy-1.html#TP1-009)), never a key that signs
evidence events ([ECL1N-0156](../render/ecl-1_standard.html#ECL1N-0156)).

### What it may not do before the decision

- Cause the effect: Enforcement applies the outcome before execution
  ([ECL1N-0036](../render/ecl-1_standard.html#ECL1N-0036)), and no undisclosed
  path goes around it ([ECL1N-0141](../render/ecl-1_standard.html#ECL1N-0141)).
- Hold a credential, token, key or connection that reaches an in-scope server or
  a system behind it ([MG1-009](../render/mcp-gateway-1.html#MG1-009)), or the
  proof-of-possession key of a token presented for its action
  ([OA1-004](../render/oauth-authority-1.html#OA1-004)); checklist item
  [EA-25](../render/ecl-1_standard.html#1133-enforcement-and-action-controls)
  tries each point of effect with every credential the system holds or can
  obtain.
- From `L2`, see a plaintext secret in its reasoning context
  ([FR-106](../render/ecl-1_standard.html#FR-106)).
- Control an asserted value, its authenticity checks or its transition rules
  while a decision treats it as `verifiable`. A transition independently
  validated by an authority, such as a provider debit, is distinguished from
  an arbitrary actor write; source signatures do not launder assertions
  ([decision examples](decision-examples.md))
  ([ECL1N-0178](../render/ecl-1_standard.html#ECL1N-0178)).
- Start, stop or configure the enforcement point, execute code where it runs, or
  change its policy or decision binding
  ([MG1-001](../render/mcp-gateway-1.html#MG1-001),
  [AC1-002](../render/acs-binding-1.html#AC1-002),
  [ECL1N-0046](../render/ecl-1_standard.html#ECL1N-0046)).
- Approve its own action or control change. An approval is a person's, on a
  recorded presentation
  ([ECL1N-0174](../render/ecl-1_standard.html#ECL1N-0174)); a chat statement
  without that binding is not release authority
  ([EBMP2-017](../render/ebmp-2.html#EBMP2-017)); and a change that disables,
  bypasses or automatically approves a control needs a person other than its
  requester ([ECL1N-0166](../render/ecl-1_standard.html#ECL1N-0166)).

### What it does with the decision

- An `admit` binds the exact request and action by scope digest and names the
  enforcement point that may release it, with a validity window and use policy
  ([DCMP2-013](../render/dcmp-2.html#DCMP2-013),
  [DCMP2-044](../render/dcmp-2.html#DCMP2-044),
  [DCMP2-048](../render/dcmp-2.html#DCMP2-048),
  [DCMP2-049](../render/dcmp-2.html#DCMP2-049)). That enforcement point releases
  the action, after proving each `before_release` obligation
  ([ECL1N-0186](../render/ecl-1_standard.html#ECL1N-0186),
  [DCMP2-017](../render/dcmp-2.html#DCMP2-017)).
- A `deny`, `hold` or `challenge` is never release authority
  ([DCMP2-014](../render/dcmp-2.html#DCMP2-014)). A `hold` names its condition
  for progress, deadline and timeout disposition
  ([DCMP2-018](../render/dcmp-2.html#DCMP2-018)); a `challenge` names the
  evidence required and a deadline
  ([DCMP2-019](../render/dcmp-2.html#DCMP2-019)). Evidence that the answer
  references is `actor_supplied` unless authenticated from its source
  ([DCMP2-020](../render/dcmp-2.html#DCMP2-020)), and satisfying the challenge
  leads to a new evaluation and a new response, never a changed one
  ([DCMP2-021](../render/dcmp-2.html#DCMP2-021)).
- A retry is a new message and attempt
  ([DCMP2-026](../render/dcmp-2.html#DCMP2-026)); an idempotency key can name
  the intended effect boundary but replaces no identifier
  ([DCMP2-011](../render/dcmp-2.html#DCMP2-011)).

### The one-way rule from the agent's side

- What the agent host states about purpose, authority, approval or the world is
  `actor_supplied` ([ECL1N-0041](../render/ecl-1_standard.html#ECL1N-0041),
  [ECL1N-0178](../render/ecl-1_standard.html#ECL1N-0178)), and so are a
  request's risk class, constraints, budget debit and its witness and manifest
  references ([DCMP2-054](../render/dcmp-2.html#DCMP2-054)). Such an input can
  make an outcome stricter and is never the basis of an `admit`
  ([ECL1N-0179](../render/ecl-1_standard.html#ECL1N-0179)), which rests on
  policy over `verifiable` inputs alone
  ([ECL1N-0180](../render/ecl-1_standard.html#ECL1N-0180)). A model's or
  detector's output about meaning or risk is a `judgment` input, never
  `verifiable` ([ECL1N-0178](../render/ecl-1_standard.html#ECL1N-0178)).
- A verifier refuses a basis that records as `verifiable` an input whose source
  is the request's actor, but the check compares one identifier
  ([DCMP2-053](../render/dcmp-2.html#DCMP2-053)), so an input supplied under
  another name is classed by the register's declaration of its source, which
  checklist item
  [EA-21](../render/ecl-1_standard.html#1133-enforcement-and-action-controls)
  reviews ([ECL1N-0178](../render/ecl-1_standard.html#ECL1N-0178)).

### The decision basis, and what the agent host supplies to it

The Decision Layer records each decision's basis in `ecl.ext.decision-basis.v1`:
the register version and each declared or consulted input, with its class,
availability, digest and effect
([ECL1N-0181](../render/ecl-1_standard.html#ECL1N-0181)). The agent host
supplies the action's operation, target and parameters, which are the subject of
the decision, bound by digest, not inputs
([DCMP2-007](../render/dcmp-2.html#DCMP2-007),
[DCMP2-044](../render/dcmp-2.html#DCMP2-044)); and its statements, recorded as
`actor_supplied` entries that never have the effect `supports`
([DCMP2-053](../render/dcmp-2.html#DCMP2-053)). No undeclared input is consulted
([ECL1N-0178](../render/ecl-1_standard.html#ECL1N-0178)), and an ACS or AARM
adapter's records list exactly the basis's entries
([AC1-012](../render/acs-binding-1.html#AC1-012),
[AB1-013](../render/aarm-binding-1.html#AB1-013)).

### Refusals, expiry and restricted mode

- **Refusals.** A gateway answers a request it does not forward with an error
  code from its profile's table and a registered reason, never a result
  ([MG1-006](../render/mcp-gateway-1.html#MG1-006)). A server's own error that
  uses such a code reaches the agent as -32603
  ([MG1-010](../render/mcp-gateway-1.html#MG1-010)), so a table code always
  means the gateway refused, except -31009: forwarded, with no response, effect
  unknown ([MG1-006](../render/mcp-gateway-1.html#MG1-006)). A denied, held or
  challenged action is not an execution failure
  ([EBMP2-012](../render/ebmp-2.html#EBMP2-012)).
- **Unknown outcomes.** No automatic retry unless the point of effect applies
  the effect at most once
  ([ECL1N-0189](../render/ecl-1_standard.html#ECL1N-0189)); a later attempt is a
  new request ([DCMP2-026](../render/dcmp-2.html#DCMP2-026)).
- **Expiry.** An authorization lasts no longer than the requested validity
  ([DCMP2-049](../render/dcmp-2.html#DCMP2-049)), and an action whose authority
  is not usable at its release boundary is not released
  ([ECL1N-0188](../render/ecl-1_standard.html#ECL1N-0188)). Approvals expire
  ([EBMP2-017](../render/ebmp-2.html#EBMP2-017)), and an expired ACS `ask` or
  `defer`, or AARM STEP_UP or DEFER, releases nothing
  ([AC1-007](../render/acs-binding-1.html#AC1-007),
  [AB1-005](../render/aarm-binding-1.html#AB1-005)).
- **Restricted mode and halt.** Restricted mode denies new actions in its scope
  except safe-state or containment actions
  ([ECL1N-0103](../render/ecl-1_standard.html#ECL1N-0103)), within the scope
  that [ECL1N-0191](../render/ecl-1_standard.html#ECL1N-0191) gives a loss of
  required proof, and lifts only after fresh proof and a recorded authorization
  ([ECL1N-0193](../render/ecl-1_standard.html#ECL1N-0193)). Emergency halt takes
  precedence ([ECL1N-0104](../render/ecl-1_standard.html#ECL1N-0104),
  [TS1-025](../render/timing-safe-state-1.html#TS1-025)), comes only from the
  emergency control plane ([DCMP2-025](../render/dcmp-2.html#DCMP2-025)), and no
  lower-precedence decision revives what it holds
  ([TS1-027](../render/timing-safe-state-1.html#TS1-027)). A declared detection
  holds, restricts or stops the affected classes
  ([ECL1N-0167](../render/ecl-1_standard.html#ECL1N-0167)), from `L2` without a
  person's action ([ECL1N-0168](../render/ecl-1_standard.html#ECL1N-0168)).

### Worked example

From `conformance/vectors/dcmp-2/valid-decision-request.json`:

```json
{
  "actor": {"id": "urn:example:agent:payments-1", "type": "ecl.principal.workload.v1"},
  "subject": {"id": "urn:example:tenant:customer-42", "type": "ecl.principal.tenant.v1"},
  "action": {
    "action_class": "ecl.action.financial-transfer.v1",
    "operation": "transfer",
    "target": {"uri": "urn:example:account:destination-9"},
    "parameters": {"amount": "125.00", "currency": "USD"},
    "budget_debit": {"budget_id": "urn:example:budget:daily-transfer", "amount": "125.00", "unit": "ecl.unit.usd.v1"}
  },
  "constraints": {"destination_country": "US", "maximum_amount": "125.00"},
  "authority_request": {
    "audience": "urn:example:enforcement:payments-gate-1",
    "requested_validity_seconds": 5,
    "use_policy": "single_use"
  }
}
```

The agent is the actor and the tenant the subject
([DCMP2-009](../render/dcmp-2.html#DCMP2-009)); target and parameters are the
subject of the decision, bound by `parameters_digest`
([DCMP2-007](../render/dcmp-2.html#DCMP2-007)); `constraints` and `budget_debit`
are the agent's statements ([DCMP2-054](../render/dcmp-2.html#DCMP2-054)). An
`admit` must name the enforcement point
`urn:example:enforcement:payments-gate-1` with a single-use authorization of at
most five seconds ([DCMP2-048](../render/dcmp-2.html#DCMP2-048),
[DCMP2-049](../render/dcmp-2.html#DCMP2-049)).

## 2. The tool server or MCP server

Behind an MCP gateway, the release boundary is the gateway's write of the
forwarded request to the server's transport, and the server's execution of the
call is the later effect boundary, which the gateway does not observe
([MG1-014](../render/mcp-gateway-1.html#MG1-014)).

### What it accepts only through the gateway

- Requests from the governed AI system: all pass through the gateway, and any
  other path to the server or a system behind it is closed or disclosed
  ([MG1-001](../render/mcp-gateway-1.html#MG1-001)).
- The credential that reaches it, held by the gateway or a broker behind it and
  used only for forwarded requests
  ([MG1-009](../render/mcp-gateway-1.html#MG1-009)).
- TLS under anchors that the gateway's operator configures; the gateway follows
  no redirect ([MG1-011](../render/mcp-gateway-1.html#MG1-011)).
- For a transactional store, changes to protected resources, only through its
  admission function, whatever credential the system's services or agents hold
  ([TE1-001](../render/transactional-effect-1.html#TE1-001)).

### What it must not accept directly

A call from the governed AI system with any credential that the system holds or
can obtain, or a credential that the system presented to the gateway, which the
gateway never passes on ([MG1-009](../render/mcp-gateway-1.html#MG1-009);
checklist item
[EA-25](../render/ecl-1_standard.html#1133-enforcement-and-action-controls)).

### What it reports about itself

The mapping names the server by identifier, name and version, and the tool by
its name and the digest of its reviewed definition
([MG1-003](../render/mcp-gateway-1.html#MG1-003)). The gateway compares each
definition from `tools/list` with that digest, and refuses calls to a changed or
added tool, or to any tool of a server whose name or version in
`io.modelcontextprotocol/serverInfo` changed, until review
([MG1-008](../render/mcp-gateway-1.html#MG1-008),
[ECL1N-0170](../render/ecl-1_standard.html#ECL1N-0170)). A server that reports a
stable name and version lets the gateway apply both rules, and its annotations
never choose an action class ([MG1-003](../render/mcp-gateway-1.html#MG1-003)).
It receives exactly the decided call, `method` and `params` unchanged
([MG1-004](../render/mcp-gateway-1.html#MG1-004),
[MG1-005](../render/mcp-gateway-1.html#MG1-005)), and its own errors with codes
of the gateway's table reach the agent as -32603
([MG1-010](../render/mcp-gateway-1.html#MG1-010)).

### How it exposes an effect record, or lets an effect be observed

- A successful tool return is not a successful effect unless the observation
  boundary supports it ([EBMP2-015](../render/ebmp-2.html#EBMP2-015)). The
  gateway binds the server's response by digest in its terminal event
  ([MG1-010](../render/mcp-gateway-1.html#MG1-010),
  [EBMP2-075](../render/ebmp-2.html#EBMP2-075)), a statement at the level
  `issuer-asserted` ([EBMP2-061](../render/ebmp-2.html#EBMP2-061)).
- An effect is `corroborated` only by a `verification` event from another
  principal, under disjoint keys, attesting each side effect's URI and digest
  ([EBMP2-061](../render/ebmp-2.html#EBMP2-061)).
- A released attempt whose response was lost stays unresolved until evidence
  such as an authoritative status query at the point of effect resolves it
  ([ECL1N-0189](../render/ecl-1_standard.html#ECL1N-0189)); a server that
  answers such queries lets it be resolved. An `unknown` terminal lists the
  known side effects and the residual uncertainty
  ([EBMP2-013](../render/ebmp-2.html#EBMP2-013)).

### Idempotency and the effect boundary

- A claim names each class's release boundary and any later effect boundary
  ([ECL1N-0185](../render/ecl-1_standard.html#ECL1N-0185)). A check at the
  release boundary does not show that the authority was valid when the server
  acted; that needs a check at the point of effect or a declared bound on the
  delay ([ECL1N-0188](../render/ecl-1_standard.html#ECL1N-0188)), as a resource
  server's token check provides
  ([OA1-005](../render/oauth-authority-1.html#OA1-005)).
- An attempt that may have executed is not retried automatically unless the
  point of effect applies the effect at most once, for example by honoring an
  idempotency key ([ECL1N-0189](../render/ecl-1_standard.html#ECL1N-0189),
  [DCMP2-011](../render/dcmp-2.html#DCMP2-011)); the gateway never retries it
  ([MG1-016](../render/mcp-gateway-1.html#MG1-016)). A server that honors such a
  key lets a claim show it.
- A transactional store commits at most one effect per action key and charged
  use ([TE1-003](../render/transactional-effect-1.html#TE1-003)), and answers a
  retry with the same key and digest with the committed outcome
  ([TE1-006](../render/transactional-effect-1.html#TE1-006)).

### Worked example

From `conformance/suites/mcp-gateway/mcp-valid-forwarded-on-admit.json`, the
mapping, and the value of `ecl.ext.mcp-binding.v1` on the `succeeded` terminal
event:

```json
{
  "mapping": {
    "server_id": "urn:example:mcp-server:issues",
    "server_name": "issue-tracker",
    "server_version": "2.3.0",
    "target_argument": "repository",
    "tool": "create_issue",
    "tool_definition_digest": {"algorithm": "ecl.digest.sha-256.v1", "value": "2a520e7ae0ae8b0e0e443cea4fd0d26e5bf837f6a4069bd068691d9c445874a6"}
  }
}
```

```json
{
  "response_digest": {"algorithm": "ecl.digest.sha-256.v1", "value": "384f5c3b46ea9ce649189b73b571c00d24c2752937673d7fa75a8a87ce83aa7b"},
  "server_id": "urn:example:mcp-server:issues",
  "tool": "create_issue"
}
```

The server is pinned by identity and reviewed definition, and the target comes
from the `repository` argument ([MG1-003](../render/mcp-gateway-1.html#MG1-003),
[MG1-008](../render/mcp-gateway-1.html#MG1-008)). The response is bound by
digest ([EBMP2-075](../render/ebmp-2.html#EBMP2-075)), and `succeeded` is the
server's report, `issuer-asserted` until corroborated
([EBMP2-061](../render/ebmp-2.html#EBMP2-061)).

## 3. An OAuth resource server

An action under OAUTH-AUTHORITY-1 has two boundaries: the issuer releases
authority by issuing a token, only for a verified `admit`
([OA1-008](../render/oauth-authority-1.html#OA1-008)), and the resource server's
acceptance of the presented token releases the action at the point of effect
([OA1-005](../render/oauth-authority-1.html#OA1-005),
[OA1-011](../render/oauth-authority-1.html#OA1-011),
[ECL1N-0185](../render/ecl-1_standard.html#ECL1N-0185)).

### What it exposes

- Acceptance only for the named request: the presented target, operation and
  parameter digest equal the token's ECL entry, within its use policy; every
  instance shares one store of uses and accepted proof identifiers
  ([OA1-005](../render/oauth-authority-1.html#OA1-005)).
- An audience check ([OA1-002](../render/oauth-authority-1.html#OA1-002)), and a
  time check against the token's validity, with a declared clock skew of at most
  60 seconds, and against the entry's window with none
  ([OA1-003](../render/oauth-authority-1.html#OA1-003)).
- A proof-of-possession check, by DPoP or mutual TLS, refusing a replayed proof
  ([OA1-004](../render/oauth-authority-1.html#OA1-004)).
- Signature checks under issuer keys from its own configuration, never from the
  token's header, with `none` and symmetric algorithms refused and every segment
  read as strict JSON ([OA1-007](../render/oauth-authority-1.html#OA1-007)).
- For a delegated action, refusal of a token whose `act` claim does not name the
  actor ([OA1-006](../render/oauth-authority-1.html#OA1-006)).
- The code of the first failing check, in the presentation table's order
  ([OA1-011](../render/oauth-authority-1.html#OA1-011)), and retained records as
  `ecl_oauth_presentation_v1`
  ([OA1-010](../render/oauth-authority-1.html#OA1-010)).

### What it must not hold or accept

It accepts no token without valid proof of possession of the bound key, which
the presenting component holds and the governed AI system cannot read
([OA1-004](../render/oauth-authority-1.html#OA1-004)), and takes no AuthZEN
permit as a reason to accept more: such an evaluation may only narrow the
request ([OA1-009](../render/oauth-authority-1.html#OA1-009)).

### Worked example

From
`conformance/suites/oauth-authority/oauth-valid-replayed-proof-refused.json`:

```json
{
  "presentation": {
    "method": "POST",
    "operation": "payments.transfer",
    "seen_dpop_jti": ["dpop-0001"],
    "uri": "https://rs.example.com/payments/transfers",
    "use_count": 1
  },
  "resource_server": "https://rs.example.com",
  "result": {"accepted": false, "error": "ecl.error.replay.v1"}
}
```

The token names this server and request, and this is its first use, but the DPoP
proof, omitted here, carries the `jti` `dpop-0001`, already accepted within the
proof window, so check 5 refuses it as a replay
([OA1-004](../render/oauth-authority-1.html#OA1-004),
[OA1-011](../render/oauth-authority-1.html#OA1-011)).

## 4. The gateway or enforcement point at a tool boundary

MCP-GATEWAY-1 states what an enforcement point between the governed AI system
and its MCP servers does; one at another tool boundary meets the same core
requirements through its own enforcement profile
([ECL1N-0185](../render/ecl-1_standard.html#ECL1N-0185),
[ECL1N-0186](../render/ecl-1_standard.html#ECL1N-0186)).

### Admission

- **Placement.** The claim names the MCP revision, the in-scope servers and the
  transports; every request to those servers passes through the gateway, which
  runs in no process, container or account that the governed AI system can
  start, stop or configure, or in which it can execute code
  ([MG1-001](../render/mcp-gateway-1.html#MG1-001)).
- **Requests that need a decision.** Every `tools/call` and its retries, every
  `tasks/update` of a governed task, and every request the register maps to a
  consequential class; unmapped methods and tools are refused with -31007, and
  only the listed discovery requests and client notifications pass without one
  ([MG1-002](../render/mcp-gateway-1.html#MG1-002)).
- **The mapping and the request.** A reviewed mapping per tool gives the action
  class, operation, target rule and evidence profile
  ([MG1-003](../render/mcp-gateway-1.html#MG1-003)). The request carries the
  arguments as parameters, and the critical `ecl.ext.mcp-binding.v1` binds the
  complete `params`; a request with another member, or a number that RFC 8785
  cannot represent exactly, is refused
  ([MG1-004](../render/mcp-gateway-1.html#MG1-004)).
- **The decision exchange.** One HTTPS POST per attempt within a declared
  timeout, with no redirect or retry, and limits applied before parsing; a
  timeout, a transport failure or a non-200 response is a dependency failure,
  and an invalid response with status 200 is a distinct failure that never
  enters evidence ([DHB1-001](../render/dcmp2-http-1.html#DHB1-001),
  [DHB1-003](../render/dcmp2-http-1.html#DHB1-003),
  [DHB1-007](../render/dcmp2-http-1.html#DHB1-007),
  [DHB1-008](../render/dcmp2-http-1.html#DHB1-008)).
- **A verified decision, or nothing.** Without a verified response carrying
  exactly one decision basis that passes
  [DCMP2-053](../render/dcmp-2.html#DCMP2-053), nothing is forwarded and nothing
  retried ([MG1-007](../render/mcp-gateway-1.html#MG1-007)).

### The release order and obligations before release

The gateway forwards only on a verified `admit` for exactly the request, within
its use policy, after discharging every pre-release obligation, through the
release order, at a final clock observation inside the window with the release
guard added, and forwards exactly the bound call
([MG1-005](../render/mcp-gateway-1.html#MG1-005)). These are the items of
[ECL1N-0186](../render/ecl-1_standard.html#ECL1N-0186) at its release boundary.

- **Obligations.** For each `before_release` obligation and deferred witness,
  the gateway obtains a proof from a principal that the claim accepts, never the
  governed AI system, naming this request, fresh and unused, and checks it with
  the verifier declared for its type; otherwise it refuses with -31010, since
  neither the type's recognition nor the signed `admit` proves anything
  ([MG1-013](../render/mcp-gateway-1.html#MG1-013),
  [ECL1N-0187](../render/ecl-1_standard.html#ECL1N-0187)). The claim declares
  each type with its verifier, issuers and freshness rule
  ([MG1-013](../render/mcp-gateway-1.html#MG1-013)).
- **The order.** Under a lock covering every use of the authorization, it reads
  its clock and consumes a use if the window and use policy allow, records
  `authority_consumed` and then `release_prepared`, discharges the obligations,
  reads its clock again under the lock and goes on only if that final
  observation passes, and records `execution_released` before writing the
  request ([MG1-014](../render/mcp-gateway-1.html#MG1-014)).

### Expiry at the release boundary

- The release guard bounds the delay from the final observation to the write,
  and immediately before writing, the gateway checks by a monotonic clock that
  the authorization has not ended
  ([MG1-014](../render/mcp-gateway-1.html#MG1-014)): a declared and enforced
  bound as [ECL1N-0188](../render/ecl-1_standard.html#ECL1N-0188) allows.
- A refusal after the use was consumed is a `cancelled` terminal with no side
  effect and its reason, -31006 when the authorization would not be valid at the
  write ([MG1-014](../render/mcp-gateway-1.html#MG1-014)).
- `forwarded_at` and the release event's `observed_at` are the final observation
  ([MG1-015](../render/mcp-gateway-1.html#MG1-015),
  [EBMP2-071](../render/ebmp-2.html#EBMP2-071)). A send that completes at or
  after `valid_until` is marked in a critical extension and reported, after the
  fact ([MG1-015](../render/mcp-gateway-1.html#MG1-015),
  [EBMP2-072](../render/ebmp-2.html#EBMP2-072)).

### Journal and recovery

- A gateway that retains exchange records journals each event, with the record
  and the signed decision messages, makes each entry durable before the step it
  evidences, and keeps it until the record and bundle are durable
  ([MG1-016](../render/mcp-gateway-1.html#MG1-016)), which preserves the
  recovery information of [ECL1N-0189](../render/ecl-1_standard.html#ECL1N-0189)
  before the release.
- At start, each journal is settled by what it holds, never by what it lacks,
  without retrying: a release without a terminal becomes `unknown`, and no
  release becomes `cancelled` after an `admit`
  ([MG1-016](../render/mcp-gateway-1.html#MG1-016)). The claim declares which of
  process exit, host crash, storage failure and evidence-service loss the
  journal survives ([MG1-016](../render/mcp-gateway-1.html#MG1-016),
  [ECL1N-0190](../render/ecl-1_standard.html#ECL1N-0190)).
- An entry that cannot be made durable before the release stops it, with -31011
  unless an earlier cause applies
  ([MG1-017](../render/mcp-gateway-1.html#MG1-017)).

### What it records

- A forwarded request yields `authority_consumed`, `release_prepared`,
  `execution_released`, with the discharge in `ecl.ext.obligation-discharge.v1`
  when obligations were deferred, and a terminal event binding the response; a
  refusal yields a non-release state, or `cancelled` after consumption
  ([MG1-010](../render/mcp-gateway-1.html#MG1-010),
  [EBMP2-070](../render/ebmp-2.html#EBMP2-070)). Each proof that the discharge
  names travels in the bundle ([MG1-013](../render/mcp-gateway-1.html#MG1-013),
  [EBMP2-070](../render/ebmp-2.html#EBMP2-070)).
- Use counts stay within the authorization, single-use consumption is recorded
  ([EBMP2-073](../render/ebmp-2.html#EBMP2-073),
  [EBMP2-074](../render/ebmp-2.html#EBMP2-074)), MCP bindings repeat the decided
  call ([EBMP2-075](../render/ebmp-2.html#EBMP2-075)), and no non-release state
  appears with consumed authority or side effects
  ([EBMP2-053](../render/ebmp-2.html#EBMP2-053)).
- Retained records follow `ecl_mcp_gateway_exchange_v1`
  ([MG1-012](../render/mcp-gateway-1.html#MG1-012)), and refusals the error
  table and its order ([MG1-006](../render/mcp-gateway-1.html#MG1-006)). The
  gateway's event keys are out of the governed AI system's reach and sign for
  the enforcement point alone
  ([ECL1N-0156](../render/ecl-1_standard.html#ECL1N-0156),
  [ECL1N-0157](../render/ecl-1_standard.html#ECL1N-0157)).

### Worked example

From
`conformance/suites/mcp-gateway/mcp-valid-obligation-unproven-cancelled.json`:

```json
{
  "decision": {"response": {"outcome": "admit", "obligations": [
    {"id": "urn:example:obligation:mcp-repository-witness", "satisfaction": "before_release", "type": "ecl.obligation.verify-witness.v1"},
    {"id": "urn:example:obligation:mcp-release-approval", "satisfaction": "before_release", "type": "ecl.obligation.approval-record.v1"}
  ]}},
  "returned": {"error": {"code": -31010, "data": {"ecl": {"code": "obligation-unproven", "reason": "ecl.error.obligation-unproven.v1"}}}},
  "terminal": {"event": {
    "residual_state": "The gateway did not write the request to the server.",
    "side_effects": [],
    "state": "cancelled"
  }}
}
```

The gateway had consumed the use and recorded `release_prepared` when it found
an obligation unproven, so it wrote nothing, answered -31010 and recorded a
`cancelled` terminal with no side effect
([MG1-006](../render/mcp-gateway-1.html#MG1-006),
[MG1-013](../render/mcp-gateway-1.html#MG1-013),
[MG1-014](../render/mcp-gateway-1.html#MG1-014)).

## 5. A policy engine behind AuthZEN

An AuthZEN evaluation is a decision input; an action is released, if at all, by
an enforcement point on an ECL `admit`
([AZB1-001](../render/authzen-binding-1.html#AZB1-001)).

### What it exposes

- One evaluation endpoint, called once per attempt over TLS under an anchor the
  caller configures, with no redirect, retry or discovery
  ([AZB1-005](../render/authzen-binding-1.html#AZB1-005)).
- A permit as an unqualified JSON boolean `true`, the only answer that
  contributes to an `admit`; a permit qualified by a non-empty context is denied
  ([AZB1-002](../render/authzen-binding-1.html#AZB1-002)).
- Answers that classify cleanly: `false` denies as a policy denial, a qualified
  permit as unsupported, a malformed or oversized answer as invalid, and a
  redirect, failure or timeout as unavailable
  ([AZB1-003](../render/authzen-binding-1.html#AZB1-003)).
- Identifiers it accepts, from a mapping that is injective and maps only
  decision requests ([AZB1-004](../render/authzen-binding-1.html#AZB1-004)).

### What it must not hold

- ECL authority: a permit never creates, widens, extends or revives authority,
  the decision point keeps its own checks
  ([AZB1-001](../render/authzen-binding-1.html#AZB1-001)), and no token is
  issued on a permit ([OA1-009](../render/oauth-authority-1.html#OA1-009)).
- The responsibilities ECL keeps, among them holds, obligations, validity, use
  policy, safe states and control operations
  ([AZB1-006](../render/authzen-binding-1.html#AZB1-006)).
- Immediate effect: a policy change affects only later evaluations, and
  immediate effect goes through ECL's control path
  ([AZB1-007](../render/authzen-binding-1.html#AZB1-007)). Deviations from the
  bound protocol are declared
  ([AZB1-008](../render/authzen-binding-1.html#AZB1-008)).

### Worked example

No vector of the conformance corpus is an AuthZEN exchange. These members of
`conformance/vectors/dcmp-2/valid-decision-request.json` are among those that
section 3 of `docs/authzen-binding.md` maps:

```json
{
  "action": {"operation": "transfer", "target": {"uri": "urn:example:account:destination-9"}},
  "actor": {"id": "urn:example:agent:payments-1", "type": "ecl.principal.workload.v1"},
  "issued_at": "2026-07-27T04:30:00.000000Z",
  "message_id": "https://externalcontrollayer.ai/ns/message/req-001",
  "subject": {"id": "urn:example:tenant:customer-42", "type": "ecl.principal.tenant.v1"}
}
```

The actor becomes the evaluation's subject, the operation its action, the target
its resource with the tenant as a property, and the identifier and issue time
its context; parameters, constraints and the authority request are not sent
([AZB1-004](../render/authzen-binding-1.html#AZB1-004)). The answer is one
boolean, and every check that decides authority stays with ECL
([AZB1-001](../render/authzen-binding-1.html#AZB1-001),
[AZB1-006](../render/authzen-binding-1.html#AZB1-006)).

## 6. An OWASP ACS Guardian or an AARM control plane

Both profiles release an action only at an ECL enforcement point, on the `admit`
of a DCMP-2 response that an ECL decision point signs for the exact request
([AC1-003](../render/acs-binding-1.html#AC1-003),
[AB1-002](../render/aarm-binding-1.html#AB1-002)).

### What it exposes

- **Declarations.** For ACS, the pinned release, the Guardian's identity and
  each hook point claimed as an enforcement point
  ([AC1-001](../render/acs-binding-1.html#AC1-001)); for AARM, the pinned
  revision and, per class, whether it is the Decision Layer or a `judgment`
  source ([AB1-001](../render/aarm-binding-1.html#AB1-001)).
- **Signed responses, as the Decision Layer.** Bound to the exact request and
  signed under a key with the decision-response purpose
  ([AB1-002](../render/aarm-binding-1.html#AB1-002)).
- **Outcomes no weaker than the mapping.** `allow` or ALLOW is `admit` only when
  policy over `verifiable` inputs permits; `ask` or STEP_UP a `challenge` or
  `hold`; `defer` or DEFER a `hold`; `modify` or MODIFY a `deny` of the original
  ([AC1-004](../render/acs-binding-1.html#AC1-004),
  [AB1-003](../render/aarm-binding-1.html#AB1-003)).
- **Modifications as new requests,** carrying the new parameters as the same
  JSON values, linked by `ecl.relation.modification-of.v1` and admitted on their
  own; one that changes the target or operation ends in `deny`
  ([AC1-005](../render/acs-binding-1.html#AC1-005),
  [AB1-004](../render/aarm-binding-1.html#AB1-004)).
- **Bindings and records.** `ecl.ext.acs-decision.v1` with the chain hash
  ([AC1-008](../render/acs-binding-1.html#AC1-008)) or `ecl.ext.aarm-receipt.v1`
  with the receipt digest ([AB1-007](../render/aarm-binding-1.html#AB1-007));
  exchange records whose inputs equal the decision basis
  ([AC1-010](../render/acs-binding-1.html#AC1-010),
  [AC1-012](../render/acs-binding-1.html#AC1-012),
  [AB1-009](../render/aarm-binding-1.html#AB1-009),
  [AB1-013](../render/aarm-binding-1.html#AB1-013)).

### What it must not hold or do

- **Enforce from inside.** A hook or interception point where the governed AI
  system can execute code, or that it controls, is never an enforcement point
  and may only carry a decision
  ([AC1-002](../render/acs-binding-1.html#AC1-002),
  [AB1-010](../render/aarm-binding-1.html#AB1-010)).
- **Pass as `verifiable`.** A Guardian decision carried by a hook is
  `actor_supplied` unless the decision point verifies the Guardian's own
  signature under a key that the governed AI system cannot use, which an
  ACS-Core HMAC is not, and the decision of an `agent` or `composite` evaluator
  is `judgment` ([AC1-004](../render/acs-binding-1.html#AC1-004)); AARM's R2, R3
  and R7 outputs are `judgment`
  ([AB1-006](../render/aarm-binding-1.html#AB1-006)).
- **Create authority or release.** An ACS `allow` creates no ECL authority
  ([AC1-003](../render/acs-binding-1.html#AC1-003)), and no AARM decision,
  receipt or other artifact releases an action by itself
  ([AB1-002](../render/aarm-binding-1.html#AB1-002)); where a receipt or chain
  disagrees with the ECL evidence, the evidence governs and the disagreement is
  reported ([AB1-008](../render/aarm-binding-1.html#AB1-008),
  [AC1-009](../render/acs-binding-1.html#AC1-009)).
- **Fail open.** ACS negotiates `on_decision_failure` as `deny`, a decision
  failure ends in the safe state
  ([AC1-006](../render/acs-binding-1.html#AC1-006)), and an expiry or silence
  releases nothing ([AC1-007](../render/acs-binding-1.html#AC1-007),
  [AB1-005](../render/aarm-binding-1.html#AB1-005)).
- **Hold more than the authorization.** An R9 credential carries no more
  authority than the ECL authorization and is not held by the governed AI system
  ([AB1-012](../render/aarm-binding-1.html#AB1-012)), and R8 telemetry is a
  copy, never the record a claim relies on
  ([AB1-011](../render/aarm-binding-1.html#AB1-011)).

MCP traffic that the Observed Agent wraps in ACS also meets MCP-GATEWAY-1 where
it leaves for its server ([AC1-011](../render/acs-binding-1.html#AC1-011)).

### Worked example

From
`conformance/suites/acs-binding/acs-valid-hook-carried-guardian-actor-supplied.json`:

```json
{
  "guardian": {"channel": "hook", "result": {"decision": "allow", "metadata": {"evaluator": "deterministic"}}},
  "inputs": [
    {"class": "verifiable", "effect": "supports", "input": "urn:example:input:records-policy", "required": true, "status": "available"},
    {"class": "actor_supplied", "effect": "none", "guardian": true, "input": "urn:example:input:acs-guardian-decision", "required": false, "status": "available"}
  ],
  "on_decision_failure": "deny"
}
```

The deterministic `allow` came through a hook in the agent's process, so it is
`actor_supplied` with no effect, and the `admit` rests on the `verifiable`
records policy ([AC1-004](../render/acs-binding-1.html#AC1-004),
[ECL1N-0180](../render/ecl-1_standard.html#ECL1N-0180)). In
`conformance/suites/aarm-binding/aarm-valid-judgment-source-admit.json` the AARM
decision appears once, as an R4 `judgment` input
([AB1-006](../render/aarm-binding-1.html#AB1-006)).

## 7. What none of them holds

| Not held | By | Requirements |
|---|---|---|
| A credential, token, key or connection that reaches a point of effect without passing the enforcement point | The governed AI system, its tools and any hook in it | [ECL1N-0033](../render/ecl-1_standard.html#ECL1N-0033), [MG1-009](../render/mcp-gateway-1.html#MG1-009), [OA1-004](../render/oauth-authority-1.html#OA1-004), [AB1-012](../render/aarm-binding-1.html#AB1-012), [TE1-001](../render/transactional-effect-1.html#TE1-001); checklist item [EA-25](../render/ecl-1_standard.html#1133-enforcement-and-action-controls) |
| A key that signs decision responses, evidence events, observations or time attestations, or a way to invoke one except through its component | The governed AI system | [ECL1N-0156](../render/ecl-1_standard.html#ECL1N-0156); one role per key, [ECL1N-0157](../render/ecl-1_standard.html#ECL1N-0157), [TP1-009](../render/trust-policy-1.html#TP1-009); the inventory, [ECL1N-0155](../render/ecl-1_standard.html#ECL1N-0155); from `L2`, non-exportable keys and recorded signing, [ECL1N-0160](../render/ecl-1_standard.html#ECL1N-0160) |
| The power to change the policy, the register, the reachable tool manifest, an enforcement configuration, the trust policy or a detection response without another person's review | Anyone, its author included | [ECL1N-0170](../render/ecl-1_standard.html#ECL1N-0170), [ECL1N-0166](../render/ecl-1_standard.html#ECL1N-0166) |
| A power to rewrite, disable or bypass a control responsibility, its evidence and signing records included | The governed AI system | [ECL1N-0032](../render/ecl-1_standard.html#ECL1N-0032), [ECL1N-0046](../render/ecl-1_standard.html#ECL1N-0046), [ECL1N-0160](../render/ecl-1_standard.html#ECL1N-0160), [FR-001](../render/ecl-1_standard.html#FR-001) |
| Write access to a source of a `verifiable` input | The governed AI system | [ECL1N-0178](../render/ecl-1_standard.html#ECL1N-0178) |
| Unilateral change to control approval or evidence verification, in a `Class B` or `Class C` claim | The governed AI system and ordinary operators | [ECL1N-0143](../render/ecl-1_standard.html#ECL1N-0143) |

## 8. The evidence a buyer's verifier must be able to check

A buyer, or an assessor for one, verifies a signed bundle with no network path
to its producer ([EBMP2-057](../render/ebmp-2.html#EBMP2-057)); from `L2` the
evidence is verifiable outside the primary control plane
([FR-108](../render/ecl-1_standard.html#FR-108)).

### What the verifier takes from its caller

The current trust policy and its earlier versions, the evaluation time and the
verification profile. A bundle selects no trust roots and no profile
([TP1-001](../render/trust-policy-1.html#TP1-001),
[EBMP2-067](../render/ebmp-2.html#EBMP2-067)), and an offline package's carried
material is evidence, never a trust anchor
([IE1-021](../render/integrity-envelope-1.html#IE1-021),
[IE1-022](../render/integrity-envelope-1.html#IE1-022)).

### What every producer makes checkable

- Envelopes that verify under keys accepted for each object's role and
  principal, at the object's own time and at the evaluation time
  ([TP1-004](../render/trust-policy-1.html#TP1-004),
  [TP1-005](../render/trust-policy-1.html#TP1-005),
  [TP1-006](../render/trust-policy-1.html#TP1-006),
  [TP1-010](../render/trust-policy-1.html#TP1-010)).
- Pairing by identity ([EBMP2-058](../render/ebmp-2.html#EBMP2-058)); bindings
  of responses ([DCMP2-044](../render/dcmp-2.html#DCMP2-044) to
  [DCMP2-051](../render/dcmp-2.html#DCMP2-051)) and events
  ([EBMP2-047](../render/ebmp-2.html#EBMP2-047) to
  [EBMP2-054](../render/ebmp-2.html#EBMP2-054)); every predecessor of every
  object, observations included, present in the bundle with its digest, since a
  signed bundle declares no external dependency
  ([EBMP2-023](../render/ebmp-2.html#EBMP2-023),
  [EBMP2-059](../render/ebmp-2.html#EBMP2-059)).
- A decision basis on every response
  ([DCMP2-053](../render/dcmp-2.html#DCMP2-053)), a discharge record for every
  release with deferred obligations
  ([EBMP2-070](../render/ebmp-2.html#EBMP2-070)), release times inside the
  window ([EBMP2-050](../render/ebmp-2.html#EBMP2-050),
  [EBMP2-072](../render/ebmp-2.html#EBMP2-072)), and use counts and MCP bindings
  that agree ([EBMP2-073](../render/ebmp-2.html#EBMP2-073) to
  [EBMP2-075](../render/ebmp-2.html#EBMP2-075)).

### What the verifier reports

- One verdict, `invalid`, `incomplete`, `current-trust-failed` or `verified`
  ([EBMP2-060](../render/ebmp-2.html#EBMP2-060)), its primary finding by stage
  ([EBMP2-068](../render/ebmp-2.html#EBMP2-068)), and each effect's level,
  `none`, `issuer-asserted` or `corroborated`
  ([EBMP2-061](../render/ebmp-2.html#EBMP2-061)).
- Its scope: `established`, the checks made that held, and `not_established`,
  the rest, which always includes that recorded times are true, that effects
  occurred, that the deployment was assessed and that the bundle's statements,
  the enforcement point's included, are true; that list is shown wherever a
  verdict is shown to a person ([EBMP2-076](../render/ebmp-2.html#EBMP2-076)).
- It reports no check that it did not make as passed, and keeps verification of
  an assertion apart from corroboration of the event
  ([ECL1N-0194](../render/ecl-1_standard.html#ECL1N-0194); checklist item
  [VF-12](../render/ecl-1_standard.html#1135-verification-and-fleet-controls)).

### Worked example

From `conformance/fixtures/evidence/trust-policy.json`, two of its four keys:

```json
{
  "keys": [
    {"key_id": "urn:example:key:bundle-agent", "principal": "urn:example:agent:test-1", "purposes": ["ecl.purpose.decision-request.v1"], "suite_id": "ecl.sig.ed25519.v1"},
    {"key_id": "urn:example:key:bundle-ep", "principal": "urn:example:ep:test", "purposes": ["ecl.purpose.evidence-event.v1"], "suite_id": "ecl.sig.ed25519.v1"}
  ],
  "policy_id": "urn:example:trust-policy:bundle"
}
```

Each key has one principal and one purpose
([TP1-005](../render/trust-policy-1.html#TP1-005),
[TP1-009](../render/trust-policy-1.html#TP1-009)). Under this policy the public
verifier (`web/verifier/index.html`, or `ecl-verify-ts`) reports
`conformance/fixtures/evidence/succeeded.json` as `verified`, with a `succeeded`
effect at `issuer-asserted`. It establishes `envelope-signatures`,
`current-trust`, `object-rules`, `decision-basis-recorded`, `bindings`,
`release-within-authority` and `causal-completeness`, and leaves `trusted-time`,
`recorded-times-true`, `effects-occurred`, `deployment-assessed` and
`statements-true` not established; `decision-basis-register` is not listed,
since it applies only when a register is supplied
([EBMP2-076](../render/ebmp-2.html#EBMP2-076)). `tampered.json` is `invalid`;
`corroborated.json` has a `corroborated` effect, and `effects-occurred` is still
not established ([EBMP2-061](../render/ebmp-2.html#EBMP2-061),
[EBMP2-076](../render/ebmp-2.html#EBMP2-076)).

## 9. Three claims kept apart

A bundle's records make different claims, and verification does not merge them
([EBMP2-076](../render/ebmp-2.html#EBMP2-076)).

- **An authorization says what may happen, under which conditions:** one request
  and action, an audience, a window and a use policy
  ([DCMP2-013](../render/dcmp-2.html#DCMP2-013),
  [DCMP2-044](../render/dcmp-2.html#DCMP2-044) to
  [DCMP2-050](../render/dcmp-2.html#DCMP2-050)). It does not show that
  Enforcement honored it (DCMP-2, section 9;
  [EBMP2-076](../render/ebmp-2.html#EBMP2-076)).
- **An enforcement record says what the control mechanism checked and
  released.** The consumption, preparation, release and discharge records are
  the enforcement point's statements
  ([EBMP2-004](../render/ebmp-2.html#EBMP2-004),
  [EBMP2-071](../render/ebmp-2.html#EBMP2-071)); a verifier checks their
  completeness and agreement and a carried proof's signatures and digest, not
  that the proof meets its obligation or that a time is true
  ([EBMP2-070](../render/ebmp-2.html#EBMP2-070),
  [EBMP2-076](../render/ebmp-2.html#EBMP2-076)).
- **An effect record or outside observation says what happened.** A terminal
  event is its producer's statement, corroborated only by a separately keyed
  observer ([EBMP2-015](../render/ebmp-2.html#EBMP2-015),
  [EBMP2-061](../render/ebmp-2.html#EBMP2-061)).

No component presents one as another: a gateway does not report a server's
success as its own observation ([EBMP2-015](../render/ebmp-2.html#EBMP2-015)), a
verifier does not report an asserted time or obligation as checked
([ECL1N-0194](../render/ecl-1_standard.html#ECL1N-0194)), and a receipt, session
chain or log record never shows that an action was authorized or released
([AB1-008](../render/aarm-binding-1.html#AB1-008),
[AB1-011](../render/aarm-binding-1.html#AB1-011),
[AC1-009](../render/acs-binding-1.html#AC1-009)).

## 10. How a component shows that it meets the contract, and what it may claim

- **The tests for its role.** The suites `mcp-gateway`, `oauth-authority`,
  `acs-binding`, `aarm-binding` and `binding-basis` hold passing and failing
  records, and a component's records are checked as theirs are, by schema and
  then by the profile's rules ([MG1-012](../render/mcp-gateway-1.html#MG1-012),
  [OA1-010](../render/oauth-authority-1.html#OA1-010),
  [AC1-010](../render/acs-binding-1.html#AC1-010),
  [AB1-009](../render/aarm-binding-1.html#AB1-009)). Its DCMP-2 and EBMP-2
  messages pass strict parsing, schema, semantic, critical-extension and
  integrity checks ([ECL1N-0118](../render/ecl-1_standard.html#ECL1N-0118);
  checklist item
  [EA-26](../render/ecl-1_standard.html#1133-enforcement-and-action-controls)).
  What no record can show, such as the absence of another path or credential, an
  assessor checks by procedure ([MG1-001](../render/mcp-gateway-1.html#MG1-001),
  [MG1-009](../render/mcp-gateway-1.html#MG1-009); checklist item
  [EA-25](../render/ecl-1_standard.html#1133-enforcement-and-action-controls)).
- **A component's test result.** The conformance tests that apply to a
  component show, for a named version, whether it meets the connection
  requirements of this contract for its role. That result says nothing about a
  deployment's evidence or enforcement, and it is not a conformance claim: a
  claim declares a System of Interest, boundary class and level
  ([ECL1N-0009](../render/ecl-1_standard.html#ECL1N-0009),
  [ECL1N-0073](../render/ecl-1_standard.html#ECL1N-0073),
  [ECL1N-0074](../render/ecl-1_standard.html#ECL1N-0074)), and only a mediation
  claim provides the ECL-1 guarantee (Section 2.5).
- **What a component may say.** A statement about a component names it, its
  version, its role and the date, with the ECL-1 core version and companion
  version set that a claim declares
  ([ECL1N-0087](../render/ecl-1_standard.html#ECL1N-0087)), and states no level
  or claim status, which belong to a claim about a System of Interest
  ([ECL1N-0078](../render/ecl-1_standard.html#ECL1N-0078)). "ECL-1 compliant"
  alone is no claim ([ECL1N-0078](../render/ecl-1_standard.html#ECL1N-0078);
  checklist item
  [PR-05](../render/ecl-1_standard.html#1136-procurement-and-reporting-controls));
  no statement presents conformance as legal compliance or certification
  ([ECL1N-0027](../render/ecl-1_standard.html#ECL1N-0027),
  [ECL1N-0084](../render/ecl-1_standard.html#ECL1N-0084)), merges results,
  severities, status and procurement decisions into one label
  ([ECL1N-0081](../render/ecl-1_standard.html#ECL1N-0081)), or implies a
  framework owner's endorsement
  ([ECL1N-0128](../render/ecl-1_standard.html#ECL1N-0128)).

## 11. What this contract does not cover

- **Any one implementation.** Nothing here describes or depends on a
  particular decision service, enforcement engine or MCP gateway. Where a requirement
  states a mechanism, such as the release order of
  [MG1-014](../render/mcp-gateway-1.html#MG1-014) or the journal of
  [MG1-016](../render/mcp-gateway-1.html#MG1-016), its text is what an
  implementation meets, and an alternative meets it when the assessor finds an
  equivalent security and governance effect
  ([ECL1N-0061](../render/ecl-1_standard.html#ECL1N-0061),
  [ECL1N-0062](../render/ecl-1_standard.html#ECL1N-0062),
  [ECL1N-0183](../render/ecl-1_standard.html#ECL1N-0183)).
- **The decision service's internals,** beyond what its responses and their
  decision basis show ([ECL1N-0040](../render/ecl-1_standard.html#ECL1N-0040),
  [ECL1N-0181](../render/ecl-1_standard.html#ECL1N-0181)).
- **The enforcement engine,** beyond the profile its claim relies on
  ([ECL1N-0185](../render/ecl-1_standard.html#ECL1N-0185),
  [ECL1N-0186](../render/ecl-1_standard.html#ECL1N-0186)).
- **The rest of a claim:** the register, timing case, modes, dependency model,
  key custody, approvals, detections and assessment
  ([ECL1N-0007](../render/ecl-1_standard.html#ECL1N-0007),
  [ECL1N-0097](../render/ecl-1_standard.html#ECL1N-0097),
  [ECL1N-0101](../render/ecl-1_standard.html#ECL1N-0101),
  [ECL1N-0192](../render/ecl-1_standard.html#ECL1N-0192),
  [ECL1N-0155](../render/ecl-1_standard.html#ECL1N-0155),
  [ECL1N-0174](../render/ecl-1_standard.html#ECL1N-0174),
  [ECL1N-0167](../render/ecl-1_standard.html#ECL1N-0167),
  [ECL1N-0148](../render/ecl-1_standard.html#ECL1N-0148)).
