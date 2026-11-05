# Threat-model summary

This guide is informative. It adds no requirement, and where it and a
requirement differ, the requirement governs. The normative threat model is
Section 9 of the [core standard](../standard/ECL-1_Standard.md): the threat
scope (9.1), the baseline adversary model (9.2), the threat categories and their
layered controls (9.3), the security requirements (9.4) and the custody of
evidence-signing keys (9.8). This guide adds threats that the one-way rule, the
binding profiles, the key roles of TRUST-POLICY-1 and the release boundary
address. Each entry states the threat as it applies to any implementation, the
requirements that mitigate it and what remains.

## The one-way rule and the binding profiles

These entries cover the one-way rule, the five binding profiles and the
key-role rule of TRUST-POLICY-1. The binding entries cite the requirements of
the profiles in `profiles/` by their identifiers.

### Steering a judgment input

The governed AI system, or anyone who controls content that it reads, can
shape the inputs that a probabilistic detector scores (intent alignment,
semantic drift, a risk score), and it writes the inputs it produces itself,
such as a self-report. Under the one-way rule these `judgment` and
`actor_supplied` inputs can make a decision stricter but are never the reason
for an `admit`, which rests on policy over `verifiable` inputs whose authority,
authenticity and transition checks the governed AI system cannot alter or bypass
(ECL1N-0041, ECL1N-0164 and ECL1N-0165, and the
statement of the rule in ECL1N-0178 to ECL1N-0182, whose decision basis a
response records in `ecl.ext.decision-basis.v1` under DCMP2-053).

What remains: a steered input can still cause holds and denials, a loss of
availability rather than a release. The rule protects only as far as the
Consequential Action Register classes each input correctly. A source declared
`verifiable` that merely stores or signs an actor-controlled assertion defeats
it. An independently validated authoritative state transition is different:
an admitted debit can change a ledger balance without letting the actor invent
that balance. An assessor checks the authority, transition validation, freshness,
selection and completeness against the reachable capability inventory
(ECL1N-0008, ECL1N-0164, ECL1N-0178).

### MCP-GATEWAY-1: gateway bypass and changed tools

The governed AI system reaches an MCP server, or a system behind one of its
tools, by a path that skips the gateway or with a credential of its own. Or a
server changes a tool definition after review, adds a tool or changes its
identity, so that a mapped call now does something else, or a changed
description carries instructions to the model. Or the governed AI system stops,
reconfigures or runs code inside the gateway, sends a request that no mapping covers, or reads a
server's own error as the gateway's refusal. Or the gateway forwards members that no decision
covered, such as a `_meta` entry or a task that changes how the server runs the call. Mitigations: every request passes
through the gateway and any other path is closed or disclosed in the Negative
Boundary Annex, and the gateway runs in no process, container or account that
the governed AI system can start, stop or configure or execute code in
(MG1-001, ECL1N-0038, ECL1N-0046); a request that the claim neither maps nor
lists among the six discovery and list requests is refused, and an unlisted
notification is not forwarded (MG1-002); the governed AI system holds no
credential for an in-scope server (MG1-009); the mapping fixes the digest of
the reviewed definition, the action class and target come from the mapping,
never from the request or the tool's annotations (MG1-003), and the decision
point admits only under the mapping and definition digest that its register
holds (MG1-004); a changed or added tool, or a changed server identity, is
refused until it is reviewed (MG1-008, ECL1N-0170); the decision request binds
the digest of the call's complete `params`, and only exactly that call is
forwarded, within its use policy (MG1-004, MG1-005); an unreachable decision
service, or a response whose decision basis breaks DCMP2-053, ends in refusal
(MG1-007); a refusal carries the code of the first
cause in a fixed order (MG1-006); and a server error that uses a code of the
error table reaches the governed AI system with -32603 (MG1-010). The core rules
are ECL1N-0033, ECL1N-0046 and ECL1N-0141.

What remains: the gateway compares definitions, not behavior. A server that
behaves differently from its reviewed definition is outside the boundary; its
effects are limited to the admitted target and parameters.

### ACS-BINDING-1: the fail-open default

As ACS-BINDING-1 reads the pinned ACS text, the handshake member
`on_decision_failure` defaults to `proceed`, and an `ask` can declare a
`timeout_disposition` of `allow`. A Guardian that is slow, unreachable or cut
off would then let actions go ahead, and a hook in the agent's own process can
be disabled by the agent. ACS-Core signs with an HMAC under a key that the
Observed Agent holds, so such a hook can also forge the Guardian's decision that
it carries. Mitigations: a decision failure at an ECL enforcement point ends in
the declared safe state whatever posture was negotiated, a claim negotiates
`deny` and sets the startup posture to `refuse`, and a failure includes a
timeout, a transport failure, an error response, an unmapped disposition, a
decision for another request, a Guardian signature that does not verify and a
decision that arrives after the safe state was applied (AC1-006); an expired
`ask` or `defer` releases nothing, and the response expires no later than the
Guardian's deadline into a safe state that permits no new effect (AC1-007); only
a signed DCMP-2 `admit` releases an action, and a Guardian `allow` creates no
ECL authority (AC1-003); a hook point in a process, container or account where
the governed AI system can execute code, or that it can start, stop or
reconfigure, is never claimed as an ECL enforcement point and only carries the
Guardian's decision to an ECL decision point (AC1-002, ECL1N-0046); a
deterministic Guardian decision that a hook carried is `actor_supplied`, only
one that the decision point obtains from the Guardian directly or authenticates
by the Guardian's own signature can be `verifiable`, and one from an `agent` or
`composite` evaluator, or that states no evaluator, is a `judgment` input
(AC1-004, ECL1N-0178); the new request for a modified action describes the
original action with other parameters, carried as the same JSON values, only a
`modify` has a new request, and a modification that changes the action's target
or operation cannot be applied and ends with no new request (AC1-005); and the
exchange record's inputs, classes and digests are those that the ECL response
records as its decision basis, which satisfies DCMP2-053, and the decision basis
of the response to a modified action carries the same register reference and
records the same inputs with the same declarations (AC1-012). The core rules are
DCMP2-041, FR-003 and TS1-009.

What remains: an adversary who can delay or drop Guardian traffic causes
denials. No ACS liveness method is mapped, so a silent Guardian is detected only
when the decision timeout expires. An exchange record does not show how a
deployment derives an action's target from its arguments. A checker accepts the
record of a modification that ends with no new request and no release, whatever
the reason, and a modification that changed the argument naming the target and
went ahead is found by an assessor against the deployment's mapping, not by a
checker of the record.

### OTEL-EVIDENCE-EXPORT-1: leakage through exported attributes

Telemetry pipelines reach more people and systems than the evidence store. An
exporter that copies action parameters, tool arguments, results, credentials,
tokens, signatures or reason text into a record discloses them, a consumer may
read a record, its severity or its absence as evidence of authorization, and an
export failure could block or change a decision. Mitigations: none of that data
leaves unless the export policy declares the attribute and its data class, and
no undeclared attribute or body is emitted (OE1-005, EBMP2-034, EBMP2-035); the
identifiers of people and records, `ecl.actor.id`, `ecl.subject.id` and
`ecl.action.target`, also leave only when the export policy declares them
(OE1-005); telemetry is a copy and never the evidence (OE1-001); no record
carries a digest that can be computed without a secret, such as the SHA-256
digest of the object or the parameters digest it carries (OE1-004), because a
reader who can list the possible parameter values (an amount, a short list of
accounts) could compute each candidate's digest and confirm which one was used;
with the deployment's export key, the object's digest and its parameters digest
are HMAC-SHA-256 under that key, each the `stringValue` of 64 lowercase
hexadecimal digits that a consumer without the key still checks, and without one
no digest is exported (OE1-010); each attribute key appears once, so that no
reader takes a first attribute of a key that no check saw (OE1-003); nothing is
inferred from severity or absence (OE1-008); and an export failure changes no
decision, release or evidence (OE1-002).

What remains: the exported object identifiers and outcomes still describe
activity, and a declared identifier of a person or record tells every reader of
the pipeline who acted or on what. A reader who obtains the export key can confirm guesses as an unkeyed digest
would allow, so the key's custody, an assessor check, decides how far the keyed
digests protect. The `object_id` of an EBMP-2 event is derived from its content
(EBMP2-047) and is exported as its identifier; a reader would need every member
of the event, including the digests of the objects it references, which no
record carries, to confirm a guess through it. Without an export key, a
consumer matches records to the bundle by identifier only.

### OAUTH-AUTHORITY-1: token replay and audience confusion

An access token that expresses ECL authority is copied and presented again, at
another resource server, after the authorization expired or was revoked, or with
another request; or a verifier accepts a token whose header chooses its own key
or algorithm. Mitigations: `aud` is exactly the authorization's audience
(OA1-002); the token's validity lies inside the authorization window, with a
short maximum lifetime (OA1-003); the token is sender-constrained by DPoP or
mutual TLS to a key the governed AI system cannot read, the DPoP proof's
signature is verified with the key it carries before that key is compared with
the token's confirmation, which names the key by a string, and a repeated DPoP
`jti`, or a proof without a `jti` of 1 to 256 characters, which no record of the
`jti` values seen could hold, is refused (OA1-004); the clock-skew allowance on
`nbf` and `exp` is none unless the claim declares one, within the profile's
bound, and the presentation must fall inside the ECL entry's window with no
allowance (OA1-003); target, operation and parameter digest must match, the use
policy is enforced in one store that every resource-server instance shares, and
other entries cannot widen the authority (OA1-005); algorithms, keys and issuers
come from the verifier's own configuration, a token names its key by `kid`, and
every token and proof segment is canonical base64url read as strict JSON, so
that a parser difference cannot change a time claim and two token strings cannot
carry one signature (OA1-007); a refusal names the code of the first check that
fails (OA1-011); and tokens are issued only for a verified `admit` and stop
working within the revocation propagation bound (OA1-008). The core rules are
DCMP2-044, DCMP2-048 to DCMP2-050 and FR-104.

What remains: replay protection for DPoP proofs and use counts depends on the
shared store that every instance of the resource server reaches, which an
assessor checks, and a revoked token stays usable until the propagation bound
of the declared timing case has passed (ECL1N-0097).

### AARM-BINDING-1: a compromised or manipulated judgment source

An AARM control plane, or a model behind its context accumulation, intent
alignment or semantic distance, is compromised or steered by the content it
evaluates and returns ALLOW or a favorable score for an action that policy over
verifiable inputs would not admit; or an AARM receipt is offered as proof that
an action was authorized. Mitigations: the R2, R3 and R7 outputs, and the AARM
decision in the judgment-source role, which the record lists once as an R4
input, are `judgment` inputs and never the basis of an `admit` (AB1-006); ALLOW
maps to `admit` only when policy over `verifiable` inputs permits the action
(AB1-003); only a signed DCMP-2 response bound to the exact request releases an
action (AB1-002); a receipt cannot establish authorization or release (AB1-008);
an interception point where the governed AI system can execute code, or that it
can start, stop or reconfigure, is never claimed as an ECL enforcement point and
only carries an AARM decision to an ECL decision point (AB1-010, ECL1N-0046); a
credential issued under R9 carries no more authority than the ECL authorization
(AB1-012); the new request for a modified action describes the original action
with other parameters, carried as the same JSON values, only a MODIFY has a new
request, and a MODIFY that changes the action's target or operation ends in
`deny` with no new request (AB1-004); and the exchange record lists each input
with the class and digest that the response's signed decision basis records, so
a record cannot class an output as `judgment` while the basis rests an `admit`
on it as `verifiable`, that basis satisfies DCMP2-053, and the decision basis of
the response to a modified action carries the same register reference and
records the same inputs with the same declarations (AB1-013). The entry on
steering a judgment input applies as well.

What remains: where the AARM control plane implements the Decision Layer
(AB1-002), its response-signing key is a decision point key, and whoever holds
it can sign decisions as the decision point does (Section 9.3). A checker
accepts the record of a MODIFY that ends with no new request and no release,
whatever the reason; a MODIFY that changed the parameter from which the
deployment derives the target and went ahead is found by an assessor against the
deployment's mapping, since the exchange record does not show the derivation.

### TRUST-POLICY-1: one key in two roles

A trust policy gives one key both the decision-request and the
decision-response purposes, or another pair of roles. The holder of a
requester's key, an enforcement point or, where requests are agent-signed, the
governed AI system, can then sign a decision response that standalone envelope
verification counts, since both purposes sign the DCMP-2 media type.
Mitigations: a verifier refuses a trust policy whose
key carries more than one of the decision-request, decision-response,
observation and trusted-time purposes (TP1-009, ECL1N-0157); envelope
verification under a trust policy, standalone or within a bundle, counts a
decision request only under a key with the decision-request purpose and a
decision response only under a key with the decision-response purpose
(TP1-010); and the bundle verifier refuses a signer without the object's
purpose (TP1-004).

What remains: a trust policy does not say who holds a key, so whether the
governed AI system holds a requester's key that also carries the evidence-event
purpose, which ECL1N-0156 forbids, is an assessor check. A challenge, a
challenge response or a control message has no purpose of its own, so
standalone verification binds it to its media type only, and its role check
stays with the bundle verifier.

### Hostile input to parsers and verifiers

Malformed, truncated, reordered and adversarial input reaches the RFC 8785
canonicalizer, the envelope and bundle verifiers, the offline package verifier
and the validation of decision messages. Mitigations: a signed payload first
satisfies the restricted canonical JSON profile (IE1-001); every parser,
verifier and offline-package processor runs under a declared profile of finite
resource limits (IE1-028), enforces them before unbounded allocation,
decompression, recursive traversal or cryptographic work, and fails closed on
malformed input or a limit violation with a stable error, never with a
partially verified artifact (IE1-029); archive processing rejects paths and
members that could alias or leave the package (IE1-030) and departures from the
deterministic package format (IE1-031); a verifier refuses a bundle that
exceeds its declared limits before it verifies signatures (EBMP2-062) and
derives causal order from authenticated references, not from the order of the
bundle (EBMP2-029); and an unknown critical extension is rejected (XR1-006).

What remains: the limits bound the work that an input can cause, and the values
a verifier declares decide how much work that is. A defect in a parser is found
by testing that parser with such input, which each implementation does for its
own code.

## Attacks on the release path

These attacks need no forged signature, and the evidence of some of them
verifies. Each entry states the attack as it applies to any enforcement point,
the requirements that mitigate it and what remains.

### An obligation deferred to enforcement is ignored

A decision service admits an action with an obligation that enforcement has to
prove before release: an owner's approval, or a state witness whose result is
`required_before_release`. An enforcement point that checks only the
signature, the binding and the window releases the action without the proof.
Anyone who benefits from the witness being stale or wrong, or from the approval
never being sought, needs to forge nothing: the admit is genuine. Mitigations:
an obligation with `before_release` satisfaction is proven at enforcement before
release, and an unproven one converts the disposition to the declared safe
state (DCMP2-017); the enforcement point establishes every such obligation at
the release boundary, by proof that is authentic, bound to the action, fresh
and of a kind it supports (ECL1N-0186); missing, unsupported, stale, failed or
wrongly bound proof prevents the release, and neither a signed admit, nor
recognizing the obligation's type, nor a proof of valid form that was not
checked counts as satisfaction (ECL1N-0187); and a verifier does not present an
obligation that it did not check as passed (ECL1N-0194).

What remains: an enforcement point satisfies only the obligation kinds it
supports, and refuses the others, so an unsupported kind costs availability.
Whether a proof's issuer may vouch for the obligation is a matter of the trust
policy. A verifier sees only what the evidence records, and cannot tell from a
signed event that the enforcement point examined the proof it names.

### Authority expires between the check and the release

An attacker who can slow an operation that runs between the enforcement
point's check of the authorization window and the release, such as a stalled
evidence sink, a slow signer, contention for a lock or a scheduling pause, has
the action released after its authorization expired. If the release record
took its time before the delay, the evidence shows a release inside the window
and the bundle verifies. Mitigations: an event's observation time is the time
of the release boundary under the declared clock policy, never an earlier
decision, preparation, construction or recording time; work that can block
between the last check and the release lies inside the declared timing
argument, by a check at the release boundary with nothing that can block
before the release, an enforced bound on the delay that the check allows for,
or a check at the point of effect; and an action whose authority cannot be
established as usable at the release boundary is not released (ECL1N-0188).
An `execution_released` event whose time lies outside the authorization's window
makes the bundle invalid (EBMP2-050), and a verifier keeps the producer's
asserted time apart from an independently established one (ECL1N-0194). A
transaction that admits and commits on one store under
TRANSACTIONAL-EFFECT-1 makes every check at one admission instant while it
holds the exclusion that TE1-002 requires, and its events carry that instant.

What remains: a check at the release boundary shows that the authority was
usable when the release happened, not when a remote effect happened. A gateway
cannot show that the server acted before the authorization expired; that needs
a check at the point of effect, such as a resource server's check of a token
under OAUTH-AUTHORITY-1. Clock policy and skew still apply to every reading. An
event's time is the producer's statement unless a trusted-time countersignature
attests it (INTEGRITY-ENVELOPE-1 section 9), and no verifier can establish from
the evidence alone when a call was sent.

### An effect without durable evidence

The enforcement point's process ends, or its evidence storage fails or fills,
after an effect and before the evidence of it is durable, so an action happened
of which no record survives; an attacker who can end the process at that moment
hides an action. A gateway that keeps its use counts only in memory can also,
after a restart, accept again an authorization it already used. Mitigations:
before the release, the enforcement point durably preserves the attempt's
identity, the authority and use it consumes, and its binding to the request;
after a covered failure it classifies every outstanding attempt as executed,
not executed or unresolved, and infers none of them, and no reusable authority,
from a missing terminal record; an unresolved attempt stays recorded as such
and is not retried automatically unless the point of effect applies each effect
at most once (ECL1N-0189); the claim declares which of process exit, host crash,
storage failure and loss of the evidence service its recovery information and
evidence survive (ECL1N-0190); the evidence capacity that the claim requires is
available before the release (ECL1N-0186); and evidence buffering declares its
capacity, durability and overflow, never drops verifier-critical events
silently, and recovers what it buffered (TS1-021 to TS1-024). Under
TRANSACTIONAL-EFFECT-1 the evidence of an effect is committed in the
transaction that commits the effect, so a failed signature rolls both back
(TE1-004).

What remains: a local journal cannot be made atomic with a remote call. An
attempt journaled as released whose response was lost stays unresolved until
the server's record, an authoritative status query or a person resolves it,
and a retry can repeat an irreversible effect unless the server applies each
call at most once. A failure outside the declared ones, such as the loss of the
storage that holds the journal where the claim does not cover it, can still
lose an attempt. A retention period keeps evidence that was written; it does
not recover evidence that never was (ECL1N-0050).

### A second instance on the evidence, and a proof stale at the release

Two attacks act on a gateway's recovery and on the freshness of a proof. In
the first, a second gateway instance started on the same evidence directory
settles the running instance's unfinished exchanges as not written and writes a
record and a bundle for each; the first instance then releases the request, and
the only record left when it ends says that the call had no effect. Nothing has
to be forged. Mitigations: one instance at a time owns the evidence directory
under an exclusive lock taken before it reads anything, a second instance stops
before it reads or writes, only the opening entry creates a journal, recovery
records its decision durably before it writes and settles each journal once,
never deleting one, and a journal it cannot read is kept and listed with nothing
settled from it (MG1-016; ECL1N-0189 forbids inferring non-execution from
information recovery cannot read). In the second, an approval that expires just
before the release, or a witness older than its declared maximum age at the
release, lets the call through when the proof is checked only when it is
obtained and not again at the release. Mitigations: the discharge records each
proof's `fresh_until`, the gateway tests it at the final observation that
precedes the release (MG1-013, MG1-014; ECL1N-0186, item 6), and a verifier
refuses a release observed, with its guard added, at or after a proof's
`fresh_until` (EBMP2-070). A wall clock stepped back during a blocking step
would extend the window; the gateway reads a monotonic clock before the wall
clock at each check and refuses a regression (MG1-014).

What remains: a gateway counts the uses of an authorization in the instance
that holds them, so two instances that each hold an authorization would each
release once under it; a deployment routes every use of an authorization
through one instance or shares the use store (MG1-005). A proof's freshness
bound is what its type declares; a proof type that declares none is fresh for
as long as the claim's rule says, and the verifier can test only the bound that
the discharge records.
