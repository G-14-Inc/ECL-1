# ECL MCP Gateway Profile 1

Requirement-IDs: compiled
Version: 1.0
Status: normative profile of ECL-1 Version 1.0, a published version

This profile places an ECL enforcement point between a governed AI system and the
Model Context Protocol (MCP) servers it uses. The gateway receives every request
that the governed AI system sends to an in-scope server. For each side-effecting
request it builds a DCMP-2 decision request from a declared mapping, forwards
the request only on a verified `admit` for exactly that request, returns a
defined MCP error otherwise, and records the result in signed EBMP-2 evidence.
The decision request binds the request's complete `params` by digest, and the
gateway forwards the request exactly as it received it (MG1-004, MG1-005). Its
release boundary is the write of the forwarded request to the server's
transport: before that write it proves every obligation that the admit leaves to
Enforcement (MG1-013), and it checks the authorization's validity, and the
freshness of every proof, at a final observation of its clock taken after every
step that can block (MG1-014). One gateway instance owns an evidence directory
at a time, and recovery settles each journal once (MG1-016).
The governed AI system holds no credential for the servers or for the systems
their tools reach, so that, with the placement and path rules of MG1-001, the
gateway is the only path to an effect. A change to a server's tools is a
control change that waits for review.

The profile adds requirements to a claim that declares it. It removes none of
the core requirements or of the requirements of DCMP-2, EBMP-2, DCMP2-HTTP-1 and
TRUST-POLICY-1.

Requirement identifiers are allocated in the order requirements were added and
never reused, so a later identifier appears among earlier ones where its subject
belongs: MG1-013 to MG1-015 follow MG1-007, and MG1-016 and MG1-017 follow
MG1-012.

## Pinned sources

The machine-readable record of these pins is `conformance/binding-sources.json`.

| Source | Revision | File | SHA-256 |
| --- | --- | --- | --- |
| MCP specification revision 2026-07-28, the revision that https://modelcontextprotocol.io/specification/latest names | `modelcontextprotocol/modelcontextprotocol` tag `2026-07-28`, commit `5f5440bb26a62e2cf3440b92da5a667efa03b267` | `schema/2026-07-28/schema.json` | `ef70b61f99b6d2e5e3b46863822eab08dff6a45bedc7a08914e0e5b133f40203` |
| Tools | same commit | `docs/specification/2026-07-28/server/tools.mdx` | `ed550806a58eb7744b858fb9f26001aa5e55dac9e2babe88317cc81d9d4c490d` |
| Base protocol, error codes and `_meta` | same commit | `docs/specification/2026-07-28/basic/index.mdx` | `ce6b16e0b22544bb7efc201b09906b5f3efb6d55a83881766b36b8a71cfbeb95` |
| Multi round-trip requests | same commit | `docs/specification/2026-07-28/basic/patterns/mrtr.mdx` | `a8671eb2a0d292c0dcbae19666ff4fc3d97f294ce8107e9f38259cc5a02a066b` |
| Streamable HTTP transport | same commit | `docs/specification/2026-07-28/basic/transports/streamable-http.mdx` | `22574bf11e004068493787203ce92be1162107cad717bcb805a15780d4fa69c9` |
| Tasks extension (`io.modelcontextprotocol/tasks`) | same commit | `docs/extensions/tasks/overview.mdx` | `7f33873a3d20d58ccfcd3162db21b073e21c5ab34d5242887703217ce7eeb62c` |
| RFC 8785, JSON Canonicalization Scheme, for the digests of MCP content | https://www.rfc-editor.org/rfc/rfc8785.txt | `rfc8785.txt` | `63d52294eb0e3f0014174288186d388b4ddbf2c67d1ce8af1d9726eb0c3ab240` |

In the pinned revision MCP has no protocol-level session and no `initialize`
handshake; every request carries its protocol version in `_meta`. The only
notification that the pinned schema defines for a client to send is
`notifications/cancelled` (`ClientNotification`). A
`tools/call` can return an `InputRequiredResult`, after which the client retries
the call with `inputResponses` and `requestState`. Long-running work uses the
tasks extension, in which `tasks/update` supplies input to a running task.

## Scope and mapping

**MG1-001** — A claim of this profile MUST identify the MCP revision its gateway
implements by the revision and digests that this profile pins, every in-scope
MCP server, and the transports between the governed AI system and the gateway
and between the gateway and each server; every request from the governed AI
system to an in-scope server MUST pass through the gateway, and any other path
from the governed AI system to the server or to a system its tools reach MUST be
closed or disclosed in the Negative Boundary Annex (ECL1N-0008, ECL1N-0038). The
gateway MUST NOT run in a process, container or account that the governed AI
system can start, stop or configure, or in which it can execute code.

**MG1-002** — The gateway MUST treat as side-effecting, and send to the Decision
Layer before forwarding, every `tools/call` request (including a retry that
carries `inputResponses` or `requestState`), every `tasks/update` request for a
task that a governed tool call created, and every other request that the
Consequential Action Register maps to a consequential action class, such as a
`resources/read` that discloses non-public data. It MUST refuse, with code
-31007, every request whose method the claim neither maps to an action class
nor lists as forwarded without a decision, and every `tools/call` for a tool
that has no mapping. The claim MAY list `server/discover`, the list requests of
the pinned revision (`tools/list`, `resources/list`, `resources/templates/list`
and `prompts/list`) and `subscriptions/listen` as forwarded without a decision,
unless the register classifies them as consequential, and MUST NOT list any
other request. The claim MAY list for forwarding without a decision only
notifications that the pinned revision defines for a client, and MUST NOT list
one that the register maps to a consequential action class; the gateway MUST
NOT forward any other notification from the governed AI system. As JSON-RPC 2.0
requires, it returns no response to a notification.

**MG1-003** — Each in-scope tool MUST have a mapping declared with the
Consequential Action Register that names the server (identifier, name and
version), the tool name, the `ecl.digest.sha-256.v1` digest of the RFC 8785
canonical form of the tool definition as reviewed, the action class, the
operation, the rule that derives the target from the call's arguments, and the
evidence profile; the gateway MUST take the action class, operation and target of
the decision request from that mapping, and never from the governed AI system's
request or from the tool's own annotations.

**MG1-004** — The decision request MUST carry the call's `arguments` object,
read from its RFC 8785 canonical form, as `action.parameters`, with
`action.parameters_digest` its digest under DCMP2-007, and MUST carry the
registered extension `ecl.ext.mcp-binding.v1`, marked critical, naming the
server, the tool, the tool-definition digest and the mapping, and the digests of
any `inputResponses` and `requestState` that the call carries; the gateway MUST
refuse, and not forward, a call whose arguments, read from their RFC 8785
canonical form, are outside the restricted canonical JSON profile (IE1-001). A
decision point that evaluates such a request MUST check that the mapping and the
tool-definition digest it names are the reviewed ones that its register holds
for that server and tool, and MUST NOT admit the request otherwise. The decision
request MUST also carry, in `ecl.ext.mcp-binding.v1`, `params_digest`: the
`ecl.digest.sha-256.v1` digest of the RFC 8785 canonical form of the call's
complete `params` object, `_meta` included. The gateway MUST refuse with -31007,
and not forward, a request that has a member other than `jsonrpc`, `id`,
`method` and `params`, or whose `id` or `params` holds a number that RFC 8785
does not represent exactly: a number of magnitude greater than 2^53 - 1, beyond
the range [-(2^53)+1, (2^53)-1] that RFC 7493 section 2.2 gives for exact
integers, or any other number whose RFC 8785 form does not have the value
written.

## Forwarding and refusal

**MG1-005** — The gateway MUST forward a side-effecting request only after it has
verified a DCMP-2 `admit` for exactly that request under DCMP2-HTTP-1 and the
claim's trust policy, only within its use policy, only after it has discharged
every pre-release obligation of the admit (MG1-013), and only through the
release order of MG1-014, at a final observation of its clock that is no
earlier than the authorization's `valid_from` and that, with the release guard
added, is earlier than its `valid_until`; it MUST forward exactly the call that
the admitted request binds: the forwarded request's `method` and `params` MUST
be the call's, `params` MUST have the digest `params_digest`, and the gateway
MUST NOT add, remove or change any member of the call. The gateway counts the
uses of an authorization in the instance that holds them, so a deployment MUST
route every use of an authorization through one gateway instance, or share the
use store among its instances by a mechanism that this profile does not
specify, so that the count of ECL1N-0186 item 3 covers every instance.

**MG1-006** — For every request that it does not forward, the gateway MUST return
a JSON-RPC error response with the code that the error table of this profile
gives for the cause and a `data.ecl` member naming the cause and its registered
reason, and MUST NOT return a `result`; the codes lie outside the range that
JSON-RPC 2.0 reserves (-32768 to -32000), as the pinned MCP text asks of
application-defined errors. When more than one cause holds, the gateway MUST
return the code of the first that holds in this order: -31007, -31008, -31004,
-31005, then the code of the decision's outcome (-31001, -31002 or -31003), then
-31010, -31011 and -31006. A pre-release obligation that the gateway has not
discharged when it refuses is unproven, so the refusal of an admit that carries
one is -31010, whether or not its authorization is also unusable. A record
cannot show that the gateway's journal failed (-31011, MG1-017), so a checker
that reads a record whose refusal is -31011 checks only that no earlier cause
holds.

**MG1-007** — When the decision service cannot be reached, does not answer
within the declared total timeout, or answers with anything other than a
verified decision response for the request, the gateway MUST NOT forward the
request, MUST return the error for an unavailable or invalid decision, and MUST
NOT retry within the decision attempt (DHB1-007, DHB1-008). A decision response
that does not carry exactly one `ecl.ext.decision-basis.v1`, or whose decision
basis fails DCMP2-053 with the record's `decision_request` as the request it
answers, with the response clock-skew allowance of the reference verification
profile, zero (DCMP2-047), is not a verified decision response, and a record
that holds such a response as an answered decision MUST be reported with
`ecl.rule.decision-basis-one-way.v1`. Each DCMP-2 message that the record holds,
other than the `response` of a `decision` whose `status` is `invalid`, MUST
satisfy the semantic rules of DCMP-2, and a record that holds one that fails a
rule MUST be reported with that rule.

## Release boundary and pre-release obligations

**MG1-013** — Before it releases a request, the gateway MUST discharge each
obligation of the admit whose `satisfaction` is `before_release` and each
`witness_result` of `ecl.ext.consequence-coupling.v1` whose `outcome` is
`required_before_release` (DCMP2-017). For each, it MUST obtain a proof that is
authenticated under the claim's trust policy as issued by a principal that the
claim accepts for that obligation, never the governed AI system, and, for an
approval record, signed only by keys that the trust policy marks with
`ecl.purpose.approval.v1`; that names this
decision request by its `message_id`, with the request's digest or the digest of
its action; that is fresh under the rule that the claim declares for the
obligation's type, both when the gateway checks it and at the final observation
of MG1-014; and that the gateway has not used for another release. It MUST check
the proof with the verifier that the claim declares for the obligation's type.
The claim MUST declare the obligation types its gateway discharges, with the
verifier, the accepted issuers and the freshness rule of each. The gateway MUST
refuse with -31010, and forward nothing, when the admit carries a pre-release
obligation of a type that the claim does not declare, or when a proof is absent,
not authenticated, bound to another request, stale or already used, or fails its
check. It MUST NOT treat the recognition of an obligation's type, or the signed
`admit` itself, as a proof. A deferred witness that an
`ecl.obligation.verify-witness.v1` obligation of the admit names is discharged
with that obligation's proof, and any other deferred witness as an obligation of
that type whose value is the witness's URI. The gateway MUST record the
discharge in the `execution_released` event, in
`ecl.ext.obligation-discharge.v1`, with an entry for each obligation and each
deferred witness as EBMP-2 EBMP2-070 gives them, and in the record's
`obligation_discharge`. Each entry MUST give `fresh_until`, the instant after
which the proof no longer shows the obligation met, whenever the proof's type
declares a freshness bound, and MUST NOT give one later than the proof declares:
for an approval record, no later than the `expires_at` of the
`human_intervention` event; for a witness result, the proof's `observed_at` plus
the maximum age that the claim declares for the witness; a proof of a type that
declares no bound has no `fresh_until`. The gateway MUST carry each proof that
is an ECL object, a signed envelope of a registered type, in the evidence bundle
of the exchange, a witness's `verification` event among its `observations` and
any other proof among its `envelopes`, with the entry's `reference` naming that
object and its `digest` the object's digest (EBMP2-070); a proof that is not an
ECL object is recorded by its kind, reference and digest only.

**MG1-014** — The gateway's release boundary is the write of the forwarded
request to the server's transport. Its effect boundary is the server's execution
of the call, which comes after the release boundary and which the gateway does
not observe, so a check at the release boundary does not show that the
authorization was valid when the server acted (ECL1N-0185, ECL1N-0188). An admit
whose obligation list names one obligation `id` more than once fails the
gateway's reading of the decision: the gateway MUST refuse it with -31005 before
step 1 and consume no use. On a verified `admit` the gateway MUST take these
steps in this order, and MUST NOT write the request unless every step passes:
(1) under a lock that orders it with every other use of the same authorization,
after it holds the lock, read a monotonic clock and then its wall clock and,
only when the wall reading is no earlier than the authorization's `valid_from`,
the reading plus the release guard is earlier than its `valid_until`, and the
use policy allows another use, consume one use; (2) record `authority_consumed`;
(3) record `release_prepared`, which names the attempt; (4) discharge the
pre-release obligations (MG1-013); (5) under the lock, read the monotonic clock
first and the wall clock after it, so that a pause between the two readings
shortens what remains of the window and never extends it; the wall reading is
the final observation, and the gateway MUST release only when it passes the test
of step 1 and, with the release guard added, is earlier than every `fresh_until`
of the discharge, and MUST refuse with -31006 and the outcome reason
`ecl.error.clock-regressed.v1` when the final observation is earlier than the
wall reading of step 1, or when the wall time elapsed since step 1 differs from
the monotonic time elapsed since step 1 by more than the release guard; (6)
record `execution_released`, whose `observed_at` is the final observation and
whose `release_guard_ms` is the release guard, and then write the request. The
release guard is the bound that the claim declares on the delay from the final
observation to the write. Immediately before the write, after the connection to
the server is open, the gateway MUST check that the time elapsed since the final
observation, measured by the monotonic clock, is within the release guard and
that the final observation plus that time is earlier than `valid_until` and
than every `fresh_until`, and MUST NOT write the request otherwise. When it
refuses after
step 1, the gateway MUST record an `execution_terminal` event in state
`cancelled`, with no side effect, a `residual_state` stating that the request
was not written, and the registered reason of the refusal in
`ecl.ext.outcome-reason.v1`, since a non-release state would contradict the
consumed authority (EBMP2-053); it returns -31010 when a proof is stale at step
5, whether or not the authorization is also unusable, and -31006 when the
authorization would not be valid at the write, when the write would not begin
within the release guard, or when the clock regressed. A failure
of the evidence sink at any of these steps ends the attempt as MG1-017 gives,
and nothing is written to the server before `execution_released` is durable.

**MG1-015** — The `forwarded_at` of a record MUST be the final observation of
MG1-014, the time that the `execution_released` event records: the last reading
of the gateway's clock before the release, after which the release, the write of
the request, begins within the declared release guard. The gateway MUST NOT
record an earlier sample, such as the time of the check of step 1, as the time
of the forward or of the release, and MUST record the guard it applied as
`release_guard_ms` of the `execution_released` event and as
`release_guard_milliseconds` of the record. Immediately after the write to the
transport returns, the gateway MUST measure by the monotonic clock the time
elapsed since the final observation and, when the final observation plus that
time is at or after `valid_until`, MUST set `released_after_valid_until` to
`true` in the `ecl.ext.mcp-binding.v1` of the terminal event and mark the
extension critical (EBMP2-071); it MUST NOT set that member from the time at
which the server answered, and a checker MUST report a record whose terminal
carries it set to `true`. When the server's answer arrives, whatever it is, the
gateway MUST observe its clock and record that observation as
`forward_completed_at` in the record's `forwarded` member and in the extension
of the terminal event. A `forward_completed_at` at or after `valid_until` is a
completion after the window: a verifier reports it beside its verdict, and it is
not by itself a finding (EBMP2-072).

## Change control and credentials

**MG1-008** — A tool added to or removed from an in-scope server's tool list, a
change to any member of a tool definition, and a change of the server's name or
version in `io.modelcontextprotocol/serverInfo` MUST be treated as a control
change that requires review under ECL1N-0170: the gateway MUST compare the
current definition, obtained from `tools/list`, with the mapped digest before it
forwards a call, and MUST refuse calls to a changed or added tool, and to every
tool of a server whose identity or version changed, until the change is reviewed
and the mapping updated.

**MG1-009** — The governed AI system MUST NOT hold a credential, token, key or
connection that reaches an in-scope server or a system that one of its tools
reaches; the gateway, or a credential broker behind it, MUST hold that material,
MUST use it only for forwarded requests, and MUST NOT pass a credential that the
governed AI system presents to the gateway on to a server.

## Evidence and records

**MG1-010** — The gateway MUST record EBMP-2 evidence for each side-effecting
request as an enforcement point: for a forwarded request, `authority_consumed`,
`release_prepared`, `execution_released`, which carries the discharge of MG1-013
when the admit carries a pre-release obligation, and an `execution_terminal`
event that carries `ecl.ext.mcp-binding.v1` with the `ecl.digest.sha-256.v1`
digest of the RFC 8785 canonical form of the response the server returned and
the forward's completion (MG1-015); for a refused request, an
`execution_terminal` event in the non-release state that EBMP2-051 gives, or in
state `cancelled` when the gateway consumed the authorization before it refused
(MG1-014). The response the gateway returns to the governed AI system for a forwarded request
MUST be the response whose digest the evidence records, with one exception: the
gateway MUST NOT return a server error that uses a code of the error table, and
returns such an error with its `error.code` replaced by -32603 and every other
member unchanged.

**MG1-011** — The gateway MUST authenticate the decision service and each
in-scope server with TLS under trust anchors that its operator configures, with
plain HTTP only on the loopback interface and only when explicitly enabled for
testing; it MUST NOT follow redirects from either, and MUST apply the
DCMP2-HTTP-1 limits to decision exchanges and declared limits to MCP messages
before parsing them.

**MG1-012** — A gateway that retains exchange records MUST write each one as
`ecl_mcp_gateway_exchange_v1`, valid against
`https://externalcontrollayer.ai/ns/schema/binding/mcp-gateway-exchange/1`, and
every value of `ecl.ext.mcp-binding.v1` it emits MUST validate against
`https://externalcontrollayer.ai/ns/schema/extension/mcp-binding/1`. A record
member that holds MCP content (`call`, `tool_definition`, the `request` of
`forwarded`, `server_response` and `returned`) MUST hold it as the JSON object
itself when the content, read from its RFC 8785 canonical form, lies within the
restricted canonical JSON profile (IE1-001), and otherwise as an object whose
only member, `rfc8785`, is the canonical base64, with padding, of the content's
RFC 8785 canonical bytes. A checker MUST treat a record as failing its schema
when such a member does not decode to the RFC 8785 canonical form of a JSON
object that lies outside the restricted profile, or when the content it decodes
does not satisfy the definition that the record schema gives the same content
held as itself (`jsonRpcRequest` for the call and the forwarded request,
`jsonRpcResponse` for the server's response and the response returned, and
`toolDefinition` for the tool definition), and otherwise MUST apply this
profile's rules to the content it decodes.

**MG1-016** — A gateway that retains exchange records MUST record each EBMP-2
event of a side-effecting request in a journal, together with the exchange
record and the signed decision messages once the decision is known, and MUST
make each entry durable, by flushing the journal file and, when it creates the
file, its directory to storage, before it takes the step that the entry
evidences. The gateway MUST hold an exclusive lock on its evidence directory,
taken before it reads, settles or writes any journal there and held for as long
as it can write there, so that one instance at a time owns the directory; a
gateway, a recovery command or a library caller that finds the lock held MUST
stop before it reads or writes anything else in the directory. It MUST create
the evidence directory and the directories of its journals, records and bundles
accessible to its own account only, and MUST flush each new directory into its
parent. One journal holds exactly one exchange: only the entry that opens the
exchange creates its journal, and every later entry is appended to the journal
that exists; when no journal exists for an entry before `execution_released` has
been journaled, the gateway MUST refuse the request with -31011 and restore the
use, and after `execution_released` it MUST report the condition and still
record the terminal event from what it holds in memory; an opening entry for a
journal that already exists MUST be refused with -31011 before any use is
consumed. The gateway MUST keep an exchange's journal until the exchange's
record and evidence bundle are durable, and MUST NOT delete a journal when it
recovers. When it starts, under the lock, it MUST settle each journal that
remains by what the journal holds, never by what it lacks, and MUST NOT retry
the request. It MUST first truncate an incomplete final line, as the gateway
also does before it appends to a journal. An exchange whose journal holds
`execution_released` and no `execution_terminal` event has an unknown outcome,
recorded by a terminal event in state `unknown` with no side effect known and a
`residual_state` that states the uncertainty; an exchange whose journal holds no
`execution_released` was not sent, and is recorded as `cancelled` after an
`admit` and in the non-release state that the decision gives otherwise; and an
exchange whose journal holds its terminal event keeps it. A journal that does
not open with the entry that opens an exchange, that holds entries of more than
one exchange, or that cannot be parsed beyond an incomplete final line is
damaged: recovery MUST keep it in place, list it in its report with the reason,
settle nothing from it and restore no use. For each journal that it settles,
recovery MUST append to the journal, and make durable, an entry that records its
decision, the outcome and the identifiers of the records it will write, before
it writes any record or bundle, and an entry that records completion after it
has written them; a journal with a recorded decision and no completion MUST be
completed from the decision, and a journal with a recorded completion MUST be
skipped. Record identifiers MUST derive from the journal, from the exchange's
identity and the entry's kind, so that a repeated recovery writes the same
files; a record that already exists under its identifier MUST be left as it is
and never signed again, and recovery MUST NOT produce a second signed terminal
event for one exchange. A terminal event that recovery records MUST carry
`recovered_at` in its `ecl.ext.mcp-binding.v1`, and its record MUST carry
`recovery`, with the time of the recovery and what the journal showed. The claim
MUST declare which of these failures its journal survives: the exit of the
gateway's process, a crash of its host, a failure of its storage, and the loss
of an evidence service that it writes to.

**MG1-017** — When the gateway cannot make durable an entry that MG1-016
requires before the release, because a write or a flush fails, its storage is
exhausted or its evidence sink fails in any other way, it MUST NOT release the
request and MUST NOT take the step that the entry would evidence, and it MUST
return -31011 unless an earlier cause of MG1-006 holds. The gateway MUST catch
every error that the evidence sink raises, so that none ends the exchange with a
use consumed and no terminal recorded. When the failure comes after the use was
consumed, the gateway MUST restore the use and record the attempt as `cancelled`
when the journal can take the entry; when it cannot, the journal shows
`release_prepared` without `execution_released`, which recovery settles as not
released. Once `execution_released` is durable, a failure of the sink MUST NOT
stop the write: the gateway reports the failure, and the records that it could
not write are produced by the next recovery from the journal. Only a release
that was durably journaled and whose terminal event is missing is recorded as
`unknown` on recovery.

## Error table

The gateway returns these codes in the JSON-RPC `error` member, with
`data.ecl.code` set to the name in the second column and `data.ecl.reason` set
to a registered reason or error identifier. For a refusal that a decision
carries, `data.ecl.request_id` names the DCMP-2 request, and `data.ecl.reason`
is left out when the response carries no reason. The row of -31009 is not a
refusal: it reports a forwarded request whose response never arrived. When several
causes hold, MG1-006 gives the order: a request that has no mapping is refused
as not mapped before anything else is checked, and a decision is asked for only
when the tool and the server's identity still match the reviewed mapping. A
server's own error never carries one of these codes to the governed AI system
(MG1-010), so a code of this table always means what the table says.

| Code | `data.ecl.code` | Cause | `data.ecl.reason` |
| --- | --- | --- | --- |
| -31001 | `denied` | The decision is `deny` | The response's first reason code, when it has one |
| -31002 | `held` | The decision is `hold` | The response's first reason code, when it has one |
| -31003 | `challenged` | The decision is `challenge` | The response's first reason code, when it has one |
| -31004 | `decision-unavailable` | The decision service is unreachable, silent past the timeout or answers with a status other than 200, or the signed decision request exceeds the envelope cap of DCMP2-HTTP-1 (DHB1-003) | `ecl.error.dependency-unavailable.v1` |
| -31005 | `decision-invalid` | The response fails signature, purpose, principal, schema, semantic or binding checks, such as a decision basis that breaks DCMP2-053, or names one obligation `id` more than once (MG1-014) | `ecl.error.dependency-response-invalid.v1`, `ecl.error.integrity-invalid.v1` or `ecl.error.request-binding-invalid.v1`; `ecl.error.dependency-response-invalid.v1` for a repeated obligation |
| -31006 | `authorization-unusable` | The admit is verified, but its authorization is not yet valid, has expired, would expire within the release guard of the gateway's observation or before the write of the request, or the write could not begin within the release guard after the final observation, or is used up, or the gateway's wall clock read earlier at its final observation than at its first check, or disagreed with its monotonic clock by more than the release guard (MG1-014) | `ecl.error.expired.v1`, `ecl.error.replay.v1` or, for a regressed clock, `ecl.error.clock-regressed.v1` |
| -31007 | `not-mapped` | No mapping for the tool or method, arguments that are not a JSON object, null included, or that lie outside the restricted canonical profile in their RFC 8785 form, arguments from which the mapping derives no target, a member of the request that no decision binds, or a number in its `id` or `params` that RFC 8785 does not represent exactly (MG1-004) | `ecl.error.binding-unsupported.v1` |
| -31008 | `unreviewed-change` | The tool list, a tool definition or the server identity differs from the reviewed mapping | `ecl.error.control-change-unreviewed.v1` |
| -31009 | `forward-failed` | The request was forwarded and no response arrived within the forwarding timeout, so its effect is unknown | `ecl.error.dependency-unavailable.v1` |
| -31010 | `obligation-unproven` | The admit carries an obligation whose `satisfaction` is `before_release`, or defers a state witness, that the gateway did not discharge: its type is not one that the claim declares, or its proof is absent, not authenticated, bound to another request, stale when checked or no longer fresh at the final observation, already used, or fails its check (MG1-013, MG1-014) | `ecl.error.obligation-unproven.v1` |
| -31011 | `evidence-unavailable` | The gateway cannot make durable an event that must precede the release: a write or a flush of its journal fails, its storage is exhausted or its evidence sink fails, or the exchange's journal is missing or already exists when the gateway opens it (MG1-016, MG1-017) | `ecl.error.evidence-unavailable.v1` |

## Evidence states (informative)

| Server response | `execution_terminal` state |
| --- | --- |
| A result with `resultType` `complete` and `isError` false | `succeeded`, as the server reports it (EBMP2-015) |
| A result with `isError` true, or a JSON-RPC error | `failed` |
| An `InputRequiredResult`, or a task handle | `unknown`, with `residual_state` naming the input request or task; the retry or the task's later result is a new request |
| No response within the forwarding timeout, or a broken stream | `unknown`, with `residual_state` stating that the effect is uncertain |
| No write: the gateway consumed the authorization and then refused, for an unproven obligation or one whose proof was no longer fresh at the final observation, a failed final check, a regressed clock, a journal that failed or an evidence sink that failed (MG1-014, MG1-017) | `cancelled`, with no side effect, `residual_state` stating that the request was not written and the refusal's reason in `ecl.ext.outcome-reason.v1` |
| Recovery: the journal holds `execution_released` and no terminal event (MG1-016) | `unknown`, recovered, with `residual_state` stating that the outcome is not known |
| Recovery: the journal holds no `execution_released` (MG1-016) | `cancelled` after an admit, otherwise the non-release state of the decision, recovered |
| Recovery: the journal is damaged, since it does not open with the exchange's first entry, holds more than one exchange or does not parse beyond a torn final line (MG1-016) | None: the journal is kept and listed with its reason; nothing is settled and no use is restored |

The digest in `ecl.ext.mcp-binding.v1` covers the whole JSON-RPC response
object, so an error response is bound as a result is. A number in the server's
response that RFC 8785 does not represent exactly is bound, and recorded, as the
nearest double. The evidence level of a terminal event is issuer-asserted unless
a separately keyed observer corroborates it (EBMP2-061).

The digests of MCP content (tool definitions, input responses, request state and
responses) are of its RFC 8785 canonical form, which keeps floating-point
numbers. The decision request's `action.parameters_digest` is of the restricted
canonical form (IE1-001), which has none, so a call whose arguments, read from
their RFC 8785 form, hold a number with a fractional part, or an integer beyond
2^53 in magnitude, is refused with -31007 rather than rounded. A number written
with a fraction or an exponent whose value is an integer, such as `2.0` or
`1E+0`, is that integer in RFC 8785 form, so a call that holds one is decided
with the integer, which its record holds (MG1-004, MG1-012). Elsewhere in
`params`, and in `id`, the gateway refuses a number that RFC 8785 does not
represent exactly (MG1-004): it reads such a number as the nearest double, so
the forward would carry another value than the call did, and `params_digest`,
which is of the RFC 8785 form, would bind the rounded value. The gateway sees
such a number only in the text it receives; an exchange record holds MCP content
in RFC 8785 form, in which only a magnitude greater than 2^53 - 1 stays visible.

An exchange record is strict JSON (IE1-002), which also has no floating-point
numbers. MG1-012 therefore holds MCP content outside the restricted profile in
encoded form, so that a call refused for a fractional number in its arguments, a
tool definition whose input schema holds a fractional bound, and a server's
response that holds a floating-point number can all be recorded. The encoded
bytes are the content's RFC 8785 canonical form, the same bytes that its digests
cover. Content held in encoded form satisfies the same definition of the record
schema as content held as itself, so that the encoding carries no call, request,
response or tool definition that the schema would refuse, such as a call with a
null `id`.

When a server answers a forwarded request with a JSON-RPC error whose code is
one of the error table's, such as -31001 for an error of its own, the evidence
binds the server's error as it arrived, and the governed AI system receives the
same error with the code -32603 (MG1-010). Otherwise the governed AI system
could read the server's error as a refusal by the gateway, although the request
was forwarded and may have had an effect.

## Release timing and durability (informative)

The final observation of MG1-014 is the last time the gateway reads its wall
clock before it writes the request; the `forwarded_at` of the record and the
`observed_at` of `execution_released` are that observation, and the event's
`release_guard_ms` is the guard that applied (MG1-015). The observation is the
recorded release time, and the release begins within the guard after it: between
the two the gateway signs the release event, makes it durable and opens the
connection to the server, with a TLS handshake when the server uses TLS. The
gateway does not release when the final observation plus the guard reaches
`valid_until` or the end of a proof's freshness, and immediately before the
write it measures, with a monotonic clock, the time elapsed since the final
observation, and does not write when that time exceeds the guard or when the
authorization or a proof would have ended. The
monotonic clock is read before the wall clock at step 1 and at step 5, so a
pause between the two readings of step 5 only shortens what remains; a wall
clock that reads earlier at step 5 than at step 1, or that disagrees with the
monotonic clock by more than the guard, is refused as regressed, with the reason
`ecl.error.clock-regressed.v1`. A pause of the process after the last
measurement before the write, or a clock that is wrong in a way the two readings
do not show, is not detected before the write. Immediately after the write
returns, the gateway measures the elapsed time again and sets
`released_after_valid_until` when the write may have come late;
`forward_completed_at` is when the server's answer arrived (MG1-015). A late
answer to a timely release is reported by a verifier as a completion after the
window and is not a finding (EBMP2-072): the answer's time says when the server
replied, not when the request was written.

A pre-send observation bounds the delay to the write only by the declared guard,
and it does not establish when the server, or a system that the tool reaches,
acted on the request: the server may queue it, and the effect may occur later in
another system. Authority checked at the point of effect, by the server or by
the system behind it, is outside this profile; a deployment that needs it binds
the authorization to that point by other means.

A journal that meets MG1-016 can be one file per exchange in the evidence
directory, to which the gateway appends each entry and which it flushes to
storage before it takes the step that the entry evidences. The lock of MG1-016
is held by whatever writes the directory, for as long as it can write there: a
gateway that serves requests, a recovery run or a library caller. A second
holder is refused before it reads or writes anything else, so two writers in
one process conflict as two processes do. Only the entry that opens an exchange
creates its journal, and an opening entry for a journal that exists is refused.
A failure or exhaustion of the storage before the release makes the gateway
refuse with -31011, so no request is sent without its evidence; the gateway
catches every error of its sink, and a failure after the use was consumed
restores the use and ends the attempt as `cancelled` (MG1-017). After the
release, such a failure leaves the journal as it stood: the gateway returns the
server's response, since the request may have had its effect, and recovery
produces the records. A deployment that places its evidence directory on
networked storage, or writes to an evidence service, inherits the guarantees of
that storage or service and declares them (MG1-016).

Recovery runs under the lock and settles each journal once. It truncates a torn
final line, classifies the journal, appends an entry that records its decision,
with the outcome and the identifiers of the records it will write, flushes it,
writes the records and the bundle, and appends an entry that records its
completion. A journal with a recorded decision and no completion is completed
from the decision; one with a recorded completion is skipped. Record
identifiers derive from the exchange's identity and the entry's kind, so a
recovery run twice, or stopped and run again, writes the same files, and a
record that exists is left as it is. A journal that does not open with the entry
that opens an exchange, holds entries of more than one exchange, or fails to
parse beyond a torn final line is listed as damaged with its reason and kept;
nothing is settled from it and no use is restored. The write to the server and
the local journal cannot be made one atomic step. A request whose release the
journal holds and whose outcome it does not hold is recorded, after recovery, as
`unknown`, and stays unknown until the server's records or another observation
settle it; the gateway never retries it, since a retry could repeat an effect. A
gateway that holds the use counts of authorizations in memory restores, on
recovery, those that unsettled journals show, and a response binds one decision
request (DCMP2-044, DCMP2-045), so it cannot serve a later call after a restart.
Two instances that each hold a use count for one authorization do not see each
other's uses, which is why MG1-005 routes every use of an authorization through
one instance or a shared use store.

## Exchange record (informative)

An `ecl_mcp_gateway_exchange_v1` record holds one request that the gateway sent
to the Decision Layer or refused; a request that the claim lists as forwarded
without a decision needs no record, nor does a request refused for a number, in
any of its members, that RFC 8785 does not represent exactly, which a record
could not hold as it arrived, and a record that shows a forward is checked as a
request that needed an `admit`. Its members are the in-scope `server` with the
identity it reports; the `call` as received, and when (`received_at`); the
tool's `mapping` and its current `tool_definition` when it has them; the
`decision_request` and the `decision`, whose `status` is `answered`,
`unavailable` or `invalid`; the uses of the authorization before this request
(`prior_uses`); the gateway's release guard (`release_guard_milliseconds`); the
`release_prepared` event (`prepared`), the discharge of the pre-release
obligations (`obligation_discharge`) and the `execution_released` event
(`released`), which carries `release_guard_ms`, when the gateway reached those
steps; a `forwarded` member, with
`forwarded_at` and `forward_completed_at`, only when the gateway released the
request; the `server_response`; the response `returned` to the governed AI
system, and when (`returned_at`); the `terminal` event; and, in a record that
recovery wrote, `recovery`, which such a record holds in place of `returned`.
The members that hold MCP content may be in the encoded form of MG1-012. The
rules registered for this profile, whose names begin `ecl.rule.mcp-`, check a
record after its schema.

## Security considerations

The gateway's guarantee rests on two facts that an assessor checks: no other path
reaches the servers or the systems behind them (MG1-001, MG1-009), and the
gateway's decision path cannot be altered by the governed AI system, because
the gateway runs outside everything that system can execute code in or control
(MG1-001). Tool
descriptions and annotations are text that a server controls and that a
language model reads; a changed description can carry instructions, which is
why a change waits for review (MG1-008) and why annotations never choose the
action class. The call's complete `params` are bound by digest, so an admitted
request cannot be forwarded with other arguments, with other `_meta` members or
with a member that changes how the server runs it, such as a task, and the
authorization's use policy prevents a second forward. A member outside `params`
and a number that RFC 8785 would round reach no decision at all: the gateway
refuses the request first (MG1-004). The error data names a cause and a registered reason only, so a
refusal does not return policy details to the governed AI system. An obligation
that the decision leaves to Enforcement, such as a state witness or a human
approval, is proven before the release by a proof that names the request and
that the governed AI system cannot issue (MG1-013): recognizing the obligation
does not prove it. The release order checks the authorization after every step
that can block, so a slow evidence store or a wait for a lock cannot carry an
expired authorization to the server (MG1-014), and every event is durable
before the step that it evidences (MG1-016). One instance owns an evidence
directory at a time, so a second instance cannot settle a running instance's
exchanges as not written, and recovery settles each journal once, so a repeated
or interrupted recovery leaves one signed terminal event (MG1-016). The clock is
read twice at step 5, monotonic first, so a wall clock stepped back between the
first check and the release does not extend the window (MG1-014), and a proof's
freshness is tested at the release, not only when the proof is obtained
(MG1-013).

## Conformance

| Kind | What the citation establishes |
| --- | --- |
| Vectors | The `mcp-gateway` suite holds a passing record for each row of the error table, each with the error that row gives, and passing records of a refused request whose method the claim neither maps nor lists, of a call refused for the first of two causes, of a call whose arguments hold a number with a fractional part or lack the argument the target comes from, of a call whose `arguments` is null, refused although its mapping gives a fixed target, of a server error returned with -32603, of content held in the encoded form, and of a call whose `id` holds a Unicode noncharacter, which puts the call and both responses in the encoded form, and refusals of a call with a member that no decision binds and of a call whose `_meta` holds a number that RFC 8785 rounds. It refuses a forward while the decision service is unavailable, without an `admit`, after the authorization expired, a second time under a single-use authorization, with arguments, a method, a tool or an `id` other than the call's and the admit's, among them the `id` `"1"` for a call whose `id` is 1 and the `id` `true`, which the record schema refuses, or with a member that the call did not carry; a forward on an answered `admit` whose decision basis breaks DCMP2-053, or that carries no decision basis; a decision request for a call with a member outside `params` or a number of magnitude greater than 2^53 - 1, and one that declares a negative budget debit; a forward of an unlisted method, or to a tool that has no mapping or whose definition changed after review; a decision request whose class or parameters do not come from the mapping and the call, whose `params_digest` does not cover a `_meta` member of the call, or that lacks the binding extension; a refusal returned as a result, with another code, with the code of a later cause or with an `id` other than the call's, among them the `id` `"1"` for a call whose `id` is 1; a forwarded response that the evidence does not bind, among them one returned with `0` where the server's response holds `false`, that the governed AI system did not receive, that reaches it with a code of the error table, or whose state the evidence misreads; a result returned for a forward that the server never answered; and encoded content that is not canonical base64, not the RFC 8785 form of its content, content within the restricted profile, or content that the record schema would refuse when held as itself: a call with a null `id`, forwarded without one or refused with an error that has none, and a call forwarded with the `jsonrpc` 1.0. For the release path (MG1-013 to MG1-017) the suite holds passing records of a forward whose two obligations and deferred witness are discharged, of the release order, of a refusal at the first check of an obligation that no declared verifier checks, of cancelled attempts after an unproven obligation, a failed final check and a journal that failed, with and without a recorded prepared release, and of recovered records of an unknown outcome and of a request that was not released; it refuses a forward on an admit with obligations whose release records no discharge, or a discharge without the deferred witness or the approval; a refusal of an undischarged obligation with -31006 or -31011; a release within the release guard of the window's end; a `forwarded_at` earlier than the release that the evidence records; a send that completed after `valid_until`, marked or not; a cancelled refusal recorded as `expired_before_release`, and a refusal at the first check recorded as cancelled; a recovered record of an unknown outcome that claims success, or whose classification is not one that the schema lists; and a record without the response returned. The suite also holds a refusal, with -31005 and no use consumed, of an admit that names one obligation twice; cancelled attempts whose proof was no longer fresh at the final observation (-31010), whose clock regressed (-31006 with `ecl.error.clock-regressed.v1`) and whose write could not begin within the release guard after the final observation (-31006); a release whose event carries `release_guard_ms`; and a forward written inside its window whose answer arrived after `valid_until`, recorded with `forward_completed_at` after the window and without `released_after_valid_until`; it refuses a release event without `release_guard_ms` and a discharge entry whose `fresh_until` is not later than the final observation plus the guard |
| Deployment tests | A gateway's tests of its release path, with faults injected at each step of the release order and of the journal: a run on the real clock, crashes at each step followed by recovery, failures and exhaustion of its storage, two instances on one evidence directory, two writers of one evidence directory in one process and threads on one authorization, damaged journals of each class, a recovery stopped after its decision, run twice and run concurrently, a torn last line, a stale approval and an over-age witness at the release, a clock stepped back between the first check and the final observation and between the two readings of step 5, the evidence sink failing at each step, a full and a read-only directory, and a late answer inside the window; `docs/bindings.md` lists what each of these tests must observe |
| Assessor procedure | Path enumeration and the absence of credentials in the governed AI system, transport configuration and change review; the declared release guard, obligation types and their verifiers, the failures that the journal survives, and the statement that every use of an authorization passes through one instance or a shared use store (MG1-005, MG1-013, MG1-014, MG1-016; the assessment area `mcp-release-order-and-journal-declarations` of `conformance/requirement-evaluations.json`) |
