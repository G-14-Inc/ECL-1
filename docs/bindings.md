# ECL-1 bindings

This guide explains the five binding profiles of ECL-1. Read it if you run one
of these systems beside an ECL-1 deployment: an AARM control plane, an Agent
Control Standard (ACS) Guardian, Model Context Protocol (MCP) servers, an
OpenTelemetry pipeline or an OAuth authorization server. Each profile is a
normative companion of ECL-1 Version 1.0 and applies only to a claim that
declares it. This guide adds no requirements; the profiles in
[`profiles/`](../profiles/) are the text that counts.

## What you need to do

1. Find the profile for the system you run in the table below, and read its
   requirements.
2. Use the revision of the other system that the profile pins. Each profile
   lists its pinned sources with their SHA-256 digests, and
   `conformance/binding-sources.json` holds the same pins in machine-readable
   form.
3. Declare the profile in your conformance claim, with the declarations that
   its first requirement asks for.
4. Have your adapter write its records in the profile's record format, and
   check them with the profile's rules, as the vectors of its suite in
   `conformance/suites/` are checked.
5. For the requirements that no record can show, such as the absence of
   another path to an MCP server, prepare the evidence that the assessment
   procedure of each requirement names in
   `conformance/requirement-evaluations.json`.

## The rule every binding keeps

An ECL-1 deployment releases an action only on an `admit` signed for exactly
that request. The bindings keep that rule: an AARM decision, an ACS `allow`, an
MCP tool annotation, a log record or an OAuth token never releases an action
on its own. These ideas recur across the profiles:

- **Judgment inputs.** Inputs that the governed AI system produces or can
  write, and judgments about meaning or risk, are `judgment` or
  `actor_supplied` inputs under Section 5.2 of the core standard. So is an
  input that reaches the decision point through a channel that the governed AI
  system can write, such as a hook in its own process, unless the decision
  point authenticates the input's origin with a key that the system does not
  hold. They can only make an outcome stricter: an `admit` can become a
  `challenge`, `hold` or `deny`, a `challenge` a `hold` or `deny`, and a `hold`
  a `deny`, never the reverse. They are never the reason for an `admit`, which
  rests on policy over `verifiable` inputs. AARM's intent alignment and an ACS
  Guardian built on a language model are examples.
- **Placement.** A hook, an interception point or a gateway counts as an ECL
  enforcement point only when it runs outside every process, container and
  account in which the governed AI system can execute code or that it can
  start, stop or reconfigure. A component inside them can carry a decision to
  an ECL decision point, and the decision is then enforced elsewhere.
- **Failures.** When the other system does not answer, answers late
  or answers with something that cannot be checked, the action is not
  released. Where the other system's own default would let the action go ahead,
  the profile overrides that default for every action an ECL claim covers.
- **Modifications.** When the other system changes an
  action's parameters, the changed action goes through ECL as a new decision
  request that names the original with `ecl.relation.modification-of.v1`. The
  original is never released, and only a modification has a new request.
- **Evidence.** Receipts, session chains, log records and
  tokens are bound to the signed ECL evidence by digest. When one disagrees
  with the evidence, the evidence governs and the disagreement is reported.

## Choosing a profile

| Profile | Use it when | Conformance suite |
| --- | --- | --- |
| [AARM-BINDING-1](../profiles/AARM-BINDING-1.md) | An AARM control plane decides on, or evaluates, actions that your claim covers | `aarm-binding` |
| [ACS-BINDING-1](../profiles/ACS-BINDING-1.md) | An ACS Guardian reviews the agent's steps through ACS hooks | `acs-binding` |
| [MCP-GATEWAY-1](../profiles/MCP-GATEWAY-1.md) | The governed AI system calls tools on MCP servers | `mcp-gateway` |
| [OTEL-EVIDENCE-EXPORT-1](../profiles/OTEL-EVIDENCE-EXPORT-1.md) | You send ECL decisions and evidence to observability or SIEM tools | `otel-export` |
| [OAUTH-AUTHORITY-1](../profiles/OAUTH-AUTHORITY-1.md) | A resource server that accepts OAuth access tokens enforces ECL authority | `oauth-authority` |

Profiles combine. An AARM deployment that issues OAuth tokens for admitted
actions follows OAUTH-AUTHORITY-1 for those tokens, and its telemetry follows
OTEL-EVIDENCE-EXPORT-1. When ACS wraps MCP traffic, each MCP request also
passes through a gateway under MCP-GATEWAY-1.

## AARM

AARM (Autonomous Action Runtime Management) defines a control plane that
intercepts an agent's actions before they run (R1), accumulates context (R2),
evaluates policy with intent alignment (R3) and returns one of five decisions:
ALLOW, DENY, MODIFY, STEP_UP and DEFER (R4). AARM-BINDING-1 pins AARM 1.0. For
each in-scope action class, your claim says which of two roles the control
plane takes:

- As the ECL Decision Layer, it answers DCMP-2 decision requests itself, with
  signed responses bound to the exact request.
- As a judgment source, it feeds a separate ECL Decision Layer, and everything
  it outputs, its decision included, is a `judgment` input.

ALLOW becomes `admit` only when ECL policy over `verifiable` inputs permits the
action, and `deny` otherwise. DENY becomes `deny`. STEP_UP becomes `challenge`
until an approval is recorded, and DEFER becomes `hold`; when the deadline
passes, nothing is released (AB1-003, AB1-005). MODIFY becomes `deny` of the
original request, and the modified action goes through ECL as a new request for
the same action: it keeps the original request's operation, target, action and
risk classes, actor, subject, authority request, constraints and integrity
policy, and changes only the action's identifier and parameters, so the admit
that releases the modified action is an admit for that action (AB1-004). Its
parameters are the modified parameters as the same JSON values, so a new request
that carries `1` where the MODIFY sets `true` is refused. A MODIFY that changes
the parameter from which your deployment derives the target or operation, such
as the account to be debited, cannot be applied and ends in `deny` with no new
request. Its record, which holds neither a new request nor a release, is valid
to every checker, and a record that holds a response to a new request without
the new request is refused. The exchange record does not show how a deployment
derives its targets, so a checker cannot see a MODIFY that changed the target
and went ahead; an assessor checks this against your mapping. Only a MODIFY has
a new request: a record of any other decision that holds one is refused, so an
action cannot be released under an admit given to a second request.

Context accumulation, policy evaluation with intent alignment, and semantic
distance tracking (R7) work over content that the governed AI system influences,
so the profile treats their outputs as `judgment` inputs in both roles
(AB1-006). The decision records them in `ecl.ext.decision-basis.v1`, which the
core standard defines.
The exchange record lists the entries of the decision basis of its response,
each once, and AB1-013 compares every member of each entry, not only its class
and digest: a record that disagrees with the decision basis of its response is
refused. So the adapter's record cannot class an output as `judgment` while the
signed decision rests on it (AB1-013). In the judgment-source role the record
lists the AARM decision itself once, as an R4 input of class `judgment`, so an
AARM decision listed without its requirement cannot escape that class
(AB1-006).
The response, and the response to a modified action, must also satisfy the
one-way rule of DCMP-2 (DCMP2-053), as it would in a signed evidence bundle: a
record whose response admits while a required input was unavailable, or rests
the admit on an input computed from the intent-alignment score, is refused under
`ecl.rule.decision-basis-one-way.v1`.
The response is checked with its own outcome and `evaluated_at` and with the
request that the record holds, so an admit less strict than the recorded
verifiable-only outcome, an input recorded as available although it was obtained
after the decision, and a `verifiable` input whose source is the requesting
agent are refused as well.
The response to a modified action answers a request for the same action under
the same register version, so its decision basis carries the register reference
of the first response's basis, member for member, and records the record's
inputs, each with the class, required flag, source and `derived_from` that the
record gives it; only the status, effect, reference and times of each input may
differ. If the register version changed between the two decisions, the
modification is not admitted.
A second decision therefore cannot class an input differently from the first, or
treat a required input as optional (AB1-013).

Each AARM receipt (R5) is bound to the action's ECL evidence: the action's
`execution_terminal` event carries `ecl.ext.aarm-receipt.v1` with the receipt's
identifier, its decision and the SHA-256 digest of its RFC 8785 canonical form
(AB1-007). A receipt supports claims about what AARM evaluated. It does not
show that an action was authorized or released; the ECL evidence shows that
(AB1-008).

An AARM interception point where the governed AI system can execute code, or
that it can start, stop or reconfigure, is never claimed as an ECL enforcement
point (AB1-010). It can carry an AARM decision to an ECL decision point, and an
enforcement point outside the governed AI system's reach then enforces the
decision. Telemetry exported under R8 follows OTEL-EVIDENCE-EXPORT-1 (AB1-011),
and a credential issued under R9 carries no more authority than the action's
ECL authorization (AB1-012).

## Agent Control Standard

The OWASP Agent Control Standard (ACS) lets an Observed Agent send its steps,
through hooks, to a Guardian that answers `allow`, `deny`, `modify`, `ask` or
`defer`. ACS-BINDING-1 pins ACS specification 0.1.0 at repository release
0.1.2. The ACS prose is licensed CC BY-SA 4.0, so the profile cites ACS
identifiers and does not reproduce ACS text.

ACS hooks run in the Observed Agent. A hook point in a process, container or
account in which the governed AI system can execute code, or that it can start,
stop or reconfigure, is never claimed as an ECL enforcement point (AC1-002); it
can carry the Guardian's decision to an ECL decision point. A Guardian decision
reaches an ECL enforcement point only through a signed DCMP-2 response from an
ECL decision point. An `allow` creates no ECL authority: the decision point
still applies its own authority, scope, validity, budget and approval checks.
When the Guardian is an `agent` or `composite` evaluator, or states no
evaluator, its decision is a `judgment` input. A deterministic Guardian's
decision that a hook carries to the decision point is `actor_supplied`: the
ACS-Core signature is an HMAC under a key that the Observed Agent holds, so the
governed AI system could forge the decision. Only a decision that the decision
point obtains from the Guardian directly, or whose Guardian signature it
verifies under a key that the governed AI system cannot use, such as an
ACS-Crypto signature under a key that only the Guardian holds, can be
`verifiable`. The exchange record states which in `guardian.channel`
(`direct`, `signed` or `hook`). Such a decision takes the least trusted class
of the inputs that its request carried, which the exchange record names in the
`derived_from` of the Guardian's input, so a decision over SessionContext,
Intent or other content that the governed AI system wrote is `actor_supplied`,
and one whose input names no `derived_from` cannot be `verifiable` (AC1-004).
When the response records the Guardian decision in `ecl.ext.acs-decision.v1`,
exactly one input is marked as that decision. As for AARM, the exchange record
lists the entries of the decision basis that the response records in
`ecl.ext.decision-basis.v1`, AC1-012 compares every member of each entry, and
the response must satisfy DCMP2-053 with the record's request as the request it
answers.

Two ACS defaults would let an action go ahead without a decision. The
handshake member `on_decision_failure` defaults to `proceed`, and an `ask` can
declare a `timeout_disposition` of `allow`. A claim of this profile negotiates
`on_decision_failure` as `deny` and sets the posture for a Guardian that cannot
be reached at startup to `refuse`. At an ECL enforcement point, a Guardian
failure or an expired `ask` or `defer` releases nothing, whatever the handshake
says. A failure is a timeout, a transport failure, an error response, a
disposition that the mapping does not cover, a decision for another request, a
Guardian signature that does not verify, or a decision that arrives after the
safe state was applied (AC1-006, AC1-007). No ACS liveness method is mapped;
the decision timeout bounds a Guardian that stays silent.

A `modify` becomes a new decision request for the parameters after the
modification. The profile states how to compute them from ACS parameter
overrides, redactions and wholesale replacements, and a modification that cannot
be applied releases nothing. The new request describes the same action as the
original, with only the action's identifier and parameters changed, and the
decision basis of the response that admits it records the exchange record's
inputs with their declarations, as for AARM (AC1-005, AC1-012). Its parameters
are the effective parameters as the same JSON values, so a new request that
carries `1` where the Guardian's override sets `true` is refused. A modification
that changes the argument from which your deployment derives the target or
operation cannot be applied either, and ends in `deny` with no new request. Its
record, which holds neither a new request nor a release, is valid to every
checker, and a record that holds a response to a new request without the new
request is refused. The record does not show how the target is derived, so a
checker cannot see a modification that changed the target and went ahead; an
assessor checks this against your mapping, which for an MCP tool is the mapping
of MG1-003. Only a `modify` has a new request: a record of any other decision,
or of a decision failure, that holds one is refused (AC1-005).

The ACS session chain stays an ACS record. The ECL response records, in
`ecl.ext.acs-decision.v1`, the chain hash that the Guardian published for the
step, so a verifier can match the chain to the ECL evidence (AC1-008). A chain
that disagrees with the evidence is reported, and neither record is rewritten to
repair it (AC1-009).

## MCP gateway

MCP-GATEWAY-1 places an ECL enforcement point, the gateway, between the
governed AI system and the MCP servers it uses. It pins MCP revision
2026-07-28. The profile requires that the governed AI system hold no
credential for the servers or for the systems their tools reach, and that the
gateway run in a process, container and account that the governed AI system
can neither start, stop or configure nor execute code in, so that the gateway
is the only way to cause an effect through them (MG1-001). For each
`tools/call`, the gateway:

1. refuses, before any decision, a call that holds, in any member, a number
   that RFC 8785 may not represent exactly, without a record, which could not
   hold the call as it arrived, and a call with a member other than
   `jsonrpc`, `id`, `method` and `params`, with a record of the refusal
   (MG1-004);
2. checks that the tool has a reviewed mapping, and that the tool's current
   definition and the server's name and version still match it;
3. builds a DCMP-2 decision request whose action class, operation and target
   come from the mapping, with the call's arguments as `action.parameters` and,
   in `ecl.ext.mcp-binding.v1`, the digest of the call's complete `params`, its
   `_meta` included; a call without `arguments` has the parameters `{}`, and a
   call whose `arguments` is not an object, null included, is refused with
   -31007 (MG1-004);
4. asks the decision service under DCMP2-HTTP-1 and verifies the signed
   response, which includes the one-way rule of DCMP2-053 for its decision
   basis, and checks that the response carries exactly one decision basis,
   which satisfies DCMP2-053 with the request the gateway sent (MG1-007);
5. proves, before the release, each obligation of the admit whose
   `satisfaction` is `before_release` and each state witness that the admit
   defers to Enforcement (`required_before_release`), with a proof that a
   principal the claim accepts signed for exactly this request, that is fresh
   when it is checked and still fresh at the final observation before the
   release, and that the gateway has not used for another release, checked by
   the verifier that the claim declares for the obligation's type; anything
   else is refused with
   -31010 (MG1-013);
6. forwards exactly the call that the admit binds, in its RFC 8785 form, only
   on an `admit` for that request, within its validity window and use limit and
   only through the release order below, so
   that no member that the decision did not cover, such as a `_meta` entry or a
   task, reaches the server (MG1-004, MG1-005, MG1-014).
   The checker compares the decision request and the forwarded request with
   the call, and with what the admit binds, as the same JSON values and with
   the same members, so an argument forwarded as `1` is not the call's `true`,
   and a forward that leaves out an `id` that the call holds is not the call;
7. records EBMP-2 evidence that binds the server's response by digest, and
   returns that response. A server's own error that uses a code of the
   profile's table reaches the governed AI system with the code -32603, so a
   code of the table always means the gateway's refusal (MG1-010).

When a step fails, the gateway forwards nothing and returns a JSON-RPC error
from the profile's table, codes -31001 to -31008, -31010 and -31011, with the
cause and a registered reason in `data.ecl`. When several causes hold, it
returns the code of the first in the order that MG1-006 gives: -31007, -31008,
-31004, -31005, the decision's outcome, -31010, -31011, then -31006. Code
-31009 reports a forwarded call whose server never answered; the evidence
records its effect as unknown.

The release boundary is the write of the forwarded request to the server's
transport (MG1-014). On a verified admit the gateway takes these steps in order
and writes nothing unless each passes: under a lock, it reads a monotonic clock
and then its wall clock and consumes one use when the authorization is valid at
that time and until the release guard after it; it records `authority_consumed`,
then `release_prepared`, which names the attempt; it proves the pre-release
obligations and records, for each proof, the instant after which it no longer
shows the obligation met (`fresh_until`); it reads the monotonic clock and then
the wall clock again under the lock, the final observation, and releases only
when that observation passes the same test and, with the guard added, precedes
every `fresh_until`, refusing with -31006 and `ecl.error.clock-regressed.v1` a
wall clock that reads earlier than at the first check or that disagrees with the
monotonic clock by more than the guard; and it records `execution_released`,
observed at the final observation and carrying the guard as `release_guard_ms`,
and writes the request. The release guard is the bound that the claim declares
on the delay from the final observation to the write: the recorded release time
is the final observation, and the release begins within the guard after it.
Immediately before the write, after the connection is open, the gateway also
checks, with the monotonic clock, that no more than the guard has elapsed since
the final observation and that the authorization and every proof have not ended.
A refusal after the use was consumed is recorded as a `cancelled` attempt, since
a non-release state would contradict the consumed authority (EBMP2-053); an
admit that names one obligation twice is refused with -31005 before any use is
consumed. The record's `forwarded_at` is the final observation. Immediately
after the write returns, the gateway measures the time elapsed since the final
observation and marks the terminal event `released_after_valid_until` when the
write may have come at or after `valid_until`; `forward_completed_at` is the
time at which the server's answer arrived, and an answer after the window for a
request written inside it is reported by a verifier as `completion_after_window`
beside its scope, not as a finding (MG1-015). Nothing in the profile establishes
when the server, or a system behind it, acted on the request.

Each EBMP-2 event of a side-effecting request, with the exchange record and
the signed decision messages once the decision is known, is journaled before
the step that it evidences, one journal per exchange, each entry flushed to
storage, and the journal is kept until the exchange's record and bundle are
durable (MG1-016). One gateway instance owns an evidence directory at a time: it holds
an exclusive lock on the directory, taken before it reads a journal, and a
second gateway, a recovery command or a library caller that finds the lock held
stops before it reads or writes anything else there. Only the entry that opens
an exchange creates its journal; an append that finds no journal before the
release refuses the request with -31011 and restores the use. When the journal
cannot record an entry before the release, because a write or a flush fails, the
storage is full or the sink fails in any other way, the gateway refuses with
-31011, restores a use it had consumed and writes nothing to the server
(MG1-017). When the gateway starts, under the lock, it settles each journal that
an earlier run left: a journal with `execution_released` and no terminal event
becomes a terminal in state `unknown`, a journal without `execution_released` an
attempt that was not sent, `cancelled` after an `admit`, and a request is never
sent again. Recovery records its decision in the journal before it writes any
record and its completion after, derives record identifiers from the journal and
never signs a terminal twice, so a recovery that is interrupted or repeated
writes the same files; a journal that does not open with its first entry, holds
two exchanges or does not parse beyond a torn last line is kept and listed as
damaged, with nothing settled from it, and recovery deletes no journal. The
claim declares which failures its journal survives: the exit of the gateway's
process, a crash of its host, a failure of its storage and the loss of an
evidence service that it writes to (MG1-016). A gateway that counts the uses of
an authorization in the instance that holds them needs every use of an
authorization routed through one instance, or a use store that its instances
share (MG1-005).

A claim may list `server/discover`, `tools/list`, `resources/list`,
`resources/templates/list`, `prompts/list` and `subscriptions/listen` to pass
through without a decision, and no other request (MG1-002). Every other request
that the claim does not map to a consequential action class is refused with
-31007. A claim may list for forwarding only the notifications that the pinned
revision defines for a client to send, of which there is one,
`notifications/cancelled`, and none that the register maps to a consequential
action class; the gateway forwards no other notification.

A changed tool definition, a new tool, or a change of the server's name or
version is a control change. Calls to the changed tool, or to every tool of a
server whose identity changed, are refused with -31008 until someone reviews
the change and updates the mapping. Tool descriptions are text that a server
controls and a language model reads, which is why a change waits for review
and why tool annotations never choose the action class.

The behavior matrix below lists, for each family of the release path, what a
test of a gateway must observe. Such tests can drive the gateway with a clock
that moves only when the test moves it and with faults injected at each step of
the release order and of the journal, and, where the row says so, on the real
clock or with a second process.

| Test family | Required observation |
| --- | --- |
| A valid proof of each obligation and of the deferred witness (MG1-013) | Forwarded; the release event records one entry for each obligation and one for the witness, and the record passes the checker |
| The bundle carries each proof (MG1-013, EBMP2-070) | The witness's `verification` event among the observations and the approval's `human_intervention` event among the envelopes, each named by the discharge with its digest; the discharge is critical; the bundle verifies, and its scope establishes the discharge record and never that an obligation was met |
| A deferred witness that no obligation names (MG1-013) | Proven as an obligation whose id and value are the witness's URI |
| No obligation policy, an undeclared type, or a witness without a declared source (MG1-013) | -31010 before any use is consumed or any proof is asked for; no upstream call |
| A proof that is absent, stale, for another request, failed or untrusted (MG1-013) | -31010, a cancelled attempt, no upstream call |
| Several obligations, only some proven (MG1-013) | -31010, no upstream call |
| A proof replayed for a later request (MG1-013) | Refused as already used; no upstream call for the later request |
| The proof service (MG1-013, MG1-011) | One request per obligation, with the gateway's credential; an error, a redirect, a body that is not one envelope, an oversized body or no answer is no proof; no retry |
| The declared release guard and obligation types (MG1-013, MG1-014) | Reach the gateway from its configuration; a declared issuer needs a key with its purpose in the trust policy |
| Expiry during each blocking step: the journal entries, the proofs, the lock of the final check (MG1-014) | -31006, a cancelled attempt, no upstream call |
| Expiry after the final observation: the release entry, the connection (MG1-014) | Nothing written; -31006 |
| The exact boundary (MG1-014) | Refused at the release guard before `valid_until`, released one microsecond earlier |
| A wait for the lock (MG1-014) | The clock is read after the lock is held; -31006 with no use consumed |
| Concurrent use of one single-use authorization (MG1-014) | One request written; the other refused as a replay |
| A stall before the write, on the real clock (MG1-014) | Nothing written; -31006 |
| A server answer that arrives after `valid_until` for a request written inside its window, on the real clock (MG1-015) | `forward_completed_at` after `valid_until` and no `released_after_valid_until`, which is the gateway's own observation of its write; the checker reports nothing |
| A stall before the write longer than the release guard, with the window open (MG1-014, MG1-015) | Nothing written; -31006, the attempt cancelled with a residual state that names the guard; the checker takes the cause from the record |
| The journal at each step (MG1-016) | Every entry that a step rests on is in the journal and flushed before the step |
| A write or flush failure, or full storage, before the release (MG1-017) | -31011, no upstream call |
| A storage failure with an obligation pending (MG1-006) | -31010, no upstream call |
| A storage failure after the release (MG1-016) | The server's response is returned; the journal keeps the release; recovery records `unknown` and sends nothing |
| A crash before and after the release, the send and the response (MG1-016) | Recovery: no release becomes `cancelled`, a release without a terminal becomes `unknown`; no retry; the consumed use is kept; the bundle verifies |
| A crash during retention, with one of two files written (MG1-016) | The recorded outcome is kept and the files are written once |
| A crash after the discharge (MG1-013, MG1-016) | The recovered record carries the discharge, and the recovered bundle carries the proof and verifies |
| The exit of the gateway's process after the write (MG1-016) | Another process records the outcome as `unknown` |
| A gateway that keeps nothing in memory (MG1-016) | Records and bundles are written, and the bundles verify |
| A start after a crash (MG1-016) | The gateway settles the journals of the earlier run before its endpoint listens |
| A retry after a send whose outcome is unknown (MG1-010, MG1-014) | The first attempt stays `unknown` with -31009; a retry is a new request with its own decision and authorization |

## OpenTelemetry export

OTEL-EVIDENCE-EXPORT-1 copies ECL decisions and evidence into OpenTelemetry log
records so that observability and SIEM tools can ingest them. It pins
OpenTelemetry Specification 1.61.0, OTLP 1.11.1 and Semantic Conventions 1.44.0.

The export is a copy. The signed evidence bundle stays the record that a claim
relies on and that a third party can check and, from `L2`, verify offline. The
exporter reads an object only after it is recorded. An export failure, such as
an unreachable collector or a full disk, does not change a decision, and it does
not delay or block the release of an action or the recording of evidence
(OE1-002).
A deployment that wants to react when its monitoring path fails does so
through a declared detection, whose response is recorded as its own control
action.

Each DCMP-2 message or EBMP-2 event becomes one log record. Its event name is
`ecl.dcmp.` or `ecl.ebmp.` followed by the message or event type, and its
`ObservedTimestamp` is when the exporter read the object. Its attributes copy
the object's identifier and the outcome or state, so a consumer can match the
record to the bundle, each as a `stringValue`, or as an `intValue` for the
workflow attempt and sequence; a checker takes an attribute held in another
kind, such as a `bytesValue` that holds the outcome's text, for no copy of the
value (OE1-003). A record names each attribute once, and a checker refuses a
record that repeats a key, since a reader that took the first attribute of that
key would read a value that no comparison saw (OE1-003). Each attribute applies
only to the objects that the profile's table names: a control message's safe
state is not exported as a decision's, and a challenge, a challenge response and
a request event carry the identifier of their request (OE1-004). Action
parameters, tool arguments and results, credentials, signatures and the free
text of reasons stay out unless the export policy declares them (OE1-005). So do
the identifiers of people and records, `ecl.actor.id`, `ecl.subject.id` and
`ecl.action.target`, which the exporter copies only when the export policy
declares them (OE1-005).

A record never carries a digest of the object or of what it holds that anyone
can compute, such as the SHA-256 digest of the object or the parameters digest
it holds: a reader who can list the possible values of an amount or an account
could test each one against it. When the deployment holds an export key, a
secret of at least 32 bytes used for nothing else, the record carries the
object's digest and its parameters digest as HMAC-SHA-256 under that key, with
the key's identifier as a string, so a consumer that holds the key can still
match the record to the bundle (OE1-010).
A consumer that does not hold the key a record names cannot compare its digests,
and still checks their form: each is the `stringValue` of 64 lowercase
hexadecimal digits, and the keyed parameters digest is there exactly when the
object has a parameters digest, so the object's SHA-256 is refused in any other
kind or form (OE1-010). The digest of the policy that decided leaves as the
response holds it: it identifies the policy, as the policy's identifier and
version, which are exported too, do (OE1-004). Without an export key, the record
carries no digest. The digests inside the signed evidence bundle do not change.
Severity follows a fixed table, with `SeverityText` the table's name for the
number, and a consumer infers nothing about authorization from it or from a
missing record. The profile also has an informative note on mapping the records
to OCSF 1.9.0.

## OAuth tokens

OAUTH-AUTHORITY-1 lets a resource server that already accepts OAuth access
tokens enforce an ECL `admit` without learning DCMP-2. One token expresses one
`admit`:

- Its `authorization_details` entry (RFC 9396) names the action class, the
  operation, the target, the parameter digest and the use limits of the admit.
- Its `aud` is the authorization's audience, as a single value, and its
  lifetime lies inside the authorization's window, at most 300 seconds unless
  the claim declares less.
- It is sender-constrained with DPoP (RFC 9449) or mutual TLS (RFC 8705) to a
  key that the governed AI system does not hold.
- For a delegated action, the RFC 8693 `act` claim names the actor apart from
  the subject.

An issuer issues a token only for a verified `admit`, never for `deny`, `hold`
or `challenge` (OA1-008), with every claim that RFC 9068 requires of a JWT
access token, among them `iss`, `client_id` and `jti` as strings, and with a
lifetime greater than zero (OA1-001, OA1-003). A resource server accepts the
token only for the request it names, within its use limit and with a valid proof
of possession (OA1-004, OA1-005). A verifier takes the issuer's keys from its
own configuration and refuses the algorithm `none`, symmetric algorithms, an
`alg` that is not a name, EdDSA on a curve other than Ed25519 unless the claim
declares it, a header without a key identifier or with an unknown one, a `typ`
other than the string `at+jwt`, compared exactly, keys carried in the token's
header, an issuer it is not configured for and a signature that does not verify
(OA1-007). It reads every segment of a token or proof as strict JSON, so a time
claim is an integer and a NumericDate with a fraction is refused, and refuses a
segment whose base64url text is not canonical, which would let two token strings
carry one signature (OA1-007). It may allow a clock skew of at most 60 seconds
on `nbf` and `exp`, none by default, but the presentation must fall inside the
ECL entry's window with no allowance (OA1-003). It checks the DPoP proof's
signature with the key that the proof carries before it compares that key with
`cnf.jkt` (OA1-004), refuses a proof that carries no `jti` string of 1 to 256
characters, since its replay cannot be checked or recorded, and a token whose
`cnf` names its key by anything but a string (OA1-004), keeps the `jti` values
and use counts in one store that every instance shares (OA1-005), and refuses a
presentation with the code that the profile's table gives for the first check
that fails (OA1-011). Where AUTHZEN-BINDING-1 is also claimed, an AuthZEN permit
is never a reason to issue a token, and an AuthZEN check at the resource server
can only narrow the request.

The tokens of the `oauth-authority` suite are signed with test keys that each
presentation record names as the issuer's keys, and no live authorization
server is involved: the suite tests the mapping and the checks, not a token
service.

## Records and vector suites

Each profile defines a record, with a JSON Schema in `schemas/`, that an
adapter can keep for audit: an exchange record for AARM, ACS and MCP, an export
record for OpenTelemetry and a presentation record for OAuth. The `binding`
stage of the [conformance tests](../conformance/README.md) validates a record
against its schema and then applies the profile's rules, and
`evaluateBindingRecord` of the TypeScript package
[`packages/ecl-ts`](../packages/ecl-ts/README.md) does the same for a record
of your own.

Each profile has a vector suite in `conformance/suites/`: `aarm-binding`,
`acs-binding`, `mcp-gateway`, `otel-export` and `oauth-authority`. Each suite
has failing vectors that show records of a weakened guarantee, which the
profile's rules refuse, for example `acs-invalid-decision-failure-proceeds`, a
Guardian failure that the record shows going ahead, and
`mcp-invalid-forwarded-when-unavailable`.
The `binding-basis` suite holds AARM and ACS records whose inputs disagree with
the decision basis of their response, and records whose response records a
decision basis that breaks DCMP2-053 (AB1-013, AC1-012).
`conformance/shared-corpus.json` names the optional capability that each vector
needs: `binding-profile-rules` for most vectors of the profile suites;
`binding-basis-agreement-rule` for the vectors that compare a record's inputs
with the decision basis of its response, those of the `binding-basis` suite and
a few of the `aarm-binding` and `acs-binding` suites; and
`otel-export-keyed-digests` for the `otel-export` suite, whose digests are keyed
and are checked with the suite's export key file. The AARM, ACS and MCP checks apply the one-way rule
of DCMP2-053 to the decision responses that a record holds, so an
implementation that declares `binding-profile-rules` or
`binding-basis-agreement-rule` also declares `decision-basis-rule`. The
TypeScript package implements all three capabilities, and its unit tests run
every vector of these suites.

## Limits

- Each profile pins one revision of the other system. A claim that relies on a
  later revision needs the mapping reviewed against it first.
- Some requirements cannot be shown by any record, such as the absence of
  another path to an MCP server or of a credential in the governed AI system.
  An assessor checks them by procedure, not by vectors.
