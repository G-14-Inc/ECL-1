# ECL-1 AuthZEN binding

This guide explains [AUTHZEN-BINDING-1](../profiles/AUTHZEN-BINDING-1.md), the
profile under which an ECL decision point consults a policy decision point
(PDP) of the OpenID [AuthZEN Authorization API
1.0](https://openid.net/specs/authorization-api-1_0-final.html) as an
additional policy check. The profile is the text that counts; this guide adds
no requirement. The request mapping of section 3 and the response table of
section 4 are informative examples of a binding that meets the profile. The
capability table of section 6 is the binding's exact capability table
(AZB1-006).

## 1. Scope

An AuthZEN evaluation is a decision input. It releases no action and has no
release boundary: an action is released, if at all, by an enforcement point on
an ECL `admit` (ECL1N-0185, AZB1-001). A PDP `true` contributes to an `admit`
but never replaces ECL's native grant, scope, generation, halt, validity and
use checks, and every response other than an unqualified JSON boolean `true`
denies with a registered reason (AZB1-001 to AZB1-003). The check supplies no
authority, validity window, use policy or obligation. Where OAUTH-AUTHORITY-1
is also claimed, an AuthZEN permit is never a reason to issue a token, and an
AuthZEN check at the resource server can only narrow the request.

## 2. Transport

The decision point sends one canonical JSON `POST` to a configured evaluation
URL, normally `/access/v1/evaluation`, on a fresh connection, with the headers
`Content-Type`, `Accept`, `Connection: close` and `X-Request-ID` and, when one is
configured, an `Authorization` value. HTTPS authenticates the PDP under a trust
anchor that the caller configures; plain HTTP is allowed only when it is enabled
explicitly, and only to a loopback host for testing. The client follows no
redirect, makes no retry within a decision attempt and calls no batch or
metadata-discovery endpoint (AZB1-005). It declares a total deadline for the
call and a cap on the size of the response, and a call that exceeds either
denies (AZB1-003).

## 3. Request mapping (informative)

The example mapping uses only the members of a DCMP-2 `decision_request` in the
table below. In it, `enc(x)` is the encoding described after the table, and
`type(t)` is the principal type `t` without its `ecl.<area>.` prefix and its
`.v<N>` suffix; an actor whose type is not a principal type is refused before
any call.

| DCMP-2 source | AuthZEN evaluation slot |
|---|---|
| `actor.type` | `subject.type = type(actor.type)` |
| `actor.id` | `subject.id = enc(actor.id)` |
| `action.operation` | `action.name` |
| configured resource type | `resource.type` |
| `action.target.uri` | `resource.id = enc(action.target.uri)` |
| differing tenant `subject.id` | `resource.properties.tenant = enc(subject.id)` |
| differing non-tenant `subject` | `subject.properties.on_behalf_of_type`, `on_behalf_of_id` |
| `action.target.version` | `resource.properties.version`, when present |
| SHA-256 `action.target.digest.value` | `resource.properties.digest`, when present |
| `message_id` | `context.ecl.request_id` |
| `issued_at` | `context.ecl.issued_at` |

`enc` percent-encodes the UTF-8 bytes of an identifier that lie outside the
unreserved characters of RFC 3986, the percent sign included. The encoding is
injective, so two ECL identifiers never reach the PDP as one, and it sends no
raw character that a policy engine's identifier syntax rejects (AZB1-004). An
identifier longer than the engine accepts is refused rather than shortened. A
raw identifier with colons, such as a URN, is not read the same way by every
engine, which is why the mapping never sends one.

The mapping omits `action.parameters`, `constraints`, `authority_request`,
`workflow` and `extensions`; the ECL decision point checks them natively. An
operation that the mapping does not cover, and every DCMP-2 message type other
than `decision_request`, is refused before any PDP call (AZB1-004).

## 4. Strict response acceptance

| PDP behavior | Result |
|---|---|
| Bare `{"decision":true}`, or `true` with an empty `context` | Contributes to an `admit`, with no reason |
| Boolean `false` | Deny, `ecl.reason.authzen-denied.v1` |
| Non-empty `context` on `true` | Deny, `ecl.error.binding-unsupported.v1`; a qualified permit is never flattened into an unqualified one |
| Missing or non-boolean `decision`, a body or `context` that is not an object, duplicate members, a number with a fractional part anywhere, malformed JSON | Deny, `ecl.error.dependency-response-invalid.v1` |
| An unknown top-level member, a wrong media type, or a body over the cap | Deny, `ecl.error.dependency-response-invalid.v1` |
| A redirect, a 4xx or 5xx status, a connection or TLS failure, a body cut short | Deny, `ecl.error.dependency-unavailable.v1`; a redirect is never followed |
| A slow trickle of bytes, a DNS lookup that does not return, or exhausted connection capacity | Deny, `ecl.error.dependency-unavailable.v1`, by the total deadline or the bounded capacity |

An empty `context` does not qualify the decision, and a valid `false` is a policy
denial, not a transport failure (AZB1-002, AZB1-003). The parser refuses numbers
with a fractional part, duplicate names, invalid Unicode, excess depth and
excess nodes, which is stricter than the I-JSON recommendation of AuthZEN
§11.5. The client also denies an unknown top-level member, although AuthZEN
§10.1.1 asks a client to ignore one: an unknown member might qualify a permit,
and the binding refuses to approximate it. These two are the binding's
declared deviations from the bound protocol (AZB1-008).

## 5. Correlation

Every request carries a fresh UUID in `X-Request-ID`. The identifier in the
response is recorded but does not gate the decision: AuthZEN §10.1.3 asks a PDP
to echo it, and not every engine does. Pairing therefore rests on the
dedicated, unpooled connection, and the sent and received identifiers and the
digests of the bytes exchanged remain diagnostic evidence.

## 6. Capability and loss table

`supported` means that the binding sends or consumes the capability. `native`
means that the ECL protocol assigns the capability to ECL's own path, which the
PDP cannot override; the disposition assigns that responsibility and does not
claim that a deployment implements every native control operation.
`unsupported` means that the binding neither sends the capability nor treats it
as a release capability, so a request or response that depends on it is
refused or not produced. A deployment publishes this table, with these
dispositions, under AZB1-006.

| Capability | Disposition | ECL behavior |
|---|---|---|
| evaluation | supported | One evaluation per decision attempt. |
| decision-boolean | supported | Only unqualified boolean true contributes to admit. |
| request-correlation | supported | Fresh request id and unpooled connection; echo recorded only. |
| evaluations-batch | unsupported | No batch endpoint; an empty evaluations array could evaluate defaults under AuthZEN §7.1. |
| metadata-discovery | unsupported | Evaluation URL is pinned configuration. |
| search-subject | unsupported | No search endpoint. |
| search-resource | unsupported | No search endpoint. |
| search-action | unsupported | No search endpoint. |
| decision-context | unsupported | A context-qualified permit denies; context is never interpreted as an obligation. |
| signed-metadata | unsupported | No signed PDP metadata is accepted. |
| policy-reference | unsupported | The PDP supplies no ECL policy identifier, version or digest. The DCMP-2 response binds the policy that the decision point applied (DCMP2-016); the digests of the PDP request and response and the PDP endpoint identify the exchange. |
| outcome-hold | native | A boolean PDP cannot originate a DCMP-2 hold. |
| outcome-challenge | native | A boolean PDP cannot originate a DCMP-2 challenge. |
| obligations | native | ECL must handle obligations; PDP context never creates one. |
| validity-window | native | ECL must set and check the authority window. |
| use-policy | native | The ECL decision and enforcement path must own use charges and quota. |
| safe-state | native | A dependency-failure deny must apply ECL's declared safe-state rule (DCMP2-041). |
| control-cancel | native | ECL control path is specified separately; not an AuthZEN evaluation. |
| control-revoke | native | ECL control path is specified separately; not an AuthZEN evaluation. |
| control-supersede | native | ECL control path is specified separately; not an AuthZEN evaluation. |
| control-quarantine | native | ECL control path is specified separately; not an AuthZEN evaluation. |
| control-halt | native | ECL control path is specified separately; not an AuthZEN evaluation. |
| action-parameters | unsupported | Parameters are not sent; the ECL decision path must check them. |
| constraints | unsupported | Constraints are not sent; the ECL decision path must check them. |
| delegation-chain | unsupported | Delegation is not sent; the ECL decision path must check it. |

DCMP-2 control messages (`cancel`, `revoke`, `supersede`, `quarantine`, `halt`),
`challenge` and `challenge_response` are refused by the binding; ECL processes
the control and challenge flows it supports natively.

## 7. Policy changes and bounded staleness

A change of the PDP's policy affects only later evaluations (AZB1-007). Unless
a native revocation or halt intervenes, an ECL authorization issued before the
change stays outstanding until its own validity window ends. Immediate effect
uses ECL's control path: a revocation or a halt changes the control state that
is checked again before release, and nothing that a PDP returns revokes,
extends or creates ECL authority. This is the binding's **bounded staleness**
rule: outstanding authority is bounded by its existing window, not by polling
the policy engine.

## 8. The check at the decision point

The decision point treats the check as one decision input. A check that denies
puts its registered reason first among the reasons of the DCMP-2 `deny`, and a
check that permits still has to pass ECL's native checks. The enforcement
point's evidence carries registered `ecl.error.*` reasons only, so a reason of
the check, such as `ecl.reason.authzen-denied.v1`, reaches the evidence only
through the enforcement point's own mapping of the decision. The PDP's
diagnostic detail is information for the operator, not signed evidence.
