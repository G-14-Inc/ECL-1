# ECL OAuth Authority Profile 1

Requirement-IDs: compiled
Version: 1.0
Status: normative profile in the ECL-1 Version 1 public-review local candidate
Source build: `1.0.2-review.1`; prepared `2026-11-10`

This profile expresses ECL's transaction-bound authority as an OAuth 2.0 access
token, so that a resource server that already accepts OAuth tokens can enforce
an ECL `admit` without learning DCMP-2. One token expresses one `admit`. Its
`authorization_details` entry (RFC 9396) binds the action class, the operation,
the target, the parameter digest and the use limits of that admit; its `act`
claim (RFC 8693) keeps the actor and the subject of a delegated action apart; its
lifetime lies inside the authorization's window; and it is sender-constrained
with DPoP (RFC 9449) or mutual TLS (RFC 8705) to a key that the governed AI system
does not hold, so a copied token alone does not satisfy proof of possession.

The profile adds requirements to a claim that declares it. It removes none of
the core requirements, of DCMP-2 or of AUTHZEN-BINDING-1 where that profile is
also claimed.

Under this profile an action has two boundaries that ECL1N-0185 asks a claim to
name: the authority issuer's issuance of the token, which releases authority and
happens only for a verified `admit` (OA1-008), and the resource server's
acceptance of the presented token, which releases the action after the checks
of the presentation table (OA1-005, OA1-011); the effect follows at the
resource server.

## Pinned sources

RFCs are immutable; the digests identify the plain-text editions at the RFC
Editor. The machine-readable record of these pins is
`conformance/binding-sources.json`.

| Source | URL | SHA-256 |
| --- | --- | --- |
| RFC 7515, JSON Web Signature | https://www.rfc-editor.org/rfc/rfc7515.txt | `ecbf84674118e62526511c1237e1deaa86aada86d25b247623a2a7e04ae62e40` |
| RFC 7518, JSON Web Algorithms | https://www.rfc-editor.org/rfc/rfc7518.txt | `9a9ae524b09ea700ad3f189bac115df95ba69af84b26ffdbe3cdfb8d2152b1fc` |
| RFC 7519, JSON Web Token | https://www.rfc-editor.org/rfc/rfc7519.txt | `fecd930e9ccf2276b95c0017c6c4ff5d09352e4bc3c7629946447894e0f97248` |
| RFC 7638, JSON Web Key Thumbprint | https://www.rfc-editor.org/rfc/rfc7638.txt | `98b29ab9652070e6a5fec748d43e221bbedc66b6b22e05903fb5366c04ef3110` |
| RFC 7800, Proof-of-Possession Key Semantics for JWTs | https://www.rfc-editor.org/rfc/rfc7800.txt | `051514a781038027c2ac07c26ebe8533556012b2353cdaec8f3baeac53a7c919` |
| RFC 8037, CFRG Elliptic Curve Diffie-Hellman and Signatures in JOSE | https://www.rfc-editor.org/rfc/rfc8037.txt | `f14347f9d8eead78ef6e7a1ea3d795d35d664033095a76a80fcd567904aaedaa` |
| RFC 8693, OAuth 2.0 Token Exchange | https://www.rfc-editor.org/rfc/rfc8693.txt | `358d658014738bf4dc56c8aae2094ce716ede23b6d5a80488a7dc8e8d72da609` |
| RFC 8705, OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens | https://www.rfc-editor.org/rfc/rfc8705.txt | `6e45a1ee94c6a6a177a4cb077fe67d74bd70c1218c9362f2db2f153239612414` |
| RFC 8707, Resource Indicators for OAuth 2.0 | https://www.rfc-editor.org/rfc/rfc8707.txt | `3b89844a938b9219571931b664ed4a7b380555a4dda1df4e9445a2f72188e76b` |
| RFC 8725, JSON Web Token Best Current Practices | https://www.rfc-editor.org/rfc/rfc8725.txt | `737b7013a2495dcfd5481cf4c57c87e2455d537c4cec1140c9096a71fcef0812` |
| RFC 9068, JWT Profile for OAuth 2.0 Access Tokens | https://www.rfc-editor.org/rfc/rfc9068.txt | `68d3ff3910c0f2340fd7b93b430e00053da845b6eebe095ebef0c8bfda5e14c5` |
| RFC 9396, OAuth 2.0 Rich Authorization Requests | https://www.rfc-editor.org/rfc/rfc9396.txt | `d6a8f032d8a585daae1c33a8c7b6e539d199f886ec8cc1c7898436f7f2eed29c` |
| RFC 9449, OAuth 2.0 Demonstrating Proof of Possession (DPoP) | https://www.rfc-editor.org/rfc/rfc9449.txt | `3842c58e1f6043389416023b9bb8d765048266024982fbbd90640e05943f4e13` |

## Version 1.0 capability boundary

Each token carries one `single_use` DCMP-2 authorization and permits at most
one accepted presentation across all resource-server instances. The optional
`max_uses` is the integer 1. The reserved `bounded_multi_use` value is not
supported by issuance or presentation checking in this draft.

The profile deliberately carries no obligations. An OAuth resource server can
perform the presentation checks without a DCMP-2 processor, but that does not
supply an interoperability contract for fresh state proofs, critical token
conditions or proof retrieval at release. Those modes are not defined here.
The issuer refuses all such admits before token issuance, even when an earlier
proof was valid. This restriction does not exempt a deployment from core
release-boundary, control-state, policy or revocation requirements. Offline
record checking does not establish that a deployed revocation service works.

## Token content

**OA1-001** — An OAuth access token that expresses ECL authority MUST express
exactly one `admit`, and MUST carry, as a signed JWT access token (RFC 9068),
exactly one `authorization_details` entry of the type
`https://externalcontrollayer.ai/ns/authorization-details/action/1` whose
members equal the admit's authorization and request as the entry table below
gives. Its `use_policy` MUST be `single_use` and `max_uses` MUST be absent or the
integer 1, consistent with DCMP2-050. Introspection-carried authority requires a separately defined binding;
this profile does not define its authenticated representation or verification.

**OA1-002** — The token's `aud` MUST be exactly the authorization's `audience`, as
a single value; a client MUST request the token with a resource indicator (RFC
8707) equal to that audience, and a resource server MUST reject a token whose
`aud` does not name it, with `ecl.error.audience-mismatch.v1`.

**OA1-003** — The token's validity MUST lie inside the authorization's window:
its `nbf`, or its `iat` when it has no `nbf`, MUST NOT be earlier than
`valid_from`, its `exp` MUST NOT be later than `valid_until`, and its lifetime
from `iat` to `exp` MUST be greater than zero and MUST NOT exceed the declared
maximum token lifetime, 300 seconds unless the claim declares a shorter one;
each of `iat`, `nbf` and `exp` MUST be a NumericDate without a fraction, an
integer number of seconds. The token's `nbf` (or `iat` when `nbf` is absent)
MUST be strictly earlier than `exp` before any clock-skew allowance is applied.
A resource server MUST reject an empty or inverted token window with
`ecl.error.expired.v1`; clock skew MUST NOT create validity for that window.
A resource server MUST reject, with
`ecl.error.expired.v1`, a token presented before its `nbf` (or its `iat` when it
has no `nbf`) less the declared clock-skew allowance, or at or after its `exp`
plus that allowance, and, when the token carries one ECL entry, a token
presented outside that entry's window (from `valid_from` until before
`valid_until`), to which no allowance applies. The clock-skew allowance is zero
unless the claim declares one, and at most 60 seconds.

The allowance tolerates a resource server whose clock differs a little from the
authority issuer's, and the entry's window keeps every accepted presentation
inside the ECL authorization even when the allowance reaches past the token's
own validity. RFC 7519 allows a NumericDate with a fraction; this profile does
not, so that every verifier compares times exactly, and a token or proof whose
time has a fraction cannot be read under OA1-007.

## Sender constraint and presentation

**OA1-004** — The token MUST be sender-constrained, with `cnf.jkt` (RFC 9449) or
the `cnf` member `x5t#S256` (RFC 8705), to a key held by the component that
presents it and not readable by the governed AI system. The confirmation
thumbprint MUST be canonical unpadded base64url encoding of exactly 32 bytes
(SHA-256), and a resource server
MUST reject a token presented without valid proof of possession. For DPoP the
presentation MUST carry exactly one proof, a JWS whose header has `typ`
`dpop+jwt`, an algorithm from the declared asymmetric set of OA1-007 and a `jwk`
that holds a public key only and, for Ed25519, is neither the identity nor any
other point of small order (order dividing 8), including alternative encodings
that decode to such a point; whose signature verifies under that `jwk`; whose
`jwk` has the RFC 7638 thumbprint `cnf.jkt`; whose `htm` equals the request
method and whose `htu` equals the request URI with its scheme in lowercase,
without its query and fragment and without other normalization (RFC 9449,
Section 4.3); whose `iat`, an integer number of seconds, lies no more than the
declared proof window before or after the time of presentation, the window being
60 seconds unless the claim declares another of at most 300 seconds; whose `ath`
is the base64url SHA-256 of the access token; and whose `jti`, a string of 1 to
256 characters, the resource server has not already accepted in the proof
key and endpoint context. After acceptance, the resource server MUST retain the
`jti` until after `iat + W`, where `W` is the declared proof window in seconds;
the cache entry remains active at that inclusive endpoint. The cache key MUST
include the presenter-key thumbprint, HTTP method and the normalized `htu`
compared above, or use a broader scope that cannot allow replay in that context.
A repeated `jti` in that active cache MUST be refused with
`ecl.error.replay.v1`. For mutual TLS the
client certificate's SHA-256 thumbprint MUST equal `x5t#S256`.

This profile uses a stricter URI comparison than the normalization recommended
by RFC 9449, Section 4.3. For a presentation to pass, the client and resource
server need the same URI spelling apart from the transformations in OA1-004.
Otherwise equivalent URI spellings can be refused. A future-dated proof can be
accepted at `iat - W`, so a cache that remembers only the preceding `W` seconds
is insufficient: the same proof remains acceptable through `iat + W`. The
small-order exclusion above applies to the presenter key carried by an
untrusted DPoP proof; configured issuer keys remain subject to OA1-007 and the
issuer-key provisioning policy.

**OA1-005** — A resource server or enforcement point MUST accept the token only
for a request whose target, operation and parameter digest equal the
`identifier`, the `actions` member and the `parameters_digest` of the token's
ECL entry, refusing any other with `ecl.error.scope-mismatch.v1`, and only within
the entry's single-use policy, refusing a further accepted use of that
authorization with `ecl.error.replay.v1`. It MUST reject an ECL entry whose
`use_policy` is not `single_use` or whose `max_uses` is present and not the
integer 1 with `ecl.error.binding-unsupported.v1`, in the order of OA1-011. Every
instance of a resource server that accepts the token MUST count its uses, and
remember the DPoP `jti` values it accepted, in one store that all of them
share, so that a use or a proof that one instance accepted counts at every
other. An `authorization_details` entry of another type MUST NOT widen the
authority that the ECL entry expresses.

## Delegation

**OA1-006** — When the decision request names a subject distinct from its actor,
the token MUST carry the subject in `sub` and the actor in the RFC 8693 `act`
claim (`act.sub`), with any earlier actors of the delegation as nested `act`
claims; a token for such an action that lacks `act`, or whose `act.sub` differs
from the request's actor, MUST be rejected, and a token exchange MUST NOT widen
the subject token's authority and MUST preserve the members that ECL1N-0067
lists (ECL1N-0031). Whenever `act` is present, including when the request has
no distinct subject, its outer `sub` MUST identify the request's actor. Each
`act` value, including nested history, MUST be a JSON object under RFC 8693
Section 4.1. Nested actor history is informational and MUST NOT widen access
control authority; an empty ECL `delegation_chain` does not establish that
the issuer has no earlier actor history.

## Signatures, issuance and records

**OA1-007** — The token MUST be a JWS (RFC 7515) signed with an algorithm from
the declared asymmetric set, with the header `typ` `at+jwt` (RFC 9068) and a
`kid` that names the signing key; the declared asymmetric set is the set of
asymmetric JWS algorithms that the claim declares, and ES256 and EdDSA with the
curve Ed25519 (RFC 8037) when it declares none. A verifier MUST take the
issuer's keys from its own configuration; MUST reject the algorithm `none`, a
symmetric algorithm, a header without a `kid` or with a `kid` it does not know,
a `crit` header it does not understand (RFC 7515, Section 4.1.11), and a token
whose header carries `jwk`, `jku`, `x5u` or `x5c` (RFC 8725, Sections 2.1, 3.1
and 3.10, treats `none`, algorithm substitution, `kid`, `jku` and `x5u`); and
MUST reject a token whose `iss` is not a configured issuer or whose signature
does not verify under that issuer's configured keys. A verifier MUST refuse as
malformed a token or a DPoP proof with a segment that is not unpadded base64url
(RFC 7515, Section 2) whose unused bits are zero, MUST read the JSON of the
header and payload segments of each under the strict JSON profile of ECL objects
(IE1-002), and MUST refuse as malformed a header or payload segment outside
that profile or one that is not a JSON object, such as one that repeats a member name or holds
a number with a fraction or an exponent, an integer beyond the exact
interoperable range, `NaN`, an unpaired surrogate or a byte order mark.

**OA1-007 (continued)** — In an `ecl_oauth_presentation_v1` record, the entries of `issuer_keys.keys`
MUST have distinct `kid` values. A record verifier MUST check this before
constructing a key map or selecting a verification key. A duplicate, including
an identical repeated key or a key the token does not select, fails the key
check at step 1 of the presentation table (OA1-011): an accepted record gives
`ecl.rule.oauth-token-signature-checked.v1`, and a refused presentation MUST
name `ecl.error.integrity-invalid.v1`. This is a restriction of this record
format; RFC 7517, Section 4.5 permits applications to use some same-identifier
alternatives. Other JWK members remain subject to their applicable key-type
rules; an unknown additional member is ignored as RFC 7517, Section 4 specifies.

**OA1-007 (continued)** — RFC 7515 requires a JSON object for the JOSE header,
and RFC 7519 for the JWT claims set. Both allow a verifier either to refuse a
repeated member name or to keep the last one. This profile refuses repeated
names and applies ECL's strict JSON rules to the header and payload objects so
that verifiers read them consistently. Base64url text whose
unused bits are not zero decodes to the same bytes as its canonical form, so a
verifier that accepted it would accept two token strings for one signature, of
which the `ath` of RFC 9449 and the digest of OA1-008 name only one. The
vectors use the default algorithm set. The profile narrows RFC
9068 in two places. The token's `typ` is the string `at+jwt`, compared exactly:
a resource server refuses the `application/at+jwt` that RFC 9068, Section 4 also
lets it accept, and a `typ` that differs only in letter case, such as the
`at+JWT` of the example in RFC 9068, Section 3, although media type names are
case-insensitive (RFC 7515, Section 4.1.9). The default set also leaves out
RS256, which RFC 9068, Section 2.1 requires conforming authorization servers and
resource servers to support; a claim may
declare RS256, which the vectors do not exercise.

**OA1-008** — An authority issuer MUST issue a token only for a verified `admit`,
never for `deny`, `hold` or `challenge` (DCMP2-014). The request and response
MUST satisfy the DCMP-2 message semantic rules, including critical-extension
handling, and the single-use request and authorization domains of DCMP2-050.
An issuer MUST NOT issue a token for an unsupported use policy or maximum; a
verifier of an `ecl_oauth_presentation_v1` record MUST reject that issuance with
`ecl.rule.oauth-token-expresses-admit.v1`.
The response MUST carry exactly one `ecl.ext.decision-basis.v1` and
satisfy DCMP2-053 with the request it answers; a record verifier MUST report
violations under the same registered DCMP-2 predicates, including
`ecl.rule.decision-basis-one-way.v1` for a missing or invalid basis. When the admit's
`authorization.token_reference` names the token, its digest MUST be the SHA-256
of the token's compact serialization; and when the ECL authorization is revoked,
the token MUST become unusable within the declared revocation propagation bound,
through introspection or a lifetime no longer than that bound. Version 1.0 of
this profile supports only an admit whose `obligations` list is empty. An issuer
MUST NOT issue a token for any admit carrying an obligation, including one
claimed to have been discharged, and a verifier of an
`ecl_oauth_presentation_v1` record MUST reject a record of such an issuance
with `ecl.rule.oauth-token-expresses-admit.v1`. A token, custom
claim or successful issuance MUST NOT be treated as discharging an obligation
at a later release boundary. Actions requiring obligations use a declared
DCMP-2 enforcement path with release-time proofs; they are outside this
profile's Version 1.0 capability. Grant revocation and policy changes MUST
invalidate or narrow authority within their declared propagation bounds; token
lifetime alone is sufficient only when it is within every applicable bound.

**OA1-009** — Where AUTHZEN-BINDING-1 is also claimed, an AuthZEN permit MUST NOT
be a reason to issue a token (AZB1-001): the token is issued only from the ECL
admit, and an AuthZEN evaluation that a resource server runs when the token is
presented MAY only narrow the presented request.

**OA1-010** — A resource server or enforcement point that retains presentation
records for audit MUST write each one as `ecl_oauth_presentation_v1`, valid
against `https://externalcontrollayer.ai/ns/schema/binding/oauth-presentation/1`.

## Presentation checks and refusals

**OA1-011** — A resource server MUST refuse a presentation that fails a check of
the presentation table below with the code that the table gives for that check,
and a presentation that fails more than one check with the code of the first of
them in the table's order. A presentation record's `result` MUST be the
resource server's decision: `accepted` true only for a presentation that passes
every check, and otherwise `accepted` false with that code in `error`. An
accepted result MUST NOT carry `error`. Every refused result MUST name a
registered entry in the error-code registry, including a refusal made when
none of the table's checks fails.

| Order | Check | Requirement | Code |
| --- | --- | --- | --- |
| 1 | The token is a compact JWS whose segments the verifier reads under OA1-007, and it passes the header, algorithm, key, signature and issuer checks of OA1-007 | OA1-007 | `ecl.error.integrity-invalid.v1` |
| 2 | The token's `aud` names the resource server | OA1-002 | `ecl.error.audience-mismatch.v1` |
| 3 | The time of presentation lies within the token's validity, with the clock-skew allowance, and within its ECL entry's window | OA1-003 | `ecl.error.expired.v1` |
| 4 | The ECL entry's `use_policy` is `single_use` and `max_uses` is absent or the integer 1 | OA1-005 | `ecl.error.binding-unsupported.v1` |
| 5 | The proof of possession passes every check of OA1-004 other than the check that its `jti` was not accepted before: a DPoP proof that carries a `jti` string of 1 to 256 characters and binds the request and the token, or the bound client certificate | OA1-004 | `ecl.error.integrity-invalid.v1` |
| 6 | The DPoP proof's `jti` is absent from the unexpired cache for its proof key and endpoint context, retained through `iat + W` | OA1-004 | `ecl.error.replay.v1` |
| 7 | The presented target, operation and parameter digest equal those of the token's one ECL entry | OA1-005 | `ecl.error.scope-mismatch.v1` |
| 8 | The authorization has no previously accepted presentation | OA1-005 | `ecl.error.replay.v1` |

The checks of the issuer's side (OA1-001, OA1-006 and OA1-008) need the ECL
request and response, which a resource server need not hold, so they are not
in the table; the profile's vectors check them on the record as the issuer's
obligations.

## Entry table

**OA1-001 (continued)** — The following table gives the ECL entry members.

| ECL entry member | Value |
| --- | --- |
| `type` | `https://externalcontrollayer.ai/ns/authorization-details/action/1` |
| `locations` | `[authorization.audience]` |
| `actions` | `[request.action.operation]` |
| `identifier` | `request.action.target.uri` |
| `authorization_id` | `authorization.authorization_id` |
| `request_id` | `request.message_id`, which the response carries as `request_id` |
| `action_id` | `request.action.action_id` |
| `action_class` | `request.action.action_class` |
| `scope_digest` | `authorization.scope_digest` (DCMP2-044) |
| `parameters_digest` | `request.action.parameters_digest` |
| `use_policy` | `authorization.use_policy` |
| `max_uses` | `authorization.max_uses`, when present |
| `valid_from`, `valid_until` | The authorization's window |
| `decision` | When the token is issued after the response: `uri` the response's `message_id` and `digest` its digest |

## Claim table (informative)

A JWT access token carries every claim that RFC 9068, Section 2.2 requires,
among them `iss`, `client_id` and `jti`, each a string (OA1-001). The table
gives the value of each claim for an ECL admit.

| JWT claim | Value |
| --- | --- |
| `iss` | The authority issuer, the principal that holds the token-signing key |
| `sub` | `request.subject.id`, or `request.actor.id` when the request names no subject |
| `act` | `{"sub": request.actor.id}` when the subject differs from the actor |
| `aud` | `authorization.audience` |
| `iat`, `nbf` | Integer seconds. `nbf`, or `iat` when `nbf` is absent, is not earlier than `authorization.valid_from`. |
| `exp` | Integer seconds, not later than `authorization.valid_until` |
| `jti` | Unique per token |
| `client_id` | The enforcement point or gateway that presents the token |
| `cnf` | `{"jkt": ...}` or `{"x5t#S256": ...}` |
| `authorization_details` | `[ECL entry]` |

The `scope_digest` already binds the request identifier and the complete action,
so a resource server that receives the request and action can check the binding
again; one that receives only the target and parameters checks the members of
the entry.

## Presentation record (informative)

An `ecl_oauth_presentation_v1` record holds one presentation: the `issuer` and
the `issuer_keys` that the verifier configures; the `resource_server` that
received the presentation; the declared maximum token lifetime, DPoP proof
window and clock-skew allowance (`max_token_lifetime_seconds`,
`dpop_proof_window_seconds` and `clock_skew_seconds`, each its default when
absent); the DCMP-2 `request` and `response` the token expresses; the `token`;
the `presentation` with the HTTP method and URI, the target, operation and
parameter digest presented, the time, the number of uses with this one, the DPoP
proof or the client certificate thumbprint, and the DPoP `jti` values that the
resource server previously accepted whose retention interval has not ended
at this presentation in the proof key and endpoint context (`seen_dpop_jti`,
OA1-004); and the `result`, which names the code of OA1-011 for a
refusal. The rules registered for this profile, whose names begin
`ecl.rule.oauth-`, check a record after its schema: the issuer's side always,
the checks of the presentation table when the record accepts the presentation,
and the code of the first check that fails when it refuses it. The DCMP-2
message and decision-basis checks also apply to issuance in every record. The
record states the replay-cache contents; checking it does not demonstrate that
a deployed cache retained every entry across servers or restarts.

## Security considerations

A bearer token in an agent's context is a credential that the agent can leak or
misuse, which is the gap that ECL1N-0033 and the direct-access control gap (G2)
describe. Binding the token to a proof-of-possession key that the governed AI
system cannot read makes a copied token useless, and binding it to one admit and
one parameter digest makes a stolen proof and token usable only for the action
already admitted, once for that captured DPoP proof, within the ECL
authorization window and the token-validity checks, including any declared
clock-skew allowance. The verifier's own key configuration
closes the attacks that take a key or an algorithm from the token's own header,
such as the `none` and algorithm-substitution attacks of RFC 8725, Section 2.1,
and the `kid`, `jku` and `x5u` misuse of its Section 3.10, and reading every
segment under the strict JSON profile leaves no room for two verifiers to read
one token differently. Replay protection holds only as far as the use counts and
the remembered `jti` values reach, which is why every instance of a resource
server shares them (OA1-005). Token exchange across trust domains can widen authority by interpretation; ECL1N-0031 requires a denial
when the intersection with the parent authority cannot be shown.

## Conformance

| Kind | What the citation establishes |
| --- | --- |
| Vectors | The `oauth-authority` suite refuses a token issued for a non-admit response, with a lifetime beyond the window or of zero, missing the `act` claim of a delegated action or the `jti` claim, expressing other parameters, whose entry holds the `max_uses` `true` where the admit grants one use or a `decision` of null, or not sender-constrained, among them a token bound to an `x5t#S256` of null and presented with no client certificate; a resource server that accepts a token signed with `none`, with a key its own header carries or with Ed448, a token whose header gives `alg` as a list or names no `kid`, a token whose signature segment is not canonical base64url, a token whose claims hold a NumericDate with a fraction or an integer beyond the exact range, a token for another audience, an expired token, a token presented within the clock-skew allowance but after its entry's window, a proof from another key, a proof that carries the bound key but whose signature does not verify, a proof that carries no `jti` or an empty one, a replayed proof, another target, or a second use; and a refusal with another code than the first failing check gives, among them a refusal as a replay of a proof whose `jti` has more than 256 characters. It accepts a presentation within the declared clock-skew allowance and a refusal with the code of the first failing check |
| Assessor procedure | Key custody for the proof-of-possession key, revocation propagation, resource-indicator use and token exchange policy |

No live authorization server is used: the tokens of the `oauth-authority`
suite are signed with test keys that each presentation record names as the
issuer's keys.
