# ECL Trust Policy Profile 1

Requirement-IDs: compiled
Version: 1.0
Status: normative profile of ECL-1 Version 1.0, a published version

This profile describes the caller-controlled trust-policy input to envelope
verification (INTEGRITY-ENVELOPE-1 section 11) and to the offline bundle
verifier. Standalone envelope verification binds each payload to the purpose of
its role (TP1-010); the bundle verifier additionally binds every object role and
principal within each media type.

**TP1-001** — The verifier MUST use only its caller's current trust policy and
explicitly supplied earlier versions of that same policy; a bundle MUST NOT
carry, select, or substitute trust roots, and an embedded policy reference that
matches none of those supplied versions MUST be reported as a policy mismatch,
with `ecl.error.signature-policy-invalid.v1`.

**TP1-002** — A trust-policy document MUST validate against
`https://externalcontrollayer.ai/ns/schema/trust-policy/1` with no unknown members.
A loader MUST refuse a document that fails the strict JSON checks of
INTEGRITY-ENVELOPE-1 (IE1-037), in their order, or fails the schema with
`ecl.error.schema-invalid.v1`, except that a declared limit gives the error of
TP1-007.

**TP1-003** — A trust-policy document MUST have unique key identifiers and public
keys, active supported signature suites, canonically decoded keys of the correct
length, a valid P-256 curve point or a canonical Ed25519 curve point of non-small
order, a validity end later than its start when present, registered key purposes,
and at most one revocation per known key. A loader MUST refuse a document that
fails any of these conditions with `ecl.error.semantic-invalid.v1`.

**TP1-004** — Bundle verification MUST accept a key only for an object's declared
role within its payload media type, and MUST reject a decision-request key used
for a decision response even though both use the DCMP-2 media type.

**TP1-005** — Bundle verification MUST reject a signing key whose bound principal
differs from the object's issuer or producer identifier.

**TP1-006** — Bundle verification MUST evaluate each trust dependency of a
bundle: each signing key of each envelope and observation, and each signing key
of each time attestation that a trusted-time countersignature carries
(INTEGRITY-ENVELOPE-1 section 9). Every key that signed anything in the bundle
is a trust dependency, whether or not its signature counts toward the policy:
its historical status is the result of INTEGRITY-ENVELOPE-1 IE1-040 step 6 for
that signature at the dependency's time together with the revocation check
below, and a signature that does not verify makes its dependency historically
invalid with `ecl.error.integrity-invalid.v1`. IE1-015 still decides from the
signatures that count whether the envelope or the attestation is valid, so the
verdict does not change; a scope item that rests on a dependency (EBMP-2
EBMP2-076) is established only when that dependency is historically valid. A
dependency is historically valid only when
both hold: it is valid at the dependency's time under the policy version that
its object names (TP1-001), a revocation in that version effective at or before
that time making it invalid; and the caller's current policy holds no
revocation, effective at or before the dependency's time, of a key that has the
dependency's key identifier or its public key. The dependency's time is the time
at which INTEGRITY-ENVELOPE-1 IE1-034 evaluates its signature, for a signer of an
object, and the attested time, for a signer of a time attestation. A revocation
states that the key is not trusted from its effective time, whatever reason it
gives, so a revocation in the current policy reaches evidence that an earlier
version still accepts; a claimant that does not know when a compromise began
revokes from the earliest suspected time (ECL-1 ECL1N-0159). Only a revocation
carries later knowledge of a compromise: a key's later retirement, a validity
interval that the current policy ends or shortens, or the key's absence from the
current policy does not make a dependency historically invalid. Bundle
verification MUST also report each dependency's current status at the caller's
evaluation time under the current policy, which MUST use the caller's current
policy whatever version the object's embedded reference names and MUST find the
key in it with the public key that the historical check used; the matching of
TP1-001 applies to historical validity only. The report MUST name, for each
dependency, the policy version of its historical check, the current policy
version whose revocations it applied, and the effective time of any such
revocation. Each dependency's report member `at` MUST be the time at which its
signer was evaluated, or `null` when it was not evaluated, including when the
envelope's status was decided before any signer was evaluated.

**TP1-007** — A verifier interface MUST enforce declared byte limits before
parsing. The verifier published with ECL-1, for the command line
(`packages/ecl-ts`) and for the browser (`web/verifier`), declares a limit of
256 KiB for each trust-policy input and of 1 MiB for its evidence-bundle input.
A verifier MUST refuse an input that exceeds a declared limit, including a limit
of its strict JSON parser (INTEGRITY-ENVELOPE-1 IE1-037), with
`ecl.error.resource-limit-exceeded.v1`.

The byte limits apply to the interfaces that read bytes, such as a command-line
interface. An interface that accepts parsed objects applies the envelope,
observation, node and depth limits that it declares (EBMP-2 EBMP2-062). An
embedded reference identifies a supplied policy version; it never supplies that
policy's keys. The current policy and the history versions are caller inputs.

The seven registered purposes are `ecl.purpose.decision-request.v1`,
`ecl.purpose.decision-response.v1`, `ecl.purpose.control.v1`,
`ecl.purpose.evidence-event.v1`, `ecl.purpose.observation.v1`,
`ecl.purpose.trusted-time.v1`, which signs time attestations
(INTEGRITY-ENVELOPE-1 section 9), and `ecl.purpose.approval.v1`, which marks an
approval service's key: a verifier admits an approval record as the proof of an
approval obligation only when every key that signed it holds that purpose
(EBMP-2 EBMP2-070). The approval purpose qualifies a key that also holds the
evidence-event purpose and lets a key sign no payload by itself, so a verifier
refuses a trust policy in which a key holds it alone. INTEGRITY-ENVELOPE-1
IE1-039 gives the purpose that the key of each kind of payload holds. Adding revocations changes the
policy digest.

**TP1-008** — Ed25519 verification MUST require canonical scalar `S < L` and
check the cofactorless equation `[S]B = R + [k]A`, where `k` is the
little-endian SHA-512 challenge reduced modulo `L`. It MUST NOT substitute
a cofactor-multiplied verification equation. Canonical decoding and non-small
order of the policy's public key remain mandatory under TP1-003.

[RFC 8032 §5.1.7](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.7)
requires the cofactored equation `[8][S]B = [8]R + [8][k]A` and permits the
cofactorless `[S]B = R + [k]A` instead, with `k` the unreduced digest. With
`k` reduced modulo `L`, the check above is that cofactorless equation for a
public key of prime order. For a key with a small-order component, which
TP1-003 admits, it can differ from it, and every signature it accepts still
satisfies the cofactored equation.
The edge corpus includes fourteen refused small-order encodings, accepted and
refused mixed-order signatures, and a refused torsion-R signature. The Go edge
checks exercise the same bytes with `crypto/ed25519`; they do not establish a
complete Go trust-policy or envelope capability.

Five of the purposes each belong to one component role: the decision-request
purpose to the requester of a decision, which may be the enforcement point or
the governed AI system itself, the decision-response purpose to the decision
point, the control purpose to the control plane that issues DCMP-2 control
messages, the observation purpose to an observer and the trusted-time purpose
to a time authority. The requester also answers the challenges of the decision
point, so a challenge response is signed under the decision-request purpose and
a challenge under the decision-response purpose. The evidence-event purpose is
not a role of its own: the component that records an evidence event signs it. A
key that held two roles would let the holder of one role sign for the other,
such as a requester forging decision responses.

**TP1-009** — A trust-policy key MUST NOT carry more than one of the
decision-request, decision-response, control, observation and trusted-time
purposes; the evidence-event purpose MAY accompany one of them. A verifier MUST refuse a
trust-policy document with a key that carries two of these purposes as
`ecl.error.semantic-invalid.v1` (ECL1N-0157).

**TP1-010** — Envelope verification under a trust policy, standalone or within a
bundle, MUST count a signature over a DCMP-2 message only when its key carries
the purpose that INTEGRITY-ENVELOPE-1 IE1-039 gives its message type: the
decision-request purpose for a decision request or a challenge response, the
decision-response purpose for a decision response or a challenge, and the
control purpose for a control message; a signature by any other key MUST NOT
count toward that object's threshold or required keys.

## Evidence

| Kind | What the citation establishes |
|---|---|
| Vectors | Reproducible object acceptance and exact error attribution |
| Verifier tests | A verifier's behavior where no vector applies; this is not a deployment assessment |

TP1-002 and TP1-003 have vectors in the `trust-policy` suite, including the
small-order key refusal. TP1-009 and TP1-010 have vectors in the `key-roles`
suite: policies whose one key carries two roles, and envelopes of each DCMP-2
message type that a key with and without the role signed. The `evidence-bundle`
suite refuses a bundle that carries its own trust policy (TP1-001) and a
decision response signed with a key bound to another principal (TP1-005), and
tells a key revoked before the evidence was signed, which makes the bundle
invalid, from one revoked after it, which is a current-trust failure (TP1-006).
The `envelope` suite refuses a signature by a key without the object's purpose
(TP1-004) and checks the Ed25519 rules of TP1-008. TP1-007, the limits on the
bytes that a verifier loads, has no vector: an assessor checks that the
verifier refuses a trust policy or a bundle over its limit before it parses the
input. These checks establish a verifier's behavior, not the identity or
independence of an assessor or the trustworthiness of production keys.
