# ECL Transactional Effect Profile 1

Requirement-IDs: compiled
Version: 1.0
Status: normative profile in the ECL-1 Version 1 public-review local candidate
Source build: `1.0.2-review.1`; prepared `2026-11-10`

This profile governs a declared action class over a store with the properties
below. It is self-contained: the values a deployment chooses, such as the
acknowledgment bound B and the maximum authorization validity, are parameters
that a claim declares. The parenthesized CE labels name counterexamples of the
informative catalog at the end of this profile: each is an adverse condition
under which a test of the obligation is run, and a claim names its own test
catalog under TE1-013. The store and clock assumptions stated in the
obligations are part of the declared scope.

The release boundary of an action under this profile (ECL1N-0185) is the
admission instant of TE1-002, and its effect boundary is the commit of the same
transaction, which TE1-002 and TE1-004 bind to the admission and to the evidence
of the effect.

**TE1-001** — The effect store MUST refuse changes to protected resources from every credential available to the SoI's services or agents except through the admission function. Credentials outside the declared trust boundary (store superuser, schema owner, host administrator) MUST be enumerated in the claim's negative boundary. (CE-13)

**TE1-002** — Before evaluating authority, time, control state and preconditions, admission MUST establish mutual exclusion against every control change and competing effect that could invalidate those evaluations, using a declared total lock order whose control-change conflicts are **fairly queued** (a waiting control change MUST NOT be overtaken indefinitely by later-arriving compatible work); MUST evaluate all of them at one admission instant from the declared time source while that exclusion holds; and MUST commit the effect atomically with the admission. An equivalent isolation mechanism MAY substitute under ECL1N-0061 with evidence. (CE-01, CE-05, CE-32)

**TE1-003** — The claim MUST define the action-key namespace, including any authenticated principal or tenant context it uses to distinguish independent intents. Within that declared namespace, an action key MUST produce at most one committed effect, and a charged policy or grant use under TE1-010 MUST produce at most one committed effect, across retries, reissues, concurrent duplicates, crashes and recovery. (CE-02..04, CE-08)

**TE1-004** — Evidence of a committed effect MUST be committed atomically with the effect, and the store MUST refuse a terminal record that contradicts the presence or absence of the effect. Evidence of a non-effect outcome MUST be durable before the outcome is reported. An artifact MUST NOT be fabricated for a dependency that produced none. (CE-09, CE-30, CE-11)

**TE1-005** — A control change MUST be acknowledged only after it is durable; every effect MUST be serialized entirely before or after each control change affecting its scope; after acknowledgment no effect depending on the halted scope or revoked authority may commit. The acknowledgment bound B MUST be declared and enforced — a single acknowledgment attempt MUST succeed within B under sustained admission load and against sessions that override cooperative timeouts, if necessary by terminating the conflicting effect and issuance sessions. Contention between two emergency-plane operations is outside B, and each such operation MUST NOT hold its transaction open. (CE-05, CE-12, CE-31, CE-32)

**TE1-006** — A retry with the same action key and request digest MUST return the committed outcome without re-applying the effect, and MUST NOT report a committed success as denied. A same-key request with a different digest MUST be rejected as a distinct intent. (CE-04, CE-08)

**TE1-007** — Non-release outcomes MUST NOT emit `authority_consumed` or `execution_released`, MUST NOT carry side effects, and MUST be recorded with their own EBMP-2 non-release state (`denied`, `held`, `challenged`, `expired_before_release`), never coerced into another state. (CE-21, CE-22)

**TE1-008** — The applied parameters, target and expected precondition MUST be exactly those bound by the admitted authorization; that per-action DCMP-2 authorization MUST be `single_use` under DCMP2-050 and verifiably bound to the action key and request digest; and admission MUST refuse an authorization whose bound values differ from those the enforcement point requested. (CE-14, CE-28)

**TE1-009** — Every decision about time MUST use one declared time source of a declared time class; the deployment MUST declare the source's discipline and the verifier-facing skew policy; admission MUST reject an instant earlier than the authorization's issue time; and the claim MUST declare a maximum authorization validity, which producer, consumer and verifier MUST each enforce by rejecting a longer validity. (CE-16, CE-27)

**TE1-010** — A policy or higher-level grant quota MUST be accounted in charged uses: a charge is consumed at most once per action key, never re-consumed by reissue or retry, MUST NOT exceed the grant's maximum, and a charged action later denied at admission still consumes its charge. The profile MUST state this consumption rule. This quota is separate from each action's DCMP-2 `single_use` authorization; charging the quota MUST NOT by itself create release authority or an EBMP-2 `authority_consumed` event. Such an event records per-action release-authority consumption only when TE1-007 and the outcome evidence table permit it. (CE-24)

**TE1-011** — Each terminal outcome class MUST yield the evidence set that the TRANSACTIONAL-EFFECT-1 outcome evidence table gives for it, with a terminal reason as specified by that table; any reason carried MUST be a registered identifier; requests rejected before an action is claimed are outside evidence scope and the claim MUST say so. (CE-21, CE-25)

**TE1-012** — The emergency control plane (halt, resume, revoke) MUST be authenticated separately from policy administration, restricted to containment actions, and separately audited; its use MUST be visible in the control event stream. (CE-13, CE-31)

**TE1-013** — A claim of this profile MUST name its counterexample-test catalog,
store, action class and declared bound B under which it was demonstrated, and
MUST label effect evidence issuer-asserted unless corroborated.

## Outcome evidence table

The envelopes of each outcome class's evidence bundle, in causal order, and its
terminal reason. A terminal reason is a registered identifier carried in the
extension `ecl.ext.outcome-reason.v1`; "bound" means the terminal event names the
response as its `decision` reference by identifier and digest. Corroborating
observations attach through the bundle's `observations` member and are not
produced by the enforcement point.

| Outcome class | Envelopes, in causal order | Terminal reason |
| --- | --- | --- |
| Rejected before an action is claimed | None: outside evidence scope (TE1-011) | None |
| Succeeded | request; response (`admit`); `authority_consumed`; `execution_released`; `execution_terminal` (`succeeded`) | None |
| Denied by the decision point | request; response (`deny`), bound; `execution_terminal` (`denied`) | The response's primary reason |
| Denied at admission | request; response (`admit`), bound; `execution_terminal` (`denied`); no `authority_consumed` or `execution_released` | The admission refusal's registered reason |
| Expired before release | request; response (`admit`), bound; `execution_terminal` (`expired_before_release`); no `authority_consumed` or `execution_released` | `ecl.error.expired.v1` |
| Held or challenged | request; response (`hold` or `challenge`), bound; `execution_terminal` (`held` or `challenged`) | Optional |
| Obligations unsupported | request; response (`admit` with obligations), bound; `execution_terminal` (`denied`); no `authority_consumed` or `execution_released` | `ecl.error.safe-state-required.v1` |
| Decision point unavailable | request; `execution_terminal` (`denied`); no decision-point object, and none fabricated | `ecl.error.dependency-unavailable.v1` |
| Decision point response invalid | request; `execution_terminal` (`denied`); the invalid artifact kept outside the bundle | The registered reason for the failed check, under the binding's error precedence: for MCP/DCMP2-HTTP-1, `ecl.error.integrity-invalid.v1`, `ecl.error.signature-policy-invalid.v1`, `ecl.error.request-binding-invalid.v1`, or `ecl.error.dependency-response-invalid.v1`, as applicable |

## Evidence and counterexamples (informative)

| Kind | What the citation establishes |
|---|---|
| Vectors | Message semantics and offline artifact checks |
| Counterexample tests | Each obligation under the adverse conditions its CE labels name, against the declared store, action class, clock and load |

The CE labels name the adverse conditions in the last table below. A claim
names its own counterexample-test catalog under TE1-013; these labels are one
set of conditions that such a catalog can cover. Passing an offline signature
check does not prove its transaction, clock or privilege properties. The
profile itself makes no observer-independence or assessment-class claim.
Privileged store operators and the signer's possible backdating remain
disclosed claim boundaries.

| Profile requirement | Counterexamples |
|---|---|
| TE1-001 | CE-13 |
| TE1-002 | CE-01, CE-05, CE-32 |
| TE1-003 | CE-02..04, CE-08 |
| TE1-004 | CE-09, CE-30, CE-11 |
| TE1-005 | CE-05, CE-12, CE-31, CE-32 |
| TE1-006 | CE-04, CE-08 |
| TE1-007 | CE-21, CE-22 |
| TE1-008 | CE-14, CE-28 |
| TE1-009 | CE-16, CE-27 |
| TE1-010 | CE-24 |
| TE1-011 | CE-21, CE-25 |
| TE1-012 | CE-13, CE-31 |
| TE1-013 | The claim's declared catalog, store, action class, B and corroboration provenance |

| Counterexample | Adverse condition | Required result |
|---|---|---|
| CE-01 | The lock on the protected record is held past the authorization's `valid_until` while admission waits | Denied as expired before release; no effect; the charged use is consumed |
| CE-02 | Two generations of authorization for one action race | One effect; both callers see the same terminal outcome |
| CE-03 | Many concurrent identical requests share one action key | One effect and identical responses |
| CE-04 | The same raw action-key value is used in two declared namespaces distinguished by authenticated principal or tenant context, or a request body changes within one namespace | Independent actions in the different namespaces; a changed body under the same namespaced key is refused as a distinct intent |
| CE-05 | A halt arrives while an effect transaction waits on the record | The effect commits before the halt or is denied; nothing commits after the acknowledgment |
| CE-08 | The connection is lost after the commit is sent | A retry returns the stored committed outcome; one effect |
| CE-09 | The signer fails inside the effect transaction | The transaction rolls back with no effect; a retry succeeds once |
| CE-11 | The decision point does not answer | Denied for an unavailable dependency; no decision-point object is fabricated, and the bundle verifies |
| CE-12 | A halt arrives against effect transactions in flight | Acknowledged within the declared bound B |
| CE-13 | Each credential available to the services and agents attempts direct changes to protected resources, privilege changes and changes to evidence | Refused, apart from operations the claim declares and bounds |
| CE-14 | A changed parameter under the same action key, or another action's authorization | Refused |
| CE-16 | An authorization whose issue time is later than the admission instant | Refused as a clock rollback |
| CE-21 | Actions admitted and then denied, and actions whose authorization expired | Each bundle verifies with its recorded non-release state and issued authority, with no `authority_consumed` event; a charged use remains counted under TE1-010. These conditions do not by themselves make the bundle `incomplete`. |
| CE-22 | A `hold` or `challenge`, or an `admit` with obligations the enforcement point does not support | No effect; the terminal state is `held`, `challenged` or `denied`; every bundle verifies |
| CE-24 | The policy or higher-level grant's maximum number of charged uses is reached | Further actions are refused; retries of charged actions still complete; a charged action denied later has consumed its charge |
| CE-25 | Oversized and malformed input | Refused before any work on the store; no secret in any log or bundle |
| CE-27 | The enforcement point's host clock is skewed by minutes while the declared time source is separate and remains unaffected | No protocol timestamp or verdict changes due to the host-clock skew |
| CE-28 | A stored authorization whose bound values differ from the enforcement point's request | Refused |
| CE-30 | A committed effect with a terminal record of denial, or a success record with no effect | Both refused, and the transaction rolls back |
| CE-31 | A session disables its timeouts, admits an action and stalls, and then a halt arrives | Acknowledged within B by ending the session; the stalled transaction never commits; later admissions are denied |
| CE-32 | A halt arrives during a sustained stream of admissions | One acknowledgment within B; every effect commits before the halt |
