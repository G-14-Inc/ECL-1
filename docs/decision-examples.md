# Decisions that need more than a wire-format check

These examples explain Section 4.3, ECL1N-0174/0178, ECL1N-0050/0056 and
OA1-008. The requirements are authoritative. A schema or signed bundle cannot
by itself establish how a deployed source, approval display, administrator or
legal decision operates. Assessors examine the controls and keep the results.

## Decision-input classification

| Observation | Classification and acceptance evidence |
| --- | --- |
| The AI writes `approved=true` to a database, then reads it | `actor_supplied`; storage and retrieval add no authority |
| A service signs the AI's assertion without validating it | `actor_supplied`; the signature establishes receipt, not independent authority |
| A budget service independently checks and commits a permitted debit | The resulting authoritative balance can be `verifiable`; test that the actor cannot choose the balance or bypass the debit rules |
| A payment provider supplies an authenticated balance after an admitted payment | Can be `verifiable`; establish the provider's authority, freshness, account scope and state-transition controls |
| An authorized principal signs a mandate through a channel the AI cannot control | Can be `verifiable` for the signed scope; check principal authority, expiry and revocation |
| An independent sensor measures a state changed by an admitted action | Can be `verifiable` for its measurement under declared assumptions; causal influence is distinct from forging its reading |
| The AI selects one authentic observation and omits others | Authenticity can hold while completeness fails; refuse an admit that needs completeness without independent evidence for it |
| An authentic balance snapshot is too old | Authenticity does not establish current authority; a required stale input cannot support an admit |
| A model summarizes authoritative records or assigns a risk score | A meaning/risk judgment remains `judgment`; a deterministic transformation keeps the least trusted input class and its declared derivation |
| The actor can replace the source key or validation code | `actor_supplied`; the actor controls authenticity or transition checks |

For each applicable case, inspect the source's actual privileges and validation,
try an unauthorized assertion or transition, and record the source, scope,
freshness and completeness on which the policy relies. The wire-level one-way
rule still prevents actor assertions and judgments from relaxing an outcome.

## Human approval

Exercise the real interface, including its accessible alternative:

1. Show a harmless summary while hiding a consequential amount, destination,
   deletion scope or privilege change. It cannot support approval.
2. Show only a parameter digest. It cannot support informed approval.
3. Use look-alike account names, truncated identifiers, different units or
   currency, rounding and locale changes. The presentation identifies the
   actual recipient, scope and values without changing their meaning.
4. Approve an action, then change an amount or destination. The old approval
   cannot release the changed action; a new presentation and approval are needed.
5. Confirm that the presentation is retained by reference and digest, the full
   parameters are accessible, and the record binds it to the canonical action.

Time spent on the page alone does not establish understanding. The assessment
records the interface behavior and action binding, without claiming to read
the approver's mind.

## OAuth capability

Version 1.0 supports an empty obligations list only. A token issuer refuses
every admit carrying an obligation, including a claimed prior discharge.
The corpus has separate cases for `before_release`, `during_execution` and
`after_execution`; all three verifiers reject the issuer's record. A valid
obligation-free token still needs the profile's normal signature, audience,
time, exact action, proof-of-possession, use and revocation controls.

A proof that expires, state that changes after issue, an unreachable proof
service or an unsupported critical condition cannot be made safe by omitting
the obligation. Use a DCMP-2 enforcement path that can meet and evidence the
obligation at its required boundary. For policy/grant invalidation, measure
the actual propagation bound rather than assuming a token's lifetime suffices.

## Retention conflicts

Use a qualified legal review of the actual records, purpose, jurisdiction,
holds and requests. These cases specify engineering behavior and do not decide
which law applies:

| Case | Evidence and expected behavior |
| --- | --- |
| No legal conflict | Retain the required evidence for the applicable floor |
| A reviewer determines that minimization is required earlier | Record authority, basis, scope and deadline; minimize the relevant content and identifiers; retain only lawful accountability material |
| A hold conflicts with a removal request | Obtain a recorded legal precedence decision within the applicable deadline; an administrative hold supplies no independent legal authority |
| An original is lawfully destroyed | Record lawful destruction evidence and residual limits; disclose unavailable evidence and reassess affected claims |
| A verifier receives a destruction record instead of required evidence | Apply EBMP-2’s defined bundle verdict and primary finding to the evidence present; determine assessment status separately under Section 7.6; never claim a complete original bundle |

Do not assume that retaining a hash satisfies privacy obligations. The assessor
checks the recorded determination and actual transformation, replica handling,
access restrictions and claim consequences. Review of release rights is separate.

## Independence and shared roots

FR-001 applies at every class. Exercise each power in the ECL1N-0056 matrix:

| Deployment | Result and required evidence |
| --- | --- |
| Two processes and two keys, with one root able to replace both | Fails every class; labels and logs do not remove the common power |
| One operator, separated credentials and control roots, with no one role able to change both planes | Can satisfy Class A if the other requirements and cross-plane tests hold; this supplies no separate-administration claim |
| One cloud administrator can replace both the AI and its enforcement configuration | Fails every class even if runtime workload credentials differ |
| Shared hardware with a boundary that prevents its ordinary host root from changing effective controls | Co-location alone decides nothing; test the actual capabilities and all remaining roots |
| Approval is separately administered but verification is not | Does not satisfy Class B |
| Both approval and verification are separately administered | Can satisfy Class B if every lower-class test passes |
| Both functions are held by an externally independent authority | Can satisfy Class C if every Class B test and the external-independence review passes |

Record administrator, credential-custodian and host-compromise powers. A diagram
without attempted cross-plane changes is insufficient assessment evidence.
