------------------------------ MODULE ECLCore ------------------------------
(***************************************************************************)
(* The ECL-1 runtime control invariant (standard section 5.1) at the level  *)
(* of the normative text.                                                  *)
(*                                                                         *)
(* A governed AI system (the actor below) proposes actions through         *)
(* enforcement points. A decision service returns admit, deny, hold or     *)
(* challenge under a versioned policy and trust state, and issues an       *)
(* authority object for each admit, bound to the exact request (its        *)
(* identifier and the digest of its action: target and parameters), the    *)
(* requesting enforcement point as audience, a validity window, the trust  *)
(* epoch and a single use. An enforcement point executes only with valid,  *)
(* matching, unrevoked, unused authority inside its window, with fresh     *)
(* control state and no halt, and records evidence in the same step.       *)
(* Revocations and trust changes reach enforcement points within a         *)
(* propagation bound while connected; a disconnected enforcement point     *)
(* stops once its control state is older than the staleness bound. The     *)
(* decision service can be unavailable. The emergency halt is a separate   *)
(* plane that works during that outage and is acknowledged within the      *)
(* bound B.                                                                *)
(*                                                                         *)
(* The governed AI system can propose any request through any enforcement  *)
(* point, chooses its own asserted input values (actor_supplied) and       *)
(* steers the inputs a probabilistic detector derives from its content     *)
(* (judgment), and can present any request together with any authority     *)
(* object it has seen, at any enforcement point and at any time: replay,   *)
(* use for another target, parameters, request or audience, use after      *)
(* expiry, revocation or halt. It has no action that writes a decision, an *)
(* authority object or evidence, and no path to an effect other than an    *)
(* enforcement point.                                                      *)
(*                                                                         *)
(* Variant selects the correct design ("correct") or one deliberate flaw;   *)
(* each flaw removes one rule, and TLC must find the property it breaks.    *)
(*                                                                         *)
(* Time is a discrete tick (Lamport, "Real Time is Really Simple"); a       *)
(* deadline is a condition on Tick. Hash chains, signatures and digests are *)
(* abstracted: an authority object can be created only by the decision      *)
(* service, an action's digest is the action itself (an injective digest),  *)
(* and the evidence log is a sequence that only the control layer appends   *)
(* to.                                                                     *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS
    EPs,              \* enforcement points; each is the audience of the authority it requests
    ReqIds,           \* logical request identifiers (DCMP-2 message_id)
    Targets,          \* action targets
    Params,           \* action parameters (abstracted by the parameter digest)
    Allowed,          \* actions the verifiable inputs support (system of record, mandate)
    MaxTime,          \* last tick explored
    MaxRequests,      \* requests the governed AI system may submit in one behavior
    MaxOutages,       \* outages of the decision service in one behavior
    MaxRevocations,   \* explicit revocations of authority objects
    MaxTrustChanges,  \* changes of the policy and trust epoch
    AllowHalt,        \* whether the emergency operator may halt
    Validity,         \* authorization validity in ticks (DCMP2-015, TE1-009)
    DecisionDeadline, \* how long an enforcement point waits for a decision (DCMP2-041)
    HoldDeadline,     \* deadline a hold or challenge carries (DCMP2-018)
    PropagationBound, \* connected revocation propagation (ECL1N-0097)
    StalenessBound,   \* offline control-state staleness before restricted mode (FR-110)
    HaltBound,        \* emergency-halt acknowledgment bound B (TS1-036)
    SyncWithoutNews,  \* whether a refresh with nothing new may happen (see Sync)
    Variant,          \* "correct" or one flaw from Flaws
    NoAuthority       \* a model value: the authority of an effect that had none

Flaws == {"outage_proceeds", "no_digest_binding", "no_target_binding",
          "no_audience_binding", "no_window", "no_single_use",
          "ignore_revocation", "ignore_staleness", "no_propagation_deadline",
          "ignore_halt", "halt_unbounded", "evidence_not_atomic", "bypass",
          "actor_writes_authority", "actor_writes_decision", "actor_erases_evidence",
          "judgment_admits", "self_report_admits", "hold_never_times_out",
          "no_decision_timeout", "halt_ack_lost", "late_decision_used"}

ASSUME Variant \in Flaws \cup {"correct"}
ASSUME /\ Allowed \subseteq [target : Targets, params : Params]
       /\ MaxTime \in Nat /\ MaxRequests \in Nat /\ MaxOutages \in Nat
       /\ MaxRevocations \in Nat /\ MaxTrustChanges \in Nat /\ AllowHalt \in BOOLEAN
       /\ Validity \in Nat \ {0} /\ DecisionDeadline \in Nat /\ HoldDeadline \in Nat
       /\ PropagationBound \in Nat /\ StalenessBound \in Nat /\ HaltBound \in Nat
       /\ SyncWithoutNews \in BOOLEAN

NoTime == -1
Min(a, b) == IF a <= b THEN a ELSE b
Max(a, b) == IF a >= b THEN a ELSE b
Flawed(f) == Variant = f

Actions == [target : Targets, params : Params]
Requests == [id : ReqIds, action : Actions, aud : EPs]
(* What an authorization's scope digest binds: the request identifier and   *)
(* the action (DCMP2-044).                                                  *)
Scopes == [id : ReqIds, action : Actions]
ScopeOf(r) == [id |-> r.id, action |-> r.action]

(* Decision-input classes. The verifiable input comes from a source the     *)
(* governed system cannot write; the actor writes the actor_supplied input  *)
(* and steers the judgment input.                                          *)
SelfReports == {"ok", "bad"}     \* actor_supplied: the governed system's own report
Judgments == {"low", "high"}     \* judgment: a risk score derived from actor-influenced content
Verifiable(r) == IF r.action \in Allowed THEN "permit" ELSE "forbid"

(* The Strictness Order of the core standard (Section 4.3):               *)
(* admit < challenge < hold < deny.                                        *)
Rank(o) == CASE o = "admit" -> 0
             [] o = "challenge" -> 1
             [] o = "hold" -> 2
             [] o = "deny" -> 3

(* Policy over the verifiable inputs alone.                                *)
VerifiableOnly(r) == IF Verifiable(r) = "permit" THEN "admit" ELSE "deny"

(* The decision function. Under the one-way rule the actor_supplied and    *)
(* judgment inputs only make the outcome stricter; the two flaws let one   *)
(* of them admit.                                                          *)
Evaluate(r, s, j) ==
    CASE Flawed("judgment_admits") /\ j = "low" -> "admit"
      [] Flawed("self_report_admits") /\ s = "ok" -> "admit"
      [] Verifiable(r) = "forbid" -> "deny"
      [] j = "high" -> "hold"
      [] s = "bad" -> "challenge"
      [] OTHER -> "admit"

AuthorityOf(d) ==
    [req |-> d.req, aud |-> d.req.aud, from |-> d.at, until |-> d.at + Validity,
     epoch |-> d.epoch]

VARIABLES
    now,          \* global tick
    dsUp,         \* decision service available
    upSince,      \* tick since which it has been continuously up, or NoTime
    downSince,    \* tick at which the current outage began, or NoTime
    outages,      \* outages so far
    submitted,    \* requests the actor has submitted
    pending,      \* [req, deadline]: awaiting a decision
    held,         \* [req, deadline]: held or challenged, awaiting an authenticated input
    decisions,    \* decision records; only the decision service adds to this set
    issued,       \* authority objects; only the decision service adds to this set
    consumed,     \* authority objects an enforcement point has used
    revocations,  \* [auth, at]: explicit revocations at the control plane
    trustEpoch,   \* policy and trust epoch at the control plane
    trustChanges, \* [epoch, at]: when each epoch began
    view,         \* enforcement point -> [synced, epoch, revoked]: its local control state
    haltAt,       \* tick of the emergency halt request, or NoTime
    halted,       \* enforcement point -> halt acknowledged
    closed,       \* requests that ended in deny or the declared safe state
    effects,      \* effects that occurred
    unlogged,     \* effects whose evidence is not yet written (flaw evidence_not_atomic only)
    log           \* append-only evidence log

vars == << now, dsUp, upSince, downSince, outages, submitted, pending, held,
           decisions, issued, consumed, revocations, trustEpoch, trustChanges,
           view, haltAt, halted, closed, effects, unlogged, log >>

Times == NoTime..MaxTime
Epochs == 0..MaxTrustChanges
Authorities == [req : Requests, aud : EPs, from : 0..MaxTime,
                until : Validity..(MaxTime + Validity), epoch : Epochs]
Decisions == [req : Requests, outcome : {"admit", "deny", "hold", "challenge"},
              at : 0..MaxTime, epoch : Epochs]
Effects == [n : Nat, ep : EPs, scope : Scopes, auth : Authorities \cup {NoAuthority},
            at : 0..MaxTime, up : BOOLEAN, upSince : Times, downSince : Times]

TypeOK ==
    /\ now \in 0..MaxTime
    /\ dsUp \in BOOLEAN /\ upSince \in Times /\ downSince \in Times
    /\ outages \in 0..MaxOutages
    /\ submitted \subseteq Requests
    /\ pending \subseteq [req : Requests, deadline : 0..MaxTime]
    /\ held \subseteq [req : Requests, deadline : 0..MaxTime]
    /\ decisions \subseteq Decisions
    /\ issued \subseteq Authorities
    /\ consumed \subseteq Authorities
    /\ revocations \subseteq [auth : Authorities, at : 0..MaxTime]
    /\ trustEpoch \in Epochs
    /\ trustChanges \subseteq [epoch : Epochs, at : 0..MaxTime]
    /\ view \in [EPs -> [synced : 0..MaxTime, epoch : Epochs, revoked : SUBSET Authorities]]
    /\ haltAt \in Times
    /\ halted \in [EPs -> BOOLEAN]
    /\ closed \subseteq Requests
    /\ effects \subseteq Effects
    /\ unlogged \subseteq effects
    /\ log \in Seq([kind : {"effect"}, n : Nat])

Init ==
    /\ now = 0
    /\ dsUp = TRUE /\ upSince = 0 /\ downSince = NoTime /\ outages = 0
    /\ submitted = {} /\ pending = {} /\ held = {}
    /\ decisions = {} /\ issued = {} /\ consumed = {}
    /\ revocations = {} /\ trustEpoch = 0 /\ trustChanges = {}
    /\ view = [ep \in EPs |-> [synced |-> 0, epoch |-> 0, revoked |-> {}]]
    /\ haltAt = NoTime /\ halted = [ep \in EPs |-> FALSE]
    /\ closed = {} /\ effects = {} /\ unlogged = {} /\ log = << >>

-----------------------------------------------------------------------------
(* The governed AI system (the actor).                                     *)

(* Propose any request through any enforcement point (its audience).       *)
Submit(r) ==
    /\ Cardinality(submitted) < MaxRequests
    /\ r \notin submitted
    /\ submitted' = submitted \cup {r}
    /\ pending' = pending \cup {[req |-> r, deadline |-> Min(now + DecisionDeadline, MaxTime)]}
    /\ UNCHANGED << now, dsUp, upSince, downSince, outages, held, decisions, issued,
                    consumed, revocations, trustEpoch, trustChanges, view, haltAt,
                    halted, closed, effects, unlogged, log >>

(* Flaw "bypass": a path from the actor to the effect that skips the       *)
(* enforcement point (ECL1N-0033, ECL1N-0141).                             *)
DirectEffect(r) ==
    /\ Flawed("bypass")
    /\ r \in submitted
    /\ effects' = effects \cup {[n |-> Cardinality(effects), ep |-> r.aud, scope |-> ScopeOf(r),
                                 auth |-> NoAuthority, at |-> now, up |-> dsUp,
                                 upSince |-> upSince, downSince |-> downSince]}
    /\ UNCHANGED << now, dsUp, upSince, downSince, outages, submitted, pending, held,
                    decisions, issued, consumed, revocations, trustEpoch, trustChanges,
                    view, haltAt, halted, closed, unlogged, log >>

(* Flaw "actor_writes_authority": the actor can create an authority object *)
(* (ECL1N-0046, FR-001).                                                    *)
ForgeAuthority(r) ==
    /\ Flawed("actor_writes_authority")
    /\ r \in submitted
    /\ issued' = issued \cup {[req |-> r, aud |-> r.aud, from |-> now,
                               until |-> now + Validity, epoch |-> trustEpoch]}
    /\ UNCHANGED << now, dsUp, upSince, downSince, outages, submitted, pending, held,
                    decisions, consumed, revocations, trustEpoch, trustChanges, view,
                    haltAt, halted, closed, effects, unlogged, log >>

(* Flaw "actor_writes_decision": the actor can record an admit, and so      *)
(* obtain its authority object (ECL1N-0046, FR-001).                       *)
ForgeDecision(r) ==
    /\ Flawed("actor_writes_decision")
    /\ r \in submitted
    /\ LET d == [req |-> r, outcome |-> "admit", at |-> now, epoch |-> trustEpoch]
       IN /\ decisions' = decisions \cup {d}
          /\ issued' = issued \cup {AuthorityOf(d)}
    /\ UNCHANGED << now, dsUp, upSince, downSince, outages, submitted, pending, held,
                    consumed, revocations, trustEpoch, trustChanges, view, haltAt,
                    halted, closed, effects, unlogged, log >>

(* Flaw "actor_erases_evidence": the actor can remove the latest evidence   *)
(* record (EBMP2-038, ECL1N-0047).                                         *)
EraseEvidence ==
    /\ Flawed("actor_erases_evidence")
    /\ Len(log) > 0
    /\ log' = SubSeq(log, 1, Len(log) - 1)
    /\ UNCHANGED << now, dsUp, upSince, downSince, outages, submitted, pending, held,
                    decisions, issued, consumed, revocations, trustEpoch, trustChanges,
                    view, haltAt, halted, closed, effects, unlogged >>

-----------------------------------------------------------------------------
(* The decision service. s and j are chosen by the governed AI system.     *)

Decide(p, s, j) ==
    /\ dsUp
    /\ p \in pending
    /\ LET r == p.req
           collision == \E d \in decisions : d.req.id = r.id /\ d.req # r   \* DCMP2-005
           o == IF collision THEN "deny" ELSE Evaluate(r, s, j)
           d == [req |-> r, outcome |-> o, at |-> now, epoch |-> trustEpoch]
       IN /\ pending' = pending \ {p}
          /\ decisions' = decisions \cup {d}
          /\ issued' = IF o = "admit" THEN issued \cup {AuthorityOf(d)} ELSE issued
          /\ held' = IF o \in {"hold", "challenge"}
                        THEN held \cup {[req |-> r, deadline |-> Min(now + HoldDeadline, MaxTime)]}
                        ELSE held
          /\ closed' = IF o = "deny" THEN closed \cup {r} ELSE closed
    /\ UNCHANGED << now, dsUp, upSince, downSince, outages, submitted, consumed,
                    revocations, trustEpoch, trustChanges, view, haltAt, halted,
                    effects, unlogged, log >>

(* An authenticated approval or signed witness answers a hold or challenge *)
(* (ECL1N-0177, DCMP2-021). The actor cannot perform this step. The new    *)
(* evaluation rests on the verifiable inputs.                              *)
Resolve(h) ==
    /\ dsUp
    /\ h \in held
    /\ LET r == h.req
           o == VerifiableOnly(r)
           d == [req |-> r, outcome |-> o, at |-> now, epoch |-> trustEpoch]
       IN /\ held' = held \ {h}
          /\ decisions' = decisions \cup {d}
          /\ issued' = IF o = "admit" THEN issued \cup {AuthorityOf(d)} ELSE issued
          /\ closed' = IF o = "deny" THEN closed \cup {r} ELSE closed
    /\ UNCHANGED << now, dsUp, upSince, downSince, outages, submitted, pending, consumed,
                    revocations, trustEpoch, trustChanges, view, haltAt, halted,
                    effects, unlogged, log >>

-----------------------------------------------------------------------------
(* Enforcement points.                                                     *)

(* No decision before the deadline: the declared safe state (DCMP2-041,    *)
(* TS1-009). Flaw "outage_proceeds": when the decision service is down the  *)
(* enforcement point lets the action go ahead. Flaw "late_decision_used":   *)
(* the request stays open at the decision service, so a decision that       *)
(* arrives after the safe state can still release it (DCMP2-014).           *)
DecisionTimeout(p) ==
    /\ ~Flawed("no_decision_timeout")
    /\ p \in pending
    /\ now >= p.deadline
    /\ ~(Flawed("late_decision_used") /\ p.req \in closed)
    /\ pending' = IF Flawed("late_decision_used") THEN pending ELSE pending \ {p}
    /\ IF Flawed("outage_proceeds") /\ ~dsUp
         THEN LET e == [n |-> Cardinality(effects), ep |-> p.req.aud, scope |-> ScopeOf(p.req),
                        auth |-> NoAuthority, at |-> now, up |-> dsUp,
                        upSince |-> upSince, downSince |-> downSince]
              IN /\ effects' = effects \cup {e}
                 /\ log' = Append(log, [kind |-> "effect", n |-> e.n])
                 /\ UNCHANGED closed
         ELSE /\ closed' = closed \cup {p.req}
              /\ UNCHANGED << effects, log >>
    /\ UNCHANGED << now, dsUp, upSince, downSince, outages, submitted, held, decisions,
                    issued, consumed, revocations, trustEpoch, trustChanges, view,
                    haltAt, halted, unlogged >>

(* A hold or challenge that is not answered by its deadline ends in the    *)
(* declared safe state (DCMP2-018). Flaw "hold_never_times_out".           *)
HoldTimeout(h) ==
    /\ ~Flawed("hold_never_times_out")
    /\ h \in held
    /\ now >= h.deadline
    /\ held' = held \ {h}
    /\ closed' = closed \cup {h.req}
    /\ UNCHANGED << now, dsUp, upSince, downSince, outages, submitted, pending,
                    decisions, issued, consumed, revocations, trustEpoch, trustChanges,
                    view, haltAt, halted, effects, unlogged, log >>

(* The checks an enforcement point applies to a presented request and      *)
(* authority object; each flaw drops one.                                  *)
Admissible(ep, sc, a) ==
    /\ a.req.id = sc.id                                                          \* DCMP2-044
    /\ Flawed("no_digest_binding") \/ a.req.action.params = sc.action.params    \* DCMP2-007, DCMP2-044
    /\ Flawed("no_target_binding") \/ a.req.action.target = sc.action.target    \* DCMP2-044
    /\ Flawed("no_audience_binding") \/ a.aud = ep                             \* DCMP2-048
    /\ Flawed("no_window") \/ (a.from <= now /\ now < a.until)                \* DCMP2-049, EBMP2-050
    /\ Flawed("no_single_use") \/ a \notin consumed                            \* DCMP2-050, EBMP2-008
    /\ Flawed("ignore_revocation")
         \/ (a \notin view[ep].revoked /\ a.epoch >= view[ep].epoch)           \* DCMP2-014, ECL1N-0053
    /\ Flawed("ignore_staleness") \/ now - view[ep].synced <= StalenessBound    \* FR-110, TS1-013
    /\ Flawed("ignore_halt") \/ ~halted[ep]                                    \* TS1-025, FR-004

(* The actor presents any request, named by its scope (identifier and       *)
(* action), with any authority object it has seen, at any enforcement      *)
(* point. Effect and evidence are one step (TE1-004); flaw                 *)
(* "evidence_not_atomic" separates them.                                   *)
Execute(ep, sc, a) ==
    /\ a \in issued
    /\ Admissible(ep, sc, a)
    /\ LET e == [n |-> Cardinality(effects), ep |-> ep, scope |-> sc, auth |-> a, at |-> now,
                 up |-> dsUp, upSince |-> upSince, downSince |-> downSince]
       IN /\ effects' = effects \cup {e}
          /\ consumed' = consumed \cup {a}
          /\ IF Flawed("evidence_not_atomic")
               THEN /\ unlogged' = unlogged \cup {e}
                    /\ UNCHANGED log
               ELSE /\ log' = Append(log, [kind |-> "effect", n |-> e.n])
                    /\ UNCHANGED unlogged
    /\ UNCHANGED << now, dsUp, upSince, downSince, outages, submitted, pending, held,
                    decisions, issued, revocations, trustEpoch, trustChanges, view,
                    haltAt, halted, closed >>

RecordEvidence(e) ==
    /\ e \in unlogged
    /\ unlogged' = unlogged \ {e}
    /\ log' = Append(log, [kind |-> "effect", n |-> e.n])
    /\ UNCHANGED << now, dsUp, upSince, downSince, outages, submitted, pending, held,
                    decisions, issued, consumed, revocations, trustEpoch, trustChanges,
                    view, haltAt, halted, closed, effects >>

(* An enforcement point refreshes its control state while the control      *)
(* plane is reachable (ECL1N-0053, FR-110). A configuration in which no     *)
(* bound can expire (both bounds at least MaxTime) may set SyncWithoutNews  *)
(* to FALSE: a refresh that brings nothing new then changes no enforcement  *)
(* decision, and leaving it out only removes redundant states.              *)
Sync(ep) ==
    /\ dsUp
    /\ LET fresh == [synced |-> now, epoch |-> trustEpoch, revoked |-> {rv.auth : rv \in revocations}]
       IN /\ view[ep] # fresh
          /\ \/ SyncWithoutNews
             \/ view[ep].epoch # fresh.epoch
             \/ view[ep].revoked # fresh.revoked
          /\ view' = [view EXCEPT ![ep] = fresh]
    /\ UNCHANGED << now, dsUp, upSince, downSince, outages, submitted, pending, held,
                    decisions, issued, consumed, revocations, trustEpoch, trustChanges,
                    haltAt, halted, closed, effects, unlogged, log >>

-----------------------------------------------------------------------------
(* Control plane, emergency plane and environment.                         *)

Revoke(a) ==
    /\ a \in issued
    /\ Cardinality(revocations) < MaxRevocations
    /\ ~\E rv \in revocations : rv.auth = a
    /\ revocations' = revocations \cup {[auth |-> a, at |-> now]}
    /\ UNCHANGED << now, dsUp, upSince, downSince, outages, submitted, pending, held,
                    decisions, issued, consumed, trustEpoch, trustChanges, view, haltAt,
                    halted, closed, effects, unlogged, log >>

(* A policy or trust change ends every authority issued under the earlier  *)
(* epoch.                                                                  *)
TrustChange ==
    /\ trustEpoch < MaxTrustChanges
    /\ trustEpoch' = trustEpoch + 1
    /\ trustChanges' = trustChanges \cup {[epoch |-> trustEpoch + 1, at |-> now]}
    /\ UNCHANGED << now, dsUp, upSince, downSince, outages, submitted, pending, held,
                    decisions, issued, consumed, revocations, view, haltAt, halted,
                    closed, effects, unlogged, log >>

Fail ==
    /\ dsUp
    /\ outages < MaxOutages
    /\ dsUp' = FALSE /\ downSince' = now /\ upSince' = NoTime /\ outages' = outages + 1
    /\ UNCHANGED << now, submitted, pending, held, decisions, issued, consumed,
                    revocations, trustEpoch, trustChanges, view, haltAt, halted, closed,
                    effects, unlogged, log >>

Recover ==
    /\ ~dsUp
    /\ dsUp' = TRUE /\ upSince' = now /\ downSince' = NoTime
    /\ UNCHANGED << now, outages, submitted, pending, held, decisions, issued, consumed,
                    revocations, trustEpoch, trustChanges, view, haltAt, halted, closed,
                    effects, unlogged, log >>

(* The emergency plane is separately authenticated: the actor cannot use   *)
(* it, and it does not depend on the decision service (FR-004, DCMP2-025). *)
HaltRequest ==
    /\ AllowHalt
    /\ haltAt = NoTime
    /\ haltAt' = now
    /\ UNCHANGED << now, dsUp, upSince, downSince, outages, submitted, pending, held,
                    decisions, issued, consumed, revocations, trustEpoch, trustChanges,
                    view, halted, closed, effects, unlogged, log >>

HaltAck(ep) ==
    /\ ~Flawed("halt_ack_lost")
    /\ haltAt # NoTime
    /\ ~halted[ep]
    /\ halted' = [halted EXCEPT ![ep] = TRUE]
    /\ UNCHANGED << now, dsUp, upSince, downSince, outages, submitted, pending, held,
                    decisions, issued, consumed, revocations, trustEpoch, trustChanges,
                    view, haltAt, closed, effects, unlogged, log >>

(* Time advances only when the deadlines the control layer owes are met:   *)
(* connected propagation within PropagationBound (ECL1N-0097) and halt     *)
(* acknowledgment within HaltBound (TS1-036).                              *)
Tick ==
    /\ now < MaxTime
    /\ \/ Flawed("no_propagation_deadline")
       \/ \A ep \in EPs : ~dsUp \/ now + 1 - view[ep].synced <= PropagationBound
    /\ \/ Flawed("halt_unbounded")
       \/ haltAt = NoTime
       \/ now + 1 - haltAt <= HaltBound
       \/ \A ep \in EPs : halted[ep]
    /\ now' = now + 1
    /\ UNCHANGED << dsUp, upSince, downSince, outages, submitted, pending, held,
                    decisions, issued, consumed, revocations, trustEpoch, trustChanges,
                    view, haltAt, halted, closed, effects, unlogged, log >>

Next ==
    \/ \E r \in Requests : Submit(r)
    \/ \E p \in pending, s \in SelfReports, j \in Judgments : Decide(p, s, j)
    \/ \E h \in held : Resolve(h)
    \/ \E p \in pending : DecisionTimeout(p)
    \/ \E h \in held : HoldTimeout(h)
    \/ \E ep \in EPs, sc \in Scopes, a \in issued : Execute(ep, sc, a)
    \/ \E e \in unlogged : RecordEvidence(e)
    \/ \E r \in submitted : DirectEffect(r)
    \/ \E r \in submitted : ForgeAuthority(r)
    \/ \E r \in submitted : ForgeDecision(r)
    \/ EraseEvidence
    \/ \E a \in issued : Revoke(a)
    \/ TrustChange
    \/ \E ep \in EPs : Sync(ep)
    \/ Fail
    \/ Recover
    \/ HaltRequest
    \/ \E ep \in EPs : HaltAck(ep)
    \/ Tick

(* Fairness for the steps the control layer owes; none for the actor, the  *)
(* environment (outages) or the operators.                                 *)
Fairness ==
    /\ WF_vars(Tick)
    /\ \A ep \in EPs : WF_vars(Sync(ep)) /\ WF_vars(HaltAck(ep))
    /\ WF_vars(\E p \in pending : DecisionTimeout(p))
    /\ WF_vars(\E h \in held : HoldTimeout(h))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* Safety properties.                                                      *)

(* S1. No effect without a matching admit: every effect rests on an admit  *)
(* the decision service issued for exactly that request, that is, for its  *)
(* identifier and the digest of its action, which the authorization's      *)
(* scope digest binds (DCMP2-044), with that enforcement point as audience *)
(* (DCMP2-048). Other members of a presented request do not reach the      *)
(* effect.                                                                 *)
EffectHasMatchingAdmit ==
    \A e \in effects :
        /\ e.auth # NoAuthority
        /\ \E d \in decisions : /\ d.outcome = "admit"
                                /\ AuthorityOf(d) = e.auth
                                /\ ScopeOf(d.req) = e.scope
        /\ e.auth.aud = e.ep

(* S2. No effect from authority used outside its scope, audience, window   *)
(* or use count.                                                           *)
EffectWithinAuthority ==
    \A e \in effects : e.auth # NoAuthority =>
        /\ ScopeOf(e.auth.req) = e.scope
        /\ e.auth.aud = e.ep
        /\ e.auth.from <= e.at /\ e.at < e.auth.until

SingleUse ==
    \A e1, e2 \in effects : (e1.auth # NoAuthority /\ e1.auth = e2.auth) => e1 = e2

(* S3. No effect at an enforcement point after it acknowledged a halt, and *)
(* none anywhere later than HaltBound after the halt request.              *)
NoEffectAtHaltedEP == [][\A e \in effects' \ effects : ~halted[e.ep]]_vars

NoEffectBeyondHaltBound ==
    \A e \in effects : haltAt = NoTime \/ e.at <= haltAt + HaltBound

(* S4. Revocation and trust changes: no effect once the enforcement point  *)
(* knows of them; none later than the propagation bound after them while   *)
(* the control plane was reachable throughout, and none later than the     *)
(* larger of the two bounds in any case.                                   *)
EndTimes(a) ==
    {rv.at : rv \in {x \in revocations : x.auth = a}}
        \cup {tc.at : tc \in {x \in trustChanges : x.epoch > a.epoch}}

RevocationBound ==
    \A e \in effects : e.auth # NoAuthority =>
        \A t \in EndTimes(e.auth) :
            /\ e.at <= t + Max(PropagationBound, StalenessBound)
            /\ (e.up /\ e.upSince <= t) => e.at <= t + PropagationBound

NoEffectWithKnownRevocation ==
    [][\A e \in effects' \ effects :
          e.auth # NoAuthority =>
              /\ e.auth \notin view[e.ep].revoked
              /\ e.auth.epoch >= view[e.ep].epoch]_vars

(* S5. Every effect has an evidence record, and the log is append-only.    *)
EffectHasEvidence ==
    \A e \in effects : \E i \in 1..Len(log) : log[i].kind = "effect" /\ log[i].n = e.n

LogAppendOnly == [][Len(log') >= Len(log) /\ SubSeq(log', 1, Len(log)) = log]_vars

DecisionsAppendOnly == [][decisions \subseteq decisions' /\ issued \subseteq issued']_vars

(* S6. The one-way rule: every decision is at least as strict, in the     *)
(* Strictness Order, as the policy over the verifiable inputs alone (the   *)
(* Verifiable-Only Outcome), so an admit never rests only on               *)
(* actor_supplied or judgment inputs.                                      *)
OneWayRule == \A d \in decisions : Rank(d.outcome) >= Rank(VerifiableOnly(d.req))

AdmitOnlyAllowed == \A d \in decisions : d.outcome = "admit" => d.req.action \in Allowed

(* S7. An outage never lets an action go ahead: an effect while the        *)
(* decision service is down rests on an admit issued before the outage     *)
(* began, inside the staleness bound measured from the outage's start.     *)
NoEffectDuringOutage ==
    \A e \in effects : ~e.up =>
        /\ e.auth # NoAuthority
        /\ e.auth.from <= e.downSince
        /\ e.at <= e.downSince + StalenessBound

(* S8. A request that ended in deny or the declared safe state has no      *)
(* effect.                                                                 *)
SafeStateHasNoEffect ==
    \A r \in closed :
        ~\E e \in effects : \/ (e.auth = NoAuthority /\ e.scope = ScopeOf(r) /\ e.ep = r.aud)
                           \/ (e.auth # NoAuthority /\ e.auth.req = r)

Safety ==
    /\ TypeOK /\ EffectHasMatchingAdmit /\ EffectWithinAuthority /\ SingleUse
    /\ NoEffectBeyondHaltBound /\ RevocationBound /\ EffectHasEvidence
    /\ OneWayRule /\ AdmitOnlyAllowed /\ NoEffectDuringOutage /\ SafeStateHasNoEffect

-----------------------------------------------------------------------------
(* Liveness under fairness.                                                *)

HeldReqs == {h.req : h \in held}
FinalDecided(r) == \E d \in decisions : d.req = r /\ d.outcome \in {"admit", "deny"}

(* A held or challenged action is eventually decided or ends in the safe   *)
(* state.                                                                  *)
HoldResolves == \A r \in Requests : (r \in HeldReqs) ~> (FinalDecided(r) \/ r \in closed)

(* Every submitted request is eventually decided or ends in the safe state. *)
RequestResolves ==
    \A r \in Requests : (r \in submitted) ~> (FinalDecided(r) \/ r \in closed)

(* A halt request takes effect at every enforcement point.                 *)
HaltTakesEffect == (haltAt # NoTime) ~> (\A ep \in EPs : halted[ep])

=============================================================================
