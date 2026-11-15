--------------------------------- MODULE MC ---------------------------------
(***************************************************************************)
(* Model values and definitions shared by the TLC configurations in        *)
(* configs/. Only the action that names target t1 with parameters p1 is     *)
(* supported by MCAllowed. Continuation binding checks can use MCAllowedAll *)
(* so that a changed action is not refused by policy before its binding is  *)
(* tested.                                                                 *)
(***************************************************************************)
EXTENDS ECLCore, TLC

CONSTANTS e1, e2, r1, r2, r3, t1, t2, p1, p2

MCAllowed == {[target |-> t1, params |-> p1]}
MCAllowedAll == Actions

(* Enforcement points and request identifiers are interchangeable: nothing  *)
(* in the specification or in MCAllowed names one of them.                 *)
MCSymmetry == Permutations(EPs) \cup Permutations(ReqIds)

(***************************************************************************)
(* Reachability witnesses. The correct design must violate each negated    *)
(* reachability condition in its own configuration. State invariants and   *)
(* action properties are used as appropriate. These witnesses establish    *)
(* their specific situations, not nonvacuity of every property in every    *)
(* configuration.                                                           *)
(***************************************************************************)

(* An effect occurs.                                                       *)
WitnessNoEffect == effects = {}

(* A fresh request continues an authenticated human-approval challenge. *)
WitnessNoAdmitAfterChallenge ==
    ~\E c \in continuations : Admitted(c.req)

(* A reused identifier is refused without creating a second response. *)
WitnessNoCollisionRefusal == rejected = {}

WitnessNoApprovalReplayRefusal ==
    ~\E c1,c2 \in continuations :
       /\ c1.req # c2.req /\ c1.challenge = c2.challenge /\ c1.approval = c2.approval
       /\ Admitted(c1.req) /\ ContinuationBound(c2)
       /\ \E d \in decisions : /\ d.req = c2.req /\ d.outcome = "deny"
                               /\ d.at < c2.approval.until /\ d.epoch = c2.approval.epoch

WitnessNoLaterContinuationDecision ==
    ~\E c \in continuations : \E d \in decisions :
        /\ d.req = c.req /\ d.outcome = "admit" /\ d.at > c.challenge.at

(* An effect occurs during an outage of the decision service: on an admit  *)
(* issued before it began, inside the staleness bound (ECL1N-0102).        *)
WitnessNoEffectDuringOutage == \A e \in effects : e.up

(* An effect uses an authority after the control plane revoked it or       *)
(* changed the trust epoch, before the enforcement point learned of it:     *)
(* the propagation window that ECL1N-0097 permits. An action property.     *)
WitnessNoEffectInRevocationWindow ==
    [][\A e \in effects' \ effects :
          \/ e.auth = NoAuthority
          \/ /\ e.auth \notin {rv.auth : rv \in revocations}
             /\ e.auth.epoch >= trustEpoch]_vars

(* An effect occurs after a halt request and before the enforcement point   *)
(* acknowledged it: the window of the bound B that TS1-036 permits. An      *)
(* action property.                                                        *)
WitnessNoEffectInHaltWindow == [][\A e \in effects' \ effects : haltAt = NoTime]_vars

(* A request ends in the declared safe state with no decision at all.      *)
WitnessNoTimeout == \A r \in closed : \E d \in decisions : d.req = r
(* An effect after a completed outage/reconciliation cycle is reachable.  *)
WitnessNoEffectAfterRecovery ==
    [][\A e \in effects' \ effects :
        ~(outages > 0 /\ operationMode = "normal" /\ RecoveryReady)]_vars

(* A short outage need not create a staleness restriction. *)
WitnessNoEffectAfterShortOutage ==
    [][\A e \in effects' \ effects :
       ~(dsUp /\ outages > 0 /\ operationMode = "normal"
         /\ restriction[e.ep].generation = 0 /\ e.auth # NoAuthority
         /\ e.auth.from < upSince)]_vars

(* Fresh proof and a recorded lift can revalidate still-valid old authority. *)
WitnessNoRevalidatedAuthorityAfterRestriction ==
    [][\A e \in effects' \ effects :
       ~(restriction[e.ep].generation > 0 /\ ~restriction[e.ep].active
         /\ restriction[e.ep].proof = restriction[e.ep].generation
         /\ restriction[e.ep].lifted = restriction[e.ep].generation
         /\ e.auth # NoAuthority /\ e.auth.from < restriction[e.ep].faultAt)]_vars

(* The continuation liveness bounds admit a real bounded hold and timeout. *)
WitnessNoContinuationTimeout ==
    ~\E c \in continuations :
        /\ c.req \in closed /\ c.req \notin HeldReqs
        /\ \E d \in decisions : d.req = c.req /\ d.outcome = "hold"

(* A second stale crossing can be recovered with a new proof; still-valid *)
(* authority from before both faults remains usable after a recorded lift. *)
WitnessNoRevalidatedAuthorityAfterRepeatedStaleness ==
    [][\A e \in effects' \ effects :
       ~(restriction[e.ep].generation >= 2 /\ ~restriction[e.ep].active
         /\ restriction[e.ep].proof = restriction[e.ep].generation
         /\ restriction[e.ep].lifted = restriction[e.ep].generation
         /\ e.auth # NoAuthority /\ e.auth.from < restriction[e.ep].faultAt)]_vars

=============================================================================
