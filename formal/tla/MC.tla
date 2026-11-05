--------------------------------- MODULE MC ---------------------------------
(***************************************************************************)
(* Model values and definitions shared by the TLC configurations in        *)
(* configs/. Only the action that names target t1 with parameters p1 is     *)
(* supported by the verifiable inputs, so every other action differs from   *)
(* it in its target, its parameters, or both.                               *)
(***************************************************************************)
EXTENDS ECLCore, TLC

CONSTANTS e1, e2, r1, r2, t1, t2, p1, p2

MCAllowed == {[target |-> t1, params |-> p1]}

(* Enforcement points and request identifiers are interchangeable: nothing  *)
(* in the specification or in MCAllowed names one of them.                 *)
MCSymmetry == Permutations(EPs) \cup Permutations(ReqIds)

(***************************************************************************)
(* Reachability witnesses. Each is an invariant that the correct design    *)
(* must violate: the violation shows that the situation the safety         *)
(* properties speak about is reachable, so they do not hold vacuously, and *)
(* it records a window that the normative text permits.                    *)
(***************************************************************************)

(* An effect occurs.                                                       *)
WitnessNoEffect == effects = {}

(* A held request is later admitted after an authenticated approval.       *)
WitnessNoAdmitAfterHold ==
    ~\E d1, d2 \in decisions : /\ d1.req = d2.req
                               /\ d1.outcome = "hold"
                               /\ d2.outcome = "admit"

(* A reused request identifier with other content is denied (DCMP2-005).   *)
WitnessNoCollisionDeny ==
    \A d \in decisions : d.outcome = "deny" => d.req.action \notin Allowed

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
=============================================================================
