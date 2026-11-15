--------------------------- MODULE RecoveryReview ---------------------------
EXTENDS MC
NoRecoveredEffectOnUnreconciledRevocation ==
    [][\A e \in effects' \ effects :
        ~( /\ dsUp /\ outages > 0 /\ view[e.ep].synced < upSince
           /\ e.auth # NoAuthority
           /\ e.auth \in {rv.auth : rv \in revocations} )]_vars
=============================================================================
