# ECL Deployment Profiles 1

Status: informative guide for ECL-1 Version 1.0, a published version. It states no
requirement of its own: every obligation it describes is allocated, with an ID, in
the core standard or a normative companion it cites.  
Schema: `https://externalcontrollayer.ai/ns/schema/deployment-profile/1`

This profile family describes the deployment requirements allocated in the core
standard (Sections 8.1 to 8.8). It does not introduce a seventh runtime responsibility and does
not weaken Decision, Authority, Enforcement, Provenance, Verification, or
Fleet.

## Invariant release architecture

Every deployment profile includes a local gate. Consequential action release
is evaluated in-process, on the same host, or on a declared local-network
appliance using signed local or bounded cached state. A hosted or self-managed
control plane distributes policy, manages fleet state, receives evidence, and
supports verification; it is not an undeclared remote dependency in the
release hot path.

This invariant makes a local gate and a remote control plane compatible
delivery surfaces rather than separate conformance systems. It also permits
the same receipt and verification semantics in connected, disconnected,
sovereign, and air-gapped deployments.

## Model matrix

| Model | Required delivery surface | Distinguishing controls |
|---|---|---|
| Centralized distributed enforcement | local gate and hosted control plane | low-latency signed policy distribution, central audit, rapid revocation |
| Federated multi-domain | local gate plus one or more control planes | trust-bundle exchange, narrowing delegation, cross-domain verification, complete authority context |
| Sovereign self-managed | local gate and self-managed control plane | local control of policy, keys, evidence, and residency boundary |
| Offline edge | local gate and offline verifier | bounded cache staleness, stricter stale transition, reconnect reconciliation |
| Air-gapped segmented | local gate and transfer station | update/export integrity, dual control, disconnected incident and revocation workflows |

The topology model describes trust and connectivity. Delivery-surface labels
describe packaging. A deployment may compose compatible surfaces, but each
assessed System of Interest has one declared primary topology and one complete
machine-readable profile.

## Timing and fallback

The profile carries the level-bound connected revocation, offline staleness,
and evidence-export timing case. A non-default timing case includes its
rationale, control assumptions, and residual risk. The fallback precedence is
fixed:

1. emergency halt;
2. restricted;
3. degraded;
4. ordinary.

Degraded operation is bounded to signed cached state and named actions.
Restricted operation permits only diagnosis, recovery, containment, or safe
shutdown. The machine profile binds these controls to evidence and drills.
A fallback state applies to a scope: a loss of required proof restricts the
action classes that the claim's dependency model ties to the lost proof, and a
critical integrity failure or an emergency activation applies to the whole
deployment (core standard, ECL1N-0191 to ECL1N-0193).

## Public claim boundary

A deployment profile is evidence for a conformance claim; it is not itself a
claim. A public claim additionally binds the System of Interest, action
register, Negative Boundary Annex, version set, assessment package,
independence class, limitations, and any external mapping packet.

Examples under `profiles/examples/deployment/` are non-claims used for schema
and interoperability testing. Their identifiers and digests are illustrative.
