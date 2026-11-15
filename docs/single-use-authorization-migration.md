# Single-use authorization migration

Authors and producers: Robert F. Tilley Jr. and G-14, Inc.

This public-review draft supports one release per DCMP-2 authorization. It
restricts a previously advertised capability: `bounded_multi_use` is now a
reserved, unsupported value. Earlier published artifacts remain historical
records; this draft is a changed specification and implementation, not a
byte-for-byte reproduction of those artifacts.

## Supported inputs

Both `decision_request.authority_request.use_policy` and an admitting
`decision_response.authorization.use_policy` are `single_use`. In either
object, `max_uses` is absent or the integer 1. Boolean, fractional, null and
string values are not substitutes for the integer. The existing matching rule
is retained: if a request explicitly carries `max_uses: 1`, its admit also
carries `max_uses: 1`. A request without that member permits an admit either
with it or without it.

Schema validation refuses unsupported values. Decoded-object response-binding
APIs also refuse them, including an unsupported request paired with a
non-admitting response, with `ecl.error.request-binding-invalid.v1`.
Execution-event and authority-event binding APIs use their existing
`ecl.error.decision-binding-invalid.v1` diagnostic. An evidence verifier never
interprets an unsupported policy as an unlimited consumption count.

OAuth issuance requires a supported request and admit. Presentation checking
refuses an unsupported token entry with `ecl.error.binding-unsupported.v1`
after signature, audience and time checks and before possession and replay
checks. Each authorization permits one accepted presentation across all
instances. DPoP replay protection remains a separate obligation: its cache
can refuse a previously accepted proof even when the current authorization
has not been used. MCP refuses an unsupported decision before committing a
use or forwarding a request. Its consumption, preparation, proof, release and
recovery order is unchanged.

## Producer migration

Do not edit or relabel an existing `bounded_multi_use` request, admit, token or
signed bundle to make it appear single-use. Its semantics and integrity
bindings would change. Retain it under the specification and verification
context that originally described it.

For a new intended action, obtain a new request and admit with a distinct
single-use authorization. Evaluate its applicable policy, consequences,
budgets, proof freshness and release conditions. Repeating an uncertain
operation is not automatically a new intended action: reconcile its recorded
outcome and retain the action-key/idempotency rules that prevent duplicate
effects. Recovery does not restore consumed authority.

TRANSACTIONAL-EFFECT-1 may account a policy or higher-level grant quota across
several action keys. Each action still has its own DCMP-2 single-use
authorization. A quota charge that remains counted after a denial is separate
from EBMP-2 release-authority consumption and creates no release evidence by
itself.

The restriction addresses an incomplete multi-use representation: the earlier
contract could count uses but did not consistently bind a separate release,
consumable proof, budget debit and terminal outcome to each use. Supporting
multi-use again requires a complete interoperable contract for those objects
and their recovery behavior. The reserved identifier provides no such
contract.

Private gateways, resource servers and other external producers need their
own migration and deployment tests. Changes to the published verifier
interfaces do not establish that those systems have been updated.
