# Evidence verification API changes

Authors and producers: Robert F. Tilley Jr. and G-14, Inc.

The public-review candidate checks the decision and authority bindings of
`release_prepared` and `execution_observed` records as well as release and
terminal records. These records must pair with the request, name its response
when one exists, and bind any authority they carry. A prepared record remains
evidence of preparation; it does not establish that dispatch occurred.
Operation, parameter and target comparisons retain the scope of EBMP2-047:
release and terminal records. Existing release-window and terminal-state checks
retain their scope.

A discharge now checks every applicable `before_release` obligation sharing its
identifier and type, including a deferred witness requirement. An earlier
post-release occurrence cannot replace a required approver or witness. Identical
requirements can share the matching discharge; a carried proof must satisfy all
requirements that the discharge names. A carried verification proof belongs in
the bundle's `observations` collection under EBMP2-070.

Approval-purpose and signer-principal checks use the historically verified
signing keys. Extra signatures that fail verification remain visible as trust
dependencies. They do not become authenticated approvers, witnesses or actors,
and they do not invalidate an envelope whose signature threshold still holds
(TP1-006). An invalid approval remains invalid; secondary findings can change
when they previously depended on unauthenticated signer metadata.

The causal analyzer returns `indeterminate` when a declared resource limit
prevents analysis. It does not report records beyond a truncated input as
missing predecessors. Conflicting records with the same identifier are all
excluded from the unique-record graph; the collision is reported and its
status is `indeterminate`. Genuinely missing predecessor identifiers remain
listed. An execution attempt with a contradictory state transition is not
classified as a valid open or terminal attempt. These are changes to invalid
input diagnostics; valid closed graphs still report `complete`, and genuine
open attempts or missing predecessors still report `incomplete`.

Python callers of `verify_bundle` must pass an actual boolean for
`accept_current_trust_failure`. TypeScript callers must omit
`acceptCurrentTrustFailure` or pass an actual boolean. Values such as the string
`"false"`, integers and `null` are rejected as malformed caller options. Go's
option already has a boolean type. The Python extension descriptor helper
accepts the registry's `additive-critical` compatibility class and requires a
positive integer version; booleans and fractional values are rejected.

Extension consumers interpret only an active identifier and version on an
object type named by the registry. Unknown noncritical versions are retained
without interpretation. They cannot satisfy a required decision basis,
discharge, receipt or binding, and their values do not impose current-version
constraints or become projected telemetry attributes.

Python callers of `process_extensions` now supply the required keyword
`object_type`, such as `"DCMP-2"` for a decision message. Occurrence versions
must be positive integers, and `critical` must be a boolean. The helper uses
the descriptor's declared object types as well as its identifier, version and
status. The ordinary verifiers use the registry shipped with their build.
