"""ECL-1's offline verifier in Python: the `ecl-verify` command and the modules it runs.

The modules read, check and verify ECL-1 objects without any network request: strict JSON and
canonical digests (`canonical`), schemas (`schema`, `schema_patterns`, `resources`), the semantic
rules (`semantic`, `semantic_rc4`, `decision_basis_checks`, `extensions`), integrity envelopes
(`integrity`, `signature_metadata`), trust policies (`trust`), evidence bundles (`bundle`,
`bundle_verification`), offline packages (`offline`, `package_verification`), binding records
(`binding`, `bindings`) and the claim, deployment, safe-state and timing documents (`claims`,
`deployment`, `safe_state`, `timing`). `cli` is the command.
"""

__version__ = "1.0.0"
