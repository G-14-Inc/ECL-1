# Lifecycle policy declaration migration

The public-review candidate keeps the `lifecycle-policy/1` schema identity and
adds the representation required to declare all ten policy areas in EL1-002.
An earlier schema accepted a record with five areas absent and prohibited
adding fields for them. Existing records require an explicit migration.

Add a `policy_requirements` object containing `supersession`, `revocation`,
`residency`, `encryption`, and `access`. Each value is a nonblank string that
identifies the applicable evidence classes and the requirement or a precise
policy reference. If an area does not apply, state the scope and reason. Keep
the existing structured retention, hold-precedence, export, redaction, and
destruction fields. Populate declarations from the governing policy; generic
text inserted merely to satisfy the schema does not establish policy adequacy.

`retention_rules[].duration` now checks the explicit lexical contract in
EL1-007. Use ordered `Y`, `M`, `D`, and optional `T` time components `H`, `M`,
`S`. At least one component is required, and `T` requires a time component.
Only seconds may have a decimal fraction, with digits on both sides of the
point. Signs, weeks, whitespace, and other text are refused. Examples include
`P1Y`, `P1M`, `P1DT6H`, and `PT0.25S`. The [XSD duration
reference](https://www.w3.org/TR/xmlschema11-2/#duration) defines the component
ordering; this JSON representation uses an unsigned subset without whitespace
normalization.

`P0D` and `PT0S` remain valid syntax. Whether a period is permitted depends on
the evidence class, ECL1N-0050, and any applicable recorded legal determination
under ECL1N-0195 to ECL1N-0199. Years and months are calendar units, so a
consumer calculates them from the declared start event under the policy.

Schema failures retain `ecl.error.schema-invalid.v1`. Python, TypeScript, and
Go use the same schema and portable `lifecycle-policy-contract` cases through
the existing `document-validation` capability. These checks establish field
presence and lexical validity; policy review and operational evidence establish
the substance and enforcement of the declarations. The authored corpus policy
and its mutations are migrated by `scripts/generate_document_vectors.py`;
`scripts/generate_lifecycle_policy_vectors.py` reproduces the focused controls.
Historical released artifacts remain unchanged.
