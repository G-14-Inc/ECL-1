# ECL OpenTelemetry Evidence Export Profile 1

Requirement-IDs: compiled
Version: 1.0
Status: normative profile of ECL-1 Version 1.0, a published version

This profile copies ECL decisions and evidence into OpenTelemetry log records so
that observability tools and security information and event management (SIEM)
systems can ingest them. The export is a copy. The signed evidence bundle remains
the record that a claim relies on, and a third party still verifies the bundle,
not the copy. The exporter sits after the evidence path: it reads objects once
they are recorded, and its failure changes no decision and blocks no evidence.
Each record carries the identifiers of the request, response and action it
belongs to and, when the deployment holds an export key, a digest of the object
keyed with that key, so that a consumer can match the record to the bundle
without the telemetry letting its readers test guesses about what the object
holds.

The profile adds requirements to a claim that declares it. It removes none of
the core requirements or of the requirements of DCMP-2 and EBMP-2.

This profile has no release boundary in the sense of ECL1N-0185: the exporter
copies evidence after it is recorded and releases no action (OE1-002).

## Pinned sources

The machine-readable record of these pins is `conformance/binding-sources.json`.

| Source | Revision | File | SHA-256 |
| --- | --- | --- | --- |
| OpenTelemetry Specification 1.61.0, logs data model (stable) | `open-telemetry/opentelemetry-specification` tag `v1.61.0`, commit `32c0b2c1d9e11f68da0e6e7b63044e57878590de` | `specification/logs/data-model.md` | `3ee2c391a5d3262130582df89a3dc5a5640d837d010734ea79458fe3ece31173` |
| OpenTelemetry Specification 1.61.0, file exporter (development) | same commit | `specification/protocol/file-exporter.md` | `0e345162b279a4d849c95b27b9afb3a6c958aeed27fac9e04576948aed1cb257` |
| OTLP 1.11.1, JSON Protobuf encoding | `open-telemetry/opentelemetry-proto` tag `v1.11.1`, commit `b3f75588eb23c5fca62264edd05d382de49beb1a` | `docs/specification.md` | `18525fa29803740421409d87a07d56cbaa47c204405811618463c823cb770486` |
| OTLP 1.11.1, log record message | same commit | `opentelemetry/proto/logs/v1/logs.proto` | `0c9d0c45eea723d38ef28ee13135ff61c037387f41cacc476ccac3485d6c138a` |
| Semantic Conventions 1.44.0, naming | `open-telemetry/semantic-conventions` tag `v1.44.0`, commit `e10a930844c6951757a43b849d364f7d056ac32b` | `docs/general/naming.md` | `3a33354b1f56d6b55d44703c81793b5944200b8488b40c1d9b25beb46c48be34` |
| Semantic Conventions 1.44.0, events | same commit | `docs/general/events.md` | `6fdd91ce96792d6600fdcb79ec0002d9dafa9a79f7c608fe75e551c7f535789b` |

The `ecl.` attribute namespace is not a namespace of the pinned semantic
conventions. The naming guidance there recommends a prefix that the defining
organization controls; the profile keeps `ecl.`, the prefix of ECL-1's names.
A change of prefix would go through the change process of ECL-1.

## Copy, not record

**OE1-001** — Exported telemetry MUST be a copy of ECL evidence: the signed
evidence bundle remains the record for every claim, and a log record, span event
or other exported item MUST NOT be offered as the evidence that ECL1N-0047,
FR-107 or FR-108 requires.

**OE1-002** — Apart from the response of a detection declared under
ECL1N-0167, an export failure, such as an unreachable collector, a full buffer,
a serialization error or a crash of the exporter, MUST NOT change a decision,
delay or block the release of an admitted action, or change, delay or block the
recording of evidence: the exporter MUST read an object only after it is
recorded and MUST NOT be a dependency of the decision or enforcement path. A
deployment that reacts to the loss of its monitoring path MUST do so through
such a declared detection, whose response is recorded as its own control
action.

## Log records

**OE1-003** — Each exported DCMP-2 message or EBMP-2 event MUST become one
OpenTelemetry log record whose `EventName` is `ecl.dcmp.` followed by the
message type or `ecl.ebmp.` followed by the event type, whose `Timestamp` is the
object's `issued_at` or `observed_at`, whose `ObservedTimestamp` is the time at
which the exporter read the object and is not earlier than `Timestamp`, and
whose attributes, in which no key appears more than once, are those of the
attribute table below for that object, each equal to the value in the object it
copies and held in the OTLP `AnyValue` kind that the table gives for it.

**OE1-004** — Each log record MUST carry the identifiers of its workflow,
request, response and action where the object has them, and MUST NOT carry a
digest that can be computed without the export key of OE1-010, such as the
SHA-256 digest of the object it copies or the parameters digest that the object
carries, other than the policy digest of the attribute table, which identifies
the policy that decided as the policy's identifier and version do; a consumer
that holds the export key MUST treat a record whose keyed digest differs from
the one it computes over the bundle's object as not describing that object.

**OE1-005** — A log record MUST NOT carry action parameters, tool arguments or
results, constraints, credentials, tokens, signatures, key material, the free
text of reasons, the identifiers of people and records (`ecl.actor.id`,
`ecl.subject.id` and `ecl.action.target`), or other non-public data, in its
attributes or its `Body`, unless the export policy declares the attribute and
the data class it carries (EBMP2-034, EBMP2-035); an exporter MUST NOT emit a
log record attribute that is neither in the attribute table nor declared, an
attribute that the table exports only when declared without that declaration,
or a `Body` that the export policy does not declare.

**OE1-006** — When the decision and enforcement path is traced, an exporter MAY
also add the record's attributes to a span event named as its `EventName` on the
span of the governed operation, and MAY set the record's `TraceId` and `SpanId`
to that span; a span event MUST NOT replace the log record.

**OE1-007** — An exporter that writes to a file or to standard output MUST write
one OTLP `LogsData` object per line in JSON Lines form, encoded under the pinned
OTLP JSON Protobuf encoding: trace and span identifiers in hexadecimal, enum
values as integers, and 64-bit integers, including timestamps, as decimal
strings.

**OE1-008** — The `SeverityNumber` of a record MUST follow the severity table
below, and its `SeverityText` MUST be the short name that the table gives for
that number (`INFO`, `WARN` or `ERROR`); a consumer MUST NOT infer
authorization, release or the absence of an effect from a record's severity or
from the presence or absence of a record.

**OE1-009** — An exporter that retains export records MUST write each one as
`ecl_otel_export_record_v1`, valid against
`https://externalcontrollayer.ai/ns/schema/binding/otel-export/1`.

## Keyed digests

**OE1-010** — An exporter MUST NOT emit `ecl.object.digest`,
`ecl.action.parameters_digest` or `ecl.export.key_id` unless the deployment
holds an export key: a secret of at least 32 bytes from a cryptographically
secure random source, generated for that deployment's telemetry export alone,
held only by the exporter and by the consumers that match records to the bundle,
never readable by the governed AI system, and never a key that signs or verifies
ECL evidence. With an export key, every record MUST carry the key's identifier,
a string, as the `stringValue` of `ecl.export.key_id`, which MUST NOT be derived
from the key; in `ecl.object.digest`, the HMAC-SHA-256 (RFC 2104) under the key
of the restricted canonical JSON of the object (IE1-001); and, where the object
has a parameters digest, in `ecl.action.parameters_digest`, the HMAC-SHA-256
under the key of the restricted canonical JSON of that digest; each HMAC as the
`stringValue` of its 64 lowercase hexadecimal digits. A consumer that does not
hold the key that a record names MUST still treat as not describing the object a
record whose keyed digests are not in that form, or that lacks a keyed digest
that the object has.

An unkeyed digest of an object, or the parameters digest that a request or an
execution event carries, lets a reader of the telemetry who can list the
possible values, such as an amount or a short list of accounts, compute the
digest of each candidate and confirm which one was used. A digest keyed with a
secret that the telemetry's readers do not hold still lets a consumer that holds
the key match a record to the bundle, and it gives everyone else nothing to
compare a guess with. The digests inside the signed evidence bundle are not
keyed and do not change. Replacing the export key changes its identifier, so a
consumer knows which key a record needs. An exporter without an export key
exports no digest, and a consumer then matches records to the bundle by their
identifiers.

## Attribute table

Every attribute value is a string held as an OTLP `stringValue`, except
`ecl.workflow.attempt` and `ecl.workflow.sequence`, which are integers held as
an `intValue` (OE1-003, OE1-007); an attribute held in another `AnyValue` kind,
such as a `bytesValue` that holds the same text, does not hold the value that
the table gives. String values copy the object's value. Each attribute key
appears once in a record (OE1-003), as the pinned `logs.proto` requires of a log
record's attributes. A keyed digest is a `stringValue` of 64 lowercase
hexadecimal digits (OE1-010), a form that a consumer without the export key can
check, though it cannot compare the digest with the object. Attributes whose
source member is absent are left out, and a row applies only to the objects it
names, also when another object holds the same member. Execution events are the
EBMP-2 events of kind `execution` (`release_prepared`, `execution_released`,
`execution_observed` and `execution_terminal`), decision events those of kind
`decision` (`decision_recorded`), authority events those of kind `authority`
(`authority_issued` and `authority_consumed`), request events those of kind
`request` (`request_received`), and terminal events those of type
`execution_terminal`. The rows marked "when declared" carry the identifiers of
people and records: an exporter emits each of them only when the export policy
declares it with the data class it carries (OE1-005), and then for every object
that the row names and that holds the source member.

| Attribute | Objects | Source |
| --- | --- | --- |
| `ecl.export.profile` | all | The constant `OTEL-EVIDENCE-EXPORT-1/1.0` |
| `ecl.protocol` | all | `protocol` |
| `ecl.object.id` | all | `message_id` or `object_id` |
| `ecl.object.type` | all | `message_type` or `event_type` |
| `ecl.object.digest` | all, with an export key | HMAC-SHA-256 under the export key of the restricted canonical JSON of the object, hexadecimal (OE1-010) |
| `ecl.export.key_id` | all, with an export key | The identifier of the export key (OE1-010) |
| `ecl.workflow.id` | all | `workflow.workflow_id` |
| `ecl.workflow.root_trace_id` | all | `workflow.root_trace_id` |
| `ecl.workflow.attempt` | all | `workflow.attempt` (integer) |
| `ecl.workflow.sequence` | all | `workflow.sequence` (integer) |
| `ecl.issuer.id` | DCMP-2 | `issuer.id` |
| `ecl.producer.id` | EBMP-2 | `producer.id` |
| `ecl.evidence.bundle` | all, when known | The identifier of the bundle that holds the object |
| `ecl.action.id` | decision request; execution events | `action.action_id` or `event.action_id` |
| `ecl.action.class` | decision request | `action.action_class` |
| `ecl.action.operation` | decision request; execution events | `action.operation` or `event.operation` |
| `ecl.action.target` | decision request; execution events; when declared | `action.target.uri` or `event.target.uri` |
| `ecl.action.parameters_digest` | decision request; execution events; with an export key | HMAC-SHA-256 under the export key of the restricted canonical JSON of `action.parameters_digest` or `event.parameters_digest`, hexadecimal (OE1-010) |
| `ecl.actor.id` | decision request; when declared | `actor.id` |
| `ecl.subject.id` | decision request; when declared | `subject.id` |
| `ecl.request.id` | decision response; challenge; challenge response; request events | `request_id` or `event.request.uri` |
| `ecl.decision.id` | decision response | `decision_id` |
| `ecl.decision.outcome` | decision response | `outcome` |
| `ecl.decision.reason_code` | decision response | the `code` of the first reason |
| `ecl.decision.safe_state` | decision response | `safe_state` |
| `ecl.policy.id` | decision response | `policy.id` |
| `ecl.policy.version` | decision response | `policy.version` |
| `ecl.policy.digest` | decision response | the value of `policy.digest` |
| `ecl.authorization.id` | admit response; authority events | `authorization.authorization_id` or `authorization_id` |
| `ecl.event.kind` | EBMP-2 | `event.kind` |
| `ecl.event.state` | EBMP-2 | `event.state` |
| `ecl.event.decision_id` | decision events; execution events | `event.decision.uri` |
| `ecl.event.reason_code` | terminal events | the `code` of `ecl.ext.outcome-reason.v1` |

## Severity table

| Object | `SeverityNumber` |
| --- | --- |
| Decision response with outcome `admit` | 9 (INFO) |
| Decision response with outcome `deny`, `hold` or `challenge` | 13 (WARN) |
| `execution_terminal` in `succeeded` | 9 (INFO) |
| `execution_terminal` in `denied`, `held`, `challenged`, `expired_before_release`, `rolled_back` or `compensated` | 13 (WARN) |
| `execution_terminal` in `failed`, `partially_succeeded`, `timed_out`, `cancelled` or `unknown` | 17 (ERROR) |
| Control message `halt` or `quarantine` | 17 (ERROR) |
| Any other message or event | 9 (INFO) |

## Mapping to OCSF (informative)

A consumer that normalizes to the Open Cybersecurity Schema Framework (OCSF,
schema 1.9.0, tag `1.9.0`, commit `856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba`)
can map a decision response record to the API Activity class (`class_uid`
6003): `time` from `Timestamp`, `action_id` 1 (Allowed) for `admit` and 2
(Denied) for `deny`, `action_id` 99 (Other) with the outcome in `action` for
`hold` and `challenge`, `disposition_id` 1 (Allowed), 2 (Blocked) or 14
(Delayed), and the `ecl.` attributes in `unmapped`. An `execution_terminal`
record maps to the same class with its state in `status_detail`. OCSF records
made this way are copies of copies: for a consumer that holds the export key,
the keyed digest in `ecl.object.digest` is what connects them to the signed
bundle, and otherwise only their identifiers do.

## Export record (informative)

An `ecl_otel_export_record_v1` record holds one export: the `object` the
exporter read; the OTLP `log_record` it made; the `bundle_id` of the bundle that
holds the object, which a log record that carries `ecl.evidence.bundle` copies;
the `declared_attributes` of the export policy, each with the data class it
carries, where the name `body` declares a log record body; the `export` outcome
(`exported` or `failed`) and when it was attempted; and `evidence_after`, the
same object as the evidence held it after the attempt. The rules registered
for this profile, whose names begin `ecl.rule.otel-`, check a record after its
schema; a checker compares a keyed digest only under an export key that its
caller supplies, and recognizes a digest that needs no key without one.

## Security considerations

Telemetry pipelines are wider and less protected than the evidence store, and
their contents reach people and systems outside the claim's trust boundary. The
profile therefore exports identifiers, outcomes and, with an export key, keyed
digests, and leaves parameters, results, reason text and every digest that needs
no key in the bundle, apart from the policy digest, which identifies the policy
as its identifier and version do. A digest of low-entropy content lets a reader
confirm guessed values; this profile exports such digests only under an export
key (OE1-010), and exports the identifiers of people and records only when the
export policy declares them. A record can be forged, dropped or delayed anywhere
along the pipeline, so its only authority is the keyed digest that a consumer
that holds the export key compares with the signed bundle. A reader who obtains
the export key can test guesses as an unkeyed digest would let them, which is
why the key stays with the exporter and those consumers. The `object_id` of an
EBMP-2 event is derived from the event's content (EBMP2-047) and is exported as
its identifier; confirming a guess through it needs every member of the event,
including the digests of the objects it references, which no record carries.
Making release wait for an export would let anyone who can disrupt the pipeline
stop or slow governed actions, and a deny that depended on export would turn
monitoring into a control path that the claim does not declare; both are
excluded by OE1-002.

## Conformance

| Kind | What the citation establishes |
| --- | --- |
| Vectors | The `otel-export` suite refuses a record that misstates the outcome or the keyed digest of the object it copies, or exports its attempt 1 as the boolean `true` or its outcome as a `bytesValue`, a record that repeats an attribute key, a record that carries a digest that needs no key, also under a key the suite does not hold as a `bytesValue` of its text or of its bytes, or that names the export key without the keyed digest of the object or of a request's parameters, or by an identifier that is not a string, a record of a response that carries a parameters digest, a record of a control message that carries a decision's safe state, a record of a request event without the identifier of its request, a record that carries the action's parameters in an undeclared attribute or an undeclared body, a record that carries the identifier of a person or record that the export policy does not declare, a deny exported with the severity of an admit, a severity text other than the table's name, an observed time earlier than the object's time or beyond the range of a `fixed64`, an export read before the object's time, an export failure after which the evidence differs, and a severity encoded as an enum name; it accepts a record that carries the declared identifiers, and the records of a challenge, a `halt` control message and a request event |
| Assessor procedure | Pipeline placement after the evidence path, the export policy's declared data classes, and the generation and custody of the export key |

The digests of the suite's vectors are keyed with a published test export key
that the suite's manifest names, never an operational key.
