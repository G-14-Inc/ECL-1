"""Semantic checks that JSON Schema cannot express reliably."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .canonical import CanonicalizationError, object_digest, same_json
from .decision_basis_checks import (
    REGISTER_DOCUMENT_RULE,
    REGISTER_SCHEMA_VERSION,
    one_way_problems,
    register_document_problems,
)
from .schema import rfc3339_utc_nanoseconds


@dataclass(frozen=True)
class Finding:
    rule_id: str
    path: str
    message: str


def _time(value: str) -> int:
    return rfc3339_utc_nanoseconds(value)


# EBMP2-046: the event kind each core event type carries and, where the type fixes it, the
# states its event may be in. A terminal execution state is checked by the terminal-state rule.
EVENT_KINDS: dict[str, tuple[str, frozenset[str] | None]] = {
    "request_received": ("request", None),
    "decision_recorded": ("decision", None),
    "authority_issued": ("authority", frozenset({"issued", "active"})),
    "authority_consumed": (
        "authority",
        frozenset({"consumed", "revoked", "expired", "superseded"}),
    ),
    "release_prepared": ("execution", frozenset({"prepared"})),
    "execution_released": ("execution", frozenset({"released"})),
    "execution_observed": ("execution", frozenset({"running"})),
    "execution_terminal": ("execution", None),
    "human_intervention": ("intervention", None),
    "verification": ("verification", None),
    "safe_state_transition": ("state", None),
    "fleet_transition": ("state", None),
    "lifecycle_transition": ("lifecycle", None),
}
# EBMP2-013: terminal states that declare their known side effects and residual uncertainty.
UNCERTAIN_STATES = frozenset({"partially_succeeded", "timed_out", "cancelled", "unknown"})
# DCMP2-025: the control operations that only the emergency control plane may carry.
EMERGENCY_OPERATIONS = frozenset({"halt", "quarantine"})
# DCMP2-013: the members of an admit's authorization that bind its release authority.
AUTHORITY_MEMBERS = (
    "authorization_id",
    "audience",
    "scope_digest",
    "valid_from",
    "valid_until",
    "use_policy",
)
# Registered extensions whose values carry rules (DCMP2-052, DCMP2-053, EBMP2-063, EBMP2-064).
COUPLING = "ecl.ext.consequence-coupling.v1"
DECISION_BASIS = "ecl.ext.decision-basis.v1"
APPROVAL_RECORD = "ecl.ext.approval-record.v1"
CONTROL_CHANGE = "ecl.ext.control-change.v1"
# DCMP2-053, ECL1N-0179 and ECL1N-0182: the one-way rule. An input that the governed AI system
# controls as an assertion, or a judgment about meaning or risk, only makes an outcome stricter,
# and an input that was not available supports nothing.
DECISION_BASIS_RULE = "ecl.rule.decision-basis-one-way.v1"
# XR1-010: one object carries each extension identifier at one version, unless the registry entry
# of that identifier declares its versions composable.
EXTENSION_VERSION_RULE = "ecl.rule.extension-single-version.v1"
# DCMP2-052: in an admit, each coupling result reports an outcome that permits release. A witness
# check may be deferred to enforcement, which then proves it before release (DCMP2-017).
PERMITTING_RESULTS = {
    "budget_result": frozenset({"authorized"}),
    "witness_result": frozenset({"satisfied", "required_before_release"}),
    "quorum_result": frozenset({"met"}),
}
# EBMP2-064: the control changes that switch a safeguard off and therefore must expire.
DISABLING_CHANGES = frozenset({"disable", "bypass", "auto_approve"})
# A validator for an extension value returns a message per failure, none when the value is valid.
ValueValidator = Callable[[Any], Iterable[str]]


def _extension_values(value: dict[str, Any], identifier: str) -> list[tuple[int, dict[str, Any]]]:
    """(index, value) of each well-formed occurrence of one extension; others are left to the
    schema and value checks."""
    extensions = value.get("extensions")
    if not isinstance(extensions, list):
        return []
    return [
        (index, extension["value"])
        for index, extension in enumerate(extensions)
        if isinstance(extension, dict)
        and extension.get("id") == identifier
        and isinstance(extension.get("value"), dict)
    ]


def allocated_extension_versions(
    entries: Iterable[Mapping[str, Any]],
) -> dict[str, frozenset[int]]:
    """The versions the extension registry allocates for each identifier (XR1-003).

    An extension is the pair of its identifier and version (XR1-009), so a consumer can interpret
    only the versions allocated for an identifier it knows.
    """
    versions: dict[str, set[int]] = {}
    for entry in entries:
        attributes = entry.get("attributes")
        version = attributes.get("version") if isinstance(attributes, Mapping) else None
        identifier = entry.get("id")
        if isinstance(identifier, str) and type(version) is int:
            versions.setdefault(identifier, set()).add(version)
    return {identifier: frozenset(found) for identifier, found in versions.items()}


def active_extension_versions(
    entries: Iterable[Mapping[str, Any]],
) -> dict[str, frozenset[int]]:
    """The versions of the active entries of the extension registry (XR1-006).

    An occurrence is known to a consumer only through an active entry of its identifier and
    version that the consumer implements; a consumer that implements every active entry knows
    exactly these versions. A deprecated, prohibited, superseded or reserved entry stays allocated
    for XR1-017 but makes no occurrence known.
    """
    return allocated_extension_versions(
        entry for entry in entries if entry.get("status") == "active"
    )


def composable_extensions(entries: Iterable[Mapping[str, Any]]) -> frozenset[str]:
    """The identifiers whose registry entry declares their versions composable (XR1-010).

    Only the attribute `composable_versions` set to `true` declares it; anything else, including
    an absent attribute, leaves two versions of the identifier in one object a conflict.
    """
    found: set[str] = set()
    for entry in entries:
        attributes = entry.get("attributes")
        identifier = entry.get("id")
        if (
            isinstance(identifier, str)
            and isinstance(attributes, Mapping)
            and attributes.get("composable_versions") is True
        ):
            found.add(identifier)
    return frozenset(found)


ADAPTER_RULE = "ecl.rule.adapter-source-binding-valid.v1"
ADAPTER_RESPONSIBILITIES = (
    "Decision",
    "Authority",
    "Enforcement",
    "Provenance",
    "Verification",
    "Fleet",
)
# EBMP2-069: the media type each derived-object protocol names, the prefix of a binding identity,
# and the one authority boundary the schema allows.
ADAPTER_MEDIA_TYPES = {
    "DCMP-2": "application/vnd.ecl.dcmp+json",
    "EBMP-2": "application/vnd.ecl.ebmp+json",
}
ADAPTER_BINDING_PREFIX = "https://externalcontrollayer.ai/ns/adapter-binding/sha256/"
ADAPTER_AUTHORITY_BOUNDARY = {
    "native_authoritative_for_effects": True,
    "ecl_is_portable_evidence_only": True,
    "inbound_requires_native_reevaluation": True,
    "conflict_disposition": "fail_closed_no_release",
}


def _object_entries(value: dict[str, Any], member: str) -> list[dict[str, Any]] | None:
    """The entries of an array member when every entry is an object; None otherwise."""
    entries = value.get(member)
    if isinstance(entries, list) and all(isinstance(entry, dict) for entry in entries):
        return entries
    return None


def _entry_strings(entries: list[dict[str, Any]] | None, member: str) -> list[str] | None:
    """One member of every entry, when each is a string; None otherwise."""
    if entries is None:
        return None
    values = [entry.get(member) for entry in entries]
    strings = [item for item in values if isinstance(item, str)]
    return strings if len(strings) == len(values) else None


def _entry_string_lists(
    entries: list[dict[str, Any]] | None, member: str
) -> list[list[str]] | None:
    """One member of every entry, when each is an array of strings; None otherwise."""
    if entries is None:
        return None
    values = [entry.get(member) for entry in entries]
    lists = [
        item
        for item in values
        if isinstance(item, list) and all(isinstance(text, str) for text in item)
    ]
    return lists if len(lists) == len(values) else None


def _names_derived_object(pointer: str, count: int) -> bool:
    """Whether a JSON Pointer's first reference token is an array index (RFC 6901, section 4)
    less than `count`."""
    if not pointer.startswith("/"):
        return False
    token = pointer.split("/")[1]
    if re.fullmatch("0|[1-9][0-9]*", token) is None:
        return False
    return len(token) <= len(str(count)) and int(token) < count


def adapter_binding_findings(value: dict[str, Any]) -> list[Finding]:
    """EBMP2-069: the conditions of a native adapter binding that the binding alone shows.

    On a schema-invalid binding each condition is checked only when every member it names is
    present with the JSON type that the schema requires (DCMP2-043). The digests of the source
    object and of each derived object need those objects, and ``verify_adapter_binding`` checks
    them when it is given them.
    """

    findings: list[Finding] = []

    def fail(path: str, message: str) -> None:
        findings.append(Finding(ADAPTER_RULE, path, message))

    objects = _object_entries(value, "ecl_objects")
    object_ids = _entry_strings(objects, "object_id")
    accounting = _object_entries(value, "field_accounting")

    # 1. The digest of the binding without binding_digest.
    supplied_digest = value.get("binding_digest")
    if isinstance(supplied_digest, dict):
        body = {key: item for key, item in value.items() if key != "binding_digest"}
        try:
            expected_digest = {
                "algorithm": "ecl.digest.sha-256.v1",
                "value": object_digest(body),
            }
        except CanonicalizationError as exc:
            fail(
                "/binding_digest",
                f"binding body is outside the restricted canonical profile: {exc}",
            )
        else:
            if supplied_digest != expected_digest:
                fail(
                    "/binding_digest",
                    "binding body digest does not match the canonical binding body",
                )

    # 2. The binding identity binds the source and the derived-object list.
    source = value.get("source")
    binding_id = value.get("binding_id")
    if isinstance(source, dict) and isinstance(binding_id, str) and object_ids is not None:
        source_digest = source.get("object_digest")
        seed_values = [source.get("system"), source.get("contract"), source.get("object_id")]
        if isinstance(source_digest, dict):
            seed_values.append(source_digest.get("value"))
        if len(seed_values) == 4 and all(isinstance(item, str) for item in seed_values):
            seed = {
                "system": seed_values[0],
                "contract": seed_values[1],
                "object_id": seed_values[2],
                "object_digest": seed_values[3],
                "ecl_object_ids": object_ids,
            }
            try:
                expected_id: str | None = ADAPTER_BINDING_PREFIX + object_digest(seed)
            except CanonicalizationError:
                expected_id = None
            if binding_id != expected_id:
                fail(
                    "/binding_id",
                    "binding identity does not bind the source and derived-object set",
                )

    # 3. Distinct derived objects.
    if object_ids is not None and len(object_ids) != len(set(object_ids)):
        fail("/ecl_objects", "derived ECL object identifiers are not unique")

    # 4. The media type that each derived object's protocol names.
    protocols = _entry_strings(objects, "protocol")
    media_types = _entry_strings(objects, "media_type")
    if protocols is not None and media_types is not None:
        for index, (protocol, media_type) in enumerate(zip(protocols, media_types)):
            if ADAPTER_MEDIA_TYPES.get(protocol) != media_type:
                fail(
                    f"/ecl_objects/{index}/media_type",
                    "derived-object protocol and media type disagree",
                )

    # 5. Each source field is accounted once.
    source_paths = _entry_strings(accounting, "source_path")
    if source_paths is not None and len(source_paths) != len(set(source_paths)):
        fail("/field_accounting", "a source field is accounted more than once")

    # 6. The loss class follows from the dispositions.
    dispositions = _entry_strings(accounting, "disposition")
    loss_class = value.get("loss_class")
    if dispositions is not None and isinstance(loss_class, str):
        expected_loss = (
            "rejected"
            if "rejected" in dispositions
            else "loss_accounted"
            if "retained_source_only" in dispositions
            else "lossless"
        )
        if loss_class != expected_loss:
            fail("/loss_class", "loss class does not match per-field accounting")

    # 7. Every target path begins with the index of a derived object.
    target_lists = _entry_string_lists(accounting, "target_paths")
    derived_targets = _entry_strings(_object_entries(value, "derived_fields"), "target_path")
    if objects is not None and target_lists is not None and derived_targets is not None:
        for index, targets in enumerate(target_lists):
            if not all(_names_derived_object(target, len(objects)) for target in targets):
                fail(
                    f"/field_accounting/{index}",
                    "target path does not name a bound derived-object index",
                )
        for index, target in enumerate(derived_targets):
            if not _names_derived_object(target, len(objects)):
                fail(
                    f"/derived_fields/{index}",
                    "target path does not name a bound derived-object index",
                )

    # 8. Each responsibility's coverage names exactly the derived objects that list it.
    listed = _entry_string_lists(objects, "responsibilities")
    coverage = value.get("responsibility_coverage")
    if (
        object_ids is not None
        and listed is not None
        and isinstance(coverage, dict)
        and all(
            isinstance(coverage.get(responsibility), dict)
            and isinstance(coverage[responsibility].get("status"), str)
            and isinstance(coverage[responsibility].get("object_ids"), list)
            and all(isinstance(item, str) for item in coverage[responsibility]["object_ids"])
            for responsibility in ADAPTER_RESPONSIBILITIES
        )
    ):
        for responsibility in ADAPTER_RESPONSIBILITIES:
            disposition = coverage[responsibility]
            expected_ids = [
                identifier
                for identifier, responsibilities in zip(object_ids, listed)
                if responsibility in responsibilities
            ]
            if (disposition["status"] == "represented") != bool(expected_ids) or disposition[
                "object_ids"
            ] != expected_ids:
                fail(
                    f"/responsibility_coverage/{responsibility}",
                    "responsibility coverage disagrees with derived-object metadata",
                )

    # 9. The fail-closed authority boundary, the one value the schema allows, compared as the same
    # JSON value: 1 is not `true`.
    boundary = value.get("authority_boundary")
    if isinstance(boundary, dict) and not same_json(boundary, ADAPTER_AUTHORITY_BOUNDARY):
        fail(
            "/authority_boundary",
            "adapter authority boundary is not the exact fail-closed boundary",
        )

    return sorted(
        findings,
        key=lambda item: (item.rule_id, item.path, item.message),
    )


class SemanticValidator:
    """Validate ECL cross-field semantics using an explicit registry snapshot."""

    def __init__(
        self,
        known_extensions: Iterable[str],
        value_validators: Mapping[str, ValueValidator] | None = None,
        *,
        allocated_versions: Mapping[str, Iterable[int]] | None = None,
        composable: Iterable[str] = (),
        active_versions: Mapping[str, Iterable[int]] | None = None,
    ) -> None:
        # XR1-017: the allocated identifiers, whatever their status.
        self.known_extensions = frozenset(known_extensions)
        self.value_validators = dict(value_validators or {})
        # XR1-010: the identifiers whose versions the registry declares composable.
        self.composable = frozenset(composable)
        # None: every version of a known identifier is interpretable, as before RC-5.
        self.allocated_versions = (
            None
            if allocated_versions is None
            else {
                identifier: frozenset(versions)
                for identifier, versions in allocated_versions.items()
            }
        )
        # XR1-006: the versions of the active entries the consumer implements. None: a known
        # identifier at an allocated version is interpretable, as before.
        self.active_versions = (
            None
            if active_versions is None
            else {
                identifier: frozenset(versions)
                for identifier, versions in active_versions.items()
            }
        )

    def _interpretable(self, identifier: str, version: Any) -> bool:
        """Whether the consumer can interpret this occurrence (XR1-006): an active entry of its
        identifier and version that the consumer implements, or, without that snapshot, a known
        identifier at a version the registry allocated for it (XR1-003, XR1-009)."""
        if self.active_versions is not None:
            return type(version) is int and version in self.active_versions.get(
                identifier, frozenset()
            )
        if identifier not in self.known_extensions:
            return False
        if self.allocated_versions is None or identifier not in self.allocated_versions:
            return True
        return type(version) is int and version in self.allocated_versions[identifier]

    def _extension_value_schemas(self, value: dict[str, Any]) -> list[Finding]:
        """XR1-023: a registered extension's value validates against its registered schema."""
        findings: list[Finding] = []
        extensions = value.get("extensions")
        if not isinstance(extensions, list):
            return findings
        for index, extension in enumerate(extensions):
            if not isinstance(extension, dict):
                continue
            validate = self.value_validators.get(str(extension.get("id")))
            if validate is None or "value" not in extension:
                continue
            errors = sorted(validate(extension["value"]))
            if errors:
                findings.append(
                    Finding(
                        "ecl.rule.extension-value-valid.v1",
                        f"/extensions/{index}/value",
                        f"value of {extension.get('id')} does not match its registered schema: "
                        + errors[0][:160],
                    )
                )
        return findings

    @staticmethod
    def _coupling_results(value: dict[str, Any]) -> list[Finding]:
        """DCMP2-052: an admit carries only permitting consequence-coupling results."""
        if value.get("message_type") != "decision_response" or value.get("outcome") != "admit":
            return []
        findings: list[Finding] = []
        obligations = value.get("obligations")
        deferred = isinstance(obligations, list) and any(
            isinstance(item, dict) and item.get("satisfaction") == "before_release"
            for item in obligations
        )
        for index, coupling in _extension_values(value, COUPLING):
            for member, permitting in PERMITTING_RESULTS.items():
                result = coupling.get(member)
                if not isinstance(result, dict):
                    continue
                outcome = result.get("outcome")
                if outcome not in permitting:
                    findings.append(
                        Finding(
                            "ecl.rule.coupling-results-permit-admit.v1",
                            f"/extensions/{index}/value/{member}/outcome",
                            f"an admit cannot carry {member} outcome {outcome!r}",
                        )
                    )
                elif outcome == "required_before_release" and not deferred:
                    findings.append(
                        Finding(
                            "ecl.rule.coupling-results-permit-admit.v1",
                            f"/extensions/{index}/value/{member}/outcome",
                            "a deferred witness check needs a before_release obligation",
                        )
                    )
            if "blocker_reason" in coupling:
                findings.append(
                    Finding(
                        "ecl.rule.coupling-results-permit-admit.v1",
                        f"/extensions/{index}/value/blocker_reason",
                        "an admit cannot carry a blocker reason",
                    )
                )
        return findings

    @staticmethod
    def _decision_basis(value: dict[str, Any]) -> list[Finding]:
        """DCMP2-053: each input once; no actor_supplied or judgment input, and no input that was
        not available or was computed from one that was not, supports an outcome; no input
        computed from one that is not verifiable is verifiable, and none is computed from itself;
        an admit rests on at least one verifiable input that supports it and on no required input
        that was not available; the outcome is no less strict than a recorded verifiable-only
        outcome; and no input obtained after the decision is recorded as available
        (`ecl_verify.decision_basis_checks`)."""
        if value.get("message_type") != "decision_response":
            return []
        outcome = value.get("outcome")
        return [
            Finding(DECISION_BASIS_RULE, f"/extensions/{index}/value{path}", message)
            for index, basis in _extension_values(value, DECISION_BASIS)
            for path, message in one_way_problems(
                basis,
                admit=outcome == "admit",
                outcome=outcome,
                evaluated_at=value.get("evaluated_at"),
            )
        ]

    @staticmethod
    def _register_declarations(value: dict[str, Any]) -> list[Finding]:
        """ECL1N-0178: a Consequential Action Register declares each action class once and each
        input of a class once, names in `derived_from` only other inputs of the class, declares no
        input computed from one that is not verifiable as verifiable, and computes no input from
        itself (`ecl_verify.decision_basis_checks.register_document_problems`)."""
        return [
            Finding(REGISTER_DOCUMENT_RULE, path, message)
            for path, message in register_document_problems(value)
        ]

    @staticmethod
    def _approval_records(value: dict[str, Any]) -> list[Finding]:
        """EBMP2-063: an approval or rejection respects its recorded minimum review time."""
        event = value.get("event")
        if (
            value.get("event_type") != "human_intervention"
            or not isinstance(event, dict)
            or event.get("operation") not in {"approve", "reject"}
            or not isinstance(event.get("issued_at"), str)
        ):
            return []
        findings: list[Finding] = []
        for index, record in _extension_values(value, APPROVAL_RECORD):
            presented = record.get("presented_at")
            minimum = record.get("minimum_review_seconds")
            if not isinstance(presented, str) or type(minimum) is not int:
                continue
            if _time(event["issued_at"]) < _time(presented) + minimum * 1_000_000_000:
                findings.append(
                    Finding(
                        "ecl.rule.approval-review-time-respected.v1",
                        f"/extensions/{index}/value/presented_at",
                        "the decision came sooner than the minimum review time after presentation",
                    )
                )
        return findings

    @staticmethod
    def _control_changes(value: dict[str, Any]) -> list[Finding]:
        """EBMP2-064: a control change has approvers other than its requester and, when it switches
        a control off, an expiry after it takes effect."""
        findings: list[Finding] = []
        for index, change in _extension_values(value, CONTROL_CHANGE):
            approvers = change.get("approved_by")
            if isinstance(approvers, list) and change.get("requested_by") in approvers:
                findings.append(
                    Finding(
                        "ecl.rule.control-change-approved-and-bounded.v1",
                        f"/extensions/{index}/value/approved_by",
                        "the requester of a control change cannot approve it",
                    )
                )
            effective, expires = change.get("effective_at"), change.get("expires_at")
            if change.get("change") in DISABLING_CHANGES and isinstance(effective, str):
                if not isinstance(expires, str) or _time(expires) <= _time(effective):
                    findings.append(
                        Finding(
                            "ecl.rule.control-change-approved-and-bounded.v1",
                            f"/extensions/{index}/value/expires_at",
                            f"a {change.get('change')} change must expire after it takes effect",
                        )
                    )
        return findings

    @staticmethod
    def _extensions(value: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()
        extensions = value.get("extensions")
        if extensions is None:
            return findings
        if not isinstance(extensions, list):
            raise TypeError("extensions must be an array")
        for index, extension in enumerate(extensions):
            if not isinstance(extension, dict):
                raise TypeError("extension entries must be objects")
            identifier = extension.get("id")
            version = extension.get("version")
            if not isinstance(identifier, str) or not isinstance(version, int):
                raise TypeError("extension id and version have invalid types")
            key = (identifier, version)
            if key in seen:
                findings.append(
                    Finding(
                        "ecl.rule.extension-identifiers-unique.v1",
                        f"/extensions/{index}",
                        f"duplicate extension allocation {key[0]} version {key[1]}",
                    )
                )
            seen.add(key)
        return findings

    def _extension_versions(self, value: dict[str, Any]) -> list[Finding]:
        """XR1-010: an object carries each extension identifier at one version only, unless the
        registry declares the identifier's versions composable. A version the consumer does not
        know is a version all the same, so it conflicts with a known one."""
        extensions = value.get("extensions")
        if extensions is None:
            return []
        if not isinstance(extensions, list):
            raise TypeError("extensions must be an array")
        first: dict[str, int] = {}
        findings: list[Finding] = []
        for index, extension in enumerate(extensions):
            if not isinstance(extension, dict):
                raise TypeError("extension entries must be objects")
            identifier = extension.get("id")
            version = extension.get("version")
            # Other types are refused by the schema and by the uniqueness check.
            if not isinstance(identifier, str) or type(version) is not int:
                continue
            if identifier in self.composable:
                continue
            earlier = first.setdefault(identifier, version)
            if version != earlier:
                findings.append(
                    Finding(
                        EXTENSION_VERSION_RULE,
                        f"/extensions/{index}",
                        f"extension {identifier} appears at version {earlier} and at version {version}",
                    )
                )
        return findings

    def _extension_namespace(self, value: dict[str, Any]) -> list[Finding]:
        """XR1-017: an `ecl.*` extension identifier must be allocated in the registry snapshot."""
        findings: list[Finding] = []
        extensions = value.get("extensions")
        if extensions is None:
            return findings
        if not isinstance(extensions, list):
            raise TypeError("extensions must be an array")
        for index, extension in enumerate(extensions):
            if not isinstance(extension, dict):
                raise TypeError("extension entries must be objects")
            identifier = extension.get("id")
            if (
                isinstance(identifier, str)
                and identifier.startswith("ecl.")
                and identifier not in self.known_extensions
            ):
                findings.append(
                    Finding(
                        "ecl.rule.extension-namespace-allocated.v1",
                        f"/extensions/{index}/id",
                        f"unallocated ECL extension identifier {identifier}",
                    )
                )
        return findings

    def _critical_extensions(self, value: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        extensions = value.get("extensions")
        if extensions is None:
            return findings
        if not isinstance(extensions, list):
            raise TypeError("extensions must be an array")
        for index, extension in enumerate(extensions):
            if not isinstance(extension, dict):
                raise TypeError("extension entries must be objects")
            identifier = str(extension.get("id"))
            if extension.get("critical") and not self._interpretable(
                identifier, extension.get("version")
            ):
                findings.append(
                    Finding(
                        "ecl.rule.unknown-critical-extension-rejected.v1",
                        f"/extensions/{index}/id",
                        f"unknown critical extension {identifier}"
                        f" version {extension.get('version')!r}",
                    )
                )
        return findings

    @staticmethod
    def _self_causation(value: dict[str, Any]) -> list[Finding]:
        object_id = value.get("message_id") or value.get("object_id")
        workflow = value.get("workflow")
        if workflow is None:
            return []
        if not isinstance(workflow, dict):
            raise TypeError("workflow must be an object")
        predecessors = workflow.get("causal_predecessors") or []
        if not isinstance(predecessors, list):
            raise TypeError("causal_predecessors must be an array")
        if object_id and any(
            isinstance(item, dict) and item.get("id") == object_id
            for item in predecessors
        ):
            return [
                Finding(
                    "ecl.rule.message-cannot-cause-itself.v1",
                    "/workflow/causal_predecessors",
                    "an object cannot name itself as a causal predecessor",
                )
            ]
        return []

    @staticmethod
    def _integrity_policy(value: dict[str, Any]) -> list[Finding]:
        policy = value.get("integrity_policy")
        if not isinstance(policy, dict):
            return []
        required = bool(policy.get("required"))
        threshold = policy.get("threshold")
        required_keys = policy.get("required_key_ids") or []
        eligible_keys = policy.get("eligible_key_ids") or []
        if not isinstance(required_keys, list) or not isinstance(
            eligible_keys, list
        ):
            raise TypeError("integrity key identifiers must be arrays")
        invalid = (
            not isinstance(threshold, int)
            or isinstance(threshold, bool)
            or (required and threshold < 1)
            or (not required and threshold != 0)
            or threshold < len(required_keys)
            or (eligible_keys and not set(required_keys).issubset(eligible_keys))
        )
        if invalid:
            return [
                Finding(
                    "ecl.rule.integrity-threshold-consistent.v1",
                    "/integrity_policy",
                    "integrity required flag, threshold, eligible keys, and required keys are inconsistent",
                )
            ]
        return []

    # DCMP2-043: each DCMP-2 rule is checked on its own and only on input members of the types the
    # schema requires, so that a member one rule cannot read leaves the other rules' findings.
    @staticmethod
    def _message_expiry(value: dict[str, Any]) -> list[Finding]:
        """DCMP2-032: a message's `expires_at` is later than its `issued_at`."""
        issued_at = value.get("issued_at")
        expires_at = value.get("expires_at")
        if not (isinstance(issued_at, str) and issued_at and isinstance(expires_at, str) and expires_at):
            return []
        if _time(expires_at) <= _time(issued_at):
            return [
                Finding(
                    "ecl.rule.expiry-after-issue.v1",
                    "/expires_at",
                    "expires_at must be later than issued_at",
                )
            ]
        return []

    @staticmethod
    def _request_parameters(value: dict[str, Any]) -> list[Finding]:
        """DCMP2-007, for a decision request."""
        if value.get("message_type") != "decision_request":
            return []
        return SemanticValidator._parameters_digest(value)

    @staticmethod
    def _budget_debit(value: dict[str, Any]) -> list[Finding]:
        """DCMP2-055: a request's declared budget debit is written without a sign."""
        if value.get("message_type") != "decision_request":
            return []
        action = value.get("action")
        debit = action.get("budget_debit") if isinstance(action, dict) else None
        amount = debit.get("amount") if isinstance(debit, dict) else None
        if isinstance(amount, str) and amount.startswith("-"):
            return [
                Finding(
                    "ecl.rule.budget-debit-non-negative.v1",
                    "/action/budget_debit/amount",
                    "a declared budget debit cannot be negative",
                )
            ]
        return []

    @staticmethod
    def _control_plane(value: dict[str, Any]) -> list[Finding]:
        """DCMP2-025: a halt or quarantine is declared on the emergency control plane."""
        if value.get("message_type") != "control":
            return []
        authority = value.get("authority")
        plane = authority.get("plane") if isinstance(authority, dict) else None
        if value.get("operation") in EMERGENCY_OPERATIONS and plane != "emergency":
            return [
                Finding(
                    "ecl.rule.emergency-control-plane-required.v1",
                    "/authority/plane",
                    "halt and quarantine require the emergency control plane",
                )
            ]
        return []

    @staticmethod
    def _admit_authority(value: dict[str, Any]) -> list[Finding]:
        """DCMP2-013: an admit carries an authorization object with every member that binds its
        release authority; how those members bind the request is DCMP2-044 to DCMP2-050."""
        if value.get("message_type") != "decision_response" or value.get("outcome") != "admit":
            return []
        authorization = value.get("authorization")
        if isinstance(authorization, dict) and all(
            member in authorization for member in AUTHORITY_MEMBERS
        ):
            return []
        return [
            Finding(
                "ecl.rule.admit-requires-valid-authority.v1",
                "/authorization",
                "admit requires an authorization with its identifier, audience, scope digest, "
                "validity interval and use policy",
            )
        ]

    @staticmethod
    def _non_admit_authority(value: dict[str, Any]) -> list[Finding]:
        """DCMP2-012: a response whose outcome is not admit carries no authorization object."""
        if value.get("message_type") != "decision_response" or value.get("outcome") == "admit":
            return []
        authorization = value.get("authorization")
        if isinstance(authorization, dict) and authorization:
            return [
                Finding(
                    "ecl.rule.non-admit-prohibits-authority.v1",
                    "/authorization",
                    "a non-admit response cannot issue authority",
                )
            ]
        return []

    @staticmethod
    def _authority_interval(value: dict[str, Any]) -> list[Finding]:
        """DCMP2-032: an authorization's `valid_until` is later than its `valid_from`."""
        if value.get("message_type") != "decision_response":
            return []
        authorization = value.get("authorization")
        if not isinstance(authorization, dict):
            return []
        start = authorization.get("valid_from")
        end = authorization.get("valid_until")
        if not (isinstance(start, str) and isinstance(end, str)):
            return []
        if _time(end) <= _time(start):
            return [
                Finding(
                    "ecl.rule.expiry-after-issue.v1",
                    "/authorization/valid_until",
                    "authority validity interval is empty or reversed",
                )
            ]
        return []

    @staticmethod
    def _parameters_digest(value: dict[str, Any]) -> list[Finding]:
        """DCMP2-007: in-band parameters hash to `parameters_digest` (SHA-256, canonical JSON)."""
        action = value.get("action")
        if not isinstance(action, dict) or "parameters" not in action:
            return []
        declared = action.get("parameters_digest")
        expected = {
            "algorithm": "ecl.digest.sha-256.v1",
            "value": object_digest(action["parameters"]),
        }
        if declared != expected:
            return [
                Finding(
                    "ecl.rule.parameters-digest-matches.v1",
                    "/action/parameters_digest",
                    "parameters_digest is not the SHA-256 digest of the canonical in-band parameters",
                )
            ]
        return []

    @staticmethod
    def _ebmp(value: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        if value.get("object_type") != "event_record":
            return findings
        event_type = value.get("event_type")
        event = value.get("event") or {}
        if not isinstance(event, dict):
            raise TypeError("event must be an object")
        expected_kind = EVENT_KINDS.get(event_type) if isinstance(event_type, str) else None
        if expected_kind is not None:
            kind, states = expected_kind
            if event.get("kind") != kind:
                findings.append(
                    Finding(
                        "ecl.rule.event-type-kind-consistent.v1",
                        "/event/kind",
                        f"event_type {event_type} requires event kind {kind}",
                    )
                )
            elif states is not None and event.get("state") not in states:
                findings.append(
                    Finding(
                        "ecl.rule.event-type-kind-consistent.v1",
                        "/event/state",
                        f"event_type {event_type} cannot carry state {event.get('state')!r}",
                    )
                )
        terminal_states = {
            "succeeded",
            "failed",
            "partially_succeeded",
            "cancelled",
            "timed_out",
            "rolled_back",
            "compensated",
            "unknown",
            "denied",
            "held",
            "challenged",
            "expired_before_release",
        }
        state = event.get("state")
        if event_type == "execution_terminal" and state not in terminal_states:
            findings.append(
                Finding(
                    "ecl.rule.terminal-execution-state-consistent.v1",
                    "/event/state",
                    f"execution_terminal cannot carry non-terminal state {state!r}",
                )
            )
        if event_type != "execution_terminal" and state in terminal_states:
            findings.append(
                Finding(
                    "ecl.rule.terminal-execution-state-consistent.v1",
                    "/event/state",
                    "terminal execution state requires event_type execution_terminal",
                )
            )
        residual = event.get("residual_state")
        if (
            event_type == "execution_terminal"
            and state in UNCERTAIN_STATES
            and not (
                isinstance(event.get("side_effects"), list)
                and isinstance(residual, str)
                and residual
            )
        ):
            findings.append(
                Finding(
                    "ecl.rule.terminal-execution-state-consistent.v1",
                    "/event",
                    f"{state} requires side_effects and a non-empty residual_state (EBMP2-013)",
                )
            )
        if event_type == "lifecycle_transition":
            operation = event.get("operation")
            if operation in {"redact", "supersede"} and not event.get(
                "derived_artifact"
            ):
                findings.append(
                    Finding(
                        "ecl.rule.lifecycle-derived-artifact-required.v1",
                        "/event/derived_artifact",
                        f"{operation} requires a derived artifact reference",
                    )
                )
            # EBMP2-040 and EL1-014: a redaction also references its redaction manifest.
            if operation == "redact" and not event.get("redaction_manifest"):
                findings.append(
                    Finding(
                        "ecl.rule.lifecycle-derived-artifact-required.v1",
                        "/event/redaction_manifest",
                        "redact requires a redaction manifest reference",
                    )
                )
        return findings

    def validate(self, value: dict[str, Any]) -> list[Finding]:
        if not isinstance(value, dict):
            return [
                Finding(
                    "ecl.error.schema-invalid.v1",
                    "/",
                    "semantic validation requires an object",
                )
            ]
        findings: list[Finding] = []

        def guarded(name: str, check: Any) -> None:
            try:
                findings.extend(check(value))
            except (
                AttributeError,
                CanonicalizationError,
                IndexError,
                KeyError,
                OverflowError,
                RecursionError,
                TypeError,
                ValueError,
            ) as exc:
                findings.append(
                    Finding(
                        "ecl.error.schema-invalid.v1",
                        "/",
                        f"{name} semantic check rejected malformed input: {exc}",
                    )
                )

        guarded("extension uniqueness", self._extensions)
        guarded("extension versions", self._extension_versions)
        guarded("extension namespace", self._extension_namespace)
        guarded("critical extension", self._critical_extensions)
        guarded("self-causation", self._self_causation)
        guarded("integrity policy", self._integrity_policy)
        protocol = value.get("protocol")
        if isinstance(protocol, str) and protocol in {"DCMP-2", "EBMP-2"}:
            guarded("extension value", self._extension_value_schemas)
        if protocol == "DCMP-2":
            guarded("message expiry", self._message_expiry)
            guarded("parameters digest", self._request_parameters)
            guarded("budget debit", self._budget_debit)
            guarded("emergency control plane", self._control_plane)
            guarded("admit authority", self._admit_authority)
            guarded("non-admit authority", self._non_admit_authority)
            guarded("authority interval", self._authority_interval)
            guarded("consequence coupling", self._coupling_results)
            guarded("decision basis", self._decision_basis)
        elif protocol == "EBMP-2":
            guarded("EBMP-2", self._ebmp)
            guarded("approval record", self._approval_records)
            guarded("control change", self._control_changes)
        elif value.get("schema_version") == "ecl_adapter_binding_v1":
            guarded("adapter binding", adapter_binding_findings)
        elif value.get("schema_version") == REGISTER_SCHEMA_VERSION:
            guarded("register declarations", self._register_declarations)
        return sorted(findings, key=lambda item: (item.rule_id, item.path, item.message))
