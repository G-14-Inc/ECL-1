"""Offline verification checks and read-only metadata for decision_basis."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .canonical import object_digest
from .schema import rfc3339_utc_nanoseconds

DECISION_BASIS = "ecl.ext.decision-basis.v1"

ONE_WAY_RULE = "ecl.rule.decision-basis-one-way.v1"

REQUIRED_RULE = "ecl.rule.decision-basis-required.v1"

REGISTER_RULE = "ecl.rule.decision-basis-matches-register.v1"

REGISTER_DOCUMENT_RULE = "ecl.rule.register-declarations-consistent.v1"

REGISTER_SCHEMA_VERSION = "ecl_action_register_v1"

REGISTER_SCHEMA = "https://externalcontrollayer.ai/ns/schema/action-register/1"

DIGEST_SUITE = "ecl.digest.sha-256.v1"

CLASSES = ("verifiable", "judgment", "actor_supplied")

RESTRICTING_ONLY_CLASSES = frozenset({"actor_supplied", "judgment"})

STATUSES = ("available", "unavailable", "late", "malformed")

EFFECTS = ("supports", "restricts", "none")

OUTCOMES = ("admit", "challenge", "hold", "deny")

_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")

_HEX_DIGITS = frozenset("0123456789ABCDEFabcdef")


def _percent_upper(name: str) -> str:
    """`name` with the two hexadecimal digits of every percent-encoding in upper case."""
    parts: list[str] = []
    index = 0
    while index < len(name):
        if (
            name[index] == "%"
            and index + 2 < len(name)
            and name[index + 1] in _HEX_DIGITS
            and name[index + 2] in _HEX_DIGITS
        ):
            parts.append("%" + name[index + 1 : index + 3].upper())
            index += 3
        else:
            parts.append(name[index])
            index += 1
    return "".join(parts)


def input_key(name: str) -> str:
    """The form in which DCMP2-053 compares an input name, an entry's `source` with its declared
    source and with the request's `actor`: the case normalization of RFC 3986 section 6.2.2.1
    and RFC 8141 section 3.1, in ASCII only. The URI scheme is lowercased; so are, for a URN, its
    namespace identifier and, for an `http` or `https` URI, its host (the authority after any
    user information, port included); then the two hexadecimal digits of every percent-encoding
    are uppercased. No other normalization is applied."""
    colon = name.find(":")
    if colon <= 0:
        return _percent_upper(name)
    scheme = name[:colon].translate(_ASCII_LOWER)
    rest = name[colon:]
    if scheme == "urn":
        end = name.find(":", colon + 1)
        if end != -1:
            rest = ":" + name[colon + 1 : end].translate(_ASCII_LOWER) + name[end:]
    elif scheme in ("http", "https") and rest.startswith("://"):
        start = 3
        end = len(rest)
        for delimiter in "/?#":
            found = rest.find(delimiter, start)
            if found != -1 and found < end:
                end = found
        host = rest.rfind("@", start, end) + 1 or start
        rest = rest[:host] + rest[host:end].translate(_ASCII_LOWER) + rest[end:]
    return _percent_upper(scheme + rest)


def _instant(value: object) -> int | None:
    """An ECL instant in nanoseconds, or None for a value that is not one; a check that needs a
    time leaves a value of another form to the value schema (XR1-023)."""
    try:
        return rfc3339_utc_nanoseconds(value)
    except ValueError:
        return None


def _derived_names(item: Mapping[str, Any]) -> list[str]:
    derived = item.get("derived_from")
    return [name for name in derived if isinstance(name, str)] if isinstance(derived, list) else []


def _sources(item: Mapping[str, Any], by_key: Mapping[str, Mapping[str, Any]]) -> set[str]:
    """The keys of the entries that `item` is computed from, directly or through other entries:
    the names its `derived_from` gives, other than its own, followed through the entries they
    name. A name that names no entry is not followed."""
    own = item.get("input")
    own_key = input_key(own) if isinstance(own, str) else None
    pending = [
        key
        for key in (input_key(name) for name in _derived_names(item))
        if key != own_key and key in by_key
    ]
    seen: set[str] = set()
    while pending:
        key = pending.pop()
        if key in seen:
            continue
        seen.add(key)
        pending.extend(
            source
            for source in (input_key(name) for name in _derived_names(by_key[key]))
            if source in by_key and source not in seen
        )
    return seen


def least_trusted(classes: Iterable[str]) -> str:
    """The least trusted of `classes` in the order of Section 4.3; `verifiable` for none."""
    ranks = [CLASSES.index(item) for item in classes if item in CLASSES]
    return CLASSES[max(ranks)] if ranks else "verifiable"


def register_digest(register: Mapping[str, Any]) -> dict[str, str]:
    """The `ecl.digest.sha-256.v1` digest of a register document's restricted canonical JSON."""
    return {"algorithm": DIGEST_SUITE, "value": object_digest(register)}


def register_reference(register: Mapping[str, Any]) -> dict[str, Any]:
    """The `register` member that names a register document (ECL1N-0181)."""
    reference: dict[str, Any] = {"uri": str(register["register_id"])}
    version = register.get("register_version")
    if isinstance(version, str):
        reference["version"] = version
    reference["digest"] = register_digest(register)
    return reference


def action_entry(register: Mapping[str, Any], action_class: str) -> Mapping[str, Any] | None:
    """The register's entry for `action_class`, or None when it has none."""
    entries = register.get("entries")
    if not isinstance(entries, list):
        return None
    for item in entries:
        if isinstance(item, Mapping) and item.get("action_class_id") == action_class:
            return item
    return None


def declared_inputs(register: Mapping[str, Any], action_class: str) -> list[dict[str, Any]]:
    """The decision inputs that the register declares for `action_class`; none without an entry."""
    entry = action_entry(register, action_class)
    declared = entry.get("decision_inputs") if entry is not None else None
    if not isinstance(declared, list):
        return []
    return [dict(item) for item in declared if isinstance(item, Mapping)]


def values(response: Mapping[str, Any]) -> list[tuple[int, Any]]:
    """(index, value) of each occurrence of the extension on a message."""
    extensions = response.get("extensions")
    if not isinstance(extensions, list):
        return []
    return [
        (index, item.get("value"))
        for index, item in enumerate(extensions)
        if isinstance(item, Mapping) and item.get("id") == DECISION_BASIS
    ]


def one_way_problems(
    value: Mapping[str, Any],
    *,
    admit: bool,
    outcome: object = None,
    evaluated_at: object = None,
) -> list[tuple[str, str]]:
    """(path below the value, message) for each way a decision-basis value breaks DCMP2-053.

    `admit` says whether the response is an `admit`. `outcome` and `evaluated_at` are the
    response's, when the caller has the response: with them the value's
    `verifiable_only_outcome`, `received_at` and each entry's `obtained_at` are checked against
    the decision too. Members of another shape are left to the value schema (XR1-023); this reads
    only what it needs, and never raises for a value of any shape.
    """
    inputs = value.get("inputs")
    if not isinstance(inputs, list):
        return []
    entries = [
        (position, item) for position, item in enumerate(inputs) if isinstance(item, Mapping)
    ]
    problems: list[tuple[str, str]] = []
    by_key: dict[str, Mapping[str, Any]] = {}
    for position, item in entries:
        name = item.get("input")
        if isinstance(name, str):
            key = input_key(name)
            if key in by_key:
                problems.append(
                    (f"/inputs/{position}/input", "the record lists this input more than once")
                )
            else:
                by_key[key] = item
    decided = _instant(evaluated_at)
    for position, item in entries:
        path = f"/inputs/{position}"
        supports = item.get("effect") == "supports"
        available = item.get("status") == "available"
        if supports and item.get("class") in RESTRICTING_ONLY_CLASSES:
            problems.append(
                (
                    path + "/effect",
                    f"an input of class {item.get('class')!r} can only make an outcome stricter",
                )
            )
        if supports and not available:
            problems.append(
                (
                    path + "/effect",
                    f"an input whose status is {item.get('status')!r} cannot support an outcome",
                )
            )
        if admit and item.get("required") is True and not available:
            problems.append(
                (
                    path + "/status",
                    f"an admit cannot proceed while a required input is {item.get('status')!r}",
                )
            )
        own = item.get("input")
        own_key = input_key(own) if isinstance(own, str) else None
        derived = item.get("derived_from")
        if isinstance(derived, list):
            for offset, name in enumerate(derived):
                source = input_key(name) if isinstance(name, str) else None
                if source is None or source == own_key or source not in by_key:
                    problems.append(
                        (
                            f"{path}/derived_from/{offset}",
                            "the record lists no other input with this name",
                        )
                    )
                elif (
                    item.get("class") == "verifiable"
                    and by_key[source].get("class") != "verifiable"
                ):
                    problems.append(
                        (
                            path + "/class",
                            "an input computed from an input of class "
                            f"{by_key[source].get('class')!r} cannot be verifiable",
                        )
                    )
        sources = _sources(item, by_key)
        if own_key is not None and own_key in sources:
            problems.append(
                (path + "/derived_from", "the input is computed from itself through other inputs")
            )
        unavailable = any(
            by_key[key].get("status") != "available" for key in sources if key != own_key
        )
        if unavailable and available and supports:
            problems.append(
                (
                    path + "/effect",
                    "an input computed from an input that was not available cannot support an "
                    "outcome",
                )
            )
        if unavailable and available and admit and item.get("required") is True:
            problems.append(
                (
                    path + "/status",
                    "an admit cannot proceed while a required input is computed from an input "
                    "that was not available",
                )
            )
        obtained = _instant(item.get("obtained_at"))
        if available and decided is not None and obtained is not None and obtained > decided:
            problems.append(
                (path + "/status", "an input obtained after the decision was not available")
            )
        described = _instant(item.get("value_at"))
        if described is not None and obtained is not None and described > obtained:
            problems.append(
                (path + "/value_at", "the input's value describes a time after it was obtained")
            )
        if described is not None and decided is not None and described > decided:
            problems.append(
                (path + "/value_at", "the input's value describes a time after the decision")
            )
        if (
            available
            and "received_at" in value
            and not ("obtained_at" in item and "value_at" in item)
        ):
            problems.append(
                (
                    path,
                    "a record that gives when the request was received gives when each "
                    "available input was obtained and the time its value describes",
                )
            )
    if admit and not any(
        item.get("class") == "verifiable" and item.get("effect") == "supports"
        for _, item in entries
    ):
        problems.append(("/inputs", "an admit records no verifiable input that supports it"))
    if "received_at" not in value and any("obtained_at" in item for _, item in entries):
        problems.append(
            (
                "/received_at",
                "a record that gives when an input was obtained gives when the request was "
                "received",
            )
        )
    received = _instant(value.get("received_at"))
    if received is not None and decided is not None and received > decided:
        problems.append(("/received_at", "the request was received after the decision"))
    recorded = value.get("verifiable_only_outcome")
    if (
        isinstance(recorded, str)
        and recorded in OUTCOMES
        and isinstance(outcome, str)
        and outcome in OUTCOMES
        and OUTCOMES.index(outcome) < OUTCOMES.index(recorded)
    ):
        problems.append(
            (
                "/verifiable_only_outcome",
                f"the outcome {outcome!r} is less strict than the verifiable-only outcome "
                f"{recorded!r}",
            )
        )
    if isinstance(recorded, str) and recorded in OUTCOMES:
        problems.extend(_verifiable_only_problems(recorded, entries, by_key))
    return problems


def _verifiable_only_problems(
    recorded: str,
    entries: Sequence[tuple[int, Mapping[str, Any]]],
    by_key: Mapping[str, Mapping[str, Any]],
) -> list[tuple[str, str]]:
    """DCMP2-053 on a recorded `verifiable_only_outcome`: an input supports only a verifiable-only
    `admit` (ECL1N-0181), and a verifiable-only `admit` rests on at least one `verifiable` input
    that supports it and on no required `verifiable` input that was not available, an input
    computed from one that was not available counting as not available itself. A required
    `actor_supplied` or `judgment` input does not change the verifiable-only outcome, which treats
    every such input as absent (ECL-1 Section 4.3); whether it was available affects only the
    decision's outcome (ECL1N-0182)."""
    problems: list[tuple[str, str]] = []
    if recorded != "admit":
        problems.extend(
            (
                f"/inputs/{position}/effect",
                f"no input supports an outcome whose verifiable-only outcome is {recorded!r}",
            )
            for position, item in entries
            if item.get("effect") == "supports"
        )
        return problems
    if not any(
        item.get("class") == "verifiable" and item.get("effect") == "supports"
        for _, item in entries
    ):
        problems.append(
            (
                "/verifiable_only_outcome",
                "a verifiable-only admit records no verifiable input that supports it",
            )
        )
    for position, item in entries:
        if item.get("required") is not True or item.get("class") != "verifiable":
            continue
        own = item.get("input")
        own_key = input_key(own) if isinstance(own, str) else None
        unavailable = item.get("status") != "available" or any(
            by_key[key].get("status") != "available"
            for key in _sources(item, by_key)
            if key != own_key
        )
        if unavailable:
            problems.append(
                (
                    f"/inputs/{position}/status",
                    "a verifiable-only admit cannot have a required verifiable input that was "
                    "not available",
                )
            )
    return problems


def response_one_way_problems(
    response: Mapping[str, Any], value: Mapping[str, Any]
) -> list[tuple[str, str]]:
    """`one_way_problems` for a decision-basis value carried by `response`, with the response's
    outcome and `evaluated_at` (DCMP2-053)."""
    outcome = response.get("outcome")
    return one_way_problems(
        value,
        admit=outcome == "admit",
        outcome=outcome,
        evaluated_at=response.get("evaluated_at"),
    )


def actor_source_problems(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> list[tuple[str, str]]:
    """(path below the value, message) for each entry that a decision-basis value records as
    `verifiable` while its `source` is the request's `actor`, the governed AI system that requested
    the action (DCMP2-053): an input that the governed AI system produces is `actor_supplied`
    (ECL-1 Section 4.3, ECL1N-0178). Names are compared by `input_key`. The check sees one
    identifier, the request's `actor.id`. A verifier that holds the request applies it, through
    `request_problems`, under `ecl.rule.decision-basis-one-way.v1`; this never raises."""
    actor = request.get("actor")
    actor_id = actor.get("id") if isinstance(actor, Mapping) else None
    inputs = value.get("inputs")
    if not isinstance(actor_id, str) or not isinstance(inputs, list):
        return []
    key = input_key(actor_id)
    return [
        (
            f"/inputs/{position}/class",
            "an input whose source is the requesting actor cannot be verifiable",
        )
        for position, item in enumerate(inputs)
        if isinstance(item, Mapping)
        and item.get("class") == "verifiable"
        and isinstance(item.get("source"), str)
        and input_key(item["source"]) == key
    ]


def request_problems(
    value: Mapping[str, Any], request: Mapping[str, Any], *, skew_seconds: int = 0
) -> list[tuple[str, str]]:
    """(path below the value, message) for each way a decision-basis value breaks DCMP2-053 with
    the request it answers: an input recorded as `verifiable` whose `source` is the request's
    `actor` (`actor_source_problems`), and a `received_at` earlier than the request's `issued_at`
    by more than the response clock-skew allowance of the verification profile (DCMP2-047),
    `skew_seconds`, zero in the reference profile. A verifier that holds the request applies
    both under `ecl.rule.decision-basis-one-way.v1`; this never raises."""
    problems = actor_source_problems(value, request)
    received = _instant(value.get("received_at"))
    issued = _instant(request.get("issued_at"))
    if (
        received is not None
        and issued is not None
        and received < issued - max(skew_seconds, 0) * 1_000_000_000
    ):
        problems.append(("/received_at", "the request was received before it was issued"))
    return problems


def register_problems(
    value: Mapping[str, Any],
    register: Mapping[str, Any],
    action_class: object,
    *,
    evaluated_at: object = None,
) -> list[tuple[str, str]]:
    """(path below the value, message) for each way a decision basis disagrees with the register
    that a verifier holds (`ecl.rule.decision-basis-matches-register.v1`).

    The record must name that register version: its `register_id` as `uri` and the digest of its
    restricted canonical JSON. Its inputs must be exactly the inputs the register declares for
    `action_class` (the request's `action.action_class`), each once, with the declared class,
    required flag, source and `derived_from` (absent naming none). With the response's
    `evaluated_at`, an input recorded as available must not
    have been obtained more than its declared deadline after the value's `received_at`, nor have a
    value older than its declared maximum age at `evaluated_at` (ECL1N-0182). A register without
    an entry for the class declares no input for it. An input that the register declares twice for
    the class matches no record. Input names are compared by `input_key`.
    """
    problems: list[tuple[str, str]] = []
    named = value.get("register")
    digest = register_digest(register)
    if not isinstance(named, Mapping) or named.get("uri") != register.get("register_id"):
        problems.append(("/register/uri", "the record names another register"))
    elif named.get("digest") != digest:
        problems.append(("/register/digest", "the record names another version of the register"))
    if (
        "register_version" in register
        and isinstance(named, Mapping)
        and "version" in named
        and named.get("version") != register.get("register_version")
    ):
        problems.append(("/register/version", "the record names another register version"))
    inputs = value.get("inputs")
    if not isinstance(inputs, list):
        return problems
    declared: dict[str, Mapping[str, Any]] = {}
    repeated: set[str] = set()
    for item in (
        declared_inputs(register, str(action_class)) if isinstance(action_class, str) else []
    ):
        name = item.get("input")
        if not isinstance(name, str):
            continue
        key = input_key(name)
        if key in declared:
            repeated.add(key)
        else:
            declared[key] = item
    decided = _instant(evaluated_at)
    received = _instant(value.get("received_at"))
    listed: set[str] = set()
    for position, item in enumerate(inputs):
        path = f"/inputs/{position}"
        name = item.get("input") if isinstance(item, Mapping) else None
        if not isinstance(item, Mapping) or not isinstance(name, str):
            continue
        key = input_key(name)
        listed.add(key)
        declaration = declared.get(key)
        if declaration is None:
            problems.append(
                (path + "/input", "the register does not declare this input for the action class")
            )
            continue
        if key in repeated:
            problems.append((path + "/input", "the register declares this input more than once"))
            continue
        if item.get("class") != declaration.get("class"):
            problems.append((path + "/class", "the class is not the one the register declares"))
        if item.get("required") is not declaration.get("required"):
            problems.append(
                (path + "/required", "the required flag is not the one the register declares")
            )
        recorded_source = item.get("source")
        declared_source = declaration.get("source")
        if not (
            isinstance(recorded_source, str)
            and isinstance(declared_source, str)
            and input_key(recorded_source) == input_key(declared_source)
        ):
            problems.append((path + "/source", "the source is not the one the register declares"))
        derived = {input_key(source) for source in _derived_names(item)}
        if derived != {input_key(source) for source in _derived_names(declaration)}:
            problems.append(
                (
                    path + "/derived_from",
                    "the inputs it is computed from are not the ones the register declares",
                )
            )
        if item.get("status") != "available":
            continue
        deadline = declaration.get("deadline_milliseconds")
        obtained = _instant(item.get("obtained_at"))
        if (
            type(deadline) is int
            and obtained is not None
            and received is not None
            and obtained - received > deadline * 1_000_000
        ):
            problems.append(
                (path + "/obtained_at", "the input was obtained after its declared deadline")
            )
        maximum_age = declaration.get("maximum_age_seconds")
        value_at = _instant(item.get("value_at"))
        if (
            type(maximum_age) is int
            and value_at is not None
            and decided is not None
            and decided - value_at > maximum_age * 1_000_000_000
        ):
            problems.append(
                (path + "/value_at", "the input's value is older than its declared maximum age")
            )
    problems.extend(
        ("/inputs", f"the record does not list the declared input {item.get('input')}")
        for key, item in declared.items()
        if key not in listed
    )
    return problems


def _declaration_problems(declared: Sequence[object], base: str) -> list[tuple[str, str]]:
    """The register document rule for the `decision_inputs` of one action entry."""
    problems: list[tuple[str, str]] = []
    entries = [
        (position, item) for position, item in enumerate(declared) if isinstance(item, Mapping)
    ]
    by_key: dict[str, Mapping[str, Any]] = {}
    for position, item in entries:
        name = item.get("input")
        if isinstance(name, str):
            key = input_key(name)
            if key in by_key:
                problems.append(
                    (
                        f"{base}/{position}/input",
                        "the register declares this input more than once for the action class",
                    )
                )
            else:
                by_key[key] = item
    for position, item in entries:
        path = f"{base}/{position}"
        own = item.get("input")
        own_key = input_key(own) if isinstance(own, str) else None
        derived = item.get("derived_from")
        if isinstance(derived, list):
            for offset, name in enumerate(derived):
                source = input_key(name) if isinstance(name, str) else None
                if source is None or source == own_key or source not in by_key:
                    problems.append(
                        (
                            f"{path}/derived_from/{offset}",
                            "the register declares no other input of the action class with this "
                            "name",
                        )
                    )
                elif (
                    item.get("class") == "verifiable"
                    and by_key[source].get("class") != "verifiable"
                ):
                    problems.append(
                        (
                            path + "/class",
                            "an input computed from an input of class "
                            f"{by_key[source].get('class')!r} cannot be verifiable",
                        )
                    )
        if own_key is not None and own_key in _sources(item, by_key):
            problems.append(
                (path + "/derived_from", "the input is computed from itself through other inputs")
            )
    return problems


def register_document_problems(register: Mapping[str, Any]) -> list[tuple[str, str]]:
    """(path, message) for each way a register document breaks
    `ecl.rule.register-declarations-consistent.v1` (ECL1N-0178): an action class declared more
    than once, an input declared more than once for a class, a `derived_from` name that is not
    another input of the class, an input declared `verifiable` that is computed from one that is
    not, or an input computed from itself through other inputs. Members of another shape are left
    to the register schema; this never raises for a value of any shape."""
    problems: list[tuple[str, str]] = []
    entries = register.get("entries")
    if not isinstance(entries, list):
        return problems
    classes: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            continue
        path = f"/entries/{index}"
        action_class = entry.get("action_class_id")
        if isinstance(action_class, str):
            if action_class in classes:
                problems.append(
                    (
                        path + "/action_class_id",
                        "the register declares this action class more than once",
                    )
                )
            else:
                classes.add(action_class)
        declared = entry.get("decision_inputs")
        if isinstance(declared, list):
            problems.extend(_declaration_problems(declared, path + "/decision_inputs"))
    return problems
