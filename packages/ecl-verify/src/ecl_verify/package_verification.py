"""Verify an offline verification package as the evidence bundle it carries (IE1-021, IE1-022).

An offline package (OFFLINE-VERIFICATION-1) is an `ecl.zip.store.v1` archive: `manifest.json` and
the artifacts it names, each bound by role, size and SHA-256 digest. Its `envelope` and
`observation` artifacts are the envelopes and observations of one evidence bundle (EBMP-2 section
11), its `payload` artifacts are their canonical payloads, and the rest is the material that the
producer used. That material is evidence and never a trust anchor (IE1-022): the bundle is verified
under the trust policy, earlier policy versions and evaluation time that the caller supplies, as any
bundle is.

`verify_offline_package` makes the checks of IE1-022 in its order and reports the verdict and the
error code of the first that fails:

1. the archive is in `ecl.zip.store.v1` form (IE1-030, IE1-031), or `invalid`, semantic-invalid;
2. it holds `manifest.json`, or `incomplete`, causal-closure-incomplete;
3. the manifest is strict JSON that satisfies its schema, with valid `created_at` and `expires_at`
   instants and a SHA-256 digest in every artifact entry and reference, or `invalid`,
   schema-invalid;
4. its artifact paths could be the entry names of one such archive together with `manifest.json`
   (entry names of the profile, no two of them aliases after ASCII case folding, none an alias of
   `manifest.json` and none a parent directory of another), and it names every other member, or
   `invalid`, semantic-invalid;
5. `expires_at` is later than `created_at`, or `invalid`, expired;
6. every artifact the archive holds has its manifest size and digest, or `invalid`,
   integrity-invalid;
7. every `envelope` and `observation` artifact is a strict JSON object, or `invalid`,
   schema-invalid;
8. every `payload` artifact is the payload of one of them, or `invalid`, integrity-invalid;
9. when the package carries an envelope, the bundle is not `invalid`, or `invalid` with the
   bundle's findings;
10. every artifact the manifest names or IE1-021 requires, and the payload of every packaged
    envelope and observation, is present, and there is an envelope, or `incomplete`,
    causal-closure-incomplete;
11. the bundle is not `incomplete`, or `incomplete` with the bundle's findings.

Otherwise the package has its bundle's verdict, except that a package whose `expires_at` is not
later than the evaluation time is `current-trust-failed`, with the expired code, where its bundle is
`verified`. A package that exceeds a declared limit of the verifier (IE1-028) is `invalid` with
resource-limit-exceeded at the check that meets the limit, as a bundle over a limit is (EBMP2-062):
the archive's limits at check 1, the strict JSON parser's limits at checks 3 and 7, and the artifact
count and path bytes at check 4.

The caller's options are those of `verify_bundle`, passed to it unchanged, so an option that the
bundle verifier gains reaches the package's bundle without a change here: among them, the decision
basis is required unless the caller opts out, and a register is applied when the caller gives one.
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any

from .bundle_verification import BundleReport, verify_bundle, with_scope
from .bundle_verification import reported_identifiers as bundle_identifiers
from .canonical import CanonicalizationError, loads_json_strict
from .integrity import IntegrityError, decode_payload
from .offline import (
    CLOSURE_INCOMPLETE,
    DEFAULT_OFFLINE_RESOURCE_LIMITS,
    EXPIRED,
    INTEGRITY_INVALID,
    MANIFEST_NAME,
    MANIFEST_SCHEMA,
    REQUIRED_ROLES,
    RESOURCE_LIMIT,
    SCHEMA_INVALID,
    SEMANTIC_INVALID,
    OfflinePackageError,
    OfflineResourceLimits,
    _checked_artifacts,
    _time,
    _validate_limits,
    verify_zip_members,
)
from .resources import validator_for
from .trust import TrustPolicy

# The artifact roles whose envelopes form the package's evidence bundle, and the bundle member
# each one fills.
EVIDENCE_ROLES = {"envelope": "envelopes", "observation": "observations"}
# The manifest references whose artifacts IE1-021 requires, with the role each artifact has.
REFERENCE_ROLES = (
    ("trust_policy", "trust_policy"),
    ("revocation_snapshot", "revocation_snapshot"),
    ("registry_snapshots", "registry_snapshot"),
    ("time_evidence", "time_evidence"),
)
SHA_256 = "ecl.digest.sha-256.v1"
CURRENT_TRUST_FAILED = "current-trust-failed"


def _issue(code: str, message: str) -> str:
    return f"{code}: {message}"


def _references(manifest: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Each manifest reference whose artifact IE1-021 requires, with that artifact's role."""
    found: list[tuple[str, dict[str, Any]]] = []
    for member, role in REFERENCE_ROLES:
        value = manifest[member]
        found.extend((role, item) for item in (value if isinstance(value, list) else [value]))
    return found


def _manifest_problem(manifest: Any) -> str | None:
    """Why the manifest fails check 3, or None."""
    if not validator_for(MANIFEST_SCHEMA).is_valid(manifest):
        return f"{MANIFEST_NAME} does not satisfy {MANIFEST_SCHEMA}"
    try:
        _time(manifest["created_at"])
        _time(manifest["expires_at"])
    except OfflinePackageError:
        return "created_at or expires_at is not a valid instant"
    for item in manifest["artifacts"]:
        if item["digest"]["algorithm"] != SHA_256:
            return f"artifact {item['path']} has no {SHA_256} digest"
    for role, reference in _references(manifest):
        if reference.get("digest", {}).get("algorithm") != SHA_256:
            return f"a {role} reference has no {SHA_256} digest"
    return None


def verify_offline_package(
    value: bytes,
    policy: TrustPolicy,
    *,
    now: str,
    history: Sequence[TrustPolicy] = (),
    require_trusted_time: bool = False,
    register: Mapping[str, Any] | None = None,
    limits: OfflineResourceLimits = DEFAULT_OFFLINE_RESOURCE_LIMITS,
    **options: Any,
) -> BundleReport:
    """The verdict of an offline package under the caller's trust policy at `now`.

    `policy`, `now`, `history`, `require_trusted_time`, `register` and `options` are the
    caller's inputs to `verify_bundle`, which receives them unchanged (`options` takes
    `response_clock_skew_seconds`, `accept_current_trust_failure` and any option the bundle
    verifier gains); nothing the package carries replaces them. A package's bundle is therefore
    verified under the same options as a bundle on its own: every decision response must record
    its decision basis, and a register applies as it does to a bundle on its own. Package data
    is reported, never raised. A malformed caller argument raises ValueError before the package
    is read, whatever the package holds: `value` that is not bytes, `limits`, and every argument
    that `verify_bundle` refuses.
    """
    if not isinstance(value, bytes):
        raise ValueError("an offline package is bytes")
    _validate_limits(limits)  # OfflinePackageError is a ValueError
    bundle_options: dict[str, Any] = {
        **options,
        "history": tuple(history),
        "require_trusted_time": require_trusted_time,
        "register": register,
    }
    # The bundle verifier checks the caller's arguments itself, before it reads a bundle: it
    # raises ValueError for one it refuses, and otherwise reports this empty bundle as invalid.
    # Its report carries what the options give every report (the verification profile and the
    # register among them), so the package's own refusals start from it.
    base = verify_bundle({}, policy, now=now, **bundle_options)

    def _report(verdict: str, findings: Sequence[str]) -> BundleReport:
        # EBMP2-076: the scope follows the package's verdict.
        return with_scope(replace(base, verdict=verdict, findings=tuple(findings)))

    # 1. The container profile, within the verifier's limits: a limit that the archive meets is a
    # resource limit, and any other departure from the profile is semantic-invalid.
    try:
        names = verify_zip_members(value, limits=limits)
    except OfflinePackageError as error:
        code = RESOURCE_LIMIT if error.code == RESOURCE_LIMIT else SEMANTIC_INVALID
        return _report("invalid", [_issue(code, str(error))])
    # 2. The manifest.
    if MANIFEST_NAME not in names:
        return _report("incomplete", [_issue(CLOSURE_INCOMPLETE, f"there is no {MANIFEST_NAME}")])
    with zipfile.ZipFile(io.BytesIO(value), "r") as archive:
        members = {name: archive.read(name) for name in names}
    # 3. Strict JSON, its schema, its times and SHA-256 digests.
    # A strict JSON refusal that the parser reports as a limit (IE1-037) is a resource limit.
    problem_code = SCHEMA_INVALID
    try:
        manifest = loads_json_strict(members[MANIFEST_NAME])
    except CanonicalizationError as error:
        problem: str | None = f"{MANIFEST_NAME} is not strict JSON: {error}"
        if error.finding_id == RESOURCE_LIMIT:
            problem_code = RESOURCE_LIMIT
    else:
        problem = _manifest_problem(manifest)
    if problem is not None:
        return _report("invalid", [_issue(problem_code, problem)])
    # 4. Entry names that one archive could hold with the manifest, naming exactly the other
    # members.
    try:
        artifacts = _checked_artifacts(manifest, limits, archive=True)
    except OfflinePackageError as error:
        return _report("invalid", [_issue(error.code, str(error))])
    listed = [item["path"] for item in artifacts]
    unnamed = sorted(set(names) - set(listed) - {MANIFEST_NAME})
    if unnamed:
        message = f"the archive holds a member the manifest does not name: {unnamed[0]}"
        return _report("invalid", [_issue(SEMANTIC_INVALID, message)])
    # 5. The package's validity interval.
    if _time(manifest["expires_at"]) <= _time(manifest["created_at"]):
        message = "the package expires no later than it was created"
        return _report("invalid", [_issue(EXPIRED, message)])
    expired = _time(now) >= _time(manifest["expires_at"])
    # 6. Size and digest of every artifact the archive holds.
    # Check 1 has bounded each member and their total by the verifier's limits.
    carried: dict[str, bytes] = {}
    absent: list[str] = []
    for item in artifacts:
        relative = item["path"]
        data = members.get(relative)
        if data is None:
            absent.append(relative)
            continue
        if item["size_bytes"] != len(data):
            message = f"the size of {relative} differs from its manifest entry"
            return _report("invalid", [_issue(INTEGRITY_INVALID, message)])
        if item["digest"]["value"] != hashlib.sha256(data).hexdigest():
            message = f"the digest of {relative} differs from its manifest entry"
            return _report("invalid", [_issue(INTEGRITY_INVALID, message)])
        carried[relative] = data
    # 7. The evidence bundle: the envelope and observation artifacts.
    bundle: dict[str, Any] = {"schema_version": "ecl_evidence_bundle_v1", "envelopes": []}
    payloads: set[str] = set()
    for item in artifacts:
        member = EVIDENCE_ROLES.get(item["role"])
        data = carried.get(item["path"])
        if member is None or data is None:
            continue
        try:
            envelope = loads_json_strict(data)
        except CanonicalizationError as error:
            message = f"{item['path']} is not strict JSON: {error}"
            code = RESOURCE_LIMIT if error.finding_id == RESOURCE_LIMIT else SCHEMA_INVALID
            return _report("invalid", [_issue(code, message)])
        if not isinstance(envelope, dict):
            message = f"{item['path']} is not a JSON object"
            return _report("invalid", [_issue(SCHEMA_INVALID, message)])
        bundle.setdefault(member, []).append(envelope)
        try:
            payloads.add(hashlib.sha256(decode_payload(envelope)).hexdigest())
        except IntegrityError:
            # The bundle verifier refuses an envelope whose payload does not decode (check 9).
            continue
    # 8. Every payload artifact is the payload of a packaged envelope or observation.
    roles: dict[str, set[str]] = {}
    for item in artifacts:
        if item["path"] in carried:
            roles.setdefault(item["role"], set()).add(item["digest"]["value"])
    stray = sorted(roles.get("payload", set()) - payloads)
    if stray:
        message = f"a payload artifact is no packaged envelope's payload: sha256 {stray[0]}"
        return _report("invalid", [_issue(INTEGRITY_INVALID, message)])
    # 9. The bundle, under the caller's trust policy, history and evaluation time.
    report: BundleReport | None = None
    if bundle["envelopes"]:
        report = verify_bundle(bundle, policy, now=now, **bundle_options)
        if report.verdict == "invalid":
            return report
    # 10. The material IE1-021 requires, every payload, and at least one envelope.
    missing = [f"the archive lacks {relative}, which the manifest names" for relative in absent]
    missing.extend(
        f"no artifact has the required role {role}" for role in sorted(REQUIRED_ROLES - set(roles))
    )
    missing.extend(
        f"the {role} artifact that the manifest references is not carried"
        for role, reference in _references(manifest)
        if reference["digest"]["value"] not in roles.get(role, set())
    )
    missing.extend(
        f"the payload of a packaged envelope is not carried: sha256 {digest}"
        for digest in sorted(payloads - roles.get("payload", set()))
    )
    if report is None:
        missing.append("the package carries no envelope")
        return _report("incomplete", [_issue(CLOSURE_INCOMPLETE, item) for item in missing])
    if missing:
        findings = [_issue(CLOSURE_INCOMPLETE, message) for message in missing]
        return with_scope(
            replace(report, verdict="incomplete", findings=(*findings, *report.findings))
        )
    # 11. The bundle's own closure, then its verdict.
    if report.verdict == "incomplete":
        return report
    if expired and report.verdict == "verified":
        notice = _issue(EXPIRED, f"the package expired at {manifest['expires_at']}")
        return with_scope(
            replace(report, verdict=CURRENT_TRUST_FAILED, findings=(*report.findings, notice))
        )
    return report


def reported_package_identifiers(report: BundleReport) -> list[str]:
    """The identifiers of a package's report in order, each once, the primary first (IE1-022,
    EBMP2-068): the code of the first check of IE1-022 that fails, or the findings of the bundle
    in the order of EBMP2-068; for a current-trust-failed package, after the expired code of a
    package that has expired, the current status of each envelope that is not valid, in the order
    of stage 4 of EBMP2-068; for an incomplete package without findings, the causal-closure code.
    """
    codes = list(dict.fromkeys(item.split(":", 1)[0] for item in report.findings))
    if report.verdict == CURRENT_TRUST_FAILED:
        return codes + [item for item in bundle_identifiers(report) if item not in codes]
    if report.verdict == "incomplete" and not codes:
        return [CLOSURE_INCOMPLETE]
    return codes
