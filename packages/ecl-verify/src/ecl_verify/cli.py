"""Installed command for offline verification of signed ECL evidence bundles and offline packages.

A file that begins with the bytes `PK` is verified as an offline package (OFFLINE-VERIFICATION-1,
IE1-022) of at most 1 GiB, the declared archive limit; any other file is a JSON evidence bundle of
at most 1 MiB (TP1-007). Both are verified under the same caller inputs and reported in the same
form.

An input that cannot be verified at all is a usage error (exit status 2), reported on standard
error in one line: `error: CODE: MESSAGE` when the refusal has a registered code, every refusal of
a declared limit being `ecl.error.resource-limit-exceeded.v1`, and `error: MESSAGE` otherwise.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from .bundle_verification import (
    MAX_REGISTER_BYTES,
    SCOPE_TEXT,
    BundleReport,
    load_register,
    primary_finding,
    report_to_json,
    verify_bundle,
)
from .canonical import CanonicalizationError, canonicalize, loads_json_strict
from .offline import DEFAULT_OFFLINE_RESOURCE_LIMITS
from .package_verification import verify_offline_package
from .trust import MAX_TRUST_POLICY_BYTES, TrustPolicy, TrustPolicyError

MAX_BUNDLE_BYTES = 1024 * 1024
# An offline package is read up to the verifier's declared archive limit (IE1-028).
MAX_PACKAGE_BYTES = DEFAULT_OFFLINE_RESOURCE_LIMITS.max_archive_bytes
# The first bytes of a ZIP archive's local file header; no JSON text begins with them.
PACKAGE_MAGIC = b"PK"
# Exit codes: 0 verified, 1 invalid, 2 usage error, 3 incomplete, 4 current trust failed
# (EBMP2-060).
_EXIT = {"verified": 0, "invalid": 1, "incomplete": 3, "current-trust-failed": 4}


# The registered refusal of a declared limit (TP1-007, IE1-028).
RESOURCE_LIMIT = "ecl.error.resource-limit-exceeded.v1"


class _InputError(ValueError):
    """Input that cannot be verified at all. `code` is the registered code of the refusal when
    there is one, and the command prints it first: every refusal of a declared limit is
    `ecl.error.resource-limit-exceeded.v1`."""

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


def _read_limited(path: Path, *, limit: int, kind: str, label: str) -> bytes:
    try:
        with path.open("rb") as source:
            data = source.read(limit + 1)
    except OSError as error:
        raise _InputError(f"cannot read {kind} file ({type(error).__name__})") from error
    if len(data) > limit:
        raise _InputError(f"{kind} file exceeds the {label} limit", RESOURCE_LIMIT)
    return data


def _is_package(path: Path) -> bool:
    """Whether the evidence file is an offline package: an archive begins with `PK`."""
    try:
        with path.open("rb") as source:
            return source.read(len(PACKAGE_MAGIC)) == PACKAGE_MAGIC
    except OSError as error:
        raise _InputError(f"cannot read bundle file ({type(error).__name__})") from error


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _human(report: BundleReport, *, current_version: str) -> str:
    # EBMP2-076: what the verdict does not establish comes with the verdict, then what it does.
    lines = [f"verdict: {report.verdict}"]
    # EBMP2-060: the primary finding of a verdict other than verified, the failing current status
    # of a trust dependency for current-trust-failed among them.
    primary = primary_finding(report)
    if primary is not None:
        lines.append(f"primary: {primary}")
    reasons = report.scope.reasons
    lines.extend(
        f"not-established: {item}: {SCOPE_TEXT[item]}"
        + (f" (reason: {reasons[item]})" if item in reasons else "")
        for item in report.scope.not_established
    )
    lines.extend(f"established: {item}: {SCOPE_TEXT[item]}" for item in report.scope.established)
    # EBMP2-076: the checks that ran for each established item and the objects they covered.
    lines.extend(
        f"checks {item}: {','.join(report.scope.checks[item]['checks'])} "
        f"objects={','.join(str(index) for index in report.scope.checks[item]['objects']) or '-'}"
        for item in report.scope.established
    )
    lines.append(f"verification-profile: {report.verification_profile}")
    lines.append(f"evaluation-time: {report.evaluation_time or '-'}")
    if report.accepted_current_trust_failure:
        lines.append("accepted: current trust failure, by --accept-current-trust-failure")
    if report.register is not None:
        register = report.register
        lines.append(
            f"decision-basis register: {register['uri']} sha256:{register['digest']['value']}"
        )
    else:
        lines.append(
            "decision-basis register: none; declared classes not checked against a register"
        )
    lines.extend(
        (
            f"envelope {check.index}: kind={check.kind} "
            f"signers={','.join(check.signer_key_ids) or '-'} "
            f"historical={check.historical} current={check.current} "
            f"historical-policy={check.historical_policy_version or '-'} "
            f"current-policy={current_version} "
            f"trusted-time={check.trusted_time or '-'}"
        )
        for check in report.envelope_checks
    )
    # TP1-006: each trust dependency, with the policy versions and the revocation it used.
    lines.extend(
        (
            f"dependency {item.index}: role={item.role} key={item.key_id} "
            f"counter={item.counter_id or '-'} at={item.at or '-'} "
            f"historical-policy={item.historical_policy_version or '-'} "
            f"historical={item.historical} current-policy={item.current_policy_version} "
            f"revoked-effective-at={item.revoked_effective_at or '-'} current={item.current}"
        )
        for item in report.trust_dependencies
    )
    lines.extend(
        f"binding {check.name}: {'pass' if check.passed else check.code or 'fail'}"
        for check in report.binding_checks
    )
    lines.append(f"causal: {report.causal_status}")
    lines.extend(f"unresolved-predecessor: {item}" for item in report.unresolved_predecessor_ids)
    # EBMP2-072: a server answer that arrived after the authorization's window is information.
    lines.append(
        f"completion-after-window: {'true' if report.completion_after_window else 'false'}"
    )
    lines.extend(
        (
            f"effect {effect.action_id}: state={effect.state} level={effect.level} "
            f"authority={effect.authority} reason={effect.reason or '-'}"
        )
        for effect in report.effects
    )
    lines.extend(f"finding: {finding}" for finding in report.findings)
    return "\n".join(lines) + "\n"


def _write_stdout(text: str) -> None:
    """Keep UTF-8 and LF stable when Windows or a locale configures text stdout."""
    binary = getattr(sys.stdout, "buffer", None)
    if binary is None:
        sys.stdout.write(text)
    else:
        sys.stdout.flush()
        binary.write(text.encode("utf-8"))
        binary.flush()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "bundle",
        type=Path,
        metavar="BUNDLE",
        help="a signed evidence bundle (JSON), or an offline package (an ecl.zip.store.v1 archive)",
    )
    parser.add_argument("--trust-policy", required=True, type=Path, metavar="FILE")
    parser.add_argument(
        "--trust-policy-history", action="append", default=[], type=Path, metavar="FILE"
    )
    parser.add_argument("--now", metavar="RFC3339")
    parser.add_argument(
        "--accept-current-trust-failure",
        action="store_true",
        help="report verified, with the acceptance stated, when a signer is not acceptable now",
    )
    parser.add_argument(
        "--require-trusted-time",
        action="store_true",
        help="refuse an envelope without a valid trusted-time countersignature (IE1-035)",
    )
    parser.add_argument(
        "--register",
        type=Path,
        metavar="FILE",
        help="check each decision basis against this Consequential Action Register (DCMP2-053)",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        trust_bytes = _read_limited(
            args.trust_policy,
            limit=MAX_TRUST_POLICY_BYTES,
            kind="trust policy",
            label="256 KiB",
        )
        try:
            policy = TrustPolicy.load(trust_bytes)
        except TrustPolicyError as error:
            raise _InputError("malformed trust policy", error.code) from error
        history: list[TrustPolicy] = []
        for path in args.trust_policy_history:
            older_bytes = _read_limited(
                path,
                limit=MAX_TRUST_POLICY_BYTES,
                kind="trust policy history",
                label="256 KiB",
            )
            try:
                history.append(TrustPolicy.load(older_bytes))
            except TrustPolicyError as error:
                raise _InputError("malformed trust policy history", error.code) from error
        register = None
        if args.register is not None:
            register_bytes = _read_limited(
                args.register, limit=MAX_REGISTER_BYTES, kind="register", label="1 MiB"
            )
            try:
                register = load_register(register_bytes)
            except ValueError as error:
                raise _InputError(
                    f"malformed register: {error}", getattr(error, "code", None)
                ) from error
        now = args.now if args.now is not None else _utc_now()
        if _is_package(args.bundle):
            # An offline package (IE1-022): its bundle is verified under the same inputs.
            try:
                oversized = args.bundle.stat().st_size > MAX_PACKAGE_BYTES
            except OSError as error:
                raise _InputError(
                    f"cannot read offline package file ({type(error).__name__})"
                ) from error
            if oversized:
                raise _InputError("offline package file exceeds the 1 GiB limit", RESOURCE_LIMIT)
            package_bytes = _read_limited(
                args.bundle, limit=MAX_PACKAGE_BYTES, kind="offline package", label="1 GiB"
            )
            try:
                report = verify_offline_package(
                    package_bytes,
                    policy,
                    now=now,
                    history=history,
                    accept_current_trust_failure=args.accept_current_trust_failure,
                    require_trusted_time=args.require_trusted_time,
                    register=register,
                )
            except ValueError as error:
                raise _InputError(f"invalid --now: {error}") from error
        else:
            bundle_bytes = _read_limited(
                args.bundle, limit=MAX_BUNDLE_BYTES, kind="bundle", label="1 MiB"
            )
            try:
                bundle = loads_json_strict(bundle_bytes, max_bytes=MAX_BUNDLE_BYTES)
            except CanonicalizationError as error:
                raise _InputError("malformed bundle JSON", error.finding_id) from error
            try:
                report = verify_bundle(
                    bundle,
                    policy,
                    now=now,
                    history=history,
                    accept_current_trust_failure=args.accept_current_trust_failure,
                    require_trusted_time=args.require_trusted_time,
                    register=register,
                )
            except ValueError as error:
                raise _InputError(f"invalid --now: {error}") from error
    except _InputError as error:
        prefix = f"{error.code}: " if error.code is not None else ""
        print(f"error: {prefix}{error}", file=sys.stderr)
        return 2

    if args.json:
        json_value = report_to_json(report)
        _write_stdout(canonicalize(json_value).decode("utf-8") + "\n")
    else:
        _write_stdout(_human(report, current_version=policy.version))
    return _EXIT[report.verdict]


if __name__ == "__main__":
    raise SystemExit(main())
