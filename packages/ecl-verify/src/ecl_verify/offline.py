"""Offline verification checks and read-only metadata for offline."""

from __future__ import annotations

import hashlib
import io
import re
import stat
import string
import struct
import unicodedata
import warnings
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import IO, Any

from .canonical import CanonicalizationError, canonicalize, loads_json_strict
from .schema import parse_rfc3339_utc

SCHEMA_INVALID = "ecl.error.schema-invalid.v1"

SEMANTIC_INVALID = "ecl.error.semantic-invalid.v1"

INTEGRITY_INVALID = "ecl.error.integrity-invalid.v1"

CLOSURE_INCOMPLETE = "ecl.error.causal-closure-incomplete.v1"

EXPIRED = "ecl.error.expired.v1"

RESOURCE_LIMIT = "ecl.error.resource-limit-exceeded.v1"

CONFIGURATION_INVALID = "ecl.error.configuration-invalid.v1"

MANIFEST_NAME = "manifest.json"

MANIFEST_SCHEMA = "https://externalcontrollayer.ai/ns/schema/offline-verification-package/1"

REQUIRED_ROLES = frozenset(
    {
        "payload",
        "envelope",
        "trust_policy",
        "verification_key",
        "revocation_snapshot",
        "registry_snapshot",
        "time_evidence",
    }
)

_DEVICE_NAME = re.compile(
    r"(?:con|prn|aux|nul|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3]|conin\$|conout\$)",
    re.IGNORECASE,
)

PORTABLE_NAME_CHARACTERS = frozenset(string.ascii_letters + string.digits + "._-")

_PORTABLE_DEVICE_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {stem + digit for stem in ("com", "lpt") for digit in string.digits}
)

_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)

_OVERLAP_WARNING = (
    "ignore",
    re.compile("Overlapped entries", re.IGNORECASE),
    UserWarning,
    re.compile(re.escape(__name__) + r"\Z"),
    0,
)

def _silence_overlap_warning() -> None:
    if _OVERLAP_WARNING not in warnings.filters:
        warnings.filterwarnings(
            "ignore",
            message="Overlapped entries",
            category=UserWarning,
            module=re.escape(__name__) + r"\Z",
        )

_silence_overlap_warning()

class OfflinePackageError(ValueError):
    """Raised when an offline package is malformed, unsafe, stale, or incomplete."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code

@dataclass(frozen=True)
class OfflinePackageResult:
    package_id: str
    artifact_count: int
    verified_paths: tuple[str, ...]
    roles: tuple[str, ...]
    manifest_sha256: str

@dataclass(frozen=True)
class OfflineResourceLimits:
    """Explicit verifier budgets for untrusted offline package inputs."""

    max_archive_bytes: int = 1 * 1024 * 1024 * 1024
    max_member_count: int = 100_000
    max_entry_uncompressed_bytes: int = 512 * 1024 * 1024
    max_total_uncompressed_bytes: int = 4 * 1024 * 1024 * 1024
    max_compression_ratio: int = 1_000
    max_path_bytes: int = 4_096

DEFAULT_OFFLINE_RESOURCE_LIMITS = OfflineResourceLimits()

def _validate_limits(limits: OfflineResourceLimits) -> None:
    """The verifier's declared limits (IE1-028): each an `int` of at least 1, checked by type, so
    that a `bool`, a `float` (`NaN` and the infinities among them) or another number is refused
    with the configuration-error code before any input is read, never compared."""
    if not isinstance(limits, OfflineResourceLimits):
        raise OfflinePackageError("offline resource profile is invalid", CONFIGURATION_INVALID)
    for name in (
        "max_archive_bytes",
        "max_member_count",
        "max_entry_uncompressed_bytes",
        "max_total_uncompressed_bytes",
        "max_compression_ratio",
        "max_path_bytes",
    ):
        value = getattr(limits, name)
        if type(value) is not int or value < 1:
            raise OfflinePackageError(
                f"offline resource limit must be an integer of at least 1: {name}",
                CONFIGURATION_INVALID,
            )

def _time(value: str) -> datetime:
    """An ECL RFC 3339 UTC instant, by the shared parser (one to nine fractional digits)."""
    try:
        return parse_rfc3339_utc(value)
    except ValueError as exc:
        raise OfflinePackageError(f"invalid UTC timestamp: {value!r}", "ecl.error.semantic-invalid.v1") from exc

def safe_relative_path(
    value: str,
    *,
    limits: OfflineResourceLimits = DEFAULT_OFFLINE_RESOURCE_LIMITS,
) -> PurePosixPath:
    """`value` as a relative POSIX path that names the same file on every platform.

    Refused (IE1-030; OFFLINE-VERIFICATION-1): absolute, home-relative and drive paths, a colon
    anywhere (a drive-relative path or an alternate data stream on Windows), parent and current
    directory and empty components, backslashes, control and format characters, a name that is
    not NFC, a component that ends in a dot or a space (Windows drops them, so two names alias one
    file), and Windows device names such as CON or nul.txt.
    """
    _validate_limits(limits)
    if isinstance(value, str) and len(value.encode("utf-8")) > limits.max_path_bytes:
        raise OfflinePackageError(
            "package path length exceeds the verifier budget",
            RESOURCE_LIMIT,
        )
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or value.startswith("/")
        or value.startswith("~")
        or value != unicodedata.normalize("NFC", value)
        or any(
            ord(character) < 32
            or ord(character) == 127
            or unicodedata.category(character).startswith("C")
            for character in value
        )
    ):
        raise OfflinePackageError(
            f"unsafe package path: {value!r}",
            "ecl.error.semantic-invalid.v1",
        )
    raw_parts = value.split("/")
    if (
        any(part in {"", ".", ".."} for part in raw_parts)
        or ":" in value
        or any(part.endswith((".", " ")) for part in raw_parts)
        or any(_DEVICE_NAME.fullmatch(part.split(".", 1)[0].rstrip(" ")) for part in raw_parts)
    ):
        raise OfflinePackageError(
            f"unsafe package path: {value!r}",
            "ecl.error.semantic-invalid.v1",
        )
    path = PurePosixPath(value)
    if path.as_posix() != value:
        raise OfflinePackageError(
            f"unsafe package path: {value!r}",
            "ecl.error.semantic-invalid.v1",
        )
    return path

def _alias(path: str) -> str:
    """The form under which two safe paths name one file on a case-insensitive file system."""
    return unicodedata.normalize("NFC", path).casefold()

def _portable_component(part: str) -> bool:
    return (
        bool(part)
        and part not in (".", "..")
        and not part.endswith(".")
        and set(part) <= PORTABLE_NAME_CHARACTERS
        and part.split(".", 1)[0].translate(_ASCII_LOWER) not in _PORTABLE_DEVICE_NAMES
    )

def zip_entry_name(
    value: str,
    *,
    limits: OfflineResourceLimits = DEFAULT_OFFLINE_RESOURCE_LIMITS,
) -> str:
    """`value` as an entry name of the `ecl.zip.store.v1` profile (IE1-030, IE1-031).

    An entry name is one or more components separated by "/". Each component is drawn from the
    POSIX portable filename characters (A to Z, a to z, 0 to 9, ".", "_" and "-"), is not "." or
    "..", does not end in ".", and is not a Windows device name (CON, PRN, AUX, NUL, COM0 to COM9,
    LPT0 to LPT9) in any letter case before its first ".". Two entry names are aliases when they
    are equal after ASCII case folding (_zip_alias). Every name the rule accepts, safe_relative_path
    accepts too, and the rule needs no Unicode table. A name longer than `limits.max_path_bytes`
    is refused first, as over the verifier's budget (IE1-028).
    """
    _validate_limits(limits)
    if isinstance(value, str) and len(value.encode("utf-8", "surrogatepass")) > limits.max_path_bytes:
        raise OfflinePackageError(
            "entry name exceeds the verifier budget for path bytes",
            RESOURCE_LIMIT,
        )
    if not isinstance(value, str) or not all(
        _portable_component(part) for part in value.split("/")
    ):
        raise OfflinePackageError(
            f"unsafe package path: {value!r} is not an ecl.zip.store.v1 entry name",
            "ecl.error.semantic-invalid.v1",
        )
    return value

def _zip_alias(name: str) -> str:
    """The form under which two ecl.zip.store.v1 entry names are aliases: ASCII lower case."""
    return name.translate(_ASCII_LOWER)

def _file_and_directory(
    paths: list[str], alias: Callable[[str], str] = _alias
) -> str | None:
    """A path that is also the parent directory of another path, or None.

    No file system can hold both, so such a package has no single meaning once materialized.
    """
    aliases = {alias(path) for path in paths}
    for path in paths:
        parts = alias(path).split("/")
        for depth in range(1, len(parts)):
            parent = "/".join(parts[:depth])
            if parent in aliases:
                return parent
    return None

def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def _malformed(member: str) -> OfflinePackageError:
    return OfflinePackageError(
        f"offline package manifest is malformed: {member}", SCHEMA_INVALID
    )

def _require_digest(value: Any, member: str) -> None:
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("algorithm"), str)
        or not isinstance(value.get("value"), str)
    ):
        raise _malformed(member)

def _require_reference(value: Any, member: str) -> None:
    if not isinstance(value, dict):
        raise _malformed(member)
    _require_digest(value.get("digest"), f"{member}.digest")

def _checked_artifacts(
    manifest: Any, limits: OfflineResourceLimits, *, archive: bool = False
) -> list[dict[str, Any]]:
    """The manifest's artifacts once the manifest has the shape and the paths the verifier
    needs; before any time, file or archive is read.

    The artifact paths are entry names of `ecl.zip.store.v1` (zip_entry_name), no two of them
    aliases and none a parent directory of another, after ASCII case folding, for a package held
    as a directory as for an archive (IE1-030). With `archive`, the package is an archive, so the
    paths must also be names that one archive could hold together with `manifest.json`: none is an
    alias of `manifest.json` or of one of its parent directories.
    """
    if not isinstance(manifest, dict):
        raise _malformed("the manifest is not a JSON object")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise OfflinePackageError(
            "offline package artifacts are not a list",
            "ecl.error.semantic-invalid.v1",
        )
    if len(artifacts) > limits.max_member_count:
        raise OfflinePackageError(
            "offline package artifact count exceeds the verifier budget",
            RESOURCE_LIMIT,
        )
    for name in ("package_id", "created_at", "expires_at"):
        if not isinstance(manifest.get(name), str):
            raise _malformed(name)
    for name in ("trust_policy", "revocation_snapshot"):
        _require_reference(manifest.get(name), name)
    for name in ("registry_snapshots", "time_evidence"):
        items = manifest.get(name)
        if not isinstance(items, list):
            raise _malformed(name)
        for item in items:
            _require_reference(item, name)
    for item in artifacts:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("path"), str)
            or not isinstance(item.get("role"), str)
            or "size_bytes" not in item
        ):
            raise _malformed("artifacts")
        _require_digest(item.get("digest"), "artifacts.digest")
    alias = _zip_alias
    seen: set[str] = set()
    aliases: set[str] = set()
    for item in artifacts:
        relative = zip_entry_name(item["path"], limits=limits)
        if archive and alias(relative) == MANIFEST_NAME:
            raise OfflinePackageError(
                f"the manifest names {MANIFEST_NAME}, or an alias of it, as an artifact",
                SEMANTIC_INVALID,
            )
        if relative in seen or alias(relative) in aliases:
            raise OfflinePackageError(
                f"duplicate package path: {relative}",
                "ecl.error.semantic-invalid.v1",
            )
        seen.add(relative)
        aliases.add(alias(relative))
    conflict = _file_and_directory(sorted(seen | ({MANIFEST_NAME} if archive else set())), alias)
    if conflict is not None:
        raise OfflinePackageError(
            f"package path is both a file and a directory: {conflict}",
            "ecl.error.semantic-invalid.v1",
        )
    from .resources import validator_for

    if not validator_for(MANIFEST_SCHEMA).is_valid(manifest):
        raise OfflinePackageError(
            f"offline package manifest does not satisfy {MANIFEST_SCHEMA}", SCHEMA_INVALID
        )
    return artifacts

def _check_validity(manifest: dict[str, Any], evaluated_at: str) -> None:
    if _time(manifest["expires_at"]) <= _time(manifest["created_at"]):
        raise OfflinePackageError(
            "offline package expiry is not later than creation",
            "ecl.error.expired.v1",
        )
    if _time(evaluated_at) >= _time(manifest["expires_at"]):
        raise OfflinePackageError(
            "offline package is expired at the evaluation time",
            "ecl.error.expired.v1",
        )

def _reference_digest(reference: dict[str, Any]) -> str:
    digest = reference.get("digest") or {}
    if digest.get("algorithm") != "ecl.digest.sha-256.v1":
        raise OfflinePackageError(
            "offline reference lacks the universal SHA-256 digest",
            "ecl.error.integrity-invalid.v1",
        )
    return str(digest.get("value") or "")

@dataclass(frozen=True)
class _Source:
    """An artifact's bytes as the package holds them: its size, and how to stream it."""

    size: int
    open: Callable[[], IO[bytes]]

def _directory_source(root: Path, relative: str) -> _Source:
    """The artifact `relative` under `root`; a file the system cannot look up is missing."""
    try:
        return _directory_artifact(root, relative)
    except OSError as exc:
        # Such as a name longer than the file system allows (IE1-029: a stable classification).
        raise OfflinePackageError(
            f"package artifact cannot be read: {relative}", CLOSURE_INCOMPLETE
        ) from exc

def _directory_artifact(root: Path, relative: str) -> _Source:
    path = root.joinpath(*PurePosixPath(relative).parts)
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            raise OfflinePackageError(
                f"package artifact traverses a symlink: {relative}",
                "ecl.error.semantic-invalid.v1",
            )
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise OfflinePackageError(
            f"package artifact is missing: {relative}",
            "ecl.error.causal-closure-incomplete.v1",
        ) from exc
    if root not in resolved.parents or not resolved.is_file():
        raise OfflinePackageError(
            f"package artifact escapes boundary or is not a regular file: {relative}",
            "ecl.error.semantic-invalid.v1",
        )
    return _Source(resolved.stat().st_size, lambda: resolved.open("rb"))

def _archive_source(archive: zipfile.ZipFile, relative: str) -> _Source:
    try:
        info = archive.getinfo(relative)
    except KeyError as exc:
        raise OfflinePackageError(
            f"package artifact is missing: {relative}",
            "ecl.error.causal-closure-incomplete.v1",
        ) from exc
    return _Source(info.file_size, lambda: archive.open(info, "r"))

def _verify_artifacts(
    manifest: dict[str, Any],
    artifacts: list[dict[str, Any]],
    source: Callable[[str], _Source],
    limits: OfflineResourceLimits,
) -> OfflinePackageResult:
    roles: set[str] = set()
    digests_by_role: dict[str, set[str]] = {}
    verified: list[str] = []
    total_bytes = 0
    for item in artifacts:
        relative = item["path"]
        held = source(relative)
        declared_size = item["size_bytes"]
        if (
            not isinstance(declared_size, int)
            or isinstance(declared_size, bool)
            or declared_size < 0
            or declared_size > limits.max_entry_uncompressed_bytes
        ):
            raise OfflinePackageError(
                f"artifact size exceeds the verifier budget: {relative}",
                RESOURCE_LIMIT,
            )
        actual_size = held.size
        total_bytes += actual_size
        if total_bytes > limits.max_total_uncompressed_bytes:
            raise OfflinePackageError(
                "offline package size exceeds the verifier budget",
                RESOURCE_LIMIT,
            )
        if actual_size != declared_size:
            raise OfflinePackageError(
                f"artifact size mismatch: {relative}",
                "ecl.error.integrity-invalid.v1",
            )
        digest_value = hashlib.sha256()
        observed_size = 0
        try:
            with held.open() as stream:
                while chunk := stream.read(1024 * 1024):
                    observed_size += len(chunk)
                    if observed_size > limits.max_entry_uncompressed_bytes:
                        raise OfflinePackageError(
                            f"artifact grew beyond the verifier budget: {relative}",
                            RESOURCE_LIMIT,
                        )
                    digest_value.update(chunk)
        except OSError as exc:
            raise OfflinePackageError(
                f"package artifact cannot be read: {relative}", CLOSURE_INCOMPLETE
            ) from exc
        if observed_size != actual_size:
            raise OfflinePackageError(
                f"artifact changed during verification: {relative}",
                "ecl.error.integrity-invalid.v1",
            )
        digest = item["digest"]
        if (
            digest.get("algorithm") != "ecl.digest.sha-256.v1"
            or digest.get("value") != digest_value.hexdigest()
        ):
            raise OfflinePackageError(
                f"artifact digest mismatch: {relative}",
                "ecl.error.integrity-invalid.v1",
            )
        role = item["role"]
        roles.add(role)
        digests_by_role.setdefault(role, set()).add(digest["value"])
        verified.append(relative)

    missing_roles = sorted(REQUIRED_ROLES - roles)
    if missing_roles:
        raise OfflinePackageError(
            f"offline package lacks required roles: {missing_roles}",
            "ecl.error.causal-closure-incomplete.v1",
        )
    bindings = [
        ("trust_policy", [_reference_digest(manifest["trust_policy"])]),
        (
            "revocation_snapshot",
            [_reference_digest(manifest["revocation_snapshot"])],
        ),
        (
            "registry_snapshot",
            [_reference_digest(item) for item in manifest["registry_snapshots"]],
        ),
        (
            "time_evidence",
            [_reference_digest(item) for item in manifest["time_evidence"]],
        ),
    ]
    for role, expected in bindings:
        missing = sorted(set(expected) - digests_by_role.get(role, set()))
        if missing:
            raise OfflinePackageError(
                f"manifest {role} references are not carried as artifacts: {missing}",
                "ecl.error.causal-closure-incomplete.v1",
            )
    manifest_bytes = canonicalize(manifest)
    return OfflinePackageResult(
        package_id=manifest["package_id"],
        artifact_count=len(verified),
        verified_paths=tuple(sorted(verified)),
        roles=tuple(sorted(roles)),
        manifest_sha256=_sha256(manifest_bytes),
    )

def verify_directory_package(
    root: Path,
    manifest: dict[str, Any],
    *,
    evaluated_at: str,
    limits: OfflineResourceLimits = DEFAULT_OFFLINE_RESOURCE_LIMITS,
) -> OfflinePackageResult:
    """Check the package `manifest` describes, held in the directory `root`.

    The manifest defines the package: a file under `root` that it does not name is not part of
    the package and is not verified, so a consumer reads only the paths the result lists.

    This is not the verification of IE1-022 and gives no verdict: it checks the manifest, its
    entry names (IE1-030) and the artifacts' sizes, digests and required roles, but not the
    package's evidence bundle. A package whose `expires_at` is not later than `evaluated_at` is
    refused with the expired code, as `verify_zip_package` refuses it. IE1-022 gives such a
    package `current-trust-failed` only where its bundle is `verified`, and this check does not
    verify the bundle, so it cannot give that verdict.
    """
    _validate_limits(limits)
    artifacts = _checked_artifacts(manifest, limits)
    _check_validity(manifest, evaluated_at)
    root = root.resolve()
    return _verify_artifacts(
        manifest, artifacts, lambda relative: _directory_source(root, relative), limits
    )

def verify_zip_package(
    value: bytes,
    *,
    evaluated_at: str,
    limits: OfflineResourceLimits = DEFAULT_OFFLINE_RESOURCE_LIMITS,
) -> OfflinePackageResult:
    """Verify an `ecl.zip.store.v1` package: `manifest.json` and exactly the artifacts it names.

    The archive must be in its exact profile encoding (verify_zip_members). A member that the
    manifest does not name is refused, and so is an artifact the archive lacks.
    """
    names = verify_zip_members(value, limits=limits)
    if MANIFEST_NAME not in names:
        raise OfflinePackageError(
            f"offline package archive has no {MANIFEST_NAME}", CLOSURE_INCOMPLETE
        )
    try:
        with zipfile.ZipFile(io.BytesIO(value), "r") as archive:
            try:
                manifest = loads_json_strict(archive.read(MANIFEST_NAME))
            except CanonicalizationError as exc:
                raise OfflinePackageError(
                    f"{MANIFEST_NAME} is not strict JSON", SCHEMA_INVALID
                ) from exc
            artifacts = _checked_artifacts(manifest, limits, archive=True)
            listed = {item["path"] for item in artifacts}
            if MANIFEST_NAME in listed:
                raise OfflinePackageError(
                    f"the manifest names {MANIFEST_NAME} as an artifact", SEMANTIC_INVALID
                )
            unlisted = sorted(set(names) - listed - {MANIFEST_NAME})
            if unlisted:
                raise OfflinePackageError(
                    f"package member is not named by the manifest: {unlisted[0]}",
                    SEMANTIC_INVALID,
                )
            _check_validity(manifest, evaluated_at)
            return _verify_artifacts(
                manifest,
                artifacts,
                lambda relative: _archive_source(archive, relative),
                limits,
            )
    except OfflinePackageError:
        raise
    except (
        EOFError,
        OSError,
        RuntimeError,
        ValueError,
        NotImplementedError,
        struct.error,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ) as exc:
        raise OfflinePackageError(
            f"malformed archive: {exc}",
            "ecl.error.semantic-invalid.v1",
        ) from exc

_END_SIGNATURE = 0x06054B50

_CENTRAL_SIGNATURE = 0x02014B50

_ZIP64_LOCATOR_SIGNATURE = 0x07064B50

_END_SIZE = 22

_CENTRAL_SIZE = 46

_MAX_COMMENT = 0xFFFF

_MAX_EXTRACT_VERSION = 63

_SATURATED = 0xFFFFFFFF

def _departure(message: str) -> OfflinePackageError:
    """A central directory that cannot be read as the profile's: a malformed archive, as the
    archive library's own refusals are reported."""
    return OfflinePackageError(f"malformed archive: {message}", SEMANTIC_INVALID)

_CENTRAL_HEADER = struct.Struct("<IHBxH10xIIHHH8xI")

def _check_extra_fields(extra: bytes, sizes: list[int]) -> None:
    """The structure of an entry's extra fields, and the eight-byte value that a ZIP64 field gives,
    in order, for each of the file size, compressed size and local header offset that is
    saturated."""
    field = 0
    while len(extra) - field >= 4:
        kind = int.from_bytes(extra[field : field + 2], "little")
        field_length = int.from_bytes(extra[field + 2 : field + 4], "little")
        if field_length + 4 > len(extra) - field:
            raise _departure("a corrupt extra field")
        if kind == 0x0001:
            data = extra[field + 4 : field + 4 + field_length]
            for index, size_value in enumerate(sizes):
                if size_value == _SATURATED:
                    if len(data) < 8:
                        raise _departure("a corrupt ZIP64 extra field")
                    sizes[index] = int.from_bytes(data[:8], "little")
                    data = data[8:]
        field += field_length + 4

def _central_directory_count(value: bytes) -> int:
    """The number of entries in the archive's central directory, read as a ZIP reader reads them,
    before the archive library reads them (IE1-029).

    The archive library builds an entry object for every central directory entry before the
    member limit can be compared, so an archive within the byte limit could make it hold millions.
    This count reads the same structure without keeping anything: the end record (the last 22
    bytes, or the last end signature where a comment could lie), a ZIP64 locator before it, the
    archive comment, and each entry's fixed header, signature, name flagged as UTF-8, extraction
    version and extra fields. A structure that cannot be read, a ZIP64 record and a comment depart
    from the profile, as the TypeScript and Go readers find (`directory` in their `zip` modules),
    and are refused here with the semantic-invalid code.
    """
    length = len(value)

    def u16(offset: int) -> int:
        return int.from_bytes(value[offset : offset + 2], "little")

    def u32(offset: int) -> int:
        return int.from_bytes(value[offset : offset + 4], "little")

    def signature_at(offset: int, signature: int) -> bool:
        return 0 <= offset and offset + 4 <= length and u32(offset) == signature

    if length < _END_SIZE:
        raise _departure("no end of central directory record")
    comment = b""
    if signature_at(length - _END_SIZE, _END_SIGNATURE) and u16(length - 2) == 0:
        position = length - _END_SIZE
    else:
        position = value.rfind(b"PK\x05\x06", max(length - _MAX_COMMENT - _END_SIZE, 0))
        if position < 0 or position + _END_SIZE > length:
            raise _departure("no end of central directory record")
        start = position + _END_SIZE
        comment = value[start : min(length, start + u16(position + 20))]
    if signature_at(position - 20, _ZIP64_LOCATOR_SIGNATURE):
        raise _departure("a ZIP64 record")
    size = u32(position + 12)
    # The directory ends where the end record begins, whatever offset the record states.
    start = position - size
    if start < 0:
        raise _departure("the central directory has a negative offset")
    if comment:
        raise _departure("an archive comment")
    stop = start + size
    at, total, count = start, 0, 0
    header = _CENTRAL_HEADER.unpack_from
    while total < size:
        if at + _CENTRAL_SIZE > stop:
            raise _departure("a truncated or unreadable central directory entry")
        (signature, _made_by, extract_version, flags, compressed_size, file_size, name_length,
         extra_length, comment_length, header_offset) = header(value, at)
        if signature != _CENTRAL_SIGNATURE:
            raise _departure("a truncated or unreadable central directory entry")
        name_start = at + _CENTRAL_SIZE
        name_end = min(stop, name_start + name_length)
        if flags & 0x800:
            try:
                value[name_start:name_end].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise _departure("a name flagged as UTF-8 that is not UTF-8") from exc
        extra_end = min(stop, name_end + extra_length)
        if extract_version > _MAX_EXTRACT_VERSION:
            raise _departure("an unsupported extraction version")
        if extra_end > name_end:
            _check_extra_fields(value[name_end:extra_end], [file_size, compressed_size, header_offset])
        count += 1
        total += _CENTRAL_SIZE + name_length + extra_length + comment_length
        at = min(stop, extra_end + comment_length)
    return count

_ZIP_VERSION = 20

_ZIP_MADE_BY = (3 << 8) | _ZIP_VERSION

_ZIP_DOS_DATE = (1 << 5) | 1

_ZIP_EXTERNAL = (stat.S_IFREG | 0o644) << 16

def _profile_layout_problem(value: bytes, members: list[tuple[str, int, int]]) -> str | None:
    """Where `value` departs from the exact ecl.zip.store.v1 encoding of `members`, or None.

    `members` are (name, CRC-32, size) in archive order. The profile fixes every byte of an
    archive but the member data (IE1-031), so its encoding is exact: each local header at the
    offset where the previous member's data ends, then the central directory, then an end record
    that ends the input. Prepended or trailing data, gaps, local extra fields and any header
    field outside the profile depart from it.
    """
    offset = 0
    directory = bytearray()
    for name, crc, size in members:
        # Entry names are ASCII (zip_entry_name), so no member sets the language-encoding flag.
        encoded = name.encode("ascii")
        flags = 0
        local = struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            _ZIP_VERSION,
            flags,
            0,
            0,
            _ZIP_DOS_DATE,
            crc,
            size,
            size,
            len(encoded),
            0,
        ) + encoded
        if value[offset : offset + len(local)] != local:
            return f"local header of {name!r} is not at its profile offset or not in profile form"
        directory += struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            _ZIP_MADE_BY,
            _ZIP_VERSION,
            flags,
            0,
            0,
            _ZIP_DOS_DATE,
            crc,
            size,
            size,
            len(encoded),
            0,
            0,
            0,
            0,
            _ZIP_EXTERNAL,
            offset,
        ) + encoded
        offset += len(local) + size
    end = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        len(members),
        len(members),
        len(directory),
        offset,
        0,
    )
    if value[offset:] != bytes(directory) + end:
        return "the central directory and end record are not the profile encoding, or bytes follow"
    return None

def verify_zip_members(
    value: bytes,
    *,
    limits: OfflineResourceLimits = DEFAULT_OFFLINE_RESOURCE_LIMITS,
) -> tuple[str, ...]:
    """The member names of an archive in exact `ecl.zip.store.v1` form; refuse anything else.

    Refused with OfflinePackageError (IE1-028 to IE1-031): budgets exceeded, a name that is not an
    entry name of the profile (zip_entry_name, checked as stored, before the archive library
    shortens a name at a NUL byte), an aliasing (ASCII case), duplicate or out-of-order name, a
    non-regular, encrypted, compressed or described member, metadata, comments or extra fields
    outside the profile, a language-encoding flag, a CRC or size that does not hold, any byte
    outside the profile encoding, and every malformed archive.
    """

    _validate_limits(limits)
    if not isinstance(value, bytes):
        raise OfflinePackageError(
            "archive input must be bytes",
            "ecl.error.schema-invalid.v1",
        )
    if len(value) > limits.max_archive_bytes:
        raise OfflinePackageError(
            "archive size exceeds the verifier budget",
            RESOURCE_LIMIT,
        )
    # The member limit, before the archive library builds an entry object for every member of the
    # central directory (IE1-029); the count refuses a structure it cannot read as the profile's.
    if _central_directory_count(value) > limits.max_member_count:
        raise OfflinePackageError(
            "archive member count exceeds the verifier budget",
            RESOURCE_LIMIT,
        )
    _silence_overlap_warning()
    names: list[str] = []
    seen: set[str] = set()
    layout: list[tuple[str, int, int]] = []
    try:
        with zipfile.ZipFile(io.BytesIO(value), "r") as archive:
            if archive.comment:
                raise OfflinePackageError(
                    "archive comment is not deterministic",
                    "ecl.error.semantic-invalid.v1",
                )
            members = archive.infolist()
            if len(members) > limits.max_member_count:
                raise OfflinePackageError(
                    "archive member count exceeds the verifier budget",
                    RESOURCE_LIMIT,
                )
            total_uncompressed = 0
            for info in members:
                if info.flag_bits & 0x1:
                    raise OfflinePackageError(
                        "encrypted archive members are unsupported",
                        "ecl.error.semantic-invalid.v1",
                    )
                if info.file_size > limits.max_entry_uncompressed_bytes:
                    raise OfflinePackageError(
                        f"archive member exceeds the verifier budget: {info.filename}",
                        RESOURCE_LIMIT,
                    )
                total_uncompressed += info.file_size
                if total_uncompressed > limits.max_total_uncompressed_bytes:
                    raise OfflinePackageError(
                        "archive expansion exceeds the verifier budget",
                        RESOURCE_LIMIT,
                    )
                if (
                    info.file_size
                    and info.file_size
                    > max(info.compress_size, 1) * limits.max_compression_ratio
                ):
                    raise OfflinePackageError(
                        f"archive member compression ratio exceeds the verifier budget: "
                        f"{info.filename}",
                        RESOURCE_LIMIT,
                    )

            prior_key: bytes | None = None
            for info in members:
                if info.orig_filename != info.filename:
                    raise OfflinePackageError(
                        f"unsafe package path: {info.orig_filename!r}",
                        "ecl.error.semantic-invalid.v1",
                    )
                name = zip_entry_name(info.orig_filename, limits=limits)
                if _zip_alias(name) in seen:
                    raise OfflinePackageError(
                        f"duplicate archive member: {name}",
                        "ecl.error.semantic-invalid.v1",
                    )
                seen.add(_zip_alias(name))
                mode = (info.external_attr >> 16) & 0xFFFF
                if (
                    stat.S_IFMT(mode) != stat.S_IFREG
                    or stat.S_IMODE(mode) != 0o644
                    or info.create_system != 3
                    or info.create_version != 20
                    or info.extract_version != 20
                    or info.volume != 0
                    or info.internal_attr != 0
                ):
                    raise OfflinePackageError(
                        f"archive member metadata is not deterministic: {name}",
                        "ecl.error.semantic-invalid.v1",
                    )
                if (
                    info.date_time != (1980, 1, 1, 0, 0, 0)
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.flag_bits != 0
                    or info.extra
                    or info.comment
                ):
                    raise OfflinePackageError(
                        f"archive member encoding is not deterministic: {name}",
                        "ecl.error.semantic-invalid.v1",
                    )
                key = name.encode("utf-8")
                if prior_key is not None and key < prior_key:
                    raise OfflinePackageError(
                        "archive entries are not in deterministic path order",
                        "ecl.error.semantic-invalid.v1",
                    )
                prior_key = key
                observed = 0
                # The archive library's warning about entries that overlap is silenced by the
                # module's filter (`_silence_overlap_warning`); the layout comparison below
                # refuses such an archive.
                with archive.open(info, "r") as stream:
                    while chunk := stream.read(1024 * 1024):
                        observed += len(chunk)
                        if observed > limits.max_entry_uncompressed_bytes:
                            raise OfflinePackageError(
                                f"archive member expanded beyond the verifier budget: {name}",
                                RESOURCE_LIMIT,
                            )
                if observed != info.file_size:
                    raise OfflinePackageError(
                        f"archive member size is inconsistent: {name}",
                        "ecl.error.integrity-invalid.v1",
                    )
                names.append(name)
                layout.append((name, info.CRC, info.file_size))
        conflict = _file_and_directory(names, _zip_alias)
        if conflict is not None:
            raise OfflinePackageError(
                f"archive member is both a file and a directory: {conflict}",
                "ecl.error.semantic-invalid.v1",
            )
        problem = _profile_layout_problem(value, layout)
        if problem is not None:
            raise OfflinePackageError(
                f"archive is not in its ecl.zip.store.v1 encoding: {problem}",
                "ecl.error.semantic-invalid.v1",
            )
    except OfflinePackageError:
        raise
    except (
        EOFError,
        OSError,
        RuntimeError,
        ValueError,
        NotImplementedError,
        struct.error,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ) as exc:
        raise OfflinePackageError(
            f"malformed archive: {exc}",
            "ecl.error.semantic-invalid.v1",
        ) from exc
    return tuple(names)
