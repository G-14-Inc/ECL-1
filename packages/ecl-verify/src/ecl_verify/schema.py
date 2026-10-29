"""Deterministic JSON Schema format checks with no optional dependencies."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from ipaddress import ip_address
from urllib.parse import urlsplit

from jsonschema import FormatChecker

_URI_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")
_URI_CHARACTERS = re.compile(
    r"^[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$"
)
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_RFC3339_UTC = re.compile(
    r"^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])"
    r"T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(\.[0-9]{1,9})?Z$"
)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _utc_parts(value: object) -> tuple[datetime, str]:
    if not isinstance(value, str) or not (match := _RFC3339_UTC.fullmatch(value)):
        raise ValueError("timestamp must be an ECL RFC 3339 UTC instant")
    # Python 3.10 rejects nine fractional digits; validate the calendar without the fraction.
    base = datetime.fromisoformat(value[:19] + "+00:00")
    fraction = match.group(4)
    return base, fraction[1:] if fraction else ""


def parse_rfc3339_utc(value: object) -> datetime:
    """Parse an ECL instant, flooring nanoseconds to datetime's microseconds."""
    base, fraction = _utc_parts(value)
    return base.replace(microsecond=int(fraction[:6].ljust(6, "0"))) if fraction else base


def rfc3339_utc_nanoseconds(value: object) -> int:
    """Return an ECL instant as exact nanoseconds since the UTC Unix epoch."""
    base, fraction = _utc_parts(value)
    delta = base - _EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + int(
        fraction.ljust(9, "0") or "0"
    )


def _valid_rfc3339_utc(value: object) -> bool:
    try:
        _utc_parts(value)
    except ValueError:
        return False
    return True


def _valid_bracketed_authority(netloc: str) -> bool:
    """Apply IE1-038 directly; urlsplit's host checks vary by Python patch level."""
    host_and_port = netloc.rpartition("@")[2]
    before, opening, bracketed = host_and_port.partition("[")
    if not opening or before:
        return False
    hostname, closing, port = bracketed.partition("]")
    if not closing or (port and not port.startswith(":")):
        return False
    if hostname.startswith("v"):
        return re.fullmatch(r"v[a-fA-F0-9]+\..+", hostname) is not None
    try:
        return ip_address(hostname).version == 6
    except ValueError:
        return False


def _valid_absolute_uri(value: object) -> bool:
    if not isinstance(value, str) or any(
        ord(character) <= 0x20
        or ord(character) >= 0x7F
        or character == "\\"
        for character in value
    ):
        return False
    if not _URI_CHARACTERS.fullmatch(value):
        return False
    for match in re.finditer("%", value):
        if _PERCENT_ESCAPE.match(value, match.start()) is None:
            return False
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    # Do not rely on newer urlsplit checks being present on every supported interpreter.
    if ("[" in parsed.netloc or "]" in parsed.netloc) and not _valid_bracketed_authority(
        parsed.netloc
    ):
        return False
    return bool(
        parsed.scheme
        and _URI_SCHEME.fullmatch(parsed.scheme)
        and (parsed.netloc or parsed.path)
    )


def ecl_format_checker() -> FormatChecker:
    """Return a fresh checker with mandatory ECL formats always active."""

    checker = FormatChecker()
    checker.checks("date-time")(_valid_rfc3339_utc)
    checker.checks("uri")(_valid_absolute_uri)
    return checker
