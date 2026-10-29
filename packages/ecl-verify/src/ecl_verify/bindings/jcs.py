"""RFC 8785 (JSON Canonicalization Scheme) for content that ECL binds by digest but does not make.

ECL objects keep the restricted profile of `ecl_verify.canonical` (IE1-001), which refuses
floating-point numbers. The external content that the binding profiles digest can carry them: MCP
tool definitions, arguments and results, ACS context entries, AARM receipts. This module
implements all of RFC 8785 for that content:

- numbers are IEEE 754 doubles, serialized as ECMAScript's Number.prototype.toString serializes
  them (RFC 8785 section 3.2.2.3); an integer beyond 2**53 in magnitude is first rounded to the
  nearest double, as an ECMAScript parser would round it;
- strings keep every character except the quotation mark, the reverse solidus and the controls
  U+0000 to U+001F, which take the short escapes or `\\u00xx` in lower case (section 3.2.2.2);
- object members are sorted by the UTF-16 code units of their names (section 3.2.3).

`loads` parses I-JSON (RFC 7493) for this purpose: duplicate member names, a lone surrogate,
NaN, an infinity and a number that overflows a double are refused, and a number with a fraction or
an exponent becomes a float. `digest` is the `ecl.digest.sha-256.v1` digest object of the
canonical bytes. packages/ecl-verify/tests/test_bindings_jcs.py pins the number samples of RFC 8785 Appendix B.
"""

from __future__ import annotations

import decimal
import hashlib
import json
import math
from typing import Any

DIGEST_SUITE = "ecl.digest.sha-256.v1"
# Doubles represent every integer up to this magnitude exactly.
_EXACT_INTEGER = 2**53
# RFC 8785 section 3.2.2.3 bounds the decimal exponents written without an exponent.
_PLAIN_MAX = 21
_PLAIN_MIN = -6
_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


class JcsError(ValueError):
    """The value has no RFC 8785 canonical form, or the text is not I-JSON."""


def _string(value: str) -> str:
    parts = ['"']
    for character in value:
        code = ord(character)
        if 0xD800 <= code <= 0xDFFF:
            raise JcsError("a lone surrogate has no canonical form")
        escaped = _ESCAPES.get(character)
        if escaped is not None:
            parts.append(escaped)
        elif code < 0x20:
            parts.append(f"\\u{code:04x}")
        else:
            parts.append(character)
    parts.append('"')
    return "".join(parts)


def _shortest(value: float) -> tuple[str, int]:
    """The digits s and the exponent n of a positive double: value = 0.s * 10**n, s minimal.

    Python's repr is the shortest string that reads back as the same double, nearest to it when
    several are equally short, as ECMAScript requires of s (ECMA-262 Number::toString).
    """
    text = repr(value)
    mantissa, _, power = text.partition("e")
    whole, _, fraction = mantissa.partition(".")
    digits = whole + fraction
    stripped = digits.lstrip("0")
    exponent = len(whole) + (int(power) if power else 0) - (len(digits) - len(stripped))
    return stripped.rstrip("0"), exponent


def number(value: float) -> str:
    """ECMAScript's Number.prototype.toString of a finite double (RFC 8785 section 3.2.2.3)."""
    if math.isnan(value) or math.isinf(value):
        raise JcsError("NaN and the infinities have no JSON form")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    digits, n = _shortest(abs(value))
    k = len(digits)
    if k <= n <= _PLAIN_MAX:
        return sign + digits + "0" * (n - k)
    if 0 < n <= _PLAIN_MAX:
        return sign + digits[:n] + "." + digits[n:]
    if _PLAIN_MIN < n <= 0:
        return sign + "0." + "0" * -n + digits
    power = n - 1
    exponent = ("+" if power >= 0 else "-") + str(abs(power))
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    return sign + mantissa + "e" + exponent


def _integer(value: int) -> str:
    if abs(value) <= _EXACT_INTEGER:
        return str(value)
    try:
        return number(float(value))
    except OverflowError as error:
        raise JcsError("an integer beyond the range of a double has no canonical form") from error


def _serialize(value: Any, depth: int) -> str:
    if depth > 256:
        raise JcsError("the value nests deeper than 256 levels")
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if type(value) is int:
        return _integer(value)
    if type(value) is float:
        return number(value)
    if type(value) is str:
        return _string(value)
    if type(value) is list:
        return "[" + ",".join(_serialize(item, depth + 1) for item in value) + "]"
    if type(value) is dict:
        if not all(type(key) is str for key in value):
            raise JcsError("object member names must be strings")
        names = sorted(value, key=_utf16)
        return (
            "{"
            + ",".join(_string(name) + ":" + _serialize(value[name], depth + 1) for name in names)
            + "}"
        )
    raise JcsError(f"no JSON form for a value of type {type(value).__name__}")


def _utf16(name: str) -> bytes:
    for character in name:
        if 0xD800 <= ord(character) <= 0xDFFF:
            raise JcsError("a lone surrogate has no canonical form")
    return name.encode("utf-16-be")


def canonicalize(value: Any) -> bytes:
    """The RFC 8785 canonical UTF-8 bytes of a parsed JSON value."""
    return _serialize(value, 0).encode("utf-8")


def digest(value: Any) -> dict[str, str]:
    """The `ecl.digest.sha-256.v1` digest object of the canonical bytes of `value`."""
    return {"algorithm": DIGEST_SUITE, "value": hashlib.sha256(canonicalize(value)).hexdigest()}


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, item in pairs:
        if name in result:
            raise JcsError(f"duplicate object member: {name!r}")
        result[name] = item
    return result


def _float(text: str) -> float:
    parsed = float(text)
    if math.isinf(parsed):
        raise JcsError(f"the number {text} overflows a double")
    return parsed


def _constant(text: str) -> float:
    raise JcsError(f"{text} is not JSON")


def inexact_numbers(data: str | bytes) -> list[str]:
    """The JSON Pointers of the numbers in a JSON text that RFC 8785 may not represent exactly:
    each of magnitude greater than 2^53 - 1 (RFC 7493 section 2.2), and each other number whose
    RFC 8785 form does not have the value written, such as a fraction with more significant digits
    than a double keeps. `loads` reads both as the nearest double, so a gateway that forwards the
    canonical form of what `loads` returns would forward another value (MG1-004). Text that is not
    JSON has no such numbers here; `loads` refuses it."""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError:
            return []
    try:
        value = json.loads(
            data,
            object_pairs_hook=_pairs,
            parse_float=decimal.Decimal,
            parse_int=int,
            parse_constant=_constant,
        )
    except (JcsError, ValueError, RecursionError):
        return []
    found: list[str] = []
    pending: list[tuple[Any, str]] = [(value, "")]
    while pending:
        item, where = pending.pop()
        if type(item) is dict:
            pending.extend(
                (child, f"{where}/{name.replace('~', '~0').replace('/', '~1')}")
                for name, child in item.items()
            )
        elif type(item) is list:
            pending.extend((child, f"{where}/{index}") for index, child in enumerate(item))
        elif (type(item) is int and abs(item) > _EXACT_INTEGER - 1) or (
            type(item) is decimal.Decimal
            and (abs(item) > _EXACT_INTEGER - 1 or not _same_value(item))
        ):
            found.append(where)
    return sorted(found)


def _same_value(written: decimal.Decimal) -> bool:
    """The RFC 8785 form of the double nearest to `written` has the value written."""
    try:
        nearest = float(written)
        if math.isinf(nearest):
            return False
        return decimal.Decimal(number(nearest)) == written
    except (JcsError, OverflowError, decimal.InvalidOperation):
        return False


def loads(data: str | bytes) -> Any:
    """Parse I-JSON text for canonicalization; see the module documentation for what it refuses."""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise JcsError("the text is not UTF-8") from error
    if data.startswith("﻿"):
        raise JcsError("the text begins with a byte-order mark")
    try:
        value = json.loads(
            data, object_pairs_hook=_pairs, parse_float=_float, parse_constant=_constant
        )
    except JcsError:
        raise
    except (ValueError, RecursionError) as error:
        raise JcsError(f"the text is not JSON: {error}") from error
    canonicalize(value)
    return value
