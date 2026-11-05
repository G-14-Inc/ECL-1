"""Restricted RFC 8785 canonicalization and strict JSON loading.

Strict input (INTEGRITY-ENVELOPE-1, IE1-002 and IE1-037) is checked in a fixed order, and the
first check that fails decides the one finding a refusal carries (`CanonicalizationError.finding_id`):

1. the declared byte limit (`ecl.error.resource-limit-exceeded.v1`);
2. UTF-8 without a byte order mark, then the JSON grammar of RFC 8259 without the constants
   `NaN`, `Infinity` and `-Infinity` (`ecl.rule.json-strict-syntax.v1`); a value nested deeper than
   the parser's own bound, `GRAMMAR_NESTING_BOUND` or the declared nesting limit if that is
   greater, ends the check as a resource limit;
3. the declared nesting and value-count limits (`ecl.error.resource-limit-exceeded.v1`);
4. every string and member name holds only Unicode scalar values that are not noncharacters
   (`ecl.rule.json-strict-syntax.v1`);
5. no object repeats a member name (`ecl.rule.json-no-duplicate-members.v1`);
6. every number is an integer within plus or minus 2**53 - 1 without a fraction, an exponent or a
   negative zero (`ecl.rule.json-restricted-numbers.v1`).

Checks 3 to 6 read every value of the input, the values of a repeated member name included, so
the order of the checks, not the position of a defect in the text, decides the finding.

The parse is one pass over the text that counts values and nesting as it reads them (IE1-029).
While the input is within the declared limits it builds the value and notes the first defect of
checks 4 to 6. At the first value beyond a declared limit it drops what it has built and reads the
rest of the text for check 2 alone, keeping only the kind of each open container, so the memory a
refusal costs follows the declared limits, not the size of the input. The limits are checked by
type before any input is read: each is an `int` of at least 1, never a `bool`, a `float` (`NaN` and
the infinities among them) or another number (IE1-028).
"""

from __future__ import annotations

import codecs
import hashlib
import json
import re
from json.decoder import scanstring as _scanstring  # type: ignore[attr-defined]
from pathlib import Path
from typing import Any

MAX_SAFE_INTEGER = 9007199254740991
# The declared limits of the strict parser (IE1-028): encoded bytes, nesting depth counted from 0
# for the top-level value, and values. A caller may configure others, each an exact positive
# integer within its ceiling; any other configured limit is refused before any input is read.
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 256
MAX_JSON_NODES = 1_000_000
MAX_JSON_BYTES_CEILING = 2_147_483_647
MAX_JSON_DEPTH_CEILING = 4_096
MAX_JSON_NODES_CEILING = 100_000_000
# The nesting depth (the top-level value at 0) to which the grammar check reads an input that is
# beyond the declared limits. A value nested deeper than this and than the declared nesting limit
# ends the check with a resource-limit refusal (IE1-037, check 2); below it the check reads the
# whole text, so the finding of an input that exceeds a declared limit never depends on the parser.
GRAMMAR_NESTING_BOUND = 10_000

# The findings a refusal of strict input carries (IE1-037).
STRICT_SYNTAX = "ecl.rule.json-strict-syntax.v1"
DUPLICATE_MEMBERS = "ecl.rule.json-no-duplicate-members.v1"
RESTRICTED_NUMBERS = "ecl.rule.json-restricted-numbers.v1"
RESOURCE_LIMIT = "ecl.error.resource-limit-exceeded.v1"
# The finding of a configured limit that is not an exact positive integer within its ceiling
# (IE1-028): the one configuration-error code of every lane.
CONFIGURATION_INVALID = "ecl.error.configuration-invalid.v1"

# Surrogate code points and the 66 noncharacters of Unicode: U+FDD0 to U+FDEF, and the last two
# code points of each of the 17 planes. I-JSON (RFC 7493, section 2.1) excludes both from strings
# and member names, and so does IE1-002.
_NONCHARACTERS = "﷐-﷯" + "".join(
    chr((plane << 16) | 0xFFFE) + chr((plane << 16) | 0xFFFF) for plane in range(17)
)
_INVALID_SCALAR = re.compile("[\ud800-\udfff" + _NONCHARACTERS + "]")
# A surrogate code point in text, which has no UTF-8 form (IE1-037, check 2).
_SURROGATE = re.compile("[\ud800-\udfff]")


class CanonicalizationError(ValueError):
    """Raised when a value is outside the ECL canonical JSON profile.

    `finding_id` is the registered rule or error that the refusal names (IE1-037).
    """

    def __init__(self, message: str, finding_id: str = STRICT_SYNTAX) -> None:
        super().__init__(message)
        self.finding_id = finding_id

    def __reduce__(self) -> tuple[Any, ...]:
        # The default would call CanonicalizationError(message) and lose the finding.
        return (CanonicalizationError, (str(self), self.finding_id))


_NODE_BUDGET = "JSON value exceeds the canonical node budget"
_NESTING_BUDGET = "JSON value exceeds the canonical nesting budget"
# The message of a refusal at the declared value limit, by which a caller that passes a remaining
# budget as `max_nodes` tells that refusal from the others (EBMP2-062).
NODE_BUDGET_MESSAGE = _NODE_BUDGET
_LIMIT_NAMES = ("max_bytes", "max_depth", "max_nodes")
_LIMIT_CEILINGS = {
    "max_bytes": MAX_JSON_BYTES_CEILING,
    "max_depth": MAX_JSON_DEPTH_CEILING,
    "max_nodes": MAX_JSON_NODES_CEILING,
}
# UTF-8 input is checked in slices of this many bytes, so the check holds no decoded copy of it:
# the text of one slice, at most four bytes for each of its bytes, is all it holds at once.
_UTF8_SLICE = 8 * 1024


class _Grammar:
    """The patterns and delimiters of the RFC 8259 grammar, for text or for UTF-8 bytes.

    UTF-8 bytes are parsed as bytes, so no decoded copy of the input is made: every delimiter of
    the grammar is ASCII, and the bytes of a multi-byte UTF-8 sequence are all above 0x7F, so they
    never match a delimiter, a control character or an escape.
    """

    def __init__(self, kind: type[str] | type[bytes]) -> None:
        def pattern(text: str) -> Any:
            return re.compile(text if kind is str else text.encode("ascii"))

        def token(text: str) -> Any:
            return text if kind is str else text.encode("ascii")

        self.whitespace = pattern(r"[ \t\n\r]*").match
        # RFC 8259 numbers with ASCII digits: the integer part, then a fraction and an exponent.
        self.number = pattern(r"-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?").match
        # A run of string characters that needs no escape, and one escape (RFC 8259, section 7).
        self.run = pattern(r'[^"\\\x00-\x1f]*').match
        self.escape = pattern(r'\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4})').match
        # A whole string without an escape, the common case, read by one match.
        self.plain = pattern(r'"([^"\\\x00-\x1f]*)"').match
        self.open_object, self.close_object = token("{"), token("}")
        self.open_array, self.close_array = token("["), token("]")
        self.quote, self.backslash = token('"'), token("\\")
        self.comma, self.colon = token(","), token(":")
        self.literals = {
            token("n"): (token("null"), None),
            token("t"): (token("true"), True),
            token("f"): (token("false"), False),
        }
        self.constants = tuple(token(name) for name in ("NaN", "Infinity", "-Infinity"))
        self.text = kind is str


_TEXT_GRAMMAR = _Grammar(str)
_BYTES_GRAMMAR = _Grammar(bytes)


def _check_limit(name: str, value: object) -> int:
    """A configured limit (IE1-028): an `int` from 1 to the ceiling of the limit, checked by type.

    A `bool`, a `float` (so `NaN`, which no comparison refuses, and the infinities, which every
    input is below), `None`, a string, an int subclass and every other type are refused, never
    compared, so that no configuration turns a finite limit into none; so is a value above the
    ceiling. The refusal is the configuration-error code, `ecl.error.configuration-invalid.v1`.
    """
    if type(value) is not int or value < 1:
        # The message names the type, not the value: the text of a huge integer can itself fail.
        kind = "an integer below 1" if type(value) is int else f"a {type(value).__name__}"
        raise CanonicalizationError(
            f"strict JSON limit {name} must be an integer of at least 1, not {kind}",
            CONFIGURATION_INVALID,
        )
    ceiling = _LIMIT_CEILINGS.get(name, MAX_JSON_NODES_CEILING)
    if value > ceiling:
        raise CanonicalizationError(
            f"strict JSON limit {name} must be at most {ceiling}, its ceiling",
            CONFIGURATION_INVALID,
        )
    return value


def _check_utf8(data: bytes) -> None:
    """Check 2's encoding: `data` is UTF-8, decoded a slice at a time, so that no decoded copy of
    the whole input is held."""
    if data.isascii():
        return
    view = memoryview(data)
    start, end = 0, len(data)
    try:
        while start < end:
            stop = min(start + _UTF8_SLICE, end)
            # A sequence cut at the end of a slice is not consumed and begins the next slice. The
            # decoded text is dropped at once; only the count of bytes consumed is kept.
            start += codecs.utf_8_decode(view[start:stop], "strict", stop == end)[1]
    except UnicodeDecodeError as exc:
        raise CanonicalizationError("strict JSON input is not UTF-8") from exc


def _syntax(message: str, position: int) -> CanonicalizationError:
    return CanonicalizationError(f"invalid strict JSON: {message} (char {position})")


def _skip_string(grammar: _Grammar, text: Any, position: int) -> int:
    """The position after the string that begins at `position`, read for the grammar alone, with
    nothing decoded or kept."""
    end = len(text)
    run, escape = grammar.run, grammar.escape
    position += 1
    while True:
        position = run(text, position).end()
        if position >= end:
            raise _syntax("unterminated string", position)
        character = text[position : position + 1]
        if character == grammar.quote:
            return position + 1
        if character != grammar.backslash:
            raise _syntax("invalid control character in a string", position)
        found = escape(text, position)
        if found is None:
            raise _syntax("invalid escape in a string", position)
        position = found.end()


def _read_string(grammar: _Grammar, text: Any, position: int) -> tuple[str, int]:
    """The decoded string that begins at `position`, and the position after it."""
    try:
        if grammar.text:
            return _scanstring(text, position + 1, True)  # type: ignore[no-any-return]
        # UTF-8 bytes, which the encoding check has found valid: the string's own bytes alone are
        # decoded, then its escapes.
        plain = grammar.plain(text, position)
        if plain is not None:
            return plain.group(1).decode("utf-8"), plain.end()
        stop = _skip_string(grammar, text, position)
        raw = text[position:stop].decode("utf-8")
        if "\\" in raw:
            return _scanstring(raw, 1, True)[0], stop
        return raw[1:-1], stop
    except ValueError as exc:
        if isinstance(exc, CanonicalizationError):
            raise
        raise CanonicalizationError(f"invalid strict JSON: {exc}") from exc


def _scalar_problem(value: str) -> str | None:
    """Check 4 for one string or member name: the defect it holds, if any. An ASCII string holds
    none, which `str.isascii` tells without reading it."""
    if value.isascii():
        return None
    match = _INVALID_SCALAR.search(value)
    if match is None:
        return None
    codepoint = ord(match.group())
    if 0xD800 <= codepoint <= 0xDFFF:
        return "lone Unicode surrogate is prohibited"
    return f"Unicode noncharacter U+{codepoint:04X} is prohibited"


def _number_problem(literal: str, fraction: bool) -> str | None:
    """Check 6 for one number: the defect it holds, if any."""
    if fraction:
        return f"floating-point JSON numbers are prohibited by the ECL profile: {literal[:40]}"
    if literal == "-0":
        return "negative zero is prohibited"
    digits = literal[1:] if literal.startswith("-") else literal
    # At most 16 digits can be within the exact range; converting more is never needed.
    if len(digits) > 16 or abs(int(literal)) > MAX_SAFE_INTEGER:
        return f"integer exceeds exact interoperable range: {literal[:40]}"
    return None


def _parse(text: Any, max_depth: int, max_nodes: int) -> Any:
    """Checks 2 to 6 of IE1-037 over `text` (a str, or bytes already found to be UTF-8), in one
    pass with an explicit stack.

    `kinds` holds the open containers for the grammar, one byte each (1 for an object, 0 for an
    array). While the input is within the limits, `frames` holds the containers being built and
    `names` the member name each open object reads; at the first value beyond a limit both are
    dropped and the rest of the text is read for the grammar alone, so check 2 still decides
    between a grammar error anywhere in the text and the limit.
    """
    grammar = _TEXT_GRAMMAR if isinstance(text, str) else _BYTES_GRAMMAR
    skip, number = grammar.whitespace, grammar.number
    open_object, close_object = grammar.open_object, grammar.close_object
    open_array, close_array = grammar.open_array, grammar.close_array
    quote, comma, colon, literals = grammar.quote, grammar.comma, grammar.colon, grammar.literals
    end = len(text)
    bound = max(GRAMMAR_NESTING_BOUND, max_depth)
    kinds = bytearray()
    frames: list[Any] = []
    names: list[str] = []
    building = True
    nodes = 0
    budget: str | None = None
    scalar: str | None = None
    duplicate: str | None = None
    numeral: str | None = None
    value: Any = None

    def member_name(position: int) -> tuple[str, int]:
        """The member name at `position` and the position of its value, past the colon."""
        nonlocal scalar
        if text[position : position + 1] != quote:
            raise _syntax("expecting a property name enclosed in double quotes", position)
        if building:
            name, position = _read_string(grammar, text, position)
            if scalar is None:
                scalar = _scalar_problem(name)
        else:
            name, position = "", _skip_string(grammar, text, position)
        position = skip(text, position).end()
        if text[position : position + 1] != colon:
            raise _syntax("expecting ':' delimiter", position)
        return name, skip(text, position + 1).end()

    position = skip(text, 0).end()
    while True:
        # A value begins at `position`, nested in the open containers.
        depth = len(kinds)
        nodes += 1
        if building and (nodes > max_nodes or depth > max_depth):
            budget = _NODE_BUDGET if nodes > max_nodes else _NESTING_BUDGET
            building = False
            frames.clear()
            names.clear()
            value = None
        if depth > bound:
            raise CanonicalizationError(
                "strict JSON nesting exceeds the parser's bound", RESOURCE_LIMIT
            )
        character = text[position : position + 1]
        if character == open_object or character == open_array:
            is_object = character == open_object
            position = skip(text, position + 1).end()
            if text[position : position + 1] == (close_object if is_object else close_array):
                position += 1
                value = {} if is_object else []
            else:
                kinds.append(is_object)  # a bool is the byte 1 or 0
                if building:
                    frames.append({} if is_object else [])
                if is_object:
                    name, position = member_name(position)
                    if building:
                        names.append(name)
                continue
        elif character == quote:
            if building:
                value, position = _read_string(grammar, text, position)
                if scalar is None:
                    scalar = _scalar_problem(value)
            else:
                position = _skip_string(grammar, text, position)
        elif character in literals and text.startswith(literals[character][0], position):
            literal, value = literals[character]
            position += len(literal)
        else:
            match = number(text, position)
            if match is None:
                for constant in grammar.constants:
                    if text.startswith(constant, position):
                        shown = constant if grammar.text else constant.decode("ascii")
                        raise CanonicalizationError(
                            f"non-JSON numeric constant is prohibited: {shown}", STRICT_SYNTAX
                        )
                raise _syntax("expecting a value", position)
            position = match.end()
            if building:
                found = match.group()
                literal_text = found if grammar.text else found.decode("ascii")
                fraction = match.group(1) is not None or match.group(2) is not None
                problem = _number_problem(literal_text, fraction)
                if problem is None:
                    value = int(literal_text)
                else:
                    value = 0
                    if numeral is None:
                        numeral = problem
        # The value is read: add it to its container, then close each container that ends here.
        while True:
            position = skip(text, position).end()
            if not kinds:
                if position != end:
                    raise _syntax("extra data after the JSON value", position)
                if budget is not None:
                    raise CanonicalizationError(budget, RESOURCE_LIMIT)
                if scalar is not None:
                    raise CanonicalizationError(scalar, STRICT_SYNTAX)
                if duplicate is not None:
                    raise CanonicalizationError(duplicate, DUPLICATE_MEMBERS)
                if numeral is not None:
                    raise CanonicalizationError(numeral, RESTRICTED_NUMBERS)
                return value
            is_object = kinds[-1]
            if building:
                container = frames[-1]
                if is_object:
                    name = names[-1]
                    if duplicate is None and name in container:
                        duplicate = f"duplicate JSON object member: {name!r}"
                    container[name] = value
                else:
                    container.append(value)
            character = text[position : position + 1]
            if character == comma:
                position = skip(text, position + 1).end()
                if is_object:
                    name, position = member_name(position)
                    if building:
                        names[-1] = name
                break
            if character == (close_object if is_object else close_array):
                position += 1
                kinds.pop()
                if building:
                    value = frames.pop()
                    if is_object:
                        names.pop()
                continue
            raise _syntax("expecting ',' or '}'" if is_object else "expecting ',' or ']'", position)


def _validate_value_limits(
    value: Any,
    *,
    max_depth: int = MAX_JSON_DEPTH,
    max_nodes: int = MAX_JSON_NODES,
) -> None:
    """The limits and the string profile of a Python value handed to the canonicalizer."""
    _check_limit("max_depth", max_depth)
    _check_limit("max_nodes", max_nodes)
    stack: list[tuple[Any, int, bool]] = [(value, 0, False)]
    active: set[int] = set()
    nodes = 0
    while stack:
        current, depth, leaving = stack.pop()
        if leaving:
            active.remove(id(current))
            continue
        nodes += 1
        if nodes > max_nodes:
            raise CanonicalizationError(
                "JSON value exceeds the canonical node budget", RESOURCE_LIMIT
            )
        if depth > max_depth:
            raise CanonicalizationError(
                "JSON value exceeds the canonical nesting budget", RESOURCE_LIMIT
            )
        if isinstance(current, str):
            _validate_string(current)
            continue
        if isinstance(current, (list, dict)):
            identity = id(current)
            if identity in active:
                raise CanonicalizationError(
                    "cyclic Python containers cannot be canonical JSON"
                )
            active.add(identity)
            stack.append((current, depth, True))
            # The base-class views: a subclass cannot show one content here and another to
            # _serialize.
            if isinstance(current, dict):
                for key, item in dict.items(current):
                    if not isinstance(key, str):
                        raise CanonicalizationError(
                            "JSON object member names must be strings"
                        )
                    _validate_string(key)
                    stack.append((item, depth + 1, False))
            else:
                for item in list.__iter__(current):
                    stack.append((item, depth + 1, False))


def loads_json_strict(
    value: str | bytes,
    *,
    max_bytes: int = MAX_JSON_BYTES,
    max_depth: int = MAX_JSON_DEPTH,
    max_nodes: int = MAX_JSON_NODES,
) -> Any:
    """Parse strict JSON, refusing it with the finding of the first check that fails (IE1-037).

    The limits are checked first, by type (IE1-028). Then the input is sized before anything is
    decoded or parsed (check 1): text is measured as UTF-8 only once its length in code points,
    which no UTF-8 form is shorter than, is within the byte limit.
    """
    if not isinstance(value, (str, bytes)):
        raise CanonicalizationError("strict JSON input must be text or bytes")
    for name, limit in zip(_LIMIT_NAMES, (max_bytes, max_depth, max_nodes)):
        _check_limit(name, limit)
    # Check 1. A text holding a lone surrogate has no UTF-8 form; it is sized as if it had one.
    size = len(value)
    if isinstance(value, str) and size <= max_bytes and not value.isascii():
        size = len(value.encode("utf-8", "surrogatepass"))
    if size > max_bytes:
        raise CanonicalizationError("strict JSON input exceeds the byte budget", RESOURCE_LIMIT)
    # Check 2. I-JSON (IE1-002) is UTF-8 without a byte-order mark. Bytes are parsed as they are,
    # once they are found to be UTF-8, so that no decoded copy of the input is made.
    if isinstance(value, bytes):
        _check_utf8(value)
        if value.startswith(b"\xef\xbb\xbf"):
            raise CanonicalizationError("strict JSON input begins with a byte-order mark")
    else:
        if _SURROGATE.search(value) is not None:
            raise CanonicalizationError("strict JSON input is not valid Unicode")
        if value.startswith("\ufeff"):
            raise CanonicalizationError("strict JSON input begins with a byte-order mark")
    return _parse(value, max_depth, max_nodes)


def load_json_strict(path: str | Path, *, max_bytes: int = MAX_JSON_BYTES) -> Any:
    """Read the file at `path` as strict JSON, reading at most `max_bytes` + 1 bytes of it, so a
    file over the byte limit is refused without being read whole (IE1-029)."""
    _check_limit("max_bytes", max_bytes)
    with Path(path).open("rb") as source:
        data = source.read(max_bytes + 1)
    return loads_json_strict(data, max_bytes=max_bytes)


def _validate_string(value: str) -> None:
    problem = _scalar_problem(str.__str__(value))
    if problem is not None:
        raise CanonicalizationError(problem)


def _quote(value: str) -> str:
    text = str.__str__(value)
    _validate_string(text)
    return json.dumps(text, ensure_ascii=False, separators=(",", ":"))


def _utf16_sort_key(value: str) -> bytes:
    text = str.__str__(value)
    _validate_string(text)
    return text.encode("utf-16-be")


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        # The integer's own value and digits: a subclass's str() can be any text (on Python 3.10
        # an IntEnum member's is its qualified name), which would put foreign JSON in the bytes.
        number = int.__int__(value)
        if abs(number) > MAX_SAFE_INTEGER:
            raise CanonicalizationError(
                f"integer exceeds exact interoperable range: {number}", RESTRICTED_NUMBERS
            )
        return int.__repr__(number)
    if isinstance(value, float):
        raise CanonicalizationError("floating-point values are prohibited", RESTRICTED_NUMBERS)
    if isinstance(value, str):
        return _quote(value)
    if isinstance(value, list):
        return "[" + ",".join(_serialize(item) for item in list.__iter__(value)) + "]"
    if isinstance(value, dict):
        members = dict.items(value)
        if not all(isinstance(key, str) for key, _item in members):
            raise CanonicalizationError("JSON object member names must be strings")
        ordered = sorted(members, key=lambda member: _utf16_sort_key(member[0]))
        return "{" + ",".join(
            f"{_quote(key)}:{_serialize(item)}" for key, item in ordered
        ) + "}"
    raise CanonicalizationError(
        f"unsupported value type for canonical JSON: {type(value).__name__}"
    )


def canonicalize(value: Any) -> bytes:
    """Return RFC 8785-compatible bytes under the restricted ECL profile."""

    _validate_value_limits(value)
    result = _serialize(value).encode("utf-8")
    if len(result) > MAX_JSON_BYTES:
        raise CanonicalizationError(
            "canonical JSON output exceeds the byte budget", RESOURCE_LIMIT
        )
    return result


def object_digest(value: Any) -> str:
    return hashlib.sha256(canonicalize(value)).hexdigest()


def object_id(value: Any) -> str:
    return f"https://externalcontrollayer.ai/ns/sha256/{object_digest(value)}"


def same_json(left: object, right: object) -> bool:
    """Two JSON values are the same: of the same type and equal, so a boolean never equals a
    number, where Python's `==` equates `true` with 1 and `false` with 0."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(same_json(left[key], right[key]) for key in left)
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            same_json(first, second) for first, second in zip(left, right, strict=True)
        )
    return left == right
