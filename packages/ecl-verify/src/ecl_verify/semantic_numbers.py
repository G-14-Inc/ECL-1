"""Integer operands for schema-backed semantic checks, without changing caller values."""
import math

MAX_SAFE_INTEGER = 9007199254740991


def schema_int(value: object) -> int | None:
    """Keep integer operands and read finite whole floats in the interoperable range.

    Schema validation retains JSON Schema's mathematical integer type. Wire parsing,
    canonicalization and explicitly typed binding APIs retain their separate domains.
    Booleans are never integer operands.
    """
    if type(value) is int:
        return value
    if (type(value) is float and math.isfinite(value)
            and value.is_integer() and abs(value) <= MAX_SAFE_INTEGER):
        return int(value)
    return None
