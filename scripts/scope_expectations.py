"""Compare recorded scope with a corpus oracle, including its supporting checks."""
from __future__ import annotations

from typing import Any


def scope_expectation_matches(actual: Any, expected: dict[str, Any]) -> bool:
    if not isinstance(actual, dict):
        return False
    if any(actual.get(key) != expected[key] for key in ("established", "not_established", "reasons")):
        return False
    if "checks" not in expected:
        return True
    got, want = actual.get("checks"), expected["checks"]
    if not isinstance(got, dict) or set(got) != set(want):
        return False
    for item, entry in want.items():
        observed = got[item]
        if not isinstance(observed, dict) or set(observed) != {"checks", "objects"}:
            return False
        for field, kind in (("checks", str), ("objects", int)):
            values = observed[field]
            if not isinstance(values, list) or any(type(value) is not kind for value in values):
                return False
            if len(values) != len(set(values)) or set(values) != set(entry[field]):
                return False
    return True


# Unicode White_Space, enumerated explicitly to avoid platform trim differences.
# U+FEFF and U+001C..U+001F are not members. This compares without changing IDs.
OBSERVATION_WHITE_SPACE = "\u0009\u000a\u000b\u000c\u000d\u0020\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"


def effect_identifiers_nonblank(effects: list[dict[str, Any]]) -> bool:
    """Every observed effect names an action; no URI grammar or normalization."""
    return all(isinstance(item.get("action_id"), str)
               and bool(item["action_id"].strip(OBSERVATION_WHITE_SPACE)) for item in effects)
