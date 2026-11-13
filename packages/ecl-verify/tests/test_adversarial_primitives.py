"""Bounded producer and archive-configuration regressions using synthetic data."""
from dataclasses import replace
from pathlib import Path

import pytest

from ecl_verify.canonical import (
    CanonicalizationError, canonicalize, loads_json_strict, object_digest,
)
from ecl_verify.offline import (
    CONFIGURATION_INVALID, DEFAULT_OFFLINE_RESOURCE_LIMITS, OfflinePackageError,
    verify_directory_package, verify_zip_members,
)


def test_archive_encoded_byte_ceiling_precedes_input_inspection(monkeypatch):
    def inspected(_value):
        pytest.fail("archive input was inspected under an invalid configuration")

    monkeypatch.setattr("ecl_verify.offline._central_directory_count", inspected)
    for maximum in (2_147_483_648, 9_007_199_254_740_991):
        limits = replace(DEFAULT_OFFLINE_RESOURCE_LIMITS, max_archive_bytes=maximum)
        for call in (
            lambda: verify_zip_members(b"", limits=limits),
            lambda: verify_directory_package(Path("unread-synthetic-package"), {}, evaluated_at="bad", limits=limits),
        ):
            with pytest.raises(OfflinePackageError) as found:
                call()
            assert found.value.code == CONFIGURATION_INVALID


def test_archive_encoded_byte_ceiling_itself_is_valid():
    limits = replace(DEFAULT_OFFLINE_RESOURCE_LIMITS, max_archive_bytes=2_147_483_647)
    assert verify_zip_members(b"PK\x05\x06" + b"\x00" * 18, limits=limits) == ()


class DistinctName(str):
    """Two instances can coexist as dictionary keys despite the same base string."""
    def __hash__(self):
        return id(self)

    def __eq__(self, other):
        return self is other


def test_canonical_member_names_cannot_collide_after_base_string_conversion():
    ambiguous = {DistinctName("authority"): "deny", DistinctName("authority"): "admit"}
    assert len(ambiguous) == 2
    for value in (ambiguous, {"nested": [ambiguous]}, {"authority": "deny", DistinctName("authority"): "admit"}):
        for entry in (canonicalize, object_digest):
            with pytest.raises(CanonicalizationError) as found:
                entry(value)
            assert found.value.finding_id == "ecl.rule.json-no-duplicate-members.v1"


def test_distinct_base_names_and_supported_subclasses_remain_canonical():
    class Number(int):
        def __str__(self):
            return "not-the-number"

    value = {DistinctName("authority"): "deny", DistinctName("count"): Number(2)}
    encoded = canonicalize(value)
    assert encoded == b'{"authority":"deny","count":2}'
    assert loads_json_strict(encoded) == {"authority": "deny", "count": 2}
