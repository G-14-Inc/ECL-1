"""A completed drill cannot be dated after its evaluation.

Robert F. Tilley Jr.; G-14, Inc.
"""
import pytest
from ecl_verify.timing import EmergencyChannelDrill, TimingError

@pytest.mark.parametrize("last", ["2026-11-10T00:00:00.000000001Z", "2026-11-10T00:01:00Z"])
def test_future_drill_cannot_establish_current_completed_test(last):
    with pytest.raises(TimingError, match="later than"):
        EmergencyChannelDrill("ch", 60, last, "2026-11-10T00:00:00Z", None, True).validate()

@pytest.mark.parametrize("evaluated,valid", [
    ("2026-11-10T00:00:00Z", True),
    ("2026-11-10T00:01:00Z", True),
    ("2026-11-10T00:01:00.000000001Z", False),
])
def test_same_time_and_exact_due_boundary_are_valid(evaluated, valid):
    evidence = EmergencyChannelDrill("ch", 60, "2026-11-10T00:00:00Z", evaluated, None, True)
    if valid: evidence.validate()
    else:
        with pytest.raises(TimingError, match="overdue"): evidence.validate()
