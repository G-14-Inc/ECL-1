"""Archive check-1 diagnostics depend on stored metadata and declared limits.

Robert F. Tilley Jr.; G-14, Inc. Synthetic archives contain no expanded data.
"""
import base64,json
from pathlib import Path
import pytest
from ecl_verify.offline import OfflineResourceLimits,OfflinePackageError,verify_zip_members,zip_entry_name
from ecl_verify.package_verification import verify_offline_package,reported_package_identifiers
from ecl_verify.trust import TrustPolicy

ROOT=Path(__file__).resolve().parents[1]
CASES=json.loads((ROOT/'tests/fixtures/archive-metadata-boundaries.json').read_text())['cases']
POLICY=TrustPolicy.load((ROOT/'conformance/suites/offline-package/trust-policy.json').read_bytes())

@pytest.mark.parametrize('case',CASES,ids=lambda case:case['id'])
def test_archive_metadata_boundary(case):
    data=base64.b64decode(case['archive_base64']);limits=OfflineResourceLimits(**case['limits'])
    try:
        verify_zip_members(data,limits=limits)
        code='accepted'
    except OfflinePackageError as error:
        code=error.code
    assert code==case['reader_code']
    report=verify_offline_package(data,POLICY,now='2026-10-01T00:00:00Z',limits=limits)
    assert report.verdict==case['package_verdict']
    assert sorted(reported_package_identifiers(report))==case['package_codes']


def test_resolved_metadata_budgets_precede_library_entry_construction(monkeypatch):
    def forbidden(*args,**kwargs):
        pytest.fail('archive library constructed entries before the declared size refusal')
    monkeypatch.setattr('ecl_verify.offline.zipfile.ZipFile',forbidden)
    case=next(row for row in CASES if row['id']=='zip64-duplicate-max-then-small')
    with pytest.raises(OfflinePackageError) as found:
        verify_zip_members(base64.b64decode(case['archive_base64']),limits=OfflineResourceLimits(**case['limits']))
    assert found.value.code=='ecl.error.resource-limit-exceeded.v1'


def test_direct_text_path_budget_still_counts_utf8_bytes():
    # The archive uses stored bytes; this separate direct string helper has no
    # archive encoding and continues to count its documented UTF-8 representation.
    with pytest.raises(OfflinePackageError) as found:
        zip_entry_name('░'*1500)
    assert found.value.code=='ecl.error.resource-limit-exceeded.v1'
