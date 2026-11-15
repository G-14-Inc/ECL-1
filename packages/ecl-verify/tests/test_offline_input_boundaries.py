"""Malformed container names must still produce a usable, classified JSON report."""
from copy import deepcopy
import io
import json
from pathlib import Path
import zipfile

import pytest

from ecl_verify import cli, offline

ROOT = Path(__file__).resolve().parents[3]
NOW = "2026-10-01T00:00:00Z"
CASES = json.loads((ROOT / "tests/fixtures/offline-cli-cases.json").read_text())["cases"]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_untrusted_zip_name_has_canonical_json_report(case, tmp_path, capsys):
    archive = tmp_path / "malformed.zip"
    archive.write_bytes(bytes.fromhex(case["archive_hex"]))
    result = cli.main([str(archive), "--trust-policy",
                       str(ROOT / "conformance/suites/offline-package/trust-policy.json"),
                       "--now", NOW, "--json"])
    captured = capsys.readouterr()
    assert result == 1
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["verdict"] == "invalid"
    assert report["primary"] == case["primary"]
    assert report["scope"]["established"] == []


def test_lone_surrogate_path_has_a_classified_refusal():
    with pytest.raises(offline.OfflinePackageError) as caught:
        offline.safe_relative_path("\ud800")
    assert caught.value.code == offline.SEMANTIC_INVALID
    assert offline.safe_relative_path("caf\u00e9/a.txt").as_posix() == "caf\u00e9/a.txt"


def test_standalone_manifest_preserves_depth_budget_refusal():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        info = zipfile.ZipInfo("manifest.json", (1980, 1, 1, 0, 0, 0))
        info.create_system = 3
        info.create_version = info.extract_version = 20
        info.external_attr = 0o100644 << 16
        archive.writestr(info, b"[" * 300 + b"]" * 300)
    with pytest.raises(offline.OfflinePackageError) as caught:
        offline.verify_zip_package(stream.getvalue(), evaluated_at=NOW)
    assert caught.value.code == offline.RESOURCE_LIMIT


def test_invalid_caller_time_precedes_archive_read():
    with pytest.raises(offline.OfflinePackageError, match="invalid UTC timestamp"):
        offline.verify_zip_package(b"not a ZIP", evaluated_at="yesterday")


def test_directory_errors_are_classified_and_valid_package_remains_valid(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    with zipfile.ZipFile(ROOT / "conformance/suites/offline-package/package-valid-verified.zip") as archive:
        manifest = json.loads(archive.read("manifest.json"))
        for item in archive.infolist():
            target = root / item.filename
            assert target.resolve().is_relative_to(root.resolve())
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(item))
    valid = offline.verify_directory_package(root, manifest, evaluated_at=NOW)
    assert valid.artifact_count == len(manifest["artifacts"])
    invalid = deepcopy(manifest)
    invalid["artifacts"][0]["media_type"] = "application/x\ufffe"
    with pytest.raises(offline.OfflinePackageError) as caught:
        offline.verify_directory_package(root, invalid, evaluated_at=NOW)
    assert caught.value.code == offline.SCHEMA_INVALID
    loop = tmp_path / "loop"
    try:
        loop.symlink_to("loop")
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    with pytest.raises(offline.OfflinePackageError) as caught:
        offline.verify_directory_package(loop, manifest, evaluated_at=NOW)
    assert caught.value.code == offline.CLOSURE_INCOMPLETE
