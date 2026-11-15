"""Exact source-export names are distinct from untrusted evidence paths.

Robert F. Tilley Jr.; G-14, Inc.
"""
import errno
import hashlib
import json
import os
from pathlib import Path

import pytest
from scripts.verify_external_implementation_report import source_tree, confined_file

NAMES = ["notes 1.txt", "café.txt", "cafe\u0301.txt", "\ue000.txt", "\U00010000.txt",
         "a\u2028b\u2029.txt", "\ufffd.txt", "\ufeffname.txt", "CON.txt", "notes.", "notes ", "name:stream.txt"]

@pytest.mark.parametrize("name", NAMES)
def test_source_export_preserves_exact_utf8_name(tmp_path, name):
    if os.name == "nt" and name in {"CON.txt", "notes.", "notes ", "name:stream.txt"}:
        pytest.skip("host does not preserve this POSIX filename")
    (tmp_path / name).write_bytes(b"x")
    if name not in os.listdir(tmp_path):
        pytest.skip("host normalizes the requested filename")
    entries = [{"path": name, "size_bytes": 1, "sha256": hashlib.sha256(b"x").hexdigest()}]
    expected = hashlib.sha256(json.dumps(entries, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert source_tree(tmp_path) == (expected, entries)

@pytest.mark.parametrize("directory", [False, True])
def test_source_export_refuses_git_metadata(tmp_path, directory):
    (tmp_path / "control").write_text("x")
    path = tmp_path / ".git"
    path.mkdir() if directory else path.write_text("gitdir: elsewhere")
    with pytest.raises(ValueError, match="clean export"):
        source_tree(tmp_path)

@pytest.mark.skipif(os.name != "posix", reason="raw byte filenames require POSIX")
@pytest.mark.parametrize("alias,directory", [(False, False), (True, False), (False, True), (True, True)])
def test_source_export_refuses_invalid_utf8_without_aliasing(tmp_path, alias, directory):
    (tmp_path / "control").write_text("control")
    raw = os.fsencode(tmp_path) + b"/\xff"
    try:
        if directory:
            os.mkdir(raw)
            if alias: (tmp_path / "\ufffd").mkdir()
        else:
            with open(raw, "wb") as stream: stream.write(b"different bytes")
            if alias: (tmp_path / "\ufffd").write_bytes(b"benign alias")
    except OSError as error:
        if error.errno in (errno.EINVAL, errno.EILSEQ):
            pytest.skip("host refuses invalid-byte filenames")
        raise
    with pytest.raises(ValueError):
        source_tree(tmp_path)

@pytest.mark.skipif(os.name != "posix", reason="POSIX filename and FIFO controls")
@pytest.mark.parametrize("kind", ["backslash", "symlink", "fifo"])
def test_source_export_keeps_unsafe_entry_refusals(tmp_path, kind):
    (tmp_path / "control").write_text("control")
    if kind == "backslash": (tmp_path / "a\\b").write_text("x")
    elif kind == "symlink": (tmp_path / "link").symlink_to(tmp_path / "control")
    else: os.mkfifo(tmp_path / "pipe")
    with pytest.raises(ValueError): source_tree(tmp_path)

@pytest.mark.parametrize("name", ["CON.txt", "notes.", "cafe\u0301.txt", "\ue000.txt", "name:stream.txt"])
def test_raw_evidence_path_profile_remains_stricter(tmp_path, name):
    with pytest.raises(ValueError): confined_file(tmp_path, name)

def test_source_root_boundary_is_the_export(tmp_path):
    ordinary = tmp_path / "ordinary"
    nested = tmp_path / ".git" / "clean-export"
    for root in (ordinary, nested):
        root.mkdir(parents=True)
        (root / "control.txt").write_bytes(b"same source bytes\n")
    assert source_tree(ordinary) == source_tree(nested)
    with pytest.raises(ValueError, match="clean export"):
        source_tree(tmp_path / ".git")

@pytest.mark.skipif(os.name != "posix", reason="symlink creation requires host permission")
def test_source_root_symlink_is_not_a_clean_export(tmp_path):
    root = tmp_path / "source"; root.mkdir(); (root / "control").write_text("x")
    link = tmp_path / "link"; link.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        source_tree(link)

@pytest.mark.parametrize("spelling", [".", "refs/..", "refs/../."])
def test_metadata_root_alias_is_refused(tmp_path, monkeypatch, spelling):
    root = tmp_path / ".git"; (root / "refs").mkdir(parents=True)
    (root / "HEAD").write_text("same source bytes\n")
    monkeypatch.chdir(root)
    with pytest.raises(ValueError, match="clean export"):
        source_tree(Path(spelling))

@pytest.mark.skipif(os.name != "posix", reason="host symlink creation")
def test_lexical_root_alias_does_not_dereference_a_link(tmp_path):
    root = tmp_path / "source"; (root / "sub").mkdir(parents=True)
    (root / "control").write_text("x")
    link = tmp_path / "link"; link.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        source_tree(link / "sub" / "..")

def test_relative_source_root_preserves_hash(tmp_path, monkeypatch):
    (tmp_path / "control").write_text("x")
    expected = source_tree(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert source_tree(Path(".")) == expected
