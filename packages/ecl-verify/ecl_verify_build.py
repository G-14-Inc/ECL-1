"""Ship the ECL-1 schemas and registries in the ecl-verify wheel, as ecl_verify/_data/.

The verifier reads the JSON schemas and registries of the ECL-1 package. In a checkout of the
ECL-1 repository they are the top-level `schemas/` and `registries/`, two levels above this file,
and the modules read them there. A wheel carries a copy under `ecl_verify/_data/`, which this
build step writes; the source tree never holds a second copy. An editable install skips the copy.

The copy holds the files of the ECL-1 specification package only: where the repository's
`release/package-scope.json` exists (G-14's own repository), the files it classes `public` or
`both`; where it does not (the published package, which holds no other files), every `*.json` file
of the two folders. pyproject.toml names this class in `[tool.setuptools.cmdclass]`.

Build a wheel with `uv build --wheel` or `pip wheel`, from a checkout or the unpacked package. An
sdist would lack the data, since it holds this folder only: build the wheel from the tree.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from setuptools import build_meta as _build_meta
from setuptools.command.build_py import build_py
from setuptools.errors import FileError

# PEP 517 requires a backend named alongside backend-path to live in that path.
# Keep this module importable for the cmdclass and delegate the standard hooks.
build_wheel = _build_meta.build_wheel
build_sdist = _build_meta.build_sdist
get_requires_for_build_wheel = _build_meta.get_requires_for_build_wheel
get_requires_for_build_sdist = _build_meta.get_requires_for_build_sdist
prepare_metadata_for_build_wheel = _build_meta.prepare_metadata_for_build_wheel
build_editable = _build_meta.build_editable
get_requires_for_build_editable = _build_meta.get_requires_for_build_editable
prepare_metadata_for_build_editable = _build_meta.prepare_metadata_for_build_editable

PROJECT = Path(__file__).resolve().parent
REPOSITORY = PROJECT.parent.parent
DATA_DIRECTORIES = ("schemas", "registries")
SCOPE = "release/package-scope.json"
IN_PUBLIC_PACKAGE = frozenset({"public", "both"})


def public_files(repository: Path) -> frozenset[str] | None:
    """The paths that the package scope places in the specification package, if it is present."""
    scope = repository / SCOPE
    if not scope.is_file():
        return None
    entries = json.loads(scope.read_text(encoding="utf-8"))["files"]
    return frozenset(entry["path"] for entry in entries if entry["class"] in IN_PUBLIC_PACKAGE)


def data_files(repository: Path) -> dict[str, list[Path]]:
    """The schema and registry files that the wheel bundles, by folder."""
    published = public_files(repository)
    found: dict[str, list[Path]] = {}
    for name in DATA_DIRECTORIES:
        files = sorted((repository / name).glob("*.json"))
        if published is not None:
            files = [path for path in files if f"{name}/{path.name}" in published]
        if not files:
            raise FileError(
                f"{repository / name} has no JSON files to bundle, so the wheel would ship"
                " without them. Build the wheel from a checkout or the unpacked ECL-1 package."
            )
        found[name] = files
    return found


class BuildPy(build_py):
    """build_py, then the data copy into the build's ecl_verify/_data/."""

    def run(self) -> None:
        super().run()
        if self.editable_mode:
            return
        bundled = Path(self.build_lib) / "ecl_verify" / "_data"
        if bundled.exists():
            shutil.rmtree(bundled)  # no ignore_errors: a copy that stays may be stale
        for name, files in data_files(REPOSITORY).items():
            self.mkpath(str(bundled / name))
            for file in files:
                self.copy_file(str(file), str(bundled / name / file.name), preserve_mode=False)
