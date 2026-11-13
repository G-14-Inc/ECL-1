"""Reproduce the 35 retained TLC recovery checks in a fresh output directory."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
from collections.abc import Sequence


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def configured_properties(text: str) -> list[str]:
    """All PROPERTY/PROPERTIES names, excluding comments and quoted values."""
    clean: list[str] = []
    index, depth = 0, 0
    while index < len(text):
        if not depth and text.startswith("\\*", index):
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
        elif not depth and text[index] == '"':
            # A quoted constant can contain comment delimiters or property names.
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                elif text[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            clean.append(" ")
        elif text.startswith("(*", index):
            depth += 1
            index += 2
            clean.append(" ")
        elif depth and text.startswith("*)", index):
            depth -= 1
            index += 2
        else:
            if not depth:
                clean.append(text[index])
            index += 1
    keywords = {
        "CONSTANT", "CONSTANTS", "INIT", "NEXT", "SPECIFICATION", "INVARIANT", "INVARIANTS",
        "PROPERTY", "PROPERTIES", "CONSTRAINT", "CONSTRAINTS", "ACTION_CONSTRAINT",
        "ACTION_CONSTRAINTS", "SYMMETRY", "VIEW", "ALIAS", "CHECK_DEADLOCK", "POSTCONDITION",
    }
    active, names = False, []
    for word in re.findall(r"\w+", "".join(clean)):
        if word in keywords:
            active = word in {"PROPERTY", "PROPERTIES"}
        elif active and word not in names:
            names.append(word)
    return names


def outcome_matches(code: int | None, output: str, expected: str, config: str) -> bool:
    """Match a named counterexample, or the sole configured liveness property."""
    if expected == "no error":
        return code == 0 and "Model checking completed. No error has been found." in output
    if code not in (12, 13):
        return False
    named = re.search(
        r"(?:Invariant|Action property) " + re.escape(expected) + r" is violated\.", output
    )
    if named:
        return True
    # TLC 1.7.4 can report a temporal violation without naming the property.
    # Attribute it only when all uncommented declarations name that one property.
    return configured_properties(config) == [expected] and "Temporal properties were violated." in output


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jar", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--java", default="java")
    parser.add_argument("--timeout", type=int, default=1200, help="Seconds per check")
    args = parser.parse_args(argv)
    if args.timeout < 1:
        parser.error("--timeout must be positive")

    packet = Path(__file__).resolve().parent / "diagnostics/2026-11-10-recovery"
    record_path = packet / "COMBINED-RESULTS.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    jar = args.jar.resolve()
    if sha256(jar) != record["tool_sha256"]:
        parser.error("TLC JAR does not match the recorded pin")
    # Validate every retained input before creating output or launching Java.
    for case in record["cases"]:
        for filename, digest in case["inputs"].items():
            source = packet / case["name"] / filename
            if sha256(source) != digest:
                parser.error("input hash mismatch: " + str(source))
    # Probe Java before reserving the result directory. A missing or failed
    # executable must not leave a directory that appears to be a started run.
    found_java = shutil.which(args.java)
    if found_java is None:
        parser.error(f"Java executable not found: {args.java}")
    # Case processes run in their own directories, so retain an absolute path
    # even when --java or the matching PATH entry was relative to the caller.
    java_bin = str(Path(found_java).resolve())
    try:
        version = subprocess.run(
            [java_bin, "-version"], capture_output=True, text=True, check=True,
            encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.CalledProcessError) as error:
        parser.error(f"Java version probe failed: {error}")
    java_version = version.stdout + version.stderr
    output_root = args.output.resolve()
    output_root.mkdir(parents=True, exist_ok=False)
    results = []
    report = {
        "started_from_record_sha256": sha256(record_path),
        "runner_sha256": sha256(Path(__file__)),
        "java_version": java_version,
        "tool_sha256": sha256(jar),
        "cases": results,
    }
    for case in record["cases"]:
        directory = output_root / case["name"]
        directory.mkdir()
        for filename in case["inputs"]:
            shutil.copyfile(packet / case["name"] / filename, directory / filename)
        config = (directory / "case.cfg").read_text(encoding="utf-8")
        command = [
            java_bin, "-Xmx1800m", "-XX:+UseParallelGC", "-cp", str(jar), "tlc2.TLC",
            "-workers", "2", "-metadir", str(directory / "states"),
            "-config", "case.cfg", "RecoveryReview.tla",
        ]
        started = time.monotonic()
        with (directory / "stdout.log").open("wb") as stdout, (directory / "stderr.log").open("wb") as stderr:
            try:
                code = subprocess.run(
                    command, cwd=directory, stdout=stdout, stderr=stderr, timeout=args.timeout
                ).returncode
            except subprocess.TimeoutExpired:
                code = None
            except OSError as error:
                code = None
                stderr.write(f"{type(error).__name__}: {error}\n".encode("utf-8", errors="replace"))
        matched = outcome_matches(code, (directory / "stdout.log").read_text(encoding="utf-8", errors="replace"), case["expected"], config)
        results.append({
            "name": case["name"],
            "expected": case["expected"],
            "expected_outcome_matched": matched,
            "returncode": code,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "command": command,
            "inputs": case["inputs"],
            "outputs": {name: sha256(directory / name) for name in ("stdout.log", "stderr.log")},
        })
        report.update({
            "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "complete": len(results) == len(record["cases"]),
            "all_expected_outcomes_matched": all(item["expected_outcome_matched"] for item in results),
        })
        (output_root / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(case["name"], matched, flush=True)
        if not matched:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
