"""Run the formal checks of formal/: TLC on the TLA+ model and Tamarin on the protocol model.

Every check has an expected outcome. The correct design passes every property and proves every
lemma; each deliberately broken variant and each reachability witness yields the counterexample
named for it. The run fails when any outcome differs from its expectation, so a property that
stops catching its flaw fails the run as surely as a property that stops holding.

The tools are not dependencies of the repository. The script finds them through the options or
the environment (ECL_TLA2TOOLS_JAR, ECL_TAMARIN_PROVER, ECL_MAUDE_DIR, or `tamarin-prover` and
`maude` on PATH), checks the pinned versions and SHA-256 digests in PINS, and otherwise prints
how to get them and exits with status 2.

`--record FILE` writes each result with the SHA-256 digests of the model files it ran on, so a
record that no longer matches the models is detectable; results of checks that did not run in
this invocation are kept from an existing FILE. `--readme` renders the results tables of
formal/README.md from formal/results.json and needs no tools. formal/README.md describes the
checks and the results.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

FORMAL = Path(__file__).resolve().parent
TLA = FORMAL / "tla"
PROTOCOL = FORMAL / "protocol"
THEORY = "DCMP2_Binding.spthy"
RESULTS = FORMAL / "results.json"
README = FORMAL / "README.md"
RECORD_SCHEMA = "ecl_formal_results_v1"
JAVA_HEAP = "-Xmx1500m"
DEFAULT_TIMEOUT = 900
START = "<!-- formal:results -->"
END = "<!-- /formal:results -->"

PINS = {
    "tla2tools": {
        "version": "1.7.4",
        "source": "https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar",
        "sha256": "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88",
    },
    "tamarin": {
        "version": "1.12.0",
        "source": "https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/"
        "tamarin-prover-1.12.0-linux64-ubuntu.tar.gz",
        "archive_sha256": "201be06f469e47cff554df6ca93db8366fc2c69d70c61fcbd1370a1074b469c6",
        "sha256": "9d3fcbaa65aeea244cff5b8074338d129427161cc8b02e5aee72d30ee072acc9",
    },
    "maude": {
        "version": "3.5.1",
        "source": "https://github.com/maude-lang/Maude/releases/download/Maude3.5.1/"
        "Maude-3.5.1-linux-x86_64.zip",
        "archive_sha256": "72ed1ca87e3b3d0dfc6ee1436baf154bf04c45ff97d521bec040c5e8dfc8f92c",
        "sha256": "9dd4044e693944aae97ad72086bc70275fa34bf635f9b377a5b2100bf3ed8655",
    },
}

# TLC: configuration name -> expected outcome, "pass" or the property its counterexample breaks.
TLC_CHECKS: dict[str, str] = {
    "correct-binding": "pass",
    "correct-control": "pass",
    "correct-liveness": "pass",
    "broken-outage-proceeds": "NoEffectDuringOutage",
    "broken-late-decision-used": "SafeStateHasNoEffect",
    "broken-no-digest-binding": "EffectHasMatchingAdmit",
    "broken-no-target-binding": "EffectHasMatchingAdmit",
    "broken-no-audience-binding": "EffectWithinAuthority",
    "broken-no-window": "EffectWithinAuthority",
    "broken-no-single-use": "SingleUse",
    "broken-ignore-revocation": "NoEffectWithKnownRevocation",
    "broken-ignore-staleness": "NoEffectDuringOutage",
    "broken-no-propagation-deadline": "RevocationBound",
    "broken-ignore-halt": "NoEffectAtHaltedEP",
    "broken-halt-unbounded": "NoEffectBeyondHaltBound",
    "broken-evidence-not-atomic": "EffectHasEvidence",
    "broken-bypass": "EffectHasMatchingAdmit",
    "broken-actor-writes-authority": "EffectHasMatchingAdmit",
    "broken-actor-writes-decision": "AdmitOnlyAllowed",
    "broken-actor-erases-evidence": "LogAppendOnly",
    "broken-judgment-admits": "OneWayRule",
    "broken-self-report-admits": "OneWayRule",
    "broken-hold-never-times-out": "HoldResolves",
    "broken-no-decision-timeout": "RequestResolves",
    "broken-halt-ack-lost": "HaltTakesEffect",
    "witness-effect": "WitnessNoEffect",
    "witness-admit-after-hold": "WitnessNoAdmitAfterHold",
    "witness-collision-deny": "WitnessNoCollisionDeny",
    "witness-effect-during-outage": "WitnessNoEffectDuringOutage",
    "witness-effect-in-revocation-window": "WitnessNoEffectInRevocationWindow",
    "witness-effect-in-halt-window": "WitnessNoEffectInHaltWindow",
    "witness-timeout": "WitnessNoTimeout",
}

LIVENESS = ("HoldResolves", "RequestResolves", "HaltTakesEffect")

LEMMAS = (
    "executable",
    "request_origin",
    "response_authenticity",
    "request_response_binding",
    "authorization_scope_and_audience",
    "single_use",
    "one_effect_per_request",
)

# Tamarin: check name -> (preprocessor flag or None, lemma it falsifies or None for all proved).
TAMARIN_CHECKS: dict[str, tuple[str | None, str | None]] = {
    "protocol-correct": (None, None),
    "protocol-skip-response-signature": ("skip_response_signature", "response_authenticity"),
    "protocol-shared-role-key": ("shared_role_key", "response_authenticity"),
    "protocol-response-not-bound": ("response_not_bound", "request_response_binding"),
    "protocol-no-scope-check": ("no_scope_check", "authorization_scope_and_audience"),
    "protocol-no-audience-check": ("no_audience_check", "authorization_scope_and_audience"),
    "protocol-no-single-use": ("no_single_use", "single_use"),
    "protocol-dp-no-message-identity": ("dp_no_message_identity", "one_effect_per_request"),
    "protocol-dp-skips-request-signature": ("dp_skips_request_signature", "request_origin"),
}

_VIOLATION = re.compile(r"Error: (?:Invariant|Action property) (\w+) is violated")
_STATES = re.compile(
    r"([\d,]+) states generated, ([\d,]+) distinct states found, ([\d,]+) states left on queue"
)
_DEPTH = re.compile(r"The depth of the complete state graph search is (\d+)")
_TRACE_STATE = re.compile(r"^State \d+:", re.MULTILINE)
_ILL_FORMED = re.compile(r"wellformedness checks? failed")
_SUMMARY = re.compile(
    r"^\s+(\w+) \((?:all-traces|exists-trace)\): "
    r"(verified|falsified - found trace|analysis incomplete)(?: \((\d+) steps\))?",
    re.MULTILINE,
)


@dataclass
class Result:
    name: str
    tool: str
    expected: str
    observed: str
    passed: bool
    seconds: float
    states_generated: int | None = None
    distinct_states: int | None = None
    depth: int | None = None
    trace_states: int | None = None
    lemmas: dict[str, str] = field(default_factory=dict)
    steps: dict[str, int] = field(default_factory=dict)
    inputs: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Tools:
    java: str | None
    tla2tools: Path | None
    tamarin: Path | None
    maude_dir: Path | None


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def number(text: str) -> int:
    return int(text.replace(",", ""))


def inputs(name: str) -> dict[str, str]:
    """The model files check `name` runs on, relative to formal/, with their SHA-256 digests."""
    if name in TLC_CHECKS:
        files = [TLA / "ECLCore.tla", TLA / "MC.tla", TLA / "configs" / f"{name}.cfg"]
    else:
        files = [PROTOCOL / THEORY]
    return {path.relative_to(FORMAL).as_posix(): sha256(path) for path in files}


def tlc_command(tools: Tools, name: str, workdir: Path) -> list[str]:
    if tools.java is None or tools.tla2tools is None:
        raise ValueError("TLC needs java and tla2tools.jar")
    return [
        tools.java,
        JAVA_HEAP,
        "-XX:+UseParallelGC",
        f"-Djava.io.tmpdir={workdir}",
        "-cp",
        str(tools.tla2tools),
        "tlc2.TLC",
        "-workers",
        "1",
        "-metadir",
        str(workdir / name),
        "-config",
        f"configs/{name}.cfg",
        "MC.tla",
    ]


def checked_liveness(name: str) -> list[str]:
    """The liveness properties that configuration `name` checks."""
    text = (TLA / "configs" / f"{name}.cfg").read_text(encoding="utf-8")
    return [word for word in re.findall(r"\w+", text) if word in LIVENESS]


def parse_tlc(name: str, expected: str, output: str, seconds: float) -> Result:
    if "Model checking completed. No error has been found." in output:
        observed = "pass"
    elif match := _VIOLATION.search(output):
        observed = match.group(1)
    elif "Error: Temporal properties were violated." in output:
        # TLC does not name the temporal property; a configuration that checks only one does.
        liveness = checked_liveness(name)
        observed = liveness[0] if len(liveness) == 1 else "temporal"
    else:
        observed = "error"
    result = Result(name, "tlc", expected, observed, observed == expected, round(seconds, 1))
    if states := _STATES.findall(output):
        generated, distinct, _queue = states[-1]
        result.states_generated, result.distinct_states = number(generated), number(distinct)
    if depth := _DEPTH.search(output):
        result.depth = int(depth.group(1))
    if observed != "pass":
        result.trace_states = len(_TRACE_STATE.findall(output)) or None
    return result


def run_tlc(tools: Tools, name: str, timeout: int, workdir: Path) -> Result:
    expected = TLC_CHECKS[name]
    start = time.monotonic()
    try:
        # The command is this module's own: the pinned tools on the committed configurations.
        completed = subprocess.run(  # noqa: S603
            tlc_command(tools, name, workdir),
            cwd=TLA,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = completed.stdout + completed.stderr
    except subprocess.TimeoutExpired:
        return Result(name, "tlc", expected, "timeout", False, float(timeout))
    result = parse_tlc(name, expected, output, time.monotonic() - start)
    result.inputs = inputs(name)
    return result


def tamarin_command(tools: Tools, flag: str | None, lemma: str | None) -> list[str]:
    if tools.tamarin is None:
        raise ValueError("Tamarin checks need tamarin-prover")
    command = [str(tools.tamarin), "--derivcheck-timeout=0"]
    command.append("--prove" if lemma is None else f"--prove={lemma}")
    if flag is not None:
        command.append(f"-D={flag}")
    return [*command, THEORY, "+RTS", "-N1", "-M1500m", "-RTS"]


def parse_tamarin(name: str, lemma: str | None, output: str, seconds: float) -> Result:
    found = _SUMMARY.findall(output)
    lemmas = {match[0]: match[1] for match in found}
    steps = {match[0]: int(match[2]) for match in found if match[2]}
    wellformed = _ILL_FORMED.search(output) is None
    if lemma is None:
        expected = "all verified"
        observed = (
            "all verified"
            if wellformed and all(lemmas.get(item) == "verified" for item in LEMMAS)
            else "not proved"
        )
    else:
        expected = f"{lemma} falsified"
        observed = (
            f"{lemma} falsified"
            if wellformed and lemmas.get(lemma) == "falsified - found trace"
            else f"{lemma} {lemmas.get(lemma, 'not analyzed')}"
        )
    result = Result(name, "tamarin", expected, observed, observed == expected, round(seconds, 1))
    analyzed = LEMMAS if lemma is None else (lemma,)
    result.lemmas = {item: lemmas.get(item, "not analyzed") for item in analyzed}
    result.steps = {item: steps[item] for item in analyzed if item in steps}
    return result


def run_tamarin(tools: Tools, name: str, timeout: int) -> Result:
    flag, lemma = TAMARIN_CHECKS[name]
    environment = dict(os.environ, LC_ALL="C.UTF-8", LANG="C.UTF-8")
    if tools.maude_dir is not None:
        environment["PATH"] = f"{tools.maude_dir}{os.pathsep}{environment.get('PATH', '')}"
    start = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603
            tamarin_command(tools, flag, lemma),
            cwd=PROTOCOL,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
            check=False,
        )
        output = completed.stdout + completed.stderr
    except subprocess.TimeoutExpired:
        expected = "all verified" if lemma is None else f"{lemma} falsified"
        return Result(name, "tamarin", expected, "timeout", False, float(timeout))
    result = parse_tamarin(name, lemma, output, time.monotonic() - start)
    result.inputs = inputs(name)
    return result


def find_tools(arguments: argparse.Namespace) -> Tools:
    def path(option: str | None, variable: str, command: str | None = None) -> Path | None:
        value = option or os.environ.get(variable)
        if value:
            return Path(value)
        found = shutil.which(command) if command else None
        return Path(found) if found else None

    tamarin = path(arguments.tamarin, "ECL_TAMARIN_PROVER", "tamarin-prover")
    maude_dir = path(arguments.maude_dir, "ECL_MAUDE_DIR")
    if maude_dir is None and (maude := shutil.which("maude")):
        maude_dir = Path(maude).parent
    return Tools(
        java=arguments.java or shutil.which("java"),
        tla2tools=path(arguments.tla2tools, "ECL_TLA2TOOLS_JAR"),
        tamarin=tamarin,
        maude_dir=maude_dir,
    )


def pin_problems(tools: Tools, *, tlc: bool, tamarin: bool) -> list[str]:
    """Why the tools cannot run the checks as pinned: missing, or another version."""
    problems: list[str] = []
    if tlc:
        if tools.java is None:
            problems.append("java (21 or later) is not on PATH")
        if tools.tla2tools is None or not tools.tla2tools.is_file():
            problems.append("tla2tools.jar not found: pass --tla2tools or set ECL_TLA2TOOLS_JAR")
        elif sha256(tools.tla2tools) != PINS["tla2tools"]["sha256"]:
            problems.append(f"{tools.tla2tools.name} is not the pinned tla2tools.jar 1.7.4")
    if tamarin:
        if tools.tamarin is None or not tools.tamarin.is_file():
            problems.append("tamarin-prover not found: pass --tamarin or set ECL_TAMARIN_PROVER")
        elif sha256(tools.tamarin) != PINS["tamarin"]["sha256"]:
            problems.append("tamarin-prover is not the pinned 1.12.0 Linux binary")
        maude = tools.maude_dir / "maude" if tools.maude_dir is not None else None
        if maude is None or not maude.is_file():
            problems.append("maude not found: pass --maude-dir or set ECL_MAUDE_DIR")
        elif sha256(maude) != PINS["maude"]["sha256"]:
            problems.append("maude is not the pinned 3.5.1 Linux binary")
    return problems


def java_version(java: str) -> str | None:
    """The version that `java -version` reports, such as 21.0.10, or None."""
    try:
        completed = subprocess.run(  # noqa: S603
            [java, "-version"], capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r'version "([^"]+)"', completed.stdout + completed.stderr)
    return match.group(1) if match else None


def write_record(path: Path, results: list[Result], tools: Tools, timeout: int) -> None:
    """Write `results` to `path`, keeping the results of other checks from an existing record."""
    settings = {"java_heap": JAVA_HEAP, "tlc_workers": 1, "timeout_seconds": timeout}
    pins = {
        name: {key: value for key, value in pin.items() if key != "source"}
        for name, pin in PINS.items()
    }
    kept: list[dict[str, object]] = []
    java = java_version(tools.java) if tools.java else None
    if path.exists():
        earlier = json.loads(path.read_text(encoding="utf-8"))
        if earlier.get("schema_version") != RECORD_SCHEMA:
            raise ValueError(f"{path} is not a formal results record")
        if earlier.get("settings") != settings or earlier.get("tools") != pins:
            raise ValueError(f"{path} was recorded with other settings or tools; remove it first")
        ran = {result.name for result in results}
        kept = [check for check in earlier["checks"] if check["name"] not in ran]
        java = java if any(result.tool == "tlc" for result in results) else earlier.get("java")
    order = {name: index for index, name in enumerate([*TLC_CHECKS, *TAMARIN_CHECKS])}
    checks = sorted(
        [*kept, *(asdict(result) for result in results)],
        key=lambda check: order.get(str(check["name"]), len(order)),
    )
    record = {
        "schema_version": RECORD_SCHEMA,
        "tools": pins,
        "java": java,
        "settings": settings,
        "checks": checks,
    }
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, int):
        return f"{value:,}"
    return str(value)


def outcome(value: str) -> str:
    return "no error" if value == "pass" else f"`{value}`"


def tlc_row(check: dict[str, Any]) -> str:
    cells = [
        f"`{check['name']}`",
        outcome(check["expected"]),
        outcome(check["observed"]),
        *(cell(check[key]) for key in ("distinct_states", "states_generated", "depth")),
        cell(check["trace_states"]),
        cell(check["seconds"]),
    ]
    return "| " + " | ".join(cells) + " |"


def tamarin_rows(check: dict[str, Any]) -> list[str]:
    rows = []
    lemmas = [lemma for lemma in LEMMAS if lemma in check["lemmas"]]
    for index, lemma in enumerate(lemmas):
        status, first = check["lemmas"][lemma], index == 0
        rows.append(
            f"| {'`' + check['name'] + '`' if first else ''} | `{lemma}` | {status}"
            f" | {cell(check['steps'].get(lemma))} | {cell(check['seconds']) if first else ''} |"
        )
    return rows


def render(record: dict[str, Any]) -> str:
    """The results tables of formal/README.md for `record`."""
    checks: list[dict[str, Any]] = record["checks"]
    lines = [
        START,
        "| TLC check | Expected | Observed | Distinct states | States generated | Depth"
        " | Trace states | Seconds |",
        "|---|---|---|---:|---:|---:|---:|---:|",
    ]
    lines.extend(tlc_row(check) for check in checks if check["tool"] == "tlc")
    lines += [
        "",
        "| Tamarin check | Lemma | Result | Proof steps | Seconds |",
        "|---|---|---|---:|---:|",
    ]
    for check in checks:
        if check["tool"] == "tamarin":
            lines.extend(tamarin_rows(check))
    lines.append(END)
    return "\n".join(lines)


def update_readme(*, check: bool) -> int:
    """Render the results tables of formal/README.md from formal/results.json."""
    record = json.loads(RESULTS.read_text(encoding="utf-8"))
    text = README.read_text(encoding="utf-8")
    pattern = re.compile(re.escape(START) + r".*?" + re.escape(END), re.DOTALL)
    blocks = list(pattern.finditer(text))
    if len(blocks) != 1:
        print("formal/README.md: the results block is missing or ambiguous", file=sys.stderr)
        return 1
    expected = render(record)
    if check:
        if blocks[0].group() != expected:
            print("formal/README.md: the results tables are stale", file=sys.stderr)
            return 1
        return 0
    README.write_text(text[: blocks[0].start()] + expected + text[blocks[0].end() :], "utf-8")
    return 0


def instructions() -> str:
    lines = ["The formal checks need tools that are not repository dependencies:"]
    for name, pin in PINS.items():
        lines.append(f"  {name} {pin['version']}: {pin['source']}")
        if "archive_sha256" in pin:
            lines.append(f"    archive SHA-256 {pin['archive_sha256']}")
        lines.append(f"    {'jar' if name == 'tla2tools' else 'binary'} SHA-256 {pin['sha256']}")
    lines.append("Java 21 runs TLC. See formal/README.md, 'Running the checks'.")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--tla2tools", help="path to the pinned tla2tools.jar")
    parser.add_argument("--tamarin", help="path to the pinned tamarin-prover binary")
    parser.add_argument("--maude-dir", help="directory that holds the pinned maude binary")
    parser.add_argument("--java", help="the java to run TLC with (default: java on PATH)")
    parser.add_argument("--only", action="append", default=[], metavar="CHECK")
    parser.add_argument("--skip-tlc", action="store_true")
    parser.add_argument("--skip-tamarin", action="store_true")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, metavar="SECONDS")
    parser.add_argument("--record", type=Path, metavar="FILE", help="write the results as JSON")
    parser.add_argument("--allow-unpinned", action="store_true", help="run other tool versions")
    parser.add_argument(
        "--readme", action="store_true", help="render the README results from the record and stop"
    )
    arguments = parser.parse_args(argv)
    if arguments.readme:
        return update_readme(check=False)

    names = [*TLC_CHECKS, *TAMARIN_CHECKS]
    unknown = sorted(set(arguments.only) - set(names))
    if unknown:
        parser.error(f"unknown check: {', '.join(unknown)}")
    selected = [name for name in names if not arguments.only or name in arguments.only]
    tlc_names = [name for name in selected if name in TLC_CHECKS and not arguments.skip_tlc]
    tamarin_names = [
        name for name in selected if name in TAMARIN_CHECKS and not arguments.skip_tamarin
    ]
    tools = find_tools(arguments)
    problems = pin_problems(tools, tlc=bool(tlc_names), tamarin=bool(tamarin_names))
    missing = [
        problem for problem in problems if "not found" in problem or "not on PATH" in problem
    ]
    if missing or (problems and not arguments.allow_unpinned):
        print("\n".join(f"error: {problem}" for problem in problems), file=sys.stderr)
        print(instructions(), file=sys.stderr)
        return 2

    results: list[Result] = []
    with tempfile.TemporaryDirectory(prefix="ecl-formal-") as scratch:
        workdir = Path(scratch)
        for name in tlc_names:
            results.append(run_tlc(tools, name, arguments.timeout, workdir))
            print(summary(results[-1]), flush=True)
        for name in tamarin_names:
            results.append(run_tamarin(tools, name, arguments.timeout))
            print(summary(results[-1]), flush=True)

    if arguments.record is not None:
        if problems:
            print("error: a record needs the pinned tools", file=sys.stderr)
            return 2
        write_record(arguments.record, results, tools, arguments.timeout)
    failed = [result.name for result in results if not result.passed]
    print(f"{len(results) - len(failed)} of {len(results)} checks as expected")
    return 1 if failed else 0


def summary(result: Result) -> str:
    states = f" {result.distinct_states} states" if result.distinct_states is not None else ""
    verdict = "ok" if result.passed else "UNEXPECTED"
    return (
        f"{verdict:10} {result.name:40} expected {result.expected!r}, observed {result.observed!r}"
        f"{states} in {result.seconds} s"
    )


if __name__ == "__main__":
    sys.exit(main())
