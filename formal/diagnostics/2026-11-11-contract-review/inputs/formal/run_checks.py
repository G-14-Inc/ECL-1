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
import datetime
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
RECORD_SCHEMA = "ecl_formal_results_v2"
JAVA_HEAP = "-Xmx1500m"
DEFAULT_TIMEOUT = 900
DERIVCHECK_TIMEOUT = 0  # Historical command; positive seconds enable derivation diagnostics.
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
    "broken-ignore-staleness": "ControlStateFreshAtEffect",
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
    "witness-admit-after-challenge": "WitnessNoAdmitAfterChallenge",
    "witness-collision-refusal": "WitnessNoCollisionRefusal",
    "witness-effect-during-outage": "WitnessNoEffectDuringOutage",
    "witness-effect-in-revocation-window": "WitnessNoEffectInRevocationWindow",
    "witness-effect-in-halt-window": "WitnessNoEffectInHaltWindow",
    "witness-timeout": "WitnessNoTimeout",
    "correct-continuation": "pass",
    "correct-delayed-continuation": "pass",
    "broken-continuation-binding": "ContinuationAdmitBound",
    "broken-approval-reuse": "OneAdmittingContinuation",
    "broken-expired-approval": "ContinuationAdmitBound",
    "broken-revoked-approval": "NoContinuationWithRevokedApproval",
    "witness-approval-replay-refused": "WitnessNoApprovalReplayRefusal",
    "witness-later-continuation": "WitnessNoLaterContinuationDecision",
    "broken-recovery-without-reconciliation": "RecoveryBeforeNormal",
    "broken-recovered-trust-state": "NoRecoveredEffectOnUnreconciledState",
    "broken-restriction-bypass": "NoEffectWhileRestricted",
    "broken-stale-recovery-proof": "RestrictionLiftRequiresFreshProof",
    "broken-unrecorded-restriction-lift": "RestrictionLiftRequiresFreshProof",
    "witness-effect-after-reconciliation": "WitnessNoEffectAfterRecovery",
    "witness-effect-after-short-outage": "WitnessNoEffectAfterShortOutage",
    "witness-revalidated-authority-after-restriction": "WitnessNoRevalidatedAuthorityAfterRestriction",
    "broken-connected-stale-view": "ControlStateFreshAtEffect",
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
    "execution_request_binding",
    "agent_signed_executable",
)

# Tamarin: check name -> (preprocessor flag or None, lemma it falsifies or None for all proved).
TAMARIN_CHECKS: dict[str, tuple[str | None, str | None]] = {
    "protocol-correct": (None, None),
    "protocol-skip-response-signature": ("skip_response_signature", "response_authenticity"),
    "protocol-shared-role-key": ("shared_role_key", "response_authenticity"),
    "protocol-response-not-bound": ("response_not_bound", "request_response_binding"),
    "protocol-presentation-not-bound": ("presentation_not_bound", "execution_request_binding"),
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
    started_utc: str | None = None
    finished_utc: str | None = None
    java: str | None = None
    runner_sha256: str | None = None
    command: list[str] = field(default_factory=list)
    returncode: int | None = None
    output_sha256: str | None = None
    log_file: str | None = None


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


def checked_properties(name: str) -> list[str]:
    """All PROPERTY/PROPERTIES names, excluding comments and quoted values."""
    text = (TLA / "configs" / f"{name}.cfg").read_text(encoding="utf-8")
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


def checked_liveness(name: str) -> list[str]:
    """Known liveness names; not sufficient to attribute an unnamed failure."""
    return [name for name in checked_properties(name) if name in LIVENESS]


def parse_tlc(name: str, expected: str, output: str, seconds: float) -> Result:
    if "Model checking completed. No error has been found." in output:
        observed = "pass"
    elif match := _VIOLATION.search(output):
        observed = match.group(1)
    elif "Error: Temporal properties were violated." in output:
        # TLC does not name the temporal property; a configuration that checks only one does.
        properties = checked_properties(name)
        observed = properties[0] if len(properties) == 1 else "temporal"
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


def execute_check(
    tools: Tools, name: str, timeout: int, command: list[str], cwd: Path,
    *, environment: dict[str, str] | None = None, log_dir: Path | None = None,
) -> Result:
    """Bind successful, failed and timed-out checks to the bytes present before execution."""
    tlc = name in TLC_CHECKS
    lemma = None if tlc else TAMARIN_CHECKS[name][1]
    expected = TLC_CHECKS[name] if tlc else (
        "all verified" if lemma is None else f"{lemma} falsified"
    )
    digests = inputs(name)
    runner_digest = sha256(Path(__file__))
    java = java_version(tools.java) if tlc and tools.java else None
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    start = time.monotonic()
    returncode = None
    try:
        completed = subprocess.run(  # noqa: S603
            command, cwd=cwd, capture_output=True, text=True, timeout=timeout,
            env=environment, check=False,
        )
        output = completed.stdout + completed.stderr
        returncode = completed.returncode
        seconds = time.monotonic() - start
        result = parse_tlc(name, expected, output, seconds) if tlc else parse_tamarin(
            name, lemma, output, seconds
        )
        # TLC uses nonzero status for expected counterexamples. A success banner
        # accompanying abnormal exit is not a successful exhaustive check.
        if returncode != 0 and (not tlc or result.observed == "pass"):
            result.observed, result.passed = "tool-error", False
    except subprocess.TimeoutExpired as error:
        def decoded(value: str | bytes | None) -> str:
            return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""
        output = decoded(error.stdout) + decoded(error.stderr)
        result = Result(name, "tlc" if tlc else "tamarin", expected, "timeout", False,
                        round(time.monotonic() - start, 1))
    except OSError as error:
        output = f"{type(error).__name__}: {error}\n"
        result = Result(name, "tlc" if tlc else "tamarin", expected, "tool-error", False,
                        round(time.monotonic() - start, 1))
    result.inputs = digests
    if inputs(name) != digests or sha256(Path(__file__)) != runner_digest:
        result.observed, result.passed = "inputs-changed", False
    result.started_utc, result.finished_utc = started, datetime.datetime.now(datetime.timezone.utc).isoformat()
    result.java, result.runner_sha256 = java, runner_digest
    result.command, result.returncode = command, returncode
    result.output_sha256 = hashlib.sha256(output.encode("utf-8")).hexdigest()
    if log_dir is not None:
        log = log_dir / f"{name}.log"
        with log.open("x", encoding="utf-8") as stream:
            stream.write(output)
        result.log_file = log.name
    return result


def run_tlc(
    tools: Tools, name: str, timeout: int, workdir: Path, log_dir: Path | None = None,
) -> Result:
    return execute_check(tools, name, timeout, tlc_command(tools, name, workdir), TLA,
                         log_dir=log_dir)


def tamarin_command(
    tools: Tools, flag: str | None, lemma: str | None, derivcheck: int = DERIVCHECK_TIMEOUT,
) -> list[str]:
    if tools.tamarin is None:
        raise ValueError("Tamarin checks need tamarin-prover")
    command = [str(tools.tamarin), f"--derivcheck-timeout={derivcheck}"]
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


def run_tamarin(
    tools: Tools, name: str, timeout: int, derivcheck: int = DERIVCHECK_TIMEOUT,
    log_dir: Path | None = None,
) -> Result:
    flag, lemma = TAMARIN_CHECKS[name]
    environment = dict(os.environ, LC_ALL="C.UTF-8", LANG="C.UTF-8")
    if tools.maude_dir is not None:
        environment["PATH"] = f"{tools.maude_dir}{os.pathsep}{environment.get('PATH', '')}"
    return execute_check(tools, name, timeout, tamarin_command(tools, flag, lemma, derivcheck),
                         PROTOCOL, environment=environment, log_dir=log_dir)


def find_tools(arguments: argparse.Namespace) -> Tools:
    def path(option: str | None, variable: str, command: str | None = None) -> Path | None:
        value = option or os.environ.get(variable)
        if value:
            return Path(value).resolve()
        found = shutil.which(command) if command else None
        return Path(found).resolve() if found else None

    tamarin = path(arguments.tamarin, "ECL_TAMARIN_PROVER", "tamarin-prover")
    maude_dir = path(arguments.maude_dir, "ECL_MAUDE_DIR")
    if maude_dir is None and (maude := shutil.which("maude")):
        maude_dir = Path(maude).resolve().parent
    java = shutil.which(arguments.java or "java")
    return Tools(
        java=str(Path(java).resolve()) if java else None,
        tla2tools=path(arguments.tla2tools, "ECL_TLA2TOOLS_JAR"),
        tamarin=tamarin,
        maude_dir=maude_dir,
    )


def pin_problems(tools: Tools, *, tlc: bool, tamarin: bool) -> list[str]:
    """Why the tools cannot run the checks as pinned: missing, or another version."""
    problems: list[str] = []
    if tlc:
        if tools.java is None:
            problems.append("java not found: pass an executable --java or put java on PATH")
        elif shutil.which(tools.java) is None:
            problems.append(f"java not found: {tools.java} is not executable")
        if tools.tla2tools is None or not tools.tla2tools.is_file():
            problems.append("tla2tools.jar not found: pass --tla2tools or set ECL_TLA2TOOLS_JAR")
        elif sha256(tools.tla2tools) != PINS["tla2tools"]["sha256"]:
            problems.append(f"{tools.tla2tools.name} is not the pinned tla2tools.jar 1.7.4")
    if tamarin:
        if tools.tamarin is None or not tools.tamarin.is_file() or not os.access(tools.tamarin, os.X_OK):
            problems.append("tamarin-prover not found: pass --tamarin or set ECL_TAMARIN_PROVER")
        elif sha256(tools.tamarin) != PINS["tamarin"]["sha256"]:
            problems.append("tamarin-prover is not the pinned 1.12.0 Linux binary")
        maude = tools.maude_dir / "maude" if tools.maude_dir is not None else None
        if maude is None or not maude.is_file() or not os.access(maude, os.X_OK):
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


def record_settings(timeout: int, derivcheck: int) -> dict[str, object]:
    return {"java_heap": JAVA_HEAP, "tlc_workers": 1, "timeout_seconds": timeout,
            "derivcheck_timeout": derivcheck}


def record_pins() -> dict[str, dict[str, str]]:
    return {name: {key: value for key, value in pin.items() if key != "source"}
            for name, pin in PINS.items()}


def retained_checks(path: Path, names: set[str], timeout: int, derivcheck: int) -> list[dict[str, Any]]:
    """Refuse legacy, incompatible or stale retained evidence before running new work."""
    if not path.exists():
        return []
    earlier = json.loads(path.read_text(encoding="utf-8"))
    if earlier.get("schema_version") != RECORD_SCHEMA:
        raise ValueError(f"{path} is not a {RECORD_SCHEMA} record; preserve it and use a new file")
    if earlier.get("settings") != record_settings(timeout, derivcheck) or earlier.get("tools") != record_pins():
        raise ValueError(f"{path} was recorded with other settings or tools; use a new file")
    checks = earlier["checks"]
    if len({check["name"] for check in checks}) != len(checks):
        raise ValueError(f"{path} contains duplicate checks")
    kept = [check for check in checks if check["name"] not in names]
    for check in kept:
        name = check["name"]
        if name not in TLC_CHECKS and name not in TAMARIN_CHECKS:
            raise ValueError(f"{path} contains an unknown check: {name}")
        expected = TLC_CHECKS[name] if name in TLC_CHECKS else (
            "all verified" if TAMARIN_CHECKS[name][1] is None
            else f"{TAMARIN_CHECKS[name][1]} falsified"
        )
        if check.get("expected") != expected or check.get("tool") != (
            "tlc" if name in TLC_CHECKS else "tamarin"
        ):
            raise ValueError(f"{path} retains {name} under another expectation or tool; rerun it")
        if check.get("inputs") != inputs(name):
            raise ValueError(f"{path} contains stale retained inputs for {name}; rerun it or use a new file")
        if not all(check.get(key) for key in ("started_utc", "finished_utc", "runner_sha256", "output_sha256", "command")):
            raise ValueError(f"{path} lacks invocation provenance for {name}")
    return kept


def write_record(
    path: Path, results: list[Result], tools: Tools, timeout: int,
    derivcheck: int = DERIVCHECK_TIMEOUT,
) -> None:
    """Merge only compatible v2 entries; each retains its own runtime, timestamps and hashes."""
    kept = retained_checks(path, {result.name for result in results}, timeout, derivcheck)
    java = next((result.java for result in reversed(results) if result.tool == "tlc"), None)
    if not any(result.tool == "tlc" for result in results) and path.exists():
        java = json.loads(path.read_text(encoding="utf-8")).get("java")
    order = {name: index for index, name in enumerate([*TLC_CHECKS, *TAMARIN_CHECKS])}
    checks = sorted([*kept, *(asdict(result) for result in results)],
                    key=lambda check: order.get(str(check["name"]), len(order)))
    record = {"schema_version": RECORD_SCHEMA, "tools": record_pins(), "java": java,
              "settings": record_settings(timeout, derivcheck), "checks": checks}
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


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
    lines.append("TLC needs a Java runtime that can run tla2tools.jar 1.7.4; no Java version gate is imposed.")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--tla2tools", help="path to the pinned tla2tools.jar")
    parser.add_argument("--tamarin", help="path to the pinned tamarin-prover binary")
    parser.add_argument("--maude-dir", help="directory that holds the pinned maude binary")
    parser.add_argument("--java", help="executable Java for TLC; actual version recorded (default: java on PATH)")
    parser.add_argument("--only", action="append", default=[], metavar="CHECK")
    parser.add_argument("--skip-tlc", action="store_true")
    parser.add_argument("--skip-tamarin", action="store_true")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, metavar="SECONDS")
    parser.add_argument("--derivcheck-timeout", type=int, default=DERIVCHECK_TIMEOUT,
                        metavar="SECONDS", help="Tamarin derivation diagnostics: 0 disables (historical setting)")
    parser.add_argument("--log-dir", type=Path, help="fresh directory for complete tool output")
    parser.add_argument("--record", type=Path, metavar="FILE", help="write the results as JSON")
    parser.add_argument("--allow-unpinned", action="store_true", help="run other tool versions")
    parser.add_argument(
        "--readme", action="store_true", help="render the README results from the record and stop"
    )
    arguments = parser.parse_args(argv)
    if arguments.readme:
        return update_readme(check=False)
    if arguments.timeout <= 0 or arguments.derivcheck_timeout < 0:
        parser.error("--timeout must be positive and --derivcheck-timeout must be nonnegative")

    names = [*TLC_CHECKS, *TAMARIN_CHECKS]
    unknown = sorted(set(arguments.only) - set(names))
    if unknown:
        parser.error(f"unknown check: {', '.join(unknown)}")
    selected = [name for name in names if not arguments.only or name in arguments.only]
    tlc_names = [name for name in selected if name in TLC_CHECKS and not arguments.skip_tlc]
    tamarin_names = [
        name for name in selected if name in TAMARIN_CHECKS and not arguments.skip_tamarin
    ]
    if not tlc_names and not tamarin_names:
        parser.error("no checks selected")
    tools = find_tools(arguments)
    problems = pin_problems(tools, tlc=bool(tlc_names), tamarin=bool(tamarin_names))
    missing = [
        problem for problem in problems if "not found" in problem or "not on PATH" in problem
    ]
    if missing or (problems and not arguments.allow_unpinned):
        print("\n".join(f"error: {problem}" for problem in problems), file=sys.stderr)
        print(instructions(), file=sys.stderr)
        return 2

    if arguments.record is not None:
        if problems:
            print("error: a record needs the pinned tools", file=sys.stderr)
            return 2
        try:
            temporary = arguments.record.with_name(arguments.record.name + ".tmp")
            if temporary.exists():
                raise ValueError(f"{temporary} already exists; preserve it and select another record path")
            retained_checks(arguments.record, set(tlc_names + tamarin_names),
                            arguments.timeout, arguments.derivcheck_timeout)
        except (ValueError, KeyError, TypeError, OSError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
    if arguments.log_dir is not None:
        try:
            arguments.log_dir.mkdir(parents=True, exist_ok=False)
        except OSError as error:
            print(f"error: log directory must be new and writable: {error}", file=sys.stderr)
            return 2
    results: list[Result] = []
    with tempfile.TemporaryDirectory(prefix="ecl-formal-") as scratch:
        workdir = Path(scratch)
        for name in tlc_names:
            results.append(run_tlc(tools, name, arguments.timeout, workdir, arguments.log_dir))
            print(summary(results[-1]), flush=True)
        for name in tamarin_names:
            results.append(run_tamarin(tools, name, arguments.timeout, arguments.derivcheck_timeout, arguments.log_dir))
            print(summary(results[-1]), flush=True)

    if arguments.record is not None:
        try:
            write_record(arguments.record, results, tools, arguments.timeout, arguments.derivcheck_timeout)
        except (ValueError, KeyError, TypeError, OSError) as error:
            print(f"error: results could not be recorded: {error}", file=sys.stderr)
            return 2
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
