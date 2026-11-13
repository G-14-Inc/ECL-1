"""Formal-runner process and parser boundaries; these fixtures are not solver proofs."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runner = load("formal_output_runner", "formal/run_checks.py")
recovery = load("formal_output_recovery", "formal/check_recovery.py")


@contextlib.contextmanager
def changed_directory(directory):
    previous = Path.cwd()
    os.chdir(directory)
    try:
        yield
    finally:
        os.chdir(previous)


class RecoveryExecutableTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        formal = self.root / "formal"
        formal.mkdir()
        self.runner_path = formal / "check_recovery.py"
        self.runner_path.write_text("# fixture runner identity\n", encoding="utf-8")
        packet = formal / "diagnostics/2026-11-10-recovery"
        case = packet / "correct-control"
        case.mkdir(parents=True)
        (case / "case.cfg").write_text("CHECK_DEADLOCK FALSE\n", encoding="utf-8")
        (case / "RecoveryReview.tla").write_text("---- MODULE RecoveryReview ----\n====\n", encoding="utf-8")
        self.jar = self.root / "pinned.jar"
        self.jar.write_bytes(b"fixture, not a solver")
        record = {"tool_sha256": recovery.sha256(self.jar), "cases": [{
            "name": "correct-control", "expected": "no error",
            "inputs": {name: recovery.sha256(case / name)
                       for name in ("case.cfg", "RecoveryReview.tla")},
        }]}
        (packet / "COMBINED-RESULTS.json").write_text(json.dumps(record), encoding="utf-8")
        self.output = self.root / "results"
        self.executable = self.root / ("jdk/bin/java.cmd" if os.name == "nt" else "jdk/bin/java")
        self.executable.parent.mkdir(parents=True)
        self.stub()

    def tearDown(self):
        self.temp.cleanup()

    def stub(self, *, version_exit=0):
        script = self.executable.with_suffix(".py") if os.name == "nt" else self.executable
        script.write_text(
            f"#!{sys.executable}\n"
            "import os, sys\n"
            "if sys.argv[1:] == ['-version']:\n"
            "    print('openjdk version \\\"fixture\\\"', file=sys.stderr)\n"
            f"    sys.exit({version_exit})\n"
            "print('Model checking completed. No error has been found.')\n",
            encoding="utf-8",
        )
        if os.name == "nt":
            self.executable.write_text(
                f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8", newline="\n")
        self.executable.chmod(0o755)

    def call(self, executable):
        with changed_directory(self.root), patch.object(recovery, "__file__", str(self.runner_path)), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return recovery.main(["--java", executable, "--jar", str(self.jar),
                                  "--output", str(self.output)])

    def result(self):
        return json.loads((self.output / "RESULT.json").read_text(encoding="utf-8"))

    def assert_success(self):
        result = self.result()
        self.assertTrue(result["complete"])
        self.assertTrue(result["all_expected_outcomes_matched"])
        case = result["cases"][0]
        self.assertEqual(case["command"][0], str(self.executable.resolve()))
        self.assertEqual(case["returncode"], 0)
        self.assertEqual(case["outputs"]["stdout.log"], recovery.sha256(self.output / "correct-control/stdout.log"))

    def test_relative_explicit_java_survives_case_directory(self):
        self.assertEqual(self.call("./jdk/bin/" + self.executable.name), 0)
        self.assert_success()

    def test_relative_path_entry_survives_case_directory(self):
        with patch.dict(os.environ, {"PATH": "jdk/bin"}):
            self.assertEqual(self.call(self.executable.name), 0)
        self.assert_success()

    def test_absolute_java_remains_supported(self):
        self.assertEqual(self.call(str(self.executable)), 0)
        self.assert_success()

    def test_missing_java_does_not_reserve_output(self):
        with self.assertRaises(SystemExit) as caught:
            self.call("./jdk/bin/absent-java")
        self.assertEqual(caught.exception.code, 2)
        self.assertFalse(self.output.exists())

    def test_failed_java_version_does_not_reserve_output(self):
        self.stub(version_exit=9)
        with self.assertRaises(SystemExit) as caught:
            self.call(str(self.executable))
        self.assertEqual(caught.exception.code, 2)
        self.assertFalse(self.output.exists())

    def test_executable_lost_after_preflight_is_recorded_as_failure(self):
        real_run = recovery.subprocess.run
        def remove_after_probe(command, *args, **kwargs):
            result = real_run(command, *args, **kwargs)
            if command[1:] == ["-version"]:
                self.executable.unlink()
            return result
        with patch.object(recovery.subprocess, "run", side_effect=remove_after_probe):
            self.assertEqual(self.call(str(self.executable)), 1)
        result = self.result()
        self.assertTrue(result["complete"])
        self.assertFalse(result["all_expected_outcomes_matched"])
        case = result["cases"][0]
        self.assertIsNone(case["returncode"])
        self.assertFalse(case["expected_outcome_matched"])
        error_log = self.output / "correct-control/stderr.log"
        self.assertIn("FileNotFoundError", error_log.read_text(encoding="utf-8"))
        self.assertEqual(case["outputs"]["stderr.log"], recovery.sha256(error_log))

    def test_existing_output_is_never_overwritten(self):
        self.output.mkdir()
        sentinel = self.output / "preserved.txt"
        sentinel.write_text("retain", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            self.call(str(self.executable))
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "retain")
        self.assertFalse((self.output / "RESULT.json").exists())


class TlcExitClassificationTests(unittest.TestCase):
    def execute(self, name, code, output):
        tools = runner.Tools(java=sys.executable, tla2tools=Path("fixture.jar"), tamarin=None, maude_dir=None)
        process = subprocess.CompletedProcess(["fixture"], code, output, "")
        with patch.object(runner, "java_version", return_value="fixture"), \
             patch.object(runner.subprocess, "run", return_value=process):
            return runner.execute_check(tools, name, 10, ["fixture"], ROOT)

    def test_counterexample_requires_safety_or_liveness_exit(self):
        output = "Error: Invariant WitnessNoTimeout is violated.\n"
        for code in (0, 1, 2, 10, 11, 14, 75, 76, 77, 134, 137, 150, 151, 152, 153, 255, -9):
            with self.subTest(code=code):
                result = self.execute("witness-timeout", code, output)
                self.assertFalse(result.passed)
                self.assertEqual(result.observed, "tool-error")
                self.assertEqual(result.returncode, code)

    def test_valid_counterexample_exits_preserve_named_result(self):
        output = "Error: Invariant WitnessNoTimeout is violated.\nState 1:\n"
        for code in (12, 13):
            with self.subTest(code=code):
                result = self.execute("witness-timeout", code, output)
                self.assertTrue(result.passed)
                self.assertEqual(result.observed, "WitnessNoTimeout")
                self.assertEqual(result.trace_states, 1)

    def test_correct_check_needs_success_banner_and_zero_exit(self):
        output = "Model checking completed. No error has been found.\n"
        for code in (0, 1, 12, 13, 255, -9):
            with self.subTest(code=code):
                result = self.execute("correct-binding", code, output)
                self.assertEqual(result.passed, code == 0)
                self.assertEqual(result.observed, "pass" if code == 0 else "tool-error")

    def test_wrong_named_violation_is_not_an_expected_counterexample(self):
        result = self.execute("witness-timeout", 12, "Error: Invariant Other is violated.\n")
        self.assertFalse(result.passed)
        self.assertEqual(result.observed, "Other")

    def test_zero_exit_without_success_banner_does_not_pass(self):
        self.assertFalse(self.execute("correct-binding", 0, "no result\n").passed)


class TamarinSummaryTests(unittest.TestCase):
    def all_summaries(self, changed=None, status="verified", steps=9):
        return "\n".join(
            f"  {name} ({'exists-trace' if name in ('executable', 'agent_signed_executable') else 'all-traces'}): "
            f"{status if name == changed else 'verified'} ({steps if name == changed else 1} steps)"
            for name in runner.LEMMAS
        )

    def test_falsified_existence_is_retained_without_false_correct_pass(self):
        for lemma in ("executable", "agent_signed_executable"):
            with self.subTest(lemma=lemma):
                result = runner.parse_tamarin("protocol-correct", None,
                    self.all_summaries(lemma, "falsified - no trace found"), 1)
                self.assertFalse(result.passed)
                self.assertEqual(result.lemmas[lemma], "falsified - no trace found")
                self.assertEqual(result.steps[lemma], 9)

    def test_explicit_existence_falsification_is_classified(self):
        result = runner.parse_tamarin("fixture-existence", "executable",
            "  executable (exists-trace): falsified - no trace found (9 steps)\n", 1)
        self.assertTrue(result.passed)
        self.assertEqual(result.observed, "executable falsified")
        self.assertEqual(result.steps["executable"], 9)

    def test_universal_falsification_remains_supported(self):
        result = runner.parse_tamarin("protocol-no-single-use", "single_use",
            "  single_use (all-traces): falsified - found trace (7 steps)\n", 1)
        self.assertTrue(result.passed)
        self.assertEqual(result.steps["single_use"], 7)

    def test_quantifier_and_falsification_status_must_agree(self):
        for quantifier, status in (("all-traces", "falsified - no trace found"),
                                   ("exists-trace", "falsified - found trace")):
            with self.subTest(quantifier=quantifier):
                result = runner.parse_tamarin("fixture-invalid-summary", "single_use",
                    f"  single_use ({quantifier}): {status} (4 steps)\n", 1)
                self.assertFalse(result.passed)
                self.assertEqual(result.lemmas["single_use"], status)

    def test_all_verified_quantifiers_remain_supported(self):
        result = runner.parse_tamarin("protocol-correct", None, self.all_summaries(), 1)
        self.assertTrue(result.passed)
        self.assertEqual(len(result.lemmas), len(runner.LEMMAS))

    def test_incomplete_and_absent_results_are_distinct_failures(self):
        result = runner.parse_tamarin("protocol-correct", None,
            self.all_summaries("executable", "analysis incomplete"), 1)
        self.assertFalse(result.passed)
        self.assertEqual(result.lemmas["executable"], "analysis incomplete")
        missing = runner.parse_tamarin("fixture-missing", "executable", "", 1)
        self.assertFalse(missing.passed)
        self.assertEqual(missing.lemmas["executable"], "not analyzed")
        self.assertNotIn("executable", missing.steps)

    def test_wellformedness_failure_still_prevents_acceptance(self):
        output = self.all_summaries() + "\nwellformedness checks failed\n"
        self.assertFalse(runner.parse_tamarin("protocol-correct", None, output, 1).passed)
        output = "  executable (exists-trace): falsified - no trace found (9 steps)\nwellformedness check failed\n"
        self.assertFalse(runner.parse_tamarin("fixture-existence", "executable", output, 1).passed)


if __name__ == "__main__":
    unittest.main()
