"""Regression checks for formal-runner failure paths and evidence provenance.

Run with: python3 -m unittest discover -s tests -p test_formal_runner.py
These tests use mocked tool processes; they do not substitute for TLC/Tamarin runs.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ecl_formal_runner_under_test", ROOT / "formal/run_checks.py")
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


class FormalRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.tools = runner.Tools(sys.executable, self.directory / "tlc.jar", self.directory / "tamarin", self.directory)

    def tearDown(self):
        self.temp.cleanup()

    def execute(self, *, name="correct-binding", process=None, error=None, log_dir=None):
        process = process or subprocess.CompletedProcess(["tool"], 0, "Model checking completed. No error has been found.\n", "")
        with patch.object(runner, "java_version", return_value="17.test"), patch.object(runner.subprocess, "run", return_value=process, side_effect=error):
            return runner.execute_check(self.tools, name, 9, ["tool", "input"], self.directory, log_dir=log_dir)

    def test_missing_java_never_launches_even_when_unpinned_allowed(self):
        jar = self.directory / "tlc.jar"; jar.write_bytes(b"dummy pinned jar")
        directory = self.directory / "directory"; directory.mkdir()
        for java in (str(self.directory / "absent"), str(self.directory / "not-executable"), str(directory)):
            if java.endswith("not-executable"):
                Path(java).write_text("not a program")
            error = io.StringIO()
            with self.subTest(java=java), patch.dict(runner.PINS["tla2tools"], {"sha256": runner.sha256(jar)}), patch.object(runner.subprocess, "run", side_effect=AssertionError("must not launch")), contextlib.redirect_stderr(error):
                self.assertEqual(runner.main(["--java", java, "--tla2tools", str(jar), "--skip-tamarin", "--only", "witness-timeout", "--allow-unpinned"]), 2)
            self.assertIn("java not found", error.getvalue())
            self.assertNotIn("tla2tools.jar not found", error.getvalue())

    def test_relative_tool_paths_survive_model_cwd_change(self):
        import argparse
        import os
        executable = self.directory / "java"
        executable.write_text("#!/bin/sh\nexit 0\n")
        executable.chmod(0o700)
        arguments = argparse.Namespace(java="./java", tla2tools="./tlc.jar",
                                      tamarin="./tamarin", maude_dir="./maude-dir")
        old_cwd = Path.cwd()
        try:
            os.chdir(self.directory)
            selected = runner.find_tools(arguments)
        finally:
            os.chdir(old_cwd)
        self.assertEqual(selected.java, str(executable))
        self.assertEqual(selected.tla2tools, self.directory / "tlc.jar")
        self.assertEqual(selected.tamarin, self.directory / "tamarin")
        self.assertEqual(selected.maude_dir, self.directory / "maude-dir")

    def test_invalid_limits_and_empty_selection_rejected(self):
        for arguments in (["--timeout", "0"], ["--derivcheck-timeout", "-1"], ["--skip-tlc", "--skip-tamarin"]):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                runner.main(arguments)
            self.assertEqual(exc.exception.code, 2)

    def test_record_pin_error_is_rejected_before_launch(self):
        with patch.object(runner, "find_tools", return_value=self.tools), patch.object(runner, "pin_problems", return_value=["wrong pinned tool"]), patch.object(runner.subprocess, "run", side_effect=AssertionError("must not launch")), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(runner.main(["--skip-tamarin", "--only", "witness-timeout", "--allow-unpinned", "--record", str(self.directory / "result.json")]), 2)

    def test_liveness_uses_declarations_and_ignores_nested_comments(self):
        cfg = self.directory / "configs"; cfg.mkdir()
        (cfg / "sample.cfg").write_text("\\* HoldResolves (* comment opener ignored\nCONSTANT X = RequestResolves\n(* outer (* HaltTakesEffect *) HoldResolves *)\nPROPERTIES\n HoldResolves \\* HoldResolves\n (* RequestResolves *)\nCHECK_DEADLOCK FALSE\n")
        with patch.object(runner, "TLA", self.directory):
            self.assertEqual(runner.checked_liveness("sample"), ["HoldResolves"])
            result = runner.parse_tlc("sample", "HoldResolves", "Error: Temporal properties were violated.", 1)
            self.assertTrue(result.passed)

    def test_existing_liveness_configurations_identify_one_expected_property(self):
        for name, expected in runner.TLC_CHECKS.items():
            if expected in runner.LIVENESS:
                self.assertEqual(runner.checked_liveness(name), [expected])

    def test_timeout_binds_input_bytes_and_preserves_partial_log(self):
        result = self.execute(error=subprocess.TimeoutExpired(["tool"], 9, output=b"partial stdout", stderr=b"partial stderr"), log_dir=self.directory)
        self.assertEqual(result.observed, "timeout")
        self.assertFalse(result.passed)
        self.assertEqual(result.inputs, runner.inputs(result.name))
        self.assertEqual((self.directory / result.log_file).read_text(), "partial stdoutpartial stderr")
        self.assertTrue(result.started_utc and result.finished_utc and result.runner_sha256 and result.output_sha256)
        self.assertEqual(result.java, "17.test")

    def test_tamarin_timeout_has_theory_hash_and_no_java(self):
        result = self.execute(name="protocol-correct", error=subprocess.TimeoutExpired(["tool"], 9))
        self.assertEqual(result.inputs, runner.inputs("protocol-correct"))
        self.assertIsNone(result.java)
        self.assertEqual(result.observed, "timeout")

    def test_os_error_records_failure_and_input_hashes(self):
        result = self.execute(error=PermissionError("blocked"))
        self.assertEqual(result.observed, "tool-error")
        self.assertFalse(result.passed)
        self.assertEqual(result.inputs, runner.inputs(result.name))

    def test_changed_input_is_never_passed(self):
        with patch.object(runner, "inputs", side_effect=[{"model": "before"}, {"model": "after"}]):
            result = self.execute()
        self.assertEqual(result.observed, "inputs-changed")
        self.assertFalse(result.passed)
        self.assertEqual(result.inputs, {"model": "before"})

    def test_abnormal_exit_does_not_accept_success_banner(self):
        result = self.execute(process=subprocess.CompletedProcess([], 1, "Model checking completed. No error has been found.", "fatal"))
        self.assertFalse(result.passed)
        self.assertEqual(result.returncode, 1)

    def test_expected_counterexample_can_have_nonzero_tlc_exit(self):
        result = self.execute(name="witness-timeout", process=subprocess.CompletedProcess([], 12, "Error: Invariant WitnessNoTimeout is violated.", ""))
        self.assertTrue(result.passed)
        self.assertEqual(result.observed, "WitnessNoTimeout")

    def test_derivation_setting_preserves_default_and_positive_flag(self):
        default = runner.tamarin_command(self.tools, None, None)
        diagnostic = runner.tamarin_command(self.tools, "no_scope_check", "authorization_scope_and_audience", 10)
        self.assertIn("--derivcheck-timeout=0", default)
        self.assertIn("--derivcheck-timeout=10", diagnostic)
        self.assertIn("-D=no_scope_check", diagnostic)
        self.assertIn("--prove=authorization_scope_and_audience", diagnostic)

    def test_wellformedness_failure_cannot_pass_lemma_summaries(self):
        output = "\n".join(f"  {lemma} (all-traces): verified (1 steps)" for lemma in runner.LEMMAS)
        result = runner.parse_tamarin("protocol-correct", None, output + "\nWARNING: wellformedness checks failed", 1)
        self.assertFalse(result.passed)

    def test_legacy_record_is_preserved_and_refused(self):
        path = self.directory / "old.json"; original = '{"schema_version":"ecl_formal_results_v1"}\n'; path.write_text(original)
        with self.assertRaisesRegex(ValueError, "preserve it"):
            runner.write_record(path, [self.execute()], self.tools, 9)
        self.assertEqual(path.read_text(), original)

    def test_merge_retains_per_check_runtime_and_timestamps(self):
        path = self.directory / "new.json"
        first = self.execute()
        runner.write_record(path, [first], self.tools, 9)
        second = self.execute(name="protocol-correct")
        runner.write_record(path, [second], self.tools, 9)
        record = json.loads(path.read_text())
        self.assertEqual(record["schema_version"], "ecl_formal_results_v2")
        self.assertEqual(record["java"], "17.test")
        self.assertEqual(record["checks"][0]["started_utc"], first.started_utc)
        self.assertEqual(record["checks"][0]["java"], "17.test")
        self.assertIsNone(record["checks"][1]["java"])
        self.assertEqual(record["settings"]["derivcheck_timeout"], 0)

    def test_stale_retained_check_and_different_settings_are_refused(self):
        path = self.directory / "record.json"
        runner.write_record(path, [self.execute()], self.tools, 9)
        second = self.execute(name="protocol-correct")
        with self.assertRaisesRegex(ValueError, "other settings"):
            runner.write_record(path, [second], self.tools, 9, 10)
        with patch.object(runner, "inputs", return_value={"changed": "model"}), self.assertRaisesRegex(ValueError, "stale retained"):
            runner.write_record(path, [second], self.tools, 9)

    def test_unknown_new_java_version_does_not_inherit_prior_runtime(self):
        path = self.directory / "new.json"
        first = self.execute(); runner.write_record(path, [first], self.tools, 9)
        second = self.execute(); second.java = None
        runner.write_record(path, [second], self.tools, 9)
        self.assertIsNone(json.loads(path.read_text())["java"])

    def test_changed_expectation_or_tool_cannot_be_retained(self):
        for field, value in (("expected", "another-property"), ("tool", "another-tool")):
            path = self.directory / (field + ".json")
            runner.write_record(path, [self.execute()], self.tools, 9)
            data = json.loads(path.read_text()); data["checks"][0][field] = value
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "another expectation or tool"):
                runner.write_record(path, [self.execute(name="protocol-correct")], self.tools, 9)

    def test_stale_record_temp_is_refused_before_tool_execution(self):
        path = self.directory / "result.json"; path.with_suffix(".json.tmp").write_text("preserve")
        error = io.StringIO()
        with patch.object(runner, "find_tools", return_value=self.tools), patch.object(runner, "pin_problems", return_value=[]), patch.object(runner.subprocess, "run", side_effect=AssertionError("must not launch")), contextlib.redirect_stderr(error):
            self.assertEqual(runner.main(["--skip-tamarin", "--only", "witness-timeout", "--record", str(path)]), 2)
        self.assertIn("already exists", error.getvalue())
        self.assertEqual(path.with_suffix(".json.tmp").read_text(), "preserve")

    def test_quoted_comment_delimiters_and_property_names_are_ignored(self):
        cfg = self.directory / "configs"; cfg.mkdir()
        (cfg / "sample.cfg").write_text('CONSTANT Foo = "(* PROPERTY HoldResolves"\nPROPERTY RequestResolves\n')
        with patch.object(runner, "TLA", self.directory):
            self.assertEqual(runner.checked_liveness("sample"), ["RequestResolves"])

    def test_pinned_tamarin_falsification_exit_zero_is_accepted(self):
        output = "  request_origin (all-traces): falsified - found trace (5 steps)\n"
        result = self.execute(name="protocol-dp-skips-request-signature", process=subprocess.CompletedProcess([], 0, output, ""))
        self.assertTrue(result.passed)

    def test_existing_logs_are_not_overwritten(self):
        log = self.directory / "correct-binding.log"; log.write_text("preserve")
        with self.assertRaises(FileExistsError):
            self.execute(log_dir=self.directory)
        self.assertEqual(log.read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
