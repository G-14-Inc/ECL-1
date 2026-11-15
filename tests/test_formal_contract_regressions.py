"""Formal-check registry and runner boundaries; no solver runs are mocked as proofs."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import re
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


runner = load("formal_contract_runner", "formal/run_checks.py")
recovery = load("formal_contract_recovery", "formal/check_recovery.py")


class FormalRegistryTests(unittest.TestCase):
    def test_every_current_configuration_is_registered(self):
        configs = {path.stem for path in (runner.TLA / "configs").glob("*.cfg")}
        self.assertEqual(configs, set(runner.TLC_CHECKS))

    def test_every_current_flaw_has_a_registered_countercheck(self):
        source = (runner.TLA / "ECLCore.tla").read_text(encoding="utf-8")
        block = re.search(r"Flaws\s*==\s*\{(.*?)\}", source, re.S).group(1)
        flaws = set(re.findall(r'"([a-z_]+)"', block))
        checked = set()
        for name, expected in runner.TLC_CHECKS.items():
            config = (runner.TLA / "configs" / f"{name}.cfg").read_text(encoding="utf-8")
            variant = re.search(r'Variant\s*=\s*"([a-z_]+)"', config).group(1)
            if variant != "correct":
                self.assertNotEqual(expected, "pass")
                checked.add(variant)
        self.assertEqual(flaws, checked)

    def test_every_current_witness_has_a_registered_reachability_check(self):
        source = (runner.TLA / "MC.tla").read_text(encoding="utf-8")
        witnesses = set(re.findall(r"^(Witness\w+)\s*==", source, re.M))
        checked = {name for name in runner.TLC_CHECKS.values() if name.startswith("Witness")}
        self.assertEqual(witnesses, checked)

    def test_every_current_protocol_lemma_is_registered(self):
        source = (runner.PROTOCOL / runner.THEORY).read_text(encoding="utf-8")
        self.assertEqual(set(re.findall(r"^lemma (\w+)\s*:", source, re.M)), set(runner.LEMMAS))


class TemporalAttributionTests(unittest.TestCase):
    def parse(self, config, expected="HoldResolves"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "configs").mkdir()
            (root / "configs/sample.cfg").write_text(config, encoding="utf-8")
            with patch.object(runner, "TLA", root):
                return runner.parse_tlc("sample", expected, "Error: Temporal properties were violated.", 1)

    def test_mixed_action_and_liveness_is_not_attributed_to_only_known_liveness(self):
        result = self.parse("PROPERTIES HoldResolves NoLateDecision\nCHECK_DEADLOCK FALSE\n")
        self.assertEqual(result.observed, "temporal")
        self.assertFalse(result.passed)

    def test_two_property_declarations_are_ambiguous(self):
        result = self.parse("PROPERTY NoLateDecision\nPROPERTY HoldResolves\n")
        self.assertEqual(result.observed, "temporal")

    def test_comment_and_quoted_property_names_do_not_create_ambiguity(self):
        result = self.parse('CONSTANT X = "PROPERTY NoLateDecision"\n'
                            '(* PROPERTY NoEffectWhileRestricted (* nested *) *)\n'
                            'PROPERTY HoldResolves \\* NoLateDecision\n')
        self.assertTrue(result.passed)


class RecoveryPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.formal = self.root / "formal"; self.formal.mkdir()
        self.runner_path = self.formal / "check_recovery.py"
        self.runner_path.write_text("# fixture runner identity\n", encoding="utf-8")
        packet = self.formal / "diagnostics/2026-11-10-recovery"
        case = packet / "correct-control"; case.mkdir(parents=True)
        (case / "case.cfg").write_text("\\* café\nCHECK_DEADLOCK FALSE\n", encoding="utf-8")
        self.jar = self.root / "pinned.jar"; self.jar.write_bytes(b"fixture")
        record = {"tool_sha256": recovery.sha256(self.jar), "cases": [{
            "name": "correct-control", "expected": "no error",
            "inputs": {"case.cfg": recovery.sha256(case / "case.cfg")},
        }]}
        (packet / "COMBINED-RESULTS.json").write_text(json.dumps(record), encoding="utf-8")
        self.output = self.root / "new-results"

    def tearDown(self):
        self.temp.cleanup()

    def call(self, process):
        argv = ["check_recovery.py", "--jar", str(self.jar), "--output", str(self.output)]
        with patch.object(recovery, "__file__", str(self.runner_path)), patch.object(sys, "argv", argv), \
             patch.object(recovery.shutil, "which", return_value="/fixture/java"), \
             patch.object(recovery.subprocess, "run", side_effect=process), \
             contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            return recovery.main()

    def test_missing_java_preserves_unused_output_path(self):
        with self.assertRaises(SystemExit) as caught:
            self.call(FileNotFoundError("java"))
        self.assertEqual(caught.exception.code, 2)
        self.assertFalse(self.output.exists())

    def test_failed_java_version_preserves_unused_output_path(self):
        with self.assertRaises(SystemExit) as caught:
            self.call(subprocess.CalledProcessError(1, ["java", "-version"]))
        self.assertEqual(caught.exception.code, 2)
        self.assertFalse(self.output.exists())

    def test_stdout_and_stderr_java_version_are_retained(self):
        def process(command, **kwargs):
            if command[-1] == "-version":
                return subprocess.CompletedProcess(command, 0, "Java stdout\n", "Java stderr\n")
            kwargs["stdout"].write(b"Model checking completed. No error has been found.\n")
            return subprocess.CompletedProcess(command, 0)
        self.assertEqual(self.call(process), 0)
        result = json.loads((self.output / "RESULT.json").read_text(encoding="utf-8"))
        self.assertEqual(result["java_version"], "Java stdout\nJava stderr\n")
        self.assertTrue(result["complete"] and result["all_expected_outcomes_matched"])
        self.assertIn("café", (self.output / "correct-control/case.cfg").read_text(encoding="utf-8"))

    def test_non_utf8_tool_output_is_retained_without_losing_the_result(self):
        def process(command, **kwargs):
            if command[-1] == "-version":
                return subprocess.CompletedProcess(command, 0, "Java version", "")
            kwargs["stdout"].write(b"\xff\nModel checking completed. No error has been found.\n")
            return subprocess.CompletedProcess(command, 0)
        self.assertEqual(self.call(process), 0)
        retained = self.output / "correct-control/stdout.log"
        self.assertEqual(retained.read_bytes()[0], 255)
        result = json.loads((self.output / "RESULT.json").read_text())
        self.assertEqual(result["cases"][0]["outputs"]["stdout.log"], recovery.sha256(retained))


if __name__ == "__main__":
    unittest.main()
