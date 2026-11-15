"""Registry coverage and result attribution; solver results are recorded separately."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runner = load("formal_progress_runner", "formal/run_checks.py")
recovery = load("formal_progress_recovery", "formal/check_recovery.py")


# These small readers cover the declarations used by this model and its configs.
# They are regression guards, not a TLA+ parser or a substitute for TLC.
def without_comments(text, *, mask_strings=False):
    result = list(text)
    index, depth = 0, 0
    while index < len(text):
        if depth:
            if text.startswith("(*", index):
                result[index:index + 2] = "  "
                depth += 1
                index += 2
            elif text.startswith("*)", index):
                result[index:index + 2] = "  "
                depth -= 1
                index += 2
            else:
                if text[index] != "\n":
                    result[index] = " "
                index += 1
        elif text.startswith("(*", index):
            result[index:index + 2] = "  "
            depth = 1
            index += 2
        elif text.startswith("\\*", index):
            end = text.find("\n", index)
            if end < 0:
                end = len(text)
            result[index:end] = " " * (end - index)
            index = end
        elif text[index] == '"':
            start = index
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                elif text[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            else:
                raise ValueError("unterminated quoted value")
            if mask_strings:
                result[start:index] = ["\n" if c == "\n" else " " for c in text[start:index]]
        else:
            index += 1
    if depth:
        raise ValueError("unterminated block comment")
    return "".join(result)


def compact(text):
    # Whitespace within a quoted constant remains significant.
    return "".join(re.findall(r'"(?:\\.|[^"\\])*"|\S', text))


def definitions(source):
    clean = without_comments(source, mask_strings=True)
    clean = re.sub(r"(?m)^[-=]{4,}.*$", "", clean)
    declarations = list(re.finditer(r"(?m)^([A-Za-z_]\w*)(?:\([^()\n]*\))?\s*==", clean))
    result = {}
    for index, declaration in enumerate(declarations):
        end = declarations[index + 1].start() if index + 1 < len(declarations) else len(clean)
        name = declaration.group(1)
        if name in result:
            raise ValueError("duplicate model definition: " + name)
        result[name] = clean[declaration.end():end].strip()
    return result


def declared_safety(source):
    bodies = definitions(source)
    safety = bodies["Safety"]
    if not re.fullmatch(r"(?:/\\\s*[A-Za-z_]\w*\s*)+", safety):
        raise ValueError("review the changed Safety definition")
    invariants = set(re.findall(r"/\\\s*([A-Za-z_]\w*)", safety))
    # Current action properties use top-level [] [action]_vars definitions. Spec is
    # a conjunction with Init and Fairness and is not itself such a property.
    actions = {name for name, body in bodies.items()
               if re.fullmatch(r"\[\]\s*\[[\s\S]*\]_\s*vars", body)}
    return invariants, actions


CONFIG_KEYWORDS = {
    "CONSTANT", "CONSTANTS", "INIT", "NEXT", "SPECIFICATION", "INVARIANT", "INVARIANTS",
    "PROPERTY", "PROPERTIES", "CONSTRAINT", "CONSTRAINTS", "ACTION_CONSTRAINT",
    "ACTION_CONSTRAINTS", "SYMMETRY", "VIEW", "ALIAS", "CHECK_DEADLOCK", "POSTCONDITION",
}


def config_sections(text):
    clean = without_comments(text)
    masked = without_comments(text, mask_strings=True)
    directives = [match for match in re.finditer(r"\b[A-Za-z_]\w*\b", masked)
                  if match.group() in CONFIG_KEYWORDS]
    sections = {}
    aliases = {"CONSTANT": "CONSTANTS", "INVARIANT": "INVARIANTS", "PROPERTY": "PROPERTIES"}
    for index, directive in enumerate(directives):
        end = directives[index + 1].start() if index + 1 < len(directives) else len(clean)
        key = aliases.get(directive.group(), directive.group())
        sections.setdefault(key, []).append(clean[directive.end():end])
    return sections


def declared_names(sections, key):
    values = []
    for body in sections.get(key, []):
        clean = without_comments(body, mask_strings=True)
        if not re.fullmatch(r"\s*(?:[A-Za-z_]\w*\s*)*", clean):
            raise ValueError("review the changed " + key + " declaration")
        values.extend(re.findall(r"[A-Za-z_]\w*", clean))
    return values


def constants(sections):
    result = {}
    for body in sections.get("CONSTANTS", []):
        masked = without_comments(body, mask_strings=True)
        assignments = list(re.finditer(r"(?m)^[ \t]*([A-Za-z_]\w*)\s*(=|<-)", masked))
        if masked[:assignments[0].start() if assignments else len(masked)].strip():
            raise ValueError("review the changed constant declaration")
        for index, assignment in enumerate(assignments):
            end = assignments[index + 1].start() if index + 1 < len(assignments) else len(body)
            name = assignment.group(1)
            if name in result:
                raise ValueError("duplicate constant declaration: " + name)
            value = compact(body[assignment.end():end])
            if not value:
                raise ValueError("missing constant value: " + name)
            result[name] = (assignment.group(2), value)
    return result


def assert_refresh_elision_bounds(test, values, name):
    if values["Variant"] != ("=", '"correct"') or values["SyncWithoutNews"] != ("=", "FALSE"):
        return
    horizon = int(values["MaxTime"][1])
    test.assertGreaterEqual(int(values["PropagationBound"][1]), horizon, name)
    test.assertGreaterEqual(int(values["StalenessBound"][1]), horizon, name)


class TemporalResultAttributionTests(unittest.TestCase):
    def test_single_property_survives_comments_directive_order_and_spelling(self):
        for config in (
            "PROPERTY HoldResolves\nCHECK_DEADLOCK FALSE\n",
            "PROPERTIES (* explanatory (* nested *) comment *) HoldResolves\n",
            "CHECK_DEADLOCK FALSE\nPROPERTIES HoldResolves \\* trailing comment\n",
            'CONSTANT note = "PROPERTY NoLateDecision"\nPROPERTY HoldResolves\n',
        ):
            with self.subTest(config=config):
                self.assertTrue(recovery.outcome_matches(
                    13, "Error: Temporal properties were violated.", "HoldResolves", config))

    def test_a_second_property_cannot_be_hidden_before_the_last_declaration(self):
        config = "PROPERTY NoLateDecision\nPROPERTIES HoldResolves\nCHECK_DEADLOCK FALSE\n"
        self.assertFalse(recovery.outcome_matches(
            13, "Error: Temporal properties were violated.", "HoldResolves", config))

    def test_commented_property_cannot_establish_unnamed_attribution(self):
        for config in (
            "(* PROPERTIES HoldResolves CHECK_DEADLOCK FALSE *)\nPROPERTY NoLateDecision\n",
            "\\* PROPERTIES HoldResolves CHECK_DEADLOCK FALSE\nPROPERTY NoLateDecision\n",
        ):
            with self.subTest(config=config):
                self.assertFalse(recovery.outcome_matches(
                    13, "Error: Temporal properties were violated.", "HoldResolves", config))

    def test_named_failure_and_exit_precedence_are_preserved(self):
        output = "Error: Invariant Bound is violated."
        self.assertTrue(recovery.outcome_matches(12, output, "Bound", ""))
        self.assertFalse(recovery.outcome_matches(1, output, "Bound", ""))
        self.assertFalse(recovery.outcome_matches(12, output, "Other", ""))


class FormalCoverageBoundaryTests(unittest.TestCase):
    def test_correct_configurations_check_every_model_safety_property(self):
        source = (runner.TLA / "ECLCore.tla").read_text(encoding="utf-8")
        invariants, actions = declared_safety(source)
        self.assertIn("UniqueWorkflowAttempt", invariants)
        self.assertIn("FreshStalenessInvalidatesProof", actions)
        for name, expected in runner.TLC_CHECKS.items():
            if expected != "pass":
                continue
            sections = config_sections((runner.TLA / "configs" / (name + ".cfg")).read_text())
            names = set(declared_names(sections, "INVARIANTS"))
            if "Safety" in names:
                names = (names - {"Safety"}) | invariants
            self.assertEqual(names, invariants, name)
            properties = set(declared_names(sections, "PROPERTIES"))
            self.assertEqual(properties - set(runner.LIVENESS), actions, name)
            self.assertEqual(properties, set(runner.checked_properties(name)), name)
            self.assertEqual(declared_names(sections, "SPECIFICATION"), ["Spec"], name)

    def test_refresh_elision_is_limited_to_nonexpiring_correct_configs(self):
        for name in runner.TLC_CHECKS:
            config = (runner.TLA / "configs" / (name + ".cfg")).read_text()
            assert_refresh_elision_bounds(self, constants(config_sections(config)), name)

    def test_liveness_configurations_preserve_fairness_and_disable_symmetry(self):
        bodies = definitions((runner.TLA / "ECLCore.tla").read_text())
        self.assertEqual(compact(bodies["Spec"]), r"Init/\[][Next]_vars/\Fairness")
        fairness = compact(bodies["Fairness"])
        for clause in (
            r"/\WF_vars(Tick)", r"/\WF_vars(Reconcile)", r"/\WF_vars(ResumeNormal)",
            r"/\\Aep\inEPs:WF_vars(Sync(ep))/\WF_vars(HaltAck(ep))",
            r"/\WF_vars(\Ep\inpending:DecisionTimeout(p))",
            r"/\WF_vars(\Eh\inheld:HoldTimeout(h))",
        ):
            self.assertIn(clause, fairness)
        for name in ("correct-liveness", "correct-continuation-liveness"):
            sections = config_sections((runner.TLA / "configs" / (name + ".cfg")).read_text())
            self.assertNotIn("SYMMETRY", sections, name)
            self.assertEqual(set(declared_names(sections, "PROPERTIES")) & set(runner.LIVENESS),
                             set(runner.LIVENESS), name)
            self.assertEqual(declared_names(sections, "SPECIFICATION"), ["Spec"], name)

    def test_paired_witnesses_and_mutants_preserve_bounds_and_specification(self):
        pairs = {
            "correct-continuation-liveness": (
                ("witness-live-continuation-admit", "correct"),
                ("witness-live-continuation-timeout", "correct"),
                ("witness-live-recovery-resumption", "correct"),
            ),
            "correct-repeated-staleness": (
                ("witness-revalidated-authority-after-repeated-staleness", "correct"),
                ("broken-repeated-staleness-proof", "repeated_staleness_ignored"),
            ),
            "correct-liveness": (("broken-recovery-never-resumes", "recovery_never_resumes"),),
        }
        for name, comparisons in pairs.items():
            sections = config_sections((runner.TLA / "configs" / (name + ".cfg")).read_text())
            expected_constants = constants(sections)
            if name == "correct-continuation-liveness":
                self.assertEqual(expected_constants["ReqIds"], ("=", "{r1,r2}"))
                self.assertEqual(expected_constants["MaxRequests"], ("=", "2"))
            for other_name, variant in comparisons:
                other = config_sections((runner.TLA / "configs" / (other_name + ".cfg")).read_text())
                expected = dict(expected_constants, Variant=("=", json.dumps(variant)))
                self.assertEqual(constants(other), expected, other_name)
                self.assertEqual(declared_names(other, "SPECIFICATION"), ["Spec"], other_name)
                self.assertNotIn("SYMMETRY", other, other_name)
                named_checks = declared_names(other, "INVARIANTS") + declared_names(other, "PROPERTIES")
                self.assertEqual(named_checks, [runner.TLC_CHECKS[other_name]], other_name)

    def test_every_symbolic_conditional_flag_has_a_negative_check(self):
        theory = (runner.PROTOCOL / runner.THEORY).read_text(encoding="utf-8")
        flags = set(re.findall(r"^#if(?:n?def)\s+(\w+)", theory, re.M))
        checked = {flag for flag, lemma in runner.TAMARIN_CHECKS.values() if flag is not None}
        self.assertEqual(flags, checked)


class FormalGuardParserTests(unittest.TestCase):
    def test_model_comments_and_strings_cannot_create_or_hide_properties(self):
        source = r'\* Bogus == [][FALSE]_vars' + '\n' + r'''
(* Hidden == [][FALSE]_vars (* nested *) *)
Note == "[] [TRUE]_vars (* string delimiters *)"
Actual == [][x' = x]_vars
Safety == /\ TypeOK (* Fake == [][FALSE]_vars *)
          /\ ActualInvariant
'''
        self.assertEqual(declared_safety(source), ({"TypeOK", "ActualInvariant"}, {"Actual"}))
        amended = source + '\nAdded == [][TRUE]_vars\n'
        self.assertEqual(declared_safety(amended)[1], {"Actual", "Added"})

    def test_directive_order_comments_and_quoted_keywords_are_not_semantic_changes(self):
        text = r'''
CONSTANTS
    Note = "PROPERTY Hidden \\\" (* text *)"
    Variant = "correct"
    EPs = {e1,
           e2}
PROPERTIES Live
(* INVARIANTS Fake (* nested *) *)
INVARIANT First
CHECK_DEADLOCK FALSE
INVARIANTS Second \* PROPERTY HiddenAgain
SPECIFICATION Spec
'''
        sections = config_sections(text)
        self.assertEqual(declared_names(sections, "INVARIANTS"), ["First", "Second"])
        self.assertEqual(declared_names(sections, "PROPERTIES"), ["Live"])
        self.assertEqual(constants(sections)["EPs"], ("=", "{e1,e2}"))
        self.assertIn("PROPERTY Hidden", constants(sections)["Note"][1])
        self.assertEqual(declared_names(sections, "SPECIFICATION"), ["Spec"])

    def test_unterminated_lexical_constructs_fail_closed(self):
        for text in ('(* open', '(* one (* two *)', '"open', '"escaped\\"'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                without_comments(text, mask_strings=True)

    def test_duplicate_declarations_do_not_silently_replace_a_guard(self):
        with self.assertRaises(ValueError):
            definitions("Guard == TRUE\nGuard == FALSE\n")
        with self.assertRaises(ValueError):
            constants(config_sections("CONSTANTS MaxTime = 2\nMaxTime = 3\n"))

    def test_refresh_elision_boundaries_and_intentional_mutant_exception(self):
        base = {"Variant": ("=", '"correct"'), "SyncWithoutNews": ("=", "FALSE"),
                "MaxTime": ("=", "3"), "PropagationBound": ("=", "3"),
                "StalenessBound": ("=", "3"), "MaxOutages": ("=", "0")}
        assert_refresh_elision_bounds(self, base, "equal bounds")
        assert_refresh_elision_bounds(self, dict(base, PropagationBound=("=", "4")), "larger bound")
        for key, value in (("PropagationBound", "2"), ("StalenessBound", "2")):
            with self.subTest(key=key), self.assertRaises(AssertionError):
                assert_refresh_elision_bounds(self, dict(base, **{key: ("=", value)}), key)
        # Reconcile refreshes control state; the guard adds no outage prohibition.
        assert_refresh_elision_bounds(self, dict(base, MaxOutages=("=", "1")), "outage count unchanged in scope")
        # A deliberately broken stale-view configuration is not a correct-design guard.
        mutant = dict(base, Variant=("=", '"ignore_staleness"'), StalenessBound=("=", "1"))
        assert_refresh_elision_bounds(self, mutant, "intentional negative")
        assert_refresh_elision_bounds(self, dict(base, SyncWithoutNews=("=", "TRUE"),
                                                StalenessBound=("=", "1")), "refresh enabled")


if __name__ == "__main__":
    unittest.main()
