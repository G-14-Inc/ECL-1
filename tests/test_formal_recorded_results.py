"""Tamper regressions for retained invocation provenance; no formal tools run.

Robert F. Tilley Jr.; G-14, Inc.
"""
import copy
import json
import importlib.util
import os
import subprocess
import tempfile
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("formal_recorded_results", ROOT / "formal/check_recorded_results.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class AggregateProvenance(unittest.TestCase):
    def setUp(self):
        self.base = 'formal/diagnostics/synthetic/'
        pins = {'tla2tools': {'version': 'synthetic', 'sha256': 'a'*64},
                'tamarin': {'version': 'synthetic', 'sha256': 'b'*64},
                'maude': {'version': 'synthetic', 'sha256': 'c'*64}}
        runner = ('TLC_CHECKS = {"correct-example": "pass"}\n'
                  'TAMARIN_CHECKS = {"protocol-correct": (None, None)}\n'
                  'PINS = ' + repr(pins) + '\n').encode()
        older = b'# Original symbolic runner fixture\n'
        current_sha, old_sha = guard.digest(runner), guard.digest(older)
        self.files = {'formal/run_checks.py': runner,
                      self.base+'inputs/formal/run_checks.py': runner,
                      self.base+f'runners/{current_sha}/run_checks.py': runner,
                      self.base+f'runners/{old_sha}/run_checks.py': older}
        common = {'passed': True, 'started_utc': '2026-11-11T00:00:00Z',
                  'finished_utc': '2026-11-11T00:00:01Z', 'command': ['synthetic'],
                  'output_sha256': 'd'*64, 'java': None, 'seconds': 0,
                  'log_file': 'synthetic.log', 'returncode': 0, 'lemmas': {},
                  'steps': {}, 'states_generated': None, 'distinct_states': None,
                  'depth': None, 'trace_states': None}
        tlc = {**common, 'name': 'correct-example', 'tool': 'tlc', 'expected': 'pass',
               'observed': 'pass', 'runner_sha256': current_sha,
               'inputs': dict.fromkeys(['tla/ECLCore.tla','tla/MC.tla','tla/configs/correct-example.cfg'],'e'*64)}
        symbolic = {**common, 'name': 'protocol-correct', 'tool': 'tamarin',
                    'expected': 'all verified', 'observed': 'all verified',
                    'runner_sha256': old_sha, 'inputs': {'protocol/DCMP2_Binding.spthy': 'f'*64}}
        self.records = [
            {'schema_version': 'ecl_formal_results_v2', 'tools': pins,
             'settings': {'timeout_seconds': 900, 'derivcheck_timeout': 10,
                          'java_heap': '-Xmx1500m', 'tlc_workers': 1}, 'checks': [tlc]},
            {'complete': True, 'all_expected': True, 'pins': pins, 'timeout_seconds': 120,
             'derivcheck_timeout': 10, 'runner_sha256': old_sha, 'checks': [symbolic]}]
        self.aggregate = {'schema_version': 'ecl_formal_results_v3', 'tools': pins,
                          'sources': [], 'check_sources': {'correct-example': 'tlc', 'protocol-correct': 'tamarin'},
                          'checks': copy.deepcopy([tlc,symbolic]),
                          'runners': {s: f'runners/{s}/run_checks.py' for s in [current_sha,old_sha]},
                          'current_runner': {'path': 'inputs/formal/run_checks.py', 'sha256': current_sha}}
        for index, (name, kind) in enumerate([('tlc','ecl_formal_results_v2'),('tamarin','tamarin-check-receipt')]):
            record=self.records[index]
            settings=record['settings'] if index==0 else {k:record[k] for k in ['timeout_seconds','derivcheck_timeout']}
            self.aggregate['sources'].append({'id':name,'path':f'invocations/{name}.json',
                                              'sha256':'','format':kind,'settings':copy.deepcopy(settings)})
            self.save_record(index)

    def save_record(self, index):
        entry=self.aggregate['sources'][index]
        data=json.dumps(self.records[index],sort_keys=True).encode()
        self.files[self.base+entry['path']]=data;entry['sha256']=guard.digest(data)

    def check(self):
        def bind(record, check, kind, path, sha):
            guard.require(guard.digest(self.files[path])==sha,'Bound bytes changed')
        guard.current_aggregate_sources(self.files,self.base,self.aggregate,'aggregate.json',bind)

    def test_distinct_timeouts_and_original_runner_are_preserved(self):
        self.check()
        self.assertEqual([s['settings']['timeout_seconds'] for s in self.aggregate['sources']],[900,120])

    def test_changed_original_source_bytes_refused(self):
        self.files[self.base+self.aggregate['sources'][1]['path']]+=b' '
        with self.assertRaises(ValueError):self.check()

    def test_fabricated_common_timeout_refused(self):
        self.aggregate['sources'][1]['settings']['timeout_seconds']=900
        with self.assertRaises(ValueError):self.check()

    def test_incomplete_invocation_refused_even_with_new_hash(self):
        self.records[1]['complete']=False;self.save_record(1)
        with self.assertRaises(ValueError):self.check()

    def test_aggregate_result_cannot_rewrite_original(self):
        self.aggregate['checks'][1]['command']=['different command']
        with self.assertRaises(ValueError):self.check()

    def test_missing_source_check_refused(self):
        self.aggregate['checks'].pop();self.aggregate['check_sources'].pop('protocol-correct')
        with self.assertRaises(ValueError):self.check()

    def test_duplicate_source_check_refused(self):
        self.records[0]['checks'].append(copy.deepcopy(self.records[0]['checks'][0]));self.save_record(0)
        with self.assertRaises(ValueError):self.check()

    def test_misattributed_check_refused(self):
        self.aggregate['check_sources']['protocol-correct']='tlc'
        with self.assertRaises(ValueError):self.check()

    def test_extra_map_entry_refused(self):
        self.aggregate['check_sources']['invented']='tlc'
        with self.assertRaises(ValueError):self.check()

    def test_relabeling_receipt_as_original_v2_refused(self):
        self.aggregate['sources'][1]['format']='ecl_formal_results_v2'
        with self.assertRaises(ValueError):self.check()

    def test_unlisted_runner_refused(self):
        self.aggregate['runners'].pop(self.records[1]['runner_sha256'])
        with self.assertRaises(ValueError):self.check()

    def test_edited_retained_runner_refused(self):
        path=self.aggregate['runners'][self.records[1]['runner_sha256']]
        self.files[self.base+path]+=b'changed'
        with self.assertRaises(ValueError):self.check()

    def test_current_runner_is_bound_separately(self):
        self.files['formal/run_checks.py']+=b'changed'
        with self.assertRaises(ValueError):self.check()

    def test_failed_result_cannot_be_promoted_even_if_both_copies_match(self):
        self.records[1]['checks'][0]['passed']=False;self.save_record(1)
        self.aggregate['checks'][1]['passed']=False
        with self.assertRaises(ValueError):self.check()

    def test_declared_runner_must_agree_with_source_checks(self):
        self.records[1]['runner_sha256']='0'*64;self.save_record(1)
        with self.assertRaises(ValueError):self.check()

    def test_omitting_input_cannot_pass_even_if_both_copies_match(self):
        del self.records[0]['checks'][0]['inputs']['tla/MC.tla'];self.save_record(0)
        del self.aggregate['checks'][0]['inputs']['tla/MC.tla']
        with self.assertRaises(ValueError):self.check()

    def test_unreviewed_global_settings_refused(self):
        self.aggregate['settings']={'timeout_seconds':900}
        with self.assertRaises(ValueError):self.check()

    def test_boolean_setting_cannot_equal_original_integer(self):
        self.aggregate['sources'][0]['settings']['tlc_workers']=True
        with self.assertRaisesRegex(ValueError,'integer'):self.check()

    def test_original_boolean_setting_cannot_equal_aggregate_integer(self):
        self.records[0]['settings']['tlc_workers']=True;self.save_record(0)
        with self.assertRaisesRegex(ValueError,'settings or pins differ'):self.check()

    def test_original_boolean_metric_cannot_equal_aggregate_integer(self):
        self.records[0]['checks'][0]['seconds']=False;self.save_record(0)
        with self.assertRaisesRegex(ValueError,'differs from its original'):self.check()

    def test_integer_tokens_do_not_accept_booleans_or_floats(self):
        for value in (True,False,1.0,1.5,'1',None):
            with self.subTest(value=value):
                aggregate=copy.deepcopy(self.aggregate)
                aggregate['sources'][0]['settings']['tlc_workers']=value
                with self.assertRaises(ValueError):guard.formal_aggregate_shape(aggregate)

    def test_nonfinite_and_boolean_measurements_refused(self):
        for value in (float('nan'),float('inf'),float('-inf'),True,False,-1):
            with self.subTest(value=value):
                aggregate=copy.deepcopy(self.aggregate);aggregate['checks'][0]['seconds']=value
                with self.assertRaises(ValueError):guard.formal_aggregate_shape(aggregate)

    def test_finite_fractional_time_and_nullable_metrics_are_valid(self):
        self.records[0]['checks'][0]['seconds']=0.25;self.save_record(0)
        self.aggregate['checks'][0]['seconds']=0.25
        self.check()

    def test_command_is_nonempty_array_of_strings(self):
        for value in ({'not':'argv'},[],['valid',True],['valid',1],'synthetic'):
            with self.subTest(value=value):
                aggregate=copy.deepcopy(self.aggregate);aggregate['checks'][0]['command']=value
                with self.assertRaises(ValueError):guard.formal_aggregate_shape(aggregate)

    def test_shape_refuses_missing_or_unknown_check_fields(self):
        for change in ('missing','unknown'):
            with self.subTest(change=change):
                aggregate=copy.deepcopy(self.aggregate)
                if change=='missing':del aggregate['checks'][0]['returncode']
                else:aggregate['checks'][0]['invented']=0
                with self.assertRaises(ValueError):guard.formal_aggregate_shape(aggregate)

    def test_nonstring_source_path_refused_with_value_error(self):
        self.aggregate['sources'][0]['path']=['invocations/tlc.json']
        with self.assertRaises(ValueError):self.check()




class PublicPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        reader = guard.SourceFiles(ROOT)
        cls.actual_summary = guard.validate_recorded_results(reader)
        cls.original_files = dict(reader.cache)
        cls.selector_name = guard.DEFAULT_SELECTOR
        selector = guard.strict_json(cls.original_files[cls.selector_name], cls.selector_name)
        cls.manifest_name = selector["packet_manifest"]
        cls.base = cls.manifest_name.rsplit("/", 1)[0] + "/"
        cls.result_name = cls.actual_summary["record"]

    def setUp(self):
        self.files = dict(self.original_files)

    def encode(self, value):
        return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()

    def refresh_manifest(self):
        manifest = json.loads(self.files[self.manifest_name])
        manifest["files"] = {name: guard.digest(self.files[self.base + name])
                             for name in manifest["files"] if self.base + name in self.files}
        manifest["record_sha256"] = guard.digest(self.files[self.result_name])
        self.files[self.manifest_name] = self.encode(manifest)
        selector = json.loads(self.files[self.selector_name])
        selector["packet_manifest_sha256"] = guard.digest(self.files[self.manifest_name])
        self.files[self.selector_name] = self.encode(selector)

    def check(self):
        return guard.validate_recorded_results(self.files)

    def test_default_current_packet_checks_without_tools(self):
        summary = self.check()
        self.assertEqual(summary["checks"], sum(summary["checks_by_tool"].values()))
        self.assertFalse(summary["formal_tools_run"])
        current = json.loads(self.files[self.result_name])
        self.assertEqual(summary["sources"], current["sources"])
        self.assertEqual(summary["current_runner"], current["current_runner"])
        self.assertEqual(set(summary["invocation_runners"]),
                         {check["runner_sha256"] for check in current["checks"]})

    def test_default_cli_succeeds_without_a_java_or_tamarin_path(self):
        environment = dict(os.environ, PATH="", PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run([sys.executable, str(ROOT / "formal/check_recorded_results.py")],
                                capture_output=True, text=True, env=environment, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)["formal_tools_run"])

    def test_stale_selector_manifest_and_current_source_are_refused(self):
        current = json.loads(self.files[self.result_name])
        config = next(name for check in current["checks"] for name in check["inputs"]
                      if name.startswith("tla/configs/"))
        log = self.base + "logs/" + current["checks"][0]["log_file"]
        for name in (self.manifest_name, "formal/run_checks.py", "formal/tla/ECLCore.tla",
                     "formal/tla/MC.tla", "formal/protocol/DCMP2_Binding.spthy",
                     "formal/" + config, log):
            with self.subTest(name=name):
                files = dict(self.original_files); files[name] += b"\n"
                with self.assertRaises(ValueError):guard.validate_recorded_results(files)

    def test_missing_log_is_refused(self):
        current = json.loads(self.files[self.result_name])
        del self.files[self.base + "logs/" + current["checks"][0]["log_file"]]
        with self.assertRaises(KeyError):self.check()

    def test_uninventoried_log_cannot_hide_behind_valid_hash(self):
        current = json.loads(self.files[self.result_name])
        log = "logs/" + current["checks"][0]["log_file"]
        manifest = json.loads(self.files[self.manifest_name]); del manifest["files"][log]
        self.files[self.manifest_name] = self.encode(manifest);self.refresh_manifest()
        with self.assertRaisesRegex(ValueError, "missing or differs in manifest"):self.check()

    def test_selector_hash_and_shape_are_enforced(self):
        for change in ("hash", "schema", "unknown"):
            with self.subTest(change=change):
                self.files = dict(self.original_files)
                selector = json.loads(self.files[self.selector_name])
                if change == "hash":selector["packet_manifest_sha256"] = "0" * 64
                elif change == "schema":selector["schema_version"] = "unreviewed"
                else:selector["invented"] = True
                self.files[self.selector_name] = self.encode(selector)
                with self.assertRaises(ValueError):self.check()

    def test_duplicate_json_keys_and_non_json_numbers_are_refused(self):
        selector = self.files[self.selector_name]
        self.files[self.selector_name] = selector.replace(b'"schema_version":', b'"schema_version": "duplicate", "schema_version":', 1)
        with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):self.check()
        self.files = dict(self.original_files)
        current = json.loads(self.files[self.result_name]);current["checks"][0]["seconds"] = float("nan")
        self.files[self.result_name] = self.encode(current);self.refresh_manifest()
        with self.assertRaisesRegex(ValueError, "Non-JSON number"):self.check()

    def test_packet_path_traversal_is_refused_before_file_read(self):
        manifest = json.loads(self.files[self.manifest_name])
        manifest["files"]["../outside"] = "a" * 64
        self.files[self.manifest_name] = self.encode(manifest)
        selector = json.loads(self.files[self.selector_name]);selector["packet_manifest_sha256"] = guard.digest(self.files[self.manifest_name])
        self.files[self.selector_name] = self.encode(selector)
        with self.assertRaisesRegex(ValueError, "Noncanonical archive path"):self.check()

    def test_aggregate_cannot_rewrite_original_check(self):
        current = json.loads(self.files[self.result_name]);current["checks"][0]["command"] = ["invented"]
        self.files[self.result_name] = self.encode(current);self.refresh_manifest()
        with self.assertRaisesRegex(ValueError, "differs from its original invocation"):self.check()

    def test_current_runner_is_parsed_as_data_and_never_executed(self):
        current = json.loads(self.files[self.result_name])
        runner_path = "formal/run_checks.py"
        altered = self.files[runner_path] + b'\nraise RuntimeError("must not execute this validated source")\n'
        self.files[runner_path] = altered
        self.files[self.base + current["current_runner"]["path"]] = altered
        current["current_runner"]["sha256"] = guard.digest(altered)
        self.files[self.result_name] = self.encode(current);self.refresh_manifest()
        self.assertEqual(self.check()["checks"], self.actual_summary["checks"])

    def test_actual_aggregate_matches_retained_structural_schema(self):
        from jsonschema import Draft202012Validator
        schema = json.loads(self.files[self.base + "result-schema.json"])
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(json.loads(self.files[self.result_name]))

    def test_fixed_v3_subset_has_documented_numeric_restrictions(self):
        from jsonschema import Draft202012Validator
        schema = json.loads(self.files[self.base + "result-schema.json"])
        value = json.loads(self.files[self.result_name])
        value["sources"][0]["settings"]["tlc_workers"] = 1.0
        # Generic JSON Schema treats 1.0 as an integer; retained records require integer tokens.
        Draft202012Validator(schema).validate(value)
        with self.assertRaisesRegex(ValueError, "integer"):guard.formal_aggregate_shape(value)
        value = json.loads(self.files[self.result_name]);value["checks"][0]["seconds"] = float("inf")
        with self.assertRaisesRegex(ValueError, "finite nonnegative"):guard.formal_aggregate_shape(value)

    def test_filesystem_reader_confines_symlinks_and_canonical_names(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp);root = base / "source";root.mkdir()
            (root / "valid.txt").write_bytes(b"inside")
            (base / "outside.txt").write_bytes(b"outside")
            (root / "escape").symlink_to(base / "outside.txt")
            reader = guard.SourceFiles(root)
            self.assertEqual(reader["valid.txt"], b"inside")
            for name in ("../outside.txt", "/outside.txt", "./valid.txt", "bad\\name", "escape", "."):
                with self.subTest(name=name), self.assertRaises(ValueError):reader[name]

    def test_stale_selector_and_runner_fail_cli(self):
        # In-memory controls above establish the detailed reasons. CLI failures
        # are checked in a small copied source surface without altering this checkout.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, data in self.files.items():
                path = root / name;path.parent.mkdir(parents=True, exist_ok=True);path.write_bytes(data)
            selector = root / self.selector_name
            original = selector.read_bytes();value = json.loads(original)
            value["packet_manifest_sha256"] = "0" * 64;selector.write_bytes(self.encode(value))
            command = [sys.executable, str(ROOT / "formal/check_recorded_results.py"), "--source-root", str(root)]
            result = subprocess.run(command,capture_output=True,text=True,check=False)
            self.assertEqual(result.returncode,1);self.assertIn("manifest changed",result.stderr)
            selector.write_bytes(original)
            runner_path = root / "formal/run_checks.py";runner_path.write_bytes(runner_path.read_bytes()+b"\n")
            result = subprocess.run(command,capture_output=True,text=True,check=False)
            self.assertEqual(result.returncode,1);self.assertIn("runner changed",result.stderr)


if __name__ == "__main__":
    unittest.main()
