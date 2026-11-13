"""Check recorded formal-result provenance without running formal tools.

Robert F. Tilley Jr.; G-14, Inc.

The explicit hash-bound selector identifies the current packet; dates are not
used to discover one. This checker implements the retained fixed v3 contract,
not arbitrary JSON Schema. Its integer-token and finite-number checks are
stricter than generic JSON Schema's mathematical integer/number model.

The checks establish internal identity, coverage and source compatibility.
They do not authenticate the publisher, reclassify solver output, rerun proofs,
or establish that the modeled system matches an executable implementation.

The fixed-v3 helpers originate in the reference edition's pdf_inputs.py guard.
Historical PDF inputs retain their separate guard and are not reinterpreted here.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import re
import sys
from pathlib import Path, PurePosixPath

SELECTOR_SCHEMA = "ecl_formal_current_results_v1"
DEFAULT_SELECTOR = "formal/current-results.json"


def strict_json(data, label):
    """Decode UTF-8 JSON without duplicate keys or non-JSON numeric constants."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"Duplicate JSON key in {label}: {key}")
            result[key] = value
        return result

    def constant(value):
        raise ValueError(f"Non-JSON number in {label}: {value}")

    return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)


class SourceFiles:
    """Read only canonical files confined to the selected source root."""
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.cache = {}

    def __getitem__(self, name):
        name = source_name(name)
        if name not in self.cache:
            path = (self.root / name).resolve()
            require(path.is_relative_to(self.root), f"Source path escapes root: {name}")
            self.cache[name] = path.read_bytes()
        return self.cache[name]


def require(condition, message):
    if not condition:
        raise ValueError(message)



def digest(data):
    return hashlib.sha256(data).hexdigest()



def source_name(name):
    require(type(name) is str and bool(name), f'Noncanonical archive path: {name!r}')
    path = PurePosixPath(name)
    require(bool(path.parts) and '\x00' not in name and not path.is_absolute()
            and str(path) == name and '..' not in path.parts and '\\' not in name,
            f'Noncanonical archive path: {name!r}')
    return name



def _formal_object(value, label, required=(), optional=None):
    require(type(value) is dict and all(type(key) is str for key in value),
            f'Formal {label} must be an object with string keys')
    require(set(required) <= set(value), f'Formal {label} is missing fields')
    if optional is not None:
        require(set(value) <= set(required) | set(optional), f'Unexpected formal {label} fields')



def _formal_integer(value, label, minimum=None, nullable=False):
    if nullable and value is None:
        return
    require(type(value) is int and (minimum is None or value >= minimum),
            f'Formal {label} must be an integer in the supported range')



def _formal_hash(value, label):
    require(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None,
            f'Formal {label} must be a SHA-256 digest')



def _same_record_value(left, right):
    """Compare retained JSON values without Python's True == 1 coercion."""
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
        right, sort_keys=True, allow_nan=False)



def formal_aggregate_shape(current):
    """Validate this fixed v3 record format, not arbitrary JSON Schema.

    Recorded integer fields use JSON integer tokens (never booleans or floats).
    Numbers must be finite. Identity, hashes and coverage are checked separately.
    Keep these explicit fields aligned with the retained result-schema.json when
    reviewing a new aggregate format; this function does not interpret schemas.
    """
    _formal_object(current, 'aggregate', {'schema_version', 'tools', 'sources',
                   'check_sources', 'runners', 'current_runner', 'checks'}, ())
    require(current['schema_version'] == 'ecl_formal_results_v3', 'Unknown current aggregate')
    _formal_object(current['tools'], 'tools', {'tla2tools', 'tamarin', 'maude'})
    for tool, pin in current['tools'].items():
        _formal_object(pin, f'{tool} pin')
        require(all(type(value) is str for value in pin.values()), 'Formal pin values must be strings')
    require(type(current['sources']) is list and bool(current['sources']),
            'Formal sources must be a nonempty array')
    for entry in current['sources']:
        _formal_object(entry, 'source', {'id', 'path', 'sha256', 'format', 'settings'}, ())
        require(type(entry['id']) is str and re.fullmatch(r'[a-z][a-z0-9-]*', entry['id']) is not None,
                'Invalid invocation ID')
        source_name(entry['path'])
        _formal_hash(entry['sha256'], 'source hash')
        require(entry['format'] in ('ecl_formal_results_v2', 'tamarin-check-receipt'),
                'Review the invocation record format')
        settings = entry['settings']
        _formal_object(settings, 'settings', {'timeout_seconds', 'derivcheck_timeout'},
                       {'java_heap', 'tlc_workers'})
        for key, minimum in [('timeout_seconds', 1), ('derivcheck_timeout', 0), ('tlc_workers', 1)]:
            if key in settings:
                _formal_integer(settings[key], key, minimum)
        if 'java_heap' in settings:
            require(type(settings['java_heap']) is str, 'Formal java_heap must be a string')
    for key in ('check_sources', 'runners'):
        _formal_object(current[key], key)
        require(bool(current[key]) and all(type(value) is str for value in current[key].values()),
                f'Formal {key} must be a nonempty string mapping')
    for sha, path in current['runners'].items():
        _formal_hash(sha, 'runner map key')
        source_name(path)
    _formal_object(current['current_runner'], 'current runner', {'path', 'sha256'}, ())
    source_name(current['current_runner']['path'])
    _formal_hash(current['current_runner']['sha256'], 'current runner hash')
    require(type(current['checks']) is list and bool(current['checks']),
            'Formal checks must be a nonempty array')
    strings = {'name', 'expected', 'observed', 'started_utc', 'finished_utc'}
    metrics = {'states_generated', 'distinct_states', 'depth', 'trace_states'}
    fields = strings | metrics | {'tool', 'passed', 'seconds', 'java', 'runner_sha256',
             'output_sha256', 'inputs', 'command', 'log_file', 'returncode', 'lemmas', 'steps'}
    for check in current['checks']:
        _formal_object(check, 'check', fields, ())
        require(all(type(check[key]) is str for key in strings), 'Formal check text must be strings')
        require(check['tool'] in ('tlc', 'tamarin') and type(check['passed']) is bool,
                'Invalid formal tool or passed flag')
        seconds = check['seconds']
        require((type(seconds) is int or type(seconds) is float and math.isfinite(seconds))
                and seconds >= 0, 'Formal seconds must be a finite nonnegative number')
        require(check['java'] is None or type(check['java']) is str, 'Invalid formal Java version')
        for key in ('runner_sha256', 'output_sha256'):
            _formal_hash(check[key], key)
        _formal_object(check['inputs'], 'inputs')
        require(bool(check['inputs']), 'Formal inputs must not be empty')
        for value in check['inputs'].values():
            _formal_hash(value, 'input hash')
        require(type(check['command']) is list and bool(check['command'])
                and all(type(arg) is str for arg in check['command']),
                'Formal command must be a nonempty array of strings')
        require(type(check['log_file']) is str and
                re.fullmatch(r'[^/\\]+\.log', check['log_file']) is not None, 'Invalid formal log name')
        _formal_integer(check['returncode'], 'returncode', nullable=True)
        for key in metrics:
            _formal_integer(check[key], key, 0, nullable=True)
        _formal_object(check['lemmas'], 'lemmas')
        require(all(type(value) is str for value in check['lemmas'].values()),
                'Formal lemma outcomes must be strings')
        _formal_object(check['steps'], 'steps')
        for value in check['steps'].values():
            _formal_integer(value, 'proof steps', 0)



def current_aggregate_sources(files, base, current, current_path, bind):
    """Validate the complete v3 provenance partition without executing source code."""
    formal_aggregate_shape(current)
    checks = {check['name']: check for check in current['checks']}
    require(bool(checks) and len(checks) == len(current['checks']), 'Duplicate aggregate check')
    require(set(current['check_sources']) == set(checks), 'Incomplete check-to-source map')
    covered, source_ids = set(), set()
    for entry in current['sources']:
        require(set(entry) == {'id', 'path', 'sha256', 'format', 'settings'},
                'Review the invocation descriptor fields')
        require(re.fullmatch(r'[a-z][a-z0-9-]*', entry['id']) is not None
                and entry['id'] not in source_ids, 'Duplicate or invalid invocation ID')
        source_ids.add(entry['id'])
        path = base + source_name(entry['path'])
        bind(current_path, '@invocation', 'source-record', path, entry['sha256'])
        record = strict_json(files[path], path)
        if entry['format'] == 'ecl_formal_results_v2':
            require(record.get('schema_version') == entry['format'], 'Invocation format differs')
            settings, pins = record['settings'], record['tools']
        elif entry['format'] == 'tamarin-check-receipt':
            require('schema_version' not in record and record.get('complete') is True
                    and record.get('all_expected') is True, 'Incomplete symbolic invocation')
            settings = {name: record[name] for name in ('timeout_seconds', 'derivcheck_timeout')}
            pins = record['pins']
        else:
            raise ValueError('Review the invocation record format')
        require(_same_record_value(settings, entry['settings']) and _same_record_value(pins, current['tools']),
                'Invocation settings or pins differ')
        source_checks = {check['name']: check for check in record['checks']}
        require(bool(source_checks) and len(source_checks) == len(record['checks']),
                'Duplicate or empty invocation check set')
        require(not covered.intersection(source_checks), 'Check repeated across invocations')
        for name, check in source_checks.items():
            require(_same_record_value(checks.get(name), check) and current['check_sources'].get(name) == entry['id'],
                    'Aggregate check differs from its original invocation')
            require(check['passed'] is True and check['expected'] == check['observed'],
                    'Invocation expected outcome did not match')
            require(all(check.get(key) for key in ('started_utc', 'finished_utc', 'command',
                                                   'runner_sha256', 'output_sha256')),
                    'Invocation provenance is incomplete')
            if 'runner_sha256' in record:
                require(record['runner_sha256'] == check['runner_sha256'],
                        'Invocation runner differs from its check')
        covered.update(source_checks)
    require(covered == set(checks) and set(current['check_sources'].values()) == source_ids,
            'Invocation partition omits or invents checks')
    used_runners = {check['runner_sha256'] for check in checks.values()}
    require(set(current['runners']) == used_runners, 'Invocation runner inventory differs')
    for sha, path in current['runners'].items():
        require(re.fullmatch(r'[0-9a-f]{64}', sha) is not None
                and path == f'runners/{sha}/run_checks.py', 'Noncanonical invocation runner path')
        bind(current_path, '@invocation', 'runner', base + source_name(path), sha)
    runner = current['current_runner']
    require(set(runner) == {'path', 'sha256'} and runner['path'] == 'inputs/formal/run_checks.py',
            'Review the current runner descriptor')
    for path in (base + runner['path'], 'formal/run_checks.py'):
        bind(current_path, '@current', 'runner', path, runner['sha256'])

    # Only literal registries are inspected. Importing a supplied runner would execute it.
    registries = {}
    for node in ast.parse(files['formal/run_checks.py'].decode('utf-8')).body:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        for target in targets:
            if isinstance(target, ast.Name) and target.id in {'TLC_CHECKS', 'TAMARIN_CHECKS', 'PINS'}:
                require(target.id not in registries, 'Repeated formal registry assignment')
                registries[target.id] = ast.literal_eval(node.value)
    require(set(registries) == {'TLC_CHECKS', 'TAMARIN_CHECKS', 'PINS'},
            'Review current runner registry syntax')
    pins = {name: {key: value for key, value in pin.items() if key != 'source'}
            for name, pin in registries['PINS'].items()}
    require(pins == current['tools'], 'Current runner pins differ from invocations')
    tlc, tamarin = registries['TLC_CHECKS'], registries['TAMARIN_CHECKS']
    require(not set(tlc).intersection(tamarin) and set(checks) == set(tlc) | set(tamarin),
            'Current registry and aggregate checks differ')
    for name, check in checks.items():
        tool = 'tlc' if name in tlc else 'tamarin'
        expected = tlc[name] if tool == 'tlc' else ('all verified' if tamarin[name][1] is None
                   else f'{tamarin[name][1]} falsified')
        required_inputs = ({'tla/ECLCore.tla', 'tla/MC.tla', f'tla/configs/{name}.cfg'}
                           if tool == 'tlc' else {'protocol/DCMP2_Binding.spthy'})
        require(check['tool'] == tool and check['expected'] == expected
                and set(check['inputs']) == required_inputs,
                'Current registry expectation or input set differs')



def validate_recorded_results(files, selector_path=DEFAULT_SELECTOR):
    """Validate the selected fixed-v3 packet using a path-to-bytes reader.

    A dict works for isolated mutation tests; SourceFiles confines filesystem
    access in the CLI. Neither form imports or executes any supplied source.
    """
    selector_path = source_name(selector_path)
    selector = strict_json(files[selector_path], selector_path)
    _formal_object(selector, "current-results selector",
                   {"schema_version", "packet_manifest", "packet_manifest_sha256"}, ())
    require(selector["schema_version"] == SELECTOR_SCHEMA, "Unknown current-results selector")
    manifest_path = source_name(selector["packet_manifest"])
    _formal_hash(selector["packet_manifest_sha256"], "selected manifest hash")
    manifest_bytes = files[manifest_path]
    require(digest(manifest_bytes) == selector["packet_manifest_sha256"],
            "Selected formal packet manifest changed")
    manifest = strict_json(manifest_bytes, manifest_path)
    _formal_object(manifest, "packet manifest", {"files", "record", "record_sha256"})
    _formal_object(manifest["files"], "packet file manifest")
    require(bool(manifest["files"]), "Formal packet manifest must not be empty")
    parent = str(PurePosixPath(manifest_path).parent)
    base = "" if parent == "." else parent + "/"
    record_path = base + source_name(manifest["record"])
    _formal_hash(manifest["record_sha256"], "record hash")
    bindings = []

    def bind(record, check, kind, path, sha):
        path = source_name(path)
        _formal_hash(sha, "bound hash")
        require(digest(files[path]) == sha, f"Formal {kind} changed: {path}")
        bindings.append({"kind": kind, "path": path, "sha256": sha})

    for name, sha in manifest["files"].items():
        bind(record_path, "@packet", "packet-file", base + source_name(name), sha)
    require(manifest["files"].get(manifest["record"]) == manifest["record_sha256"],
            "Selected result is absent from the manifest or has another digest")
    bind(record_path, "@packet", "record", record_path, manifest["record_sha256"])
    # Retain and hash the declared structural schema. Shape validation below is
    # the explicitly supported fixed-v3 subset, not evaluation of this schema.
    require("result-schema.json" in manifest["files"], "Formal result schema is not retained")
    current = strict_json(files[record_path], record_path)
    current_aggregate_sources(files, base, current, record_path, bind)
    for check in current["checks"]:
        for name, sha in check["inputs"].items():
            name = source_name(name)
            bind(record_path, check["name"], "recorded-input", base + "inputs/formal/" + name, sha)
            bind(record_path, check["name"], "current-input", "formal/" + name, sha)
        log_name = source_name(check["log_file"])
        require("/" not in log_name, "Formal log name must be one path component")
        bind(record_path, check["name"], "output", base + "logs/" + log_name,
             check["output_sha256"])
    for binding in bindings:
        if binding["path"].startswith(base):
            member = binding["path"][len(base):]
            require(manifest["files"].get(member) == binding["sha256"],
                    f"Referenced formal packet member is missing or differs in manifest: {member}")
    return {
        "selector": selector_path,
        "selector_sha256": digest(files[selector_path]),
        "packet_manifest": manifest_path,
        "packet_manifest_sha256": selector["packet_manifest_sha256"],
        "record": record_path,
        "record_sha256": manifest["record_sha256"],
        "checks": len(current["checks"]),
        "checks_by_tool": {tool: sum(check["tool"] == tool for check in current["checks"])
                           for tool in ("tlc", "tamarin")},
        "sources": current["sources"],
        "invocation_runners": current["runners"],
        "current_runner": current["current_runner"],
        "verified_bindings": len(bindings),
        "formal_tools_run": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--selector", default=DEFAULT_SELECTOR,
                        help="Canonical path relative to the source root")
    args = parser.parse_args(argv)
    try:
        result = validate_recorded_results(SourceFiles(args.source_root), args.selector)
    except (ValueError, TypeError, KeyError, OSError, SyntaxError) as error:
        print(f"Recorded formal results check failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
