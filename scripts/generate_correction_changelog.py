"""Reproduce the v1.0.1 changelog from the original archive and correction record."""
from pathlib import Path
import argparse
import hashlib
import json
import zipfile


def historical_inputs(
    root: Path, original_archive: Path, corrected_archive: Path | None = None,
    corrected_sha256: str | None = None,
) -> tuple[str, dict, dict, list[str]]:
    """Check the exact historical 53-row ledger against its two source editions.

    A later source draft is not the v1.0.1 after-image. Supply the preserved
    corrected archive and its independently recorded digest when checking history.
    """
    record_bytes = (root / 'release/CORRECTIONS-1.0.1.json').read_bytes()
    record = json.loads(record_bytes)
    digest = hashlib.sha256(original_archive.read_bytes()).hexdigest()
    if digest != record['original_source_archive_sha256']:
        raise ValueError('Original release archive digest mismatch')
    with zipfile.ZipFile(original_archive) as archive:
        original = archive.read('CHANGELOG.md').decode('utf-8')
        before = json.loads(archive.read('registries/requirements-compiled.json'))
        historical_ledger = archive.read('registries/requirement-ledger.json')
    if corrected_archive is not None:
        if corrected_sha256 is None or hashlib.sha256(corrected_archive.read_bytes()).hexdigest() != corrected_sha256:
            raise ValueError('Corrected release archive needs its matching recorded SHA-256')
        with zipfile.ZipFile(corrected_archive) as archive:
            if archive.read('release/CORRECTIONS-1.0.1.json') != record_bytes:
                raise ValueError('Historical correction record differs from the corrected release archive')
            after = json.loads(archive.read('registries/requirements-compiled.json'))
            after_ledger = archive.read('registries/requirement-ledger.json')
    else:
        if corrected_sha256 is not None:
            raise ValueError('Corrected archive SHA-256 requires a corrected archive')
        after = json.loads((root / 'registries/requirements-compiled.json').read_bytes())
        after_ledger = (root / 'registries/requirement-ledger.json').read_bytes()
    if historical_ledger != after_ledger:
        raise ValueError('Historical requirement ledger changed')
    old = {r['requirement_id']: r for r in before['requirements']}
    new = {r['requirement_id']: r for r in after['requirements']}
    if len(old) != len(before['requirements']) or len(new) != len(after['requirements']):
        raise ValueError('Historical requirement identifiers repeat')
    changed = sorted(k for k in new if k in old and new[k]['text'] != old[k]['text'])
    rows = record['changed_requirement_text']
    if old.keys() != new.keys() or changed != [r['requirement_id'] for r in rows]:
        raise ValueError('Correction record disagrees with historical requirement texts; a later draft requires the frozen corrected archive')
    if record['requirement_count'] != len(new) or record['requirements_added'] or record['requirements_removed']:
        raise ValueError('Correction record disagrees with the historical requirement inventory')
    for row in rows:
        identifier = row['requirement_id']
        for member, requirement in (('before', old[identifier]), ('after', new[identifier])):
            text = row[member]
            if text != requirement['text'] or hashlib.sha256(text.encode('utf-8')).hexdigest() != row[member + '_text_sha256']:
                raise ValueError(f'Correction record {identifier} {member} text or digest differs from its historical source')
        if row['source_path'] != old[identifier]['source_path'] or row['source_path'] != new[identifier]['source_path']:
            raise ValueError(f'Correction record {identifier} source path differs from its historical source')
    return original, old, new, changed


def render(root: Path, original_archive: Path, corrected_archive: Path | None = None, corrected_sha256: str | None = None) -> str:
    original, old, new, changed = historical_inputs(root, original_archive, corrected_archive, corrected_sha256)
    marker = 'Generated from `registries/requirement-ledger.json` (version 1.0).'
    if original.count(marker) != 1 or original.count('## 1.0\n') != 1:
        raise ValueError('Unexpected original changelog structure')
    original = original.replace(marker,
        'The historical version sections are generated from\n'
        '`registries/requirement-ledger.json` (version 1.0). The correction section\n'
        'is generated from `release/CORRECTIONS-1.0.1.json` by\n'
        '`scripts/generate_correction_changelog.py`, using the preserved original\n'
        'release archive as its historical input.')
    section = f'''## Correction release 1.0.1

This release corrects the Version 1.0 source and the accompanying Version 1
reference edition (erratum `ERR-1.0-001`). It retains all {len(new)} requirement identifiers; {len(changed)} requirement
texts differ from the original publication. The exact before/after texts are
in [CORRECTIONS-1.0.1.json](release/CORRECTIONS-1.0.1.json). The
[release notes](RELEASE-NOTES-1.0.md#correction-release-v101) describe the
verifier, model, corpus, explanatory and governance corrections. The earlier
version ledger below remains the historical record of the original release.

'''
    return original.replace('## 1.0\n', section + '## 1.0\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--original-archive', type=Path, required=True)
    parser.add_argument('--corrected-archive', type=Path, help='preserved v1.0.1 archive for checking the historical after-image')
    parser.add_argument('--corrected-sha256', help='independently recorded SHA-256 of that archive')
    parser.add_argument('--verify-record-only', action='store_true', help='validate historical ledger without comparing or writing the current changelog')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.verify_record_only:
        _, _, _, changed = historical_inputs(args.root, args.original_archive, args.corrected_archive, args.corrected_sha256)
        print(f'Historical correction record: {len(changed)} exact before/after texts and digests verified')
        return
    expected = render(args.root, args.original_archive, args.corrected_archive, args.corrected_sha256).encode('utf-8')
    target = args.root / 'CHANGELOG.md'
    if args.check:
        if target.read_bytes() != expected:
            raise SystemExit('Correction changelog is stale')
        print('Correction changelog matches its recorded inputs')
    else:
        target.write_bytes(expected)


if __name__ == '__main__':
    main()
