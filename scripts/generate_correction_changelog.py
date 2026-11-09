"""Reproduce the v1.0.1 changelog from the original archive and correction record."""
from pathlib import Path
import argparse
import hashlib
import json
import zipfile


def render(root: Path, original_archive: Path) -> str:
    record = json.loads((root / 'release/CORRECTIONS-1.0.1.json').read_text())
    digest = hashlib.sha256(original_archive.read_bytes()).hexdigest()
    if digest != record['original_source_archive_sha256']:
        raise ValueError('Original release archive digest mismatch')
    with zipfile.ZipFile(original_archive) as archive:
        original = archive.read('CHANGELOG.md').decode('utf-8')
        before = json.loads(archive.read('registries/requirements-compiled.json'))
        if archive.read('registries/requirement-ledger.json') != (root / 'registries/requirement-ledger.json').read_bytes():
            raise ValueError('Historical requirement ledger changed')
    current = json.loads((root / 'registries/requirements-compiled.json').read_text())
    old = {r['requirement_id']: r for r in before['requirements']}
    new = {r['requirement_id']: r for r in current['requirements']}
    changed = sorted(k for k in new if k in old and new[k]['text'] != old[k]['text'])
    if old.keys() != new.keys() or changed != [r['requirement_id'] for r in record['changed_requirement_text']]:
        raise ValueError('Correction record disagrees with requirement texts')
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
reference edition. It retains all {len(new)} requirement identifiers; {len(changed)} requirement
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
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    expected = render(args.root, args.original_archive)
    target = args.root / 'CHANGELOG.md'
    if args.check:
        if target.read_text() != expected:
            raise SystemExit('Correction changelog is stale')
        print('Correction changelog matches its recorded inputs')
    else:
        target.write_text(expected)


if __name__ == '__main__':
    main()
