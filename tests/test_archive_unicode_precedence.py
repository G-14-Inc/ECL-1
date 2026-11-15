"""Forbidden Unicode extras do not outrank ordered profile checks.

Robert F. Tilley Jr.; G-14, Inc. These bounded cases need no decompression.
"""
import base64
import hashlib
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from ecl_verify import offline
from scripts.generate_archive_metadata_boundaries import archive, entry, stored_archive

ROOT = Path(__file__).resolve().parents[1]


class ArchiveUnicodePrecedence(unittest.TestCase):
    def view(self, value):
        central = []
        count = offline._central_directory_count(value, members=central, keep=10)
        self.assertEqual(count, len(central))
        return offline._ProfileArchiveReader(value, central), central

    def test_public_unicode_cases_keep_profile_precedence(self):
        cases = json.loads((ROOT / 'tests/fixtures/archive-metadata-boundaries.json').read_text())['cases']
        selected = [row for row in cases if 'unicode' in row['id'] or row['id'] in ('ascii-control', 'stored-nonempty-control', 'empty-control')]
        self.assertGreaterEqual(len(selected), 21)
        for row in selected:
            with self.subTest(case=row['id']):
                value = base64.b64decode(row['archive_base64'])
                before = hashlib.sha256(value).digest()
                try:
                    offline.verify_zip_members(value, limits=offline.OfflineResourceLimits(**row['limits']))
                    code = 'accepted'
                except offline.OfflinePackageError as error:
                    code = error.code
                self.assertEqual(code, row['reader_code'])
                self.assertEqual(hashlib.sha256(value).digest(), before)

    def test_only_unicode_tag_bytes_are_masked(self):
        other = struct.pack('<HH', 0x1234, 2) + b'up'
        extra = other + struct.pack('<HH', 0x7075, 2) + b'up' + other + struct.pack('<HH', 0x7075, 0)
        value = archive([entry(extra=extra), entry(b'b')])
        reader, central = self.view(value)
        start, stop = central[0].unicode_extra_range
        expected = bytearray(value)
        for at in (start + len(other), stop - 4):
            expected[at:at + 2] = b'\0\0'
        self.assertEqual(reader.read(), bytes(expected))
        self.assertEqual(reader.tell(), len(value))
        self.assertEqual(reader.getvalue(), value)
        self.assertIs(reader._original, value)
        self.assertIsNone(central[1].unicode_extra_range)

    def test_partial_reads_preserve_offsets_and_reconstruct(self):
        value = archive([entry(extra=struct.pack('<HH', 0x7075, 0))])
        reader, central = self.view(value)
        start, _ = central[0].unicode_extra_range
        expected = value[:start] + b'\0\0' + value[start + 2:]
        for width in (1, 2, 3, 7, len(value)):
            with self.subTest(width=width):
                reader.seek(0)
                chunks = []
                while part := reader.read(width):
                    chunks.append(part)
                self.assertEqual(b''.join(chunks), expected)
        for at in (start - 1, start, start + 1, start + 2):
            reader.seek(at)
            self.assertEqual(reader.read(1), expected[at:at + 1])
        reader.seek(start)
        self.assertEqual(reader.read(0), b'')
        self.assertEqual(reader.tell(), start)
        self.assertEqual(reader.read(None), expected[start:])
        reader.seek(len(value) + 5)
        self.assertEqual(reader.read(), b'')
        self.assertEqual(reader.tell(), len(value) + 5)

    def test_bytes_in_member_payload_are_unchanged(self):
        value = stored_archive([{'data': b'prefix\x75\x70\0\0suffix'}])
        reader, central = self.view(value)
        self.assertFalse(reader._extra_ranges)
        self.assertEqual(reader.read(), value)
        self.assertEqual(offline.verify_zip_members(value), ('a',))

    def test_other_extra_fields_are_not_masked(self):
        value = archive([entry(extra=struct.pack('<HH', 0x1234, 2) + b'up')])
        reader, _ = self.view(value)
        self.assertFalse(reader._extra_ranges)
        self.assertEqual(reader.read(), value)
        with self.assertRaises(offline.OfflinePackageError) as caught:
            offline.verify_zip_members(value)
        self.assertEqual(caught.exception.code, offline.SEMANTIC_INVALID)

    def test_span_records_are_bounded_by_member_limit(self):
        value = archive([entry(bytes([ord('a') + n]), extra=struct.pack('<HH', 0x7075, 0)) for n in range(5)])
        central = []
        self.assertEqual(offline._central_directory_count(value, members=central, keep=2), 5)
        self.assertEqual(len(central), 2)
        with patch.object(offline, '_ProfileArchiveReader', side_effect=AssertionError('library reached before member limit')):
            with self.assertRaises(offline.OfflinePackageError) as caught:
                offline.verify_zip_members(value, limits=offline.OfflineResourceLimits(max_member_count=2))
        self.assertEqual(caught.exception.code, offline.RESOURCE_LIMIT)

    def test_original_bytes_reach_exact_profile_layout_check(self):
        value = stored_archive([{'data': b'abc'}])
        original = offline._profile_layout_problem
        received = []
        def inspect(actual, members):
            received.append(actual)
            self.assertIs(actual, value)
            return original(actual, members)
        with patch.object(offline, '_profile_layout_problem', inspect):
            self.assertEqual(offline.verify_zip_members(value), ('a',))
        self.assertEqual(len(received), 1)


if __name__ == '__main__':
    unittest.main()
