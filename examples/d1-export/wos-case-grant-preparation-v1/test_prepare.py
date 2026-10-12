"""Checks for the committed-reservation alternative; no live grant operations."""
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('prepare', Path(__file__).with_name('prepare.py'))
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class CommittedStartTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.start = {'caseLedgerId': 'urn:wos:test_case_example', 'caseReference': '123',
                      'draftRef': 'urn:formspec:draft:test', 'status': 'in-progress'}
        binding = {'sourceId': 'urn:formspec:source:test'}
        row = {'case_id': 'test_case_example', 'case_reference': '123',
               'draft_ref': self.start['draftRef'], 'source_id': binding['sourceId'],
               'source_binding': binding,
               'outcome_bytes': '\\x' + json.dumps(self.start).encode().hex()}
        rows = json.dumps(row).encode() + b'\n'
        self.rows_path = self.root / 'rows.private.jsonl'
        self.rows_path.write_bytes(rows)
        self.rows_path.chmod(0o600)
        receipt = {'status': 'ACTUAL_STARTED_CASE_SOURCE_OWNER_BINDING_READBACK_PASS',
                   'caseId': row['case_id'], 'caseReference': '123',
                   'draftRef': row['draft_ref'], 'sourceBinding': binding,
                   'privateRowsSha256': hashlib.sha256(rows).hexdigest()}
        path = self.root / 'receipt.json'
        raw = json.dumps(receipt).encode()
        path.write_bytes(raw)
        self.ref = {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'pointer': ''}

    def test_committed_outcome_needs_no_http_status(self):
        prepare.validate_committed_start(self.ref, self.start)

    def test_different_outcome_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'persisted Start outcome differs'):
            prepare.validate_committed_start(self.ref, {**self.start, 'draftRef': 'wrong'})

    def test_changed_rows_are_refused(self):
        self.rows_path.write_bytes(b'{}\n')
        with self.assertRaisesRegex(ValueError, 'reservation rows hash differs'):
            prepare.validate_committed_start(self.ref, self.start)


if __name__ == '__main__':
    unittest.main()
