import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts.live_network_log_ingest import ingest_once
from scripts.normalize_network_logs import ImportErrorSafe
from scripts.security_event_store import SecurityEventStore


def zeek_line(ts=1.0, uid="C123"):
    return json.dumps({"ts": ts, "uid": uid, "id.orig_h": "10.0.0.1",
                       "id.orig_p": 1234, "id.resp_h": "10.0.0.2",
                       "id.resp_p": 443, "proto": "tcp", "conn_state": "SF"}) + "\n"


def zeek_notice_line(ts=1.0, uid="N123"):
    return json.dumps({"ts": ts, "uid": uid, "note": "SSH::Password_Guessing",
                       "sub": "repeated failures", "src": "10.0.0.5",
                       "dst": "10.0.0.6", "p": 22, "password": "must-not-export"}) + "\n"


def zeek_weird_line(ts=1.0, uid="W123"):
    return json.dumps({"ts": ts, "uid": uid, "name": "bad_TCP_checksum",
                       "id.orig_h": "10.0.0.7", "id.resp_h": "10.0.0.8",
                       "proto": "tcp", "payload": "must-not-export"}) + "\n"


class LiveNetworkLogIngestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.log = self.root / "conn.json"
        self.db = self.root / "events.sqlite3"
        self.cursor = self.root / "cursor.json"

    def tearDown(self):
        self.temp.cleanup()

    def count(self):
        store = SecurityEventStore(self.db)
        try:
            return store.count(tenant_id="tenant-a")
        finally:
            store.close()

    def test_starts_at_end_then_ingests_appended_complete_lines(self):
        self.log.write_text(zeek_line(1.0, "old"), encoding="utf-8")
        inserted, read_count, _ = ingest_once(
            log_path=self.log, database=self.db, checkpoint=self.cursor,
            provider="zeek", tenant_id="tenant-a", now_ms=10_000,
        )
        self.assertEqual((inserted, read_count), (0, 0))
        with self.log.open("a", encoding="utf-8") as stream:
            stream.write(zeek_line(2.0, "new"))
        inserted, read_count, _ = ingest_once(
            log_path=self.log, database=self.db, checkpoint=self.cursor,
            provider="zeek", tenant_id="tenant-a", now_ms=10_000,
        )
        self.assertEqual((inserted, read_count), (1, 1))
        self.assertEqual(self.count(), 1)

    def test_partial_final_line_is_not_checkpointed(self):
        self.log.write_text('{"ts": 2.0, "uid": "partial"', encoding="utf-8")
        inserted, read_count, offset = ingest_once(
            log_path=self.log, database=self.db, checkpoint=self.cursor,
            provider="zeek", tenant_id="tenant-a", from_start=True, now_ms=10_000,
        )
        self.assertEqual((inserted, read_count, offset), (0, 0, 0))

    def test_rotation_resets_cursor_and_replays_safely(self):
        self.log.write_text(zeek_line(2.0, "first"), encoding="utf-8")
        ingest_once(log_path=self.log, database=self.db, checkpoint=self.cursor,
                    provider="zeek", tenant_id="tenant-a", from_start=True, now_ms=10_000)
        rotated = self.root / "old.json"
        self.log.rename(rotated)
        self.log.write_text(zeek_line(3.0, "second"), encoding="utf-8")
        inserted, read_count, _ = ingest_once(
            log_path=self.log, database=self.db, checkpoint=self.cursor,
            provider="zeek", tenant_id="tenant-a", now_ms=10_000,
        )
        self.assertEqual((inserted, read_count), (1, 1))
        self.assertEqual(self.count(), 2)

    @unittest.skipIf(os.name == "nt", "symlink creation may require elevated Windows privileges")
    def test_rejects_dangling_checkpoint_symlink(self):
        target = self.root / "missing-cursor.json"
        self.cursor.symlink_to(target)
        self.log.write_text(zeek_line(2.0, "dangling"), encoding="utf-8")
        with self.assertRaisesRegex(ImportErrorSafe, "checkpoint must not be a symlink"):
            ingest_once(log_path=self.log, database=self.db, checkpoint=self.cursor,
                        provider="zeek", tenant_id="tenant-a", now_ms=10_000)
        self.assertFalse(target.exists())

    def test_checkpoint_cannot_be_reused_across_tenants(self):
        self.log.write_text(zeek_line(2.0), encoding="utf-8")
        ingest_once(log_path=self.log, database=self.db, checkpoint=self.cursor,
                    provider="zeek", tenant_id="tenant-a", from_start=True, now_ms=10_000)
        with self.assertRaises(ImportErrorSafe):
            ingest_once(log_path=self.log, database=self.db, checkpoint=self.cursor,
                        provider="zeek", tenant_id="tenant-b", now_ms=10_000)

    def test_notice_and_weird_streams_use_separate_checkpoints_and_types(self):
        notice_cursor = self.root / "notice-cursor.json"
        weird_cursor = self.root / "weird-cursor.json"
        self.log.write_text(zeek_notice_line(2.0), encoding="utf-8")
        inserted, read_count, _ = ingest_once(
            log_path=self.log, database=self.db, checkpoint=notice_cursor,
            provider="zeek", tenant_id="tenant-a", from_start=True, now_ms=10_000,
            zeek_log_kind="notice",
        )
        self.assertEqual((inserted, read_count), (1, 1))
        self.log.write_text(zeek_weird_line(3.0), encoding="utf-8")
        inserted, read_count, _ = ingest_once(
            log_path=self.log, database=self.db, checkpoint=weird_cursor,
            provider="zeek", tenant_id="tenant-a", from_start=True, now_ms=10_000,
            zeek_log_kind="weird",
        )
        self.assertEqual((inserted, read_count), (1, 1))
        store = SecurityEventStore(self.db)
        try:
            events = store.search(tenant_id="tenant-a", limit=10)
        finally:
            store.close()
        self.assertEqual({item["event_type"] for item in events}, {"zeek.notice", "zeek.weird"})

    def test_checkpoint_cannot_be_reused_for_another_zeek_log_kind(self):
        self.log.write_text(zeek_notice_line(2.0), encoding="utf-8")
        ingest_once(log_path=self.log, database=self.db, checkpoint=self.cursor,
                    provider="zeek", tenant_id="tenant-a", from_start=True,
                    now_ms=10_000, zeek_log_kind="notice")
        with self.assertRaises(ImportErrorSafe):
            ingest_once(log_path=self.log, database=self.db, checkpoint=self.cursor,
                        provider="zeek", tenant_id="tenant-a", now_ms=10_000,
                        zeek_log_kind="weird")


if __name__ == "__main__":
    unittest.main()
