import json
import tempfile
import unittest
from pathlib import Path

from scripts.live_network_log_ingest import ingest_once
from scripts.security_event_store import SecurityEventStore


def zeek_line(ts=1.0, uid="C123"):
    return json.dumps({"ts": ts, "uid": uid, "id.orig_h": "10.0.0.1",
                       "id.orig_p": 1234, "id.resp_h": "10.0.0.2",
                       "id.resp_p": 443, "proto": "tcp", "conn_state": "SF"}) + "\n"


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

    def test_checkpoint_cannot_be_reused_across_tenants(self):
        self.log.write_text(zeek_line(2.0), encoding="utf-8")
        ingest_once(log_path=self.log, database=self.db, checkpoint=self.cursor,
                    provider="zeek", tenant_id="tenant-a", from_start=True, now_ms=10_000)
        with self.assertRaises(Exception):
            ingest_once(log_path=self.log, database=self.db, checkpoint=self.cursor,
                        provider="zeek", tenant_id="tenant-b", now_ms=10_000)


if __name__ == "__main__":
    unittest.main()
