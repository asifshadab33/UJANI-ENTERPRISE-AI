import hashlib
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.security_event_store import SecurityEventStore, StoreError


def event(tenant="tenant-a", provider="zeek", event_type="zeek.notice", severity="medium", ts=1000, suffix="1"):
    event_id = hashlib.sha256(suffix.encode()).hexdigest()
    return {
        "schema_version": "1.0", "event_id": event_id, "tenant_id": tenant,
        "provider_id": provider, "provider_version": "7.0.0",
        "event_type": event_type, "severity": severity,
        "observed_at_unix_ms": ts, "source_ref": "uid:C123",
        "summary": "Zeek notice observed", "data_classification": "internal",
        "fields": {"note": "Suspicious activity"},
    }


class SecurityEventStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = SecurityEventStore(Path(self.temp.name) / "events.sqlite3",
                                        max_records_per_tenant=3, retention_ms=60_000)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    @unittest.skipIf(os.name == "nt", "symlink creation may require elevated Windows privileges")
    def test_rejects_dangling_database_symlink(self):
        target = Path(self.temp.name) / "not-created.sqlite3"
        link = Path(self.temp.name) / "dangling.sqlite3"
        link.symlink_to(target)
        with self.assertRaisesRegex(StoreError, "database path must not be a symlink"):
            SecurityEventStore(link)
        self.assertFalse(target.exists())

    @unittest.skipIf(os.name == "nt", "directory symlink creation may require elevated Windows privileges")
    def test_pins_database_path_to_canonical_parent(self):
        root = Path(self.temp.name)
        real_parent = root / "real"
        alias_parent = root / "alias"
        real_parent.mkdir()
        alias_parent.symlink_to(real_parent, target_is_directory=True)

        store = SecurityEventStore(alias_parent / "events.sqlite3")
        try:
            self.assertEqual(Path(store.database), real_parent.resolve(strict=True) / "events.sqlite3")
        finally:
            store.close()
        self.assertTrue((real_parent / "events.sqlite3").is_file())

    def test_ingest_search_and_tenant_isolation(self):
        self.assertEqual(self.store.ingest([event()], tenant_id="tenant-a", provider_id="zeek", now_ms=2000), 1)
        self.assertEqual(len(self.store.search(tenant_id="tenant-a", provider_id="zeek")), 1)
        self.assertEqual(self.store.search(tenant_id="tenant-b"), [])
        self.assertEqual(self.store.count(tenant_id="tenant-b"), 0)

    def test_duplicate_is_idempotent(self):
        item = event()
        self.assertEqual(self.store.ingest([item, item], tenant_id="tenant-a", provider_id="zeek", now_ms=2000), 1)
        self.assertEqual(self.store.count(tenant_id="tenant-a"), 1)

    def test_rejects_cross_tenant_provider_and_future_timestamp(self):
        with self.assertRaises(StoreError):
            self.store.ingest([event(tenant="tenant-b")], tenant_id="tenant-a", provider_id="zeek", now_ms=2000)
        with self.assertRaises(StoreError):
            self.store.ingest([event(provider="suricata")], tenant_id="tenant-a", provider_id="zeek", now_ms=2000)
        with self.assertRaises(StoreError):
            self.store.ingest([event(ts=40_000)], tenant_id="tenant-a", provider_id="zeek", now_ms=2000)

    def test_batch_is_atomic_on_invalid_record(self):
        good = event(suffix="good")
        bad = event(suffix="bad")
        bad["fields"] = {"x": "y" * 2000}
        with self.assertRaises(StoreError):
            self.store.ingest([good, bad], tenant_id="tenant-a", provider_id="zeek", now_ms=2000)
        self.assertEqual(self.store.count(tenant_id="tenant-a"), 0)

    def test_filters_and_keyset_pagination(self):
        rows = [event(ts=1000 + i, suffix=str(i)) for i in range(3)]
        self.store.ingest(rows, tenant_id="tenant-a", provider_id="zeek", now_ms=3000)
        page = self.store.search(tenant_id="tenant-a", limit=2, severity="medium")
        self.assertEqual(len(page), 2)
        cursor = (page[-1]["observed_at_unix_ms"], page[-1]["event_id"])
        next_page = self.store.search(tenant_id="tenant-a", after=cursor, limit=2)
        self.assertEqual(len(next_page), 1)
        self.assertNotEqual(page[0]["event_id"], next_page[0]["event_id"])

    def test_retention_and_per_tenant_cap(self):
        rows = [event(ts=1000 + i, suffix=str(i)) for i in range(5)]
        self.store.ingest(rows, tenant_id="tenant-a", provider_id="zeek", now_ms=3000)
        self.assertEqual(self.store.count(tenant_id="tenant-a"), 3)

    def test_rejects_events_outside_retention_window(self):
        with self.assertRaises(StoreError):
            self.store.ingest([event(ts=1)], tenant_id="tenant-a", provider_id="zeek", now_ms=100_000)
        self.assertEqual(self.store.count(tenant_id="tenant-a"), 0)

    def test_rejects_non_string_tenant_values_with_store_error(self):
        for tenant in (None, 7, [], {}):
            with self.subTest(tenant=tenant):
                with self.assertRaises(StoreError):
                    self.store.ingest([event()], tenant_id=tenant, provider_id="zeek", now_ms=2000)
                with self.assertRaises(StoreError):
                    self.store.count(tenant_id=tenant)

    def test_begin_lock_failure_is_not_masked_by_rollback(self):
        locker = sqlite3.connect(self.store.database, isolation_level=None)
        try:
            locker.execute("BEGIN EXCLUSIVE")
            self.store._db.execute("PRAGMA busy_timeout=0")
            with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                self.store.ingest([event()], tenant_id="tenant-a", provider_id="zeek", now_ms=2000)
        finally:
            if locker.in_transaction:
                locker.execute("ROLLBACK")
            locker.close()

    def test_rejects_unhashable_search_filters_and_non_iterable_batches(self):
        with self.assertRaises(StoreError):
            self.store.search(tenant_id="tenant-a", provider_id=[])
        with self.assertRaises(StoreError):
            self.store.search(tenant_id="tenant-a", severity={})
        with self.assertRaises(StoreError):
            self.store.ingest(None, tenant_id="tenant-a", provider_id="zeek", now_ms=2000)

    def test_rejects_missing_tenant_and_bad_limits(self):
        with self.assertRaises(StoreError):
            self.store.search(tenant_id="../other")
        with self.assertRaises(StoreError):
            self.store.search(tenant_id="tenant-a", limit=1000)


if __name__ == "__main__":
    unittest.main()
