import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts.normalize_network_logs import (
    ImportErrorSafe,
    normalize_suricata,
    normalize_zeek,
    read_records,
    write_output,
)


class NetworkLogNormalizerTests(unittest.TestCase):
    def test_suricata_alert_is_allowlisted_and_normalized(self):
        item = normalize_suricata({
            "timestamp": "2026-11-08T10:00:00.250+0300",
            "event_type": "alert",
            "flow_id": 1234,
            "src_ip": "10.0.0.5",
            "dest_ip": "192.0.2.8",
            "proto": "TCP",
            "payload": "must-not-be-exported",
            "alert": {
                "signature_id": 42,
                "signature": "Test signature",
                "severity": 1,
            },
        }, "tenant-a", "7.0.0")
        self.assertEqual(item["provider_id"], "suricata")
        self.assertEqual(item["severity"], "high")
        self.assertEqual(item["fields"]["src_ip"], "10.0.0.5")
        self.assertNotIn("payload", item["fields"])
        self.assertEqual(item["data_classification"], "internal")

    def test_suricata_timestamp_requires_timezone(self):
        with self.assertRaises(ImportErrorSafe):
            normalize_suricata({
                "timestamp": "2026-11-08T10:00:00",
                "event_type": "alert",
            }, "tenant-a", "unknown")

    def test_zeek_connection_only_exports_safe_allowlist(self):
        item = normalize_zeek({
            "ts": 1794128400.0,
            "uid": "Cabc123",
            "id.orig_h": "10.0.0.1",
            "id.resp_h": "10.0.0.2",
            "id.orig_p": 50000,
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "password": "never-export",
            "payload": "never-export",
        }, "tenant-a", "7.0.0", "conn")
        self.assertEqual(item["event_type"], "zeek.conn")
        self.assertEqual(item["fields"]["id.orig_h"], "10.0.0.1")
        self.assertNotIn("password", item["fields"])
        self.assertNotIn("payload", item["fields"])

    def test_zeek_requires_explicit_log_kind(self):
        with self.assertRaises(ImportErrorSafe):
            normalize_zeek({"ts": 1}, "tenant-a", "unknown", "http")

    def test_duplicate_json_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "eve.json"
            source.write_text('{"timestamp":"2026-11-08T10:00:00Z","event_type":"alert","event_type":"flow"}\n')
            with self.assertRaises(ImportErrorSafe):
                read_records(source, "suricata", "tenant-a", "unknown")

    def test_zeek_comment_lines_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "conn.log"
            source.write_text('#separator \\x09\n#fields ts uid id.orig_h\n{"ts":1794128400,"uid":"C1","id.orig_h":"10.0.0.1"}\n')
            lines = read_records(source, "zeek", "tenant-a", "7.0.0", "conn")
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["provider_id"], "zeek")

    def test_symlink_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "real.json"
            target.write_text('{"timestamp":"2026-11-08T10:00:00Z","event_type":"alert"}\n')
            link = Path(tmp) / "link.json"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable on this platform")
            with self.assertRaises(ImportErrorSafe):
                read_records(link, "suricata", "tenant-a", "unknown")

    def test_output_is_written_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "normalized.jsonl"
            write_output(['{"ok":true}'], str(target))
            self.assertEqual(target.read_text(), '{"ok":true}\n')
            self.assertFalse(any(p.name.startswith(".ujani-import-") for p in Path(tmp).iterdir()))


if __name__ == "__main__":
    unittest.main()
