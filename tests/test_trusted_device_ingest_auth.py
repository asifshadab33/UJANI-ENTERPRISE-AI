import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from scripts.security_event_store import SecurityEventStore
from scripts.trusted_device_ingest_auth import (
    AuthenticationError, authenticate_envelope, sign_envelope,
)
from scripts.trusted_network_event_ingest import (
    IngestionEnvelopeError, authenticate_and_ingest,
)


class TrustedDeviceAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.replay = Path(self.temp.name) / "replay.sqlite3"
        self.secret = b"x" * 32
        self.registry = {
            "device-01": {"tenant_id": "tenant-a", "secret": self.secret, "revoked": False},
        }
        self.body = b'{"events":[]}'
        self.timestamp = 1_000_000
        self.nonce = "abcdefghijklmnopqrstuvwx12345678"
        self.signature = sign_envelope(self.secret, self.timestamp, self.nonce, self.body)

    def tearDown(self):
        self.temp.cleanup()

    def call_auth(self, **overrides):
        args = {
            "device_id": "device-01", "timestamp": self.timestamp,
            "nonce": self.nonce, "body": self.body, "signature": self.signature,
            "registry": self.registry, "replay_database": self.replay,
            "now_seconds": self.timestamp,
        }
        args.update(overrides)
        return authenticate_envelope(**args)

    def test_returns_tenant_from_registry_not_request_body(self):
        self.assertEqual(self.call_auth(), "tenant-a")

    def test_rejects_replay(self):
        self.call_auth()
        with self.assertRaises(AuthenticationError):
            self.call_auth()

    def test_concurrent_replay_accepts_nonce_at_most_once(self):
        # Independent SQLite connections model concurrent receiver workers.
        def attempt(_):
            try:
                self.call_auth()
                return True
            except AuthenticationError:
                return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(attempt, range(8)))
        self.assertEqual(sum(outcomes), 1)

    def test_concurrent_replay_is_single_use_across_processes(self):
        # Separate processes prove that SQLite, not only a Python thread lock,
        # serializes nonce consumption across independent receiver workers.
        repo_root = Path(__file__).resolve().parents[1]
        script = """
import sys
sys.path.insert(0, sys.argv[1])
from scripts.trusted_device_ingest_auth import AuthenticationError, authenticate_envelope, sign_envelope
secret = b"x" * 32
timestamp = 1000000
nonce = "abcdefghijklmnopqrstuvwx12345678"
body = b'{"events":[]}'
registry = {"device-01": {"tenant_id": "tenant-a", "secret": secret, "revoked": False}}
signature = sign_envelope(secret, timestamp, nonce, body)
try:
    authenticate_envelope(device_id="device-01", timestamp=timestamp, nonce=nonce,
        body=body, signature=signature, registry=registry,
        replay_database=sys.argv[2], now_seconds=timestamp)
    print("accepted")
except AuthenticationError:
    print("rejected")
"""
        processes = [
            subprocess.Popen(
                [sys.executable, "-c", script, str(repo_root), str(self.replay)],
                cwd=repo_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(8)
        ]
        results = [process.communicate(timeout=15) for process in processes]
        self.assertTrue(all(process.returncode == 0 for process in processes), results)
        outcomes = [stdout.strip() for stdout, _stderr in results]
        self.assertEqual(outcomes.count("accepted"), 1, results)
        self.assertEqual(outcomes.count("rejected"), 7, results)

    def test_authenticated_identity_overrides_untrusted_event_scope(self):
        store = SecurityEventStore(":memory:")
        event = {
            "schema_version": "1.0",
            "event_id": hashlib.sha256(b"stable-event").hexdigest(),
            "tenant_id": "attacker-tenant",
            "provider_id": "misp",
            "provider_version": "test",
            "event_type": "notice",
            "severity": "high",
            "observed_at_unix_ms": self.timestamp * 1000,
            "source_ref": "trusted-agent:test",
            "summary": "bounded test event",
            "data_classification": "internal",
            "fields": {},
        }
        body = json.dumps({"events": [event]}, separators=(",", ":")).encode()
        signature = sign_envelope(self.secret, self.timestamp, self.nonce, body)
        try:
            inserted = authenticate_and_ingest(
                device_id="device-01",
                timestamp=self.timestamp,
                nonce=self.nonce,
                body=body,
                signature=signature,
                registry=self.registry,
                replay_database=self.replay,
                store=store,
                provider_id="zeek",
                now_seconds=self.timestamp,
                now_ms=self.timestamp * 1000,
            )
            self.assertEqual(inserted, 1)
            self.assertEqual(len(store.search(tenant_id="tenant-a", provider_id="zeek")), 1)
            self.assertEqual(len(store.search(tenant_id="attacker-tenant")), 0)
            self.assertEqual(len(store.search(tenant_id="tenant-a", provider_id="misp")), 0)
        finally:
            store.close()

    def test_authentication_precedes_event_body_parsing(self):
        store = SecurityEventStore(":memory:")
        try:
            with self.assertRaises(AuthenticationError):
                authenticate_and_ingest(
                    device_id="device-01",
                    timestamp=self.timestamp,
                    nonce=self.nonce,
                    body=b"not-json",
                    signature="0" * 64,
                    registry=self.registry,
                    replay_database=self.replay,
                    store=store,
                    provider_id="zeek",
                    now_seconds=self.timestamp,
                )
        finally:
            store.close()

    def test_rejects_revoked_device(self):
        self.registry["device-01"]["revoked"] = True
        with self.assertRaises(AuthenticationError):
            self.call_auth()

    def test_rejects_bad_signature_and_tampered_body(self):
        with self.assertRaises(AuthenticationError):
            self.call_auth(signature="0" * 64)
        with self.assertRaises(AuthenticationError):
            self.call_auth(body=b'{"events":[1]}')

    def test_rejects_negative_timestamp(self):
        with self.assertRaises(AuthenticationError):
            self.call_auth(timestamp=-1)

    def test_rejects_stale_timestamp(self):
        with self.assertRaises(AuthenticationError):
            self.call_auth(now_seconds=self.timestamp + 301)

    def test_rejects_short_key_and_oversized_body(self):
        self.registry["device-01"]["secret"] = b"short"
        with self.assertRaises(AuthenticationError):
            self.call_auth()
        self.registry["device-01"]["secret"] = self.secret
        with self.assertRaises(AuthenticationError):
            self.call_auth(body=b"x" * (256 * 1024 + 1))

    def test_rejects_unknown_device(self):
        with self.assertRaises(AuthenticationError):
            self.call_auth(device_id="not-registered")

    def test_rejects_symlink_replay_database(self):
        target = Path(self.temp.name) / "real.sqlite3"
        target.touch()
        link = Path(self.temp.name) / "link.sqlite3"
        link.symlink_to(target)
        with self.assertRaises(AuthenticationError):
            self.call_auth(replay_database=link)

    def test_rejects_dangling_symlink_replay_database(self):
        target = Path(self.temp.name) / "missing.sqlite3"
        link = Path(self.temp.name) / "dangling.sqlite3"
        link.symlink_to(target)
        with self.assertRaises(AuthenticationError):
            self.call_auth(replay_database=link)
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
