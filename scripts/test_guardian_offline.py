import base64
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

spec = importlib.util.spec_from_file_location("guardian_offline", Path(__file__).with_name("guardian_offline.py"))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


def der(tag, value):
    if isinstance(tag, int):
        tag = bytes([tag])
    size = len(value)
    return tag + (bytes([size]) if size < 128 else (bytes([0x81, size]) if size < 256 else bytes([0x82]) + size.to_bytes(2, "big"))) + value


def ctx(tag, value):
    if tag < 31:
        return der(0xa0 | tag, value)
    groups = [tag & 127]
    tag >>= 7
    while tag:
        groups.insert(0, 128 | (tag & 127))
        tag >>= 7
    return der(bytes([0xbf]) + bytes(groups), value)


def fixture(challenge, signer, *, locked=True, noauth=True, patchlevel=202610):
    hardware = b"".join([
        ctx(1, der(0x31, der(2, b"\x02"))), ctx(2, der(2, b"\x02")),
        ctx(3, der(2, b"\x01\x00")), ctx(5, der(0x31, der(2, b"\x04"))),
        ctx(10, der(2, b"\x01")), ctx(702, der(2, b"\x00")),
        ctx(704, der(0x30, der(4, b"b" * 32) + der(1, b"\xff" if locked else b"\x00") + der(10, b"\x00") + der(4, b"h" * 32))),
        ctx(706, der(2, patchlevel.to_bytes(3, "big"))),
    ]) + (ctx(503, der(5, b"")) if noauth else b"")
    app = der(0x30, der(0x31, der(0x30, der(4, b"dev.frequency.guardian") + der(2, b"\x03"))) + der(0x31, der(4, bytes.fromhex(signer))))
    software = ctx(709, der(4, app))
    description = der(0x30, der(2, b"\x04") + der(10, b"\x01") + der(2, b"\x04") + der(10, b"\x01") + der(4, bytes.fromhex(challenge)) + der(4, b"") + der(0x30, software) + der(0x30, hardware))
    rootkey = ec.generate_private_key(ec.SECP256R1())
    key = ec.generate_private_key(ec.SECP256R1())
    rootname = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DISPOSABLE TEST ROOT")])
    leafname = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST DEVICE ONLY")])
    start = datetime.now(timezone.utc) - timedelta(minutes=1)
    end = start + timedelta(days=1)
    root = (x509.CertificateBuilder().subject_name(rootname).issuer_name(rootname).public_key(rootkey.public_key())
        .serial_number(1).not_valid_before(start).not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(rootkey.public_key()), False)
        .sign(rootkey, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(leafname).issuer_name(rootname).public_key(key.public_key())
        .serial_number(2).not_valid_before(start).not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(rootkey.public_key()), False)
        .add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), description), False)
        .sign(rootkey, hashes.SHA256()))
    export = dict(schema="frequency-guardian-attestation/v2", purpose="diagnostic-only", production_eligible=False,
        attestation_verified=False, certificates_der_b64=[g.b64(c.public_bytes(serialization.Encoding.DER)) for c in (leaf, root)])
    return key, export, g.digest(root.public_bytes(serialization.Encoding.DER))


class OfflineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/dev/shm", prefix="guardian-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.signer = "b" * 64
        self.state = dict(clock=1000, devices={}, requests={})
        self.binaries = os.environ.get("FG_RUST_BINARIES")

    def record(self):
        devicekey, export, _ = fixture("a" * 64, self.signer)
        spki = devicekey.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        device = g.digest(spki)
        self.state["devices"][device] = dict(spki=g.b64(spki), signer=self.signer, enrollment="c" * 64,
            expires=2000, revoked=False, attestation=export)
        return devicekey, device, export

    def receipt(self, key, device, envelope, approved=True):
        body = g.DECISION + bytes([int(approved)]) + g.unb64(envelope.split(".")[0])
        return dict(schema="frequency-guardian-offline-decision/v1", decision="approve" if approved else "deny",
            signed_bytes_b64=g.b64(body), signature_der_b64=g.b64(key.sign(body, ec.ECDSA(hashes.SHA256()))),
            device_spki_b64=self.state["devices"][device]["spki"])

    def test_full_request_decision_replay_and_revocation(self):
        devicekey, device, _ = self.record()
        with patch.object(g, "check_revocation"):
            envelope = g.request(self.directory, self.key, self.state, 1000, device, "Transfer 5 units")
            receipt = self.receipt(devicekey, device, envelope)
            verdict = g.verify_receipt(self.directory, self.state, 1001, receipt)
            self.assertEqual(verdict["verified_decision"], "approve")
            self.assertFalse(verdict["executed"])
            with self.assertRaises(ValueError):
                g.verify_receipt(self.directory, g.read_json(self.directory / "state.json"), 1001, receipt)
            envelope = g.request(self.directory, self.key, self.state, 1000, device, "Deny me")
            denied = self.receipt(devicekey, device, envelope, False)
            altered = dict(denied, decision="approve")
            with self.assertRaises(ValueError):
                g.verify_receipt(self.directory, self.state, 1001, altered)
            self.assertEqual(g.verify_receipt(self.directory, self.state, 1001, denied)["verified_decision"], "deny")
            envelope = g.request(self.directory, self.key, self.state, 1000, device, "Pending request")
            g.revoke(self.directory, self.key, self.state, 1001, device)
            with self.assertRaises(ValueError):
                g.request(self.directory, self.key, self.state, 1001, device, "No")
            with self.assertRaises(ValueError):
                g.verify_receipt(self.directory, self.state, 1001, self.receipt(devicekey, device, envelope))
            self.assertTrue(g.read_json(self.directory / "state.json")["devices"][device]["revoked"])

    def test_unissued_expired_wrong_key_and_corrupt_signatures(self):
        devicekey, device, _ = self.record()
        with patch.object(g, "check_revocation"):
            envelope = g.request(self.directory, self.key, self.state, 1000, device, "Action")
            receipt = self.receipt(devicekey, device, envelope)
            with self.assertRaises(ValueError):
                g.verify_receipt(self.directory, self.state, 1120, receipt)
            bad = self.receipt(self.key, device, envelope)
            with self.assertRaises(Exception):
                g.verify_receipt(self.directory, self.state, 1001, bad)
            with patch.object(g.time, "monotonic", side_effect=[0, 200]), self.assertRaises(ValueError):
                g.verify_receipt(self.directory, self.state, 1001, receipt)
            self.assertFalse(next(iter(self.state["requests"].values()))["consumed"])
            receipt["device_spki_b64"] = "wrong"
            with self.assertRaises(ValueError):
                g.verify_receipt(self.directory, self.state, 1001, receipt)

    def test_revocation_fetch_fails_closed(self):
        _, _, export = self.record()
        g.check_revocation(export, lambda: b'{"entries":{}}')
        for raw in (b'{}', b'{"entries":null}', b'{"entries":{},"entries":{}}', b'{"entries":{"2":{"status":"REVOKED"}}}',
                    b'{"entries":{"02":{"status":"UNKNOWN"}}}', b'{"entries":{"1":{}}}', b'x' * 2_000_001):
            with self.assertRaises(Exception):
                g.check_revocation(export, lambda: raw)
        with patch.object(g.urllib.request, "urlopen", side_effect=OSError("offline")):
            with self.assertRaises(OSError):
                g.check_revocation(export)

    def test_status_response_freshness_and_redirects(self):
        _, _, export = self.record()
        class Response:
            headers = {"Date": "Fri, 23 Oct 2026 06:00:00 GMT", "Age": "0"}
            url = g.REVOCATION_URL
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def geturl(self): return self.url
            def read(self, limit): return b'{"entries":{}}'
        response = Response()
        current = g.parsedate_to_datetime(response.headers["Date"]).timestamp()
        with patch.object(g.urllib.request, "urlopen", return_value=response), patch.object(g.time, "time", return_value=current):
            g.check_revocation(export)
            response.headers = {"Date": "Fri, 23 Oct 2026 06:00:00 GMT", "Age": "301"}
            with self.assertRaises(ValueError): g.check_revocation(export)
            response.headers = {}
            with self.assertRaises(Exception): g.check_revocation(export)
            response.url = "http://example.invalid/"
            with self.assertRaises(ValueError): g.check_revocation(export)

    def test_encoding_and_durable_failure(self):
        for text in ("", "a\nb", "a\u202eb"):
            with self.assertRaises(ValueError):
                g.payload(2, "a" * 64, "b" * 64, "c" * 64, "d" * 64, 1000, 1120, text)
        with self.assertRaises(ValueError):
            g.strict_json('{"a":1,"a":2}')
        (self.directory / "state.new").write_text("uncertain")
        with self.assertRaises(FileExistsError):
            g.atomic_json(self.directory / "state.json", self.state)

    def test_authority_initialization_reload_permissions_and_clock(self):
        directory = self.directory / "authority"
        policyfile = self.directory / "policy-input.json"
        policyfile.write_text(json.dumps(dict(root_pin_sha256="a" * 64, apk_signer_sha256=self.signer, minimum_os_patch=202610)))
        g.initialize(directory, policyfile)
        with self.assertRaises(FileExistsError):
            g.initialize(directory, policyfile)
        with g.authority(directory) as (_, key, policy, state, now):
            self.assertEqual(policy["minimum_os_patch"], 202610)
            self.assertEqual(state["clock"], now)
            self.assertIsInstance(key.curve, ec.SECP256R1)
        with patch.object(g.time, "time", return_value=1), self.assertRaises(ValueError):
            with g.authority(directory):
                pass
        (directory / "key.pem").chmod(0o644)
        with self.assertRaises(ValueError):
            with g.authority(directory):
                pass
        (directory / "key.pem").chmod(0o600)
        (directory / "state.new").write_text("uncertain")
        with self.assertRaises(ValueError):
            with g.authority(directory):
                pass

    @unittest.skipUnless(os.environ.get("FG_RUST_BINARIES"), "set FG_RUST_BINARIES to built independent verifier binaries")
    def test_independent_enrollment_and_policy_negatives(self):
        ledger = self.directory / "challenges"
        ledger.mkdir(mode=0o700)
        def issue():
            return json.loads(subprocess.check_output([str(Path(self.binaries) / "guardian-challenge"), str(ledger)]))["challenge_hex"]
        challenge = issue()
        _, export, pin = fixture(challenge, self.signer)
        source = self.directory / "export.json"
        source.write_text(json.dumps(export))
        policy = dict(root_pin_sha256=pin, apk_signer_sha256=self.signer, minimum_os_patch=202610)
        with patch.object(g, "check_revocation"):
            try:
                envelope = g.enroll(self.directory, self.key, policy, self.state, int(g.time.time()), source, challenge, self.binaries)
            except subprocess.CalledProcessError as error:
                self.fail(error.stderr)
            self.assertEqual(len(envelope.split(".")), 2)
            self.assertEqual(len(self.state["devices"]), 1)
            with self.assertRaises(Exception):
                g.enroll(self.directory, self.key, policy, self.state, int(g.time.time()), source, challenge, self.binaries)
        # Independent checker must reject actual signed certificates with unsafe policy.
        for changes in (dict(locked=False), dict(noauth=False), dict(patchlevel=202509)):
            challenge = issue()
            _, bad, pin = fixture(challenge, self.signer, **changes)
            source.write_text(json.dumps(bad))
            policy["root_pin_sha256"] = pin
            with patch.object(g, "check_revocation"), self.assertRaises(subprocess.CalledProcessError):
                g.enroll(self.directory, self.key, policy, self.state, int(g.time.time()), source, challenge, self.binaries)
        # Wrong independent app signer cannot be trusted from the exported certificates.
        challenge = issue()
        _, bad, pin = fixture(challenge, "e" * 64)
        source.write_text(json.dumps(bad)); policy["root_pin_sha256"] = pin
        with patch.object(g, "check_revocation"), self.assertRaises(subprocess.CalledProcessError):
            g.enroll(self.directory, self.key, policy, self.state, int(g.time.time()), source, challenge, self.binaries)


if __name__ == "__main__":
    unittest.main()
