"""Phone-approved baseline acceptance with disposable authority and simulated phone keys."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import guardian_baseline_approval as approval  # noqa: E402
import production_monitor as monitor  # noqa: E402

spec = importlib.util.spec_from_file_location("guardian_offline", HERE / "guardian_offline.py")
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)

ENDPOINT = approval.DEFAULT_ENDPOINT
SIGNER = "b" * 64
ENROLLMENT = "c" * 64


def spki(key):
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def b64(raw):
    return base64.b64encode(raw).decode()


class Fixture:
    """An independent authority, an enrolled phone, and one approved baseline."""

    def __init__(self, root):
        self.root = Path(root)
        self.authority = ec.generate_private_key(ec.SECP256R1())
        self.phone = ec.generate_private_key(ec.SECP256R1())
        self.device = hashlib.sha256(spki(self.phone)).hexdigest()
        self.baseline = self.root / "approved-baseline.json"
        self.baseline.write_text('{"format":"mcpdrift-baseline/v1","fixture":true}\n')
        self.bundle_path = self.root / "baseline-approval.json"

    def request(self, action=None, *, kind=2, device=None, key=None, issued=1000, expires=1120):
        action = approval.action_text(approval.sha256_file(self.baseline), ENDPOINT) if action is None else action
        body = g.payload(kind, device or self.device, SIGNER, ENROLLMENT, "d" * 64, issued, expires,
                         action if kind == 2 else "")
        return g.sign(key or self.authority, body)

    def receipt(self, envelope, approved=True, key=None):
        body = g.DECISION + bytes([int(approved)]) + g.unb64(envelope.split(".")[0])
        return dict(schema="frequency-guardian-offline-decision/v1", decision="approve" if approved else "deny",
                    signed_bytes_b64=b64(body),
                    signature_der_b64=b64((key or self.phone).sign(body, ec.ECDSA(hashes.SHA256()))),
                    device_spki_b64=b64(spki(self.phone)))

    def bundle(self, envelope=None, receipt=None):
        envelope = envelope or self.request()
        return {"schema": approval.BUNDLE_SCHEMA, "request": envelope,
                "receipt": receipt or self.receipt(envelope)}

    def pins(self, **changes):
        pins = dict(bundle=str(self.bundle_path), authority_spki_b64=b64(spki(self.authority)),
                    device_spki_b64=b64(spki(self.phone)), apk_signer_sha256=SIGNER, enrollment=ENROLLMENT)
        pins.update(changes)
        return pins

    def verify(self, bundle=None, pins=None, endpoint=ENDPOINT):
        return approval.verify_bundle(bundle or self.bundle(), approval.sha256_file(self.baseline),
                                      pins or self.pins(), endpoint)


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(self.temp.name)

    def refuses(self, **kwargs):
        with self.assertRaises(approval.ApprovalError):
            self.f.verify(**kwargs)

    def test_phone_approval_accepts_exact_baseline(self):
        request = self.f.verify()
        self.assertEqual(request["device"], self.f.device)
        self.assertIn(approval.sha256_file(self.f.baseline), request["action"])

    def test_parser_matches_authority_encoding(self):
        envelope = self.f.request()
        parsed = approval.parse_request(g.unb64(envelope.split(".")[0]))
        rebuilt = g.payload(2, parsed["device"], parsed["signer"], parsed["enrollment"], parsed["nonce"],
                            parsed["issued"], parsed["expires"], parsed["action"])
        self.assertEqual(rebuilt, g.unb64(envelope.split(".")[0]))

    def test_changed_baseline_needs_new_approval(self):
        bundle = self.f.bundle()
        self.f.baseline.write_text('{"format":"mcpdrift-baseline/v1","fixture":"replaced"}\n')
        self.refuses(bundle=bundle)

    def test_approval_for_other_baseline_or_endpoint_refused(self):
        other = approval.action_text("e" * 64, ENDPOINT)
        self.refuses(bundle=self.f.bundle(self.f.request(other)))
        self.refuses(endpoint="http://127.0.0.1:9999/mcp")

    def test_deny_and_relabelled_deny_refused(self):
        envelope = self.f.request()
        denied = self.f.receipt(envelope, approved=False)
        self.refuses(bundle=self.f.bundle(envelope, denied))
        self.refuses(bundle=self.f.bundle(envelope, dict(denied, decision="approve")))

    def test_wrong_authority_or_phone_refused(self):
        stranger = ec.generate_private_key(ec.SECP256R1())
        self.refuses(bundle=self.f.bundle(self.f.request(key=stranger)))
        envelope = self.f.request()
        self.refuses(bundle=self.f.bundle(envelope, self.f.receipt(envelope, key=stranger)))
        self.refuses(pins=self.f.pins(authority_spki_b64=b64(spki(stranger))))
        self.refuses(pins=self.f.pins(device_spki_b64=b64(spki(stranger))))
        self.refuses(pins=self.f.pins(apk_signer_sha256="e" * 64))
        self.refuses(pins=self.f.pins(enrollment="e" * 64))
        self.refuses(bundle=self.f.bundle(self.f.request(device="e" * 64)))

    def test_host_cannot_forge_without_both_keys(self):
        # A host-level attacker holding neither key re-signs everything with its own keys.
        attacker = ec.generate_private_key(ec.SECP256R1())
        envelope = self.f.request(key=attacker)
        self.refuses(bundle=self.f.bundle(envelope, self.f.receipt(envelope, key=attacker)))

    def test_tampering_and_strict_format_refused(self):
        bundle = self.f.bundle()
        body, sig = bundle["request"].split(".")
        self.refuses(bundle=dict(bundle, request=body + "." + sig[:-4] + "AAA="))
        receipt = dict(bundle["receipt"])
        receipt["signed_bytes_b64"] = b64(g.unb64(receipt["signed_bytes_b64"]) + b"x")
        self.refuses(bundle=dict(bundle, receipt=receipt))
        self.refuses(bundle=dict(bundle, extra=1))
        self.refuses(bundle=dict(bundle, schema="other"))
        self.refuses(bundle=dict(bundle, receipt=dict(bundle["receipt"], extra=1)))
        self.refuses(bundle=dict(bundle, request=body + "\n." + sig))
        with self.assertRaises(approval.ApprovalError):
            approval.strict_json(b'{"schema":1,"schema":2}')

    def test_grant_or_revocation_is_not_an_approval(self):
        grant = self.f.request(kind=1, expires=g.UNTIL_REVOKED)
        self.refuses(bundle=self.f.bundle(grant))
        revocation = self.f.request(kind=3)
        self.refuses(bundle=self.f.bundle(revocation))

    def test_action_text_rejects_unsafe_input(self):
        for bad in ("A" * 64, "a" * 63):
            with self.assertRaises(approval.ApprovalError):
                approval.action_text(bad)
        with self.assertRaises(approval.ApprovalError):
            approval.action_text("a" * 64, "http://x|y")

    def test_end_to_end_with_real_authority_and_cli(self):
        directory = Path(self.temp.name) / "authority"
        directory.mkdir(mode=0o700)
        authority = self.f.authority
        state = dict(clock=1000, devices={self.f.device: dict(
            spki=g.b64(spki(self.f.phone)), signer=SIGNER, enrollment=ENROLLMENT,
            expires=g.UNTIL_REVOKED, revoked=False, attestation={})}, requests={})
        script = HERE / "guardian_baseline_approval.py"
        action = subprocess.run([sys.executable, str(script), "action", "--baseline", str(self.f.baseline)],
                                check=True, capture_output=True, text=True).stdout.strip()
        with patch.object(g, "check_revocation"):
            envelope = g.request(directory, authority, state, 1000, self.f.device, action)
            receipt = self.f.receipt(envelope)
            self.assertEqual(g.verify_receipt(directory, state, 1001, receipt)["verified_decision"], "approve")
        (directory / "request.fg").write_text(envelope + "\n")
        (directory / "receipt.json").write_text(json.dumps(receipt))
        subprocess.run([sys.executable, str(script), "bundle", "--request", str(directory / "request.fg"),
                        "--receipt", str(directory / "receipt.json"), "--out", str(self.f.bundle_path)],
                       check=True, capture_output=True)
        config = Path(self.temp.name) / "approved-monitor.json"
        config.write_text(json.dumps(dict(baseline=str(self.f.baseline), guardian_approval=self.f.pins())))
        out = subprocess.run([sys.executable, str(script), "verify", "--config", str(config)],
                             check=True, capture_output=True, text=True).stdout
        self.assertEqual(json.loads(out)["guardian_approval"], "verified")


class MonitorIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.f = Fixture(self.root)
        self.marker = self.root / "verifier-ran"
        self.binary = self.root / "fake-mcpdrift"
        self.binary.write_text("#!/bin/sh\necho ran > " + str(self.marker) + "\nexit 0\n")
        self.binary.chmod(0o700)
        self.key = self.root / "baseline.pub.pem"
        self.key.write_text("fixture public key\n")

    def config(self, **extra):
        cfg = dict(approved=True, binary=str(self.binary), baseline=str(self.f.baseline), public_key=str(self.key))
        cfg["sha256"] = {n: hashlib.sha256(Path(cfg[n]).read_bytes()).hexdigest() for n in ("binary", "baseline", "public_key")}
        cfg.update(extra)
        return cfg

    def write_bundle(self, bundle=None):
        self.f.bundle_path.write_text(json.dumps(bundle or self.f.bundle()))

    def test_approved_baseline_runs_verifier(self):
        self.write_bundle()
        cfg = self.config(trust_model=monitor.GUARDIAN_TRUST_MODEL, guardian_approval=self.f.pins())
        self.assertEqual(monitor.check(cfg, self.root), ("healthy", "verifier exit 0"))
        self.assertTrue(self.marker.exists())

    def test_bad_approval_blocks_before_verifier(self):
        envelope = self.f.request()
        self.write_bundle(self.f.bundle(envelope, self.f.receipt(envelope, approved=False)))
        status, detail = monitor.check(self.config(guardian_approval=self.f.pins()), self.root)
        self.assertEqual(status, "error")
        self.assertTrue(detail.startswith("guardian approval:"), detail)
        self.assertFalse(self.marker.exists())

    def test_missing_bundle_blocks(self):
        status, detail = monitor.check(self.config(guardian_approval=self.f.pins()), self.root)
        self.assertEqual(status, "error")
        self.assertIn("bundle", detail)
        self.assertFalse(self.marker.exists())

    def test_guardian_trust_model_requires_approval(self):
        status, detail = monitor.check(self.config(trust_model=monitor.GUARDIAN_TRUST_MODEL), self.root)
        self.assertEqual(status, "error")
        self.assertIn("requires guardian_approval", detail)
        self.assertFalse(self.marker.exists())

    def test_without_guardian_config_behaviour_unchanged(self):
        self.assertEqual(monitor.check(self.config(), self.root), ("healthy", "verifier exit 0"))


if __name__ == "__main__":
    unittest.main()
