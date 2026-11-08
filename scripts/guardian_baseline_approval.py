#!/usr/bin/env python3
"""Frequency Guardian phone approval for an MCP DriftGuard baseline.

A baseline is accepted only with an approval bundle that holds:
  * a request signed by the pinned independent Guardian authority, whose
    action text names the exact baseline SHA-256 and monitored endpoint, and
  * an "approve" receipt signed by the pinned, enrolled phone key over exactly
    that request.

The host running the monitor cannot create either signature: the authority key
lives on a separate machine and the phone key is non-exportable Android
Keystore material. Replacing the baseline file changes its SHA-256, so it needs
a fresh phone approval.

This module re-implements statement parsing independently of
guardian_offline.py and needs only the `cryptography` package. It does not
consult the authority's revocation ledger: after revoking a phone, remove or
replace the monitor's `guardian_approval` pins. Request freshness was enforced
by the authority when the phone decided; this check proves the historical
approval of one exact baseline, so it does not apply the 120-second expiry.

Operator workflow (authority on its own machine, never on the monitored host):
  1. python3 guardian_baseline_approval.py action --baseline approved-baseline.json
  2. python3 guardian_offline.py AUTHORITY request --device DEVICE --action "<printed text>"
  3. Import the request on the phone, review, tap Approve, export the receipt.
  4. python3 guardian_offline.py AUTHORITY verify --receipt receipt.json
  5. python3 guardian_baseline_approval.py bundle --request request.fg \
       --receipt receipt.json --out baseline-approval.json
  6. Copy approved-baseline.json and baseline-approval.json to the monitored host.
"""
import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path
import struct

DOMAIN = b"frequency-guardian/offline-trust/v1"
DECISION = b"frequency-guardian/offline-decision/v1\0"
BUNDLE_SCHEMA = "mcpdrift-guardian-baseline-approval/v1"
RECEIPT_SCHEMA = "frequency-guardian-offline-decision/v1"
RECEIPT_KEYS = {"schema", "decision", "signed_bytes_b64", "signature_der_b64", "device_spki_b64"}
CONFIG_KEYS = {"bundle", "authority_spki_b64", "device_spki_b64", "apk_signer_sha256", "enrollment"}
DEFAULT_ENDPOINT = "http://127.0.0.1:8765/mcp"
MAX_BUNDLE = 65536
HEX = set("0123456789abcdef")


class ApprovalError(ValueError):
    pass


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def action_text(baseline_sha256, endpoint=DEFAULT_ENDPOINT):
    """Exact text the phone shows and signs. Same Who/What/Target layout as guardian_online."""
    if len(baseline_sha256) != 64 or not set(baseline_sha256) <= HEX:
        raise ApprovalError("baseline SHA-256 must be 64 lowercase hex characters")
    if not endpoint or "|" in endpoint or any(not 32 <= ord(c) <= 126 for c in endpoint):
        raise ApprovalError("endpoint must be printable ASCII without |")
    return ("Who: MCP DriftGuard monitor | What: Approve replacement MCP baseline | "
            "Target: baseline sha256 " + baseline_sha256 + " for endpoint " + endpoint)


def b64decode(value, name):
    if not isinstance(value, str):
        raise ApprovalError(name + " must be base64 text")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ApprovalError(name + " is not canonical base64") from None
    if base64.b64encode(raw).decode() != value:
        raise ApprovalError(name + " is not canonical base64")
    return raw


def strict_json(raw):
    def no_duplicates(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ApprovalError("duplicate JSON key")
        return dict(pairs)
    try:
        return json.loads(raw, object_pairs_hook=no_duplicates)
    except json.JSONDecodeError:
        raise ApprovalError("malformed JSON") from None


def _utf(data, offset):
    if offset + 2 > len(data):
        raise ApprovalError("truncated statement")
    (length,) = struct.unpack(">H", data[offset:offset + 2])
    end = offset + 2 + length
    if end > len(data):
        raise ApprovalError("truncated statement")
    raw = data[offset + 2:end]
    if any(b < 32 or b > 126 for b in raw):
        raise ApprovalError("statement text must be printable ASCII")
    return raw.decode("ascii"), end


def parse_request(body):
    """Parse an authority-signed action request (kind 2) and require canonical bytes."""
    domain, offset = _utf(body, 0)
    if domain.encode() != DOMAIN or offset >= len(body):
        raise ApprovalError("wrong trust domain")
    kind = body[offset]
    offset += 1
    fields = []
    for _ in range(4):
        value, offset = _utf(body, offset)
        if len(value) != 64 or not set(value) <= HEX:
            raise ApprovalError("statement identifiers must be SHA-256 hex")
        fields.append(value)
    if offset + 16 > len(body):
        raise ApprovalError("truncated statement")
    issued, expires = struct.unpack(">qq", body[offset:offset + 16])
    action, offset = _utf(body, offset + 16)
    if offset != len(body):
        raise ApprovalError("trailing statement bytes")
    if kind != 2:
        raise ApprovalError("bundle must contain an action request")
    if not (0 < issued < expires and expires - issued <= 120):
        raise ApprovalError("request lifetime invalid")
    device, signer, enrollment, nonce = fields
    if nonce == "0" * 64 or not action.strip():
        raise ApprovalError("invalid request")
    return dict(device=device, signer=signer, enrollment=enrollment, nonce=nonce,
                issued=issued, expires=expires, action=action)


def _p256_key(spki, name):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        key = serialization.load_der_public_key(spki)
    except ValueError:
        raise ApprovalError(name + " is not a public key") from None
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ApprovalError(name + " must be P-256")
    return key


def _verify(key, signature, data, what):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise ApprovalError(what + " signature invalid") from None


def verify_bundle(bundle, baseline_sha256, pins, endpoint=DEFAULT_ENDPOINT):
    """Return the verified request; raise ApprovalError on any mismatch."""
    if not isinstance(pins, dict) or set(pins) != CONFIG_KEYS:
        raise ApprovalError("guardian_approval needs exactly: " + ", ".join(sorted(CONFIG_KEYS)))
    for name in ("apk_signer_sha256", "enrollment"):
        if not isinstance(pins[name], str) or len(pins[name]) != 64 or not set(pins[name]) <= HEX:
            raise ApprovalError(name + " pin must be SHA-256 hex")
    authority = _p256_key(b64decode(pins["authority_spki_b64"], "authority_spki_b64"), "authority key")
    device_spki = b64decode(pins["device_spki_b64"], "device_spki_b64")
    device_key = _p256_key(device_spki, "device key")
    if not isinstance(bundle, dict) or set(bundle) != {"schema", "request", "receipt"} \
            or bundle["schema"] != BUNDLE_SCHEMA:
        raise ApprovalError("unsupported approval bundle")
    envelope = bundle["request"]
    if not isinstance(envelope, str) or len(envelope) > 16000 or envelope.count(".") != 1:
        raise ApprovalError("malformed authority request")
    body_b64, sig_b64 = envelope.split(".")
    body = b64decode(body_b64, "request body")
    _verify(authority, b64decode(sig_b64, "request signature"), body, "authority")
    request = parse_request(body)
    if request["device"] != hashlib.sha256(device_spki).hexdigest():
        raise ApprovalError("request names a different device")
    if request["signer"] != pins["apk_signer_sha256"]:
        raise ApprovalError("request names a different APK signer")
    if request["enrollment"] != pins["enrollment"]:
        raise ApprovalError("request names a different enrollment")
    if request["action"] != action_text(baseline_sha256, endpoint):
        raise ApprovalError("approval is for a different baseline or endpoint")
    receipt = bundle["receipt"]
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_KEYS or receipt["schema"] != RECEIPT_SCHEMA:
        raise ApprovalError("unsupported receipt")
    if receipt["decision"] != "approve":
        raise ApprovalError("phone decision is not approve")
    if receipt["device_spki_b64"] != pins["device_spki_b64"]:
        raise ApprovalError("receipt from a different device key")
    signed = b64decode(receipt["signed_bytes_b64"], "receipt bytes")
    if signed != DECISION + b"\x01" + body:
        raise ApprovalError("receipt does not approve this exact request")
    _verify(device_key, b64decode(receipt["signature_der_b64"], "receipt signature"), signed, "phone")
    return request


def load_bundle(path):
    path = Path(path)
    if not path.is_absolute() or not path.is_file():
        raise ApprovalError("approval bundle must be an existing absolute file")
    if path.stat().st_size > MAX_BUNDLE:
        raise ApprovalError("approval bundle exceeds 64 KiB")
    return strict_json(path.read_bytes())


def check_config(cfg, endpoint=DEFAULT_ENDPOINT):
    """Monitor hook: verify cfg['guardian_approval'] against cfg['baseline']."""
    pins = cfg["guardian_approval"]
    if not isinstance(pins, dict) or not isinstance(pins.get("bundle"), str):
        raise ApprovalError("guardian_approval.bundle must be a path string")
    return verify_bundle(load_bundle(pins["bundle"]), sha256_file(cfg["baseline"]), pins, endpoint)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="operation", required=True)
    a = sub.add_parser("action", help="print the exact action text for guardian_offline.py request")
    a.add_argument("--baseline", required=True)
    a.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    b = sub.add_parser("bundle", help="combine the authority request and phone receipt")
    b.add_argument("--request", required=True, help="file holding the authority request envelope")
    b.add_argument("--receipt", required=True, help="receipt JSON exported from the phone")
    b.add_argument("--out", required=True)
    v = sub.add_parser("verify", help="check an approved-monitor.json offline")
    v.add_argument("--config", required=True)
    v.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    args = parser.parse_args()
    if args.operation == "action":
        print(action_text(sha256_file(args.baseline), args.endpoint))
    elif args.operation == "bundle":
        envelope = Path(args.request).read_text().strip()
        receipt = strict_json(Path(args.receipt).read_bytes())
        bundle = {"schema": BUNDLE_SCHEMA, "request": envelope, "receipt": receipt}
        out = Path(args.out)
        with out.open("x") as target:
            json.dump(bundle, target, indent=2)
            target.write("\n")
        print("wrote " + str(out))
    else:
        cfg = strict_json(Path(args.config).read_bytes())
        request = check_config(cfg, args.endpoint)
        print(json.dumps({"guardian_approval": "verified", "nonce": request["nonce"],
                          "approved_at_unix": request["issued"], "action": request["action"]}))


if __name__ == "__main__":
    try:
        main()
    except (ApprovalError, OSError, KeyError) as error:
        raise SystemExit("guardian approval refused: " + str(error))
