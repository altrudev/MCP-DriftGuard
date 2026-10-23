#!/usr/bin/env python3
"""Reference offline authority. Its key/policy/state belong on an independent verifier.
No execution or publishing. Requires Python cryptography 46 and built Rust verifier binaries.
"""
import argparse
import base64
import contextlib
import fcntl
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import struct
import subprocess
import tempfile
import time
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

DOMAIN = b"frequency-guardian/offline-trust/v1"
DECISION = b"frequency-guardian/offline-decision/v1\0"
REVOCATION_URL = "https://android.googleapis.com/attestation/status"


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def read_json(path, limit=70000):
    with open(path, "rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError("oversized input")
    return strict_json(data)


def b64(value):
    return base64.b64encode(value).decode("ascii")


def unb64(value):
    return base64.b64decode(value, validate=True)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def utf(value):
    # ASCII subset of Java DataOutputStream.writeUTF; action cannot hide controls.
    value = value.encode("ascii")
    if len(value) > 4096 or any(x < 32 or x > 126 for x in value):
        raise ValueError("printable ASCII required")
    return struct.pack(">H", len(value)) + value


def payload(kind, device, signer, enrollment, nonce, issued, expires, action=""):
    for value in (device, signer, enrollment, nonce):
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("expected SHA-256 hex / 32-byte nonce")
    if nonce == "0" * 64 or kind not in (1, 2, 3):
        raise ValueError("invalid statement")
    if not (0 < issued < expires and expires - issued <= (86400 if kind == 1 else 120)):
        raise ValueError("invalid lifetime")
    if (kind == 2 and not action.strip()) or (kind != 2 and action):
        raise ValueError("invalid action")
    return (utf(DOMAIN.decode()) + bytes([kind]) + b"".join(utf(v) for v in
            (device, signer, enrollment, nonce)) + struct.pack(">qq", issued, expires) + utf(action))


def sign(key, body):
    return b64(body) + "." + b64(key.sign(body, ec.ECDSA(hashes.SHA256())))


def check_revocation(export, fetch=None):
    """Fetch from fixed HTTPS Google endpoint now; transport or schema uncertainty refuses."""
    if fetch is None:
        request = urllib.request.Request(REVOCATION_URL, headers={"Cache-Control": "no-cache", "Pragma": "no-cache"})
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.geturl() != REVOCATION_URL:
                raise ValueError("revocation endpoint redirected")
            date = parsedate_to_datetime(response.headers["Date"]).timestamp()
            if abs(time.time() - date) > 300 or not 0 <= int(response.headers.get("Age", "0")) <= 300:
                raise ValueError("stale certificate status response")
            raw = response.read(2_000_001)
    else:
        raw = fetch()
    if len(raw) > 2_000_000:
        raise ValueError("revocation list too large")
    data = strict_json(raw)
    if not isinstance(data, dict) or not isinstance(data.get("entries"), dict):
        raise ValueError("revocation list unavailable")
    entries = data["entries"]
    revoked_serials = set()
    for serial, entry in entries.items():
        if not isinstance(entry, dict) or not entry.get("status"):
            raise ValueError("invalid revocation entry")
        revoked_serials.add(int(serial, 16))  # Any listed status, including unknown, refuses.
    for encoded in export["certificates_der_b64"]:
        cert = x509.load_der_x509_certificate(unb64(encoded))
        if cert.serial_number in revoked_serials:
            raise ValueError("certificate revoked or suspended")


def atomic_json(path, value):
    # All scratch files are in /dev/shm; persistent ledger replacement stays on its filesystem.
    # The .new file is durable authority state, not temporary build data.
    target = path.with_suffix(".new")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(target, flags, 0o600)
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(value, out, separators=(",", ":"))
            out.flush()
            os.fsync(out.fileno())
        os.replace(target, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        # Leave .new on uncertainty: next operation must refuse, not reset the ledger.
        raise


@contextlib.contextmanager
def authority(directory):
    directory = Path(directory).resolve()
    info = directory.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("owner-controlled mode 0700 authority directory required")
    lock = os.open(directory / "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        for name in ("key.pem", "policy.json", "state.json"):
            p = directory / name
            m = p.lstat()
            if not stat.S_ISREG(m.st_mode) or m.st_uid != os.getuid() or m.st_mode & 0o077:
                raise ValueError("private authority file required")
        if (directory / "state.new").exists():
            raise ValueError("uncertain ledger commit; independent operator recovery required")
        key = serialization.load_pem_private_key((directory / "key.pem").read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("P-256 authority key required")
        state = read_json(directory / "state.json", 20_000_000)
        now = int(time.time())
        if now < state["clock"]:
            raise ValueError("authority clock rollback")
        state["clock"] = now
        atomic_json(directory / "state.json", state)
        yield directory, key, read_json(directory / "policy.json"), state, now
    finally:
        os.close(lock)


def enroll(directory, key, policy, state, now, attestation, challenge, binaries):
    export = read_json(attestation)
    check_revocation(export)
    # Private immutable copy removes document substitution between checks.
    with tempfile.TemporaryDirectory(dir="/dev/shm", prefix="guardian-enrollment-") as work:
        source = Path(work) / "attestation.json"
        source.write_text(json.dumps(export))
        command = [str(Path(binaries).resolve() / "guardian-enrollment"), str(source), challenge,
                   policy["root_pin_sha256"], "dev.frequency.guardian", policy["apk_signer_sha256"],
                   str(policy["minimum_os_patch"]), str(directory / "challenges")]
        checked = subprocess.run(command, check=True, capture_output=True, text=True,
                                 env={**os.environ, "TMPDIR": "/dev/shm"}, timeout=30)
    report = strict_json(checked.stdout)
    if not all(report.get(k) is True for k in
               ("chain_verified", "application_verified", "operational_key_policy_verified", "challenge_consumed")):
        raise ValueError("incomplete independent verification")
    spki = unb64(report["candidate_spki_b64"])
    device = digest(spki)
    if device in state["devices"]:
        raise ValueError("device previously enrolled or revoked; fresh key required")
    enrollment = secrets.token_hex(32)
    body = payload(1, device, policy["apk_signer_sha256"], enrollment,
                   secrets.token_hex(32), now, now + 86400)
    state["devices"][device] = dict(spki=b64(spki), enrollment=enrollment,
        signer=policy["apk_signer_sha256"], expires=now + 86400, revoked=False, attestation=export)
    atomic_json(directory / "state.json", state)
    return sign(key, body)


def request(directory, key, state, now, device, action):
    started = time.monotonic()
    record = state["devices"][device]
    if record["revoked"] or record["expires"] <= now:
        raise ValueError("revoked or expired enrollment")
    if len(state["requests"]) >= 8192:
        raise ValueError("request ledger full; independent archival/recovery required")
    check_revocation(record["attestation"])
    now += int(time.monotonic() - started)
    if record["expires"] <= now:
        raise ValueError("enrollment expired during certificate status check")
    state["clock"] = max(state["clock"], now)
    nonce = secrets.token_hex(32)
    body = payload(2, device, record["signer"], record["enrollment"], nonce, now,
                   min(now + 120, record["expires"]), action)
    state["requests"][nonce] = dict(device=device, body=b64(body), expires=min(now + 120, record["expires"]), consumed=False)
    atomic_json(directory / "state.json", state)
    return sign(key, body)


def revoke(directory, key, state, now, device):
    record = state["devices"][device]
    record["revoked"] = True
    atomic_json(directory / "state.json", state)
    return sign(key, payload(3, device, record["signer"], record["enrollment"],
                            secrets.token_hex(32), now, now + 120))


def verify_receipt(directory, state, now, receipt):
    started = time.monotonic()
    expected_keys = {"schema", "decision", "signed_bytes_b64", "signature_der_b64", "device_spki_b64"}
    if set(receipt) != expected_keys or receipt["schema"] != "frequency-guardian-offline-decision/v1":
        raise ValueError("unsupported receipt")
    if receipt["decision"] not in ("approve", "deny"):
        raise ValueError("unknown decision")
    approved = receipt["decision"] == "approve"
    body = unb64(receipt["signed_bytes_b64"])
    prefix = DECISION + bytes([int(approved)])
    if not body.startswith(prefix):
        raise ValueError("decision/domain mismatch")
    statement = body[len(prefix):]
    matches = [(nonce, r) for nonce, r in state["requests"].items() if unb64(r["body"]) == statement]
    if len(matches) != 1:
        raise ValueError("request not independently issued")
    nonce, issued = matches[0]
    record = state["devices"][issued["device"]]
    if issued["consumed"] or issued["expires"] <= now or record["revoked"] or record["expires"] <= now:
        raise ValueError("replayed, expired, or revoked decision")
    if receipt["device_spki_b64"] != record["spki"]:
        raise ValueError("device key mismatch")
    check_revocation(record["attestation"])
    public = serialization.load_der_public_key(unb64(record["spki"]))
    if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP256R1):
        raise ValueError("invalid enrolled key")
    public.verify(unb64(receipt["signature_der_b64"]), body, ec.ECDSA(hashes.SHA256()))
    now += int(time.monotonic() - started)
    if issued["expires"] <= now or record["expires"] <= now:
        raise ValueError("decision expired during certificate status/signature check")
    state["clock"] = max(state["clock"], now)
    issued["consumed"] = True
    issued["receipt"] = receipt
    issued["acceptance"] = {"verified_decision": receipt["decision"], "nonce": nonce, "device": issued["device"], "executed": False}
    atomic_json(directory / "state.json", state)
    return {"verified_decision": receipt["decision"], "nonce": nonce, "device": issued["device"], "executed": False}


def initialize(directory, policy_file):
    policy = read_json(policy_file)
    if set(policy) != {"root_pin_sha256", "apk_signer_sha256", "minimum_os_patch"}:
        raise ValueError("exact independent root/signer/patch policy required")
    for name in ("root_pin_sha256", "apk_signer_sha256"):
        value = policy[name]
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("independently obtained lowercase SHA-256 hex required")
    floor = policy["minimum_os_patch"]
    if type(floor) is not int or not (202001 <= floor <= 299912 and 1 <= floor % 100 <= 12):
        raise ValueError("minimum patch YYYYMM required")
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    (directory / "challenges").mkdir(mode=0o700)
    key = ec.generate_private_key(ec.SECP256R1())
    fd = os.open(directory / "key.pem", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        out.flush(); os.fsync(out.fileno())
    atomic_json(directory / "policy.json", policy)
    atomic_json(directory / "state.json", dict(clock=int(time.time()), devices={}, requests={}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", help="private authority directory; see docs/GUARDIAN-OFFLINE.md")
    parser.add_argument("operation", choices=("init", "public-key", "enroll", "request", "revoke", "verify"))
    parser.add_argument("--policy", help="independently sourced root/signer/patch policy for init")
    parser.add_argument("--attestation")
    parser.add_argument("--challenge")
    parser.add_argument("--binaries", default="broker/target/debug")
    parser.add_argument("--device")
    parser.add_argument("--action")
    parser.add_argument("--receipt")
    args = parser.parse_args()
    if args.operation == "init":
        initialize(args.directory, args.policy)
        print("Authority initialized; authenticate its public fingerprint independently before pinning")
        return
    with authority(args.directory) as (directory, key, policy, state, now):
        if args.operation == "public-key":
            spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            print(b64(spki), digest(spki))
        elif args.operation == "enroll":
            print(enroll(directory, key, policy, state, now, args.attestation, args.challenge, args.binaries))
        elif args.operation == "request":
            print(request(directory, key, state, now, args.device, args.action))
        elif args.operation == "revoke":
            print(revoke(directory, key, state, now, args.device))
        else:
            print(json.dumps(verify_receipt(directory, state, now, read_json(args.receipt))))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(f"offline authority refused: {error}")
