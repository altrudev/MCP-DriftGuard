"""Cross-language protocol fixture, never a production enrollment."""
import os
from pathlib import Path
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
import guardian_offline as g

root = Path(os.environ["FG_TEST_OUT"]) / "cross"
if sys.argv[1] == "prepare":
    root.mkdir(exist_ok=True)
    authority = ec.generate_private_key(ec.SECP256R1())
    device = ec.generate_private_key(ec.SECP256R1())
    for name, key in (("authority", authority), ("device", device)):
        (root / f"{name}.der").write_bytes(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    (root / "device.pk8").write_bytes(device.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    body = g.payload(2, g.digest((root / "device.der").read_bytes()), "b" * 64, "c" * 64, "d" * 64,
                     1000, 1120, "Cross-language reviewed action")
    (root / "request.fg").write_text(g.sign(authority, body))
else:
    body = g.unb64((root / "request.fg").read_text().split(".")[0])
    public = serialization.load_der_public_key((root / "device.der").read_bytes())
    for approved in (True, False):
        name = str(approved).lower()
        expected = g.DECISION + bytes([int(approved)]) + body
        assert (root / f"{name}.body").read_bytes() == expected
        public.verify((root / f"{name}.sig").read_bytes(), expected, ec.ECDSA(hashes.SHA256()))
    print("PASS: independent Python verifier matches exact Kotlin Approve/Deny bytes and verifies both signatures")
