"""Canonical Ed25519 detached signature envelopes for local verification artifacts."""
import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')

def verify(document, signature_path, public_key_path):
    envelope = json.loads(Path(signature_path).read_text())
    if set(envelope) != {'algorithm','signature'} or envelope['algorithm'] != 'Ed25519':
        raise ValueError('invalid signature envelope')
    public = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError('trusted key must be Ed25519')
    public.verify(base64.b64decode(envelope['signature'], validate=True), canonical(document))

def sign(document, private_key_path):
    private = serialization.load_pem_private_key(Path(private_key_path).read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError('evidence signer must be Ed25519')
    return {'algorithm':'Ed25519','signature':base64.b64encode(private.sign(canonical(document))).decode('ascii')}
