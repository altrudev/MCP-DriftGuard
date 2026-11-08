#!/usr/bin/env python3
"""TLS-only, non-executing transport for the independent offline authority."""
import argparse
import hashlib
import hmac
import json
import os
import secrets
import ssl
import stat
import time
from datetime import datetime, timezone
from cryptography import x509
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import guardian_offline as g

LIMIT = 70000

def provision(directory, device):
    with g.authority(directory) as (path, key, policy, state, now):
        record = state['devices'][device]
        if record['revoked'] or record['expires'] <= now:
            raise ValueError('inactive enrollment')
        token = secrets.token_urlsafe(32)
        record['online_token_hash'] = hashlib.sha256(token.encode()).hexdigest()
        # Reissue the same enrollment binding, never a new identity or trust anchor.
        record['online_grant'] = g.sign(key, g.payload(1, device, record['signer'], record['enrollment'], secrets.token_hex(32), now, record['expires']))
        g.atomic_json(path / 'state.json', state)
        return token

class Service:
    def __init__(self, directory):
        self.directory = directory
        self.buckets = {}
    def call(self, token, route, data):
        now_mono = time.monotonic()
        # Single global bound avoids attacker-controlled unbounded rate-limit state.
        self.buckets = {k:v for k,v in self.buckets.items() if now_mono-v[0] < 60}
        bucket = hashlib.sha256(token.encode()).hexdigest()
        if bucket not in self.buckets and len(self.buckets) >= 1024:
            raise ValueError('rate limited')
        start, count = self.buckets.get(bucket, (now_mono, 0))
        self.buckets[bucket] = (start, count+1)
        if count >= 30:
            raise ValueError('rate limited')
        with g.authority(self.directory) as (path, key, policy, state, now):
            matches = [(d,r) for d,r in state['devices'].items() if hmac.compare_digest(r.get('online_token_hash',''), bucket)]
            if len(matches) != 1:
                raise ValueError('unauthorized')
            device, record = matches[0]
            if record['revoked'] or record['expires'] <= now:
                raise ValueError('inactive enrollment')
            if route == '/v1/enroll' and data == {}:
                g.check_revocation(record['attestation'])
                return {'enrollment': record['online_grant'], 'device': device}
            if route == '/v1/pending' and data == {}:
                g.check_revocation(record['attestation'])
                pending = [r for r in state['requests'].values() if r['device']==device and not r['consumed'] and r['expires']>now]
                pending.sort(key=lambda r:r['expires'])
                return {'request': g.sign(key, g.unb64(pending[0]['body'])) if pending else None}
            if route == '/v1/decision' and set(data) == {'receipt'}:
                receipt = data['receipt']
                if not isinstance(receipt, dict) or receipt.get('device_spki_b64') != record['spki']:
                    raise ValueError('wrong device')
                # Receipt and consumed flag are committed atomically by the offline verifier.
                return g.verify_receipt(path, state, now, receipt)
            if route == '/v1/status' and set(data) == {'nonce'}:
                request = state['requests'].get(data['nonce'], {})
                if request.get('device') != device or 'acceptance' not in request:
                    raise ValueError('no confirmed receipt')
                return request['acceptance']
            raise ValueError('unsupported operation')

class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    server_version = 'Guardian'
    sys_version = ''
    def log_message(self, *args):
        pass  # No tokens, request bodies or device identifiers in access logs.
    def setup(self):
        super().setup()
        self.connection.settimeout(10)
    def do_POST(self):
        try:
            if self.headers.get('Transfer-Encoding') or self.headers.get_content_type() != 'application/json':
                raise ValueError('JSON with Content-Length required')
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= LIMIT:
                raise ValueError('invalid body size')
            auth = self.headers.get_all('Authorization', [])
            if len(auth) != 1 or not auth[0].startswith('Bearer ') or not 40 <= len(auth[0][7:]) <= 128:
                raise ValueError('unauthorized')
            size = int(lengths[0]); raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError('truncated body')
            data = g.strict_json(raw)
            if not isinstance(data, dict):
                raise ValueError('object required')
            result = self.server.service.call(auth[0][7:], self.path, data)
            self.reply(200, result)
        except Exception:
            self.reply(400, {'error':'refused; no acceptance confirmed'})
    def reply(self, code, result):
        body = json.dumps(result, separators=(',', ':')).encode()
        self.send_response(code)
        self.send_header('Content-Type','application/json')
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def send_error(self, code, message=None, explain=None):
        # Never emit Python version banners, HTML diagnostics or reflected paths.
        self.close_connection = True
        self.reply(code, {'error':'refused; no acceptance confirmed'})

class TLSHTTPServer(HTTPServer):
    request_queue_size = 16
    def __init__(self, address, context):
        self.tls_context = context
        super().__init__(address, Handler)
    def get_request(self):
        connection, address = self.socket.accept()
        connection.settimeout(10)
        try:
            return self.tls_context.wrap_socket(connection, server_side=True), address
        except BaseException:
            connection.close()
            raise


def server_context(directory, cert, key):
    # Refuse missing, permissive or uncertain authority state before opening a socket.
    # Startup never initializes an authority or accepts an enrollment implicitly.
    with g.authority(directory):
        pass
    private = Path(key).lstat()
    if (not stat.S_ISREG(private.st_mode) or private.st_uid != os.getuid()
            or private.st_mode & 0o077):
        raise ValueError('owner-controlled private TLS key required')
    leaf = x509.load_pem_x509_certificate(Path(cert).read_bytes())
    now = datetime.now(timezone.utc)
    if not leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc:
        raise ValueError('TLS certificate outside validity period')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(cert, key)
    return context


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory'); p.add_argument('operation', choices=['pair','request','serve'])
    p.add_argument('--who'); p.add_argument('--what'); p.add_argument('--target')
    p.add_argument('--device'); p.add_argument('--cert'); p.add_argument('--key')
    p.add_argument('--bind',default='127.0.0.1'); p.add_argument('--port',type=int,default=8443)
    a=p.parse_args()
    if a.operation == 'pair':
        print(provision(a.directory,a.device)); return
    if a.operation == 'request':
        fields = [a.who, a.what, a.target]
        if any(not v or len(v)>1000 or '|' in v for v in fields):
            raise ValueError('who, what and target required; no pipe separators')
        action = 'Who: ' + fields[0] + ' | What: ' + fields[1] + ' | Target: ' + fields[2]
        with g.authority(a.directory) as (path, key, policy, state, now):
            print(g.request(path, key, state, now, a.device, action))
        return
    context = server_context(a.directory, a.cert, a.key)
    with TLSHTTPServer((a.bind,a.port),context) as server:
        server.service=Service(a.directory)
        server.serve_forever()
if __name__ == '__main__':
    main()
