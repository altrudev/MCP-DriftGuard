"""Disposable simulated device over actual loopback TLS; never production credentials."""
import json
import io
import os
import ssl
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone, timedelta
import unittest
import urllib.request
import urllib.error
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import guardian_online as online
import guardian_offline as g

class HTTPBoundaryTests(unittest.TestCase):
    def test_unauthenticated_and_unsupported_requests_never_dispatch(self):
        calls=[]
        class Service:
            def call(self, *args):
                calls.append(args)
                raise AssertionError('unauthenticated request reached authority')
        class Connection:
            def __init__(self, request): self.request=request; self.output=bytearray()
            def makefile(self, *args): return io.BytesIO(self.request)
            def settimeout(self, *args): pass
            def sendall(self, data): self.output.extend(data)
        host=type('Host',(),{'service':Service()})()
        requests = [
            b'POST /v1/pending HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}',
            b'GET /private HTTP/1.0\r\n\r\n',
            b'POST /v1/pending HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}',
        ]
        for request in requests:
            with self.subTest(request=request.split(b'\r\n')[0]):
                connection=Connection(request)
                online.Handler(connection,('memory',0),host)
                head,body=bytes(connection.output).split(b'\r\n\r\n',1)
                self.assertNotIn(b' 200 ',head)
                self.assertNotIn(b'Python',head)
                self.assertIn(b'Cache-Control: no-store',head)
                self.assertEqual(json.loads(body),{'error':'refused; no acceptance confirmed'})
        self.assertEqual(calls,[])

class OnlineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/dev/shm', prefix='guardian-online-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        policy = self.path/'policy.json'
        binaries = os.environ.get('FG_RUST_BINARIES')
        if not binaries:
            self.skipTest('FG_RUST_BINARIES required for complete independent enrollment')
        from test_guardian_offline import fixture
        # Fresh challenge ledger is the actual independent verifier ledger.
        challenge_dir=self.path/'issued'; challenge_dir.mkdir(mode=0o700)
        challenge=json.loads(subprocess.check_output([str(Path(binaries)/'guardian-challenge'),str(challenge_dir)]))['challenge_hex']
        self.key,export,pin=fixture(challenge,'b'*64)
        policy.write_text(json.dumps(dict(root_pin_sha256=pin,apk_signer_sha256='b'*64,minimum_os_patch=202610)))
        self.directory=self.path/'authority'; g.initialize(self.directory,policy)
        # Verifier uses the same issued challenge ledger, no fabricated attestation acceptance.
        for source in challenge_dir.iterdir():
            source.rename(self.directory/'challenges'/source.name)
        source=self.path/'attestation.json'; source.write_text(json.dumps(export))
        self.status_patch=patch.object(g,'check_revocation'); self.status_patch.start(); self.addCleanup(self.status_patch.stop)
        with g.authority(self.directory) as (path,key,policy,state,now):
            g.enroll(path,key,policy,state,now,source,challenge,binaries)
        spki=self.key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        self.device=g.digest(spki)
        self.token = online.provision(self.directory,self.device)
        self.service = online.Service(self.directory)
    def issue(self):
        with g.authority(self.directory) as (path,key,policy,state,now):
            return g.request(path,key,state,now,self.device,'Who: simulated client | What: read report | Target: test record')
    def receipt(self,envelope,decision):
        body = g.DECISION + bytes([decision=='approve']) + g.unb64(envelope.split('.')[0])
        return dict(schema='frequency-guardian-offline-decision/v1',decision=decision,signed_bytes_b64=g.b64(body),signature_der_b64=g.b64(self.key.sign(body,ec.ECDSA(hashes.SHA256()))),device_spki_b64=g.b64(self.key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)))
    def call(self,route,data):
        return self.service.call(self.token,route,data)
    def test_decisions_durability_replay_revocation(self):
        self.assertIn('enrollment',self.call('/v1/enroll',{}))
        self.assertIsNone(self.call('/v1/pending',{})['request'])
        for decision in ['approve','deny']:
            self.issue(); envelope=self.call('/v1/pending',{})['request']
            receipt=self.receipt(envelope,decision)
            result=self.call('/v1/decision',{'receipt':receipt})
            self.assertEqual(result['verified_decision'],decision); self.assertFalse(result['executed'])
            self.assertEqual(online.Service(self.directory).call(self.token,'/v1/status',{'nonce':result['nonce']}),result)
            with self.assertRaises(ValueError): self.call('/v1/decision',{'receipt':receipt})
        with g.authority(self.directory) as (path,key,policy,state,now): g.revoke(path,key,state,now,self.device)
        with self.assertRaises(ValueError): self.call('/v1/pending',{})
    def test_auth_tamper_expiry_status_failure_rate_limits(self):
        with self.assertRaises(ValueError): self.service.call('z'*43,'/v1/enroll',{})
        envelope=self.issue(); receipt=self.receipt(envelope,'approve'); receipt['decision']='deny'
        with self.assertRaises(ValueError): self.call('/v1/decision',{'receipt':receipt})
        with self.assertRaises(ValueError): self.call('/v1/status',{'nonce':'f'*64})
        with self.assertRaises(ValueError): self.call('/v1/pending',{'extra':True})
        with patch.object(g,'check_revocation',side_effect=ValueError('offline')):
            with self.assertRaises(ValueError): self.call('/v1/pending',{})
        with patch.object(g.time,'time',return_value=time.time()+121):
            with self.assertRaises(ValueError): self.call('/v1/decision',{'receipt':self.receipt(envelope,'approve')})
        for _ in range(30):
            try: self.call('/v1/pending',{})
            except ValueError: pass
        with self.assertRaisesRegex(ValueError,'rate limited'): self.call('/v1/pending',{})
    def test_startup_refuses_unprotected_or_uncertain_state(self):
        cert=self.path/'cert.pem'; key=self.path/'tls.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
                        '-keyout',str(key),'-out',str(cert),'-days','1',
                        '-subj','/CN=localhost'],check=True,capture_output=True)
        key.chmod(0o600)
        self.assertIsInstance(online.server_context(self.directory,cert,key),ssl.SSLContext)
        # Server-side SSLContext loading alone accepts expired/not-yet-valid certs.
        # Refuse both before binding, even if the key and authority are valid.
        clock = datetime.now(timezone.utc)
        for instant in [clock - timedelta(days=2), clock + timedelta(days=2)]:
            with self.subTest(instant=instant), patch.object(online, 'datetime') as mocked:
                mocked.now.return_value = instant
                with self.assertRaisesRegex(ValueError, 'TLS certificate outside validity'):
                    online.server_context(self.directory,cert,key)
        key.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'private TLS key'):
            online.server_context(self.directory,cert,key)
        key.chmod(0o600)
        self.directory.chmod(0o755)
        with self.assertRaisesRegex(ValueError,'authority directory'):
            online.server_context(self.directory,cert,key)
        self.directory.chmod(0o700)
        (self.directory/'state.new').write_text('{}')
        with self.assertRaisesRegex(ValueError,'uncertain ledger'):
            online.server_context(self.directory,cert,key)
        (self.directory/'state.new').unlink()
        (self.directory/'state.json').write_text('{broken')
        with self.assertRaises(ValueError):
            online.server_context(self.directory,cert,key)
    def memory_tls(self, server_context, client_context):
        # Sandbox forbids sockets: real OpenSSL TLS records + real HTTP handler in memory.
        def exchange(route, raw, token=None, trust=None, hostname="localhost"):
            ci,co,si,so = [ssl.MemoryBIO() for _ in range(4)]
            client=(trust or client_context).wrap_bio(ci,co,server_hostname=hostname)
            server=server_context.wrap_bio(si,so,server_side=True)
            cd=sd=False
            for _ in range(20):
                if not cd:
                    try: client.do_handshake(); cd=True
                    except ssl.SSLWantReadError: pass
                si.write(co.read())
                if not sd:
                    try: server.do_handshake(); sd=True
                    except ssl.SSLWantReadError: pass
                ci.write(so.read())
                if cd and sd: break
            assert cd and sd
            request=(f'POST {route} HTTP/1.0\r\nContent-Type: application/json\r\nAuthorization: Bearer {token or self.token}\r\nContent-Length: {len(raw)}\r\n\r\n').encode()+raw
            client.write(request); si.write(co.read())
            decoded=bytearray()
            while len(decoded)<len(request): decoded.extend(server.read(16384))
            class Connection:
                def __init__(self): self.output=bytearray()
                def makefile(self,*args): return io.BytesIO(decoded)
                def settimeout(self,*args): pass
                def sendall(self,data): self.output.extend(data)
            connection=Connection()
            host=type('Host',(),{'service':self.service})()
            online.Handler(connection,('memory',0),host)
            server.write(bytes(connection.output)); ci.write(so.read())
            output=bytearray()
            while len(output)<len(connection.output): output.extend(client.read(16384))
            head,body=bytes(output).split(b'\r\n\r\n',1)
            return int(head.split()[1]),json.loads(body)
        with self.assertRaises(ssl.SSLCertVerificationError):
            exchange('/v1/enroll',b'{}',trust=ssl.create_default_context())
        with self.assertRaises(ssl.SSLCertVerificationError):
            exchange('/v1/enroll',b'{}',hostname='wrong.invalid')
        self.assertEqual(exchange('/v1/enroll',b'{}')[0],200)
        for decision in ['approve','deny']:
            self.issue(); code,pending=exchange('/v1/pending',b'{}'); self.assertEqual(code,200)
            code,result=exchange('/v1/decision',json.dumps({'receipt':self.receipt(pending['request'],decision)}).encode())
            self.assertEqual(code,200); self.assertEqual(result['verified_decision'],decision)
            self.assertEqual(exchange('/v1/status',json.dumps({'nonce':result['nonce']}).encode())[1],result)
        for route,raw,token in [('/v1/pending',b'{"x":1,"x":2}',None),('/v1/pending',b'x'*70001,None),('/v1/pending',b'{}','x'*43),('/admin',b'{}',None)]:
            self.assertEqual(exchange(route,raw,token)[0],400)
        print('PASS: TLS MemoryBIO + HTTP handler + simulated signed approve/deny (network sockets prohibited)')
    def test_actual_tls_simulated_client_and_http_negatives(self):
        cert=self.path/'cert.pem'; key=self.path/'tls.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,capture_output=True)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.minimum_version=ssl.TLSVersion.TLSv1_2; context.load_cert_chain(cert,key)
        try:
            server=online.TLSHTTPServer(('127.0.0.1',0),context)
        except PermissionError:
            if os.environ.get('FG_REQUIRE_NETWORK_TESTS') == '1':
                self.fail('real socket/TLS acceptance required, but socket creation is prohibited')
            self.memory_tls(context, ssl.create_default_context(cafile=str(cert)))
            return
        server.service=self.service
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        origin=f'https://localhost:{server.server_port}'
        client=ssl.create_default_context(cafile=str(cert))
        def send(route,raw,token=None):
            req=urllib.request.Request(origin+route,data=raw,headers={'Content-Type':'application/json','Authorization':'Bearer '+(token or self.token)})
            with urllib.request.urlopen(req,context=client,timeout=5) as response:return json.load(response)
        with self.assertRaises(urllib.error.URLError):
            urllib.request.urlopen(origin,timeout=5) # untrusted test CA is refused
        self.assertIn('enrollment',send('/v1/enroll',b'{}'))
        for decision in ['approve','deny']:
            self.issue(); envelope=send('/v1/pending',b'{}')['request']
            result=send('/v1/decision',json.dumps({'receipt':self.receipt(envelope,decision)}).encode())
            self.assertEqual(result['verified_decision'],decision)
            self.assertEqual(send('/v1/status',json.dumps({'nonce':result['nonce']}).encode()),result)
        for route,raw,token in [('/v1/pending',b'{"x":1,"x":2}',None),('/v1/pending',b'x'*70001,None),('/v1/pending',b'{}','x'*43),('/admin',b'{}',None)]:
            with self.assertRaises(urllib.error.HTTPError):send(route,raw,token)
        with self.assertRaises(Exception):
            urllib.request.urlopen(origin.replace('https:','http:'),timeout=2)

if __name__=='__main__': unittest.main()
