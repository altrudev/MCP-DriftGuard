#!/usr/bin/env python3
"""Operator evidence boundary tests: allowlist, preservation and fail-closed paths."""
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from evidence_signatures import sign, verify
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

RUNNER = Path(__file__).with_name('approved_verification_evidence.py')

class EvidenceTests(unittest.TestCase):
    def test_allowed_fixtures_and_denials(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            binary = p/'verifier.py'
            binary.write_text('#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps({"match":True,"risk":"NONE"}))\n')
            binary.chmod(0o700)
            baseline = p/'approved.json'
            baseline.write_text('approved')
            approval_key=Ed25519PrivateKey.generate()
            evidence_key=Ed25519PrivateKey.generate()
            def save_key(k,stem):
                secret=p/(stem+'.pem'); public=p/(stem+'.pub.pem')
                secret.write_bytes(k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
                public.write_bytes(k.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
                return secret,public
            approval_secret,approval_pub=save_key(approval_key,'approval')
            evidence_secret,evidence_pub=save_key(evidence_key,'evidence')
            policy = p/'approval.json'
            def seal():
                doc={'schema':'mcpdrift-operator-policy/v1','endpoint':'http://127.0.0.1:18787/mcp','binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'baseline_sha256':hashlib.sha256(baseline.read_bytes()).hexdigest()}
                policy.write_text(json.dumps(doc))
                (p/'approval.sig.json').write_text(json.dumps(sign(doc,approval_secret)))
            seal()
            def run(url,approved,out):
                # Positive fixture replaces a protected trust anchor in-process only;
                # the production CLI must not accept a caller-selected key.
                harness='import sys;sys.path.insert(0,sys.argv[1]);import approved_verification_evidence as m;from pathlib import Path;m.TRUSTED_APPROVAL_KEY=Path(sys.argv[2]);m.trusted_anchor=lambda p: p==m.TRUSTED_APPROVAL_KEY;sys.argv=[sys.argv[3]]+sys.argv[4:];sys.exit(m.main())'
                return subprocess.run([sys.executable,'-B','-c',harness,str(RUNNER.parent),str(approval_pub),str(RUNNER),'--binary',str(binary),'--baseline',str(baseline),'--endpoint',url,'--policy',str(policy),'--policy-signature',str(p/'approval.sig.json'),'--evidence-private-key',str(evidence_secret),'--output',str(out)],capture_output=True,text=True)
            good='http://127.0.0.1:18787/mcp'
            production=subprocess.run([sys.executable,'-B',str(RUNNER),'--binary',str(binary),'--baseline',str(baseline),'--endpoint',good,'--policy',str(policy),'--policy-signature',str(p/'approval.sig.json'),'--evidence-private-key',str(evidence_secret),'--output',str(p/'untrusted.json')],capture_output=True,text=True)
            self.assertNotEqual(production.returncode,0)
            self.assertFalse((p/'untrusted.json').exists())
            self.assertIn('trust anchor',production.stderr)
            out=p/'evidence.json'
            r=run(good,good,out)
            self.assertEqual(r.returncode,0,r.stderr)
            data=json.loads(out.read_text())
            self.assertEqual(data['verdict'],'PASS')
            verify(data,str(out)+'.sig.json',evidence_pub)
            tampered=dict(data,verdict='FAIL')
            with self.assertRaises(Exception): verify(tampered,str(out)+'.sig.json',evidence_pub)
            policy.write_text(policy.read_text().replace('18787','18789'))
            self.assertNotEqual(run(good,good,p/'tampered.json').returncode,0)
            self.assertFalse((p/'tampered.json').exists())
            seal()
            self.assertEqual(data['error_class'],'NONE')
            self.assertEqual(baseline.read_text(),'approved')
            self.assertEqual(run(good,good,out).returncode,2) # no overwriting
            self.assertEqual(run('http://127.0.0.1:18788/mcp',good,p/'bad.json').returncode,2)
            self.assertFalse((p/'bad.json').exists())
            self.assertEqual(run('http://localhost:18787/mcp','http://localhost:18787/mcp',p/'bad2.json').returncode,2)
            self.assertFalse((p/'bad2.json').exists())
            binary.write_text('#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps({"match":True}))\nsys.exit(2)\n')
            bad=p/'contradiction.json'
            r=run(good,good,bad)
            self.assertNotEqual(r.returncode,0)
            self.assertFalse(bad.exists()) # binary no longer matches approved digest
            seal()
            r=run(good,good,bad)
            self.assertNotEqual(r.returncode,0)
            self.assertEqual(json.loads(bad.read_text())['verdict'],'INCONCLUSIVE')

if __name__=='__main__': unittest.main()
