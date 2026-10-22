#!/usr/bin/env python3
"""Operator evidence boundary tests: allowlist, preservation and fail-closed paths."""
import json
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
            def run(url,approved,out):
                return subprocess.run([sys.executable,str(RUNNER),'--binary',str(binary),'--baseline',str(baseline),'--endpoint',url,'--approved-endpoint',approved,'--output',str(out)],capture_output=True,text=True)
            good='http://127.0.0.1:18787/mcp'
            out=p/'evidence.json'
            r=run(good,good,out)
            self.assertEqual(r.returncode,0,r.stderr)
            data=json.loads(out.read_text())
            self.assertEqual(data['verdict'],'PASS')
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
            self.assertEqual(json.loads(bad.read_text())['verdict'],'INCONCLUSIVE')

if __name__=='__main__': unittest.main()
