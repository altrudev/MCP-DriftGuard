"""Offline release disposition checks; synthetic inventories never certify release."""
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class ClosureGateTests(unittest.TestCase):
    def gate(self, issues, dispositions):
        with tempfile.TemporaryDirectory() as folder:
            a, b = Path(folder)/'issues.json', Path(folder)/'dispositions.json'
            a.write_text(json.dumps(issues))
            b.write_text(json.dumps(dispositions))
            return subprocess.run([sys.executable, str(ROOT/'scripts/release_closure_gate.py'),
                                   '--issues', str(a), '--dispositions', str(b)], capture_output=True, text=True)

    def test_dispositions(self):
        for status in ('deferred', 'blocked'):
            with self.subTest(status=status):
                self.assertEqual(self.gate([{'number':3, 'state':'open'}], {'3':{'status':status, 'evidence':'runtime proof absent'}}).returncode, 0)
        self.assertEqual(self.gate([{'number':3, 'state':'closed'}], {'3':{'status':'verified', 'evidence':'independent runtime acceptance'}}).returncode, 0)

    def test_rejects_unsupported_closure(self):
        for issues, dispositions in [([], {}), ([{'number':3,'state':'open'}], {}),
            ([{'number':3,'state':'open'}], {'3':{'status':'verified','evidence':'discovery only'}}),
            ([{'number':3,'state':'closed'}], {'3':{'status':'verified','evidence':''}}),
            ([{'number':3,'state':'open'}], {'3':{'status':'invented','evidence':'x'}}),
            ([{'number':22,'pull_request':{}}], {})]:
            with self.subTest(issues=issues, dispositions=dispositions):
                self.assertNotEqual(self.gate(issues, dispositions).returncode, 0)

    def test_runner_cannot_skip_gate_tests(self):
        import conformance_suite
        self.assertIn('release_closure_gate', dict(conformance_suite.SUITES))

class RunnerGateTests(unittest.TestCase):
    def test_missing_inventory_blocks_report_and_positive_inventory_passes(self):
        import conformance_suite
        # Run the real mandatory gate with all unrelated suites stubbed out.
        with tempfile.TemporaryDirectory() as folder:
            output=Path(folder)/'report.json'
            issues=Path(folder)/'issues.json'
            dispositions=Path(folder)/'dispositions.json'
            issues.write_text(json.dumps([{'number':3,'state':'open'}]))
            dispositions.write_text(json.dumps({'3':{'status':'blocked','evidence':'runtime behavior proof absent; discovery insufficient'}}))
            valid=['--issues',str(issues),'--dispositions',str(dispositions)]
            for inputs, expected in [([],1), (['--release-closure'],1),
                    (['--release-closure','--issues',str(issues)],1),
                    (['--release-closure','--dispositions',str(dispositions)],1),
                    (valid,0), (['--release-closure']+valid,0)]:
                with patch.object(conformance_suite,'SUITES',[]), patch.object(sys,'argv',['conformance_suite','--output',str(output)]+inputs):
                    self.assertEqual(conformance_suite.main(),expected)
                report=json.loads(output.read_text())
                self.assertEqual(report['passed'],expected==0)
                self.assertIn('release_dispositions',report['suites'])
                self.assertEqual(report['mode'],'release-closure')
                if expected:
                    self.assertEqual(report['release_closure'],'not established')
                else:
                    self.assertEqual(report['release_closure'],'reviewed dispositions only')

    def test_component_mode_runs_all_suites_without_release_claim(self):
        import conformance_suite
        for failed in (False, True):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as folder:
                output=Path(folder)/'report.json'
                with patch.object(conformance_suite, 'run', return_value={'exit':int(failed)}) as run, \
                     patch.object(sys, 'argv', ['conformance_suite','--component-only','--output',str(output)]):
                    self.assertEqual(conformance_suite.main(),int(failed))
                self.assertEqual(run.call_args_list, [unittest.mock.call(cmd) for _,cmd in conformance_suite.SUITES])
                report=json.loads(output.read_text())
                self.assertEqual(report['mode'],'component-only')
                self.assertEqual(report['release_closure'],'not established')
                self.assertEqual(report['passed'],not failed)
                self.assertEqual(set(report['suites']),set(dict(conformance_suite.SUITES)))
                self.assertNotIn('release_dispositions',report['suites'])

    def test_component_mode_rejects_release_requests(self):
        import conformance_suite
        for inputs in (['--release-closure'], ['--issues','issues.json'],
                       ['--dispositions','dispositions.json'],
                       ['--issues','issues.json','--dispositions','dispositions.json']):
            with self.subTest(inputs=inputs), \
                 patch.object(sys,'argv',['conformance_suite','--component-only']+inputs), \
                 patch.object(conformance_suite,'run') as run:
                with self.assertRaises(SystemExit) as error:
                    conformance_suite.main()
                self.assertEqual(error.exception.code,2)
                run.assert_not_called()

if __name__ == '__main__':
    unittest.main()
