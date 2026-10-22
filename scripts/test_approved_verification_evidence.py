#!/usr/bin/env python3
"""Disposable-key tests; no production paths or services are accessed."""
import contextlib
import hashlib
import io
import json
import multiprocessing
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
import uuid
from types import SimpleNamespace
from concurrent.futures import ProcessPoolExecutor
from unittest.mock import patch
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import approved_verification_evidence as runner
from evidence_signatures import sign, verify


def consume_fixture(directory, policy):
    runner.CONSUMPTION_LEDGER = Path(directory)
    with patch.object(runner, 'trusted_anchor', return_value=True):
        try:
            runner.consume_authorization(policy)
            return True
        except FileExistsError:
            return False


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.p = Path(self.tmp.name)
        self.binary = self.p/'verifier'
        self.binary.write_text('#!/usr/bin/python3\nimport json\nprint(json.dumps({"match":True}))\n')
        self.binary.chmod(0o700)
        self.baseline = self.p/'baseline'
        self.baseline.write_text('approved')
        self.ledger = self.p/'ledger'
        self.ledger.mkdir(mode=0o700)
        self.approval, self.approval_pub = self.key('approval')
        self.evidence, self.evidence_pub = self.key('evidence')
        self.policy = self.p/'policy.json'
        self.signature = self.p/'policy.sig.json'
        self.doc = dict(schema='mcpdrift-operator-policy/v2', endpoint='http://127.0.0.1:18787/mcp',
                        binary_sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                        baseline_sha256=hashlib.sha256(self.baseline.read_bytes()).hexdigest(),
                        authorization_id=uuid.uuid4().hex, issued_at=int(time.time()), expires_at=int(time.time())+120)
        self.seal()

    def key(self, name):
        key = Ed25519PrivateKey.generate()
        secret, public = self.p/(name+'.pem'), self.p/(name+'.pub.pem')
        secret.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        secret.chmod(0o600)
        public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        return secret, public

    def seal(self):
        self.policy.write_text(json.dumps(self.doc))
        self.signature.write_text(json.dumps(sign(self.doc, self.approval)))

    def run_wrapper(self, name='out', unsafe=None, extra=(), real_boundary=False):
        args = ['wrapper', '--binary', str(self.binary), '--baseline', str(self.baseline),
                '--endpoint', self.doc['endpoint'], '--policy', str(self.policy),
                '--policy-signature', str(self.signature), '--output', str(self.p/name), *extra]
        # Only fixture paths are admitted; production paths are never opened.
        def custody(path, **kwargs):
            return path in (self.approval_pub, self.evidence, self.ledger) and path != unsafe
        with contextlib.ExitStack() as stack:
            if not real_boundary:
                # Functional fixtures run as this test user, without broker custody.
                stack.enter_context(patch.object(runner, 'verifier_prefix', return_value=[]))
            return self.invoke(args, custody)

    def invoke(self, args, custody):
        with patch.object(runner, 'TRUSTED_APPROVAL_KEY', self.approval_pub), \
             patch.object(runner, 'EVIDENCE_PRIVATE_KEY', self.evidence), \
             patch.object(runner, 'CONSUMPTION_LEDGER', self.ledger), \
             patch.object(runner, 'trusted_anchor', side_effect=custody), \
             patch.object(sys, 'argv', args), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return runner.main()

    def test_unsafe_privilege_boundary_denies_before_execution_or_consumption(self):
        scenarios = [
            {'platform': 'darwin'}, {'uid': 1000}, {'euid': 1000},
            {'trusted': False}, {'executable': False}, {'missing': True},
            {'account_uid': 0}, {'account_gid': 0},
        ]
        for scenario in scenarios:
            with self.subTest(scenario=scenario), \
                 patch.object(runner.sys, 'platform', scenario.get('platform', 'linux')), \
                 patch.object(runner.os, 'getuid', return_value=scenario.get('uid', 0)), \
                 patch.object(runner.os, 'geteuid', return_value=scenario.get('euid', 0)), \
                 patch.object(runner.os, 'access', return_value=scenario.get('executable', True)), \
                 patch.object(runner.pwd, 'getpwnam',
                              side_effect=KeyError() if scenario.get('missing') else None,
                              return_value=SimpleNamespace(pw_uid=scenario.get('account_uid', 65001),
                                                           pw_gid=scenario.get('account_gid', 65001))), \
                 patch.object(runner.subprocess, 'Popen') as execute:
                # The fixture custody allowlist deliberately excludes the launcher.
                # Override only that decision for scenarios testing other failures.
                original = runner.verifier_prefix
                def boundary():
                    with patch.object(runner, 'trusted_anchor', return_value=scenario.get('trusted', True)):
                        return original()
                with patch.object(runner, 'verifier_prefix', side_effect=boundary):
                    self.assert_denied(real_boundary=True)
                execute.assert_not_called()
                self.assertEqual(list(self.ledger.iterdir()), [])

    def test_only_trusted_launcher_receives_root_execution(self):
        with patch.object(runner.sys, 'platform', 'linux'), \
             patch.object(runner.os, 'getuid', return_value=0), \
             patch.object(runner.os, 'geteuid', return_value=0), \
             patch.object(runner.os, 'access', return_value=True), \
             patch.object(runner, 'trusted_anchor', return_value=True), \
             patch.object(runner.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=65001, pw_gid=65002)) as lookup:
            prefix = runner.verifier_prefix()
        lookup.assert_called_once_with('mcpdrift-verifier')
        self.assertEqual(prefix, ['/usr/bin/setpriv', '--reuid', '65001', '--regid', '65002',
                                 '--clear-groups', '--bounding-set=-all', '--inh-caps=-all',
                                 '--ambient-caps=-all', '--no-new-privs', '--'])
        with patch.object(runner, 'verifier_prefix', return_value=prefix), \
             patch.object(runner.subprocess, 'Popen', side_effect=OSError('launcher unavailable')) as execute:
            self.assert_denied(real_boundary=True)
        command = execute.call_args.args[0]
        self.assertEqual(command[:len(prefix)], prefix)
        self.assertEqual(command[len(prefix)], str(self.binary))
        self.assertTrue(execute.call_args.kwargs['close_fds'])
        self.assertEqual(execute.call_args.kwargs['stdin'], runner.subprocess.DEVNULL)
        self.assertEqual(execute.call_args.kwargs['cwd'], '/')
        self.assertTrue(execute.call_args.kwargs['start_new_session'])
        self.assertTrue((self.ledger/self.doc['authorization_id']).exists())

    def test_launcher_restriction_failure_never_falls_back(self):
        prefix = ['/usr/bin/setpriv', '--no-new-privs', '--']
        failure = runner.subprocess.CompletedProcess(prefix, 127, '', 'setpriv: denied')
        with patch.object(runner, 'verifier_prefix', return_value=prefix), \
             patch.object(runner, 'bounded_run', return_value=failure) as execute:
            self.assertEqual(self.run_wrapper(real_boundary=True), 1)
        execute.assert_called_once()
        self.assertEqual(execute.call_args.args[0][:len(prefix)], prefix)
        self.assertEqual(json.loads((self.p/'out').read_text())['verdict'], 'INCONCLUSIVE')
        self.assertTrue((self.ledger/self.doc['authorization_id']).exists())

    def assert_denied(self, **kwargs):
        with self.assertRaises((SystemExit, ValueError, OSError, InvalidSignature)):
            self.run_wrapper(**kwargs)
        self.assertFalse((self.p/kwargs.get('name', 'out')).exists())

    def fixture_program(self, body):
        self.binary.write_text('#!/usr/bin/python3\n' + body)
        self.doc['binary_sha256'] = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.seal()

    def test_output_floods_fail_closed(self):
        for fd in (1, 2):
            with self.subTest(fd=fd):
                self.doc['authorization_id'] = uuid.uuid4().hex
                self.fixture_program('import os\nwhile True: os.write(%d, b"x" * 65536)\n' % fd)
                started = time.monotonic()
                with patch.object(runner, 'MAX_CAPTURE_BYTES', 32768), \
                     patch.object(runner, 'VERIFICATION_TIMEOUT', 2):
                    self.assertEqual(self.run_wrapper(name='flood%d' % fd), 1)
                self.assertLess(time.monotonic() - started, 4)
                data = json.loads((self.p/('flood%d' % fd)).read_text())
                self.assertEqual(data['verdict'], 'INCONCLUSIVE')
                self.assertIsNone(data['result'])
                self.assertIsNone(data['exit_code'])
                verify(data, self.p/('flood%d.sig.json' % fd), self.evidence_pub)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux process groups')
    def test_hung_descendants_and_closed_pipes_have_deadlines(self):
        for close_pipes in (False, True):
            with self.subTest(close_pipes=close_pipes):
                pidfile = self.p/('child%d' % close_pipes)
                body = ('import os, time\n'
                        'pid = os.fork()\n'
                        'if pid == 0:\n'
                        + (' os.close(1); os.close(2)\n' if close_pipes else '')
                        + ' while True: time.sleep(10)\n'
                        + 'open(%r, "w").write(str(pid))\n' % str(pidfile)
                        + 'import json; print(json.dumps(dict(match=True)), flush=True)\n')
                self.doc['authorization_id'] = uuid.uuid4().hex
                self.fixture_program(body)
                started = time.monotonic()
                with patch.object(runner, 'VERIFICATION_TIMEOUT', 0.3):
                    self.assertEqual(self.run_wrapper(name='hung%d' % close_pipes), 0 if close_pipes else 1)
                self.assertLess(time.monotonic() - started, 3)
                pid = int(pidfile.read_text())
                # A killed orphan can remain a zombie until the host reaps it.
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    path = Path('/proc/%d/stat' % pid)
                    try:
                        state = path.read_text().split(') ')[1]
                    except (FileNotFoundError, ProcessLookupError):
                        # The process may exit before or during the procfs read.
                        break
                    if state.startswith('Z'):
                        break
                    time.sleep(0.01)
                else:
                    self.fail('descendant survived process-group cleanup')

    @unittest.skipUnless(sys.platform == 'linux', 'Linux escaped descendant test')
    def test_escaped_descendant_cannot_hold_capture_open(self):
        pidfile = self.p/'escaped'
        self.fixture_program(
            'import os, time\n'
            'if os.fork() == 0:\n'
            ' os.setsid()\n'
            ' open(%r, "w").write(str(os.getpid()))\n'
            ' time.sleep(60)\n'
            'else:\n'
            ' time.sleep(60)\n' % str(pidfile))
        started = time.monotonic()
        try:
            with patch.object(runner, 'VERIFICATION_TIMEOUT', 0.3):
                self.assertEqual(self.run_wrapper(), 1)
            self.assertLess(time.monotonic() - started, 3)
        finally:
            # Escaped sessions are an explicit containment limitation. The test
            # owns this fixture and must clean it up independently.
            if pidfile.exists():
                try:
                    os.kill(int(pidfile.read_text()), runner.signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_closed_streams_do_not_bypass_leader_deadline(self):
        self.fixture_program('import os, time\nos.close(1); os.close(2)\ntime.sleep(60)\n')
        with patch.object(runner, 'VERIFICATION_TIMEOUT', 0.2):
            self.assertEqual(self.run_wrapper(), 1)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux launcher negative test')
    def test_real_launcher_rejects_invalid_identity_without_execution(self):
        # No account lookup, identity creation, or privileged configuration access.
        launcher = Path('/usr/bin/setpriv')
        if not launcher.is_file():
            self.skipTest('setpriv unavailable')
        marker = self.p/'executed'
        self.fixture_program('from pathlib import Path\nPath(%r).touch()\n' % str(marker))
        for option in ('--reuid', '--regid'):
            with self.subTest(option=option):
                self.doc['authorization_id'] = uuid.uuid4().hex
                self.seal()
                name = option[2:]
                with patch.object(runner, 'verifier_prefix',
                                  return_value=[str(launcher), option, '18446744073709551616', '--']):
                    self.assertEqual(self.run_wrapper(name=name, real_boundary=True), 1)
                self.assertFalse(marker.exists())
                self.assertEqual(json.loads((self.p/name).read_text())['verdict'], 'INCONCLUSIVE')

    def test_combined_budget_and_invalid_utf8_fail_closed(self):
        for name, body in (
            ('combined', 'import os\nos.write(1, b" " * 600)\nos.write(2, b"x" * 600)\n'),
            ('encoding', 'import os\nos.write(1, b"\\xff")\n'),
        ):
            with self.subTest(name=name):
                self.doc['authorization_id'] = uuid.uuid4().hex
                self.fixture_program(body)
                with patch.object(runner, 'MAX_CAPTURE_BYTES', 1024):
                    self.assertEqual(self.run_wrapper(name=name), 1)
                self.assertEqual(json.loads((self.p/name).read_text())['verdict'], 'INCONCLUSIVE')

    def test_success_signature_and_replay(self):
        self.assertEqual(self.run_wrapper(), 0)
        data = json.loads((self.p/'out').read_text())
        verify(data, self.p/'out.sig.json', self.evidence_pub)
        self.assertEqual(data['authorization_id'], self.doc['authorization_id'])
        self.assertEqual(self.baseline.read_text(), 'approved')
        with self.assertRaises(InvalidSignature):
            verify(dict(data, verdict='FAIL'), self.p/'out.sig.json', self.evidence_pub)
        self.assert_denied(name='replay')
        self.doc['expires_at'] += 1
        self.seal()
        self.assert_denied(name='resigned')

    def test_stale_future_invalid_and_legacy(self):
        original = dict(self.doc)
        for change in ({'expires_at':int(time.time())-1}, {'issued_at':int(time.time())+50},
                       {'expires_at':int(time.time())+301}, {'issued_at':True},
                       {'authorization_id':'../escape'}, {'schema':'mcpdrift-operator-policy/v1'}):
            with self.subTest(change=change):
                self.doc = dict(original, **change)
                self.seal()
                self.assert_denied()
                self.assertEqual(list(self.ledger.iterdir()), [])

    def test_tampering_artifacts_and_custody(self):
        for path in (self.approval_pub, self.evidence, self.ledger):
            self.assert_denied(unsafe=path)
        self.assert_denied(extra=('--evidence-private-key', str(self.evidence)))
        self.policy.write_text(self.policy.read_text().replace('18787', '18788'))
        self.assert_denied()
        self.seal()
        self.binary.write_text('changed')
        self.assert_denied()
        self.assertEqual(list(self.ledger.iterdir()), [])

    def test_failed_execution_burns_approval(self):
        self.binary.write_text('#!/usr/bin/python3\nprint("invalid JSON")\n')
        self.doc['binary_sha256'] = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.seal()
        self.assertEqual(self.run_wrapper(), 1)
        self.assertEqual(json.loads((self.p/'out').read_text())['verdict'], 'INCONCLUSIVE')
        self.assert_denied(name='retry')

    def test_contradictory_verdict_and_baseline_mutation(self):
        self.binary.write_text('#!/usr/bin/python3\nimport json,sys\nprint(json.dumps({"match":True}))\nsys.exit(2)\n')
        self.doc['binary_sha256'] = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.seal()
        self.assertEqual(self.run_wrapper(), 1)
        self.assertEqual(json.loads((self.p/'out').read_text())['verdict'], 'INCONCLUSIVE')
        self.doc['authorization_id'] = uuid.uuid4().hex
        self.binary.write_text('#!/usr/bin/python3\nfrom pathlib import Path\nimport sys\nPath(sys.argv[3]).write_text("mutated")\nimport json\nprint(json.dumps(dict(match=True)))\n')
        self.doc['binary_sha256'] = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.seal()
        with self.assertRaisesRegex(RuntimeError, 'baseline changed'):
            self.run_wrapper(name='mutation')
        self.assertFalse((self.p/'mutation').exists())
        self.assertTrue((self.ledger/self.doc['authorization_id']).exists())

    def test_endpoint_and_output_denials(self):
        self.assert_denied(extra=('--endpoint', 'http://127.0.0.1:9999/mcp'))
        (self.p/'out').write_text('existing')
        with self.assertRaises(SystemExit):
            self.run_wrapper()
        self.assertEqual((self.p/'out').read_text(), 'existing')
        (self.p/'out').unlink()
        original = self.doc['endpoint']
        for endpoint in ('http://localhost:18787/mcp', 'https://127.0.0.1/mcp',
                         'http://user@127.0.0.1/mcp', 'http://127.0.0.1/mcp#fragment'):
            self.doc['endpoint'] = endpoint
            self.seal()
            self.assert_denied()
        self.doc['endpoint'] = original
        self.seal()
        (self.p/'out.sig.json').write_text('existing')
        self.assert_denied()
        self.assertEqual(list(self.ledger.iterdir()), [])

    def test_expiry_rechecked_and_existing_ledger_symlink(self):
        with patch.object(runner.time, 'time', side_effect=[self.doc['issued_at'], self.doc['expires_at']]):
            self.assert_denied()
        (self.ledger/self.doc['authorization_id']).symlink_to(self.baseline)
        self.assert_denied()
        self.assertEqual(self.baseline.read_text(), 'approved')

    def test_atomic_multiprocess_consumption(self):
        with ProcessPoolExecutor(max_workers=4, mp_context=multiprocessing.get_context('fork')) as pool:
            results = list(pool.map(consume_fixture, [str(self.ledger)]*12, [self.doc]*12))
        self.assertEqual(sum(results), 1)

    def test_ledger_failure_prevents_execution(self):
        with patch.object(runner.os, 'fsync', side_effect=OSError('disk failure')), \
             patch.object(runner.subprocess, 'Popen') as execute:
            self.assert_denied()
            execute.assert_not_called()
        self.assert_denied(name='retry')

    def test_permissions_ownership_and_symlinks(self):
        # Simulate root-owned metadata without requiring root or touching /etc.
        target = Path('/fixture/trust/key')
        def check(mode=0o600, uid=0, ancestor_mode=0o755, ancestor_uid=0, symlink=False, private=True):
            def metadata(path):
                leaf = path == target
                return os.stat_result(((stat.S_IFLNK if symlink else stat.S_IFREG) | mode if leaf else stat.S_IFDIR | ancestor_mode,
                                       0, 0, 1, uid if leaf else ancestor_uid, 0, 0, 0, 0, 0))
            with patch.object(Path, 'lstat', metadata):
                return runner.trusted_anchor(target, private=private)
        self.assertTrue(check())
        for params in ({'mode':0o644}, {'mode':0o620}, {'uid':1000}, {'ancestor_uid':1000},
                       {'ancestor_mode':0o777}, {'symlink':True}):
            self.assertFalse(check(**params), params)
        self.assertTrue(check(mode=0o644, private=False))
        self.assertFalse(check(mode=0o666, private=False))
        def directory_metadata(path):
            return os.stat_result((stat.S_IFDIR | (0o700 if path == target else 0o755),
                                   0, 0, 1, 0, 0, 0, 0, 0, 0))
        with patch.object(Path, 'lstat', directory_metadata):
            self.assertTrue(runner.trusted_anchor(target, directory=True))
            self.assertFalse(runner.trusted_anchor(target, private=True))
        def linked_ancestor(path):
            info = list(directory_metadata(path))
            if path == target.parent:
                info[0] = stat.S_IFLNK | 0o755
            return os.stat_result(info)
        with patch.object(Path, 'lstat', linked_ancestor):
            self.assertFalse(runner.trusted_anchor(target, directory=True))
        self.assertFalse(runner.trusted_anchor(self.p/'missing'))
        with patch.object(Path, 'lstat', side_effect=OSError('denied')):
            self.assertFalse(runner.trusted_anchor(target))


if __name__ == '__main__':
    unittest.main()
