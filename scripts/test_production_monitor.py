"""Offline monitor acceptance; all signing keys are disposable fixture keys."""
import json
import hashlib
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import production_monitor as monitor


class MonitorTests(unittest.TestCase):
    def test_transitions_dedup_and_durability(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / 'monitor.db'
            for status in ['healthy', 'drift', 'drift', 'error', 'error', 'healthy', 'healthy']:
                monitor.record(db, status, 'fixture')
            with closing(sqlite3.connect(db)) as conn:
                self.assertEqual(conn.execute('select status from events').fetchall(),
                                 [('healthy',), ('drift',), ('error',), ('healthy',)])
                self.assertEqual(conn.execute('select count(*) from events where alert=1').fetchone()[0], 3)
                self.assertEqual(conn.execute('select status from current').fetchone()[0], 'healthy')

    def test_real_verifier_drift_down_bad_key_recovery(self):
        import socket
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills/mcp-driftguard'))
        from test_agent_skill import wait_server
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = Path(__file__).resolve().parents[1]
            binary, server = root/'verify', root/'server'
            for target, source in [(binary, './cmd/mcpdrift'), (server, './examples/demo-server')]:
                subprocess.run(['go', 'build', '-o', str(target), source], cwd=repo, check=True, timeout=120)
            try:
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1', 0))
                    port = sock.getsockname()[1]
            except PermissionError as exc:
                self.skipTest('sandbox denies fixture sockets: ' + str(exc))
            endpoint = f'http://127.0.0.1:{port}/mcp'
            def command(*args):
                subprocess.run([str(binary), *map(str, args)], check=True, capture_output=True, timeout=45)
            command('keygen', '--private', root/'private', '--public', root/'public')
            command('keygen', '--private', root/'wrong-private', '--public', root/'wrong-public')
            cfg = dict(approved=True, binary=str(binary), baseline=str(root/'baseline'), public_key=str(root/'public'))
            proc = None
            def start(drift=False):
                env = os.environ.copy()
                env['MCPDRIFT_DEMO_PORT'] = str(port)
                env['MCPDRIFT_DEMO_DRIFT'] = '1' if drift else ''
                p = subprocess.Popen([str(server)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    wait_server(endpoint, p)
                except Exception:
                    p.terminate(); p.wait(timeout=5)
                    raise
                return p
            def stop(p):
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill(); p.wait(timeout=5)
            try:
                proc = start()
                command('baseline', '--sign-key', root/'private', '--output', root/'baseline', endpoint)
                cfg['sha256'] = {name: hashlib.sha256(Path(cfg[name]).read_bytes()).hexdigest() for name in ['binary', 'baseline', 'public_key']}
                with patch.object(monitor, 'ENDPOINT', endpoint):
                    self.assertEqual(monitor.check(cfg, root)[0], 'healthy')
                    cfg['public_key'] = str(root/'wrong-public')
                    cfg['sha256']['public_key'] = hashlib.sha256((root/'wrong-public').read_bytes()).hexdigest()
                    self.assertEqual(monitor.check(cfg, root), ('error', 'verifier exit 5'))
                    cfg['public_key'] = str(root/'public')
                    cfg['sha256']['public_key'] = hashlib.sha256((root/'public').read_bytes()).hexdigest()
                    stop(proc); proc = None
                    self.assertEqual(monitor.check(cfg, root)[0], 'error')
                    proc = start(True)
                    self.assertEqual(monitor.check(cfg, root)[0], 'drift')
                    stop(proc); proc = None
                    proc = start()
                    self.assertEqual(monitor.check(cfg, root)[0], 'healthy')
            finally:
                if proc is not None:
                    stop(proc)

    def test_failed_transaction_preserves_previous_state(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td)/'state.db'
            monitor.record(db, 'healthy', 'fixture')
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute("CREATE TRIGGER fail_insert BEFORE INSERT ON current BEGIN SELECT RAISE(ABORT, 'disk fault fixture'); END")
            with self.assertRaises(sqlite3.IntegrityError):
                monitor.record(db, 'drift', 'fixture')
            with closing(sqlite3.connect(db)) as conn:
                self.assertEqual(conn.execute('select count(*) from events').fetchone()[0], 1)
                self.assertEqual(conn.execute('select status from current').fetchone()[0], 'healthy')

    def test_missing_config_durable_across_processes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            command = [os.sys.executable, str(Path(monitor.__file__)), '--config', str(root/'absent'), '--state-dir', str(root/'state')]
            for _ in range(2):
                result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(json.loads(result.stdout)['status'], 'error')
            with closing(sqlite3.connect(root/'state/monitor.sqlite3')) as conn:
                self.assertEqual(conn.execute('select count(*) from events where alert=1').fetchone()[0], 1)

    def test_fail_closed_missing_approval(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(monitor, 'bounded_run') as run:
                self.assertEqual(monitor.check({'approved': False}, Path(td)), ('error', 'configuration: approved must be true'))
                run.assert_not_called()

    def test_verifier_exit_mapping_and_timeout(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name in ['binary', 'baseline', 'public_key']:
                (root / name).write_text('fixture')
            cfg = {name: str(root/name) for name in ['binary', 'baseline', 'public_key']}
            cfg['approved'] = True
            cfg['sha256'] = {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ['binary', 'baseline', 'public_key']}
            for code, expected in [(0, 'healthy'), (1, 'drift'), (2, 'drift'), (3, 'error'), (4, 'error'), (5, 'error')]:
                with patch.object(monitor, 'bounded_run', return_value=subprocess.CompletedProcess([], code)):
                    self.assertEqual(monitor.check(cfg, root)[0], expected)
            with patch.object(monitor, 'bounded_run', side_effect=subprocess.TimeoutExpired('verify', 45)):
                self.assertEqual(monitor.check(cfg, root)[0], 'error')

class ReleaseTests(unittest.TestCase):
    def test_pins_fail_before_process(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = {'approved': True, 'sha256': {}}
            for name in ('binary', 'baseline', 'public_key'):
                path = root/name
                path.write_text('approved')
                cfg[name] = str(path)
                cfg['sha256'][name] = hashlib.sha256(path.read_bytes()).hexdigest()
            for name in ('binary', 'baseline', 'public_key'):
                Path(cfg[name]).write_text('replaced')
                with patch.object(monitor, 'bounded_run') as run:
                    self.assertEqual(monitor.check(cfg, root)[0], 'error')
                    run.assert_not_called()
                Path(cfg[name]).write_text('approved')
            del cfg['sha256']
            with patch.object(monitor, 'bounded_run') as run:
                self.assertEqual(monitor.check(cfg, root)[0], 'error')
                run.assert_not_called()

    def test_real_delivery_retry_order_recovery_and_restart(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db, config, receiver, received = [root/p for p in ('db', 'alerts.json', 'receiver.py', 'received')]
            receiver.write_text('import sys, pathlib\n'
                                'p = pathlib.Path(sys.argv[1])\n'
                                'if not p.with_suffix(".ready").exists(): sys.exit(1)\n'
                                'with p.open("a") as f: f.write(sys.stdin.read()+"\\n")\n')
            config.write_text(json.dumps({'command': [os.sys.executable, str(receiver), str(received)]}))
            for status in ('healthy', 'drift', 'drift', 'error', 'healthy'):
                monitor.record(db, status, 'fixture')
            self.assertFalse(monitor.deliver(db, config, root))
            received.with_suffix('.ready').touch()
            self.assertTrue(monitor.deliver(db, config, root))
            self.assertTrue(monitor.deliver(db, config, root))
            events = [json.loads(line) for line in received.read_text().splitlines()]
            self.assertEqual([e['status'] for e in events], ['drift', 'error', 'healthy'])
            self.assertEqual([e['id'] for e in events], [2, 3, 4])

    def test_real_process_deadline(self):
        import time
        start = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            monitor.bounded_run([os.sys.executable, '-c', 'import time; time.sleep(30)'],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=0.1)
        self.assertLess(time.monotonic() - start, 3)

    def test_cli_delivery_failure_cannot_report_success(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            verifier = root/'verifier'
            verifier.write_text('#!/bin/sh\nexit 0\n')
            verifier.chmod(0o700)
            cfg = {'approved': True, 'sha256': {}}
            for name in ('binary', 'baseline', 'public_key'):
                path = verifier if name == 'binary' else root/name
                if name != 'binary':
                    path.write_text('fixture')
                cfg[name] = str(path)
                cfg['sha256'][name] = hashlib.sha256(path.read_bytes()).hexdigest()
            config, alerts = root/'config', root/'alerts'
            config.write_text(json.dumps(cfg))
            args = [os.sys.executable, str(Path(monitor.__file__)), '--config', str(config),
                    '--state-dir', str(root/'state'), '--alert-config', str(alerts)]
            result = subprocess.run(args, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)['status'], 'healthy')
            self.assertEqual(json.loads(result.stdout)['delivery'], 'pending')
            alerts.write_text(json.dumps({'command': ['/bin/true']}))
            result = subprocess.run(args, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            # Mutation must reject before executing the now-invalid verifier.
            verifier.write_text('#!/bin/sh\nexit 99\n')
            result = subprocess.run(args, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertIn('differs from approved sha256', result.stdout)

    def test_install_in_disposable_user_tree_never_activates(self):
        import install_user_monitor as installer
        with tempfile.TemporaryDirectory(prefix='monitor space ') as td:
            root = Path(td)
            binary = root/'binary'
            binary.write_text('#!/bin/sh\nexit 0\n')
            binary.chmod(0o700)
            with patch.object(subprocess, 'run') as run:
                result = installer.install(binary, root/'release', root/'config', root/'state', root/'units')
                run.assert_not_called()
            self.assertFalse(result['activated'])
            self.assertFalse((root/'config/approved-monitor.json').exists())
            self.assertFalse(json.loads((root/'config/monitor.example.json').read_text())['approved'])
            self.assertNotIn('--alert-config', (root/'units/mcp-driftguard-monitor.service').read_text())
            self.assertTrue((root/'release/local_notifications.py').is_file())
            with self.assertRaises(ValueError):
                installer.install(binary, root/'release', root/'config', root/'state', root/'units')

if __name__ == '__main__':
    unittest.main()
