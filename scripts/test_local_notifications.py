import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import local_notifications as native
import production_monitor as monitor


class LocalNotificationsTests(unittest.TestCase):
    def test_capability_and_headless(self):
        with patch.object(native.sys, 'platform', 'linux'), patch.object(native.shutil, 'which', return_value='/usr/bin/notify-send'):
            self.assertIsNone(native.command({}, {}))
            self.assertIsNotNone(native.command({}, {'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/1000/bus'}))
        with patch.object(native.sys, 'platform', 'darwin'), patch.object(native.shutil, 'which', return_value='/usr/bin/osascript'), patch.object(native.os, 'stat') as console, patch.object(native.os, 'getuid', return_value=1000):
            console.return_value.st_uid = 1000
            self.assertIsNotNone(native.command({}, {}))
        with patch.object(native.sys, 'platform', 'win32'), patch.object(native.shutil, 'which', return_value='powershell.exe'):
            self.assertIsNone(native.command({}, {'SESSIONNAME': 'Services'}))
            self.assertIsNotNone(native.command({}, {'SESSIONNAME': 'Console'}))

    def test_untrusted_content_never_becomes_code(self):
        hostile = '"; $(touch /tmp/driftguard-injection); <b>&\n'
        for platform in ('linux', 'darwin', 'win32'):
            with patch.object(native.sys, 'platform', platform), patch.object(native.shutil, 'which', return_value='/native'), patch.object(native.os, 'stat') as console, patch.object(native.os, 'getuid', return_value=1000):
                console.return_value.st_uid = 1000
                argv, env = native.command({'status': 'drift', 'detail': hostile, 'action': hostile},
                    {'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/bus', 'SESSIONNAME': 'Console'})
                if platform == 'linux':
                    self.assertIn('--', argv)
                    self.assertNotIn('<b>', argv[-1])
                else:
                    self.assertNotIn(hostile, ' '.join(argv))
                self.assertNotIn('touch /tmp/driftguard-injection', ' '.join(argv[:-1]))

    def test_drift_recovery_retry_dedup_opt_out(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td)/'state.db'
            for status in ('healthy', 'drift', 'drift', 'healthy', 'healthy'):
                monitor.record(db, status, 'fixture')
            with patch.object(monitor, 'notify', return_value=False) as send:
                self.assertFalse(monitor.deliver_local(db))
                self.assertEqual(send.call_count, 1)
            with patch.object(monitor, 'notify', return_value=True) as send:
                self.assertEqual(monitor.notification_result(db, 'off')['delivery'], 'disabled')
                send.assert_not_called()
                result = monitor.notification_result(db, 'agent')
                self.assertEqual([e['status'] for e in result['events']], ['drift', 'healthy'])
                self.assertFalse(result['host_push'])
                self.assertTrue(monitor.deliver_local(db))
                self.assertEqual(send.call_count, 2)
                self.assertTrue(monitor.deliver_local(db))
                self.assertEqual(send.call_count, 2)
            with sqlite3.connect(db) as conn:
                self.assertEqual(conn.execute('select count(*) from events').fetchone()[0], 3)

    def test_native_failure_and_timeout(self):
        import subprocess
        with patch.object(native, 'command', return_value=(['/native'], {})), patch.object(native.subprocess, 'run', side_effect=subprocess.TimeoutExpired('/native', 5)):
            self.assertFalse(native.notify({}))
        with patch.object(native, 'command', return_value=None):
            self.assertFalse(native.notify({}))

    def test_real_argv_delivery_does_not_execute_event_text(self):
        import json
        import os
        import sys
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            receiver, captured, marker = root/'notify-send', root/'argv', root/'injected'
            receiver.write_text('#!' + sys.executable + '\nimport json,sys\nfrom pathlib import Path\nPath(' + repr(str(captured)) + ').write_text(json.dumps(sys.argv[1:]))\n')
            receiver.chmod(0o700)
            content = '$(touch ' + str(marker) + '); " <b>hostile</b>'
            with patch.object(native.sys, 'platform', 'linux'), patch.object(native.shutil, 'which', return_value=str(receiver)), patch.dict(os.environ, {'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/fixture'}):
                self.assertTrue(native.notify({'status': 'drift', 'detail': content}))
            self.assertFalse(marker.exists())
            args = json.loads(captured.read_text())
            self.assertEqual(args[-2], 'MCP DriftGuard: drift')
            self.assertIn('$(touch ', args[-1])
            self.assertIn('&lt;b&gt;', args[-1])

    def test_cli_opt_out_overrides_external_receiver(self):
        import contextlib
        import io
        import json
        import sys
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            config = root/'config'
            config.write_text('{}')
            argv = ['monitor', '--config', str(config), '--state-dir', str(root/'state'),
                    '--alert-config', str(root/'missing-receiver'), '--notifications', 'off']
            output = io.StringIO()
            with patch.object(sys, 'argv', argv), patch.object(monitor, 'notify') as desktop, patch.object(monitor, 'deliver') as external, contextlib.redirect_stdout(output):
                self.assertEqual(monitor.main(), 1)  # unapproved remains fail-closed
            desktop.assert_not_called()
            external.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())['delivery'], 'disabled')

    def test_adapter_nonzero_and_missing_executable(self):
        import subprocess
        with patch.object(native.sys, 'platform', 'linux'), patch.object(native.shutil, 'which', return_value=None):
            self.assertIsNone(native.command({}, {'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/bus'}))
        with patch.object(native, 'command', return_value=(['/native'], {})), patch.object(native.subprocess, 'run', return_value=subprocess.CompletedProcess('/native', 1)):
            self.assertFalse(native.notify({}))

    def test_macos_without_customer_console(self):
        with patch.object(native.sys, 'platform', 'darwin'), patch.object(native.shutil, 'which', return_value='/usr/bin/osascript'), patch.object(native.os, 'stat') as console, patch.object(native.os, 'getuid', return_value=1000):
            console.return_value.st_uid = 0
            self.assertIsNone(native.command({}, {}))
            console.return_value.st_uid = 2000
            self.assertIsNone(native.command({}, {}))
