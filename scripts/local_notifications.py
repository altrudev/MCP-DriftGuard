"""Best-effort local OS submission, never proof that a person saw an alert."""
import html
import os
import shutil
import subprocess
import sys


def command(event, environment):
    # Endpoint text is data only. Bound it and remove control characters.
    title = 'MCP DriftGuard: ' + str(event.get('status', 'event'))[:32]
    body = str(event.get('detail', ''))[:300] + ' ' + str(event.get('action', 'Review verification evidence.'))[:300]
    clean = lambda text: ''.join(c if c.isprintable() else ' ' for c in text)
    title, body = clean(title), clean(body)
    env = {k: v for k, v in environment.items() if k in (
        'PATH', 'HOME', 'USER', 'DISPLAY', 'WAYLAND_DISPLAY', 'DBUS_SESSION_BUS_ADDRESS',
        'XDG_RUNTIME_DIR', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'SESSIONNAME')}
    if sys.platform.startswith('linux'):
        executable = shutil.which('notify-send')
        if not executable or not environment.get('DBUS_SESSION_BUS_ADDRESS'):
            return None
        return [executable, '--app-name=MCP DriftGuard', '--', html.escape(title), html.escape(body)], env
    if sys.platform == 'darwin':
        executable = shutil.which('osascript')
        if not executable:
            return None
        try:
            console_uid = os.stat('/dev/console').st_uid
            if console_uid == 0 or console_uid != os.getuid():
                return None
        except OSError:
            return None
        # AppleScript source is fixed; text arrives through the environment.
        env['DRIFTGUARD_TITLE'] = title
        env['DRIFTGUARD_BODY'] = body
        # Environment avoids even option-like data in the interpreter argv.
        script = 'display notification (system attribute "DRIFTGUARD_BODY") with title (system attribute "DRIFTGUARD_TITLE")'
        return [executable, '-e', script], env
    if sys.platform == 'win32':
        executable = shutil.which('powershell.exe')
        if not executable or environment.get('SESSIONNAME', '').lower() in ('', 'services'):
            return None
        env['DRIFTGUARD_TITLE'], env['DRIFTGUARD_BODY'] = title, body
        script = '''Add-Type -AssemblyName System.Windows.Forms
$n = New-Object System.Windows.Forms.NotifyIcon
try {
$n.Icon = [System.Drawing.SystemIcons]::Information
$n.Visible = $true
$n.ShowBalloonTip(3000, $env:DRIFTGUARD_TITLE, $env:DRIFTGUARD_BODY, [System.Windows.Forms.ToolTipIcon]::Info)
Start-Sleep -Seconds 3
} finally { $n.Dispose() }'''
        return [executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script], env
    return None


def notify(event):
    adapter = command(event, os.environ)
    if adapter is None:
        return False
    argv, env = adapter
    try:
        return subprocess.run(argv, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
            check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
