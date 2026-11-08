#!/usr/bin/env python3
"""Install a per-user monitor without starting services or approving trust."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys


def unit_quote(path):
    return '"' + str(path).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'


def install(binary, prefix, config, state, units):
    for path in (binary, prefix, config, state, units):
        if not path.is_absolute() or any(c in str(path) for c in '\n\r\x00'):
            raise ValueError('installation paths must be absolute and single-line')
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError('binary must be an existing executable')
    # Never overwrite an installed release or operator configuration implicitly.
    targets = [prefix/'mcpdrift', prefix/'production_monitor.py',
               units/'mcp-driftguard-monitor.service', units/'mcp-driftguard-monitor.timer',
               prefix/'local_notifications.py']
    if any(p.exists() or p.is_symlink() for p in targets):
        raise ValueError('installation already exists; stage an upgrade in a fresh prefix/unit directory')
    for directory in (prefix, config, state, units):
        directory.mkdir(parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    shutil.copy2(binary, targets[0])
    shutil.copy2(Path(__file__).with_name('production_monitor.py'), targets[1])
    shutil.copy2(Path(__file__).with_name('local_notifications.py'), targets[4])
    example = config/'monitor.example.json'
    if not example.exists():
        example.write_text(json.dumps({'approved': False, 'binary': str(targets[0]),
            'baseline': str(config/'approved-baseline.json'),
            'public_key': str(config/'external-authority.pub.pem'),
            'sha256': {'binary': '', 'baseline': '', 'public_key': ''}}, indent=2)+'\n')
    alert_example = config/'alerts.example.json'
    if not alert_example.exists():
        alert_example.write_text(json.dumps({'command': ['/absolute/path/to/operator-alert-receiver']}, indent=2)+'\n')
    targets[2].write_text('''[Unit]
Description=Read-only DriftGuard user monitor

[Service]
Type=oneshot
UMask=0077
NoNewPrivileges=yes
MemoryMax=256M
MemorySwapMax=0
TasksMax=16
CPUQuota=50%
TimeoutStartSec=90
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=''' + ' '.join([unit_quote(sys.executable), unit_quote(targets[1]),
        '--config', unit_quote(config/'approved-monitor.json'), '--state-dir', unit_quote(state)]) + '\n')
    targets[3].write_text('''[Unit]
Description=Hourly approved DriftGuard user monitoring

[Timer]
OnCalendar=hourly
AccuracySec=1m
Unit=mcp-driftguard-monitor.service

[Install]
WantedBy=timers.target
''')
    return {'installed': [str(p) for p in targets], 'activated': False,
            'approval_created': False, 'config': str(config/'approved-monitor.json')}


def main():
    home = Path.home()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--prefix', type=Path, default=home/'.local/lib/mcp-driftguard')
    parser.add_argument('--config-dir', type=Path, default=Path(os.environ.get('XDG_CONFIG_HOME', home/'.config'))/'mcp-driftguard')
    parser.add_argument('--state-dir', type=Path, default=Path(os.environ.get('XDG_STATE_HOME', home/'.local/state'))/'mcp-driftguard')
    parser.add_argument('--unit-dir', type=Path, default=Path(os.environ.get('XDG_CONFIG_HOME', home/'.config'))/'systemd/user')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        print(json.dumps(install(args.binary, args.prefix, args.config_dir, args.state_dir, args.unit_dir)))
    except (OSError, ValueError) as exc:
        parser.exit(1, str(exc)+'\n')

if __name__ == '__main__':
    main()
