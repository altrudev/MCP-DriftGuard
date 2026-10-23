#!/usr/bin/env python3
"""One read-only verification, with transactional durable transition alerts."""
import argparse
from contextlib import closing
import fcntl
import json
import hashlib
import os
from pathlib import Path
import resource
import signal
import sqlite3
import subprocess
import tempfile
import time
from local_notifications import notify

ENDPOINT = 'http://127.0.0.1:8765/mcp'
ACTIONS = {'healthy': 'Recovered; retain approved trust configuration.',
           'drift': 'Investigate inventory changes; independent authority must review any replacement baseline.',
           'error': 'Check endpoint availability, approved baseline, external public key and verifier installation.'}


def record(path, status, detail):
    with closing(sqlite3.connect(path, timeout=5)) as conn, conn:
        conn.execute('PRAGMA synchronous=FULL')
        conn.execute('create table if not exists current (id integer primary key check(id=1), status text)')
        conn.execute('create table if not exists events (id integer primary key, time integer, status text, detail text, action text, alert integer)')
        conn.execute('BEGIN IMMEDIATE')
        previous = conn.execute('select status from current where id=1').fetchone()
        if previous is None or previous[0] != status:
            alert = int(status != 'healthy' or previous is not None)
            conn.execute('insert into events(time,status,detail,action,alert) values(?,?,?,?,?)',
                         (int(time.time()), status, detail, ACTIONS[status], alert))
        conn.execute('insert or replace into current values(1,?)', (status,))


def limits():
    resource.setrlimit(resource.RLIMIT_AS, (4*1024**3, 4*1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024**2, 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (40, 40))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def bounded_run(command, **kwargs):
    """Clean the process group on success, failure and timeout (Linux/POSIX)."""
    timeout = kwargs.pop('timeout')
    data = kwargs.pop('input', None)
    with subprocess.Popen(command, start_new_session=True,
                          stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                          **kwargs) as process:
        try:
            process.communicate(input=data, timeout=timeout)
            return subprocess.CompletedProcess(command, process.returncode)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=1)


def check(cfg, tmp):
    try:
        if cfg.get('approved') is not True:
            raise ValueError('approved must be true')
        for name in ['binary', 'baseline', 'public_key']:
            if not isinstance(cfg[name], str):
                raise ValueError(name + ' must be a path string')
            path = Path(cfg[name])
            if not path.is_absolute() or not path.is_file():
                raise ValueError(name + ' must be an existing absolute file')
        pins = cfg.get('sha256')
        if not isinstance(pins, dict):
            raise ValueError('approved sha256 artifact pins required')
        for name in ['binary', 'baseline', 'public_key']:
            expected = pins.get(name)
            if not isinstance(expected, str) or len(expected) != 64:
                raise ValueError(name + ' sha256 approval missing')
            digest = hashlib.sha256()
            with Path(cfg[name]).open('rb') as artifact:
                for chunk in iter(lambda: artifact.read(65536), b''):
                    digest.update(chunk)
            if digest.hexdigest() != expected:
                raise ValueError(name + ' differs from approved sha256')
        # Explicit public key required: never permit unsigned verification.
        env = {'PATH': '/usr/bin:/bin', 'TMPDIR': str(tmp), 'GOMEMLIMIT': '192MiB', 'GOMAXPROCS': '2'}
        with tempfile.TemporaryFile(dir=tmp) as output:
            result = bounded_run([cfg['binary'], 'verify', '--baseline', cfg['baseline'],
                                     '--verify-key', cfg['public_key'], '--format', 'json', ENDPOINT],
                                    stdout=output, stderr=output, timeout=45, env=env, preexec_fn=limits)
        code = result.returncode
        return ('healthy' if code == 0 else 'drift' if code in (1, 2) else 'error',
                'verifier exit ' + str(code))
    except (KeyError, ValueError, OSError) as exc:
        return 'error', 'configuration: ' + str(exc)[:300]
    except subprocess.TimeoutExpired:
        return 'error', 'verifier exceeded 45 second deadline'
    except subprocess.SubprocessError:
        return 'error', 'verifier process setup failed'


def deliver(db, config, tmp):
    """At-least-once command delivery. The receiver must deduplicate event IDs."""
    cfg = json.loads(config.read_text())
    command = cfg.get('command') if isinstance(cfg, dict) else None
    if (not isinstance(command, list) or not command or len(command) > 32
            or not all(isinstance(arg, str) and '\x00' not in arg for arg in command)
            or not Path(command[0]).is_absolute()):
        raise ValueError('alert command must be an absolute executable argv')
    with closing(sqlite3.connect(db, timeout=5)) as conn, conn:
        conn.execute('PRAGMA synchronous=FULL')
        conn.execute('create table if not exists delivered (event_id integer primary key)')
        rows = conn.execute('select id,time,status,detail,action from events where alert=1 '
                            'and id not in (select event_id from delivered) order by id limit 10').fetchall()
        deadline = time.monotonic() + 20
        for row in rows:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            event = dict(zip(('id', 'time', 'status', 'detail', 'action'), row))
            try:
                with tempfile.TemporaryFile(dir=tmp) as output:
                    result = bounded_run(command, input=json.dumps(event).encode(), stdout=output,
                        stderr=output, timeout=min(5, remaining), preexec_fn=limits,
                        env={'PATH': '/usr/bin:/bin', 'TMPDIR': str(tmp)})
                if result.returncode != 0:
                    return False
            except (OSError, subprocess.SubprocessError):
                return False
            conn.execute('insert into delivered values(?)', (row[0],))
            conn.commit()
        return conn.execute('select count(*) from events where alert=1 and id not in '
                            '(select event_id from delivered)').fetchone()[0] == 0


def pending_events(db):
    with closing(sqlite3.connect(db, timeout=5)) as conn, conn:
        conn.execute('create table if not exists delivered (event_id integer primary key)')
        return [dict(zip(('id', 'time', 'status', 'detail', 'action'), row)) for row in
                conn.execute('select id,time,status,detail,action from events where alert=1 '
                             'and id not in (select event_id from delivered) order by id limit 10')]


def deliver_local(db):
    deadline = time.monotonic() + 20
    for event in pending_events(db):
        if time.monotonic() + 5 > deadline or not notify(event):
            return False
        with closing(sqlite3.connect(db, timeout=5)) as conn, conn:
            conn.execute('PRAGMA synchronous=FULL')
            conn.execute('insert into delivered values(?)', (event['id'],))
    return not pending_events(db)


def notification_result(db, mode):
    if mode == 'off':
        return {'delivery': 'disabled', 'host_push': False}
    if mode == 'agent':
        return {'delivery': 'action_required' if pending_events(db) else 'idle',
                'host_push': False, 'events': pending_events(db),
                'action': 'Present these events to the user; do not adopt a replacement baseline.'}
    return {'delivery': 'delivered' if deliver_local(db) else 'pending',
            'host_push': False, 'scope': 'local OS submission only; visibility is not confirmed'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--alert-config', type=Path, help='operator-controlled command receiver config')
    parser.add_argument('--notifications', choices=('local', 'agent', 'off'), default='local',
                        help='local desktop (default), structured agent result, or opt out')
    args = parser.parse_args()
    os.umask(0o077)
    args.state_dir.mkdir(parents=True, exist_ok=True)
    # Lock covers verification and commit, so overlapping invocations cannot reorder recovery.
    with (args.state_dir / 'monitor.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        tmp = args.state_dir / 'tmp'
        tmp.mkdir(exist_ok=True)
        try:
            if args.config.stat().st_size > 65536:
                raise ValueError('configuration exceeds 64 KiB')
            cfg = json.loads(args.config.read_text())
            if not isinstance(cfg, dict):
                raise ValueError('configuration must be an object')
            status, detail = check(cfg, tmp)
        except (OSError, ValueError) as exc:
            status, detail = 'error', 'configuration: ' + str(exc)[:300]
        record(args.state_dir / 'monitor.sqlite3', status, detail)
        notification = notification_result(args.state_dir / 'monitor.sqlite3', args.notifications) if args.alert_config is None or args.notifications != 'local' else {}
        delivery = notification.get('delivery', 'pending')
        if args.alert_config is not None and args.notifications == 'local':
            try:
                if args.alert_config.stat().st_size > 65536:
                    raise ValueError('alert configuration exceeds 64 KiB')
                delivery = 'delivered' if deliver(args.state_dir / 'monitor.sqlite3', args.alert_config, tmp) else 'pending'
            except (OSError, ValueError, sqlite3.Error):
                delivery = 'pending'
        print(json.dumps({'status': status, 'detail': detail, 'action': ACTIONS[status],
                          'delivery': delivery, 'notification': notification}))
        return 0 if status == 'healthy' and delivery != 'pending' else 1

if __name__ == '__main__':
    raise SystemExit(main())
