#!/usr/bin/env python3
"""One read-only verification, with transactional durable transition alerts."""
import argparse
from contextlib import closing
import fcntl
import json
import os
from pathlib import Path
import resource
import sqlite3
import subprocess
import tempfile
import time

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


def check(cfg, tmp):
    try:
        if cfg.get('approved') is not True:
            raise ValueError('approved must be true')
        for name in ['binary', 'baseline', 'public_key']:
            path = Path(cfg[name])
            if not path.is_absolute() or not path.is_file():
                raise ValueError(name + ' must be an existing absolute file')
        # Explicit public key required: never permit unsigned verification.
        env = {'PATH': '/usr/bin:/bin', 'TMPDIR': str(tmp), 'GOMEMLIMIT': '192MiB', 'GOMAXPROCS': '2'}
        with tempfile.TemporaryFile(dir=tmp) as output:
            result = subprocess.run([cfg['binary'], 'verify', '--baseline', cfg['baseline'],
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--state-dir', type=Path, required=True)
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
        print(json.dumps({'status': status, 'detail': detail, 'action': ACTIONS[status]}))
        return 0 if status == 'healthy' else 1

if __name__ == '__main__':
    raise SystemExit(main())
