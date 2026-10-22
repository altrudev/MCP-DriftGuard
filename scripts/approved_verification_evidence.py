#!/usr/bin/env python3
"""Trusted operator-side MCP verification; Codex only reads resulting evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import stat
import re
import time
import pwd
import selectors
import signal
from urllib.parse import urlsplit
from evidence_signatures import verify, sign, canonical

# Administrator-provisioned; never supplied by the invoking agent or policy.
TRUSTED_APPROVAL_KEY = Path("/etc/mcpdrift/trust/operator-approval-ed25519.pub.pem")

EVIDENCE_PRIVATE_KEY = Path("/etc/mcpdrift/trust/operator-evidence-ed25519.pem")
CONSUMPTION_LEDGER = Path("/var/lib/mcpdrift/consumed-authorizations")
MAX_AUTHORIZATION_SECONDS = 300
PRIVILEGE_LAUNCHER = Path('/usr/bin/setpriv')
VERIFIER_ACCOUNT = 'mcpdrift-verifier'


def verifier_prefix():
    """Only a trusted launcher may start with root privileges, never the verifier.

    setpriv fails before exec if any requested restriction cannot be applied.
    Identity is administrator provisioned, never supplied by policy or caller.
    """
    if sys.platform != 'linux' or os.getuid() != 0 or os.geteuid() != 0:
        raise ValueError('privileged broker requires Linux and real/effective root')
    if not trusted_anchor(PRIVILEGE_LAUNCHER) or not os.access(PRIVILEGE_LAUNCHER, os.X_OK):
        raise ValueError('trusted privilege launcher missing or unsafe')
    try:
        account = pwd.getpwnam(VERIFIER_ACCOUNT)
    except KeyError as exc:
        raise ValueError('dedicated verifier account missing') from exc
    if account.pw_uid <= 0 or account.pw_gid <= 0:
        raise ValueError('verifier account must have non-root UID and GID')
    return [str(PRIVILEGE_LAUNCHER), '--reuid', str(account.pw_uid),
            '--regid', str(account.pw_gid), '--clear-groups',
            '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
            '--no-new-privs', '--']


def trusted_anchor(path, private=False, directory=False):
    """Require root custody throughout the absolute, symlink-free path."""
    try:
        if not path.is_absolute():
            return False
        for part in (path, *path.parents):
            info = part.lstat()
            if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
                return False
            if part != path and not stat.S_ISDIR(info.st_mode):
                return False
        mode = path.lstat().st_mode
        if directory:
            return stat.S_ISDIR(mode) and not mode & 0o077
        return stat.S_ISREG(mode) and (not private or not mode & 0o077)
    except OSError:
        return False


def validate_authorization(policy):
    fields = {'schema', 'endpoint', 'binary_sha256', 'baseline_sha256',
              'authorization_id', 'issued_at', 'expires_at'}
    if set(policy) != fields or policy.get('schema') != 'mcpdrift-operator-policy/v2':
        raise ValueError('invalid approved policy')
    if not isinstance(policy['authorization_id'], str) or not re.fullmatch(r'[0-9a-f]{32}', policy['authorization_id']):
        raise ValueError('invalid authorization identifier')
    issued, expires = policy['issued_at'], policy['expires_at']
    if type(issued) is not int or type(expires) is not int:
        raise ValueError('invalid authorization timestamps')
    now = time.time()
    if not issued <= now < expires or not 0 < expires - issued <= MAX_AUTHORIZATION_SECONDS:
        raise ValueError('authorization stale, future-dated, or lifetime too long')


def consume_authorization(policy):
    if not trusted_anchor(CONSUMPTION_LEDGER, directory=True):
        raise ValueError('authorization consumption ledger missing or unsafe')
    validate_authorization(policy)
    directory = os.open(CONSUMPTION_LEDGER, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        # ID uniqueness survives re-signing and policy changes. Burn before execution.
        fd = os.open(policy['authorization_id'], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        with os.fdopen(fd, 'w') as record:
            record.write(hashlib.sha256(canonical(policy)).hexdigest() + '\n')
            record.flush()
            os.fsync(record.fileno())
        os.fsync(directory)
    finally:
        os.close(directory)



# Combined raw stdout/stderr budget; neither stream is decoded before capture ends.
MAX_CAPTURE_BYTES = 1024 * 1024
VERIFICATION_TIMEOUT = 25
REAP_TIMEOUT = 1


class CaptureFailure(ValueError):
    """Execution cannot produce trustworthy, bounded evidence."""


def bounded_run(command):
    """Bound memory and pipe waits, including pipes inherited by descendants.

    Cleanup covers the new process group, including after a normal leader exit.
    Descendants that escape the group require operator-side cgroup containment.
    Never use communicate(), a Popen context manager, or an unbounded wait here.
    """
    deadline = time.monotonic() + VERIFICATION_TIMEOUT
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={'PATH': '/usr/bin:/bin'}, stdin=subprocess.DEVNULL,
                               close_fds=True, cwd='/', start_new_session=True)
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    captured = 0
    try:
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CaptureFailure('verification deadline exceeded')
            for key, _ in selector.select(min(remaining, 0.05)):
                # At most one byte beyond the budget is read to detect overflow.
                chunk = os.read(key.fd, min(65536, MAX_CAPTURE_BYTES - captured + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                captured += len(chunk)
                if captured > MAX_CAPTURE_BYTES:
                    raise CaptureFailure('verification output limit exceeded')
                if key.fileobj is process.stdout:
                    stdout.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CaptureFailure('verification deadline exceeded')
        try:
            code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise CaptureFailure('verification deadline exceeded') from exc
        return subprocess.CompletedProcess(command, code, stdout.decode('utf-8'), '')
    finally:
        # Do this even if the leader exited: descendants may still be running.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            selector.close()
            process.stdout.close()
            process.stderr.close()
            try:
                process.wait(timeout=REAP_TIMEOUT)
            except subprocess.TimeoutExpired as exc:
                raise CaptureFailure('verifier could not be reaped within cleanup deadline') from exc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', required=True)
    ap.add_argument('--endpoint', required=True)
    ap.add_argument('--policy', required=True, help='independently provisioned read-only policy JSON')
    ap.add_argument('--policy-signature', required=True)
    ap.add_argument('--baseline', required=True)
    ap.add_argument('--output', required=True)
    args = ap.parse_args()
    prefix = verifier_prefix()
    policy_path = Path(args.policy).resolve(strict=True)
    policy = json.loads(policy_path.read_text())
    if not trusted_anchor(TRUSTED_APPROVAL_KEY):
        ap.error("administrator approval trust anchor missing or unsafe")
    verify(policy, args.policy_signature, TRUSTED_APPROVAL_KEY)
    validate_authorization(policy)
    if not trusted_anchor(EVIDENCE_PRIVATE_KEY, private=True):
        ap.error('administrator evidence signing key missing or unsafe')
    parsed = urlsplit(args.endpoint)
    if args.endpoint != policy['endpoint'] or parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or parsed.username or parsed.password or parsed.fragment:
        ap.error('endpoint must exactly match an explicitly approved loopback target')
    binary = Path(args.binary).resolve(strict=True)
    baseline = Path(args.baseline).resolve(strict=True)
    output = Path(args.output).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK) or not baseline.is_file() or output.exists() or output.is_symlink():
        ap.error('invalid binary/baseline or output already exists')
    digest_before = hashlib.sha256(baseline.read_bytes()).hexdigest()
    binary_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if digest_before != policy['baseline_sha256'] or binary_digest != policy['binary_sha256']:
        ap.error('approved artifact digest mismatch')
    signature_output = Path(str(output) + '.sig.json')
    if signature_output.exists() or signature_output.is_symlink():
        ap.error('evidence signature output already exists')
    consume_authorization(policy)
    command = prefix + [str(binary), 'verify', '--baseline', str(baseline), '--format', 'json', args.endpoint]
    try:
        result = bounded_run(command)
        verdict = {0:'PASS',1:'REVIEW',2:'FAIL',3:'INCONCLUSIVE',4:'BASELINE_ERROR',5:'INTEGRITY_FAILURE'}.get(result.returncode,'UNEXPECTED_EXIT')
        data = json.loads(result.stdout) if result.stdout.strip() else None
        if not isinstance(data, dict):
            verdict = 'INCONCLUSIVE'
        if result.returncode in (0, 1, 2) and (not isinstance(data, dict) or data.get('match') is not (result.returncode == 0)):
            verdict = 'INCONCLUSIVE'
    except (CaptureFailure, UnicodeDecodeError, json.JSONDecodeError):
        verdict, data, result = 'INCONCLUSIVE', None, None
    digest_after = hashlib.sha256(baseline.read_bytes()).hexdigest()
    if digest_before != digest_after:
        raise RuntimeError('baseline changed during verification; evidence refused')
    payload = {'schema':'mcpdrift-operator-evidence/v1','endpoint':args.endpoint,'baseline_sha256':digest_before,'baseline_path':str(baseline),'verifier_binary':str(binary),'verdict':verdict,'exit_code':result.returncode if result else None,'result':data,'error_class':('VERIFIER_ERROR' if result and result.returncode not in (0,1,2) else 'NONE') if result else 'CAPTURE_OR_JSON_FAILURE','authorization':'one-time local signed policy','authorization_id':policy['authorization_id'],'authorization_expires_at':policy['expires_at'],'policy_sha256':hashlib.sha256(canonical(policy)).hexdigest(),'verifier_sha256':binary_digest,'baseline_modified':False}
    signed = sign(payload, EVIDENCE_PRIVATE_KEY)
    signature_output = Path(str(output) + '.sig.json')
    if signature_output.exists() or signature_output.is_symlink():
        ap.error('evidence signature output already exists')
    fd = os.open(output, os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:
        json.dump(payload,f,indent=2,sort_keys=True)
        f.write('\n')
    signature_fd = os.open(signature_output, os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(signature_fd,'w') as f:
        json.dump(signed,f,indent=2,sort_keys=True)
        f.write('\n')
    print(json.dumps({'verdict':verdict,'evidence':str(output),'baseline_sha256':digest_before}))
    return 0 if verdict in ('PASS','REVIEW','FAIL') else 1

if __name__=='__main__':
    sys.exit(main())
