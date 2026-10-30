"""Entrypoints for two separately namespaced containers in a role-free AI task."""
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import urlsplit

from .fargate import MAX_INPUT, MAX_OUTPUT, STAGES


def reject_ambient_aws_credentials():
    """Stop if a deployment starts supplying AWS identity to an AI task."""
    credential_variables = (
        'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI',
        'AWS_CONTAINER_CREDENTIALS_FULL_URI',
        'AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY',
        'AWS_SESSION_TOKEN',
        'AWS_PROFILE',
        'AWS_WEB_IDENTITY_TOKEN_FILE',
        'AWS_ROLE_ARN',
    )
    if any(os.environ.get(name) for name in credential_variables):
        raise RuntimeError('ambient_aws_credentials_forbidden')


class TransferPending(RuntimeError):
    """The exact presigned object does not exist yet."""


def transfer(method, url, *, body=None, limit=MAX_INPUT, pending=()):
    """Only presigned S3 HTTPS objects; never ambient cloud credentials."""
    import re
    import requests
    p = urlsplit(url)
    if (p.scheme != 'https' or p.username or p.password or p.port or p.fragment or not p.query
            or not re.fullmatch(r'[a-z0-9][a-z0-9.-]*\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com', p.netloc)):
        raise ValueError('unsafe_task_transfer')
    with requests.Session() as session:
        session.trust_env = False
        with session.request(method, url, data=body, stream=True, allow_redirects=False, timeout=(10, 60)) as response:
            if response.status_code in pending:
                raise TransferPending('task_transfer_pending')
            if response.status_code != 200:
                raise RuntimeError('task_transfer_failed')
            data = bytearray()
            for chunk in response.iter_content(65536):
                if len(chunk) > limit - len(data):
                    raise ValueError('task_transfer_limit')
                data.extend(chunk)
            return bytes(data)


def reuse_idle(value):
    """Seconds a retained task may wait for the same scan's next stage; 0 when absent."""
    if value is None:
        return 0
    from .fargate import REUSE_IDLE_SECONDS
    if not value.isdigit() or not 0 < int(value) <= REUSE_IDLE_SECONDS:
        raise ValueError('invalid_reuse_idle')
    return int(value)

def fetch_bootstrap(url, wait, *, clock=time.monotonic, sleep=time.sleep):
    """Fetch the relay configuration, waiting only for a not-yet-written object.

    S3 reports a missing presigned object as 404 or 403. Any other failure, or
    the bounded wait ending, stops the relay and therefore the whole task.
    """
    if not wait:
        return transfer('GET', url, limit=64_000)
    deadline = clock() + wait
    while True:
        try:
            return transfer('GET', url, limit=64_000, pending=(403, 404))
        except TransferPending:
            if clock() >= deadline:
                raise RuntimeError('task_bootstrap_unavailable') from None
            sleep(min(.5, max(0, deadline - clock())))

def admit(config, sequence, task_binding):
    """Accept only this task's expected invocation for its own tenant/scan."""
    import hmac
    if not isinstance(config, dict) or config.get('sequence', 1) != sequence:
        raise ValueError('invalid_task_invocation')
    if task_binding or sequence > 1:
        if (not task_binding or not isinstance(config.get('binding'), str)
                or not hmac.compare_digest(config['binding'], task_binding)):
            raise ValueError('task_binding_mismatch')
    return config

def run_relay(*, serve=None):
    """Serve one invocation, then at most the same scan's next one."""
    if serve is None:
        from .model_relay import serve
    url = os.environ.pop('PEASO_AI_BOOTSTRAP_URL')
    next_url = os.environ.pop('PEASO_AI_NEXT_BOOTSTRAP_URL', None)
    idle = reuse_idle(os.environ.pop('PEASO_AI_REUSE_IDLE_SECONDS', None))
    task_binding = os.environ.pop('PEASO_AI_TASK_BINDING', None)
    retain = bool(next_url and idle and task_binding)
    config = admit(json.loads(transfer('GET', url, limit=64_000)), 1, task_binding)
    if not serve(config, stop_after_result=retain) or not retain:
        return
    del config
    try:
        raw = fetch_bootstrap(next_url, idle)
    except RuntimeError:
        return  # No next stage arrived: exit, which stops the whole task.
    config = admit(json.loads(raw), 2, task_binding)
    # Acknowledge only after the binding check, before any model access.
    transfer('PUT', config['accepted_url'], body=b'{}', limit=1024)
    serve(config)

def wait_bootstrap(sequence, wait, *, get=None, clock=time.monotonic, sleep=time.sleep):
    """Read the local relay's public configuration for one exact invocation."""
    if get is None:
        import requests
        get = lambda: requests.get('http://127.0.0.1:8765/bootstrap', timeout=2, proxies={'http': None})
    deadline = clock() + wait
    while True:
        try:
            response = get()
            response.raise_for_status()
            config = response.json()
            if isinstance(config, dict) and config.get('sequence', 1) == sequence:
                return config
        except Exception:
            pass
        if clock() >= deadline:
            raise RuntimeError('relay_unavailable')
        sleep(.5)

def scrub(root='/tmp'):
    """Remove every process and file a finished stage left in this container.

    Fails closed: if anything survives, the task must not take another stage.
    """
    import shutil
    import psutil
    me = psutil.Process()
    children = me.children(recursive=True)
    for child in reversed(children):
        try:
            child.kill()
        except psutil.NoSuchProcess:
            pass
    psutil.wait_procs(children, timeout=5)
    while True:
        try:
            if os.waitpid(-1, os.WNOHANG)[0] == 0:
                break
        except ChildProcessError:
            break
    def alive(child):
        try:
            return child.status() != psutil.STATUS_ZOMBIE
        except psutil.NoSuchProcess:
            return False
    if any(alive(child) for child in me.children(recursive=True)):
        raise RuntimeError('task_scrub_failed')
    root = Path(root)
    for path in root.iterdir():
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
    if any(root.iterdir()):
        raise RuntimeError('task_scrub_failed')
    import gc
    gc.collect()

def run_agent_task(*, run=None, wait=None, clean=None):
    """Run the first invocation, then at most the same scan's next one."""
    run, wait, clean = run or run_agent, wait or wait_bootstrap, clean or scrub
    idle = reuse_idle(os.environ.pop('PEASO_AI_REUSE_IDLE_SECONDS', None))
    run(wait(1, 120))
    if not idle:
        return
    # A fresh, empty /tmp and no surviving process for the next stage. The
    # first result is already stored: a failed scrub only ends the task.
    try:
        clean()
    except Exception:
        return
    try:
        config = wait(2, idle + 60)
    except RuntimeError:
        return  # The relay ended the task's short idle window.
    run(config)

def unpack(data, root):
    import re
    total = count = 0
    with tarfile.open(fileobj=io.BytesIO(data) if isinstance(data, (bytes, bytearray)) else data, mode='r:*') as archive:
        for member in archive:
            count += 1
            total += member.size
            if (count > 32 or total > MAX_INPUT or not member.isfile()
                    or not re.fullmatch(r'[a-z][a-z0-9_.-]{0,100}', member.name)
                    or member.name in ('codex-auth.json', 'result.json')):
                raise ValueError('invalid_task_archive')
            path = root / member.name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as output, archive.extractfile(member) as source:
                remaining = member.size
                while remaining:
                    chunk = source.read(min(65536, remaining))
                    if not chunk:
                        raise ValueError('truncated_task_archive')
                    remaining -= len(chunk)
                    output.write(chunk)


def run_agent(config):
    if config.get('stage') not in STAGES:
        raise ValueError('invalid_task_stage')
    from .deadline import ENVIRONMENT_KEY, timeout_seconds
    remaining = timeout_seconds(config.get('timeout'))
    with tempfile.TemporaryDirectory(prefix='ai-', dir='/tmp') as directory:
        root = Path(directory)
        # The archive is disk-backed, not a second copy of a large bytearray.
        # Both HTTP hops stream in 64 KiB chunks before the model starts.
        with tempfile.TemporaryFile(dir=root) as archive:
            relay_request('GET', '/input', config['relay_token'], sink=archive)
            archive.seek(0)
            unpack(archive, root)
        # This file carries a task-local relay capability, not the real model credential.
        fd = os.open(root/'codex-auth.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump({**config.get('ai_configuration', {}), 'access_token': config['relay_token']}, stream)
        env = {'PATH': os.defpath + ':/usr/local/bin', 'HOME': directory, 'TMPDIR': directory,
               'PYTHONPATH': '/app', 'CODEX_HOME': directory + '/.codex', 'LANG': 'C.UTF-8',
               'AWS_EC2_METADATA_DISABLED': 'true', 'PEASO_AI_MODEL_RELAY': 'http://127.0.0.1:8765',
               'CHACK_CODEX_DIRECT_CACHE_TRANSPORT': 'off', ENVIRONMENT_KEY: str(remaining)}
        process = subprocess.Popen([sys.executable, '-m', 'peaso.ai.runner', config['stage']],
            cwd=directory, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            process.wait(timeout=remaining)
            if process.returncode == 65:
                from .output_validation import InvalidAgentOutput
                raise InvalidAgentOutput('invalid_agent_result')
            if process.returncode == 124:
                raise TimeoutError('agent_runtime_limit')
            if process.returncode == 78:
                from .providers import ConfigurationError
                raise ConfigurationError('ai_configuration_invalid')
            if process.returncode:
                raise RuntimeError('agent_failed')
            # Never follow an agent-created symlink in the trusted uploader.
            result = read_result(root)
            relay_request('POST', '/result', config['relay_token'], body=result, limit=1024)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def read_result(root):
    fd = os.open(root/'result.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_OUTPUT:
            raise ValueError('agent_output_limit')
        result = stream.read(MAX_OUTPUT + 1)
    if len(result) > MAX_OUTPUT:
        raise ValueError('agent_output_limit')
    json.loads(result)
    return result


def relay_request(method, path, capability, *, body=None, limit=MAX_INPUT, sink=None):
    import requests
    with requests.Session() as session:
        session.trust_env = False
        with session.request(method, 'http://127.0.0.1:8765' + path, data=body,
                headers={'Authorization': 'Bearer ' + capability}, stream=True,
                timeout=(5, 600 if path == '/input' else 60)) as response:
            if response.status_code != 200:
                raise RuntimeError('relay_transfer_failed')
            output = bytearray() if sink is None else None
            total = 0
            for chunk in response.iter_content(65536):
                if len(chunk) > limit - total:
                    raise ValueError('relay_transfer_limit')
                total += len(chunk)
                if sink is None:
                    output.extend(chunk)
                else:
                    sink.write(chunk)
            return bytes(output) if sink is None else None


def main():
    from .output_validation import InvalidAgentOutput
    from .providers import ConfigurationError
    os.umask(0o077)
    try:
        reject_ambient_aws_credentials()
        if sys.argv[1] == 'relay':
            run_relay()
        elif sys.argv[1] == 'agent':
            run_agent_task()
        else:
            raise ValueError('invalid_task_mode')
    except (TimeoutError, subprocess.TimeoutExpired):
        print('ai_agent_failure=deadline', file=sys.stderr, flush=True)
        sys.exit(124)
    except InvalidAgentOutput:
        print('ai_agent_failure=invalid_output', file=sys.stderr, flush=True)
        sys.exit(65)
    except ConfigurationError:
        sys.exit(78)
    except BaseException:
        # Credentials, signed URLs, provider bodies and exception text stay private.
        sys.exit(1)


if __name__ == '__main__':
    main()
