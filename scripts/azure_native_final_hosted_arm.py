"""One pinned Azure Hardening reviewer container, invoked only by gated host."""

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


WORK = Path('/workspace')
TOKEN = Path('/run/secrets/platform-codex-token')
MODEL = {'provider': 'codex', 'model': 'gpt-5.6-sol', 'thinking': 'high'}
ALIAS_SHA = '9b1002a9d5e81127c45ea3300305d4c76bf68103bc1088ad4f4752340e0359c7'
IMAGE_SOURCE_SHA = {
    'peaso/ai/agents/hardening.yaml': '0e1fe6a88266da5f88e06509f843f056ca5e22ddbc25094bd7583a5664327844',
    'peaso/ai/runner.py': 'f75c5726a4f9b9b4ae0a23ffe180f88033711317fa9e8ccea50e1791da1af478',
    'peaso/ai/output_validation.py': 'bebdce6232ccc056823646411197a12741ff5462f48050c0c8a1b2dab241314f',
    'peaso/ai/prompting.py': '4e6c4f13dce2947dc23f037c5a95ebbf0d4efc6ba9a5ed97182a73ac3a2f2914',
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def private_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True)


def cgroup(path, key=None):
    text = Path(path).read_text().strip()
    return int(text if key is None else next(line.split()[1] for line in text.splitlines()
                                             if line.startswith(key + ' ')))


def usage():
    paths = sorted((WORK / '.codex/chack').glob('*/sessions/**/*.jsonl'))
    if not paths:
        raise ValueError('missing_model_rollout')
    totals = {'model_calls': 0, 'input_tokens': 0, 'output_tokens': 0,
              'duplicate_cumulative_events': 0}
    for path in paths:
        events = []
        for line in path.open():
            row = json.loads(line)
            payload = row.get('payload') or {}
            if row.get('type') == 'event_msg' and payload.get('type') == 'token_count':
                events.append(payload['info']['total_token_usage'])
        counts = [row['total_tokens'] for row in events]
        if not counts or counts != sorted(counts):
            raise ValueError('token_event_order_invalid')
        calls = sum(value > (counts[i - 1] if i else 0) for i, value in enumerate(counts))
        totals['model_calls'] += calls
        totals['input_tokens'] += events[-1]['input_tokens']
        totals['output_tokens'] += events[-1]['output_tokens']
        totals['duplicate_cumulative_events'] += len(events) - calls
    return totals


def main():
    if (os.geteuid() != 0 or not (WORK / 'findings.json').is_file()
            or not (WORK / 'credentials.json').is_file() or not TOKEN.is_file()):
        raise ValueError('private_mount_preflight_failed')
    if sha('/app/peaso/ai/_vendor/chack/model_aliases.py') != ALIAS_SHA:
        raise ValueError('pinned_image_model_alias_drift')
    for source, expected in IMAGE_SOURCE_SHA.items():
        if sha('/app/' + source) != expected:
            raise ValueError('pinned_image_source_drift:' + source)
    token = TOKEN.read_text().strip()
    if not token:
        raise ValueError('empty_model_token')
    private_json(WORK / 'codex-auth.json', {**MODEL, 'access_token': token})
    token_sha = hashlib.sha256(token.encode()).hexdigest()
    del token
    for path in WORK.iterdir():
        os.chown(path, 10001, 10001)
    os.chown(WORK, 10001, 10001)
    cpu_before = cgroup('/sys/fs/cgroup/cpu.stat', 'usage_usec')
    start = time.monotonic()
    env = dict(os.environ)
    env.update(HOME=str(WORK), TMPDIR=str(WORK), CODEX_HOME=str(WORK / '.codex'),
               PYTHONPATH='/app', PEASO_AI_AGENT_TIMEOUT_SECONDS='480',
               AWS_EC2_METADATA_DISABLED='true', PYTHONUNBUFFERED='1')

    def drop():
        os.setgroups([])
        os.setgid(10001)
        os.setuid(10001)

    log_fd = os.open(WORK / 'runner.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(log_fd, 'wb') as log:
        process = subprocess.Popen([sys.executable, '-m', 'peaso.ai.runner', 'hardening'],
                                   cwd=WORK, env=env, stdout=log, stderr=log,
                                   preexec_fn=drop, start_new_session=True)
        try:
            code = process.wait(timeout=490)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            code = 124
    (WORK / 'codex-auth.json').unlink(missing_ok=True)
    result = {'returncode': code, 'result_available': (WORK / 'result.json').is_file(),
              'wall_seconds': time.monotonic() - start,
              'cpu_seconds': max(0, (cgroup('/sys/fs/cgroup/cpu.stat', 'usage_usec') - cpu_before) / 1e6),
              'peak_rss_bytes': cgroup('/sys/fs/cgroup/memory.peak'),
              'model': MODEL, 'token_sha256': token_sha,
              'findings_sha256': sha(WORK / 'findings.json')}
    if code == 0 and result['result_available']:
        result.update(usage())
    private_json(WORK / 'runtime-metrics.json', result)
    if code:
        raise SystemExit(code)


if __name__ == '__main__':
    main()
