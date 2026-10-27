"""One pinned b09 K8s Exposure launch; called only by the released host harness.

The root wrapper reads a mode0600 private bind mount, writes a mode0600 auth
document, then runs the actual model runner as the image's UID/GID 10001.
"""
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


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cgroup_number(path, key=None):
    content = Path(path).read_text().strip()
    if key is None:
        return int(content)
    return int(next(line.split()[1] for line in content.splitlines() if line.startswith(key + ' ')))


def private_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f, sort_keys=True)


def usage():
    rollouts = list((WORK / '.codex/chack').glob('*/sessions/**/*.jsonl'))
    if not rollouts:
        raise ValueError('rollout_count_invalid')
    totals = {'model_calls': 0, 'input_tokens': 0, 'output_tokens': 0,
              'duplicate_cumulative_events': 0, 'rollout_sha256': {}}
    for rollout in sorted(rollouts):
        events = []
        for line in rollout.open():
            item = json.loads(line)
            payload = item.get('payload') or {}
            if item.get('type') == 'event_msg' and payload.get('type') == 'token_count':
                events.append(payload['info']['total_token_usage'])
        cumulative = [item['total_tokens'] for item in events]
        if not cumulative or cumulative != sorted(cumulative):
            raise ValueError('token_events_invalid')
        calls = sum(total > (cumulative[i-1] if i else 0)
                    for i, total in enumerate(cumulative))
        if calls != len(set(cumulative)):
            raise ValueError('token_events_duplicate_invalid')
        final = events[-1]
        totals['model_calls'] += calls
        totals['input_tokens'] += final['input_tokens']
        totals['output_tokens'] += final['output_tokens']
        totals['duplicate_cumulative_events'] += len(events) - calls
        totals['rollout_sha256'][rollout.name] = sha(rollout)
    return totals


def main():
    if os.geteuid() != 0 or not (WORK / 'findings.json').is_file() or not TOKEN.is_file():
        raise ValueError('private_mount_preflight_failed')
    token = TOKEN.read_text().strip()
    if not token:
        raise ValueError('token_empty')
    secret_sha = hashlib.sha256(token.encode()).hexdigest()
    alias = Path('/app/peaso/ai/_vendor/chack/model_aliases.py')
    if sha(alias) != '9b1002a9d5e81127c45ea3300305d4c76bf68103bc1088ad4f4752340e0359c7':
        raise ValueError('d3_alias_source_drift')
    private_json(WORK / 'codex-auth.json', {**MODEL, 'access_token': token})
    del token
    for path in WORK.iterdir():
        os.chown(path, 10001, 10001)
    os.chown(WORK, 10001, 10001)
    cpu_before = cgroup_number('/sys/fs/cgroup/cpu.stat', 'usage_usec')
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
        process = subprocess.Popen([sys.executable, '-m', 'peaso.ai.runner', 'exposure'],
                                   cwd=WORK, env=env, stdout=log, stderr=log,
                                   preexec_fn=drop, start_new_session=True)
        try:
            code = process.wait(timeout=490)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            code = 124
    (WORK / 'codex-auth.json').unlink(missing_ok=True)
    metric = {'returncode': code, 'result_available': (WORK / 'result.json').is_file(),
              'wall_seconds': time.monotonic() - start,
              'cpu_seconds': max(0, (cgroup_number('/sys/fs/cgroup/cpu.stat', 'usage_usec') - cpu_before) / 1e6),
              'peak_rss_bytes': cgroup_number('/sys/fs/cgroup/memory.peak'),
              'credential_sha256': secret_sha, 'model': MODEL,
              'findings_sha256': sha(WORK / 'findings.json')}
    if code == 0 and metric['result_available']:
        metric.update(usage())
    private_json(WORK / 'runtime-metrics.json', metric)
    print(json.dumps({k: metric[k] for k in ('returncode','result_available','wall_seconds',
          'cpu_seconds','peak_rss_bytes','model_calls','input_tokens','output_tokens') if k in metric},
          sort_keys=True))
    if code:
        raise SystemExit(code)


if __name__ == '__main__':
    main()
