"""One role-free Fargate task per scan stage chain; exact-object ephemeral transport."""
import gzip
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import time
import uuid

MAX_INPUT = 512 * 1024 * 1024
MAX_OUTPUT = 8_000_000
STAGES = {'network', 'priorities'}


class TaskStartupError(RuntimeError):
    """ECS stopped the task before its agent process started."""


def configuration():
    names = ('CLUSTER', 'TASK_DEFINITION', 'SUBNETS', 'SECURITY_GROUPS', 'BUCKET')
    values = {name.lower(): os.environ.get('PEASO_AI_FARGATE_' + name, '').strip() for name in names}
    if not all(values.values()):
        raise RuntimeError('ai_isolation_unavailable')
    for name, prefix in (('subnets', 'subnet-'), ('security_groups', 'sg-')):
        values[name] = values[name].split(',')
        if not 1 <= len(values[name]) <= 8 or any(not re.fullmatch(prefix + r'[a-f0-9]{8,17}', v) for v in values[name]):
            raise RuntimeError('ai_isolation_unavailable')
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', values['bucket']):
        raise RuntimeError('ai_isolation_unavailable')
    return values


def validate_task(definition):
    """Reject a mutable deployment accidentally handing agents platform identity."""
    if (definition.get('taskRoleArn') or definition.get('networkMode') != 'awsvpc'
            or 'FARGATE' not in definition.get('requiresCompatibilities', [])
            or definition.get('pidMode') or definition.get('ipcMode')
            or len(definition.get('volumes', [])) != 2
            or {v.get('name') for v in definition.get('volumes', [])} != {'agent-scratch', 'relay-scratch'}
            or any(set(v) - {'name', 'host'} or v.get('host', {}) != {} for v in definition.get('volumes', []))):
        raise RuntimeError('unsafe_ai_task_definition')
    containers = definition.get('containerDefinitions', [])
    if len(containers) != 2 or {c.get('name') for c in containers} != {'agent', 'relay'}:
        raise RuntimeError('unsafe_ai_task_definition')
    for container in containers:
        name = container['name']
        linux = container.get('linuxParameters', {})
        if (container.get('user') != '10001:10001' or not container.get('readonlyRootFilesystem') or container.get('essential') is not True
                or container.get('privileged') or container.get('mountPoints') != [
                    {'sourceVolume': name + '-scratch', 'containerPath': '/tmp', 'readOnly': False}]
                or container.get('volumesFrom')
                or container.get('secrets') or container.get('environmentFiles')
                or container.get('environment') not in (None, [])
                or container.get('repositoryCredentials')
                or linux.get('capabilities', {}).get('add')
                or linux.get('capabilities', {}).get('drop') != ['ALL']
                or linux.get('devices') or linux.get('sharedMemorySize')
                or container.get('entryPoint') != ['python', '-m', 'peaso.ai.task_runtime']
                or container.get('command') != [name]
                or not re.fullmatch(r'[^\s]+@sha256:[a-f0-9]{64}', container.get('image', ''))):
            raise RuntimeError('unsafe_ai_task_definition')


def pack_workspace(root):
    output = io.BytesIO()
    total = 0
    paths = sorted(Path(root).iterdir())
    # The large Priorities database is already gzip-compressed. Avoid a
    # second compression pass when the complete tar fits the input limit.
    raw_size = sum(path.lstat().st_size for path in paths)
    plain = ((Path(root) / 'context.sqlite.gz').is_file()
             and raw_size + len(paths) * 1024 + 10240 <= MAX_INPUT)
    mode = 'w' if plain else 'w:gz'
    options = {} if plain else {'compresslevel': 1}
    with tarfile.open(fileobj=output, mode=mode, format=tarfile.USTAR_FORMAT, **options) as archive:
        for path in paths:
            if path.name == 'codex-auth.json':
                raise ValueError('model_token_must_not_enter_agent_bundle')
            if not re.fullmatch(r'[a-z][a-z0-9_.-]{0,100}', path.name):
                raise ValueError('invalid_agent_input_name')
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError('invalid_agent_input_file')
            total += metadata.st_size
            if total > MAX_INPUT:
                raise ValueError('agent_input_too_large')
            if path.name == 'credentials.json':
                document = json.loads(path.read_text())
                if any(entry.get('provider') == 'aws' for entry in document.get('entries', [])):
                    raise ValueError('aws_live_ai_access_disabled')
            archive.add(path, arcname=path.name, recursive=False)
    data = output.getvalue()
    if len(data) > MAX_INPUT:
        raise ValueError('agent_input_too_large')
    return data


# One retained task serves at most these two invocations, in this order.
# A Network task may stay up only to take the same scan's Priorities stage.
REUSE_IDLE_SECONDS = 90
# Minimum remaining idle window for the invoker to hand a retained task work.
REUSE_MARGIN = 15
# The retained relay must acknowledge the second invocation within this bound.
REUSE_ACCEPT_SECONDS = 30
_LIVE_TASK_STATES = {'PROVISIONING', 'PENDING', 'ACTIVATING', 'RUNNING'}

class TaskReuseError(RuntimeError):
    """A retained task cannot take this invocation; launch a fresh one."""

def _clients(ecs, s3):
    import boto3
    from botocore.config import Config
    sdk = Config(connect_timeout=5, read_timeout=10, retries={'max_attempts': 1}, signature_version='v4')
    ecs = ecs or boto3.client('ecs', config=sdk)
    s3 = s3 or boto3.client('s3', config=sdk.merge(Config(signature_version='s3v4')))
    return ecs, s3

def _keys(ident, sequence=1):
    prefix = 'invocations/' + ident + '/' + ('' if sequence == 1 else str(sequence) + '/')
    names = ('input.tgz', 'relay.json', 'result.json') + (('accepted.json',) if sequence > 1 else ())
    return {name: prefix + name for name in names}

def binding(tenant, scan):
    """Opaque tenant/scan binding carried by a task and every invocation it takes."""
    import hashlib
    return hashlib.sha256(('peaso-ai-task\0%s\0%s' % (tenant, scan or '')).encode()).hexdigest()

def _run_task(ecs, config, definition, ident, bootstrap_url, *, task_binding=None, next_url=None):
    relay = [{'name': 'PEASO_AI_BOOTSTRAP_URL', 'value': bootstrap_url}]
    environment = {'relay': relay}
    if task_binding is not None:
        relay.append({'name': 'PEASO_AI_TASK_BINDING', 'value': task_binding})
    if next_url is not None:
        # Only the same scan's next stage may follow, for a short bounded time.
        relay.append({'name': 'PEASO_AI_NEXT_BOOTSTRAP_URL', 'value': next_url})
        for name in ('relay', 'agent'):
            environment.setdefault(name, []).append(
                {'name': 'PEASO_AI_REUSE_IDLE_SECONDS', 'value': str(REUSE_IDLE_SECONDS)})
    started = ecs.run_task(cluster=config['cluster'], taskDefinition=definition['taskDefinitionArn'],
        launchType='FARGATE', platformVersion='1.4.0', count=1,
        networkConfiguration={'awsvpcConfiguration': {'subnets': config['subnets'],
            'securityGroups': config['security_groups'], 'assignPublicIp': 'ENABLED'}},
        overrides={'containerOverrides': [{'name': name, 'environment': values}
                                          for name, values in environment.items()]},
        clientToken=ident, startedBy='cspm-ai-' + ident[:24], enableExecuteCommand=False)
    tasks = started.get('tasks', [])
    if len(tasks) != 1:
        raise RuntimeError('ai_task_launch_failed')
    return tasks[0]['taskArn']

def _cleanup(ecs, s3, config, task, keys):
    # Also stop on caller errors/cancellation; tasks carry their own watchdog
    # if the analyzer is killed before it can execute this cleanup.
    if task:
        try:
            ecs.stop_task(cluster=config['cluster'], task=task, reason='AI invocation ended')
        except Exception:
            pass
    try:
        s3.delete_objects(Bucket=config['bucket'], Delete={'Objects': [{'Key': k} for k in keys.values()], 'Quiet': True})
    except Exception:
        pass  # Bucket lifecycle provides backstop cleanup after parent death.

def _signing_lifetime(s3):
    """Seconds left on temporary signing credentials, or None when not expiring.

    A presigned URL stops working when its session credential expires, and S3
    then answers 403 like a not-yet-written object. Never retain a task whose
    next-invocation URL could expire before its idle window ends.
    """
    try:
        credentials = s3._request_signer._credentials
        expiry = getattr(credentials, '_expiry_time', None)
    except AttributeError:
        return None
    if expiry is None:
        return None
    import datetime
    return (expiry - datetime.datetime.now(datetime.timezone.utc)).total_seconds()

def _read_object(s3, bucket, key, *, missing_ok=False):
    """Return an exact transport object, or None when ``missing_ok`` and absent."""
    try:
        body = s3.get_object(Bucket=bucket, Key=key)['Body']
    except Exception as error:
        code = str(((getattr(error, 'response', None) or {}).get('Error') or {}).get('Code', ''))
        if missing_ok and code in {'NoSuchKey', '404', 'NotFound', 'AccessDenied', '403'}:
            return None
        raise
    try:
        raw = body.read(MAX_OUTPUT + 1)
    finally:
        body.close()
    if len(raw) > MAX_OUTPUT:
        raise ValueError('agent_output_too_large')
    return raw

def _reusable(reuse, task_binding):
    """Validate a retained-task descriptor before any credential is written for it."""
    import hmac
    if (not isinstance(reuse, dict) or reuse.get('version') != 1 or not isinstance(task_binding, str)
            or not isinstance(reuse.get('binding'), str)
            or not hmac.compare_digest(reuse['binding'], task_binding)
            or not isinstance(reuse.get('ident'), str) or not re.fullmatch(r'[a-f0-9]{32}', reuse['ident'])
            or not isinstance(reuse.get('task'), str)
            or not re.fullmatch(r'arn:aws[a-z-]*:ecs:[a-z0-9-]+:[0-9]{12}:task/[A-Za-z0-9_-]+/[a-f0-9]{32}', reuse['task'])
            or not isinstance(reuse.get('ready_until'), (int, float))
            or time.time() + REUSE_MARGIN >= reuse['ready_until']):
        raise TaskReuseError('ai_task_not_reusable')
    return reuse

def release(reuse, *, ecs=None, s3=None):
    """Stop a retained task that no invocation will take, without waiting idle."""
    if not isinstance(reuse, dict) or not isinstance(reuse.get('task'), str) or not isinstance(reuse.get('ident'), str):
        return
    if not re.fullmatch(r'[a-f0-9]{32}', reuse['ident']):
        return
    try:
        config = configuration()
        ecs, s3 = _clients(ecs, s3)
    except Exception:
        return  # The task still exits by itself after its short idle window.
    _cleanup(ecs, s3, config, reuse['task'], _keys(reuse['ident'], 2))

def invoke(stage, root, token, timeout, *, prepare=None, ecs=None, s3=None,
           clock=time.monotonic, sleep=time.sleep, task_binding=None, retain=None, reuse=None):
    """Run one stage in a role-free task.

    ``retain`` (a dict) asks a fresh task to stay up, for at most
    REUSE_IDLE_SECONDS after its result, so the same scan's next stage can run
    in it; on success ``retain['task']`` receives the task descriptor. ``reuse``
    sends this invocation to such a retained task. Every invocation still gets
    its own credential validation, relay configuration, input, output and
    deadline. TaskReuseError means the retained task never took the invocation.
    """
    if stage not in STAGES or not 0 < timeout <= 1800 or (retain is not None or reuse is not None) and not task_binding:
        raise ValueError('invalid_agent_invocation')
    deadline = clock() + timeout
    from .providers import validate_before_launch
    token = validate_before_launch(token)
    config = configuration()
    ecs, s3 = _clients(ecs, s3)
    task = None
    if reuse is not None:
        reuse = _reusable(reuse, task_binding)
        ident, sequence, retain = reuse['ident'], 2, None
        response = ecs.describe_tasks(cluster=config['cluster'], tasks=[reuse['task']])
        rows = response.get('tasks', [])
        agent = next((c for c in (rows[0].get('containers', []) if rows else []) if c.get('name') == 'agent'), {})
        if (len(rows) != 1 or response.get('failures') or rows[0].get('lastStatus') not in _LIVE_TASK_STATES
                or rows[0].get('desiredStatus', 'RUNNING') != 'RUNNING' or agent.get('lastStatus') == 'STOPPED'):
            raise TaskReuseError('ai_task_not_reusable')
    else:
        definition = ecs.describe_task_definition(taskDefinition=config['task_definition'])['taskDefinition']
        validate_task(definition)
        ident, sequence = uuid.uuid4().hex, 1
    keys = _keys(ident, sequence)
    retained = False
    next_url = None
    if retain is not None:
        lifetime = _signing_lifetime(s3)
        next_lifetime = min(3600, int(timeout) + 30 + REUSE_IDLE_SECONDS + 2 * REUSE_MARGIN)
        if lifetime is None or lifetime > next_lifetime + REUSE_MARGIN:
            next_url = s3.generate_presigned_url('get_object', Params={
                'Bucket': config['bucket'], 'Key': _keys(ident, 2)['relay.json']}, ExpiresIn=next_lifetime)
    try:
        def upload_input():
            data = pack_workspace(root)
            s3.put_object(Bucket=config['bucket'], Key=keys['input.tgz'], Body=data, ServerSideEncryption='AES256')

        if prepare is None:
            upload_input()
        lifetime = min(3600, max(60, int(timeout) + 30))
        def url(operation, name):
            return s3.generate_presigned_url(operation, Params={'Bucket': config['bucket'], 'Key': keys[name]}, ExpiresIn=lifetime)
        from .providers import auth_document
        authentication = auth_document(token)
        relay = {'version': 1, 'stage': stage, 'token': authentication.pop('access_token'),
                 'ai_configuration': authentication, 'input_url': url('get_object', 'input.tgz'),
                 'output_url': url('put_object', 'result.json'), 'timeout': max(1, int(deadline - clock())),
                 'expires_at': time.time() + max(1, deadline - clock() - 15)}
        if task_binding:
            relay.update(sequence=sequence, binding=task_binding)
        if sequence > 1:
            relay['accepted_url'] = url('put_object', 'accepted.json')
        s3.put_object(Bucket=config['bucket'], Key=keys['relay.json'], Body=json.dumps(relay).encode(), ServerSideEncryption='AES256')
        if clock() >= deadline:
            raise TimeoutError('agent_deadline')
        if reuse is not None:
            task = reuse['task']
            accept_by = clock() + REUSE_ACCEPT_SECONDS
        else:
            task = _run_task(ecs, config, definition, ident, url('get_object', 'relay.json'),
                             task_binding=task_binding, next_url=next_url)
        if prepare is not None:
            # Image pull and task startup overlap local context construction.
            # The relay waits for this exact input object before exposing it.
            prepare()
            upload_input()
        accepted = reuse is None
        if not accepted:
            accept_by = max(accept_by, clock() + 5)
        polled = time.time()
        while clock() < deadline:
            checked = time.time()
            response = ecs.describe_tasks(cluster=config['cluster'], tasks=[task])
            rows = response.get('tasks', [])
            if len(rows) != 1 or response.get('failures'):
                if not accepted:
                    raise TaskReuseError('ai_task_not_reusable')
                raise RuntimeError('ai_task_status_unavailable')
            if not accepted:
                try:
                    accepted = _read_object(s3, config['bucket'], keys['accepted.json'], missing_ok=True) is not None
                except Exception:
                    accepted = False
            agent = next((c for c in rows[0].get('containers', []) if c.get('name') == 'agent'), {})
            agent_stopped = agent.get('lastStatus') == 'STOPPED' and agent.get('exitCode') is not None
            if rows[0].get('lastStatus') == 'STOPPED' or agent_stopped:
                if not accepted:
                    # The retained task stopped or rejected this invocation.
                    raise TaskReuseError('ai_task_not_reusable')
                if agent.get('exitCode') is None and rows[0].get('stopCode') == 'TaskFailedToStart':
                    raise TaskStartupError('ai_task_startup_failed')
                if agent.get('exitCode') == 78:
                    from .providers import launch_error
                    raise launch_error(token)
                if agent.get('exitCode') != 0:
                    raise RuntimeError('agent_failed')
                return json.loads(_read_object(s3, config['bucket'], keys['result.json']))
            if not accepted and clock() >= accept_by:
                raise TaskReuseError('ai_task_not_reusable')
            if next_url is not None:
                # A retained agent stays up after storing its validated result.
                try:
                    raw = _read_object(s3, config['bucket'], keys['result.json'], missing_ok=True)
                except ValueError:
                    raise
                except Exception:
                    raw = None  # A transient read error only delays this poll.
                if raw is not None:
                    data = json.loads(raw)
                    # The relay starts its idle window only after this object
                    # exists, so the previous poll bounds that window's start.
                    retain['task'] = {'version': 1, 'task': task, 'ident': ident, 'binding': task_binding,
                                      'ready_until': polled + REUSE_IDLE_SECONDS}
                    retained = True
                    return data
            polled = checked
            sleep(min(2, max(0, deadline - clock())))
        raise TimeoutError('agent_deadline')
    finally:
        _cleanup(ecs, s3, config, None if retained else task, keys)
