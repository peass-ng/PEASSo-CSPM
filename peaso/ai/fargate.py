"""One role-free Fargate task per agent; exact-object ephemeral transport."""
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
                # Immutable images prove sources at build time. This single
                # public constant grants no identity or additional capability.
                or container.get('environment') not in (None, [], [
                    {'name': 'PEASO_SOURCE_ATTESTATION', 'value': 'trusted'}])
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


# A prelaunched task waits, with no model access or input, for one later
# invocation. Its relay polls only for that invocation's exact bootstrap object.
MAX_PRELAUNCH_WAIT = 1800
# Minimum remaining relay bootstrap wait for a prelaunched task to be used.
PRELAUNCH_MARGIN = 60
_LIVE_TASK_STATES = {'PROVISIONING', 'PENDING', 'ACTIVATING', 'RUNNING'}


def _clients(ecs, s3):
    import boto3
    from botocore.config import Config
    sdk = Config(connect_timeout=5, read_timeout=10, retries={'max_attempts': 1}, signature_version='v4')
    ecs = ecs or boto3.client('ecs', config=sdk)
    s3 = s3 or boto3.client('s3', config=sdk.merge(Config(signature_version='s3v4')))
    return ecs, s3


def _keys(ident):
    prefix = 'invocations/' + ident + '/'
    return {name: prefix + name for name in ('input.tgz', 'relay.json', 'result.json')}


def _run_task(ecs, config, definition, ident, bootstrap_url, wait=None):
    environment = {'relay': [{'name': 'PEASO_AI_BOOTSTRAP_URL', 'value': bootstrap_url}]}
    if wait is not None:
        # Both containers wait for the later bootstrap; neither receives it here.
        for name in ('relay', 'agent'):
            environment.setdefault(name, []).append(
                {'name': 'PEASO_AI_BOOTSTRAP_WAIT_SECONDS', 'value': str(int(wait))})
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


class PrelaunchedTask:
    """A role-free task started before its invocation is known.

    It holds no model credential, relay configuration or input: its relay only
    waits for one exact presigned bootstrap object that ``invoke`` writes when
    the stage is actually admitted. ``invoke`` then computes the invocation's
    deadline, model credential and transport exactly as for a fresh launch, so
    the model's time budget starts when its input is ready, not at launch.
    """

    def __init__(self, ecs, s3, config, definition, ident, task, ready_until, clock):
        self.ecs, self.s3, self.config, self.definition = ecs, s3, config, definition
        self.ident, self.keys, self.task = ident, _keys(ident), task
        self.ready_until, self.clock = ready_until, clock
        self.taken = False

    def usable(self):
        """True only while the relay still waits and ECS reports a live task."""
        if self.clock() + PRELAUNCH_MARGIN >= self.ready_until:
            return False
        try:
            response = self.ecs.describe_tasks(cluster=self.config['cluster'], tasks=[self.task])
        except Exception:
            return False
        rows = response.get('tasks', [])
        return (len(rows) == 1 and not response.get('failures')
                and rows[0].get('lastStatus') in _LIVE_TASK_STATES
                and rows[0].get('desiredStatus', 'RUNNING') == 'RUNNING')

    def close(self):
        """Stop an unused task; an invocation that took it owns its cleanup."""
        if self.taken:
            return
        self.taken = True
        _cleanup(self.ecs, self.s3, self.config, self.task, self.keys)


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
    then answers 403 like a not-yet-written object. Never let a waiting relay
    depend on a URL that could expire before it is used.
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


def prelaunch(wait, *, ecs=None, s3=None, clock=time.monotonic):
    """Start one idle role-free task whose relay waits up to ``wait`` seconds."""
    if not 0 < wait <= MAX_PRELAUNCH_WAIT:
        raise ValueError('invalid_agent_prelaunch')
    config = configuration()
    ecs, s3 = _clients(ecs, s3)
    lifetime = _signing_lifetime(s3)
    if lifetime is not None:
        wait = min(wait, int(lifetime) - 2 * PRELAUNCH_MARGIN)
        if wait <= 2 * PRELAUNCH_MARGIN:
            raise RuntimeError('ai_prelaunch_signing_lifetime')
    definition = ecs.describe_task_definition(taskDefinition=config['task_definition'])['taskDefinition']
    validate_task(definition)
    ident = uuid.uuid4().hex
    keys = _keys(ident)
    ready_until = clock() + wait
    bootstrap = s3.generate_presigned_url('get_object', Params={'Bucket': config['bucket'], 'Key': keys['relay.json']},
                                          ExpiresIn=min(3600, int(wait) + PRELAUNCH_MARGIN))
    task = None
    try:
        task = _run_task(ecs, config, definition, ident, bootstrap, wait=wait)
    except BaseException:
        _cleanup(ecs, s3, config, task, keys)
        raise
    return PrelaunchedTask(ecs, s3, config, definition, ident, task, ready_until, clock)


class Prelaunch:
    """Start a prelaunched task in the background and hand it out at most once.

    Launch failures are not errors: the invocation then starts its own task
    exactly as before. ``close`` stops a task that was never handed out,
    including one whose launch completes after closing.
    """

    def __init__(self, wait, *, launcher=None):
        import threading
        self._lock = threading.Lock()
        self._task = None
        self._closed = False
        launcher = launcher or prelaunch
        def run():
            try:
                task = launcher(wait)
            except Exception:
                return
            with self._lock:
                if not self._closed:
                    self._task = task
                    return
            task.close()
        self._thread = threading.Thread(target=run, name='peaso-ai-prelaunch', daemon=True)
        self._thread.start()

    def claim(self, timeout=10):
        """Return the started task once, or None; never wait for long."""
        self._thread.join(timeout)
        with self._lock:
            task, self._task = self._task, None
            if self._thread.is_alive():
                self._closed = True
        return task

    def close(self):
        with self._lock:
            self._closed = True
            task, self._task = self._task, None
        if task is not None:
            task.close()


def invoke(stage, root, token, timeout, *, prepare=None, ecs=None, s3=None,
           clock=time.monotonic, sleep=time.sleep, prelaunched=None):
    if stage not in STAGES or not 0 < timeout <= 1800:
        if prelaunched is not None:
            prelaunched.close()
        raise ValueError('invalid_agent_invocation')
    deadline = clock() + timeout
    from .providers import validate_before_launch
    try:
        token = validate_before_launch(token)
    except BaseException:
        if prelaunched is not None:
            prelaunched.close()
        raise
    if prelaunched is not None and not prelaunched.usable():
        prelaunched.close()
        prelaunched = None
    if prelaunched is not None:
        prelaunched.taken = True
        ecs, s3, config, definition = (prelaunched.ecs, prelaunched.s3,
                                       prelaunched.config, prelaunched.definition)
        ident, keys, task = prelaunched.ident, prelaunched.keys, prelaunched.task
    else:
        config = configuration()
        ecs, s3 = _clients(ecs, s3)
        definition = ecs.describe_task_definition(taskDefinition=config['task_definition'])['taskDefinition']
        validate_task(definition)
        ident = uuid.uuid4().hex
        keys = _keys(ident)
        task = None
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
        s3.put_object(Bucket=config['bucket'], Key=keys['relay.json'], Body=json.dumps(relay).encode(), ServerSideEncryption='AES256')
        if clock() >= deadline:
            raise TimeoutError('agent_deadline')
        if task is None:
            task = _run_task(ecs, config, definition, ident, url('get_object', 'relay.json'))
        if prepare is not None:
            # Image pull and task startup overlap local context construction.
            # The relay waits for this exact input object before exposing it.
            prepare()
            upload_input()
        while clock() < deadline:
            response = ecs.describe_tasks(cluster=config['cluster'], tasks=[task])
            rows = response.get('tasks', [])
            if len(rows) != 1 or response.get('failures'):
                raise RuntimeError('ai_task_status_unavailable')
            agent = next((c for c in rows[0].get('containers', []) if c.get('name') == 'agent'), {})
            agent_stopped = agent.get('lastStatus') == 'STOPPED' and agent.get('exitCode') is not None
            if rows[0].get('lastStatus') == 'STOPPED' or agent_stopped:
                if agent.get('exitCode') is None and rows[0].get('stopCode') == 'TaskFailedToStart':
                    raise TaskStartupError('ai_task_startup_failed')
                if agent.get('exitCode') == 78:
                    from .providers import launch_error
                    raise launch_error(token)
                if agent.get('exitCode') != 0:
                    raise RuntimeError('agent_failed')
                body = s3.get_object(Bucket=config['bucket'], Key=keys['result.json'])['Body']
                try:
                    raw = body.read(MAX_OUTPUT + 1)
                finally:
                    body.close()
                if len(raw) > MAX_OUTPUT:
                    raise ValueError('agent_output_too_large')
                return json.loads(raw)
            sleep(min(2, max(0, deadline - clock())))
        raise TimeoutError('agent_deadline')
    finally:
        _cleanup(ecs, s3, config, task, keys)
