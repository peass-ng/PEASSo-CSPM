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
    with tarfile.open(fileobj=output, mode='w:gz', format=tarfile.USTAR_FORMAT, compresslevel=1) as archive:
        for path in sorted(Path(root).iterdir()):
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


def invoke(stage, root, token, timeout, *, ecs=None, s3=None, clock=time.monotonic, sleep=time.sleep):
    if stage not in STAGES or not 0 < timeout <= 1800:
        raise ValueError('invalid_agent_invocation')
    deadline = clock() + timeout
    from .providers import validate_before_launch
    token = validate_before_launch(token)
    config = configuration()
    import boto3
    from botocore.config import Config
    sdk = Config(connect_timeout=5, read_timeout=10, retries={'max_attempts': 1}, signature_version='v4')
    ecs = ecs or boto3.client('ecs', config=sdk)
    s3 = s3 or boto3.client('s3', config=sdk.merge(Config(signature_version='s3v4')))
    definition = ecs.describe_task_definition(taskDefinition=config['task_definition'])['taskDefinition']
    validate_task(definition)
    ident = uuid.uuid4().hex
    prefix = 'invocations/' + ident + '/'
    keys = {name: prefix + name for name in ('input.tgz', 'relay.json', 'result.json')}
    task = None
    try:
        data = pack_workspace(root)
        s3.put_object(Bucket=config['bucket'], Key=keys['input.tgz'], Body=data, ServerSideEncryption='AES256')
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
        started = ecs.run_task(cluster=config['cluster'], taskDefinition=definition['taskDefinitionArn'],
            launchType='FARGATE', platformVersion='1.4.0', count=1,
            networkConfiguration={'awsvpcConfiguration': {'subnets': config['subnets'],
                'securityGroups': config['security_groups'], 'assignPublicIp': 'ENABLED'}},
            overrides={'containerOverrides': [{'name': 'relay', 'environment': [
                {'name': 'PEASO_AI_BOOTSTRAP_URL', 'value': url('get_object', 'relay.json')}]}]},
            clientToken=ident, startedBy='cspm-ai-' + ident[:24], enableExecuteCommand=False)
        tasks = started.get('tasks', [])
        if len(tasks) != 1:
            raise RuntimeError('ai_task_launch_failed')
        task = tasks[0]['taskArn']
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
