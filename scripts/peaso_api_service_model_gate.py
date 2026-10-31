"""Package only the SDK models of services the API source creates clients for."""
import ast
import json
from pathlib import Path

REQUIRED_BOTOCORE_VERSION = '1.43.38'
API_SERVICES = frozenset({
    'accessanalyzer', 'cloudtrail', 'cognito-identity', 'cognito-idp',
    'dynamodb', 'ec2', 'ecs', 'iam', 'organizations', 's3',
    'secretsmanager', 'sso', 'sso-oidc', 'stepfunctions', 'sts',
})
API_SOURCE_DIRECTORIES = ('peaso/server', 'peaso/auth', 'peaso/storage', 'peaso/ai')
API_SOURCE_FILES = ('peaso/worker.py', 'peaso/scheduling.py', 'peaso/gcp_platform.py')
CLIENT_METHODS = frozenset({'client', 'resource', 'create_client', 'create_resource'})


def review_source(root):
    """Read-only inventory of the API's direct SDK client calls."""
    try:
        calls = direct_clients(root)
        direct_error = None
    except RuntimeError as exc:
        calls = []
        direct_error = str(exc)
    return {'direct_client_calls': calls,
            'direct_client_error': direct_error, 'reviewed_services': sorted(API_SERVICES)}


def direct_clients(root):
    root = Path(root)
    paths = [p for directory in API_SOURCE_DIRECTORIES for p in (root / directory).rglob('*.py')]
    paths += [root / name for name in API_SOURCE_FILES]
    calls = []
    for path in sorted(paths):
        tree = ast.parse(path.read_bytes(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or node.func.attr not in CLIENT_METHODS:
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
                raise RuntimeError(f'dynamic API SDK client or resource call: {path.relative_to(root)}:{node.lineno}')
            service = node.args[0].value
            if service not in API_SERVICES:
                raise RuntimeError(f'unlisted API SDK service: {path.relative_to(root)}:{node.lineno}:{service}')
            calls.append((path.relative_to(root).as_posix(), node.lineno, service))
    # API imports this selected credential factory from collectors.aws. It must
    # remain free of SDK client creation.
    aws_tree = ast.parse((root / 'peaso/collectors/aws.py').read_bytes())
    session = next((node for node in aws_tree.body if isinstance(node, ast.FunctionDef) and node.name == '_session'), None)
    if session is None or any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                              and node.func.attr in CLIENT_METHODS for node in ast.walk(session)):
        raise RuntimeError('AWS credential session factory changed SDK client behavior')
    return calls


def prune_api_service_models(root):
    root = Path(root)
    calls = direct_clients(root)
    metadata = root / f'botocore-{REQUIRED_BOTOCORE_VERSION}.dist-info/METADATA'
    if not metadata.is_file() or f'Version: {REQUIRED_BOTOCORE_VERSION}\n' not in metadata.read_text():
        raise RuntimeError('API botocore version differs from reviewed model inventory')
    data = root / 'botocore/data'
    if root.is_symlink() or (root / 'botocore').is_symlink() or data.is_symlink():
        raise RuntimeError('API SDK model tree contains a symlink')
    if not data.is_dir():
        raise RuntimeError('API botocore model tree missing')
    services = {p.name for p in data.iterdir() if p.is_dir()}
    if not API_SERVICES <= services:
        raise RuntimeError('Reviewed API SDK model tree incomplete')
    for path in data.rglob('*'):
        if path.is_symlink():
            raise RuntimeError('API SDK model tree contains a symlink')
    removed = []
    for service in sorted(services - API_SERVICES):
        directory = data / service
        for p in directory.rglob('*'):
            if p.is_file():
                removed.append(p.relative_to(root).as_posix())
        import shutil
        shutil.rmtree(directory)
    return {'allowed_services': sorted(API_SERVICES), 'direct_client_calls': calls,
            'removed_models': len(removed), 'removed_model_paths': removed}

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3 or sys.argv[1] not in {'--review-source', '--prune-target'}:
        raise SystemExit('usage: peaso_api_service_model_gate.py --review-source SOURCE_ROOT | --prune-target API_STAGING_ROOT')
    if sys.argv[1] == '--review-source':
        result = review_source(sys.argv[2])
    else:
        result = prune_api_service_models(sys.argv[2])
        result.pop('removed_model_paths')
    print(json.dumps(result, sort_keys=True))
