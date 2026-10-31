"""Unregistered optional static package indicators, not Kingfisher equivalence."""
import re
from .facts import Unavailable, get
from .aws_configuration_secret_review_20261019 import _member
from peaso.collectors.aws_package_content_indicators import SCHEMA, CATEGORIES, _arn, _digest, _path

SURFACES = {
    'lambda_function': ('FunctionArn', 'lambda_function', 'Lambda ZIP code', 'lambda:get_function'),
    'lambda_layer_version': ('LayerVersionArn', 'lambda_layer', 'Lambda layer ZIP', 'lambda:get_layer_version'),
    'ecr_repository': ('repositoryArn', 'ecr_image', 'Latest ECR image', 'ecr:batch_get_image'),
}


def _field(item, key, expected):
    if not isinstance(item, dict) or key not in item:
        raise Unavailable('indicator field absent')
    value = item[key]
    if (not isinstance(value, expected) if expected in (dict, list) else type(value) is not expected):
        raise Unavailable('indicator field malformed')
    return value


class _Reason(Unavailable):
    """An UNKNOWN whose concrete cause the collector already named."""


def _safe_code(value):
    if isinstance(value, str) and re.fullmatch(r'[a-z_]+(?:: [a-z_]+(?:, [a-z_]+)*)?', value) and len(value) <= 300:
        return value
    return None


def _incomplete(reason, base):
    return reason == base or (isinstance(reason, str) and reason.startswith(base + ': ') and _safe_code(reason) == reason)


def evaluate(kind, item, index):
    try:
        field, _, label, operation = SURFACES[kind]
        context = get(index, 'context', dict)
        account, scope = get(context, 'Account', str), get(context, 'scope', str)
        if get(context, 'provider', str) != 'aws' or not re.fullmatch(r'[0-9]{12}', account) or not scope.startswith(account + '/'):
            raise Unavailable('AWS scope absent')
        region = scope.split('/', 1)[1]
        identity = get(item, field, str)
        own, native = _arn(identity, 'ecr' if kind == 'ecr_repository' else 'lambda', region)
        if own != account: raise Unavailable('foreign account')
        _member(item, index, kind, field, scope)
        source = item.get('PackageContentSource')
        if isinstance(source, dict) and source.get('collection_status') != 'collected':
            # The collector names why content was not read (image package,
            # size bound, opt-out, download failure, ...); keep that cause.
            error = source.get('error')
            code = _safe_code(error.get('code')) if isinstance(error, dict) else None
            raise _Reason(code or 'package_content_' + (_safe_code(source.get('collection_status')) or 'unavailable'))
        source = get(item, 'PackageContentSource', dict)
        if get(source, 'collection_status', str) != 'collected': raise Unavailable('content unavailable')
        if kind == 'lambda_function':
            if native != 'function:' + get(item, 'FunctionName', str) or get(source, 'SourceVersion', str) != get(item, 'Version', str):
                raise Unavailable('function version mismatch')
            if not re.fullmatch(r'(?:\$LATEST|[1-9][0-9]*)', item['Version']): raise Unavailable('invalid version')
        elif kind == 'lambda_layer_version':
            number = get(item, 'Version', int)
            if (number < 1 or native != 'layer:' + get(item, 'LayerName', str) + ':' + str(number)
                    or item.get('LayerArn') != identity.rsplit(':', 1)[0] or get(source, 'SourceVersion', int) != number):
                raise Unavailable('layer version mismatch')
        else:
            if native != 'repository/' + get(item, 'repositoryName', str) or get(item, 'registryId', str) != account:
                raise Unavailable('repository mismatch')
            digest = get(source, 'ImageDigest', str)
            if not _digest(digest) or get(source, 'SelectedImageDigest', str) != digest: raise Unavailable('selected image mismatch')
            identity += '@' + digest
        indicator = source.get('PackageSecretIndicators')
        if not isinstance(indicator, dict): raise Unavailable('indicator absent')
        expected = {'Schema', 'ResourceId', 'AccountId', 'Region', 'SourceOperation', 'NativeResponseComplete',
                    'collection_status', 'References', 'HighConfidenceSecretPresent', 'Reason'}
        if (set(indicator) != expected or _field(indicator, 'Schema', str) != SCHEMA or _field(indicator, 'ResourceId', str) != identity
                or _field(indicator, 'AccountId', str) != account or _field(indicator, 'Region', str) != region
                or _field(indicator, 'SourceOperation', str) != operation): raise Unavailable('projection provenance absent')
        complete = _field(indicator, 'NativeResponseComplete', bool)
        base = 'image_content_incomplete' if kind == 'ecr_repository' else 'package_content_incomplete'
        if indicator['collection_status'] != ('collected' if complete else 'partial') or not (
                indicator['Reason'] is None if complete else _incomplete(indicator['Reason'], base)):
            raise Unavailable('contradictory completeness')
        refs = _field(indicator, 'References', list)
        if len(refs) > 5000: raise Unavailable('observation limit')
        for ref in refs:
            if not isinstance(ref, dict) or set(ref) - {'Leaks'} != ({'File', 'Categories', 'LayerDigest'} if kind == 'ecr_repository' else {'File', 'Categories'}):
                raise Unavailable('invalid reference')
            if _path(get(ref, 'File', str)) != ref['File']: raise Unavailable('unsafe reference path')
            cats = get(ref, 'Categories', list)
            if not cats or any(not isinstance(c, str) or c not in CATEGORIES for c in cats) or len(set(cats)) != len(cats):
                raise Unavailable('invalid categories')
            if kind == 'ecr_repository' and not _digest(ref['LayerDigest']): raise Unavailable('invalid layer reference')
        present = _field(indicator, 'HighConfidenceSecretPresent', bool)
        if present != bool(refs): raise Unavailable('contradictory presence')
        if not complete and not present: raise _Reason(indicator['Reason'])
        return ('FAIL' if present else 'PASS'), {
            'observed': label + (': selected secret indicators observed.' if present else ': no selected indicators observed in the complete bounded source.'),
            'resource_id': identity, 'references': refs,
            'secret_leaks': [dict(leak, locations=[dict(loc, **({'layer': ref['LayerDigest']} if 'LayerDigest' in ref else {})) for loc in leak['locations']]) for ref in refs for leak in ref.get('Leaks', [])],
            'coverage': 'Offline Kingfisher and TruffleHog plus supplemental patterns; bounded content only, no execution or credential validation.',
            'source_complete': complete}
    except _Reason as reason:
        return 'UNKNOWN', {'observed': 'Complete, matching optional package indicator evidence is unavailable.',
                           'reason': str(reason)}
    except Unavailable as exc:
        return 'UNKNOWN', {'observed': 'Complete, matching optional package indicator evidence is unavailable.',
                           'reason': 'package_indicator_evidence_invalid: ' + str(exc)[:200]}
    except (ValueError, TypeError, KeyError, AttributeError):
        return 'UNKNOWN', {'observed': 'Complete, matching optional package indicator evidence is unavailable.',
                           'reason': 'package_indicator_evidence_malformed'}


def function_code(item, index=None): return evaluate('lambda_function', item, index or {})
def layer_content(item, index=None): return evaluate('lambda_layer_version', item, index or {})
def image_layers(item, index=None): return evaluate('ecr_repository', item, index or {})


REVISION = '1783527c1147f584f30b60f2d7ccc8a53b4a63b7'
DETAILS = [
 ('lambda_function', 'function_code', 'awslambda', 'awslambda_function_no_secrets_in_code',
  '04100a02f56417b63d50e3f1d1e7ba648f897c3980f558b81a8681b0f09e10b8',
  'Own-account exact listed function version ZIP only, at most 8 MiB compressed. Image functions are UNKNOWN. CodeSha256 and CodeSize must match the downloaded package; configuration and code locations never enter shared caching.',
  'Remove embedded credentials from the Lambda deployment ZIP, rotate confirmed exposed values, and redeploy using managed references.'),
 ('lambda_layer_version', 'layer_content', 'awslambda', 'awslambda_layer_no_secrets_in_content',
  '6981f74363ad419de07818aba6538a508311c86d093072503fb4c8d1ba165936',
  'Every listed own-account layer version is eligible, unlike upstream attached-layer enumeration. The exact layer ARN/version and CodeSha256 bind its at-most-8-MiB ZIP. Foreign and inaccessible versions are UNKNOWN.',
  'Publish a reviewed Lambda layer without embedded credentials, replace affected function attachments, and rotate confirmed exposed credentials.'),
 ('ecr_repository', 'image_layers', 'ecr', 'ecr_repository_image_no_secrets',
  '0bf55a8808f33f5a2091c8d685e1fb65395b1d5df49733190a9770910817fe99',
  'Complete DescribeImages inventory selects one uniquely latest pushed digest. Only a single-platform OCI/Docker schema-2 manifest is supported: inspect config Env/history and every regular tar/gzip layer file, including deleted-file layers. Multiarch indexes are UNKNOWN rather than sampling a platform; older images are outside scope. Digest integrity is checked transiently. Limits: 16 MiB actual per blob, 32 MiB actual per image, 64 MiB expanded and 5000 members across config/layers.',
  'Rebuild and republish the ECR image without literal credentials in environment, build history or filesystem layers, and rotate confirmed exposed values.'),
]
DECLARATIONS, ADMISSION_DATA = [], {'schema_version': 1, 'checks': []}
for _kind, _function, _service, _upstream, _sha, _limitation, _remediation in DETAILS:
    _label = SURFACES[_kind][2]
    _id = 'aws.review.' + _kind + '.package_content_secret_indicators'
    _description = {
        'description': 'Optional ' + _label + ' static secret indicators. ' + _limitation +
            ' Disabled unless content_secret_scans is strictly true. Files stay in memory; no archive extraction or code execution. ZIP/tar links, traversal, conflicting duplicates, encryption, unsupported compression, truncation and bounds yield UNKNOWN. Kingfisher SDK 1.4.0 and TruffleHog 3.92.5 inspect each bounded file without credential validation. Supplemental static indicators are retained. Identical secret values are merged across engines and locations using a collection-local keyed fingerprint; raw matches are discarded. A missing or failed engine prevents a complete negative verdict.',
        'evaluated': [SURFACES[_kind][0], 'PackageContentSource exact source identity/version and safe indicators', 'complete same-scope native inventory'],
        'pass_when': 'Complete bound ' + _label + ' content has no selected high-confidence indicator.',
        'fail_when': 'An inspected bound ' + _label + ' file or config has a selected high-confidence indicator; a partial positive also fails.',
        'not_applicable_when': 'No automatic exclusion. Optout, missing authority, malformed, denied, foreign, unsupported or partial negative evidence is UNKNOWN.'}
    DECLARATIONS.append({'id': _id, 'provider': 'aws', 'kind': _kind, 'evaluator': _function, 'category': 'hardening', 'severity': 'high',
        'control': 'configuration_secrets', 'target': 'resource', 'dependencies': [_kind],
        'title': _label + ' has no observed selected secret indicators', 'remediation': _remediation})
    ADMISSION_DATA['checks'].append({'spec': {'id': _id, 'provider': 'aws', 'resource_kind': _kind,
        'data_source': ', '.join(_description['evaluated']), 'predicate': _description['pass_when'] + ' ' + _description['fail_when'],
        'severity': 'high', 'category': 'hardening', 'title': DECLARATIONS[-1]['title'], 'description': _description['description'],
        'remediation_hint': _remediation}, 'description': _description,
        'sources': [{'url': 'https://github.com/prowler-cloud/prowler/blob/' + REVISION + '/prowler/providers/aws/services/' + _service + '/' + _upstream + '/' + _upstream + '.py', 'sha256': _sha}],
        'requirements': [], 'function': 'peaso.checks.aws_package_content_review_20261019:' + _function,
        'review_notes': 'Corrected partial relationship to ' + _upstream + '; dual offline scanners; no exhaustive content or broad compliance equivalence claimed. ' + _limitation})


def _fixture(kind, present):
    from peaso.collectors.aws_package_content_indicators import marker
    account, region = '123456789012', 'us-east-1'
    arn = lambda service, resource: f'arn:aws:{service}:{region}:{account}:{resource}'
    if kind == 'lambda_function': item = {'FunctionArn': arn('lambda', 'function:example'), 'FunctionName': 'example', 'Version': '$LATEST'}
    elif kind == 'lambda_layer_version': item = {'LayerVersionArn': arn('lambda', 'layer:example:1'), 'LayerArn': arn('lambda', 'layer:example'), 'LayerName': 'example', 'Version': 1}
    else: item = {'repositoryArn': arn('ecr', 'repository/example'), 'repositoryName': 'example', 'registryId': account}
    identity = item[SURFACES[kind][0]]
    refs = [{'File': 'config.py', 'Categories': ['password_assignment']}] if present else []
    source = {'collection_status': 'collected'}
    if kind == 'ecr_repository':
        digest = 'sha256:' + '1' * 64
        source.update(ImageDigest=digest, SelectedImageDigest=digest)
        identity += '@' + digest
        if refs: refs[0]['LayerDigest'] = 'sha256:' + '2' * 64
    else: source['SourceVersion'] = item['Version']
    source['PackageSecretIndicators'] = marker(identity, account, region, SURFACES[kind][3], refs)
    item['PackageContentSource'] = source
    scope = account + '/' + region
    index = {'context': {'provider': 'aws', 'Account': account, 'scope': scope},
             'collections': {kind: [{'type': kind, 'scope': scope, 'status': 'collected', 'items': [item]}]},
             kind: [{'type': kind, 'scope': scope, 'data': item}]}
    return item, index


RUNTIME_CASES = {}
for _declaration in DECLARATIONS:
    _good, _gi = _fixture(_declaration['kind'], False)
    _bad, _bi = _fixture(_declaration['kind'], True)
    RUNTIME_CASES[_declaration['id']] = {'pass': _good, 'pass_index': _gi, 'index': _gi,
        'fail': _bad, 'fail_index': _bi, 'missing': {}, 'malformed': None}
