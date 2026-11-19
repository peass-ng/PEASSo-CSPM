"""Unregistered optional static package indicators, not Kingfisher equivalence."""
import re
from .facts import Unavailable, get
from peaso import oci_index_20261021 as oci_index
from .aws_configuration_secret_review_20261019 import _member
from peaso.collectors.aws_package_content_indicators import (SCHEMA, EMPTY_ECR_SCHEMA, CATEGORIES, COVERAGE_FIELDS, LAMBDA_IMAGE_OPERATION, NOTE_LIMIT,
                                                             _arn, _digest, _path, image_member_path, parse_ecr_image_uri)

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
    def __init__(self, reason, files=None):
        super().__init__(reason)
        self.files = files or {}


# Marker coverage list -> (evidence key, fields each row carries besides File/LayerDigest/ChildManifestDigest).
_COVERAGE = {'SkippedFiles': ('skipped_third_party_files', {'Reason': str}),
             'UncoveredFiles': ('uncovered_files', {'Cause': str}),
             'PublicClientIdentifiers': ('public_client_identifiers',
                                         {'Kind': str, 'Reason': str, 'Value': str, 'Detectors': list})}


def _typed(value, kind):
    # Evaluation reads sealed snapshots, whose lists are read-only list views.
    return isinstance(value, list) if kind is list else type(value) is kind


def _coverage(indicator, layered, children):
    """Evidence lists naming skipped, uncovered and public-identifier files, validated."""
    files = {}
    for field in COVERAGE_FIELDS:
        if field not in indicator:
            continue
        rows = _field(indicator, field, list)
        key, extra = _COVERAGE[field]
        if not 0 < len(rows) <= NOTE_LIMIT:
            raise Unavailable('coverage list bound')
        for row in rows:
            allowed = {'File', *extra} | ({'LayerDigest'} if layered else set()) | ({'ChildManifestDigest'} if children else set())
            if (not isinstance(row, dict) or not {'File', *extra} <= set(row) <= allowed
                    or not isinstance(row['File'], str) or not 0 < len(row['File']) <= 256
                    or any(not _typed(row[name], kind) or not row[name] for name, kind in extra.items())
                    or 'LayerDigest' in row and not _digest(row['LayerDigest'])
                    or 'ChildManifestDigest' in row and row['ChildManifestDigest'] not in children):
                raise Unavailable('invalid coverage entry')
            if field == 'UncoveredFiles' and not re.fullmatch(r'[a-z_]+', row['Cause']):
                raise Unavailable('invalid coverage entry')
        files[key] = rows
    return files


def _safe_code(value):
    if isinstance(value, str) and re.fullmatch(r'[a-z_]+(?:: [a-z_]+(?:, [a-z_]+)*)?', value) and len(value) <= 300:
        return value
    return None


def _incomplete(reason, base):
    return reason == base or (isinstance(reason, str) and reason.startswith(base + ': ') and _safe_code(reason) == reason)


def _index_children(graph, digest, complete):
    """Child manifest digests of the selected multi-platform index, as the collector bound them."""
    if (not isinstance(graph, dict) or set(graph) != {'parent_digest', 'media_type', 'children', 'complete', 'parent_binding_stable'}
            or graph['parent_digest'] != digest or graph['media_type'] not in oci_index.INDEX_TYPES
            or type(graph['complete']) is not bool or type(graph['parent_binding_stable']) is not bool
            or complete and not (graph['complete'] and graph['parent_binding_stable'])
            or not isinstance(graph['children'], list) or not 0 < len(graph['children']) <= oci_index.MAX_CHILDREN):
        raise Unavailable('invalid image index graph')
    children = set()
    for child in graph['children']:
        if (not isinstance(child, dict) or not _digest(child.get('digest')) or child['digest'] == digest
                or child['digest'] in children):
            raise Unavailable('invalid image index child')
        children.add(child['digest'])
    return children

def evaluate(kind, item, index):
    try:
        field, _, label, operation = SURFACES[kind]
        image = None
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
        if kind == 'ecr_repository' and isinstance(source, dict) and source.get('collection_status') == 'empty':
            proof = _field(source, 'EmptyImageInventory', dict)
            if (set(source) != {'collection_status', 'EmptyImageInventory'}
                    or set(proof) != {'Schema', 'ResourceId', 'AccountId', 'Region', 'RepositoryName',
                                      'SourceOperation', 'NativeResponseComplete', 'ImageCount'}
                    or native != 'repository/' + get(item, 'repositoryName', str)
                    or get(item, 'registryId', str) != account
                    or _field(proof, 'Schema', str) != EMPTY_ECR_SCHEMA
                    or _field(proof, 'ResourceId', str) != identity
                    or _field(proof, 'AccountId', str) != account
                    or _field(proof, 'Region', str) != region
                    or _field(proof, 'RepositoryName', str) != item['repositoryName']
                    or _field(proof, 'SourceOperation', str) != 'ecr:describe_images'
                    or _field(proof, 'NativeResponseComplete', bool) is not True
                    or _field(proof, 'ImageCount', int) != 0):
                raise Unavailable('empty ECR inventory binding unavailable')
            return 'EMPTY', {'observed': 'Complete native image inventory found no images in this ECR repository; no image content was inspected.',
                             'reason': 'no_images_in_repository', 'repository_arn': identity,
                             'source_operation': 'ecr:describe_images', 'image_count': 0}
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
            if 'ImageUri' in source:
                # A container-image function: its exact resolved ECR digest was scanned.
                image = parse_ecr_image_uri(get(source, 'ImageUri', str))
                if image['ImageUri'] != source['ImageUri'] or get(source, 'ImageDigest', str) != image['ImageDigest']:
                    raise Unavailable('function image mismatch')
                operation, label = LAMBDA_IMAGE_OPERATION, 'Lambda container image'
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
        # A multi-platform repository image also carries its verified index graph.
        graph = 'IndexGraph' in indicator and kind == 'ecr_repository'
        if (set(indicator) - ({'IndexGraph'} if graph else set()) - set(COVERAGE_FIELDS) != expected or _field(indicator, 'Schema', str) != SCHEMA or _field(indicator, 'ResourceId', str) != identity
                or _field(indicator, 'AccountId', str) != account or _field(indicator, 'Region', str) != region
                or _field(indicator, 'SourceOperation', str) != operation): raise Unavailable('projection provenance absent')
        complete = _field(indicator, 'NativeResponseComplete', bool)
        layered = kind == 'ecr_repository' or image is not None
        base = 'image_content_incomplete' if layered else 'package_content_incomplete'
        if indicator['collection_status'] != ('collected' if complete else 'partial') or not (
                indicator['Reason'] is None if complete else _incomplete(indicator['Reason'], base)):
            raise Unavailable('contradictory completeness')
        children = _index_children(indicator['IndexGraph'], digest, complete) if graph else None
        files = _coverage(indicator, layered, children)
        refs = _field(indicator, 'References', list)
        if len(refs) > 5000: raise Unavailable('observation limit')
        for ref in refs:
            if not isinstance(ref, dict) or set(ref) - {'Leaks'} - ({'ChildManifestDigest'} if image is not None or graph else set()) != (
                    {'File', 'Categories', 'LayerDigest'} if layered else {'File', 'Categories'}):
                raise Unavailable('invalid reference')
            if 'ChildManifestDigest' in ref and not _digest(ref['ChildManifestDigest']): raise Unavailable('invalid image reference')
            if graph and ref.get('ChildManifestDigest') not in children: raise Unavailable('invalid image reference')
            # Image members keep their real names (``Foo$1.class``, ``a:b``); ZIP members are restricted.
            try:
                safe = (image_member_path if layered else _path)(get(ref, 'File', str))
            except ValueError:
                raise Unavailable('unsafe reference path') from None
            if safe != ref['File']: raise Unavailable('unsafe reference path')
            cats = get(ref, 'Categories', list)
            if not cats or any(not isinstance(c, str) or c not in CATEGORIES for c in cats) or len(set(cats)) != len(cats):
                raise Unavailable('invalid categories')
            if layered and not _digest(ref['LayerDigest']): raise Unavailable('invalid layer reference')
        present = _field(indicator, 'HighConfidenceSecretPresent', bool)
        if present != bool(refs): raise Unavailable('contradictory presence')
        if not complete and not present: raise _Reason(indicator['Reason'], files)
        evidence = {
            'observed': label + (': selected secret indicators observed.' if present else ': no selected indicators observed in the complete bounded source.'),
            'resource_id': identity, 'references': refs,
            'secret_leaks': [dict(leak, locations=[dict(loc, **({'layer': ref['LayerDigest']} if 'LayerDigest' in ref else {})) for loc in leak['locations']]) for ref in refs for leak in ref.get('Leaks', [])],
            'coverage': 'Offline Kingfisher and TruffleHog plus supplemental patterns; bounded content only, no execution or credential validation.',
            'source_complete': complete, **files}
        if image is not None:
            evidence.update(image_uri=image['ImageUri'], image_digest=image['ImageDigest'])
        return ('FAIL' if present else 'PASS'), evidence
    except _Reason as reason:
        uncovered = reason.files.get('uncovered_files', [])
        observed = 'Complete, matching optional package indicator evidence is unavailable.'
        if uncovered:
            observed += ' Not scanned: ' + '; '.join(row['File'] + ' (' + row['Cause'] + ')' for row in uncovered[:10]) + (
                ' and %d more.' % (len(uncovered) - 10) if len(uncovered) > 10 else '.')
        return 'UNKNOWN', {'observed': observed, 'reason': str(reason), **reason.files}
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
  'Own-account exact listed function version ZIP, at most 8 MiB compressed. Container-image functions are scanned through the exact resolved ECR image digest with the scanner credentials and the ECR image bounds; an unreadable, foreign-denied, deleted or non-ECR image is UNKNOWN. CodeSha256 and CodeSize must match the downloaded package; configuration and code locations never enter shared caching.',
  'Remove embedded credentials from the Lambda deployment ZIP, rotate confirmed exposed values, and redeploy using managed references.'),
 ('lambda_layer_version', 'layer_content', 'awslambda', 'awslambda_layer_no_secrets_in_content',
  '6981f74363ad419de07818aba6538a508311c86d093072503fb4c8d1ba165936',
  'Every listed own-account layer version is eligible, unlike upstream attached-layer enumeration. The exact layer ARN/version and CodeSha256 bind its at-most-8-MiB ZIP. Foreign and inaccessible versions are UNKNOWN.',
  'Publish a reviewed Lambda layer without embedded credentials, replace affected function attachments, and rotate confirmed exposed credentials.'),
 ('ecr_repository', 'image_layers', 'ecr', 'ecr_repository_image_no_secrets',
  '0bf55a8808f33f5a2091c8d685e1fb65395b1d5df49733190a9770910817fe99',
  'Complete DescribeImages inventory selects one uniquely latest pushed digest. Single-platform OCI/Docker schema-2 manifests and every child of a multi-platform index are supported: inspect config Env/history and every regular tar/gzip layer file, including deleted-file layers. Binary files are scanned through their printable strings (strings -n 8); a symlink has no content of its own, so it never makes coverage incomplete. Every file is scanned, but hits in unmodified files whose bytes match the image dpkg md5sums or apk checksums, in package-manager metadata, in binaries under vendored dependency trees (node_modules, site-packages, dist-packages, vendor, .cargo/registry) and keyword-only hits in upstream documentation and license files are third-party distribution content and are not reported. No platform is sampled; older images are outside scope. Digest integrity is checked transiently. Layers stream through private temporary files under compressed and expanded image size bounds and at most 512 MiB of scanned file content per image; a large file is scanned in bounded windows, and a file beyond a bound leaves coverage incomplete and is named in the evidence. A runtime file over 64 MiB that an official base image installs from its upstream release archive (the node binary from nodejs.org, the Temurin JDK from Adoptium), in the layer whose recorded build step downloads it, is third-party distribution content: it is not read and the evidence lists it as skipped. A public-by-design browser key (an Amplitude browser API key assigned to the SDK apiKey setting in browser-delivered JavaScript) is not reported as a secret; the evidence lists it with the reason.',
  'Rebuild and republish the ECR image without literal credentials in environment, build history or filesystem layers, and rotate confirmed exposed values.'),
]
DECLARATIONS, ADMISSION_DATA = [], {'schema_version': 1, 'checks': []}
for _kind, _function, _service, _upstream, _sha, _limitation, _remediation in DETAILS:
    _label = SURFACES[_kind][2]
    _id = 'aws.review.' + _kind + '.package_content_secret_indicators'
    _description = {
        'description': 'Optional ' + _label + ' static secret indicators. ' + _limitation +
            ' Disabled unless content_secret_scans is strictly true. Files stay in memory; no archive extraction or code execution. ZIP links, traversal, conflicting duplicates, encryption, unsupported compression, truncation and bounds yield UNKNOWN. Kingfisher SDK 1.4.0 and TruffleHog 3.92.5 inspect each bounded file without credential validation. Supplemental static indicators are retained. Identical secret values are merged across engines and locations using a collection-local keyed fingerprint; raw matches are discarded. A missing or failed engine prevents a complete negative verdict.',
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
