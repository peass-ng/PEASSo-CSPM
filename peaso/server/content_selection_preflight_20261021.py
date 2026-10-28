"""Pure selector preflight copied from native sources; no collector imports or I/O."""

import base64
import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from types import SimpleNamespace
from urllib.parse import urlsplit

def _fingerprint(value):
    # Native HMAC is used only for duplicate equality in these selector nodes.
    return hashlib.sha256(value.encode()).hexdigest()

peers = SimpleNamespace()

def _make_association():
    MAX_IMAGE_LENGTH = 1024

    _LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z")

    _DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")

    _TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")

    _REPOSITORY = re.compile(
        r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
        r"(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*\Z"
    )

    _HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?\Z")

    class _Unresolved(ValueError):
        def __init__(self, reason, status="unknown"):
            self.reason, self.status = reason, status

    @dataclass(frozen=True)
    class ImageReference:
        registry: str
        repository: str
        tag: str | None
        digest: str | None
        explicit_registry: bool

        @property
        def repository_key(self):
            return self.registry + "/" + self.repository

        @property
        def immutable_reference(self):
            return self.repository_key + "@" + self.digest if self.digest else None

    def _text(value, maximum=512):
        return (type(value) is str and 0 < len(value) <= maximum
                and value.isascii() and all(32 < ord(c) < 127 for c in value))

    def parse_image_reference(value):
        """Conservative SHA256 Docker/OCI name subset; never resolve tags or DNS.

        Only the documented index.docker.io -> docker.io alias and Docker shorthand
        are normalized. Mirrors, custom runtime defaults, IPv6 and other algorithms
        need separate native evidence/support. These failures are not bad posture.
        """
        if (not _text(value, MAX_IMAGE_LENGTH) or any(c in value for c in "%?#\\")
                or "://" in value or value.count("@") > 1):
            raise _Unresolved("malformed_image_reference", "invalid")
        name, at, digest = value.partition("@")
        if at and not _DIGEST.fullmatch(digest):
            raise _Unresolved("unsupported_or_malformed_digest")
        digest = digest if at else None
        head, slash, tail = name.rpartition("/")
        leaf = tail if slash else name
        leaf, colon, tag = leaf.partition(":")
        if colon and not _TAG.fullmatch(tag):
            raise _Unresolved("malformed_image_tag", "invalid")
        name = head + "/" + leaf if slash else leaf
        first, sep, rest = name.partition("/")
        explicit = bool(sep and ("." in first or ":" in first or first == "localhost"))
        host, repository = (first.lower(), rest) if explicit else ("docker.io", name)
        if host == "index.docker.io":
            host = "docker.io"
        if (not _HOST.fullmatch(host) or ".." in host or host.endswith(".")
                or (":" in host and not 1 <= int(host.rsplit(":", 1)[1]) <= 65535)):
            raise _Unresolved("unsupported_or_malformed_registry", "invalid")
        if any(not _LABEL.fullmatch(part) for part in host.split(":", 1)[0].split(".")):
            raise _Unresolved("unsupported_or_malformed_registry", "invalid")
        if host == "docker.io" and "/" not in repository:
            repository = "library/" + repository
        if len(host + "/" + repository) > 255 or not _REPOSITORY.fullmatch(repository):
            raise _Unresolved("malformed_image_repository", "invalid")
        return ImageReference(host, repository, tag if colon else (None if digest else "latest"),
                              digest, explicit)
    return SimpleNamespace(parse_image_reference=parse_image_reference)


def _make_registry(association):
    SECRET_CHECK = 'k8s.review.selected_registry_image_secret_indicators'

    VULN_CHECK = 'k8s.review.selected_registry_image_high_vulnerabilities'

    OPTION = 'selected_k8s_registry_images'

    ALLOWLIST = 'selected_registry_hosts'

    MAX_TARGETS = 2

    HOST = re.compile(r'[a-z0-9](?:[a-z0-9.-]{1,251}[a-z0-9])\Z')

    LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')

    POD = re.compile(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z')

    TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')

    FIELDS = {'cluster_id', 'namespace', 'pod', 'uid', 'resource_version', 'container_type', 'container_name', 'image'}

    AUTH_FIELD = 'registry_auth'

    class Incomplete(ValueError):
        """Stable local reason; never includes URL, response, token or content."""

    def _host(value):
        if (type(value) is not str or not HOST.fullmatch(value) or '.' not in value
                or '..' in value or value.endswith(('.local', '.internal', '.localhost', '.test', '.invalid'))
                or value.startswith(('localhost.', 'metadata.', '169.254.'))):
            raise Incomplete('unsupported_registry_host')
        try:
            ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            raise Incomplete('ip_literal_registry_unsupported')
        if any(not LABEL.fullmatch(part) for part in value.split('.')):
            raise Incomplete('unsupported_registry_host')
        return value

    def selected_targets(options, scopes, named=()):
        """Validate all supplied selectors and host grants before any credentials or I/O."""
        if type(options) is not dict or ('content_secret_scans' in options and type(options['content_secret_scans']) is not bool) or ('image_vulnerability_scans' in options and type(options['image_vulnerability_scans']) is not bool):
            raise Incomplete('invalid_selection')
        if any(key in options for key in ('trivy_db_cache', 'trivy_cli')):
            raise Incomplete('trivy_runtime_configuration_is_not_a_request_option')
        if any(key in options for key in (AUTH_FIELD, 'registry_auth_document', 'image_pull_secret')):
            raise Incomplete('registry_credentials_must_be_separate')
        active = ((options.get('content_secret_scans') is True and SECRET_CHECK in named)
                  or (options.get('image_vulnerability_scans') is True and VULN_CHECK in named))
        if OPTION not in options and ALLOWLIST not in options and not active:
            return []
        targets, hosts = options.get(OPTION), options.get(ALLOWLIST)
        if (type(scopes) is not list or not 1 <= len(scopes) <= 4 or any(type(s) is not str or not LABEL.fullmatch(s) for s in scopes)
                or type(targets) is not list or not 1 <= len(targets) <= MAX_TARGETS
                or type(hosts) is not list or not 1 <= len(hosts) <= 4
                or any(type(h) is not str for h in hosts) or len(set(hosts)) != len(hosts)):
            raise Incomplete('invalid_selection')
        for host in hosts:
            _host(host)
        seen = set()
        for target in targets:
            if type(target) is not dict or set(target) != FIELDS:
                raise Incomplete('invalid_selection')
            cluster, namespace, pod = (target[k] for k in ('cluster_id', 'namespace', 'pod'))
            if (type(cluster) is not str or not 1 <= len(cluster) <= 512 or not cluster.isascii()
                    or any(ord(c) < 33 or ord(c) > 126 for c in cluster)
                    or type(namespace) is not str or namespace not in scopes or not LABEL.fullmatch(namespace)
                    or type(pod) is not str or not POD.fullmatch(pod)
                    or any(not LABEL.fullmatch(part) for part in pod.split('.'))
                    or any(type(target[k]) is not str or not TOKEN.fullmatch(target[k]) for k in ('uid', 'resource_version'))
                    or target['container_type'] not in ('regular', 'init', 'ephemeral')
                    or type(target['container_name']) is not str or not LABEL.fullmatch(target['container_name'])):
                raise Incomplete('invalid_selection')
            try:
                image = association.parse_image_reference(target['image'])
            except Exception:
                raise Incomplete('invalid_selection') from None
            if (image.digest is None or not image.explicit_registry or image.tag is not None
                    or image.immutable_reference != target['image'] or _host(image.registry) not in hosts):
                raise Incomplete('invalid_selection')
            key = (cluster, namespace, pod, target['uid'], target['container_type'], target['container_name'])
            if key in seen:
                raise Incomplete('duplicate_selection')
            seen.add(key)
        return deepcopy(targets)

    def registry_credentials(auth, targets, allowed_hosts):
        """Validate explicit encrypted connector auth against selected digest repositories."""
        if type(auth) is not dict:
            raise Incomplete('invalid_registry_auth')
        entries = auth.get(AUTH_FIELD, [])
        if type(entries) is not list or len(entries) > MAX_TARGETS:
            raise Incomplete('invalid_registry_auth')
        selected = set()
        for target in targets:
            image = association.parse_image_reference(target['image'])
            selected.add((image.registry, image.repository))
        credentials = {}
        for entry in entries:
            if type(entry) is not dict or entry.get('method') not in ('basic', 'bearer'):
                raise Incomplete('invalid_registry_auth')
            method = entry['method']
            expected = {'host', 'repository', 'method', 'token'} if method == 'bearer' else {'host', 'repository', 'method', 'username', 'password'}
            if set(entry) != expected:
                raise Incomplete('invalid_registry_auth')
            host, repository = entry['host'], entry['repository']
            if (type(host) is not str or _host(host) != host or host not in allowed_hosts
                    or type(repository) is not str or (host, repository) not in selected
                    or (host, repository) in credentials):
                raise Incomplete('foreign_registry_auth')
            if method == 'bearer':
                token = entry['token']
                if (type(token) is not str or not 1 <= len(token) <= 8192 or not token.isascii()
                        or any(ord(c) < 33 or ord(c) > 126 for c in token)):
                    raise Incomplete('invalid_registry_auth')
                header = 'Bearer ' + token
            else:
                username, password = entry['username'], entry['password']
                if (type(username) is not str or not 1 <= len(username) <= 512 or ':' in username
                        or type(password) is not str or not 1 <= len(password) <= 8192
                        or not username.isascii() or not password.isascii()
                        or any(ord(c) < 33 or ord(c) > 126 for c in username + password)):
                    raise Incomplete('invalid_registry_auth')
                header = 'Basic ' + base64.b64encode((username + ':' + password).encode()).decode()
            credentials[(host, repository)] = (method, header)
        return credentials
    def identity(target):
        return 'k8s-registry-image:' + hashlib.sha256(json.dumps(target, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    return SimpleNamespace(selected_targets=selected_targets, registry_credentials=registry_credentials, ALLOWLIST=ALLOWLIST, OPTION=OPTION, SECRET_CHECK=SECRET_CHECK, identity=identity)


def _make_flux():
    CHECK = 'k8s.review.selected_flux_artifact_secret_indicators'

    OPTION = 'selected_k8s_flux_artifacts'

    MAX_TARGETS = 2

    MAX_BYTES = 12 * 1024 * 1024

    LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')

    TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')

    DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')

    SEGMENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,255}\Z')

    FIELDS = {'cluster_id', 'kind', 'namespace', 'name', 'uid', 'resource_version', 'generation',
              'artifact_digest', 'artifact_revision', 'artifact_path', 'artifact_size',
              'service_namespace', 'service_uid', 'service_resource_version', 'service_port_name'}

    class Incomplete(ValueError):
        """Fixed code only; no URLs, response text or detected values."""

    def _path(value, kind, namespace, name):
        if (type(value) is not str or len(value) > 1024 or not value.startswith(kind.lower() + '/' + namespace + '/' + name + '/')
                or any(not SEGMENT.fullmatch(part) or part in ('.', '..') for part in value.split('/'))
                or not value.endswith(('.tar.gz', '.tgz', '.zip'))):
            raise Incomplete('invalid_artifact_path')
        return value

    def selected_targets(options, scopes, named=()):
        if type(options) is not dict or ('content_secret_scans' in options and type(options['content_secret_scans']) is not bool):
            raise Incomplete('invalid_selection')
        if OPTION not in options and not (options.get('content_secret_scans') is True and CHECK in named):
            return []
        rows = options.get(OPTION)
        if (type(rows) is not list or not 1 <= len(rows) <= MAX_TARGETS or type(scopes) is not list
                or not 1 <= len(scopes) <= 8 or any(type(s) is not str or not LABEL.fullmatch(s) for s in scopes)):
            raise Incomplete('invalid_selection')
        seen = set()
        for row in rows:
            if type(row) is not dict or set(row) != FIELDS:
                raise Incomplete('invalid_selection')
            if (type(row['cluster_id']) is not str or not 1 <= len(row['cluster_id']) <= 512
                    or not row['cluster_id'].isascii() or any(ord(c) < 33 or ord(c) > 126 for c in row['cluster_id'])
                    or row['kind'] not in ('GitRepository', 'HelmChart')
                    or any(type(row[f]) is not str or not LABEL.fullmatch(row[f]) for f in
                           ('namespace', 'name', 'service_namespace', 'service_port_name'))
                    or row['namespace'] not in scopes or row['service_namespace'] not in scopes
                    or any(type(row[f]) is not str or not TOKEN.fullmatch(row[f]) for f in
                           ('uid', 'resource_version', 'service_uid', 'service_resource_version'))
                    or type(row['generation']) is not int or not 1 <= row['generation'] <= 10**15
                    or type(row['artifact_size']) is not int or not 0 < row['artifact_size'] <= MAX_BYTES
                    or type(row['artifact_digest']) is not str or not DIGEST.fullmatch(row['artifact_digest'])
                    or type(row['artifact_revision']) is not str or not 1 <= len(row['artifact_revision']) <= 256
                    or not row['artifact_revision'].isascii()
                    or any(ord(c) < 33 or ord(c) > 126 for c in row['artifact_revision'])):
                raise Incomplete('invalid_selection')
            _path(row['artifact_path'], row['kind'], row['namespace'], row['name'])
            if row['kind'] == 'GitRepository' and not row['artifact_path'].endswith('.tar.gz'):
                raise Incomplete('unsupported_artifact_format')
            if row['kind'] == 'HelmChart' and not row['artifact_path'].endswith('.tgz'):
                raise Incomplete('unsupported_artifact_format')
            key = (row['cluster_id'], row['kind'], row['namespace'], row['name'])
            if key in seen:
                raise Incomplete('duplicate_selection')
            seen.add(key)
        return deepcopy(rows)
    return SimpleNamespace(selected_targets=selected_targets)


def _make_declaration():
    class Incomplete(ValueError):
        """A selected declaration is malformed or outside its declared scopes."""

    GUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'

    SCOPE = re.compile('/subscriptions/' + GUID + r'\Z', re.I)

    SEG = r'[A-Za-z0-9_][A-Za-z0-9_.()-]{0,89}'

    BASE = r'(/subscriptions/' + GUID + r')/resourceGroups/' + SEG + '/providers/'

    PROFILES = {
        'app_configuration': {'kind': 'azure_app_configuration_selected_values',
            'check': 'azure.review.app_configuration.selected_value_secret_indicators',
            'option': 'selected_azure_app_configuration_values', 'title': 'Selected App Configuration literal values have no detected secrets',
            'service': 'Microsoft.AppConfiguration'},
        'data_factory': {'kind': 'azure_data_factory_selected_declarations',
            'check': 'azure.review.data_factory.selected_declaration_secret_indicators',
            'option': 'selected_azure_data_factory_declarations', 'title': 'Selected Data Factory inline declarations have no detected secrets',
            'service': 'Microsoft.DataFactory'},
        'synapse': {'kind': 'azure_synapse_selected_pipelines',
            'check': 'azure.review.synapse.selected_pipeline_secret_indicators',
            'option': 'selected_azure_synapse_pipelines', 'title': 'Selected Synapse pipeline inline declarations have no detected secrets',
            'service': 'Microsoft.Synapse'},
    }

    MAX_TARGETS = 8

    def enabled(options, profile):
        return options.get('content_secret_scans') is True and isinstance(options.get('_content_secret_scan_kinds'), list) and PROFILES[profile]['kind'] in options['_content_secret_scan_kinds']

    def parse(profile, target):
        if not isinstance(target, dict) or set(target) != ({'resource_id', 'key', 'label'} if profile == 'app_configuration' else {'resource_id'}):
            raise Incomplete('invalid_selection')
        rid = target['resource_id']
        patterns = {
            'app_configuration': r'Microsoft\.AppConfiguration/configurationStores/([A-Za-z0-9][A-Za-z0-9_-]{3,48}[A-Za-z0-9])',
            'data_factory': r'Microsoft\.DataFactory/factories/([A-Za-z0-9][A-Za-z0-9-]{1,61}[A-Za-z0-9])/(pipelines|dataflows)/(' + SEG + ')',
            'synapse': r'Microsoft\.Synapse/workspaces/([a-z0-9][a-z0-9-]{1,48}[a-z0-9])/pipelines/(' + SEG + ')',
        }
        match = re.fullmatch(BASE + patterns[profile], rid, re.I) if isinstance(rid, str) and len(rid) <= 1024 else None
        if not match or any(s in ('.', '..') for s in rid.split('/')):
            raise Incomplete('invalid_selection')
        if profile == 'app_configuration':
            for field in ('key', 'label'):
                value = target[field]
                if field == 'label' and value is None:
                    continue
                if (not isinstance(value, str) or not 1 <= len(value.encode()) <= 512
                        or any(ord(c) < 32 or ord(c) == 127 for c in value) or any(c in value for c in '*\\,')):
                    raise Incomplete('invalid_selection')
        typ = {'app_configuration': 'Microsoft.AppConfiguration/configurationStores',
            'data_factory': 'Microsoft.DataFactory/factories/' + (match[3] if profile == 'data_factory' else ''),
            'synapse': 'Microsoft.Synapse/workspaces/pipelines'}[profile]
        return match[1], rid, typ

    def selected_targets(options, scopes, profile=None):
        """Pure root hook/hosted validator; no credential discovery or endpoint input."""
        if (not isinstance(options, dict) or 'content_secret_scans' in options and type(options['content_secret_scans']) is not bool):
            raise Incomplete('invalid_selection')
        profiles = [profile] if profile is not None else list(PROFILES)
        result = {}; count = 0
        for name in profiles:
            option = PROFILES[name]['option']
            if option not in options and not enabled(options, name):
                result[name] = []; continue
            targets = options.get(option)
            if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 8
                    or any(not isinstance(s, str) or not SCOPE.fullmatch(s) for s in scopes)
                    or len({s.casefold() for s in scopes}) != len(scopes)
                    or not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS):
                raise Incomplete('invalid_selection')
            seen = set()
            for target in targets:
                scope, rid, _ = parse(name, target)
                key = (rid.casefold(), target.get('key'), target.get('label'))
                if scope.casefold() not in {s.casefold() for s in scopes} or key in seen:
                    raise Incomplete('invalid_selection')
                seen.add(key)
            result[name] = deepcopy(targets); count += len(targets)
        if count > MAX_TARGETS:
            raise Incomplete('invalid_selection')
        return result[profile] if profile is not None else result

    def identity(profile, target):
        # ARM id is case-insensitive; AppConfig key and label are case-sensitive.
        return PROFILES[profile]['kind'] + ':' + _fingerprint(json.dumps({**target, 'resource_id': target['resource_id'].casefold()}, sort_keys=True))
    return SimpleNamespace(GUID=GUID, SCOPE=SCOPE, SEG=SEG, selected_targets=selected_targets)


def _make_storage():
    KIND='azure_storage_selected_source'

    OPTION='selected_azure_storage_sources'

    MAX_TARGETS=4

    GUID=r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'

    SCOPE=re.compile('/subscriptions/'+GUID+r'\Z',re.I)

    ACCOUNT=re.compile(r'(/subscriptions/'+GUID+r')/resourceGroups/([A-Za-z0-9_()-][A-Za-z0-9_.()-]{0,88}[A-Za-z0-9_()-]|[A-Za-z0-9_()-])/providers/Microsoft\.Storage/storageAccounts/([a-z0-9]{3,24})\Z',re.I)

    VERSION=re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?Z\Z')

    class Incomplete(ValueError):
        """Stable code only; never native errors, URLs, names, content or credentials."""

    def enabled(options):
        return options.get('content_secret_scans') is True and isinstance(options.get('_content_secret_scan_kinds'),list) and KIND in options['_content_secret_scan_kinds']

    def parse(target):
        if not isinstance(target,dict) or target.get('service') not in ('blob','file'):raise Incomplete('invalid_selection')
        service=target['service'];container='container' if service=='blob' else 'share'
        if set(target)-{'service','resource_id',container,'object','version','format'} or not {'service','resource_id',container,'object','format'}<=set(target):raise Incomplete('invalid_selection')
        rid=target['resource_id'];m=ACCOUNT.fullmatch(rid) if isinstance(rid,str) and len(rid)<=512 else None
        name=target[container];path=target['object'];version=target.get('version')
        if (not m or '/.' in rid or not isinstance(name,str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])',name) or '--' in name
                or not isinstance(path,str) or not 1<=len(path.encode('utf-8'))<=1024
                or not re.fullmatch(r'[A-Za-z0-9_./@+ =()-]+',path) or any(p in ('','.','..') or p.endswith(('.', ' ')) for p in path.split('/'))
                or len(path.split('/'))>32 or 'version' in target and (not isinstance(version,str) or not VERSION.fullmatch(version))
                or target['format'] not in ('text','zip','tar','tar.gz')):raise Incomplete('invalid_selection')
        if service=='file' and any(len(part)>255 for part in path.split('/')):raise Incomplete('invalid_selection')
        try:
            if version is not None:datetime.fromisoformat(version.replace('Z','+00:00'))
        except ValueError:raise Incomplete('invalid_selection') from None
        return service,m[1],rid,m[3].lower(),name,path,version,target['format']

    def selected_targets(options,scopes):
        """Credential-free validator; omitted version means coherent current read."""
        if not isinstance(options,dict) or ('content_secret_scans' in options and type(options['content_secret_scans']) is not bool):raise Incomplete('invalid_selection')
        if OPTION not in options and not enabled(options):return []
        targets=options.get(OPTION)
        if (not isinstance(scopes,list) or not 1<=len(scopes)<=8 or any(not isinstance(s,str) or not SCOPE.fullmatch(s) for s in scopes)
                or len({s.casefold() for s in scopes})!=len(scopes) or not isinstance(targets,list) or not 1<=len(targets)<=MAX_TARGETS):raise Incomplete('invalid_selection')
        seen=set()
        for target in targets:
            service,scope,rid,account,name,path,version,form=parse(target)
            key=(rid.casefold(),service,name,path.casefold() if service=='file' else path,version)
            if scope.casefold() not in {s.casefold() for s in scopes} or key in seen:raise Incomplete('invalid_selection')
            seen.add(key)
        return deepcopy(targets)

    def identity(target):
        native=deepcopy(target);native['resource_id']=native['resource_id'].casefold()
        if native['service']=='file':native['object']=native['object'].casefold()
        return KIND+':'+_fingerprint(json.dumps(native,sort_keys=True,separators=(',',':')))
    return SimpleNamespace(parse=parse, selected_targets=selected_targets)


def _make_ml_asset(GUID, SEG, SCOPE, storage):
    PROFILES={
     'environment':{'kind':'azure_ml_selected_environment_conda','check':'azure.review.machine_learning.selected_environment_conda_secret_indicators','option':'selected_azure_ml_environment_versions','asset':'environments','title':'Selected ML environment text has no detected secrets'},
     'code':{'kind':'azure_ml_selected_code_file','check':'azure.review.machine_learning.selected_code_file_secret_indicators','option':'selected_azure_ml_code_files','asset':'codes','title':'Selected ML code source files have no detected secrets'},
    }

    MAX_TARGETS=4

    ASSET=r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}'

    BASE=r'(/subscriptions/'+GUID+r')/resourceGroups/'+SEG+r'/providers/Microsoft\.MachineLearningServices/workspaces/[A-Za-z0-9][A-Za-z0-9_-]{2,32}'

    def enabled(options,profile):
        return options.get('content_secret_scans')is True and isinstance(options.get('_content_secret_scan_kinds'),list)and PROFILES[profile]['kind']in options['_content_secret_scan_kinds']

    def parse(profile,target):
        allowed=({'resource_id'},{'resource_id','datastore','storage'})if profile=='environment'else({'resource_id','datastore','storage'},{'resource_id','datastore','storage','job_resource_id'})
        if not isinstance(target,dict)or set(target)not in allowed:raise ValueError('invalid_selection')
        rid=target['resource_id'];p=PROFILES[profile]
        match=re.fullmatch('('+BASE+')/'+p['asset']+'/('+ASSET+')/versions/('+ASSET+')',rid,re.I)if isinstance(rid,str)and len(rid)<=1024 else None
        if not match or any(s in('.','..')for s in rid.split('/')):raise ValueError('invalid_selection')
        if 'job_resource_id' in target:
            job=target['job_resource_id']
            j=re.fullmatch(re.escape(match[1])+r'/jobs/('+ASSET+')',job,re.I)if isinstance(job,str)and len(job)<=1024 else None
            if not j or job.rsplit('/',1)[1] in('.','..'):raise ValueError('invalid_selection')
        if 'storage'in target:
            if not isinstance(target['datastore'],str)or not re.fullmatch(ASSET,target['datastore'])or target['datastore']in('.','..'):raise ValueError('invalid_selection')
            service,scope,*_=storage.parse(target['storage'])
            if scope.casefold()!=match[2].casefold()or target['storage']['format']!='text'or(profile=='environment'and service!='blob'):raise ValueError('invalid_selection')
        return match[2],rid,match[1]

    def identity(profile,target):
        # ML container names and versions are case-sensitive native route segments.
        scope,rid,workspace=parse(profile,target)
        native=deepcopy(target);native['resource_id']=workspace.casefold()+rid[len(workspace):]
        if 'job_resource_id'in native:native['job_resource_id']=workspace.casefold()+native['job_resource_id'][len(workspace):]
        if 'storage'in target:
            native['storage']['resource_id']=native['storage']['resource_id'].casefold()
            if native['storage']['service']=='file':native['storage']['object']=native['storage']['object'].casefold()
        return PROFILES[profile]['kind']+':'+_fingerprint(json.dumps(native,sort_keys=True,separators=(',',':')))

    def selected_targets(options,scopes,profile=None):
        if not isinstance(options,dict)or 'content_secret_scans'in options and type(options['content_secret_scans'])is not bool:raise ValueError('invalid_selection')
        result={};count=0
        for name in([profile]if profile else list(PROFILES)):
            option=PROFILES[name]['option']
            if option not in options and not enabled(options,name):result[name]=[];continue
            targets=options.get(option)
            if (not isinstance(scopes,list)or not 1<=len(scopes)<=8 or any(not isinstance(s,str)or not SCOPE.fullmatch(s)for s in scopes)
                    or len({s.casefold()for s in scopes})!=len(scopes)or not isinstance(targets,list)or not 1<=len(targets)<=MAX_TARGETS):raise ValueError('invalid_selection')
            seen=set()
            for target in targets:
                scope,_,_=parse(name,target);ident=identity(name,target)
                if scope.casefold()not in{s.casefold()for s in scopes}or ident in seen:raise ValueError('invalid_selection')
                seen.add(ident)
            result[name]=deepcopy(targets);count+=len(targets)
        if count>MAX_TARGETS:raise ValueError('invalid_selection')
        return result[profile]if profile else result
    return SimpleNamespace(selected_targets=selected_targets)


def _make_databricks(GUID, SEG, SCOPE):
    KIND='azure_databricks_selected_notebook'

    OPTION='selected_azure_databricks_notebooks'

    FILE_OPTION='selected_azure_databricks_files'

    RUN_OPTION='selected_azure_databricks_task_outputs'

    MAX_TARGETS=4

    def enabled(options):
        return options.get('content_secret_scans')is True and isinstance(options.get('_content_secret_scan_kinds'),list)and KIND in options['_content_secret_scan_kinds']

    def parse(target):
        if not isinstance(target,dict)or set(target) not in ({'workspace_resource_id','path'},{'workspace_resource_id','path','object_type'}) or target.get('object_type','NOTEBOOK') not in ('NOTEBOOK','FILE'):raise ValueError('invalid_selection')
        rid=target['workspace_resource_id'];path=target['path']
        match=re.fullmatch(r'(/subscriptions/'+GUID+r')/resourceGroups/'+SEG+r'/providers/Microsoft\.Databricks/workspaces/([A-Za-z0-9_][A-Za-z0-9_.()-]{2,63})',rid,re.I)if isinstance(rid,str)and len(rid)<=1024 else None
        if (not match or any(p in('.','..')for p in rid.split('/'))or not isinstance(path,str)or not 2<=len(path.encode())<=1024
                or not re.fullmatch(r'/[A-Za-z0-9_@+ =()./-]+',path)or len(path.split('/'))>32
                or any(p in('','.','..')or p.endswith(' ')for p in path.split('/')[1:])
                or path.casefold().startswith(('/repos/','/workspace/repos/','/volumes/','/dbfs/'))
                or path.casefold()in('/repos','/workspace/repos','/volumes','/dbfs')):raise ValueError('invalid_selection')
        return match[1],rid,path

    def identity(target):
        if 'task_run_id' in target:
            _,rid,job,parent,task,key,content=parse_job(target)
            return KIND+':'+_fingerprint(json.dumps([rid.casefold(),job,parent,task,key,content]))
        _,rid,path=parse(target)
        return KIND+':'+_fingerprint(rid.casefold()+'\n'+path+('\nFILE' if target.get('object_type')=='FILE' else ''))

    def parse_job(target):
        if not isinstance(target,dict) or set(target)!={'workspace_resource_id','job_id','parent_run_id','task_run_id','task_key','content'}:
            raise ValueError('invalid_selection')
        rid=target['workspace_resource_id']
        match=re.fullmatch(r'(/subscriptions/'+GUID+r')/resourceGroups/'+SEG+r'/providers/Microsoft\.Databricks/workspaces/([A-Za-z0-9_][A-Za-z0-9_.()-]{2,63})',rid,re.I) if isinstance(rid,str) and len(rid)<=1024 else None
        values=[target[k] for k in ('job_id','parent_run_id','task_run_id')]
        key=target['task_key'];content=target['content']
        if (not match or any(p in ('.','..') for p in rid.split('/'))
                or any(type(v)is not int or not 1<=v<=2**63-1 for v in values)
                or values[1]==values[2] or not isinstance(key,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',key)
                or content not in ('notebook_result','task_logs')):raise ValueError('invalid_selection')
        return match[1],rid,*values,key,content

    def target_scope(target):
        return parse_job(target)[0] if 'task_run_id' in target else parse(target)[0]

    def selected_targets(options,scopes):
        if not isinstance(options,dict)or 'content_secret_scans'in options and type(options['content_secret_scans'])is not bool:raise ValueError('invalid_selection')
        if OPTION not in options and FILE_OPTION not in options and RUN_OPTION not in options and not enabled(options):return[]
        notebooks=options.get(OPTION,[]);files=options.get(FILE_OPTION,[]);runs=options.get(RUN_OPTION,[])
        if (OPTION in options and (not isinstance(notebooks,list) or not notebooks)
                or FILE_OPTION in options and (not isinstance(files,list) or not files)
                or RUN_OPTION in options and (not isinstance(runs,list) or not runs)
                or any(not isinstance(t,dict) or set(t)!={'workspace_resource_id','path'} for t in notebooks)
                or any(not isinstance(t,dict) or set(t)!={'workspace_resource_id','path','object_type'} or t['object_type']!='FILE' for t in files)
                or any(not isinstance(t,dict) for t in runs)):
            raise ValueError('invalid_selection')
        targets=notebooks+files+runs
        if (not isinstance(scopes,list)or not 1<=len(scopes)<=8 or any(not isinstance(s,str)or not SCOPE.fullmatch(s)for s in scopes)
                or len({s.casefold()for s in scopes})!=len(scopes)or not isinstance(targets,list)or not 1<=len(targets)<=MAX_TARGETS):raise ValueError('invalid_selection')
        seen=set()
        for target in targets:
            scope=target_scope(target);ident=identity(target)
            if scope.casefold()not in{s.casefold()for s in scopes}or ident in seen:raise ValueError('invalid_selection')
            seen.add(ident)
        return deepcopy(targets)
    return SimpleNamespace(selected_targets=selected_targets)


def _make_synapse(GUID, SEG, SCOPE):
    KIND='azure_synapse_selected_notebook_source'

    OPTION='selected_azure_synapse_notebooks'

    MAX_TARGETS=4

    WORKSPACE=re.compile(r'(/subscriptions/'+GUID+r')/resourceGroups/'+SEG+r'/providers/Microsoft\.Synapse/workspaces/([A-Za-z0-9][A-Za-z0-9-]{0,49})\Z',re.I)

    NAME=re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z')

    def enabled(options):
        return options.get('content_secret_scans')is True and isinstance(options.get('_content_secret_scan_kinds'),list)and KIND in options['_content_secret_scan_kinds']

    def parse(target):
        if not isinstance(target,dict)or set(target)!={'workspace_resource_id','notebook_name'}:raise ValueError('invalid_selection')
        rid=target['workspace_resource_id'];name=target['notebook_name']
        m=WORKSPACE.fullmatch(rid)if isinstance(rid,str)and len(rid)<=1024 else None
        if not m or any(x in('.','..')for x in rid.split('/'))or not isinstance(name,str)or not NAME.fullmatch(name)or name in('.','..'):raise ValueError('invalid_selection')
        return m[1],rid,m[2],name

    def identity(target):
        _,rid,_,name=parse(target)
        # Stable non-secret selected resource identifier; HMAC is reserved for private evidence.
        return KIND+':'+hashlib.sha256((rid.casefold()+'\n'+name).encode()).hexdigest()

    def selected_targets(options,scopes):
        if not isinstance(options,dict)or 'content_secret_scans'in options and type(options['content_secret_scans'])is not bool:raise ValueError('invalid_selection')
        if OPTION not in options and not enabled(options):return []
        targets=options.get(OPTION)
        if (not isinstance(scopes,list)or not 1<=len(scopes)<=8 or any(not isinstance(s,str)or not SCOPE.fullmatch(s)for s in scopes)
                or len({s.casefold()for s in scopes})!=len(scopes)or not isinstance(targets,list)or not 1<=len(targets)<=MAX_TARGETS):raise ValueError('invalid_selection')
        seen=set()
        for target in targets:
            scope,_,_,_=parse(target);ident=identity(target)
            if scope.casefold()not in{s.casefold()for s in scopes}or ident in seen:raise ValueError('invalid_selection')
            seen.add(ident)
        return deepcopy(targets)
    return SimpleNamespace(selected_targets=selected_targets)


def _make_s3():
    KIND = 's3_selected_source_content'

    OPTION = 'selected_aws_s3_sources'

    FORMATS = ('text', 'zip', 'tar', 'tar.gz')

    MAX_TARGETS = 4

    MAX_SELECTED_SCOPES = 8

    SCOPE = re.compile(r'([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)\Z')

    class Incomplete(ValueError):
        pass

    def _codecommit_only(options):
        kinds = options.get('_content_secret_scan_kinds', ())
        targets = options.get('selected_aws_build_deployment_sources')
        return (OPTION not in options and isinstance(kinds, list)
                and 'build_deployment_referenced_source_content' in kinds
                and not {'s3_selected_source_content', 'ecs_selected_environment_file_content',
                         'workload_referenced_source_content'}.intersection(kinds)
                and isinstance(targets, list) and bool(targets)
                and all(isinstance(t, dict) and t.get('profile') == 'codebuild_codecommit_source' for t in targets))

    def enabled(options):
        return (options.get('content_secret_scans') is True and isinstance(options.get('_content_secret_scan_kinds'), list)
                and not _codecommit_only(options)
                and (KIND in options['_content_secret_scan_kinds'] or 'ecs_selected_environment_file_content' in options['_content_secret_scan_kinds']
                    or 'workload_referenced_source_content' in options['_content_secret_scan_kinds']
                    or 'build_deployment_referenced_source_content' in options['_content_secret_scan_kinds']))

    def parse(target):
        if (not isinstance(target, dict) or set(target) - {'scope', 'bucket', 'key', 'version_id', 'format'}
                or not {'scope', 'bucket', 'key', 'format'} <= set(target)
                or not isinstance(target['scope'], str) or not SCOPE.fullmatch(target['scope'])
                or target['format'] not in FORMATS):
            raise Incomplete('invalid_s3_selection')
        account, region = SCOPE.fullmatch(target['scope']).groups()
        if region.startswith(('cn-', 'us-gov-')) or '-iso' in region:
            raise Incomplete('unsupported_partition')
        bucket, key = target['bucket'], target['key']
        if (not isinstance(bucket, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket)
                or '..' in bucket or '.-' in bucket or '-.' in bucket
                or re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}', bucket)
                or bucket.startswith(('xn--', 'sthree-', 'amzn-s3-demo-'))
                or bucket.endswith(('-s3alias', '--ol-s3', '--x-s3', '-x-s3', '--table-s3', '.mrap'))):
            raise Incomplete('unsupported_bucket')
        if (not isinstance(key, str) or not 1 <= len(key.encode('utf-8')) <= 1024
                or any(ord(c) < 32 or ord(c) == 127 for c in key)
                or '\\' in key or key.startswith(('/', 'http:', 'https:', 's3:'))
                or any(p in ('', '.', '..') for p in key.split('/'))):
            raise Incomplete('invalid_object_key')
        version = target.get('version_id')
        if 'version_id' in target and (not isinstance(version, str) or not 1 <= len(version) <= 1024
                or any(ord(c) <= 32 or ord(c) >= 127 for c in version)):
            raise Incomplete('invalid_object_version')
        return account, region

    def selected_targets(options, scopes):
        if not isinstance(options, dict) or ('content_secret_scans' in options and type(options['content_secret_scans']) is not bool):
            raise Incomplete('invalid_s3_selection')
        if OPTION not in options and not enabled(options):
            return []
        targets = options.get(OPTION)
        if (not isinstance(scopes, list) or not scopes
                or any(not isinstance(s, str) or not SCOPE.fullmatch(s) for s in scopes)
                or len(set(scopes)) != len(scopes) or not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS):
            raise Incomplete('invalid_s3_selection')
        seen = set()
        selected_scopes = set()
        for target in targets:
            parse(target)
            # One object/version may not acquire ambiguous competing format declarations.
            locator = target['scope'], target['bucket'], target['key'], target.get('version_id')
            if target['scope'] not in scopes or locator in seen:
                raise Incomplete('invalid_s3_selection')
            seen.add(locator)
            selected_scopes.add(target['scope'])
            if len(selected_scopes) > MAX_SELECTED_SCOPES:
                raise Incomplete('invalid_s3_selection')
        return deepcopy(targets)
    return SimpleNamespace(KIND=KIND, OPTION=OPTION, SCOPE=SCOPE, parse=parse, selected_targets=selected_targets)


def _make_ecs_env(s3, peers):
    KIND = 'ecs_selected_environment_file_content'

    OPTION = 'selected_aws_ecs_environment_files'

    MAX_TARGETS = 4

    def enabled(options):
        return options.get('content_secret_scans') is True and KIND in options.get('_content_secret_scan_kinds', ())

    def selected_targets(options, scopes):
        if OPTION not in options and not enabled(options):
            return []
        targets = options.get(OPTION)
        if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS:
            raise ValueError('invalid_ecs_environment_file_selection')
        if not isinstance(scopes, list) or len(set(scopes)) != len(scopes):
            raise ValueError('invalid_ecs_environment_file_scopes')
        s3_targets = s3.selected_targets(options, scopes)
        seen = set(); seen_sources = set()
        for target in targets:
            if not isinstance(target, dict) or set(target) != {'scope', 'task_definition_arn', 'container', 'environment_file_arn'}:
                raise ValueError('invalid_ecs_environment_file_selection')
            scope = target['scope']; match = s3.SCOPE.fullmatch(scope) if isinstance(scope, str) else None
            if not match or scope not in scopes or scope.startswith(('cn-', 'us-gov-')):
                raise ValueError('invalid_ecs_environment_file_scope')
            account, region = match.groups()
            if region.startswith(('cn-', 'us-gov-')) or '-iso' in region:
                raise ValueError('unsupported_ecs_partition')
            task = target['task_definition_arn']
            if not isinstance(task, str) or not re.fullmatch(r'arn:aws:ecs:' + region + ':' + account + r':task-definition/[A-Za-z0-9_-]{1,255}:[1-9][0-9]{0,9}', task):
                raise ValueError('invalid_ecs_task_revision')
            container = target['container']
            if not isinstance(container, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,255}', container):
                raise ValueError('invalid_ecs_container')
            source = target['environment_file_arn']
            if not isinstance(source, str) or not source.startswith('arn:aws:s3:::'):
                raise ValueError('invalid_ecs_environment_file_arn')
            suffix = source[len('arn:aws:s3:::'):]
            if '/' not in suffix or not suffix.endswith('.env'):
                raise ValueError('invalid_ecs_environment_file_arn')
            bucket, key = suffix.split('/', 1)
            selected = {'scope': scope, 'bucket': bucket, 'key': key, 'format': 'text'}
            s3.parse(selected)
            source_key = json.dumps(selected, sort_keys=True)
            if selected not in s3_targets or (task, container, source) in seen or source_key in seen_sources:
                raise ValueError('ecs_environment_file_requires_exact_selected_s3_source')
            seen.add((task, container, source)); seen_sources.add(source_key)
        if KIND in options.get('_content_secret_scan_kinds', ()) and s3.KIND not in options.get('_content_secret_scan_kinds', ()):
            delegated = [source_target(t) for t in targets]
            if 'workload_referenced_source_content' in options.get('_content_secret_scan_kinds', ()):
                workload_source_target, workload_option = peers.workload_ref.source_target, peers.workload_ref.OPTION
                delegated += [workload_source_target(t) for t in options.get(workload_option, ())]
            if 'build_deployment_referenced_source_content' in options.get('_content_secret_scan_kinds',()):
                build_source_target, build_option = peers.build_ref.source_target, peers.build_ref.OPTION
                delegated += [build_source_target(t) for t in options.get(build_option,())]
            if len(delegated) != len(s3_targets) or {json.dumps(t, sort_keys=True) for t in delegated} != {json.dumps(t, sort_keys=True) for t in s3_targets}:
                raise ValueError('ecs_environment_file_extra_s3_selection')
        return deepcopy(targets)

    def source_target(target):
        bucket, key = target['environment_file_arn'][len('arn:aws:s3:::'):].split('/', 1)
        return {'scope': target['scope'], 'bucket': bucket, 'key': key, 'format': 'text'}
    return SimpleNamespace(OPTION=OPTION, source_target=source_target, selected_targets=selected_targets)


def _make_aws_config():
    KIND = 'configuration_selected_content'

    OPTION = 'selected_aws_configuration_content'

    MAX_TARGETS = 16

    MAX_SELECTED_SCOPES = 8

    SCOPE = re.compile(r'([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)\Z')

    SURFACES = {
     'cloudformation_template': ('cloudformation','get_template','cloudformation','stack/([A-Za-z][A-Za-z0-9-]{0,127})/([A-Za-z0-9-]{1,128})'),
     'codepipeline_configuration': ('codepipeline','get_pipeline','codepipeline','([A-Za-z0-9.@_-]{1,100})'),
     'cloudformation_outputs': ('cloudformation','describe_stacks','cloudformation','stack/([A-Za-z][A-Za-z0-9-]{0,127})/([A-Za-z0-9-]{1,128})'),
     'codebuild_environment': ('codebuild','batch_get_projects','codebuild','project/([A-Za-z0-9][A-Za-z0-9_-]{1,254})'),
     'rest_stage_variables': ('apigateway','get_stage','apigateway','/restapis/([a-z0-9]{1,32})/stages/([A-Za-z0-9_-]{1,128})'),
     'ecs_environment': ('ecs','describe_task_definition','ecs','task-definition/([A-Za-z0-9_-]{1,255}):([1-9][0-9]{0,9})'),
     'amplify_environment': ('amplify','get_app','amplify','apps/([a-z0-9]{1,20})'),
     'batch_environment': ('batch','describe_job_definitions','batch','job-definition/([A-Za-z0-9_-]{1,128}):([1-9][0-9]{0,9})'),
     'beanstalk_options': ('elasticbeanstalk','describe_configuration_settings','elasticbeanstalk','environment/([A-Za-z0-9_-]{1,100})/([A-Za-z0-9-]{4,40})'),
     'glue_job_arguments': ('glue','get_job','glue','job/([A-Za-z0-9_. -]{1,255})'),
     'glue_connection_properties': ('glue','get_connection','glue','connection/([A-Za-z0-9_. -]{1,255})'),
     'launch_template_userdata': ('ec2','describe_launch_template_versions','ec2','launch-template/(lt-[a-f0-9]{8,17})'),
     'launch_configuration_userdata': ('autoscaling','describe_launch_configurations','autoscaling','launchConfiguration:([A-Za-z0-9-]{1,128}):launchConfigurationName/([A-Za-z0-9_.-]{1,255})'),
     'ssm_document': ('ssm','get_document','ssm','document/([A-Za-z0-9_.-]{3,128})'),
     'state_machine_definition': ('stepfunctions','describe_state_machine','states','stateMachine:([A-Za-z0-9_-]{1,80})'),
     'notebook_lifecycle': ('sagemaker','describe_notebook_instance_lifecycle_config','sagemaker','notebook-instance-lifecycle-config/([A-Za-z0-9-]{1,63})'),
     'pipeline_definition': ('datapipeline','get_pipeline_definition','datapipeline','pipeline/(df-[A-Za-z0-9]{1,128})'),
    }

    def enabled(options):
        return (options.get('content_secret_scans') is True and isinstance(options.get('_content_secret_scan_kinds'),list)
                and KIND in options['_content_secret_scan_kinds'])

    def parse(target):
        if not isinstance(target,dict) or set(target)-{'surface','scope','resource_id','version'} or not {'surface','scope','resource_id'}<=set(target):
            raise ValueError('invalid_configuration_selection')
        surface=target['surface'];scope=target['scope'];arn=target['resource_id']
        if not isinstance(surface,str) or surface not in SURFACES or not isinstance(scope,str) or not SCOPE.fullmatch(scope) or not isinstance(arn,str) or len(arn)>2048:
            raise ValueError('invalid_configuration_selection')
        account,region=SCOPE.fullmatch(scope).groups()
        partition='aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
        if '-iso' in region:raise ValueError('invalid_configuration_selection')
        service,operation,arn_service,resource=SURFACES[surface]
        arn_account='' if surface=='rest_stage_variables' else account
        match=re.fullmatch('arn:'+partition+':'+arn_service+':'+region+':'+arn_account+':'+resource,arn)
        if not match:raise ValueError('invalid_configuration_selection')
        versioned=surface in ('launch_template_userdata','ssm_document','codepipeline_configuration')
        if versioned:
            if type(target.get('version')) is not int or not 1<=target['version']<=2147483647:raise ValueError('invalid_configuration_selection')
        elif 'version' in target:raise ValueError('invalid_configuration_selection')
        return surface,account,region,partition,match.groups()

    def selected_targets(options,scopes):
        """Credential-free public selector validator; numeric versions, no URLs."""
        if not isinstance(options,dict) or ('content_secret_scans' in options and type(options['content_secret_scans']) is not bool):raise ValueError('invalid_configuration_selection')
        if OPTION not in options and not enabled(options):return []
        targets=options.get(OPTION)
        if (not isinstance(scopes,list) or not scopes
                or any(not isinstance(s,str) or not SCOPE.fullmatch(s) for s in scopes) or len(set(scopes))!=len(scopes)
                or not isinstance(targets,list) or not 1<=len(targets)<=MAX_TARGETS):raise ValueError('invalid_configuration_selection')
        seen=set();selected_scopes=set()
        for target in targets:
            parse(target);key=identity(target)
            if target['scope'] not in scopes or key in seen:raise ValueError('invalid_configuration_selection')
            seen.add(key)
            selected_scopes.add(target['scope'])
            if len(selected_scopes)>MAX_SELECTED_SCOPES:raise ValueError('invalid_configuration_selection')
        return deepcopy(targets)

    def identity(target):return KIND+':'+_fingerprint(json.dumps(target,sort_keys=True,separators=(',',':')))
    return SimpleNamespace(selected_targets=selected_targets)


def _make_workload_source():
    CHECK = 'aws.review.workload.selected_command_literal_secret_indicators'

    KIND = 'aws_selected_workload_command_literals'

    OPTION = 'selected_aws_workload_commands'

    MAX_TARGETS, MAX_CALLS = 8, 12

    MAX_SELECTED_SCOPES = 4

    SCOPE = re.compile(r'([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)\Z')

    def parse(target):
        if not isinstance(target, dict) or set(target) != {'scope', 'service', 'definition_arn'}:
            raise ValueError('invalid_selection')
        scope, service, arn = target['scope'], target['service'], target['definition_arn']
        match = SCOPE.fullmatch(scope) if isinstance(scope, str) and len(scope) <= 80 else None
        if not match or service not in ('ecs', 'batch') or not isinstance(arn, str) or len(arn) > 512:
            raise ValueError('invalid_selection')
        account, region = match.groups()
        partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
        resource = 'task-definition' if service == 'ecs' else 'job-definition'
        prefix = f'arn:{partition}:{service}:{region}:{account}:{resource}/'
        identity = re.fullmatch(r'([A-Za-z0-9_-]{1,' + ('255' if service == 'ecs' else '128') + r'}):([1-9][0-9]{0,9})', arn[len(prefix):])
        if '-iso' in region or not arn.startswith(prefix) or not identity:
            raise ValueError('invalid_selection')
        return account, region, partition, identity[1], int(identity[2])

    def locator(target):
        return KIND + ':' + _fingerprint(json.dumps(target, sort_keys=True))
    return SimpleNamespace(CHECK=CHECK, KIND=KIND, OPTION=OPTION, MAX_TARGETS=MAX_TARGETS, MAX_SELECTED_SCOPES=MAX_SELECTED_SCOPES, SCOPE=SCOPE, parse=parse, locator=locator)


def _make_workload(source):
    CHECK, KIND, OPTION = source.CHECK, source.KIND, source.OPTION

    def targets(options, scopes, named=(), provider='aws'):
        if OPTION not in options and not (options.get('content_secret_scans') is True and CHECK in named):
            return []
        rows = options.get(OPTION)
        if (provider != 'aws' or not isinstance(scopes, list) or not scopes
                or len(set(scopes)) != len(scopes)
                or any(not isinstance(s, str) or len(s) > 80 or not source.SCOPE.fullmatch(s) for s in scopes)
                or not isinstance(rows, list) or not 1 <= len(rows) <= source.MAX_TARGETS):
            raise ValueError('invalid_selected_workload_commands')
        seen = set()
        for row in rows:
            source.parse(row)
            ident = source.locator(row)
            if row['scope'] not in scopes or ident in seen:
                raise ValueError('invalid_selected_workload_commands')
            seen.add(ident)
        if len({row['scope'] for row in rows}) > source.MAX_SELECTED_SCOPES:
            raise ValueError('invalid_selected_workload_commands')
        return deepcopy(rows)
    return SimpleNamespace(targets=targets)


def _make_workload_ref(s3, peers):
    KIND='workload_referenced_source_content'

    OPTION='selected_aws_workload_sources'

    MAX_TARGETS=4

    PROFILES={
     'glue_script':('glue','get_job','text'),
     'emr_serverless_spark':('emr-serverless','get_job_run','text'),
     'emr_serverless_spark_jar':('emr-serverless','get_job_run','zip'),
     'emr_serverless_hive':('emr-serverless','get_job_run','text'),
     'emr_serverless_hive_init':('emr-serverless','get_job_run','text'),
     'emr_step_jar':('emr','describe_step','zip'),
     'sagemaker_hyperpod_lifecycle':('sagemaker','describe_cluster','text'),
     'sagemaker_training_script':('sagemaker','describe_training_job','tar.gz'),
    }

    def enabled(options):
        return options.get('content_secret_scans') is True and KIND in options.get('_content_secret_scan_kinds',())

    def source_target(target):
        uri=target['source_s3_uri']
        if not isinstance(uri,str) or len(uri)>2048 or not uri.startswith('s3://') or any(ord(c)<32 for c in uri):
            raise ValueError('invalid_workload_s3_uri')
        parsed=urlsplit(uri)
        if parsed.scheme!='s3' or not parsed.netloc or not parsed.path.startswith('/') or parsed.query or parsed.fragment or parsed.username or parsed.password or parsed.port is not None:
            raise ValueError('invalid_workload_s3_uri')
        selected={'scope':target['scope'],'bucket':parsed.netloc,'key':parsed.path[1:],'format':PROFILES[target['profile']][2]}
        s3.parse(selected)
        return selected

    def route(target):
        profile=target['profile']
        service,operation,_=PROFILES[profile]
        if profile=='glue_script':
            return service,operation,{'JobName':target['job_name']}
        if profile.startswith('emr_serverless_'):
            match=re.fullmatch(r'arn:aws:emr-serverless:([a-z0-9-]+):([0-9]{12}):/applications/([0-9a-z]{1,64})/jobruns/([0-9a-z]{1,64})',target['job_run_arn'])
            if not match:raise ValueError('invalid_emr_serverless_arn')
            return service,operation,{'applicationId':match[3],'jobRunId':match[4],'attempt':target['attempt']}
        if profile=='emr_step_jar':
            return service,operation,{'ClusterId':target['cluster_id'],'StepId':target['step_id']}
        if profile=='sagemaker_training_script':
            return service,operation,{'TrainingJobName':target['training_job_arn'].split(':training-job/',1)[1]}
        return service,operation,{'ClusterName':target['cluster_arn']}

    def selected_targets(options,scopes):
        if OPTION not in options and not enabled(options):return []
        targets=options.get(OPTION)
        if (not isinstance(targets,list) or not 1<=len(targets)<=MAX_TARGETS or not isinstance(scopes,list)
                or len(set(scopes))!=len(scopes) or any(not isinstance(scope,str) or not s3.SCOPE.fullmatch(scope) for scope in scopes)):
            raise ValueError('invalid_workload_selection')
        selected_s3=s3.selected_targets(options,scopes)
        seen=set();sources=set()
        for target in targets:
            if not isinstance(target,dict) or target.get('profile') not in PROFILES:
                raise ValueError('invalid_workload_profile')
            profile=target['profile']
            keys={'profile','scope','source_s3_uri'}
            keys|=({'job_name'} if profile=='glue_script' else {'job_run_arn','attempt'} if profile.startswith('emr_serverless_')
                else {'cluster_id','step_id'} if profile=='emr_step_jar'
                else {'training_job_arn','program'} if profile=='sagemaker_training_script'
                else {'cluster_arn','instance_group','entry_script'})
            if set(target)!=keys or target['scope'] not in scopes:raise ValueError('invalid_workload_selection')
            account,region=s3.SCOPE.fullmatch(target['scope']).groups()
            if region.startswith(('cn-','us-gov-')) or '-iso' in region:raise ValueError('unsupported_workload_partition')
            if profile=='glue_script' and (not isinstance(target['job_name'],str) or not re.fullmatch(r'[A-Za-z0-9_\-]{1,255}',target['job_name'])):
                raise ValueError('invalid_glue_job_name')
            if profile.startswith('emr_serverless_'):
                if type(target['attempt']) is not int or not 1<=target['attempt']<=1000:
                    raise ValueError('invalid_emr_serverless_attempt')
                match=re.fullmatch(r'arn:aws:emr-serverless:'+region+':'+account+r':/applications/[0-9a-z]{1,64}/jobruns/[0-9a-z]{1,64}',target['job_run_arn']) if isinstance(target['job_run_arn'],str) else None
                if not match:raise ValueError('invalid_emr_serverless_arn')
                if profile=='emr_serverless_spark_jar' and not target['source_s3_uri'].lower().endswith('.jar'):
                    raise ValueError('invalid_emr_serverless_jar')
            if profile=='emr_step_jar':
                if (not isinstance(target['cluster_id'],str) or not re.fullmatch(r'j-[A-Z0-9]{1,32}',target['cluster_id'])
                        or not isinstance(target['step_id'],str) or not re.fullmatch(r's-[A-Z0-9]{1,32}',target['step_id'])
                        or not target['source_s3_uri'].lower().endswith('.jar')):
                    raise ValueError('invalid_emr_step_selection')
            if profile=='sagemaker_hyperpod_lifecycle':
                if (not isinstance(target['cluster_arn'],str) or not re.fullmatch(r'arn:aws:sagemaker:'+region+':'+account+r':cluster/[a-z0-9]{12}',target['cluster_arn'])
                        or not isinstance(target['instance_group'],str) or not re.fullmatch(r'[A-Za-z0-9-]{1,64}',target['instance_group'])
                        or target['entry_script'] not in ('OnCreate','OnInitComplete')):
                    raise ValueError('invalid_sagemaker_lifecycle_selection')
            if profile=='sagemaker_training_script':
                arn=target['training_job_arn'];program=target['program']
                if (not isinstance(arn,str) or not re.fullmatch(r'arn:aws:sagemaker:'+region+':'+account+
                        r':training-job/[A-Za-z0-9](?:-*[A-Za-z0-9]){0,62}',arn)
                        or not isinstance(program,str) or not program.endswith('.py')
                        or not 1<=len(program.encode())<=256
                        or any(not re.fullmatch(r'[A-Za-z0-9_.-]+',part) or part in ('.','..') for part in program.split('/'))
                        or not target['source_s3_uri'].lower().endswith('.tar.gz')):
                    raise ValueError('invalid_sagemaker_training_script_selection')
            _,_,args=route(target)
            selected=source_target(target)
            if profile=='sagemaker_hyperpod_lifecycle' and not selected['bucket'].startswith('sagemaker-'):
                raise ValueError('invalid_sagemaker_lifecycle_bucket')
            key=json.dumps(selected,sort_keys=True)
            if selected not in selected_s3 or key in sources or identity(target) in seen:
                raise ValueError('workload_requires_exact_selected_s3_source')
            seen.add(identity(target));sources.add(key)
        if enabled(options) and s3.KIND not in options.get('_content_secret_scan_kinds',()):
            delegated={json.dumps(source_target(t),sort_keys=True) for t in targets}
            if 'ecs_selected_environment_file_content' in options.get('_content_secret_scan_kinds',()):
                ecs_source_target, ecs_option = peers.ecs_env.source_target, peers.ecs_env.OPTION
                delegated|={json.dumps(ecs_source_target(t),sort_keys=True) for t in options.get(ecs_option,())}
            if 'build_deployment_referenced_source_content' in options.get('_content_secret_scan_kinds',()):
                build_source_target, build_option = peers.build_ref.source_target, peers.build_ref.OPTION
                delegated|={json.dumps(build_source_target(t),sort_keys=True) for t in options.get(build_option,())}
            if delegated!={json.dumps(t,sort_keys=True) for t in selected_s3}:
                raise ValueError('workload_extra_s3_selection')
        return deepcopy(targets)

    def identity(target):
        return KIND+':'+_fingerprint(json.dumps(target,sort_keys=True,separators=(',',':')))
    return SimpleNamespace(OPTION=OPTION, source_target=source_target, selected_targets=selected_targets)


def _make_build_ref(s3, peers):
    KIND = 'build_deployment_referenced_source_content'

    CHECK = 'aws.review.build_deployment.referenced_source_secret_indicators'

    OPTION = 'selected_aws_build_deployment_sources'

    MAX_TARGETS = 4

    UUID = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

    PROFILES = {'codebuild_s3_source': ('codebuild', 'batch_get_projects', 'zip'), 'codebuild_s3_buildspec': ('codebuild', 'batch_get_projects', 'text'), 'codebuild_build_output': ('codebuild', 'batch_get_builds', 'zip'), 'codebuild_codecommit_source': ('codebuild', 'batch_get_builds', 'text'), 'codepipeline_action_output': ('codepipeline', 'list_action_executions', 'zip'), 'elasticbeanstalk_source_bundle': ('elasticbeanstalk', 'describe_application_versions', 'zip'), 'amplify_s3_zip_deployment': ('amplify', 'get_job', 'zip')}

    def enabled(options):
        return options.get('content_secret_scans') is True and KIND in options.get('_content_secret_scan_kinds', ())

    def source_target(target):
        uri = target['source_s3_uri']
        if not isinstance(uri, str) or len(uri) > 2048 or (not uri.startswith('s3://')) or any((ord(c) < 32 for c in uri)):
            raise ValueError('invalid_source_uri')
        parsed = urlsplit(uri)
        if parsed.scheme != 's3' or not parsed.netloc or (not parsed.path.startswith('/')) or parsed.query or parsed.fragment or parsed.username or parsed.password or (parsed.port is not None):
            raise ValueError('invalid_source_uri')
        source = {'scope': target['scope'], 'bucket': parsed.netloc, 'key': parsed.path[1:], 'format': PROFILES[target['profile']][2]}
        if 'version_id' in target:
            source['version_id'] = target['version_id']
        s3.parse(source)
        return source

    def route(target):
        profile = target['profile']
        service, operation, _ = PROFILES[profile]
        if profile in ('codebuild_build_output', 'codebuild_codecommit_source'):
            return (service, operation, {'ids': [target['build_arn'].split(':build/', 1)[1]]})
        if profile == 'codepipeline_action_output':
            return (service, operation, {'pipelineName': target['pipeline_name'], 'filter': {'pipelineExecutionId': target['pipeline_execution_id']}, 'maxResults': 100})
        if profile.startswith('codebuild_'):
            return (service, operation, {'names': [target['project_arn']]})
        if profile == 'elasticbeanstalk_source_bundle':
            return (service, operation, {'ApplicationName': target['application_name'], 'VersionLabels': [target['version_label']], 'MaxRecords': 1})
        return (service, operation, {'appId': target['app_id'], 'branchName': target['branch_name'], 'jobId': target['job_id']})

    def identity(target):
        return KIND + ':' + _fingerprint(json.dumps(target, sort_keys=True, separators=(',', ':')))

    def selected_targets(options, scopes):
        if OPTION not in options and (not enabled(options)):
            return []
        targets = options.get(OPTION)
        if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS or (not isinstance(scopes, list)) or (len(set(scopes)) != len(scopes)) or any((not isinstance(scope, str) or not s3.SCOPE.fullmatch(scope) for scope in scopes)):
            raise ValueError('invalid_build_deployment_selection')
        codecommit_only = all(isinstance(t, dict) and t.get('profile') == 'codebuild_codecommit_source' for t in targets)
        s3_peers = {'s3_selected_source_content', 'ecs_selected_environment_file_content', 'workload_referenced_source_content'}
        selected_s3 = ([] if codecommit_only and s3.OPTION not in options
                       and not s3_peers.intersection(options.get('_content_secret_scan_kinds', ()))
                       else s3.selected_targets(options, scopes))
        seen = set()
        sources = set()
        for target in targets:
            if not isinstance(target, dict) or target.get('profile') not in PROFILES:
                raise ValueError('invalid_build_deployment_profile')
            profile = target['profile']
            keys = {'profile', 'scope'} if profile == 'codebuild_codecommit_source' else {'profile', 'scope', 'source_s3_uri'}
            if profile == 'codebuild_codecommit_source':
                keys |= {'build_arn', 'repository_arn', 'commit_id', 'file_path'}
            if profile == 'codebuild_build_output':
                keys |= {'build_arn'}
            elif profile == 'codepipeline_action_output':
                keys |= {'pipeline_arn', 'pipeline_name', 'pipeline_execution_id', 'action_execution_id', 'artifact_name'}
            elif profile.startswith('codebuild_') and profile != 'codebuild_codecommit_source':
                keys |= {'project_arn'}
            elif profile == 'elasticbeanstalk_source_bundle':
                keys |= {'application_name', 'version_label', 'version_arn'}
            elif profile == 'amplify_s3_zip_deployment':
                keys |= {'app_id', 'branch_name', 'job_id', 'job_arn'}
            if profile == 'codebuild_s3_source' and 'version_id' in target:
                keys.add('version_id')
            if set(target) != keys or target['scope'] not in scopes:
                raise ValueError('invalid_build_deployment_selection')
            account, region = s3.SCOPE.fullmatch(target['scope']).groups()
            if region.startswith(('cn-', 'us-gov-')) or '-iso' in region:
                raise ValueError('unsupported_partition')
            uri = target.get('source_s3_uri')
            if profile != 'codebuild_codecommit_source' and (not isinstance(uri, str) or not 1 <= len(uri) <= 2048):
                raise ValueError('invalid_source_uri')
            if profile in ('codebuild_build_output', 'codebuild_codecommit_source'):
                arn = target['build_arn']
                if not isinstance(arn, str) or not re.fullmatch('arn:aws:codebuild:' + region + ':' + account + ':build/[A-Za-z0-9_-]{1,255}:' + UUID, arn):
                    raise ValueError('invalid_codebuild_build')
                if profile == 'codebuild_codecommit_source':
                    repo = target['repository_arn']
                    path = target['file_path']
                    commit = target['commit_id']
                    if (not isinstance(repo, str) or not re.fullmatch(r'arn:aws:codecommit:' + region + ':' + account + r':[A-Za-z0-9_.-]{1,100}', repo)
                            or not isinstance(commit, str) or re.fullmatch(r'[0-9a-f]{40}', commit) is None
                            or not isinstance(path, str) or not 1 < len(path) <= 2048 or not path.startswith('/')
                            or path.endswith('/') or any(part in ('', '.', '..') for part in path[1:].split('/'))
                            or any(ord(c) < 32 for c in path)):
                        raise ValueError('invalid_codecommit_selection')
            elif profile == 'codepipeline_action_output':
                name = target['pipeline_name']
                if not isinstance(name, str) or not re.fullmatch('[A-Za-z0-9.@_-]{1,100}', name) or target['pipeline_arn'] != 'arn:aws:codepipeline:' + region + ':' + account + ':' + name or (not isinstance(target['pipeline_execution_id'], str)) or (not re.fullmatch(UUID, target['pipeline_execution_id'])) or (not isinstance(target['action_execution_id'], str)) or (not re.fullmatch(UUID, target['action_execution_id'])) or (not isinstance(target['artifact_name'], str)) or (not re.fullmatch('[A-Za-z0-9_-]{1,100}', target['artifact_name'])):
                    raise ValueError('invalid_codepipeline_action')
            elif profile.startswith('codebuild_'):
                if not isinstance(target['project_arn'], str) or not re.fullmatch('arn:aws:codebuild:' + region + ':' + account + ':project/[A-Za-z0-9][A-Za-z0-9_./-]{0,254}', target['project_arn']):
                    raise ValueError('invalid_codebuild_project')
                if profile == 'codebuild_s3_source' and (not uri.lower().endswith('.zip')) or (profile == 'codebuild_s3_buildspec' and (not uri.lower().endswith(('.yml', '.yaml')))):
                    raise ValueError('unsupported_codebuild_format')
            elif profile == 'elasticbeanstalk_source_bundle':
                if not isinstance(target['application_name'], str) or not re.fullmatch('[A-Za-z0-9_.-]{1,100}', target['application_name']) or (not isinstance(target['version_label'], str)) or (not re.fullmatch('[A-Za-z0-9_.-]{1,100}', target['version_label'])) or (target['version_arn'] != 'arn:aws:elasticbeanstalk:' + region + ':' + account + ':applicationversion/' + target['application_name'] + '/' + target['version_label']) or (not uri.lower().endswith(('.zip', '.war'))):
                    raise ValueError('invalid_application_version')
            elif not isinstance(target['app_id'], str) or not re.fullmatch('d[a-z0-9]{1,19}', target['app_id']) or (not isinstance(target['branch_name'], str)) or (not re.fullmatch('[A-Za-z0-9_.-]{1,255}', target['branch_name'])) or (not isinstance(target['job_id'], str)) or (not re.fullmatch('[0-9]{1,255}', target['job_id'])) or (target['job_arn'] != 'arn:aws:amplify:' + region + ':' + account + ':apps/' + target['app_id'] + '/branches/' + target['branch_name'] + '/jobs/' + target['job_id']) or (not uri.lower().endswith('.zip')):
                raise ValueError('invalid_amplify_job')
            if profile == 'codebuild_codecommit_source':
                if identity(target) in seen:
                    raise ValueError('duplicate_build_deployment_selection')
                seen.add(identity(target))
                continue
            source = source_target(target)
            key = json.dumps(source, sort_keys=True)
            if source not in selected_s3 or key in sources or identity(target) in seen:
                raise ValueError('build_deployment_requires_exact_selected_s3_source')
            seen.add(identity(target))
            sources.add(key)
        if enabled(options) and s3.KIND not in options.get('_content_secret_scan_kinds', ()):
            delegated = {json.dumps(source_target(t), sort_keys=True) for t in targets if t['profile'] != 'codebuild_codecommit_source'}
            if 'ecs_selected_environment_file_content' in options.get('_content_secret_scan_kinds', ()):
                source, option = (peers.ecs_env.source_target, peers.ecs_env.OPTION)
                delegated |= {json.dumps(source(t), sort_keys=True) for t in options.get(option, ())}
            if 'workload_referenced_source_content' in options.get('_content_secret_scan_kinds', ()):
                source, option = (peers.workload_ref.source_target, peers.workload_ref.OPTION)
                delegated |= {json.dumps(source(t), sort_keys=True) for t in options.get(option, ())}
            if delegated != {json.dumps(t, sort_keys=True) for t in selected_s3}:
                raise ValueError('build_deployment_extra_s3_selection')
        return deepcopy(targets)
    return SimpleNamespace(OPTION=OPTION, source_target=source_target, selected_targets=selected_targets)


def _make_gcp_uri():
    GCR_REPOSITORIES = {
        'gcr.io': ('us', 'gcr.io'),
        'us.gcr.io': ('us', 'us.gcr.io'),
        'eu.gcr.io': ('europe', 'eu.gcr.io'),
        'asia.gcr.io': ('asia', 'asia.gcr.io'),
    }

    def parse(value):
        if not isinstance(value, str):
            raise ValueError('literal image URI required')
        bare = value.removeprefix('https://')
        pkg = re.fullmatch(r'([a-z0-9-]+)-docker\.pkg\.dev/([a-z0-9-]+)/([A-Za-z0-9._-]+)/([A-Za-z0-9._/-]+)@(sha256:[a-f0-9]{64})', bare)
        if pkg:
            location, project, repository, image, digest = pkg.groups()
        else:
            gcr = re.fullmatch(r'(gcr\.io|us\.gcr\.io|eu\.gcr\.io|asia\.gcr\.io)/([a-z0-9-]+)/([a-z0-9._/-]+)@(sha256:[a-f0-9]{64})', bare)
            if not gcr:
                raise ValueError('immutable supported native registry URI required')
            host, project, image, digest = gcr.groups()
            location, repository = GCR_REPOSITORIES[host]
        if repository in ('.', '..') or any(part in ('', '.', '..') for part in image.split('/')):
            raise ValueError('unsafe native repository or image path')
        return ('https://' + bare,
                f'projects/{project}/locations/{location}/repositories/{repository}',
                digest, image + '@' + digest)
    return SimpleNamespace(parse=parse)


def _make_workerpool(native):
    POOL = re.compile(r'projects/([a-z][a-z0-9-]{0,62})/locations/([a-z][a-z0-9-]{0,62})/workerPools/([a-z][a-z0-9-]{0,62})')

    def need(ok, reason):
        if not ok:
            raise ValueError(reason)

    def selections(values, scope):
        need(type(scope) is str and re.fullmatch(r'projects/[a-z][a-z0-9-]{0,62}', scope), 'exact project required')
        need(type(values) is list and 1 <= len(values) <= 4, 'one to four selections required')
        out, seen = [], set()
        for v in values:
            need(type(v) is dict and set(v) == {'pool_name', 'pool_uid', 'revision_name', 'revision_uid', 'container_index', 'immutable_reference'}, 'closed selection required')
            pool = v['pool_name']
            need(type(pool) is str and len(pool) <= 512 and POOL.fullmatch(pool) and pool.startswith(scope + '/'), 'foreign pool')
            need(type(v['pool_uid']) is str and re.fullmatch(r'[0-9a-f-]{36}', v['pool_uid']), 'pool UID required')
            need(type(v['revision_uid']) is str and re.fullmatch(r'[0-9a-f-]{36}', v['revision_uid']), 'revision UID required')
            need(type(v['revision_name']) is str and len(v['revision_name']) <= 512 and re.fullmatch(re.escape(pool) + r'/revisions/[a-z][a-z0-9-]{0,62}', v['revision_name']), 'foreign revision')
            need(type(v['container_index']) is int and 0 <= v['container_index'] < 10, 'container index bound')
            need(type(v['immutable_reference']) is str and len(v['immutable_reference']) <= 512 and not v['immutable_reference'].startswith('https://'), 'literal digest required')
            uri, repo, digest, image_name = native.parse_image_uri(v['immutable_reference'])
            need(repo.startswith(scope + '/') and v['immutable_reference'] == v['immutable_reference'].lower(), 'foreign image repository')
            key = pool, v['revision_name'], v['container_index']
            need(key not in seen, 'duplicate selection')
            seen.add(key)
            out.append(deepcopy(v))
        return out
    return SimpleNamespace(selections=selections)


def _make_developerconnect():
    MAX_TARGETS = 4

    PROJECT = re.compile(r'projects/([a-z][a-z0-9-]{0,62})\Z')

    LINK = re.compile(r'projects/([a-z][a-z0-9-]{0,62})/locations/([a-z][a-z0-9-]{0,62})/connections/([A-Za-z][A-Za-z0-9_-]{0,62})/gitRepositoryLinks/([A-Za-z][A-Za-z0-9_-]{0,62})\Z')

    HEX40 = re.compile(r'[0-9a-f]{40}\Z')

    SEGMENT = re.compile(r'[A-Za-z0-9_.-]{1,100}\Z')

    PATH = re.compile(r'[A-Za-z0-9_./-]{1,256}\Z')

    def need(condition, reason):
        if not condition:
            raise ValueError(reason)

    def origin(clone_uri):
        need(type(clone_uri) is str and len(clone_uri) <= 512, 'clone URI bound')
        patterns = (
            ('github', r'https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?\Z'),
            ('gitlab', r'https://gitlab\.com/([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)/([A-Za-z0-9_.-]+?)(?:\.git)?\Z'),
            ('bitbucket', r'https://bitbucket\.org/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?\Z'),
        )
        for provider, pattern in patterns:
            match = re.fullmatch(pattern, clone_uri)
            if match:
                owner, repo = match.groups()
                need(all(SEGMENT.fullmatch(part) and part not in ('.', '..') for part in owner.split('/') + [repo]), 'unsafe repository path')
                return provider, owner, repo
        raise ValueError('unsupported public repository origin')

    def selections(values, scope):
        need(type(scope) is str and PROJECT.fullmatch(scope), 'one exact project required')
        need(type(values) is list and 1 <= len(values) <= MAX_TARGETS, 'one to four targets required')
        result, seen = [], set()
        keys = {'link_name', 'link_uid', 'clone_uri', 'provider', 'commit_sha', 'path', 'blob_sha'}
        for value in values:
            need(type(value) is dict and set(value) == keys, 'closed file selector required')
            link = value['link_name']
            need(type(link) is str and len(link) <= 512 and LINK.fullmatch(link) and link.startswith(scope + '/'), 'foreign link')
            need(type(value['link_uid']) is str and re.fullmatch(r'[0-9a-f-]{36}', value['link_uid']), 'link UID required')
            if value['provider'] == 'enterprise':
                from urllib.parse import urlsplit
                parsed = urlsplit(value['clone_uri']) if type(value['clone_uri']) is str else None
                need(parsed is not None and parsed.scheme == 'https' and parsed.hostname and parsed.port is None and parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment
                     and re.fullmatch(r'[a-z0-9.-]{3,253}', parsed.hostname) and parsed.hostname not in ('github.com','gitlab.com','bitbucket.org')
                     and re.fullmatch(r'/(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+(?:\.git)?', parsed.path), 'unsafe enterprise origin')
            else:
                provider, owner, repo = origin(value['clone_uri'])
                need(provider == value['provider'], 'provider origin mismatch')
            need(type(value['commit_sha']) is str and (HEX40.fullmatch(value['commit_sha']) and value['commit_sha'] != '0'*40
                 or re.fullmatch(r'[A-Za-z][A-Za-z0-9._/-]{0,63}', value['commit_sha']) and '..' not in value['commit_sha'].split('/')), 'commit or unsupported branch required')
            need(type(value['blob_sha']) is str and HEX40.fullmatch(value['blob_sha']) and value['blob_sha'] != '0'*40, 'immutable blob required')
            path = value['path']
            need(type(path) is str and PATH.fullmatch(path) and all(part not in ('', '.', '..') for part in path.split('/')), 'unsafe selected path')
            key = link, value['commit_sha'], path
            need(key not in seen, 'duplicate target')
            seen.add(key)
            result.append(deepcopy(value))
        return result
    return SimpleNamespace(selections=selections)


association = _make_association()

registry = _make_registry(association)

flux = _make_flux()

declaration = _make_declaration()

storage = _make_storage()

ml_asset = _make_ml_asset(declaration.GUID, declaration.SEG, declaration.SCOPE, storage)

databricks = _make_databricks(declaration.GUID, declaration.SEG, declaration.SCOPE)

synapse = _make_synapse(declaration.GUID, declaration.SEG, declaration.SCOPE)

s3 = _make_s3()

ecs_env = _make_ecs_env(s3, peers)

peers.ecs_env = ecs_env

aws_config = _make_aws_config()

workload_source = _make_workload_source()

workload = _make_workload(workload_source)

workload_ref = _make_workload_ref(s3, peers)

peers.workload_ref = workload_ref

build_ref = _make_build_ref(s3, peers)

peers.build_ref = build_ref

gcp_uri = _make_gcp_uri()

workerpool = _make_workerpool(SimpleNamespace(parse_image_uri=gcp_uri.parse))

developerconnect = _make_developerconnect()

SOURCE_SHA256 = {'association': 'c5fdc84792aaaafa00c482975abc13a24c3b6e5d6271b200d92689a117089483', 'registry': '4502cc4a78fe13204d8dd9accdbe25bf38870923b8fb08be3cf0b90e9db3bac2', 'flux': 'dce94812949137c89ef40429dd6cd5bb976ca2fde90dfec4e7642c1a5553816d', 'declaration': '361844ed7f69dfa530d539e3e661d40cdb7e3f96a08aa1704b36f9b76d75ed18', 'storage': '4a090b1f8fe9da69de7e4aef9d467e01d421cc00febc0fc20ea978e1f1f00b63', 'ml_asset': 'dcf7862813c41c54d05d5c8db3d3067297a96b874f7f0bc2e8babde9314bd8a8', 'databricks': '2c341ba97b78cb309fb5612b0c01ac6c45b2b8039d948268f919e43376e8510a', 'synapse': 'a5c7ae0189b0fbcc04f52ec935867c4af45acbe9f1f56105cf651f5189d1ae8b', 's3': '7314db8009503f2952576448c19da1dabd384c1629c253f88e5acc95314ac2a8', 'ecs_env': '935ef872cfe5700635d05df4b6b2fc9f78e5d04436a96863f405c0eecae2fc9e', 'aws_config': '8d258c01c306b2e4cc78d58e4e5fd4e7b15a40abc7e2fdf32837e79625377ba6', 'workload_source': 'a5aa7cba18e0acc377a505abed400d82d835eb9bf7650460d0623fea0b1d6778', 'workload': 'de543276807257ff814980b78e523be21de02cecab7f9b31b2cb7dfb0940b09d', 'workload_ref': '6622844a60a44b3c742a424a3b63b8249c985ac15d107d4c8652ba6bb6fa90e1', 'build_ref': 'ba787bb56c678c18d7da978daa0b802e599465567f372c91e34dbee455f06b99', 'gcp_uri': 'f72d575d69d9ef90bf7bcd9812dd0ba596eb2a3b9db41c89dd6045b3a825d838', 'workerpool': '1dd62095a051d7f3982e55dfd4ec530e76e31e282e9b24108695fdb6834159fe', 'developerconnect': '6dd0ef3fe52a91f6b54db35610e627ae97ae6f897b38a1d0fd6ff3e7840f1571'}

def _make_aks_image(registry):
    copy = SimpleNamespace(deepcopy=deepcopy)
    _UUID = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

    _ARM = re.compile(r'(/subscriptions/' + _UUID + r')/resourceGroups/[A-Za-z0-9_.()-]{1,90}/providers/Microsoft.ContainerService/managedClusters/[A-Za-z0-9_-]{1,63}', re.I)

    _HOST = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+')

    def _arm(value):
        if not isinstance(value, str) or not _ARM.fullmatch(value):
            raise ValueError('AKS ARM identity invalid')
        return value.lower()

    def _host(value):
        if (not isinstance(value, str) or len(value) > 253 or value != value.lower()
                or not _HOST.fullmatch(value) or not any(c.isalpha() for c in value) or any(p.startswith('xn--') for p in value.split('.'))):
            raise ValueError('AKS DNS identity invalid')
        return value

    def _server(value):
        if not isinstance(value, str):
            raise ValueError('AKS explicit HTTPS server required')
        p = urlsplit(value)
        if p.scheme != 'https' or p.netloc != p.hostname or p.path or p.query or p.fragment:
            raise ValueError('AKS server must be an exact HTTPS DNS origin')
        host=_host(p.hostname)
        if value!='https://'+host:raise ValueError('AKS noncanonical HTTPS server rejected')
        return host
    aks = SimpleNamespace(_UUID=_UUID, _ARM=_ARM)
    image = registry
    KIND = 'azure_selected_aks_pod_image'

    CHECK = 'azure.review.aks.selected_pod_image_secret_indicators'

    VULN_KIND = 'azure_selected_aks_pod_image_vulnerabilities'

    VULN_CHECK = 'azure.review.aks.selected_pod_image_high_vulnerabilities'

    OPTION = 'selected_azure_aks_pod_images'

    MAX_TARGETS = 4

    _ARC = re.compile(r'/subscriptions/' + aks._UUID +
                      r'/resourceGroups/[A-Za-z0-9_.()-]{1,90}/providers/Microsoft\.Kubernetes/connectedClusters/[A-Za-z0-9_-]{1,63}\Z', re.I)

    def selected_targets(options, scopes, named=()):
        """Entire preflight is pure and runs before ARM, Kubernetes, or registry auth."""
        if (type(options) is not dict or
                any(key in options and type(options[key]) is not bool
                    for key in ('content_secret_scans', 'image_vulnerability_scans'))):
            raise ValueError('invalid_aks_image_selection')
        if any(key in options for key in ('trivy_db_cache', 'trivy_cli')):
            raise ValueError('trivy_runtime_configuration_is_not_a_request_option')
        active = ((options.get('content_secret_scans') is True and CHECK in named)
                  or (options.get('image_vulnerability_scans') is True and VULN_CHECK in named))
        if OPTION not in options and not active:
            return []
        rows = options.get(OPTION)
        if type(rows) is not list or not 1 <= len(rows) <= MAX_TARGETS or type(scopes) is not list:
            raise ValueError('invalid_aks_image_selection')
        scopes = {s.casefold() for s in scopes if type(s) is str}
        seen = set()
        for row in rows:
            if type(row) is not dict or set(row) != {'cluster_id', 'namespace', 'pod', 'uid', 'resource_version', 'container_type', 'container_name', 'image'}:
                raise ValueError('invalid_aks_image_selection')
            rid = row['cluster_id']
            if type(rid) is not str or not (aks._ARM.fullmatch(rid) or _ARC.fullmatch(rid)) or rid.casefold().split('/resourcegroups/')[0] not in scopes:
                raise ValueError('invalid_aks_image_selection')
            # Reuse the existing exact Pod/digest/host validator without enabling I/O.
            image.selected_targets({image.OPTION: [row], image.ALLOWLIST: options.get(image.ALLOWLIST, []),
                                    'content_secret_scans': True}, [row['namespace']], [image.SECRET_CHECK])
            key = image.identity(row)
            if key in seen:
                raise ValueError('duplicate_aks_image_selection')
            seen.add(key)
        return deepcopy(rows)
    def normalize_contexts(auth):
        if auth is not None and not isinstance(auth, dict):
            raise ValueError("AKS credentials must be an object")
        contexts = {}
        if auth is not None and 'aks_workloads' in auth:
            entries = auth['aks_workloads']
            try:bounded=len(json.dumps(entries,allow_nan=False))<=2000000
            except (TypeError,ValueError):bounded=False
            if not bounded:raise ValueError('AKS credential byte budget exceeded')
            if not isinstance(entries, list) or not 0 < len(entries) <= 16:
                raise ValueError('AKS explicit credential bounds invalid')
            from cryptography import x509
            endpoints=set()
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {'cluster_id', 'server', 'ca_cert_data', 'token'}:
                    raise ValueError('AKS explicit credential fields invalid')
                rid = _arm(entry['cluster_id']); _server(entry['server'])
                if entry['server'] in endpoints:raise ValueError('AKS endpoint bound to multiple resource identities')
                endpoints.add(entry['server'])
                if rid in contexts:
                    raise ValueError('AKS duplicate credential binding')
                token, ca = entry['token'], entry['ca_cert_data']
                if not isinstance(token, str) or not 0 < len(token) <= 1000000 or not token.isascii() or any(c.isspace() or ord(c) < 33 or ord(c) > 126 for c in token):
                    raise ValueError('AKS explicit bearer token invalid')
                if not isinstance(ca, str) or not 0 < len(ca) <= 100000 or 'PRIVATE KEY' in ca:
                    raise ValueError('AKS inline CA certificate invalid')
                try:
                    certs=x509.load_pem_x509_certificates(ca.encode())
                    if not certs or any(not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca for cert in certs):
                        raise ValueError('AKS trust anchor must be a CA')
                except Exception:raise ValueError('AKS inline CA certificate invalid') from None
                contexts[rid] = copy.deepcopy(entry)
        return contexts

    return SimpleNamespace(selected_targets=selected_targets, normalize_contexts=normalize_contexts)

aks_image = _make_aks_image(registry)

def _make_ml_job(constants):
    GUID, SCOPE, SEG = constants.GUID, constants.SCOPE, constants.SEG
    KIND = 'azure_ml_selected_command_job'

    CHECK = 'azure.review.machine_learning.selected_command_job_secret_indicators'

    OPTION = 'selected_azure_ml_command_jobs'

    MAX_TARGETS = 4

    def enabled(options):
        return options.get('content_secret_scans') is True and isinstance(options.get('_content_secret_scan_kinds'), list) and KIND in options['_content_secret_scan_kinds']

    def parse(target):
        if not isinstance(target, dict) or set(target) != {'resource_id'}:
            raise ValueError('invalid_selection')
        rid = target['resource_id']
        match = re.fullmatch(r'(/subscriptions/' + GUID + r')/resourceGroups/' + SEG + r'/providers/Microsoft\.MachineLearningServices/workspaces/([A-Za-z0-9][A-Za-z0-9_-]{2,32})/jobs/([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})', rid, re.I) if isinstance(rid, str) and len(rid) <= 1024 else None
        if not match or any(p in ('.', '..') for p in rid.split('/')):
            raise ValueError('invalid_selection')
        return match[1], rid, rid.rsplit('/', 2)[0]

    def identity(target):
        _, rid, parent = parse(target)
        # Native Jobs Get documents job identifier as case-sensitive.
        return KIND + ':' + _fingerprint(parent.casefold() + '/jobs/' + rid.rsplit('/', 1)[1])

    def selected_targets(options, scopes):
        if not isinstance(options, dict) or 'content_secret_scans' in options and type(options['content_secret_scans']) is not bool:
            raise ValueError('invalid_selection')
        if OPTION not in options and not enabled(options): return []
        targets = options.get(OPTION)
        if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 8 or any(not isinstance(s, str) or not SCOPE.fullmatch(s) for s in scopes)
                or len({s.casefold() for s in scopes}) != len(scopes) or not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS):
            raise ValueError('invalid_selection')
        seen = set()
        for target in targets:
            scope, _, _ = parse(target); ident = identity(target)
            if scope.casefold() not in {s.casefold() for s in scopes} or ident in seen: raise ValueError('invalid_selection')
            seen.add(ident)
        return deepcopy(targets)
    return SimpleNamespace(selected_targets=selected_targets)

ml_job = _make_ml_job(declaration)


def _make_aws_workload_image():
    from peaso.aws_image_selection_20261021 import selections
    CHECK = 'aws.review.workload.selected_image_secret_indicators'

    ENABLE = 'content_secret_scans'

    OPTION = 'selected_aws_workload_image_secrets'

    def selected(options, scopes, named):
        """Call before credentials; a generic ECR or S3 selection grants nothing."""
        if type(options) is not dict or options.get(ENABLE) is not True or CHECK not in named:
            return []
        targets = selections({'image_vulnerability_scans': True,
            'selected_aws_image_vulnerabilities': options.get(OPTION)}, scopes)
        if len(targets) > 4 or any(not any(k in t for k in
                ('function_arn', 'task_definition_arn', 'job_definition_arn')) for t in targets):
            raise ValueError('exact_workload_target_required')
        return targets
    return SimpleNamespace(selected=selected, CHECK=CHECK, ENABLE=ENABLE, OPTION=OPTION)

aws_workload_image = _make_aws_workload_image()

def _make_azure_flex_archives():
    guid=r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
    scope=re.compile('/subscriptions/'+guid+r'\Z',re.I)
    site=re.compile(r'(/subscriptions/'+guid+r')/resourceGroups/[A-Za-z0-9_.()-]{1,90}/providers/Microsoft\.Web/sites/[A-Za-z0-9-]{1,60}\Z',re.I)
    account=re.compile(r'(/subscriptions/'+guid+r')/resourceGroups/[A-Za-z0-9_.()-]{1,90}/providers/Microsoft\.Storage/storageAccounts/[a-z0-9]{3,24}\Z',re.I)
    def selected_targets(options,scopes):
        if not isinstance(options,dict) or 'content_secret_scans' in options and type(options['content_secret_scans']) is not bool:
            raise ValueError('invalid_flex_selection')
        key='selected_azure_flex_deployment_containers'
        if key not in options:return []
        rows=options[key]
        if (not isinstance(scopes,list) or not 1<=len(scopes)<=8 or any(not isinstance(s,str) or not scope.fullmatch(s) for s in scopes)
                or not isinstance(rows,list) or not 1<=len(rows)<=2):raise ValueError('invalid_flex_selection')
        seen=set()
        for row in rows:
            if not isinstance(row,dict) or set(row)!={'site_resource_id','storage_account_resource_id','container'}:
                raise ValueError('invalid_flex_selection')
            sid=row['site_resource_id'];aid=row['storage_account_resource_id'];name=row['container']
            sm=site.fullmatch(sid) if isinstance(sid,str) and len(sid)<=512 else None
            am=account.fullmatch(aid) if isinstance(aid,str) and len(aid)<=512 else None
            if (not sm or not am or '/.' in sid or '/.' in aid or sm[1].casefold()!=am[1].casefold()
                    or sm[1].casefold() not in {s.casefold() for s in scopes} or sid.casefold() in seen
                    or not isinstance(name,str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])',name)
                    or '--' in name):raise ValueError('invalid_flex_selection')
            seen.add(sid.casefold())
        return deepcopy(rows)
    return SimpleNamespace(selected_targets=selected_targets)

azure_flex_archives=_make_azure_flex_archives()


def _make_lambda_environment():
    KIND='lambda_selected_environment'

    OPTION='selected_aws_lambda_functions'

    MAX_TARGETS=8

    MAX_SELECTED_SCOPES=8

    ARN=re.compile(r'arn:(aws|aws-cn|aws-us-gov):lambda:([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+):([0-9]{12}):function:([A-Za-z0-9_-]{1,64})\Z')

    SCOPE=re.compile(r'([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)\Z')

    class Incomplete(ValueError):
        """Stable errors only; never include provider text or selected names."""

    def enabled(options):
        return (options.get('content_secret_scans') is True and isinstance(options.get('_content_secret_scan_kinds'),list)
            and KIND in options['_content_secret_scan_kinds'])

    def parse(arn):
        match=ARN.fullmatch(arn) if isinstance(arn,str) else None
        if not match:raise Incomplete('invalid_lambda_selection')
        partition='aws-cn' if match[2].startswith('cn-') else 'aws-us-gov' if match[2].startswith('us-gov-') else 'aws'
        if match[1]!=partition or '-iso' in match[2]:raise Incomplete('invalid_lambda_selection')
        return match

    def selected_targets(options,scopes):
        """Exported credential-free public validator; exact unqualified ARN only."""
        if not isinstance(options,dict) or ('content_secret_scans' in options and type(options['content_secret_scans']) is not bool):
            raise Incomplete('invalid_lambda_selection')
        if OPTION not in options and not enabled(options):return []
        targets=options.get(OPTION)
        if (not isinstance(scopes,list) or not scopes
                or any(not isinstance(s,str) or not SCOPE.fullmatch(s) for s in scopes)
                or len(set(scopes))!=len(scopes) or not isinstance(targets,list) or not 1<=len(targets)<=MAX_TARGETS):
            raise Incomplete('invalid_lambda_selection')
        seen=set();selected_scopes=set()
        for arn in targets:
            match=parse(arn)
            if match[3]+'/'+match[2] not in scopes or arn in seen:raise Incomplete('invalid_lambda_selection')
            seen.add(arn)
            selected_scopes.add(match[3]+'/'+match[2])
            if len(selected_scopes)>MAX_SELECTED_SCOPES:raise Incomplete('invalid_lambda_selection')
        return list(targets)

    return SimpleNamespace(selected_targets=selected_targets)


lambda_environment = _make_lambda_environment()
