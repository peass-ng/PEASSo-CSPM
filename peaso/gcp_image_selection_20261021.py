"""Credential-free exact immutable GCP registry image selection.

No alias rewriting: a gcr.io URL must itself be returned by DockerImage.uri and
bound to its documented native repository before content inspection is possible.
"""
import re

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


ENABLE = 'image_vulnerability_scans'
OPTION = 'selected_gcp_registry_image_vulnerabilities'
MAX_IMAGES = 4

def selections(options, scopes):
    if type(options) is not dict or type(scopes) is not list:
        raise ValueError('invalid_registry_image_selection')
    if ENABLE in options and type(options[ENABLE]) is not bool:
        raise ValueError('image_vulnerability_scans_must_be_boolean')
    if OPTION not in options:
        return []
    if (not 1 <= len(scopes) <= 1000 or any(type(scope) is not str
            or not re.fullmatch(r'projects/[a-z][a-z0-9-]{4,61}[a-z0-9]', scope) for scope in scopes)
            or len(set(scopes)) != len(scopes)
            or any(options.get(k) for k in ('all_projects', 'discover_projects', 'all_hierarchy'))):
        raise ValueError('explicit_projects_without_discovery_required')
    refs = options[OPTION]
    if type(refs) is not list or not 1 <= len(refs) <= MAX_IMAGES:
        raise ValueError('bounded_registry_selection_required')
    seen=set()
    for reference in refs:
        if type(reference) is not str or reference.startswith('https://') or reference != reference.lower():
            raise ValueError('literal_immutable_registry_reference_required')
        uri, repository, digest, image_id=parse(reference)
        if '/'.join(repository.split('/')[:2]) not in scopes or reference in seen:
            raise ValueError('foreign_or_duplicate_registry_image')
        seen.add(reference)
    return list(refs)


def grouped_selections(options, scopes):
    """Partition validated immutable references by their exact explicit project."""
    groups = {scope: [] for scope in scopes}
    for reference in selections(options, scopes):
        _, repository, _, _ = parse(reference)
        groups['/'.join(repository.split('/')[:2])].append(reference)
    return groups
