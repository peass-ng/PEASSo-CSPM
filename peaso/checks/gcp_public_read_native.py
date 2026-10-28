"""Bounded Storage read-grant declaration closure; no object contents or requests."""
from . import result
from .facts import Unavailable, complete_items, get, list_of_objects
from .gcp_ports_iam import project_roots

READ_ROLES = frozenset({'roles/owner', 'roles/editor', 'roles/viewer',
    'roles/storage.objectViewer', 'roles/storage.objectUser', 'roles/storage.objectAdmin', 'roles/storage.admin',
    'roles/storage.legacyObjectReader', 'roles/storage.legacyObjectOwner'})
NONREAD_ROLES = frozenset({'roles/storage.objectCreator', 'roles/storage.legacyBucketReader',
                          'roles/storage.legacyBucketWriter', 'roles/storage.legacyBucketOwner'})
PUBLIC = frozenset({'allUsers', 'allAuthenticatedUsers'})


def inherited_read(item, index):
    """Extend a completed local IAM/ACL read audit with a complete native hierarchy."""
    name = get(item, 'name', str)
    roots = project_roots(item, index)
    grants = []
    unresolved = False
    for policy in roots:
        for binding in list_of_objects(get(policy, 'bindings', list)):
            members = get(binding, 'members', list)
            if any(not isinstance(member, str) for member in members):
                raise Unavailable('malformed inherited Storage principal')
            if not PUBLIC.intersection(members):
                continue
            role = get(binding, 'role', str)
            if 'condition' in binding or role not in READ_ROLES | NONREAD_ROLES:
                unresolved = True
            elif role in READ_ROLES:
                grants.append({'scope': get(policy, 'name', str), 'role': role})
    if grants:
        return result(True, bucket=name, inherited_public_read_grants=grants,
                      semantics='Unconditional public read declarations; runtime access and PAP are separate')
    if unresolved:
        raise Unavailable('conditional or custom inherited public read grant unresolved')
    rows = complete_items(index, 'bucket_effective_iam')
    matches = [row for row in rows if get(row, 'name', str) == name]
    if len(matches) != 1 or get(matches[0], 'resolutionComplete', bool) is not True:
        raise Unavailable('native Storage hierarchy or managed-folder coverage incomplete')
    return result(False, bucket=name, policy_scopes=get(matches[0], 'policyScopes', list),
                  semantics='Complete collected local/ancestor IAM and active ACL read-grant declarations; no object content retrieval')
