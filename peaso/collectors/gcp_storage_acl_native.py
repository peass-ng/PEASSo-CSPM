"""Native Storage ACL metadata and complete public-principal IAM grant closure.

No object content, media URL, object name or private ACL principal is retained.
Public access prevention never erases raw public grants from these hygiene checks.
"""
from __future__ import annotations
from hashlib import sha256
import re
from urllib.parse import quote

NATIVE_TYPES=frozenset({'bucket_acl','object_acl','bucket_effective_iam'})
READ_ROLES={'roles/storage.objectViewer','roles/storage.legacyBucketReader','roles/storage.legacyObjectReader','roles/viewer'}
WRITE_ROLES={'roles/storage.objectCreator','roles/storage.objectAdmin','roles/storage.admin','roles/owner','roles/editor','roles/storage.legacyBucketWriter','roles/storage.legacyObjectOwner'}
PUBLIC={'allUsers','allAuthenticatedUsers'}


def _error(code):
    from .gcp import ReadError
    return ReadError('unavailable',code)


def _hash(value):
    try:return sha256(value.encode('utf-8')).hexdigest()
    except UnicodeError:raise _error('storage_metadata_invalid_utf8')


def _parents(collector,scope):
    from .gcp_compliance_wave import complete_parent
    parent=complete_parent(collector,'bucket',scope)
    seen=set()
    for row in parent['items']:
        name=row.get('name')
        if not isinstance(name,str) or not re.fullmatch(r'[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]',name) or name in seen:
            raise _error('storage_bucket_identity_unresolved')
        seen.add(name)
    return parent


def _uniform(bucket):
    config=bucket.get('iamConfiguration')
    if not isinstance(config,dict) or not isinstance(config.get('uniformBucketLevelAccess'),dict):
        raise _error('storage_uniform_acl_state_unresolved')
    value=config['uniformBucketLevelAccess'].get('enabled')
    if type(value) is not bool:raise _error('storage_uniform_acl_state_unresolved')
    return value


def _acl(raw,bucket,object_ref=None,object_name=None,generation=None):
    if raw.get('bucket',bucket)!=bucket or object_name is not None and raw.get('object',object_name)!=object_name:
        raise _error('storage_acl_owner_mismatch')
    if generation is not None and 'generation' in raw and str(raw['generation'])!=generation:
        raise _error('storage_object_acl_generation_mismatch')
    entity,role=raw.get('entity'),raw.get('role')
    if not isinstance(entity,str) or not entity or role not in (('OWNER','READER') if object_ref else ('OWNER','WRITER','READER')):
        raise _error('storage_acl_entry_malformed')
    identity=entity if entity in PUBLIC else 'sha256:'+_hash(entity)
    name=bucket+'/acl/'+_hash(entity) if object_ref is None else bucket+'/objects/'+object_ref+'/acl/'+_hash(entity)
    return {'name':name,'bucket':bucket,'entity':identity,'role':role,**({'objectRef':object_ref,'generation':generation} if object_ref else {})}


def _bucket_acl(collector,scope):
    parent=_parents(collector,scope)
    for request in parent['source_requests']:yield [],request
    for bucket in parent['items']:
        if _uniform(bucket):continue
        name=bucket['name'];seen={};requests=[];pages=0
        for page,request in collector.pages('https://storage.googleapis.com/storage/v1/b/'+quote(name,safe='')+'/acl',scope,page_size_key=None):
            requests.append(request);pages+=1
            values=[]
            for raw in page:
                row=_acl(raw,name);key=row['name']
                if key in seen:raise _error('storage_duplicate_bucket_acl_entry')
                seen[key]=row;values.append(row)
            yield values,request
        with collector.lock:
            collector._storage_acl_proof[('bucket_acl',scope)][name]={
                'all_pages':True,'page_count':pages,'source_requests':requests}


def _object_acl(collector,scope):
    parent=_parents(collector,scope)
    for request in parent['source_requests']:yield [],request
    for bucket in parent['items']:
        if _uniform(bucket):continue
        name=bucket['name'];seen_objects=set();seen_acls=set();requests=[];pages=0
        params={'projection':'full','versions':'true','fields':'items(bucket,name,generation,acl(bucket,object,generation,entity,role)),nextPageToken'}
        for page,request in collector.pages('https://storage.googleapis.com/storage/v1/b/'+quote(name,safe='')+'/o',scope,params=params,page_size_key='maxResults'):
            requests.append(request);pages+=1
            values=[]
            for obj in page:
                object_name,generation=obj.get('name'),obj.get('generation')
                if obj.get('bucket')!=name or not isinstance(object_name,str) or not object_name or len(object_name.encode('utf-8',errors='surrogatepass'))>1024 or not isinstance(generation,str) or not re.fullmatch(r'[0-9]{1,20}',generation):
                    raise _error('storage_object_identity_unresolved')
                with collector.lock:
                    count=getattr(collector,'_storage_acl_objects',0)
                    if collector.max_items is not None and count>=collector.max_items:
                        raise _error('resource_limit')
                    collector._storage_acl_objects=count+1
                ref=_hash(object_name+'\0'+generation)
                if ref in seen_objects:raise _error('storage_duplicate_object_generation')
                seen_objects.add(ref)
                acls=obj.get('acl')
                if not isinstance(acls,list) or any(not isinstance(a,dict) for a in acls):
                    raise _error('storage_object_acl_not_in_full_projection')
                for raw in acls:
                    row=_acl(raw,name,ref,object_name,generation)
                    if row['name'] in seen_acls:raise _error('storage_duplicate_object_acl_entry')
                    seen_acls.add(row['name']);values.append(row)
            yield values,request
        with collector.lock:
            collector._storage_acl_proof[('object_acl',scope)][name]={
                'all_pages':True,'all_objects':True,'all_versions':True,
                'projection':'full','page_count':pages,'object_count':len(seen_objects),
                'source_requests':requests}


def _root_policies(collector,scope):
    from .gcp_compliance_wave import complete_parent
    projects=complete_parent(collector,'project',scope)
    if len(projects['items'])!=1:raise _error('storage_project_authority_unresolved')
    project=projects['items'][0];aliases={project.get('projectId'),str(project.get('name','')).split('/')[-1]}
    if scope.split('/')[1] not in aliases:raise _error('storage_project_scope_mismatch')
    ancestry=collector.ancestry.get(scope)
    if not isinstance(ancestry,list) or not ancestry:raise _error('storage_iam_ancestry_unavailable')
    chain=[];project_seen=False;org_seen=False
    for item in ancestry:
        resource=item.get('resourceId',{}) if isinstance(item,dict) else {};kind,rid=resource.get('type'),resource.get('id')
        if kind=='project':
            if project_seen or chain or rid not in aliases:raise _error('storage_iam_project_ancestry_mismatch')
            project_seen=True
        elif kind in ('folder','organization') and project_seen and isinstance(rid,str) and rid.isdigit() and not org_seen:
            node=kind+'s/'+rid
            if node in chain:raise _error('storage_iam_ancestry_cycle')
            chain.append(node);org_seen=kind=='organization'
        else:raise _error('storage_iam_ancestry_malformed')
    if not project_seen:raise _error('storage_iam_project_ancestry_missing')
    policies=[]
    for node in [scope,*chain]:
        parent=complete_parent(collector,'iam_policy',node)
        roots=[p for p in parent['items'] if p.get('name')==node]
        if len(roots)!=1 or roots[0].get('_provenance',{}).get('representation')!='full':
            raise _error('storage_iam_root_policy_not_full')
        policies.append((node,roots[0]))
    return policies


def _public_grants(policy):
    if not isinstance(policy,dict):raise _error('storage_iam_policy_malformed')
    bindings=policy.get('bindings')
    if not isinstance(bindings,list):raise _error('storage_iam_bindings_unavailable')
    access=write=False
    for binding in bindings:
        if not isinstance(binding,dict) or not isinstance(binding.get('role'),str) or not binding['role'] or not isinstance(binding.get('members'),list) or any(not isinstance(m,str) or not m for m in binding['members']) or len(binding['members'])!=len(set(binding['members'])):
            raise _error('storage_iam_binding_malformed')
        if 'condition' in binding:raise _error('storage_conditional_iam_unresolved')
        if not PUBLIC.intersection(binding['members']):continue
        role=binding.get('role')
        if role not in READ_ROLES|WRITE_ROLES:raise _error('storage_public_role_permissions_unresolved')
        access=True;write|=role in WRITE_ROLES
    return access,write


def _effective(collector,scope):
    parent=_parents(collector,scope)
    if not parent['items']:
        for request in parent['source_requests']:yield [],request
        return
    policies=_root_policies(collector,scope)
    requests=set(parent['source_requests'])
    inherited_access=inherited_write=False
    for node,policy in policies:
        access,write=_public_grants(policy);inherited_access|=access;inherited_write|=write
        requests.update(policy.get('_provenance',{}).get('source_requests',[]))
    for request in sorted(requests):yield [],request
    for bucket in parent['items']:
        coverage=bucket.get('_coverage',{}).get('iamPolicy',{})
        if coverage.get('status')!='collected':raise _error('storage_bucket_iam_unavailable')
        access,write=_public_grants(bucket.get('iamPolicy',{}))
        for request in coverage.get('source_requests',[]):yield [],request
        hierarchy=bucket.get('hierarchicalNamespace')
        if hierarchy is not None and (not isinstance(hierarchy,dict) or hierarchy.get('enabled') is not False):
            raise _error('storage_hierarchical_folder_iam_unresolved')
        if _uniform(bucket):
            for folders,request in collector.pages('https://storage.googleapis.com/storage/v1/b/'+quote(bucket['name'],safe='')+'/managedFolders',scope,
                page_size_key='maxResults'):
                yield [],request
                if folders:raise _error('storage_managed_folder_iam_unresolved')
        row={'name':bucket['name'],'resolutionComplete':True,'publicAccess':access or inherited_access,'publicWrite':write or inherited_write,
            'policyScopes':[node for node,p in policies], 'semantics':'Complete direct and ancestor IAM public-principal grant union; PAP does not erase raw grants'}
        for request in parent['source_requests'][-1:]:yield [row],request


def collect(collector):
    from .gcp import ReadError
    from .gcp_bucket_acl_evidence_native import materialize
    from collections import defaultdict
    collector._storage_acl_proof=defaultdict(dict)
    jobs=[]
    for scope in collector.scopes:
        if not scope.startswith('projects/'):continue
        for kind,fetch in (('bucket_acl',_bucket_acl),('object_acl',_object_acl),('bucket_effective_iam',_effective)):
            if kind in collector.needed:jobs.append((kind,scope,'storage',lambda fetch=fetch,scope=scope:fetch(collector,scope)))
    collector.run_jobs(jobs)
    for (kind,scope),collection in collector.collections.items():
        if kind in NATIVE_TYPES:
            parent=collector.collections.get(('bucket',scope),{})
            collection['parent_inventory']='bucket'
            collection['covered_parent_ids']=[b['name'] for b in parent.get('items',[])] if collection['status'] in ('collected','empty') else []
            disabled=[]
            for b in parent.get('items',[]):
                try:
                    if _uniform(b):disabled.append(b['name'])
                except ReadError:continue
            collection['acl_disabled_parent_ids']=disabled
            if kind in ('bucket_acl','object_acl'):
                collection['per_parent_coverage']=collector._storage_acl_proof.get((kind,scope),{})
    for scope in collector.scopes:
        if scope.startswith('projects/'):
            materialize(collector,scope)
