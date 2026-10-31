"""Scope-complete ARM diagnostic routes to existing workspaces; no log contents."""
import copy
import re

ARM = 'https://management.azure.com'
VERSION = '2021-05-01-preview'
NATIVE_TYPES = {'resource_diagnostic_setting', 'azure_diagnostic_eligible_resource'}
# Every resource listed by ARM is asked for its diagnostic categories at its own
# identity. Storage accounts also log through service children that /resources
# omits, so those children are listed explicitly below.
CHECK = 'azure_log_analytics_workspace_monitor_diagnostic_setting_with_appropriate_categories_48f6b2b'
SEGMENT = r'[^/?#%\s\\]+'
RESOURCE = (r'/subscriptions/'+SEGMENT+r'/resourceGroups/'+SEGMENT+r'/providers/'+SEGMENT+
            r'(?:/'+SEGMENT+r'/'+SEGMENT+r')+'+r'(?:/providers/'+SEGMENT+r'(?:/'+SEGMENT+r'/'+SEGMENT+r')+)*')
STORAGE_VERSION = '2023-05-01'
STORAGE_SERVICES = {'blobServices':'StorageBlobLogs','fileServices':'StorageFileLogs','queueServices':'StorageQueueLogs','tableServices':'StorageTableLogs'}
RETENTION_CHECK = 'azure.cis.monitor_resource_logging_services_support_it'


def proof(operation):
    return {'read_only':True,'representation':'full','source_operation':operation}


DESTINATIONS = {
    'workspaceId': ('Microsoft.OperationalInsights/workspaces', '2023-09-01'),
    'storageAccountId': ('Microsoft.Storage/storageAccounts', '2023-05-01'),
    'eventHubAuthorizationRuleId': ('Microsoft.EventHub/namespaces', None),
}


def identity(value, pattern):
    if (not isinstance(value, str) or not re.fullmatch(pattern, value, re.I)
            or any(ord(c) <= 32 or ord(c) == 127 for c in value)
            or any(part in ('.', '..') for part in value.split('/'))):
        raise ValueError('diagnostic metadata identity malformed or foreign')
    return value


def resource_kind(rid):
    """ARM resource type of an identity, e.g. microsoft.compute/virtualmachines/extensions."""
    suffix = re.split('/providers/', rid, flags=re.I)[-1].split('/')
    return (suffix[0]+'/'+'/'.join(suffix[1::2])).casefold()


def unsupported_type_pages(reader, request, url, kind, unsupported):
    """Category pages; Azure answers 400 ResourceTypeNotSupported for a resource type
    that has no diagnostic settings, so that type holds no resource logs to route."""
    from .azure import _arm_error_code, _status_code
    started = False
    try:
        for page in reader.pages(request, url):
            started = True
            yield page
    except Exception as exc:
        code = _arm_error_code(exc) or getattr(exc, 'code', None)
        if started or _status_code(exc) not in (400, '400') or code != 'ResourceTypeNotSupported':
            raise
        unsupported.add(kind)


def collect(reader, request, scopes, wanted):
    if not NATIVE_TYPES.intersection(wanted):
        return
    from .azure import AzureReadError
    retention = 'azure_diagnostic_eligible_resource' in wanted
    primary = 'resource_diagnostic_setting' if 'resource_diagnostic_setting' in wanted else 'azure_diagnostic_eligible_resource'
    for scope in scopes:
        def fetch(scope=scope):
            # ARM /resources supplies the actual selected resource universe;
            # never assume the subset already selected by another check is all.
            resources, seen = [], set()
            storage_accounts = []
            for page in reader.pages(request, ARM+scope+'/resources?api-version=2021-04-01&$top=1000'):
                for raw in page:
                    rid = identity(raw.get('id'), RESOURCE)
                    if not rid.casefold().startswith(scope.casefold()+'/') or rid.casefold() in seen:
                        raise ValueError('duplicate or foreign diagnostic resource')
                    resource_type = raw.get('type')
                    suffix = re.split('/providers/', rid, flags=re.I)[-1]
                    match = re.fullmatch('('+SEGMENT+r')((?:/'+SEGMENT+r'/'+SEGMENT+r')+)', suffix, re.I)
                    if not isinstance(resource_type, str) or match is None:
                        raise ValueError('diagnostic resource identity/type mismatch')
                    parts = match.group(2).strip('/').split('/')
                    native_type = match.group(1)+'/'+'/'.join(parts[::2])
                    if native_type.casefold() != resource_type.casefold():
                        raise ValueError('diagnostic resource identity/type mismatch')
                    seen.add(rid.casefold())
                    if reader.budget.max_items is not None and len(resources) >= reader.budget.max_items:
                        raise AzureReadError('resource_limit')
                    resources.append(rid)
                    if resource_type.casefold()=='microsoft.storage/storageaccounts':storage_accounts.append(rid)
            for account in storage_accounts:
                full = reader.call(request, ARM+account+'?api-version='+STORAGE_VERSION)
                if (not isinstance(full,dict) or str(full.get('id','')).casefold()!=account.casefold()
                        or str(full.get('type','')).casefold()!='microsoft.storage/storageaccounts'
                        or full.get('kind') not in {'Storage','StorageV2','BlobStorage','FileStorage','BlockBlobStorage'}):
                    raise ValueError('storage account native identity or kind unresolved')
                for segment in STORAGE_SERVICES:
                    children=set()
                    for page in reader.pages(request, ARM+account+'/'+segment+'?api-version='+STORAGE_VERSION):
                        for raw in page:
                            child=identity(raw.get('id'),re.escape(account+'/'+segment)+r'/default')
                            if (str(raw.get('type','')).casefold()!=('microsoft.storage/storageaccounts/'+segment).casefold()
                                    or raw.get('name')!='default' or child.casefold()in children or child.casefold()in seen):
                                raise ValueError('foreign or duplicate storage service')
                            children.add(child.casefold());seen.add(child.casefold())
                            if reader.budget.max_items is not None and len(resources)>=reader.budget.max_items:
                                raise AzureReadError('resource_limit')
                            resources.append(child)
            unsupported = set()
            for rid in resources:
                prefix = rid+'/providers/Microsoft.Insights/'
                categories, category_ids, names = [], set(), set()
                kind_of = resource_kind(rid)
                if kind_of in unsupported:
                    continue
                for page in unsupported_type_pages(reader, request, ARM+prefix+'diagnosticSettingsCategories?api-version='+VERSION, kind_of, unsupported):
                    for raw in page:
                        cid = identity(raw.get('id'), re.escape(prefix)+r'diagnosticSettingsCategories/'+SEGMENT)
                        props = raw.get('properties')
                        name = raw.get('name')
                        if (not isinstance(props, dict) or props.get('categoryType') not in ('Logs', 'Metrics')
                                or not isinstance(name, str) or not name or cid.rsplit('/',1)[-1] != name
                                or cid.casefold() in category_ids or name in names):
                            raise ValueError('malformed or duplicate diagnostic category')
                        category_ids.add(cid.casefold());names.add(name)
                        groups = props.get('categoryGroups', [])
                        if not isinstance(groups, list) or any(not isinstance(g,str) or not g for g in groups) or len(groups)!=len(set(groups)):
                            raise ValueError('diagnostic category groups malformed')
                        categories.append({'id':cid,'name':name,'parent_id':rid,'properties':{'categoryType':props['categoryType'],'categoryGroups':copy.deepcopy(groups)},'_provenance':proof('DiagnosticSettingsCategory_List')})
                # A successful native discovery with no Logs means this resource
                # cannot emit resource logs. Errors/unsupported responses never
                # become this empty discovery; the aggregate remains incomplete.
                if not any(c['properties']['categoryType']=='Logs' for c in categories):
                    continue
                settings, setting_ids = [], set()
                for page in reader.pages(request, ARM+prefix+'diagnosticSettings?api-version='+VERSION):
                    for raw in page:
                        sid = identity(raw.get('id'), re.escape(prefix)+r'diagnosticSettings/'+SEGMENT)
                        props = raw.get('properties')
                        if not isinstance(props,dict) or sid.casefold() in setting_ids:
                            raise ValueError('malformed or duplicate diagnostic setting')
                        setting_ids.add(sid.casefold())
                        logs = props.get('logs')
                        if not isinstance(logs,list) or any(not isinstance(log,dict) for log in logs):
                            raise ValueError('diagnostic log routes missing')
                        projected = {'logs':[{k:copy.deepcopy(v) for k,v in log.items() if k in ('enabled','category','categoryGroup')} for log in logs]}
                        if 'logAnalyticsDestinationType' in props:projected['logAnalyticsDestinationType']=copy.deepcopy(props['logAnalyticsDestinationType'])
                        destinations=[]
                        for field,(kind,version) in DESTINATIONS.items():
                            target=props.get(field)
                            # ARM optional destinations may be absent, null or
                            # empty; those are no declared destination, not proof.
                            if target in (None,''):
                                continue
                            if field=='eventHubAuthorizationRuleId':
                                pattern=r'/subscriptions/'+SEGMENT+r'/resourceGroups/'+SEGMENT+r'/providers/Microsoft.EventHub/namespaces/'+SEGMENT+r'/authorizationRules/'+SEGMENT
                            else:
                                pattern=r'/subscriptions/'+SEGMENT+r'/resourceGroups/'+SEGMENT+r'/providers/'+re.escape(kind)+'/'+SEGMENT
                            identity(target,pattern)
                            if not target.casefold().startswith(scope.casefold()+'/'):
                                raise ValueError('diagnostic destination outside selected subscription')
                            projected[field]=target
                            if field!='workspaceId':
                                # Frozen consumer validates every declared sink.
                                # Unsupported sink kinds are unresolved, never
                                # assumed existent or silently discarded.
                                raise ValueError('non-workspace diagnostic destination unresolved')
                            workspace=reader.call(request, ARM+target+'?api-version='+version)
                            if (not isinstance(workspace,dict) or str(workspace.get('id','')).casefold()!=target.casefold()
                                    or str(workspace.get('type','')).casefold()!=kind.casefold()):
                                raise ValueError('workspace GET identity or type differs')
                            destinations.append({'id':target,'exists':True})
                        setting={'id':sid,'parent_id':rid,'properties':projected,'destinationEvidence':destinations,
                            '_coverage':{'destinationEvidence':{'status':'collected'if destinations else'empty'}},
                            '_provenance':proof('DiagnosticSettings_List')}
                        if retention:
                            try:
                                exact=reader.call(request,ARM+sid+'?api-version='+VERSION)
                                if (not isinstance(exact,dict) or str(exact.get('id','')).casefold()!=sid.casefold()
                                        or not isinstance(exact.get('properties'),dict)):
                                    raise ValueError('diagnostic setting GET identity unavailable')
                                ep=exact['properties'];ep_logs=ep.get('logs')
                                if not isinstance(ep_logs,list) or any(not isinstance(log,dict)for log in ep_logs):
                                    raise ValueError('diagnostic setting GET logs unavailable')
                                normalized={'logs':[{k:copy.deepcopy(v)for k,v in log.items()if k in ('enabled','category','categoryGroup')}for log in ep_logs]}
                                for field in DESTINATIONS:
                                    if ep.get(field) not in (None,''):normalized[field]=ep[field]
                                if 'logAnalyticsDestinationType'in ep:normalized['logAnalyticsDestinationType']=ep['logAnalyticsDestinationType']
                                if normalized!=projected:raise ValueError('diagnostic setting changed between LIST and GET')
                                setting['_provenance']=proof('DiagnosticSettings_Get')
                                evidence=[]
                                workspace=projected.get('workspaceId')
                                for category in categories:
                                    name=category['name']
                                    if category['properties']['categoryType']!='Logs':continue
                                    enabled=False
                                    for log in projected['logs']:
                                        if type(log.get('enabled'))is not bool:raise ValueError('diagnostic route enabled flag unavailable')
                                        enabled |= log['enabled'] and (log.get('category')==name or log.get('categoryGroup')in category['properties']['categoryGroups'])
                                    if not enabled or workspace is None:continue
                                    mode=projected.get('logAnalyticsDestinationType')
                                    segment=rid.split('/')[-2].casefold()
                                    tables={key.casefold():value for key,value in STORAGE_SERVICES.items()}
                                    if segment in tables and mode=='Dedicated' and name in {'StorageRead','StorageWrite','StorageDelete'}:
                                        table=tables[segment]
                                    elif re.search(r'/providers/Microsoft.KeyVault/vaults/[^/]+$',rid,re.I) and mode in (None,'AzureDiagnostics'):
                                        table='AzureDiagnostics'
                                    else:raise ValueError('native category to table mapping unresolved')
                                    tid=workspace+'/tables/'+table
                                    raw_table=reader.call(request,ARM+tid+'?api-version=2023-09-01')
                                    if (not isinstance(raw_table,dict) or str(raw_table.get('id','')).casefold()!=tid.casefold()
                                            or raw_table.get('name')!=table or not isinstance(raw_table.get('properties'),dict)):
                                        raise ValueError('retention table identity unavailable')
                                    tp=raw_table['properties'];active=tp.get('retentionInDays');total=tp.get('totalRetentionInDays')
                                    if (tp.get('provisioningState')!='Succeeded' or tp.get('plan')not in ('Analytics','Basic')
                                            or type(active)is not int or not 4<=active<=730
                                            or type(total)is not int or not active<=total<=4383):
                                        raise ValueError('native effective retention unresolved')
                                    if 'archiveRetentionInDays'in tp and (type(tp['archiveRetentionInDays'])is not int or tp['archiveRetentionInDays']!=total-active):
                                        raise ValueError('conflicting native archive retention')
                                    evidence.append({'id':tid+'#'+name,'settingId':sid,'sinkId':workspace,'category':name,
                                        'sourceId':tid,'retentionDays':total,'retentionBasis':'table totalRetentionInDays includes archive',
                                        '_provenance':{**proof('Tables_Get'),'api_version':'2023-09-01'}})
                                setting['retentionEvidence']=evidence
                                setting['_coverage']['retentionEvidence']={'status':'collected'if evidence else'empty'}
                            except Exception as exc:
                                from .azure import _safe_error
                                status,error=_safe_error(exc)
                                setting['retentionEvidence']=[]
                                setting['_coverage']['retentionEvidence']={'status':status,'error':error}
                        settings.append(setting)
                yield [{'id':rid,'supportedCategories':categories,'categories':copy.deepcopy(categories),'diagnosticSettings':settings,
                    '_coverage':{'categories':{'status':'collected'},'supportedCategories':{'status':'collected'},'diagnosticSettings':{'status':'collected'if settings else'empty'}},
                    '_provenance':{'source_operation':'ARM resources LIST; diagnosticSettingsCategories LIST; diagnosticSettings LIST; workspace GET',
                        'read_only':True,'api_version':VERSION}}]
        reader.run([(primary,scope,'Microsoft.Insights',fetch)])
        source=reader.collections[-1]
        for kind in sorted((NATIVE_TYPES & set(wanted))-{primary}):
            reader.collections.append({**copy.deepcopy(source),'type':kind})
