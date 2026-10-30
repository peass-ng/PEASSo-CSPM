"""Approved audit-storage scope -> native config absence only, never delivery PASS."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
import pytest
from fastapi import HTTPException
from peaso.collectors import azure, collect_live, azure_audit_storage_native as native
from tests.test_peaso_azure_audit_storage_history import requirements as historical_requirements, evaluate as historical_evaluate

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
ACCOUNT = SCOPE + '/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account'
EP = 'https://account.blob.core.windows.net/'
SERVICE = ACCOUNT + '/blobServices/default'
BASE = SERVICE + '/providers/Microsoft.Insights/diagnosticSettingsCategories'
PRIVATE = 'NEVER_RETAIN_BLOB_BODY_OR_SECRET'


def options(mode):
    now = datetime.now(timezone.utc)
    result = {'concurrency':1, 'retries':1, 'compliance_parameters':{native.NAMESPACE:{
        'status':'collected','scope':SCOPE,'authorized_by':'security-owner','document_id':'audit-storage-classification',
        'observed_at':(now-timedelta(hours=1)).isoformat(), 'expires_at':(now+timedelta(hours=1)).isoformat(),
        'audit_account_ids':[ACCOUNT]}}}
    owner = result['compliance_parameters'][native.NAMESPACE]
    if mode == 'expired': owner['expires_at'] = (now-timedelta(minutes=1)).isoformat()
    if mode == 'future': owner['observed_at'] = (now+timedelta(minutes=1)).isoformat()
    if mode == 'no_classification': result.pop('compliance_parameters')
    if mode == 'unclassified': owner['audit_account_ids'] = [ACCOUNT + 'other']
    return result


class API:
    tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'
    def __init__(self,mode): self.mode=mode; self.calls=[]; self.closed=False
    def close(self): self.closed=True
    def allow_storage(self,endpoint,account,service): assert (endpoint,account,service)==(EP.rstrip('/'),'account','blob') or (endpoint,account,service)==(EP,'account','blob')
    def request_xml(self,url):
        self.calls.append((url,None))
        assert urlsplit(url).netloc=='account.blob.core.windows.net'
        assert parse_qs(urlsplit(url).query)=={'restype':['service'],'comp':['properties']}
        if self.mode == 'analytics_denied': raise azure.AzureReadError('fixture_denied',403)
        result = dict.fromkeys(native.OPERATIONS,False)
        if self.mode == 'analytics_read': result['read']=True
        if self.mode == 'analytics_delete': result['delete']=True
        if self.mode == 'analytics_type': result['write']=0
        return result
    def request(self,url,*,body=None,audience=azure.ARM):
        assert audience==azure.ARM
        self.calls.append((url,deepcopy(body))); path=urlsplit(url).path
        if body is not None:
            assert path=='/providers/Microsoft.ResourceGraph/resources'
            return {'data':[],'resultTruncated':False}
        parent={'id':ACCOUNT,'type':'Microsoft.Storage/storageAccounts','name':'account','etag':'v1',
            'properties':{'primaryEndpoints':{'blob':EP}},'clientSecret':PRIVATE}
        if path==SCOPE+'/providers/Microsoft.Storage/storageAccounts':
            return {'value':[parent,parent] if self.mode=='duplicate_account' else [parent]}
        if path==ACCOUNT: return parent
        if path==SERVICE+'/providers/Microsoft.Insights/diagnosticSettings':
            if self.mode=='diagnostics_denied': raise azure.AzureReadError('fixture_denied',403)
            if self.mode=='diagnostics_partial' and 'page' in parse_qs(urlsplit(url).query): raise azure.AzureReadError('fixture_denied',403)
            values=[]
            if self.mode in ('configured','disabled_setting','diagnostics_partial'):
                values=[{'id':SERVICE+'/providers/Microsoft.Insights/diagnosticSettings/logs','name':'logs',
                    'properties':{'workspaceId':SCOPE+'/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/sink',
                        'logs':[{'category':'StorageRead','enabled':self.mode!='disabled_setting'}]}}]
            return {'value':values,**({'nextLink':azure.ARM+path+'?api-version=2021-05-01-preview&page=2'} if self.mode=='diagnostics_partial' else {})}
        if path==BASE:
            if self.mode=='categories_denied': raise azure.AzureReadError('fixture_denied',403)
            if self.mode=='categories_partial' and 'page' in parse_qs(urlsplit(url).query): raise azure.AzureReadError('fixture_denied',403)
            values=[{'id':BASE+'/'+name,'name':name,'properties':{'categoryType':'Logs'}} for name in sorted(native.CATEGORIES)]
            if self.mode=='missing_category': values.pop()
            if self.mode=='foreign_category': values[0]['id']=BASE.replace('/default/','/foreign/')+'/'+values[0]['name']
            if self.mode=='duplicate_category': values.append(deepcopy(values[0]))
            if self.mode=='malformed_category': values[0]['properties']['categoryType']='FutureLogs'
            if self.mode=='no_categories': values=[]
            if self.mode=='category_page_limit':
                page=int(parse_qs(urlsplit(url).query).get('page',['0'])[0])
                return {'value':values if page==0 else [], 'nextLink':azure.ARM+path+'?api-version='+native.VERSION+'&page='+str(page+1)}
            return {'value':values,**({'nextLink':azure.ARM+path+'?api-version='+native.VERSION+'&page=2'} if self.mode=='categories_partial' else {})}
        return {'value':[]}


@pytest.mark.parametrize('mode,expected', [('absent','FAIL'), *[(m,'FAIL') for m in ('configured','disabled_setting','analytics_read','analytics_delete')],
    *[(mode,'UNKNOWN') for mode in ('diagnostics_denied','diagnostics_partial',
        'analytics_denied','analytics_type','categories_denied',
        'categories_partial','missing_category','foreign_category','duplicate_category','malformed_category',
        'no_categories','category_page_limit','expired','future','no_classification','unclassified','duplicate_account')]])
def test_normal_hosted_config_absence_only(monkeypatch,mode,expected):
    from peaso.server.validation import validate_connector
    api=API(mode); monkeypatch.setattr(azure,'AzureTransport',lambda auth:api);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:api)
    configured=options(mode); auth={'method':'token','arm_token':'inert','storage_token':'inert'}
    validate_connector('azure',auth,configured,SimpleNamespace(auth_mode='cognito'))
    connector={'provider':'azure','scopes':[SCOPE],'auth':auth,'options':configured}
    required=historical_requirements()
    assert set(required)=={'storage_account',native.KIND}
    snapshot=collect_live(connector,required)
    findings=historical_evaluate(snapshot)
    assert findings and {f['status'] for f in findings}=={expected},findings
    assert api.closed
    evidence = next(c for c in snapshot['collections'] if c['type']==native.KIND)
    if expected=='UNKNOWN' and evidence['status']=='collected':
        assert all(f['evidence'].get('reason')=='native audit classification, logging configuration or actual delivery unresolved' for f in findings)
    assert not any('signIns' in url or '/keys/' in url or '/secrets/' in url for url,body in api.calls)
    assert len([u for u,b in api.calls if urlsplit(u).path==SERVICE+'/providers/Microsoft.Insights/diagnosticSettings'])==(2 if mode=='diagnostics_partial' else 1)
    assert len([u for u,b in api.calls if urlsplit(u).netloc=='account.blob.core.windows.net'])<=1
    assert not any(any('/'+kind.lower() in url.lower() for kind in ('applicationGateways','loadBalancers','managedClusters','databaseAccounts')) for url,body in api.calls)
    import json
    assert PRIVATE not in json.dumps(snapshot)
    for env in snapshot['collections']:
        if env['type']==native.KIND:
            for row in env['items']:
                assert row['_provenance']['captured_at']==snapshot['created_at']
                assert 'policy_approved' not in row['_provenance'] and 'delivery_measured' not in json.dumps(row)


@pytest.mark.parametrize('field,value',[('captured',True),('delivery_measured',True),('is_audit_account',True),
    ('audit_account_ids',[]),('audit_account_ids',[ACCOUNT,ACCOUNT.upper()]),('audit_account_ids',[ACCOUNT+'../foreign']),
    ('audit_account_ids',[ACCOUNT.replace('11111111','33333333')])])
def test_intake_accepts_classification_not_observed_outcomes(field,value):
    from peaso.server.validation import validate_connector
    configured=options('absent'); configured['compliance_parameters'][native.NAMESPACE][field]=value
    with pytest.raises(HTTPException):
        validate_connector('azure',{'method':'token','arm_token':'inert'},configured,SimpleNamespace(auth_mode='cognito'))
