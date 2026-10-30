"""Native category groups constrain configured operation absence, never delivery."""
from copy import deepcopy
from urllib.parse import urlsplit,parse_qs
import json
import pytest
from peaso.collectors import azure,collect_live
from tests.test_peaso_azure_audit_storage_history import requirements as historical_requirements, evaluate as historical_evaluate
from tests.test_peaso_azure_audit_storage_native import API,ACCOUNT,SERVICE,SCOPE,BASE,options,native

class GroupAPI(API):
    def __init__(self,mode):super().__init__('absent');self.group_mode=mode
    def request(self,url,*,body=None,audience=azure.ARM):
        path=urlsplit(url).path;mode=self.group_mode
        if path==BASE:
            if mode=='categories_denied':raise azure.AzureReadError('inert_denied',403)
            response=super().request(url,body=body,audience=audience)
            for row in response['value']:row['properties']['categoryGroups']=['audit','allLogs']
            if mode=='enabled_subset':
                for row in response['value']:
                    if row['name']!='StorageRead':row['properties']['categoryGroups']=['allLogs']
            if mode=='group_membership_missing':response['value'][0]['properties'].pop('categoryGroups')
            if mode=='duplicate_group':response['value'][0]['properties']['categoryGroups']=['audit','audit']
            if mode=='foreign_child':response['value'][0]['id']=response['value'][0]['id'].replace('/blobServices/default/','/blobServices/foreign/')
            return response
        if path==SERVICE+'/providers/Microsoft.Insights/diagnosticSettings':
            self.calls.append((url,deepcopy(body)))
            if mode=='diagnostics_denied':raise azure.AzureReadError('inert_denied',403)
            if mode=='diagnostics_partial' and 'page' in parse_qs(urlsplit(url).query):raise azure.AzureReadError('inert_denied',403)
            enabled=mode in ('enabled_audit','same_account_configured','enabled_subset')
            sid=SERVICE+'/providers/Microsoft.Insights/diagnosticSettings/logs'
            if mode=='foreign_account':sid=sid.replace('/storageAccounts/account/','/storageAccounts/foreign/')
            group='futureGroup' if mode=='unknown_group' else 'audit'
            props={'logs':[{'categoryGroup':group,'enabled':enabled}],
                   'workspaceId':SCOPE+'/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/sink'}
            if mode=='same_account_configured':props.pop('workspaceId');props['storageAccountId']=ACCOUNT
            values=[{'id':sid,'name':'logs','properties':props}]
            if mode=='disabled_audit_plus_read':values.append({'id':SERVICE+'/providers/Microsoft.Insights/diagnosticSettings/read',
                'name':'read','properties':{'logs':[{'category':'StorageRead','enabled':True}],
                    'workspaceId':SCOPE+'/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/sink'}})
            return {'value':values,**({'nextLink':azure.ARM+path+'?api-version='+native.VERSION+'&page=2'} if mode=='diagnostics_partial' else {})}
        return super().request(url,body=body,audience=audience)

MODES=[('disabled_audit',['read','write','delete']),('disabled_audit_plus_read',['write','delete']),
       ('enabled_audit',None),('same_account_configured',None),('group_membership_missing',None),
       ('duplicate_group',None),('foreign_child',None),('foreign_account',None),('unknown_group',None),
       ('diagnostics_denied',None),('diagnostics_partial',None),('categories_denied',None)]
@pytest.mark.parametrize('mode,missing',MODES,ids=[m for m,_ in MODES])
def test_native_group_operation_evidence(monkeypatch,mode,missing):
    api=GroupAPI(mode);monkeypatch.setattr(azure,'AzureTransport',lambda auth:api);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:api)
    connector={'provider':'azure','scopes':[SCOPE],'auth':{'method':'token','arm_token':'inert','storage_token':'inert'},'options':options('absent')}
    requirements=historical_requirements()
    assert set(requirements)=={'storage_account',native.KIND}
    snapshot=collect_live(connector,requirements)
    findings=historical_evaluate(snapshot)
    assert findings and {f['status'] for f in findings}==({'FAIL'} if missing else {'UNKNOWN'}),findings
    if missing:assert all(f['evidence']['missing_blob_access_log_operations']==missing for f in findings)
    assert 'PASS' not in {f['status'] for f in findings}
    assert api.closed
    assert all(body is None or urlsplit(url).path=='/providers/Microsoft.ResourceGraph/resources' for url,body in api.calls)
    rows=[r for c in snapshot['collections'] if c['type']==native.KIND for r in c['items']]
    if rows and mode not in ('duplicate_group','foreign_child','categories_denied'):
        assert any('categoryGroups' in c for c in rows[0]['payload']['categories'])
    assert not any(field in json.dumps(rows) for field in ('delivery_measured','sink_security_measured'))


def test_observed_audit_membership_is_not_assumed_all_operations(monkeypatch):
    # Inert API-shaped membership variant verifies no hard-coded audit universe.
    test_native_group_operation_evidence(monkeypatch,'enabled_subset',['write','delete'])
