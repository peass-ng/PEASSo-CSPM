"""Independent native HTTP JSON -> real GCP Transport/Collector -> engine.

Only the HTTP session and credential header supplier are synthetic. Provider
bodies contain native fields, never CASES, policy or completeness markers.
"""
from copy import deepcopy
import json
from pathlib import Path
import socket
from types import SimpleNamespace
from urllib.parse import urlsplit
import pytest
from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.snapshot import validate

PROJECT='review-project'
NUMBER='123456789012'
SCOPE='projects/'+PROJECT
INSTANCE='native-db'
DATASET='native_dataset'
TABLE='native_table'
KEY='projects/review-project/locations/us-central1/keyRings/review/cryptoKeys/data'
AUTH='synthetic-offline-header'
# 75087001 added column type/mode to the reviewed tables.get mask.
TABLE_MASK='id,tableReference,type,encryptionConfiguration,timePartitioning,rangePartitioning,expirationTime,creationTime,lastModifiedTime,labels,requirePartitionFilter,resourceTags,schema(fields(name,type,mode,fields,policyTags(names)))'
ROSTER=['gcp.claude.sql_instance.private_ip_only', 'gcp.claude.sql_instance.second_gen_no_public_ip', 'gcp.claude2.bigquery_dataset.default_cmek', 'gcp.claude2.sql_instance.only_private_ip_addresses', 'gcp.ports.bigquery_dataset_not_publicly_accessible', 'gcp.ports.bigquery_table_encrypted_with_cmk', 'gcp.ports.sql_instance_mysql_binary_log_enabled', 'gcp.ports.sql_instance_not_open_to_internet', 'gcp.ports.sql_instance_not_publicly_accessible', 'gcp.ports.sql_instance_with_no_public_ips', 'gcp.ports.sql_no_primary_address', 'gcp.ports.sql_private_ip_assignments', 'gcp.reviewed.bigquery.cmek', 'gcp.reviewed.sql.cmek', 'gcp.reviewed.sql.high_availability', 'gcp.sql.backups', 'gcp.sql.deletion_protection', 'gcp.sql.iam_database_authentication', 'gcp.sql.mysql_admin_account_posture', 'gcp.sql.no_public_ip', 'gcp.sql.restrict_authorized_networks', 'gcp_pci_bigquery_dataset_6017267cdf32', 'gcp_pci_bigquery_dataset_fb9fcc01d5b7', 'gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6', 'gcp_sql_trace3625_off']
SQL_IDS=[i for i in ROSTER if 'bigquery' not in i and i!='gcp.sql.mysql_admin_account_posture']
BQ_IDS=[i for i in ROSTER if 'bigquery' in i and 'table_' not in i]
TABLE_ID='gcp.ports.bigquery_table_encrypted_with_cmk'
USER_ID='gcp.sql.mysql_admin_account_posture'


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args,**kwargs):pytest.fail('live socket/DNS/auth discovery is forbidden')
    monkeypatch.setattr(socket.socket,'connect',blocked)
    monkeypatch.setattr(socket.socket,'connect_ex',blocked)
    monkeypatch.setattr(socket,'create_connection',blocked)
    monkeypatch.setattr(socket,'getaddrinfo',blocked)
    monkeypatch.setattr(gcp,'Credentials',blocked)
    import google.auth
    monkeypatch.setattr(google.auth,'default',blocked)


def sql(version='MYSQL_8_0',name=INSTANCE,project=PROJECT):
    obj={'kind':'sql#instance','name':name,'project':project,
        'selfLink':f'https://sqladmin.googleapis.com/sql/v1beta4/projects/{project}/instances/{name}',
        'region':'us-central1','databaseVersion':version,'instanceType':'CLOUD_SQL_INSTANCE','backendType':'SECOND_GEN',
        'connectionName':project+':us-central1:'+name,
        'ipAddresses':[{'type':'PRIVATE','ipAddress':'10.20.0.2'}],
        'diskEncryptionConfiguration':{'kmsKeyName':KEY},
        'settings':{'settingsVersion':'7','availabilityType':'REGIONAL','deletionProtectionEnabled':True,
            'backupConfiguration':{'kind':'sql#backupConfiguration','enabled':True,'binaryLogEnabled':True},
            'ipConfiguration':{'ipv4Enabled':False,'privateNetwork':'projects/'+project+'/global/networks/native-vpc',
                'authorizedNetworks':[]},'databaseFlags':[{'name':'cloudsql_iam_authentication','value':'on'}]}}
    if not version.startswith('MYSQL_'):
        obj['settings']['backupConfiguration'].pop('binaryLogEnabled')
        obj['settings']['databaseFlags']=[{'name':'cloudsql.iam_authentication','value':'on'}] if version.startswith('POSTGRES_') else []
    return obj


def user(name='iam-user@review-project.iam',host='10.%',kind='CLOUD_IAM_SERVICE_ACCOUNT',instance=INSTANCE,project=PROJECT):
    return {'kind':'sql#user','name':name,'host':host,'type':kind,'instance':instance,'project':project}


def dataset(project=PROJECT,name=DATASET,**fields):
    return {'kind':'bigquery#dataset','id':project+':'+name,'selfLink':f'https://bigquery.googleapis.com/bigquery/v2/projects/{project}/datasets/{name}',
        'datasetReference':{'projectId':project,'datasetId':name},'location':'us-central1','creationTime':'1700000000000',
        'lastModifiedTime':'1700000000100','access':[{'role':'OWNER','userByEmail':'owner@corp.example'}],
        'defaultEncryptionConfiguration':{'kmsKeyName':KEY},**fields}


def table(project=PROJECT,dataset_id=DATASET,name=TABLE,**fields):
    # tables.get is field-masked, so only requested native fields are present.
    return {'id':project+':'+dataset_id+'.'+name,'tableReference':{'projectId':project,'datasetId':dataset_id,'tableId':name},
        'type':'TABLE','schema':{'fields':[{'name':'record_id'}]},
        'encryptionConfiguration':{'kmsKeyName':KEY},**fields}


class Credentials:
    method='offline_explicit_native_fixture'
    credential=None
    def headers(self):return {'Authorization':'Bearer '+AUTH}
    def close(self):pass


class Response:
    def __init__(self,payload,status=200):
        self.status_code=status
        self.content=json.dumps(payload).encode()
        self.headers={}
    def json(self):return json.loads(self.content)


def native_capture(monkeypatch,*,instances=None,users=None,datasets=None,tables=None,scope=SCOPE,kinds=None,
        overrides=None,partial=None,empty=None,options=None,api_project=None):
    """Exact method/host/path/query asserted below the actual GCP Transport."""
    project=scope.split('/')[1]
    instances=deepcopy([sql()] if instances is None else instances)
    users=deepcopy(([user('sqlserver','%',kind='BUILT_IN')] if instances and all(r.get('databaseVersion','').startswith('SQLSERVER_') for r in instances) else [user()]) if users is None else users)
    datasets=deepcopy([dataset()] if datasets is None else datasets)
    tables=deepcopy([table()] if tables is None else tables)
    overrides=overrides or {}
    trace=SimpleNamespace(calls=[],routes=[],native_responses=[])
    sql_base=f'/sql/v1beta4/projects/{api_project or project}/instances'
    bq_base=f'/bigquery/v2/projects/{api_project or project}/datasets'
    def route(method,url,params,body):
        parsed=urlsplit(url)
        assert method=='GET' and body is None and parsed.scheme=='https' and not parsed.query and not parsed.fragment
        host,path=parsed.hostname,parsed.path
        assert host in ('sqladmin.googleapis.com','bigquery.googleapis.com','cloudresourcemanager.googleapis.com','compute.googleapis.com')
        page=(params or {}).get('pageToken')
        call=(host,path,page)
        trace.routes.append(call)
        if host=='sqladmin.googleapis.com':
            if path==sql_base:
                assert set(params or {})<= {'maxResults','pageToken'} and params['maxResults']==100
                payload={'kind':'sql#instancesList','items':instances}
                operation='sql-list'
            else:
                names={r['name'] for r in instances}
                assert path in {sql_base+'/'+n+'/users' for n in names},path
                assert set(params or {})<= {'pageToken'}
                payload={'kind':'sql#usersList','items':users}
                operation='sql-users'
        elif host=='bigquery.googleapis.com':
            if path==bq_base:
                assert set(params or {})<= {'all','maxResults','pageToken'} and params['all']=='true' and params['maxResults']==100
                payload={'kind':'bigquery#datasetList','datasets':[{'kind':'bigquery#dataset','id':d['id'],'datasetReference':deepcopy(d['datasetReference'])} for d in datasets]}
                operation='dataset-list'
            else:
                matches=[d for d in datasets if path==bq_base+'/'+d['datasetReference']['datasetId']]
                if matches:
                    assert len(matches)==1 and params=={'accessPolicyVersion':3,'datasetView':'FULL'}
                    payload=matches[0];operation='dataset-get'
                else:
                    parents=[d for d in datasets if path.startswith(bq_base+'/'+d['datasetReference']['datasetId']+'/tables')]
                    assert len(parents)==1,path
                    parent=parents[0]['datasetReference']['datasetId'];base=bq_base+'/'+parent+'/tables'
                    if path==base:
                        assert set(params or {})<= {'maxResults','pageToken'} and params['maxResults']==100
                        payload={'kind':'bigquery#tableList','tables':[{'kind':'bigquery#table','id':r['id'],'tableReference':deepcopy(r['tableReference']),'type':r['type']} for r in tables]}
                        operation='table-list'
                    else:
                        matches=[r for r in tables if path==base+'/'+r['tableReference']['tableId']]
                        assert len(matches)==1 and params=={'fields':TABLE_MASK}
                        payload=matches[0];operation='table-get'
        elif host=='cloudresourcemanager.googleapis.com':
            assert path=='/v3/'+scope and not params
            operation='project-get';payload={'name':'projects/'+NUMBER,'projectId':PROJECT,'state':'ACTIVE'}
        else:
            assert path=='/compute/v1/'+scope and not params
            operation='project-compute';payload={'name':PROJECT,'id':NUMBER}
        replacement=overrides.get((operation,page),overrides.get(operation))
        if callable(replacement):replacement=replacement(deepcopy(payload))
        if replacement is not None:
            return replacement if isinstance(replacement,Response) else Response(replacement)
        if page:
            assert operation==partial,call
            return Response({'error':{'code':403,'status':'PERMISSION_DENIED','message':'sensitive body not retained'}},403)
        if operation==empty:
            for key in ('items','datasets','tables'):payload.pop(key,None)
        if operation==partial:payload={**payload,'nextPageToken':'opaque-next-page'}
        return Response(payload)
    class Session:
        auth=None
        def request(self,method,url,*,params,json,headers,timeout,allow_redirects):
            assert headers=={'Authorization':'Bearer '+AUTH} and allow_redirects is False and 1<=timeout<=120
            trace.calls.append({'method':method,'url':url,'params':deepcopy(params),'body':deepcopy(json)})
            response=route(method,url,params,json)
            trace.native_responses.append({'method':method,'url':url,'params':deepcopy(params),
                'http_status':response.status_code,'body':response.json()})
            return response
        def close(self):pass
    opts={'inventories':kinds or ['sql_instance'],'include_inherited':False,'metrics_scopes':False,'concurrency':1,'page_size':100,'retries':0,**(options or {})}
    transport=gcp.Transport(Credentials(),opts)
    session=Session();monkeypatch.setattr(transport,'_session',lambda:session)
    connector={'provider':'gcp','scopes':[scope],'options':opts}
    collector=gcp.GCPCollector(connector,transport=transport)
    snapshot=collector.collect()
    assert validate(snapshot)==snapshot
    trace.transport,trace.collector=transport,collector
    return snapshot,trace


def results(snapshot,cid):return evaluate_snapshot(snapshot,checks=[cid])['findings']
def resource_results(snapshot,cid):return [r for r in results(snapshot,cid) if 'native_resource_id' in r]
def assert_one(snapshot,cid,expected):
    rows=resource_results(snapshot,cid)
    assert len(rows)==1 and rows[0]['status']==expected,results(snapshot,cid)


def sql_case(cid,good=True):
    obj=sql()
    if cid=='gcp_sql_trace3625_off':
        obj=sql('SQLSERVER_2019_STANDARD');obj['settings']['databaseFlags']=[{'name':'3625 (trace flag)','value':'off' if good else 'on'}]
    elif cid=='gcp.reviewed.sql.high_availability':obj['settings']['availabilityType']='REGIONAL' if good else 'ZONAL'
    elif cid=='gcp.reviewed.sql.cmek':
        if not good:obj.pop('diskEncryptionConfiguration')
    elif cid=='gcp.sql.backups':
        obj['settings']['backupConfiguration']['enabled']=good
        if not good:obj['settings']['backupConfiguration']['binaryLogEnabled']=False
    elif cid=='gcp.sql.deletion_protection':obj['settings']['deletionProtectionEnabled']=good
    elif cid=='gcp.ports.sql_instance_mysql_binary_log_enabled':obj['settings']['backupConfiguration']['binaryLogEnabled']=good
    elif cid=='gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6':obj['settings']['databaseFlags'][0]['value']='on' if good else 'off'
    elif cid in ('gcp.sql.restrict_authorized_networks','gcp.ports.sql_instance_not_open_to_internet'):
        obj['settings']['ipConfiguration']['authorizedNetworks']=[{'name':'selected','value':'192.0.2.0/24' if good else '0.0.0.0/0'}]
    elif cid!='gcp.sql.iam_database_authentication' and not good:
        obj['ipAddresses']=[{'type':'PRIMARY','ipAddress':'203.0.113.8'}]
        obj['settings']['ipConfiguration']['ipv4Enabled']=True
    return obj


@pytest.mark.parametrize('cid',SQL_IDS,ids=SQL_IDS)
@pytest.mark.parametrize('good',[True,False],ids=['positive','negative'])
def test_native_sql_deciding_configuration(monkeypatch,cid,good):
    users=([user('sqlserver','%',kind='BUILT_IN')] if cid=='gcp_sql_trace3625_off' else [user()] if good else [user('local-admin','%',kind='BUILT_IN')])
    captured,trace=native_capture(monkeypatch,instances=[sql_case(cid,good)],users=users)
    assert_one(captured,cid,'PASS' if good else 'UNKNOWN' if cid=='gcp.reviewed.sql.cmek' else 'FAIL')
    assert len(trace.calls)==2
    assert all(r['method']=='GET' for r in trace.calls)
    assert AUTH not in json.dumps(captured)


MISSING_SQL={
 'gcp.claude.sql_instance.private_ip_only':('settings','ipConfiguration'),
 'gcp.claude.sql_instance.second_gen_no_public_ip':('backendType',),
 'gcp.claude2.sql_instance.only_private_ip_addresses':('ipAddresses',),
 'gcp.ports.sql_instance_mysql_binary_log_enabled':('settings','backupConfiguration','binaryLogEnabled'),
 'gcp.ports.sql_instance_not_open_to_internet':('settings','ipConfiguration'),
 'gcp.ports.sql_instance_not_publicly_accessible':('ipAddresses',),
 'gcp.ports.sql_instance_with_no_public_ips':('ipAddresses',),
 'gcp.ports.sql_no_primary_address':('ipAddresses',),
 'gcp.ports.sql_private_ip_assignments':('ipAddresses',),
 'gcp.reviewed.sql.cmek':('diskEncryptionConfiguration',),
 'gcp.reviewed.sql.high_availability':('settings','availabilityType'),
 'gcp.sql.backups':('settings','backupConfiguration'),
 'gcp.sql.deletion_protection':('settings','deletionProtectionEnabled'),
 'gcp.sql.no_public_ip':('settings','ipConfiguration','ipv4Enabled'),
 'gcp.sql.restrict_authorized_networks':('settings','ipConfiguration','authorizedNetworks'),
 'gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6':('settings','databaseFlags'),
 'gcp_sql_trace3625_off':('settings','databaseFlags'),
}
@pytest.mark.parametrize('cid',list(MISSING_SQL),ids=list(MISSING_SQL))
def test_native_sql_omitted_deciding_fact_stays_unresolved(monkeypatch,cid):
    obj=sql_case(cid);parent=obj
    for part in MISSING_SQL[cid][:-1]:parent=parent[part]
    parent.pop(MISSING_SQL[cid][-1])
    snapshot,_=native_capture(monkeypatch,instances=[obj])
    # APIs may omit documented empty fields. The only-private address variant
    # treats an absent ipAddresses list as []; no runtime/effective fact is inferred.
    expected='PASS' if cid=='gcp.claude2.sql_instance.only_private_ip_addresses' else 'UNKNOWN'
    assert_one(snapshot,cid,expected)


@pytest.mark.parametrize('cid',SQL_IDS+[USER_ID],ids=SQL_IDS+[USER_ID])
def test_native_sql_denied_list_cannot_prove_clean(monkeypatch,cid):
    snapshot,_=native_capture(monkeypatch,kinds=['sql_user'] if cid==USER_ID else ['sql_instance'],
        overrides={'sql-list':Response({'error':{'code':403,'status':'PERMISSION_DENIED'}},403)})
    assert results(snapshot,cid) and all(r['status'] in ('UNKNOWN','DENIED') for r in results(snapshot,cid))


@pytest.mark.parametrize('cid',SQL_IDS+[USER_ID],ids=SQL_IDS+[USER_ID])
def test_native_sql_empty_inventory_has_no_clean_resource(monkeypatch,cid):
    snapshot,_=native_capture(monkeypatch,kinds=['sql_user'] if cid==USER_ID else ['sql_instance'],empty='sql-list')
    assert not resource_results(snapshot,cid)
    assert all(r['status'] not in ('PASS','FAIL') for r in results(snapshot,cid))


@pytest.mark.parametrize('good',[True,False],ids=['positive','negative'])
def test_native_mysql_account_host_configuration(monkeypatch,good):
    snapshot,trace=native_capture(monkeypatch,kinds=['sql_user','sql_instance'],users=[user('root','10.%' if good else '%',kind='BUILT_IN')])
    assert_one(snapshot,USER_ID,'PASS' if good else 'FAIL')
    assert trace.collector.needed=={'sql_user','sql_instance'} and len(trace.calls)==2


@pytest.mark.parametrize('cid',BQ_IDS,ids=BQ_IDS)
@pytest.mark.parametrize('good',[True,False],ids=['positive','negative'])
def test_native_dataset_full_deciding_configuration(monkeypatch,cid,good):
    obj=dataset()
    if 'cmek' in cid:
        if not good:obj.pop('defaultEncryptionConfiguration')
    elif not good:obj['access']=[{'role':'READER','iamMember':'allUsers'}]
    snapshot,trace=native_capture(monkeypatch,kinds=['bigquery_dataset'],datasets=[obj])
    assert_one(snapshot,cid,'PASS' if good else 'FAIL')
    row=next(c for c in snapshot['collections'] if c['type']=='bigquery_dataset')['items'][0]
    assert row['_provenance']['representation']=='full' and '_representation' not in row
    assert row['_coverage']['datasetDetails']['status']=='collected'
    assert len(trace.calls)==2 and trace.calls[-1]['params']=={'accessPolicyVersion':3,'datasetView':'FULL'}


@pytest.mark.parametrize('cid',BQ_IDS+[TABLE_ID],ids=BQ_IDS+[TABLE_ID])
@pytest.mark.parametrize('operation',['dataset-list','dataset-get'])
def test_native_dataset_denied_dependency_cannot_prove_clean(monkeypatch,cid,operation):
    snapshot,_=native_capture(monkeypatch,kinds=['bigquery_table'] if cid==TABLE_ID else ['bigquery_dataset'],
        overrides={operation:Response({'error':{'code':403,'status':'PERMISSION_DENIED'}},403)})
    if cid==TABLE_ID and operation=='dataset-get':
        # Dataset ACL denial does not hide a successful independent tables.get.
        assert_one(snapshot,cid,'PASS')
    else:
        assert results(snapshot,cid) and all(r['status'] in ('UNKNOWN','DENIED') for r in results(snapshot,cid))


@pytest.mark.parametrize('cid',BQ_IDS+[TABLE_ID],ids=BQ_IDS+[TABLE_ID])
def test_native_dataset_empty_inventory_no_clean_resource(monkeypatch,cid):
    snapshot,_=native_capture(monkeypatch,kinds=['bigquery_table'] if cid==TABLE_ID else ['bigquery_dataset'],empty='dataset-list')
    assert not resource_results(snapshot,cid) and all(r['status'] not in ('PASS','FAIL') for r in results(snapshot,cid))


@pytest.mark.parametrize('good',[True,False],ids=['positive','negative'])
def test_native_table_explicit_cmek_value_and_real_mask(monkeypatch,good):
    obj=table()
    if not good:obj.pop('encryptionConfiguration')
    snapshot,trace=native_capture(monkeypatch,kinds=['bigquery_table'],tables=[obj])
    assert_one(snapshot,TABLE_ID,'PASS' if good else 'UNKNOWN')
    # 75087001 hydrates table IAM after the masked tables.get read.
    assert trace.collector.needed=={'bigquery_dataset','bigquery_table'} and len(trace.calls)==5
    assert trace.calls[-2]['params']=={'fields':TABLE_MASK}
    assert trace.calls[-1]['method']=='POST' and trace.calls[-1]['url'].endswith(':getIamPolicy')
    assert trace.calls[-1]['url'].startswith('https://bigquery.googleapis.com/bigquery/v2/'+SCOPE+'/datasets/')
    row=next(c for c in snapshot['collections'] if c['type']=='bigquery_table')['items'][0]
    assert row['_provenance'].get('representation')!='full' and row['_provenance']['schema_full'] is True


@pytest.mark.parametrize('operation',['table-list','table-get'])
def test_native_table_denied_read_cannot_prove_clean(monkeypatch,operation):
    snapshot,_=native_capture(monkeypatch,kinds=['bigquery_table'],overrides={operation:Response({'error':{'code':403,'status':'PERMISSION_DENIED'}},403)})
    assert results(snapshot,TABLE_ID) and all(r['status'] in ('UNKNOWN','DENIED') for r in results(snapshot,TABLE_ID))


@pytest.mark.parametrize('cid',ROSTER,ids=ROSTER)
def test_selected_check_collects_only_required_api_family(monkeypatch,cid):
    from peaso.checks import CHECKS
    check=next(c for c in CHECKS if c.id==cid)
    req={'connector':{'provider':'gcp','scopes':[SCOPE],'options':{'include_inherited':False}},'checks':[cid]}
    planned=plan_collection(req)
    assert set(planned)==set(check.dependencies)
    snapshot,trace=native_capture(monkeypatch,kinds=planned,instances=[sql_case(cid)] if cid in SQL_IDS else None)
    assert results(snapshot,cid)
    hosts={urlsplit(r['url']).hostname for r in trace.calls}
    assert hosts==({'bigquery.googleapis.com'} if 'bigquery' in cid else {'sqladmin.googleapis.com'})
    for collection in snapshot['collections']:
        for row in collection['items']:
            proof=row['_provenance'];assert proof['scope']==SCOPE and proof['source_requests']
            assert set(proof['source_requests'])<={r['id'] for r in snapshot['metadata']['source_requests']}


@pytest.mark.parametrize('cid',ROSTER,ids=ROSTER)
def test_regression_foreign_native_identity_cannot_certify_selected_resource(monkeypatch,cid):
    # A successful HTTP response alone cannot authorize a conflicting project
    # identity carried by the provider object or its detail hydration.
    if cid in SQL_IDS or cid==USER_ID:
        obj=sql_case(cid) if cid in SQL_IDS else sql()
        obj['project']='foreign-project'
        obj['selfLink']=obj['selfLink'].replace('/'+PROJECT+'/', '/foreign-project/')
        obj['connectionName']='foreign-project:us-central1:'+INSTANCE
        snapshot,_=native_capture(monkeypatch,instances=[obj],kinds=['sql_instance','sql_user'] if cid==USER_ID else ['sql_instance'],
            users=[user('root','10.%',kind='BUILT_IN')] if cid==USER_ID else [user()])
    elif cid==TABLE_ID:
        foreign=table(project='foreign-project')
        snapshot,_=native_capture(monkeypatch,kinds=['bigquery_table'],overrides={'table-get':foreign})
    else:
        foreign=dataset(project='foreign-project')
        snapshot,_=native_capture(monkeypatch,kinds=['bigquery_dataset'],overrides={'dataset-get':foreign})
    assert results(snapshot,cid) and all(r['status'] in ('UNKNOWN','DENIED') for r in results(snapshot,cid)),results(snapshot,cid)


@pytest.mark.parametrize('cid',BQ_IDS,ids=BQ_IDS)
@pytest.mark.parametrize('mismatch',['datasetId','id','selfLink'])
def test_regression_dataset_detail_exact_parent_identity(monkeypatch,cid,mismatch):
    obj=dataset()
    if mismatch=='datasetId':obj['datasetReference']['datasetId']='other_dataset'
    elif mismatch=='id':obj['id']=PROJECT+':other_dataset'
    else:obj['selfLink']=obj['selfLink'].replace(DATASET,'other_dataset')
    snapshot,_=native_capture(monkeypatch,kinds=['bigquery_dataset'],overrides={'dataset-get':obj})
    assert results(snapshot,cid) and all(r['status'] in ('UNKNOWN','DENIED') for r in results(snapshot,cid)),results(snapshot,cid)


@pytest.mark.parametrize('field,value',[('projectId','foreign-project'),('datasetId','foreign_dataset'),('tableId','other_table')])
def test_regression_table_detail_same_parent_binding(monkeypatch,field,value):
    obj=table();obj['tableReference'][field]=value
    snapshot,_=native_capture(monkeypatch,kinds=['bigquery_table'],overrides={'table-get':obj})
    assert results(snapshot,TABLE_ID) and all(r['status'] in ('UNKNOWN','DENIED') for r in results(snapshot,TABLE_ID)),results(snapshot,TABLE_ID)


@pytest.mark.parametrize('cid',['gcp.sql.iam_database_authentication',USER_ID])
def test_regression_numeric_scope_and_project_id_user_with_independent_alias_proof(monkeypatch,cid):
    # CRM provides the ID/number relation; no aliases are guessed from suffixes.
    snapshot,trace=native_capture(monkeypatch,scope='projects/'+NUMBER,api_project=PROJECT,
        kinds=['sql_instance','project']+(['sql_user'] if cid==USER_ID else []),
        users=[user('root','10.%',kind='BUILT_IN')] if cid==USER_ID else [user()])
    assert any(r['url']=='https://cloudresourcemanager.googleapis.com/v3/projects/'+NUMBER for r in trace.calls)
    assert_one(snapshot,cid,'PASS')


@pytest.mark.parametrize('cid',BQ_IDS+[TABLE_ID],ids=BQ_IDS+[TABLE_ID])
def test_regression_bigquery_numeric_scope_uses_independently_resolved_project_id(monkeypatch,cid):
    snapshot,trace=native_capture(monkeypatch,scope='projects/'+NUMBER,api_project=PROJECT,
        kinds=['project','bigquery_table' if cid==TABLE_ID else 'bigquery_dataset'])
    assert any(r['url']=='https://cloudresourcemanager.googleapis.com/v3/projects/'+NUMBER for r in trace.calls)
    assert_one(snapshot,cid,'PASS')


@pytest.mark.parametrize('cid',SQL_IDS,ids=SQL_IDS)
def test_native_sql_later_page_denial_retains_partial_coverage(monkeypatch,cid):
    snapshot,_=native_capture(monkeypatch,instances=[sql_case(cid)],partial='sql-list')
    collection=next(c for c in snapshot['collections'] if c['type']=='sql_instance')
    assert collection['status']=='partial'
    assert any(r['status']=='UNKNOWN' and r['evidence'].get('collection_status')=='partial' for r in results(snapshot,cid)),results(snapshot,cid)
    strict={'gcp.sql.deletion_protection','gcp.sql.iam_database_authentication','gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6','gcp_sql_trace3625_off'}
    assert_one(snapshot,cid,'UNKNOWN' if cid in strict else 'PASS')


@pytest.mark.parametrize('cid',BQ_IDS+[TABLE_ID],ids=BQ_IDS+[TABLE_ID])
def test_native_dataset_later_page_denial_preserves_partial_scope(monkeypatch,cid):
    snapshot,_=native_capture(monkeypatch,kinds=['bigquery_table'] if cid==TABLE_ID else ['bigquery_dataset'],partial='dataset-list')
    if cid==TABLE_ID:
        assert all(r['status'] in ('UNKNOWN','DENIED') for r in results(snapshot,cid))
    else:
        assert_one(snapshot,cid,'PASS')
        assert any(r['status']=='UNKNOWN' for r in results(snapshot,cid))


@pytest.mark.parametrize('cid',['gcp.sql.iam_database_authentication',USER_ID])
@pytest.mark.parametrize('operation',['denied','partial','foreign-instance','foreign-project','duplicate'])
def test_native_sql_user_failure_and_same_parent_guards(monkeypatch,cid,operation):
    rows=[user('root','10.%',kind='BUILT_IN')] if cid==USER_ID else [user()]
    overrides={};partial=None
    if operation=='denied':overrides['sql-users']=Response({'error':{'code':403,'status':'PERMISSION_DENIED'}},403)
    elif operation=='partial':partial='sql-users'
    elif operation=='duplicate':rows=rows*2
    else:rows[0]['instance' if operation=='foreign-instance' else 'project']='foreign'
    snapshot,_=native_capture(monkeypatch,kinds=['sql_instance','sql_user'] if cid==USER_ID else ['sql_instance'],users=rows,overrides=overrides,partial=partial)
    assert results(snapshot,cid) and all(r['status'] in ('UNKNOWN','DENIED') for r in results(snapshot,cid)),results(snapshot,cid)


@pytest.mark.parametrize('kind,expected',[
    ('CLOUD_IAM_USER','PASS'),('CLOUD_IAM_SERVICE_ACCOUNT','PASS'),('BUILT_IN','FAIL'),
    ('CLOUD_IAM_GROUP','FAIL'),('CLOUD_IAM_GROUP_USER','FAIL'),('CLOUD_IAM_GROUP_SERVICE_ACCOUNT','FAIL'),
    ('FUTURE_TYPE','UNKNOWN'),
])
def test_native_sql_iam_user_account_types(monkeypatch,kind,expected):
    snapshot,_=native_capture(monkeypatch,users=[user(kind=kind)])
    assert_one(snapshot,'gcp.sql.iam_database_authentication',expected)


@pytest.mark.parametrize('name',['cloudsql_iam_authentication','cloudsql.iam_authentication'])
@pytest.mark.parametrize('value,expected',[('on','PASS'),('off','FAIL'),('future','UNKNOWN')])
def test_native_iam_flag_engine_specific_name_and_value(monkeypatch,name,value,expected):
    obj=sql('MYSQL_8_0' if name=='cloudsql_iam_authentication' else 'POSTGRES_16')
    obj['settings']['databaseFlags']=[{'name':name,'value':value}]
    snapshot,_=native_capture(monkeypatch,instances=[obj])
    assert_one(snapshot,'gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6',expected)


@pytest.mark.parametrize('cid',['gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6','gcp_sql_trace3625_off'])
def test_native_duplicate_flag_declarations_unresolved(monkeypatch,cid):
    obj=sql_case(cid);obj['settings']['databaseFlags']*=2
    snapshot,_=native_capture(monkeypatch,instances=[obj])
    assert_one(snapshot,cid,'UNKNOWN')


@pytest.mark.parametrize('cid',BQ_IDS,ids=BQ_IDS)
def test_native_omitted_dataset_acl_or_cmek_uses_full_provenance(monkeypatch,cid):
    obj=dataset();obj.pop('defaultEncryptionConfiguration' if 'cmek' in cid else 'access')
    snapshot,_=native_capture(monkeypatch,kinds=['bigquery_dataset'],datasets=[obj])
    assert_one(snapshot,cid,'FAIL' if 'cmek' in cid else 'PASS')


@pytest.mark.parametrize('cid',BQ_IDS,ids=BQ_IDS)
def test_native_authorized_view_acl_not_invented_public_principal(monkeypatch,cid):
    obj=dataset(access=[{'view':{'projectId':'shared-project','datasetId':'views','tableId':'approved_view'}}])
    snapshot,_=native_capture(monkeypatch,kinds=['bigquery_dataset'],datasets=[obj])
    assert_one(snapshot,cid,'PASS')


@pytest.mark.parametrize('kind',['VIEW','MATERIALIZED_VIEW','EXTERNAL','SNAPSHOT'])
def test_native_table_type_and_explicit_encryption_reference(monkeypatch,kind):
    obj=table(type=kind)
    if kind in ('VIEW','EXTERNAL'):obj.pop('encryptionConfiguration')
    snapshot,_=native_capture(monkeypatch,kinds=['bigquery_table'],tables=[obj])
    assert_one(snapshot,TABLE_ID,'NOT_APPLICABLE' if kind=='VIEW' else 'UNKNOWN' if kind=='EXTERNAL' else 'PASS')


@pytest.mark.parametrize('cid',['gcp.reviewed.sql.high_availability','gcp.reviewed.sql.cmek'])
@pytest.mark.parametrize('kind',['READ_REPLICA_INSTANCE','ON_PREMISES_INSTANCE'])
def test_native_primary_sql_applicability(monkeypatch,cid,kind):
    obj=sql();obj['instanceType']=kind
    snapshot,_=native_capture(monkeypatch,instances=[obj])
    assert_one(snapshot,cid,'NOT_APPLICABLE')


def test_regression_mysql_binary_log_is_not_postgres_setting(monkeypatch):
    obj=sql('POSTGRES_16');obj['settings']['backupConfiguration'].pop('binaryLogEnabled',None)
    obj['settings']['backupConfiguration']['pointInTimeRecoveryEnabled']=True
    snapshot,_=native_capture(monkeypatch,instances=[obj])
    assert_one(snapshot,'gcp.ports.sql_instance_mysql_binary_log_enabled','NOT_APPLICABLE')


IP_IDS=['gcp.claude.sql_instance.private_ip_only','gcp.claude.sql_instance.second_gen_no_public_ip',
    'gcp.claude2.sql_instance.only_private_ip_addresses','gcp.ports.sql_instance_not_publicly_accessible',
    'gcp.ports.sql_instance_with_no_public_ips','gcp.ports.sql_no_primary_address','gcp.ports.sql_private_ip_assignments']
@pytest.mark.parametrize('cid',IP_IDS,ids=IP_IDS)
@pytest.mark.parametrize('variant',['outgoing','migrated','unspecified'])
def test_native_sql_address_enum_and_incoming_semantics(monkeypatch,cid,variant):
    obj=sql();kind={'outgoing':'OUTGOING','migrated':'MIGRATED_1ST_GEN','unspecified':'SQL_IP_ADDRESS_TYPE_UNSPECIFIED'}[variant]
    obj['ipAddresses'].append({'type':kind,'ipAddress':'203.0.113.9'})
    snapshot,_=native_capture(monkeypatch,instances=[obj])
    if variant=='unspecified':expected='UNKNOWN'
    elif variant=='outgoing':expected='FAIL' if cid=='gcp.claude2.sql_instance.only_private_ip_addresses' else 'PASS'
    else:
        # V1 migration is a legacy address declaration, not proof of current
        # ingress. Unassessed source paths stay unresolved rather than clean.
        expected='UNKNOWN' if cid in ('gcp.claude.sql_instance.private_ip_only','gcp.claude.sql_instance.second_gen_no_public_ip','gcp.ports.sql_instance_with_no_public_ips','gcp.ports.sql_no_primary_address','gcp.ports.sql_instance_not_publicly_accessible') else 'FAIL'
    assert_one(snapshot,cid,expected)


@pytest.mark.parametrize('cid',BQ_IDS,ids=BQ_IDS)
def test_native_dataset_malformed_deciding_value_unresolved(monkeypatch,cid):
    obj=dataset()
    if 'cmek' in cid:obj['defaultEncryptionConfiguration']['kmsKeyName']=None
    else:obj['access']='not-an-array'
    snapshot,_=native_capture(monkeypatch,kinds=['bigquery_dataset'],datasets=[obj])
    assert_one(snapshot,cid,'UNKNOWN')


@pytest.mark.parametrize('cid',['gcp.sql.iam_database_authentication',USER_ID])
def test_native_sql_user_missing_deciding_account_field(monkeypatch,cid):
    obj=user('root','10.%',kind='BUILT_IN') if cid==USER_ID else user()
    obj.pop('host' if cid==USER_ID else 'type')
    snapshot,_=native_capture(monkeypatch,users=[obj],kinds=['sql_instance','sql_user'] if cid==USER_ID else ['sql_instance'])
    assert results(snapshot,cid) and all(r['status'] in ('UNKNOWN','DENIED') for r in results(snapshot,cid))


@pytest.mark.parametrize('version,expected',[('POSTGRES_16','NOT_APPLICABLE'),('SQLSERVER_2019_STANDARD','NOT_APPLICABLE'),('FUTURE_1','UNKNOWN')])
def test_native_mysql_account_engine_and_role_metadata(monkeypatch,version,expected):
    row=user('database-admin','10.%',kind='BUILT_IN')
    if version=='POSTGRES_16':row['databaseRoles']=['cloudsqlsuperuser']
    if version=='SQLSERVER_2019_STANDARD':row['sqlserverUserDetails']={'serverRoles':['CustomerDbRootRole'],'disabled':False}
    snapshot,_=native_capture(monkeypatch,instances=[sql(version)],users=[row],kinds=['sql_instance','sql_user'])
    assert_one(snapshot,USER_ID,expected)


@pytest.mark.parametrize('cid',['gcp.sql.iam_database_authentication','gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6','gcp_sql_trace3625_off'])
@pytest.mark.parametrize('version',['MYSQL_8_4','POSTGRES_17','SQLSERVER_2022_ENTERPRISE','FUTURE_1'])
def test_native_sql_version_applicability(monkeypatch,cid,version):
    obj=sql(version);flag='cloudsql_iam_authentication' if version.startswith('MYSQL') else 'cloudsql.iam_authentication'
    obj['settings']['databaseFlags']=[{'name':'3625 (trace flag)','value':'off'}] if cid=='gcp_sql_trace3625_off' else [{'name':flag,'value':'on'}]
    snapshot,_=native_capture(monkeypatch,instances=[obj])
    if version=='FUTURE_1':expected='UNKNOWN'
    elif cid=='gcp_sql_trace3625_off':expected='PASS' if version.startswith('SQLSERVER') else 'NOT_APPLICABLE'
    elif version.startswith('SQLSERVER'):expected='NOT_APPLICABLE' if cid=='gcp.sql.iam_database_authentication' else 'UNKNOWN'
    else:expected='PASS'
    assert_one(snapshot,cid,expected)
