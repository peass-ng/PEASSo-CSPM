"""Independent native provider witnesses for the last 35 GCP review IDs.

No customer policy, deployment history, effective-route marker or representation
attestation is added to provider responses. Unsupported native facts stay unknown.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
from urllib.parse import urlsplit

import pytest

from peaso.checks import CHECKS
from peaso.checks.native_only import automated_checks, exclusions
from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot
from peaso.snapshot import validate
from tests.test_peaso_collectors_gcp import FixtureTransport, connector

ROOT = Path(__file__).resolve().parents[1] / '.wave2-receipts/final-services-review'
P = 'projects/native-one'
C = 'https://compute.googleapis.com/compute/v1/' + P
CRM = 'https://cloudresourcemanager.googleapis.com/v3/' + P
FN = P + '/locations/us-central1/functions/review'
CERT = P + '/locations/global/certificates/review'
BACK = C + '/global/backendServices/review'
MAP = C + '/global/urlMaps/review'
SSL = C + '/global/sslPolicies/review'
ARMOR = C + '/global/securityPolicies/review'
MIG = C + '/regions/us-central1/instanceGroupManagers/review'
GROUP = C + '/zones/us-central1-a/instanceGroups/review'
TLS = P + '/locations/global/serverTlsPolicies/review'
EMAIL = 'runtime@native-one.iam.gserviceaccount.com'
RECEIPTS = []

class NativeTransport(FixtureTransport):
    def request(self, method, url, **kwargs):
        first = len(self.evidence)
        try:
            return super().request(method, url, **kwargs)
        finally:
            for entry in self.evidence[first:]: entry['scope'] = kwargs.get('scope')

@pytest.fixture(autouse=True)
def no_network_or_auth(monkeypatch):
    forbidden=[]
    def blocked(*a, **kw):
        forbidden.append('network_or_auth_call')
        raise AssertionError('Native review forbids sockets, DNS and credentials')
    for target, attr in [(socket, 'create_connection'), (socket, 'getaddrinfo'),
                         (socket.socket, 'connect'), (gcp, 'Credentials')]:
        monkeypatch.setattr(target, attr, blocked)
    yield
    assert not forbidden,forbidden

@pytest.fixture(scope='session', autouse=True)
def receipts():
    ROOT.mkdir(parents=True, exist_ok=True)
    yield
    (ROOT/'native-cases.json').write_text(json.dumps(RECEIPTS, indent=2)+'\n')

def spec(cid, kind, path, good, bad, missing='UNKNOWN', expected=('PASS','FAIL')):
    return dict(id=cid, kind=kind, path=path, good=good, bad=bad, missing=missing, expected=expected)

def port(cid, kind, path, good, bad, **kw): return spec('gcp.ports.'+cid, kind, path, good, bad, **kw)
FW = {'direction':'INGRESS','allowed':[{'IPProtocol':'tcp','ports':['443']}]}
WAF = {'priority':1000,'action':'deny(403)','match':{'expr':{'expression':"evaluatePreconfiguredWaf('sqli-v33-stable')"}}}
DEFAULT = {'priority':2147483647,'action':'allow','match':{'versionedExpr':'SRC_IPS_V1','config':{'srcIpRanges':['*']}}}
SPECS = [
    port('dataproc_cluster_encryption_with_cmek','dataproc_cluster','config.encryptionConfig.gcePdKmsKeyName',
         {'config':{'encryptionConfig':{'gcePdKmsKeyName':P+'/locations/us-central1/keyRings/r/cryptoKeys/k'}}},
         {'config':{'encryptionConfig':{'gcePdKmsKeyName':''}}}),
    *[port('firewall_'+name+'_source_restriction','firewall','sourceRanges',
           {**FW,'sourceRanges':[source]}, {**FW,'sourceRanges':['0.0.0.0/0']}, missing='FAIL')
      for name,source in [('http_lb_proxy','35.191.0.0/16'),('iap_tcp_proxy','35.235.240.0/20')]],
    port('function_active_public_binding','function','iamPolicy.bindings',
         {'state':'ACTIVE','iamPolicy':{'bindings':[]}},
         {'state':'ACTIVE','iamPolicy':{'bindings':[{'role':'roles/cloudfunctions.invoker','members':['allUsers']}]}},missing='PASS'),
    port('function_active_vpc_connector','function','serviceConfig.vpcConnector',
         {'state':'ACTIVE','serviceConfig':{'vpcConnector':P+'/locations/us-central1/connectors/review'}},
         {'state':'ACTIVE','serviceConfig':{}}, missing='FAIL'),
    *[port('function_'+name+'_declarations','function','serviceConfig.serviceAccountEmail',
           {'serviceConfig':{'serviceAccountEmail':EMAIL}}, {'serviceConfig':{'serviceAccountEmail':EMAIL}})
      for name in ['basic_role','legacy_deployment_role','logging_mutation']],
    port('function_internal_ingress_declaration','function','serviceConfig.ingressSettings',
         {'serviceConfig':{'ingressSettings':'ALLOW_INTERNAL_ONLY'}}, {'serviceConfig':{'ingressSettings':'ALLOW_ALL'}}),
    port('logging_sink_all_entries_enabled','project','projectId',{},{}),
    port('organization_essential_contacts_complete','organization','name',{},{}),
    port('project_no_api_key','project','projectId',{},{}),
    port('project_service_cloudasset_api_enabled','project','projectId',{},{}),
    spec('gcp_api_keys_active_services_only','api_key','restrictions',
         {'restrictions':{'apiTargets':[{'service':'storage.googleapis.com'}]}},{},missing='FAIL'),
    spec('gcp_autoscaler_capacity_target','autoscaler','autoscalingPolicy.cpuUtilization.utilizationTarget',
         {'target':MIG,'autoscalingPolicy':{'cpuUtilization':{'utilizationTarget':0.6},'maxNumReplicas':5}},
         {'target':MIG,'autoscalingPolicy':{'cpuUtilization':{'utilizationTarget':0.9},'maxNumReplicas':2}}),
    spec('gcp_backend_service_checks_armor_security_policy_contains_f48cc81ccae3','security_policy','rules',
         {'rules':[WAF,DEFAULT]},{'rules':[DEFAULT]}),
    spec('gcp_c5_log_event_fields','log_entry','timestamp',
         {'timestamp':'2026-10-19T22:00:00Z'}, {'timestamp':'bad-time'}),
    *[spec('gcp_certificate_'+name,'certificate','expireTime',
           {'managed':{'state':'ACTIVE','domains':['example.invalid']},'expireTime':'2030-01-01T00:00:00Z','createTime':'2026-10-01T00:00:00Z'},
           {'managed':{'state':'ACTIVE','domains':['example.invalid']},'expireTime':'2020-01-01T00:00:00Z','createTime':'2020-01-01T00:00:00Z'},expected=('UNKNOWN','UNKNOWN'))
      for name in ['renewal_30_days','rotation_180_days','rotation_90_days']],
    spec('gcp_certificate_validity','certificate','expireTime',
         {'managed':{'state':'ACTIVE','domains':['example.invalid']},'expireTime':'2030-01-01T00:00:00Z'},
         {'managed':{'state':'ACTIVE','domains':['example.invalid']},'expireTime':'2020-01-01T00:00:00Z'}),
    spec('gcp_cloud_armor_waf_enabled','security_policy','rules',{'rules':[WAF,DEFAULT]},{'rules':[DEFAULT]}),
    spec('gcp_cloudcdn_cookie_ttl','backend_service','affinityCookieTtlSec',
         {'sessionAffinity':'GENERATED_COOKIE','affinityCookieTtlSec':1800}, {'sessionAffinity':'GENERATED_COOKIE','affinityCookieTtlSec':1801}),
    spec('gcp_gke_cluster_endpoint_publicly_accessible_ea8dcc0ec97d','gke_cluster','controlPlaneEndpointsConfig.ipEndpointsConfig.enablePublicEndpoint',
         {'controlPlaneEndpointsConfig':{'ipEndpointsConfig':{'enablePublicEndpoint':False}}},
         {'controlPlaneEndpointsConfig':{'ipEndpointsConfig':{'enablePublicEndpoint':True}}}),
    spec('gcp_gke_small_cluster_auto_upgrade','gke_cluster','nodePools',
         {'nodePools':[{'name':'pool','instanceGroupUrls':[GROUP],'management':{'autoUpgrade':True}}]},
         {'nodePools':[{'name':'pool','instanceGroupUrls':[GROUP],'management':{'autoUpgrade':False}}]}),
    spec('gcp_https_proxy_mtls_required','target_https_proxy','serverTlsPolicy',{'serverTlsPolicy':TLS},{},missing='FAIL'),
    spec('gcp_lb_server_header_rewrite','url_map','headerAction',
         {'defaultService':BACK,'headerAction':{'responseHeadersToAdd':[{'headerName':'Server','headerValue':'lb','replace':True}]}},
         {'defaultService':BACK},expected=('UNKNOWN','UNKNOWN')),
    spec('gcp_logging_enumeration_alert','logging_metric','filter',
         {'filter':'protoPayload.methodName =~ "\\.(list|get)$"','labelExtractors':{'principal':'EXTRACT(protoPayload.authenticationInfo.principalEmail)'},'metricDescriptor':{'type':'logging.googleapis.com/user/review','metricKind':'DELTA','valueType':'INT64'}},
         {'filter':'protoPayload.methodName =~ "\\.(list|get)$"','labelExtractors':{'principal':'EXTRACT(protoPayload.authenticationInfo.principalEmail)'},'metricDescriptor':{'type':'logging.googleapis.com/user/review','metricKind':'DELTA','valueType':'INT64'}}),
    spec('gcp_pci_backend_service_2ce96d36d0bf','backend_service','enableCDN',{'enableCDN':True},{'enableCDN':True}),
    spec('gcp_pci_cloudbuild_trigger_3302edf7cb18','cloudbuild_trigger','build.options.logging',
         {'build':{'steps':[{'name':'gcr.io/cloud-builders/echo','args':['review']}],'options':{'logging':'CLOUD_LOGGING_ONLY'}}},
         {'build':{'steps':[{'name':'gcr.io/cloud-builders/echo','args':['review']}],'options':{'logging':'NONE'}}},missing='PASS'),
    spec('gcp_pci_firewall_2080b14f1361','firewall','sourceRanges',
         {**FW,'sourceRanges':['10.0.0.0/8']},{**FW,'sourceRanges':['0.0.0.0/0']},missing='FAIL'),
    spec('gcp_pci_instance_template_2e26bed500fc','instance_template','properties.networkInterfaces',
         {'properties':{'networkInterfaces':[{'network':C+'/global/networks/review'}]}},
         {'properties':{'networkInterfaces':[{'network':C+'/global/networks/review','ipv6AccessConfigs':[{'type':'DIRECT_IPV6'}]}]}}),
    spec('gcp_pci_url_map_9ed56c323a05','url_map','defaultUrlRedirect',
         {'defaultUrlRedirect':{'httpsRedirect':True}}, {'defaultService':BACK}),
    spec('gcp_pubsub_topic_cmek','pubsub_topic','kmsKeyName',
         {'kmsKeyName':P+'/locations/us-central1/keyRings/r/cryptoKeys/k'},{},missing='FAIL'),
]
assert len(SPECS)==34

def find(cid): return next(s for s in SPECS if s['id']==cid or s['id'].endswith(cid))

def plan(case, branch='good'):
    kind=case['kind']; bad=branch=='bad'; cid=case['id']
    row={'name':'review',**deepcopy(case['bad' if bad else 'good'])}
    routes={}; scope='organizations/123' if kind=='organization' else P
    def add(url,data,method='GET',primary=False): routes[url]={'data':data,'method':method,'primary':primary}
    def compute(k, rows, primary=False, proxy='targetHttpsProxies'):
        for ck,endpoint,key,agg in gcp.COMPUTE:
            if ck!=k: continue
            chosen=k!='target_proxy' or endpoint.endswith('/'+proxy)
            items=rows if chosen else []
            for r in items:
                r.setdefault('selfLink',C+('/regions/us-central1/' if k=='instance_group_manager' else '/global/')+endpoint.split('/')[-1]+'/'+r['name'])
            location='zones/us-central1-a' if k=='instance_group_manager' and rows and '/zones/' in rows[0].get('selfLink','') else 'regions/us-central1' if k=='instance_group_manager' else 'global'
            add(C+'/'+endpoint, {'items':{location:{key:items}}} if agg else {'items':items},primary=primary and chosen)
        if k == 'forwarding_rule':
            add(C+'/global/forwardingRules', {'items': []})
    if kind in {ck for ck,*_ in gcp.COMPUTE}: compute(kind,[row],True)
    elif kind in ('project','organization'):
        row.update(name='organizations/123' if kind=='organization' else 'projects/123')
        if kind=='project': row.update(projectId='native-one'); add(C,{'name':'native-one','commonInstanceMetadata':{'fingerprint':'abc'}})
        add('https://cloudresourcemanager.googleapis.com/v3/'+scope,row,primary=True)
    elif kind=='function':
        row['name']=FN; policy=row.pop('iamPolicy',{'bindings':[]})
        add('https://cloudfunctions.googleapis.com/v2/'+P+'/locations',
            {'locations':[{'name':P+'/locations/us-central1','locationId':'us-central1'}]})
        add('https://cloudfunctions.googleapis.com/v2/'+P+'/locations/-/functions',{'functions':[row]},primary=True)
        add('https://cloudfunctions.googleapis.com/v2/'+FN+':getIamPolicy',policy)
    elif kind=='dataproc_cluster':
        row.update(clusterName='review',projectId='native-one',clusterUuid='11111111-1111-4111-8111-111111111111');row.pop('name')
        add('https://dataproc.googleapis.com/v1/'+P+'/regions/us-central1/clusters',{'clusters':[row]},primary=True)
        add('https://dataproc.googleapis.com/v1/'+P+'/regions/us-central1/clusters/review:getIamPolicy',
            {'bindings':[]},method='POST')
    elif kind=='api_key':
        row['name']='projects/123/locations/global/keys/key-1'
        add('https://apikeys.googleapis.com/v2/'+P+'/locations/global/keys',{'keys':[row]},primary=True)
    elif kind=='certificate':
        row['name']=CERT
        add('https://certificatemanager.googleapis.com/v1/'+P+'/locations/global/certificates',{'certificates':[row]},primary=True)
    elif kind=='security_policy':
        row['selfLink']=ARMOR
        add(C+'/global/securityPolicies',{'items':[row]},primary=True)
    elif kind=='autoscaler':
        row['selfLink']=C+'/regions/us-central1/autoscalers/review'
        add(C+'/regions/us-central1/autoscalers',{'items':[row]},primary=True)
    elif kind=='gke_cluster':
        row.update(name='review',location='us-central1-a',selfLink='https://container.googleapis.com/v1/'+P+'/locations/us-central1-a/clusters/review')
        add('https://container.googleapis.com/v1/'+P+'/locations/-/clusters',{'clusters':[row]},primary=True)
    elif kind=='target_https_proxy': compute('target_proxy',[row],True)
    elif kind=='cloudbuild_trigger':
        row.update(id='11111111-1111-4111-8111-111111111111',resourceName=P+'/locations/global/triggers/review')
        add('https://cloudbuild.googleapis.com/v1/'+P+'/locations/global/triggers',{'triggers':[row]},primary=True)
    elif kind=='pubsub_topic':
        row['name']=P+'/topics/review'
        add('https://pubsub.googleapis.com/v1/'+P+'/topics',{'topics':[row]},primary=True)
        add('https://pubsub.googleapis.com/v1/'+row['name']+':getIamPolicy',{'bindings':[]})
    elif kind=='logging_metric':
        add('https://logging.googleapis.com/v2/'+P+'/metrics',{'metrics':[row]},primary=True)
    elif kind=='log_entry':
        row.update(logName=P+'/logs/cloudaudit.googleapis.com%2Factivity',insertId='review-1',
                   resource={'type':'gce_instance','labels':{'project_id':'native-one'}},
                   protoPayload={'@type':'type.googleapis.com/google.cloud.audit.AuditLog','serviceName':'compute.googleapis.com',
                                 'methodName':'v1.compute.instances.setMetadata','resourceName':P+'/zones/us-central1-a/instances/review',
                                 'authenticationInfo':{'principalEmail':'operator@example.invalid'}})
        add(CRM,{'name':'projects/123','projectId':'native-one'})
        add('https://logging.googleapis.com/v2/entries:list',{'entries':[row]},method='POST',primary=True)
    deps=next(c.dependencies for c in CHECKS if c.id==cid)
    if 'project' in deps and kind!='project':
        add(CRM,{'name':'projects/123','projectId':'native-one'})
        add(C,{'name':'native-one','commonInstanceMetadata':{'fingerprint':'abc'}})
    if 'iam_policy' in deps:
        add('https://cloudresourcemanager.googleapis.com/v1/'+P+':getAncestry',{'ancestor':[{'resourceId':{'type':'project','id':'123'}}]},method='POST')
        mode='deployment' if 'legacy' in cid else 'logging' if 'logging_mutation' in cid else 'basic'
        role='roles/editor' if mode=='basic' and bad else P+'/roles/review'
        perms=['deploymentmanager.deployments.create' if mode=='deployment' else 'logging.sinks.update'] if bad else ['storage.buckets.get']
        add(CRM+':getIamPolicy',{'bindings':[{'role':role,'members':['serviceAccount:'+EMAIL]}]},method='POST')
        add('https://iam.googleapis.com/v1/'+P+'/roles',{'roles':[{'name':P+'/roles/review','includedPermissions':perms}]})
        add('https://iam.googleapis.com/v1/'+role,{'name':role,'includedPermissions':perms})
    if 'log_sink' in deps:
        add('https://logging.googleapis.com/v2/'+P+'/sinks',{'sinks':[{'name':'review','destination':'storage.googleapis.com/review','filter':'severity>=ERROR' if bad else ''}]})
    if 'essential_contact' in deps:
        add('https://essentialcontacts.googleapis.com/v1/'+scope+'/contacts',{'contacts':[{'name':scope+'/contacts/1','notificationCategorySubscriptions':['SECURITY'] if bad else ['ALL'],'email':'security@example.invalid'}]})
    if 'api_key' in deps and kind!='api_key':
        add('https://apikeys.googleapis.com/v2/'+P+'/locations/global/keys',{'keys':[{'name':'projects/123/locations/global/keys/key-1'}] if bad else []})
    if 'service_usage' in deps:
        add('https://serviceusage.googleapis.com/v1/'+P+'/services',{'services':[{'name':'projects/123/services/cloudasset.googleapis.com','state':'DISABLED' if bad else 'ENABLED'}]})
    if 'instance_group_manager' in deps:
        compute('instance_group_manager',[{'name':'review','selfLink':C+'/zones/us-central1-a/instanceGroupManagers/review' if kind=='gke_cluster' else MIG,'instanceGroup':GROUP,'targetSize':2}])
    if kind=='security_policy': compute('backend_service',[{'name':'review','securityPolicy':ARMOR,'loadBalancingScheme':'EXTERNAL_MANAGED'}])
    if 'server_tls_policy' in deps and row.get('serverTlsPolicy'):
        add('https://networksecurity.googleapis.com/v1/'+TLS,{'name':TLS,'mtlsPolicy':{'clientValidationMode':'REJECT_INVALID'}})
    if 'server_tls_policy' in deps:
        add('https://networksecurity.googleapis.com/v1/'+P+'/locations/global/serverTlsPolicies',
            {'serverTlsPolicies':[routes['https://networksecurity.googleapis.com/v1/'+TLS]['data']]
             if 'https://networksecurity.googleapis.com/v1/'+TLS in routes else []})
        # The native network inventory hydrates each listed policy's IAM (16bb81e0).
        if 'https://networksecurity.googleapis.com/v1/'+TLS in routes:
            add('https://networksecurity.googleapis.com/v1/'+TLS+':getIamPolicy',{'bindings':[]})
    if kind=='certificate':
        # Certificate Manager reach now joins project IAM and custom roles (16bb81e0).
        add(CRM,{'name':'projects/123','projectId':'native-one'})
        add(C,{'name':'native-one','commonInstanceMetadata':{'fingerprint':'abc'}})
        routes.setdefault(CRM+':getIamPolicy',{'data':{'bindings':[]},'method':'POST','primary':False})
        routes.setdefault('https://iam.googleapis.com/v1/'+P+'/roles',{'data':{'roles':[]},'method':'GET','primary':False})
    if 'alert_policy' in deps:
        add('https://monitoring.googleapis.com/v3/'+P+'/alertPolicies',{'alertPolicies':[{'name':P+'/alertPolicies/review','enabled':not bad,
             'notificationChannels':[P+'/notificationChannels/review'],'combiner':'OR','conditions':[{'name':P+'/alertPolicies/review/conditions/review',
             'conditionThreshold':{'filter':'metric.type="logging.googleapis.com/user/review"','comparison':'COMPARISON_GT','thresholdValue':10,
              'duration':'0s','aggregations':[{'alignmentPeriod':'300s','perSeriesAligner':'ALIGN_SUM','crossSeriesReducer':'REDUCE_SUM','groupByFields':['metric.label.principal']}]}}]}]})
    if cid=='gcp_pci_backend_service_2ce96d36d0bf':
        row['selfLink']=BACK
        compute('url_map',[{'name':'review','selfLink':MAP,'defaultService':BACK}])
        compute('target_proxy',[{'name':'review','urlMap':MAP,'sslPolicy':SSL}])
        compute('ssl_policy',[{'name':'review','selfLink':SSL,'minTlsVersion':'TLS_1_0' if bad else 'TLS_1_2','profile':'RESTRICTED'}])
    if cid=='gcp_pci_url_map_9ed56c323a05':
        row['selfLink']=MAP
        proxy=C+'/global/targetHttpProxies/review'
        compute('target_proxy',[{'name':'review','selfLink':proxy,'urlMap':MAP}],proxy='targetHttpProxies')
        compute('forwarding_rule',[{'name':'review','target':proxy,'IPProtocol':'TCP','portRange':'80-80','loadBalancingScheme':'EXTERNAL','IPAddress':'8.8.8.8'}])
    return row,routes,scope

def capture(case, branch='good', mutate=None, deny=None):
    row,routes,scope=plan(case,branch)
    if mutate: mutate(row,routes)
    primary=next(u for u,r in routes.items() if r['primary'])
    if branch=='denied': deny=primary
    native=[];unexpected=[]
    def resolve(req):
        if req['url'] not in routes or req['method']!=routes[req['url']]['method']:
            unexpected.append(deepcopy(req))
            raise AssertionError('Unexpected native transport request: '+repr(req))
        assert req['url'] in routes,req
        route=routes[req['url']];u=urlsplit(req['url'])
        allowed={(r['method'],urlsplit(url).scheme,urlsplit(url).netloc,urlsplit(url).path) for url,r in routes.items()}
        assert (req['method'],u.scheme,u.netloc,u.path) in allowed
        assert u.scheme=='https' and u.netloc.endswith('.googleapis.com')
        if req['url']==deny or branch=='partial' and req['url']==primary and req.get('params',{}).get('pageToken'):
            native.append({'request':deepcopy(req),'error':{'status':'denied','http_status':403}})
            raise gcp.ReadError('denied','permission_denied',http_status=403)
        data=deepcopy(route['data'])
        if branch=='partial' and req['url']==primary: data['nextPageToken']='review-next-page'
        native.append({'request':deepcopy(req),'response':deepcopy(data)})
        return data
    check=next(c for c in CHECKS if c.id==case['id'])
    kinds=list(dict.fromkeys([case['kind'],*check.dependencies]))
    tr=NativeTransport(resolve)
    snap=gcp.GCPCollector(connector(kinds,[scope],metrics_scopes=False,compute_resource_iam=False,resource_iam=False,
             dataproc_regions=['us-central1'],certificate_locations=['global'],autoscaler_regions=['us-central1'],
             security_policy_regions=[],networksecurity_network_locations=['global'],cloudbuild_locations=['global'],include_inherited='iam_policy' in check.dependencies),transport=tr).collect()
    assert not unexpected,unexpected
    assert validate(snap)==snap
    tr.native=native
    return snap,tr

def verdict(case,scenario,snap,tr,expected):
    before=deepcopy(snap)
    if case['id'] in exclusions():
        # These literal contracts were explicitly archived after native review.
        # Preserve their historical fixtures, but test exclusion, never a fake
        # automatic UNKNOWN/PASS or silent skip of the assigned review row.
        with pytest.raises(ValueError, match='not available for automated scans'):
            evaluate_snapshot(snap,checks=[case['id']])
        assert snap==before
        RECEIPTS.append({'check_id':case['id'],'scenario':'archived:'+scenario,
                         'test_nodeid':os.environ.get('PYTEST_CURRENT_TEST','').removesuffix(' (call)'),
                         'expected':['ARCHIVED'],'statuses':['ARCHIVED'],'historical_expected':expected,
                         'native_responses':tr.native,'collections':snap['collections'],
                         'exclusion':exclusions()[case['id']]})
        return
    findings=evaluate_snapshot(snap,checks=[case['id']])['findings']
    assert snap==before
    got=[f['status'] for f in findings]
    expected=expected if isinstance(expected,list) else [expected]
    RECEIPTS.append({'check_id':case['id'],'scenario':scenario,'test_nodeid':os.environ.get('PYTEST_CURRENT_TEST','').removesuffix(' (call)'),
                     'expected':expected,'statuses':got,'findings':findings,'native_responses':tr.native,'collections':snap['collections']})
    assert sorted(got)==sorted(expected),findings

@pytest.mark.parametrize('case',SPECS,ids=lambda s:s['id'])
@pytest.mark.parametrize('branch',['good','bad','denied'])
def test_native_independent_verdicts(case,branch):
    snap,tr=capture(case,branch)
    expected=('UNKNOWN' if case['kind']=='target_https_proxy' else 'DENIED') if branch=='denied' else case['expected'][branch=='bad']
    verdict(case,branch,snap,tr,expected)

@pytest.mark.parametrize('case',[s for s in SPECS if s['kind'] not in ('project','organization')],ids=lambda s:s['id'])
def test_native_missing_deciding_field(case):
    def mutate(row,routes):
        parent=row
        if case['path'].startswith('iamPolicy.'):
            parent=routes['https://cloudfunctions.googleapis.com/v2/'+FN+':getIamPolicy']['data']
            parts=case['path'].split('.')[1:]
        else: parts=case['path'].split('.')
        for part in parts[:-1]: parent=parent.get(part,{})
        parent.pop(parts[-1],None)
    snap,tr=capture(case,mutate=mutate)
    verdict(case,'missing_deciding_field',snap,tr,case['missing'])

@pytest.mark.parametrize('case',[s for s in SPECS if s['kind'] not in ('project','organization','gke_cluster','log_entry')],ids=lambda s:s['id'])
def test_native_partial_inventory_never_proves_absence(case):
    snap,tr=capture(case,'partial')
    local_unknown=case['kind'] in ('certificate','security_policy','autoscaler','api_key') or case['id'] in ('gcp_pci_url_map_9ed56c323a05','gcp_pci_backend_service_2ce96d36d0bf','gcp_pci_firewall_2080b14f1361')
    expected=['UNKNOWN'] if case['kind'] in ('target_https_proxy','logging_metric') else ['UNKNOWN','UNKNOWN' if local_unknown else case['expected'][0]]
    verdict(case,'partial',snap,tr,expected)

def test_archived_login_detector_remains_excluded():
    cid='gcp_logging_detect_t1110'
    assert cid not in {c.id for c in automated_checks(CHECKS)}
    assert cid in exclusions()
    RECEIPTS.append({'check_id':cid,'scenario':'archived_disposition','test_nodeid':os.environ.get('PYTEST_CURRENT_TEST','').removesuffix(' (call)'),
                     'statuses':['ARCHIVED'],'expected':['ARCHIVED'],'exclusion':exclusions()[cid]})

@pytest.mark.parametrize('variant,expected',[
    ('self_managed','PASS'),('self_managed_expired','FAIL'),('provisioning','FAIL'),('failed','FAIL'),
    ('private_pki','PASS'),('all_regions','PASS'),('client_auth','PASS'),('union_conflict','UNKNOWN'),
    ('foreign_project','UNKNOWN'),('unrecognized_state','UNKNOWN'),('missing_expiry','UNKNOWN')])
def test_certificate_manager_current_variants(variant,expected):
    case=find('gcp_certificate_validity')
    def mutate(row,routes):
        row.update(sanDnsnames=['example.invalid'],scope='DEFAULT',usedBy=[{'name':'//certificatemanager.googleapis.com/'+P+'/locations/global/certificateMaps/review/certificateMapEntries/review'}])
        if variant.startswith('self_managed'):
            row.pop('managed');row['selfManaged']={}
            if variant.endswith('expired'):row['expireTime']='2020-01-01T00:00:00Z'
        if variant in ('provisioning','failed'):row['managed']['state']=variant.upper()
        if variant=='private_pki':row['managed']['issuanceConfig']=P+'/locations/global/certificateIssuanceConfigs/private'
        if variant in ('all_regions','client_auth'):row['scope']=variant.upper()
        if variant=='union_conflict':row['selfManaged']={}
        if variant=='foreign_project':row['name']=row['name'].replace('native-one','p-other')
        if variant=='unrecognized_state':row['managed']['state']='FUTURE_STATE'
        if variant=='missing_expiry':row.pop('expireTime')
    snap,tr=capture(case,mutate=mutate)
    verdict(case,'certificate_variant:'+variant,snap,tr,expected)

@pytest.mark.parametrize('suffix',['renewal_30_days','rotation_180_days','rotation_90_days'])
@pytest.mark.parametrize('variant',['native_used_by','self_managed_pem','unused'])
def test_certificate_history_is_not_fabricated(suffix,variant):
    case=find('gcp_certificate_'+suffix)
    def mutate(row,routes):
        if variant=='native_used_by':row['usedBy']=[{'name':'//compute.googleapis.com/'+P+'/locations/global/targetHttpsProxies/review'}]
        elif variant=='self_managed_pem':
            row.pop('managed');row['selfManaged']={};row['pemCertificate']='-----BEGIN CERTIFICATE-----\npublic-certificate-placeholder\n-----END CERTIFICATE-----'
        else:row['usedBy']=[]
    snap,tr=capture(case,mutate=mutate)
    verdict(case,'history_unavailable:'+variant,snap,tr,'UNKNOWN')
    cert=next(c for c in snap['collections'] if c['type']=='certificate')['items'][0]
    assert 'deployment' not in cert
    if variant=='self_managed_pem': assert cert['pemCertificate']=='[redacted]'

@pytest.mark.parametrize('variant,expected',[
    ('missing_principal','UNKNOWN'),('missing_method','UNKNOWN'),('system_event','UNKNOWN'),
    ('foreign_project','UNKNOWN'),('missing_resource_type','UNKNOWN'),('invalid_timestamp','FAIL'),
    ('nanosecond_timestamp','PASS'),('principal_subject_only','UNKNOWN')])
def test_audit_event_actual_fields_and_classification(variant,expected):
    case=find('gcp_c5_log_event_fields')
    def mutate(row,routes):
        p=row['protoPayload']
        if variant=='missing_principal':p['authenticationInfo']={}
        if variant=='missing_method':p.pop('methodName')
        if variant=='system_event':p.pop('authenticationInfo')
        if variant=='foreign_project':row['resource']['labels']['project_id']='p-other'
        if variant=='missing_resource_type':row['resource'].pop('type')
        if variant=='invalid_timestamp':row['timestamp']='not-a-timestamp'
        if variant=='nanosecond_timestamp':row['timestamp']='2026-10-19T22:00:00.123456789Z'
        if variant=='principal_subject_only':p['authenticationInfo']={'principalSubject':'principal://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/review/subject/example'}
    snap,tr=capture(case,mutate=mutate)
    verdict(case,'audit_fields:'+variant,snap,tr,expected)

@pytest.mark.parametrize('suffix',['firewall_http_lb_proxy_source_restriction','firewall_iap_tcp_proxy_source_restriction'])
@pytest.mark.parametrize('variant,expected',[('source_or_tag','FAIL'),('udp_only','NOT_APPLICABLE'),('egress','NOT_APPLICABLE'),('disabled','NOT_APPLICABLE'),('ipv6','PASS'),('malformed_cidr','UNKNOWN')])
def test_proxy_firewall_source_semantics(suffix,variant,expected):
    case=find(suffix)
    def mutate(row,routes):
        if variant=='source_or_tag':row['sourceTags']=['unrestricted-tag']
        if variant=='udp_only':row['allowed']=[{'IPProtocol':'udp','ports':['53']}]
        if variant=='egress':row['direction']='EGRESS'
        if variant=='disabled':row['disabled']=True
        if variant=='ipv6':row['sourceRanges']=['2600:2d00:1:7::/64'] if 'iap' in suffix else ['35.191.1.0/24']
        if variant=='malformed_cidr':row['sourceRanges']=['invalid-cidr']
    snap,tr=capture(case,mutate=mutate)
    verdict(case,'firewall_source:'+variant,snap,tr,expected)

@pytest.mark.parametrize('suffix',['function_basic_role_declarations','function_legacy_deployment_role_declarations','function_logging_mutation_declarations'])
@pytest.mark.parametrize('variant,expected',[('conditional_grant','FAIL'),('other_principal','PASS'),('ancestry_denied','UNKNOWN'),('role_list_denied','UNKNOWN')])
def test_function_role_native_authority(suffix,variant,expected):
    case=find(suffix)
    def mutate(row,routes):
        policy=routes[CRM+':getIamPolicy']['data']
        if variant=='conditional_grant':policy['bindings'][0]['condition']={'title':'future','expression':'request.time < timestamp("2030-01-01T00:00:00Z")'};policy['version']=3
        if variant=='other_principal':policy['bindings'][0]['members']=['serviceAccount:unrelated@native-one.iam.gserviceaccount.com']
    deny={'ancestry_denied':'https://cloudresourcemanager.googleapis.com/v1/'+P+':getAncestry','role_list_denied':'https://iam.googleapis.com/v1/'+P+'/roles'}.get(variant)
    snap,tr=capture(case,'bad',mutate=mutate,deny=deny)
    verdict(case,'function_iam:'+variant,snap,tr,expected)

@pytest.mark.parametrize('suffix',['function_active_public_binding','function_active_vpc_connector'])
def test_function_transient_state_deliberate_source_exclusion(suffix):
    case=find(suffix)
    snap,tr=capture(case,'bad',mutate=lambda row,routes:row.update(state='DEPLOYING'))
    verdict(case,'transient_source_exclusion',snap,tr,'NOT_APPLICABLE')

@pytest.mark.parametrize('variant,expected',[('conditional_public','FAIL'),('invoker_read_denied','UNKNOWN')])
def test_function_public_policy_is_declaration_only(variant,expected):
    case=find('function_active_public_binding')
    def mutate(row,routes):
        if variant=='conditional_public':
            routes['https://cloudfunctions.googleapis.com/v2/'+FN+':getIamPolicy']['data'].update(version=3)
            routes['https://cloudfunctions.googleapis.com/v2/'+FN+':getIamPolicy']['data']['bindings'][0]['condition']={'title':'future','expression':'true'}
    snap,tr=capture(case,'bad',mutate=mutate,deny='https://cloudfunctions.googleapis.com/v2/'+FN+':getIamPolicy' if variant=='invoker_read_denied' else None)
    verdict(case,'function_public:'+variant,snap,tr,expected)

@pytest.mark.parametrize('suffix',['logging_sink_all_entries_enabled','organization_essential_contacts_complete','project_no_api_key','project_service_cloudasset_api_enabled'])
@pytest.mark.parametrize('branch',['dependency_denied','dependency_partial'])
def test_project_and_organization_dependency_coverage(suffix,branch):
    case=find(suffix)
    def mutate(row,routes):
        primary=next(r for r in routes.values() if r['primary']);primary['primary']=False
        dep=next((r for u,r in routes.items() if any(x in u for x in ['/sinks','/contacts','/keys','/services'])))
        dep['primary']=True
    row,routes,_=plan(case)
    deny=next(u for u in routes if any(x in u for x in ['/sinks','/contacts','/keys','/services'])) if branch=='dependency_denied' else None
    snap,tr=capture(case,'partial' if branch=='dependency_partial' else 'good',mutate=mutate,deny=deny)
    verdict(case,branch,snap,tr,'UNKNOWN')

@pytest.mark.parametrize('variant,expected',[('disabled','NOT_APPLICABLE'),('file_backed','UNKNOWN'),('default_logging','PASS'),('unknown_enum','UNKNOWN')])
def test_cloudbuild_native_logging_projection(variant,expected):
    case=find('gcp_pci_cloudbuild_trigger_3302edf7cb18')
    def mutate(row,routes):
        if variant=='disabled':row['disabled']=True
        if variant=='file_backed':row.pop('build');row['filename']='cloudbuild.yaml'
        if variant=='default_logging':row['build'].pop('options')
        if variant=='unknown_enum':row['build']['options']['logging']='FUTURE_MODE'
    snap,tr=capture(case,mutate=mutate)
    verdict(case,'cloudbuild_logging:'+variant,snap,tr,expected)

@pytest.mark.parametrize('variant,expected',[('broad_service','UNKNOWN'),('deleted','NOT_APPLICABLE'),('malformed_service','UNKNOWN')])
def test_api_key_restriction_boundaries(variant,expected):
    case=find('gcp_api_keys_active_services_only')
    def mutate(row,routes):
        if variant=='broad_service':row['restrictions']['apiTargets'][0]['service']='cloudapis.googleapis.com'
        if variant=='deleted':row['deleteTime']='2026-10-01T00:00:00Z'
        if variant=='malformed_service':row['restrictions']['apiTargets'][0]['service']=None
    snap,tr=capture(case,mutate=mutate)
    verdict(case,'api_key:'+variant,snap,tr,expected)

@pytest.mark.parametrize('variant,expected',[('allow_invalid','FAIL'),('foreign_policy','UNKNOWN'),('policy_denied','UNKNOWN')])
def test_mtls_native_policy_join(variant,expected):
    case=find('gcp_https_proxy_mtls_required')
    def mutate(row,routes):
        if variant=='allow_invalid':routes['https://networksecurity.googleapis.com/v1/'+TLS]['data']['mtlsPolicy']['clientValidationMode']='ALLOW_INVALID_OR_MISSING_CLIENT_CERT'
        if variant=='foreign_policy':row['serverTlsPolicy']=TLS.replace('native-one','p-other')
    snap,tr=capture(case,mutate=mutate,deny='https://networksecurity.googleapis.com/v1/'+P+'/locations/global/serverTlsPolicies' if variant=='policy_denied' else None)
    verdict(case,'mtls_join:'+variant,snap,tr,expected)

@pytest.mark.parametrize('suffix,variant,expected',[
    ('gcp_autoscaler_capacity_target','foreign_mig','UNKNOWN'),
    ('gcp_autoscaler_capacity_target','max_equal_target','FAIL'),
    ('gcp_autoscaler_capacity_target','non_cpu_policy','UNKNOWN'),
    ('gcp_cloudcdn_cookie_ttl','non_cookie','NOT_APPLICABLE'),
    ('gcp_cloudcdn_cookie_ttl','http_cookie','PASS'),
    ('gcp_cloudcdn_cookie_ttl','string_ttl','UNKNOWN'),
    ('gcp_pci_firewall_2080b14f1361','deny_only','PASS'),
    ('gcp_pci_firewall_2080b14f1361','egress','NOT_APPLICABLE'),
    ('gcp_pci_instance_template_2e26bed500fc','second_interface','FAIL'),
    ('gcp_pci_instance_template_2e26bed500fc','empty_interfaces','UNKNOWN'),
    ('gcp_backend_service_checks_armor_security_policy_contains_f48cc81ccae3','no_attachment','NOT_APPLICABLE'),
    ('gcp_backend_service_checks_armor_security_policy_contains_f48cc81ccae3','duplicate_priority','UNKNOWN'),
    ('gcp_pci_backend_service_2ce96d36d0bf','cdn_disabled','NOT_APPLICABLE'),
    ('gcp_gke_cluster_endpoint_publicly_accessible_ea8dcc0ec97d','dns_public_ip_private','PASS'),
])
def test_service_specific_scope_and_override(suffix,variant,expected):
    case=find(suffix)
    def mutate(row,routes):
        if variant=='foreign_mig':row['target']=MIG.replace('native-one','p-other')
        if variant=='max_equal_target':row['autoscalingPolicy']['maxNumReplicas']=2
        if variant=='non_cpu_policy':row['autoscalingPolicy'].pop('cpuUtilization');row['autoscalingPolicy']['loadBalancingUtilization']={'utilizationTarget':0.7}
        if variant=='non_cookie':row['sessionAffinity']='NONE'
        if variant=='http_cookie':row.update(sessionAffinity='HTTP_COOKIE',consistentHash={'httpCookie':{'name':'review','ttl':{'seconds':'1'}}})
        if variant=='string_ttl':row['affinityCookieTtlSec']='1800'
        if variant=='deny_only':row.pop('allowed');row['denied']=[{'IPProtocol':'all'}]
        if variant=='egress':row['direction']='EGRESS'
        if variant=='second_interface':row['properties']['networkInterfaces'].append({'network':C+'/global/networks/other','accessConfigs':[{'type':'ONE_TO_ONE_NAT'}]})
        if variant=='empty_interfaces':row['properties']['networkInterfaces']=[]
        if variant=='no_attachment':routes[C+'/aggregated/backendServices']['data']['items']['global']['backendServices']=[]
        if variant=='duplicate_priority':row['rules'].append(deepcopy(row['rules'][0]))
        if variant=='cdn_disabled':row['enableCDN']=False
        if variant=='dns_public_ip_private':row['controlPlaneEndpointsConfig']['dnsEndpointConfig']={'allowExternalTraffic':True}
    snap,tr=capture(case,mutate=mutate)
    verdict(case,'service_scope:'+variant,snap,tr,expected)

@pytest.mark.parametrize('suffix',['gcp_lb_server_header_rewrite'])
def test_missing_topology_is_unknown_even_with_native_config(suffix):
    case=find(suffix)
    snap,tr=capture(case)
    verdict(case,'unavailable_topology',snap,tr,'UNKNOWN')
    rows=[r for c in snap['collections'] for r in c['items']]
    assert all('internetFacing' not in r and 'effectiveRoutes' not in r and 'routeCoverageComplete' not in r for r in rows)

@pytest.mark.parametrize('suffix,variant',[(s,v) for s in ['logging_sink_all_entries_enabled','organization_essential_contacts_complete','project_no_api_key','project_service_cloudasset_api_enabled'] for v in ['empty_dependency','foreign_dependency'] if not (s=='project_no_api_key' and v=='foreign_dependency')])
def test_project_native_scope_binding(suffix,variant):
    case=find(suffix)
    def mutate(row,routes):
        route=next(r for u,r in routes.items() if any(x in u for x in ['/sinks','/contacts','/keys','/services']))
        data=route['data'];key=next(iter(data))
        if variant=='empty_dependency':data[key]=[]
        elif data[key]:
            if suffix=='project_no_api_key':data[key][0]['name']='projects/999/locations/global/keys/key-1'
            elif suffix=='organization_essential_contacts_complete':data[key][0]['name']='organizations/999/contacts/1'
            elif suffix=='project_service_cloudasset_api_enabled':data[key][0]['name']='projects/999/services/cloudasset.googleapis.com'
            else:data[key][0]['name']='foreign'
    # A sink name is API-local and prefixed by the collector, so "foreign" is
    # an ordinary sink ID. A complete empty API list can prove no keys, but
    # cannot provide a specific service state.
    branch='bad' if suffix=='project_no_api_key' else 'good'
    snap,tr=capture(case,branch,mutate=mutate)
    expected={'logging_sink_all_entries_enabled':'FAIL' if variant=='empty_dependency' else 'PASS',
              'organization_essential_contacts_complete':'FAIL',
              'project_no_api_key':'PASS',
              'project_service_cloudasset_api_enabled':'UNKNOWN'}[suffix]
    verdict(case,'project_scope:'+variant,snap,tr,expected)

@pytest.mark.parametrize('aligner,expected',[('ALIGN_SUM','PASS'),('ALIGN_COUNT','FAIL')])
def test_enumeration_alert_counts_events_not_samples(aligner,expected):
    case=find('gcp_logging_enumeration_alert')
    def mutate(row,routes):
        row['metricDescriptor']={'type':'logging.googleapis.com/user/review','metricKind':'DELTA','valueType':'INT64'}
        threshold=routes['https://monitoring.googleapis.com/v3/'+P+'/alertPolicies']['data']['alertPolicies'][0]['conditions'][0]['conditionThreshold']
        threshold['aggregations'][0].update(perSeriesAligner=aligner,crossSeriesReducer='REDUCE_SUM')
    snap,tr=capture(case,mutate=mutate)
    # Five DELTA samples each containing 100 matching events: ALIGN_SUM sees
    # 500 events, whereas ALIGN_COUNT sees five samples and never exceeds 10.
    verdict(case,'enumeration_event_count:'+aligner,snap,tr,expected)
