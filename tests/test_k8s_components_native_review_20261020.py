"""Independent native HTTP declarations -> bounded SDK -> collect -> public engine.

No historical CASES or derived component projections are used as native input.
The table spells out each reviewed source policy independently of its evaluator.
"""
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import socket
from urllib.parse import urlsplit, parse_qs

import pytest
from kubernetes import client
from urllib3.response import HTTPResponse

from peaso.collectors import k8s
from peaso.engine import evaluate_snapshot

ROOT = Path(__file__).resolve().parents[1]
QUEUE = json.loads((ROOT / 'tests/fixtures/k8s_review_batches.json').read_text())
BATCHES = {b['name']: b['ids'] for b in QUEUE['batches'] if b['name'].startswith('components_')}
ASSIGNED = [(batch, cid) for batch, ids in BATCHES.items() for cid in ids]
CAPTURES = {}


@pytest.fixture(scope='session', autouse=True)
def optional_native_receipt():
 yield
 if os.environ.get('K8S_COMPONENT_NATIVE_CAPTURE'):
  Path(os.environ['K8S_COMPONENT_NATIVE_CAPTURE']).write_text(json.dumps(CAPTURES,sort_keys=True)+'\n')
# suffix, binary, comma-separated native flag names, safe declaration, unsafe declaration
POLICY_ROWS = '''
container_argument_etcd_auto_tls_disabled|etcd|auto-tls|false|true
container_argument_etcd_certfile_and_keyfile_configured|etcd|cert-file,key-file|/etc/etcd/tls.pem|
container_argument_etcd_client_cert_auth_enabled|etcd|client-cert-auth|true|false
reference_etcd_no_peer_auto_tls|etcd|peer-auto-tls|false|true
container_argument_etcd_peer_certfile_and_peer_keyfile_configured|etcd|peer-cert-file,peer-key-file|/etc/etcd/peer.pem|
container_arg_peer_client_cert_auth_enabled|etcd|peer-client-cert-auth|true|false
container_argument_api_server_anonymous_auth_disabled|kube-apiserver|anonymous-auth|false|true
reference_apiserver_audit_log_maxage_set|kube-apiserver|audit-log-maxage|30|31
container_argument_audit_log_maxage_greater_than_30|kube-apiserver|audit-log-maxage|30|29
reference_apiserver_audit_log_maxbackup_set|kube-apiserver|audit-log-maxbackup|10|11
container_argument_audit_log_maxbackup_greater_than_10|kube-apiserver|audit-log-maxbackup|10|9
reference_apiserver_audit_log_maxsize_set|kube-apiserver|audit-log-maxsize|100|101
container_argument_audit_log_maxsize_greater_than_100|kube-apiserver|audit-log-maxsize|100|99
container_argument_audit_log_path_configured|kube-apiserver|audit-log-path|/var/log/audit.log|
container_argument_authorization_mode_node|kube-apiserver|authorization-mode|Node,RBAC|RBAC
container_argument_authorization_mode_rbac|kube-apiserver|authorization-mode|Node,RBAC|Node
container_argument_authorization_mode_no_always_allow|kube-apiserver|authorization-mode|Node,RBAC|AlwaysAllow
container_admission_control_plugin_always_pull_images|kube-apiserver|enable-admission-plugins|AlwaysPullImages,NodeRestriction|NodeRestriction
container_no_argument_basic_auth_file|kube-apiserver|basic-auth-file|ABSENT|/etc/auth.csv
reference_apiserver_client_ca_file_set|kube-apiserver|client-ca-file|/etc/kubernetes/ca.crt|
container_argument_namespace_lifecycle_enabled|kube-apiserver|enable-admission-plugins|NamespaceLifecycle,ServiceAccount|NodeRestriction
container_argument_node_restriction_enabled|kube-apiserver|enable-admission-plugins|NodeRestriction,ServiceAccount|NamespaceLifecycle
container_argument_pod_security_policy_enabled|kube-apiserver|enable-admission-plugins|PodSecurityPolicy|NamespaceLifecycle
container_no_argument_insecure_bind_address|kube-apiserver|insecure-bind-address|ABSENT|0.0.0.0
container_argument_insecure_port_0|kube-apiserver|insecure-port|0|8080
container_argument_etcd_cafile_configured|kube-apiserver|etcd-cafile|/etc/kubernetes/etcd-ca.crt|
container_argument_kube_apiserver_etcd_certfile_and_keyfile_configured|kube-apiserver|etcd-certfile,etcd-keyfile|/etc/kubernetes/etcd.pem|
container_argument_kubelet_client_certificate_and_key_configured|kube-apiserver|kubelet-client-certificate,kubelet-client-key|/etc/kubernetes/kubelet.pem|
container_argument_service_account_enabled|kube-apiserver|enable-admission-plugins|ServiceAccount,NamespaceLifecycle|NodeRestriction
container_argument_security_context_deny_enabled|kube-apiserver|enable-admission-plugins|SecurityContextDeny|NamespaceLifecycle
container_admission_control_plugin_no_always_admit|kube-apiserver|enable-admission-plugins|NodeRestriction|AlwaysAdmit
container_encryption_providers_configured|kube-apiserver|encryption-provider-config|/etc/kubernetes/encryption.yaml|
container_kubelet_certificate_authority_configured|kube-apiserver|kubelet-certificate-authority|/etc/kubernetes/ca.crt|
container_argument_kubelet_https_enabled|kube-apiserver|kubelet-https|true|false
container_argument_kube_apiserver_profiling_disabled|kube-apiserver|profiling|false|true
container_argument_secure_port_not_0|kube-apiserver|secure-port|6443|0
container_argument_service_account_key_file_appropriate|kube-apiserver|service-account-key-file|/etc/kubernetes/sa.pub|
container_argument_service_account_lookup_enabled|kube-apiserver|service-account-lookup|true|false
container_argument_kube_apiserver_tls_cert_file_and_tls_private_key_file_configured|kube-apiserver|tls-cert-file,tls-private-key-file|/etc/kubernetes/tls.pem|
container_strong_kube_apiserver_cryptographic_ciphers|kube-apiserver|tls-cipher-suites|TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|TLS_RSA_WITH_3DES_EDE_CBC_SHA
container_token_auth_file_not_configured|kube-apiserver|token-auth-file|ABSENT|/etc/tokens.csv
container_argument_kube_controller_manager_bind_address_127_0_0_1|kube-controller-manager|bind-address|127.0.0.1|0.0.0.0
container_argument_kube_controller_manager_profiling_disabled|kube-controller-manager|profiling|false|true
container_argument_kube_controller_manager_root_ca_file_configured|kube-controller-manager|root-ca-file|/etc/kubernetes/ca.crt|
container_argument_kube_controller_manager_service_account_private_key_file_configured|kube-controller-manager|service-account-private-key-file|/etc/kubernetes/sa.key|
container_argument_kubelet_terminated_pod_gc_threshold_configured|kube-controller-manager|terminated-pod-gc-threshold|12500|0
container_argument_kube_controller_manager_service_account_credentials_enabled|kube-controller-manager|use-service-account-credentials|true|false
container_argument_kube_scheduler_bind_address_127_0_0_1|kube-scheduler|bind-address|127.0.0.1|0.0.0.0
container_argument_kube_scheduler_profiling_disabled|kube-scheduler|profiling|false|true
container_argument_anonymous_auth_disabled|kubelet|anonymous-auth|false|true
container_argument_kubelet_authorization_mode_no_always_allow|kubelet|authorization-mode|Webhook|AlwaysAllow
container_argument_kubelet_client_ca_file_configured|kubelet|client-ca-file|/etc/kubernetes/ca.crt|
container_argument_event_qps_less_than_5|kubelet|event-qps|5|6
container_no_argument_hostname_override_configured|kubelet|hostname-override|ABSENT|overridden-node
container_argument_make_iptables_util_chains_enabled|kubelet|make-iptables-util-chains|true|false
container_argument_protect_kernel_defaults_enabled|kubelet|protect-kernel-defaults|true|false
container_argument_kubelet_read_only_port_0|kubelet|read-only-port|0|10255
container_rotate_certificate_enabled|kubelet|rotate-certificates|true|false
container_streaming_connection_idle_timeout_not_zero|kubelet|streaming-connection-idle-timeout|0h0m1s|0.000ms
container_argument_kubelet_tls_cert_file_and_tls_private_key_file_configured|kubelet|tls-cert-file,tls-private-key-file|/etc/kubernetes/tls.pem|
container_strong_kubelet_cryptographic_ciphers|kubelet|tls-cipher-suites|TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|TLS_RSA_WITH_3DES_EDE_CBC_SHA
container_argument_rotate_kubelet_server_certificate_enabled|kubelet|feature-gates|RotateKubeletServerCertificate=true|RotateKubeletServerCertificate=false
'''
POLICIES = {parts[0]: tuple(parts[1:]) for parts in (line.split('|') for line in POLICY_ROWS.strip().splitlines())}
# Explicit native paths, GVKs and container paths, not imported from the producer.
KINDS = {
 'pod': ('/api/v1', 'pods', 'Pod', 'spec'),
 'podtemplate': ('/api/v1', 'podtemplates', 'PodTemplate', 'template.spec'),
 'replicationcontroller': ('/api/v1', 'replicationcontrollers', 'ReplicationController', 'spec.template.spec'),
 'deployment': ('/apis/apps/v1', 'deployments', 'Deployment', 'spec.template.spec'),
 'daemonset': ('/apis/apps/v1', 'daemonsets', 'DaemonSet', 'spec.template.spec'),
 'replicaset': ('/apis/apps/v1', 'replicasets', 'ReplicaSet', 'spec.template.spec'),
 'statefulset': ('/apis/apps/v1', 'statefulsets', 'StatefulSet', 'spec.template.spec'),
 'job': ('/apis/batch/v1', 'jobs', 'Job', 'spec.template.spec'),
 'cronjob': ('/apis/batch/v1', 'cronjobs', 'CronJob', 'spec.jobTemplate.spec.template.spec'),
}

@pytest.fixture(autouse=True)
def offline(monkeypatch):
 attempts=[]
 def blocked(*args, **kwargs):
  attempts.append('blocked');raise AssertionError('Network/auth forbidden')
 for name in ('create_connection','getaddrinfo','gethostbyname','gethostbyname_ex','gethostbyaddr','getnameinfo'):
  monkeypatch.setattr(socket,name,blocked)
 for name in ('connect','connect_ex','sendto'):
  monkeypatch.setattr(socket.socket,name,blocked)
 from kubernetes import config
 for name in ('load_kube_config','load_incluster_config','new_client_from_config'):
  monkeypatch.setattr(config,name,blocked)
 yield
 assert not attempts


def native_object(kind, binary, flags, *, version='v1.18.0'):
 prefix,plural,gvk,path=KINDS[kind]
 row={'apiVersion':prefix.removeprefix('/apis/').removeprefix('/api/'),'kind':gvk,
      'metadata':{'name':'component-review','namespace':'kube-system','uid':'native-uid-1','resourceVersion':'71',
                  'labels':{'component':binary}}}
 current=row
 for key in path.split('.'):current=current.setdefault(key,{})
 current['containers']=[{'name':binary,'image':'registry.k8s.io/'+binary+':'+version,
                         'command':[binary], 'args':['--'+key+'='+value for key,value in flags.items()]}]
 return row


def containers(row,kind):
 for key in KINDS[kind][3].split('.'):row=row[key]
 return row['containers']


def collect_native(kind, payloads, *, options=None, namespace='kube-system'):
 config=client.Configuration();config.host='https://components-native.invalid';config.verify_ssl=True
 config.api_key={'authorization':'Bearer inert-offline-token'};config.proxy=None
 sdk=client.ApiClient(config);api=k8s._wrap_client(sdk)
 calls=[];payloads=iter(payloads)
 class Pool:
  def request(self,method,url,**kwargs):
   target=urlsplit(url);prefix,plural,_,_=KINDS[kind]
   assert method=='GET' and target.scheme=='https' and target.netloc=='components-native.invalid'
   assert target.path==prefix+'/namespaces/'+namespace+'/'+plural
   assert kwargs['redirect'] is False and kwargs['retries'] is False
   query=dict(kwargs.get('fields') or []);query.update({k:v[0] for k,v in parse_qs(target.query).items()})
   assert set(query)<= {'limit','continue'} and int(query['limit'])>0
   calls.append((method,target.path,query))
   payload=next(payloads)
   status=403 if payload=='DENIED' else 200
   body={'kind':'Status','apiVersion':'v1','status':'Failure','reason':'Forbidden','code':403} if status==403 else payload
   return HTTPResponse(body=io.BytesIO(json.dumps(body).encode()),status=status,
                       headers={'Content-Type':'application/json'},preload_content=False)
  def clear(self):pass
 api.api_client.rest_client.pool_manager.pool=Pool()
 try:
  snapshot=k8s.collect({'provider':'k8s','scopes':[namespace],'auth':{'cluster_id':'review-cluster'},
                        'options':{'inventories':[kind],'max_workers':1,**(options or {})}},api=api)
 finally:api.close()
 assert calls
 return snapshot,calls


def native_list(kind, rows, *, token=None, rv='71'):
 prefix,_,gvk,_=KINDS[kind]
 return {'apiVersion':prefix.removeprefix('/apis/').removeprefix('/api/'),'kind':gvk+'List',
         'metadata':{'resourceVersion':rv,**({'continue':token} if token else {})},'items':rows}


def evaluate_native(cid,row=None,*,payloads=None,options=None):
 kind=cid.split('.')[2]
 snapshot,calls=collect_native(kind,payloads if payloads is not None else [native_list(kind,[row])],options=options)
 report=evaluate_snapshot(snapshot,checks=[cid])
 findings=[f for f in report['findings'] if f['check_id']==cid]
 assert findings,report
 if len(findings)>1:
  assert snapshot['collections'][0]['status']=='partial'
  assert any(f['status']=='UNKNOWN' for f in findings),findings
  findings=[f for f in findings if f.get('native_resource_id')]
 assert len(findings)==1,findings
 return findings[0]['status'],snapshot,findings[0],calls

CASES_NATIVE=('safe','unsafe','missing','malformed','denied','partial','foreign','ordinary','wrapped','duplicate')
@pytest.mark.parametrize('batch,cid',ASSIGNED,ids=[b+':'+c for b,c in ASSIGNED])
@pytest.mark.parametrize('case',CASES_NATIVE)
def test_per_id_native_http(batch,cid,case):
 binary,names,good,bad=POLICIES[cid.split('.',3)[3]];kind=cid.split('.')[2]
 value=bad if case=='unsafe' else good
 flags={} if value=='ABSENT' or case=='missing' else {name:value for name in names.split(',')}
 row=native_object(kind,binary,flags)
 expected='FAIL' if case=='unsafe' else 'PASS'
 payloads=None;options=None
 if case=='missing':expected='PASS' if good=='ABSENT' else 'UNKNOWN'
 if case=='malformed':containers(row,kind)[0]['args']=42;expected='UNKNOWN'
 if case=='denied':payloads=['DENIED'];expected='DENIED'
 if case=='partial':payloads=[native_list(kind,[row],token='page-2')];options={'max_pages':1}
 if case=='foreign':row['metadata']['namespace']='other';expected='UNKNOWN'
 if case=='ordinary':
  row['metadata']['labels']={};containers(row,kind)[0].update(name='app',command=['app'],args=[]);expected='NOT_APPLICABLE'
 if case=='wrapped':containers(row,kind)[0]['command']=['/bin/sh','-c',binary];expected='UNKNOWN'
 if case=='duplicate':
  name=names.split(',')[0];containers(row,kind)[0]['args']=['--'+name+'='+bad,'--'+name+'='+good];expected='UNKNOWN'
 status,snapshot,finding,calls=evaluate_native(cid,row,payloads=payloads,options=options)
 assert status==expected,(cid,case,finding)
 if case in ('safe','unsafe','missing'):
  projected=snapshot['collections'][0]['items'][0]
  assert projected['provenance']['cluster_id']=='review-cluster'
  assert projected['provenance']['namespace']=='kube-system'
  assert projected['provenance']['uid']=='native-uid-1'
  assert projected['provenance']['resourceVersion']=='71'
  output=json.dumps(projected)
  assert '"command":' not in output and '"args":' not in output
  if case in ('safe','unsafe'):
   CAPTURES[cid+':'+case]={'http_requests':calls,'native_response':native_list(kind,[row]),
      'collected_object':projected,'engine_status':status,'engine_evidence':finding['evidence']}

@pytest.mark.parametrize('argv,wanted',[
 (['kube-apiserver','--anonymous-auth','false'],'UNKNOWN'),
 (['kube-apiserver','--','--anonymous-auth=false'],'UNKNOWN'),
 (['kube-apiserver','--anonymous_auth=true','--anonymous-auth=false'],'UNKNOWN'),
 (['kube-apiserver','--profiling','false','--anonymous-auth=false'],'UNKNOWN'),
])
def test_native_argv_not_a_different_pflag_declaration(argv,wanted):
 cid='k8s.ports.pod.container_argument_api_server_anonymous_auth_disabled'
 row=native_object('pod','kube-apiserver',{})
 containers(row,'pod')[0].update(command=argv,args=[])
 status,_,finding,_=evaluate_native(cid,row)
 assert status==wanted,finding

@pytest.mark.parametrize('plugin', ['AlwaysPullImages','NodeRestriction','NamespaceLifecycle','ServiceAccount'])
def test_native_enable_disable_contradiction_never_passes(plugin):
 suffix={'AlwaysPullImages':'container_admission_control_plugin_always_pull_images',
         'NodeRestriction':'container_argument_node_restriction_enabled',
         'NamespaceLifecycle':'container_argument_namespace_lifecycle_enabled',
         'ServiceAccount':'container_argument_service_account_enabled'}[plugin]
 row=native_object('pod','kube-apiserver',{'enable-admission-plugins':plugin,'disable-admission-plugins':plugin})
 status,_,finding,_=evaluate_native('k8s.ports.pod.'+suffix,row)
 assert status=='UNKNOWN',finding

@pytest.mark.parametrize('kind',list(KINDS))
@pytest.mark.parametrize('value',['','garbage','Node,,RBAC','Webhook,Unknown'])
def test_native_invalid_authorizer_is_not_safe_exclusion(kind,value):
 row=native_object(kind,'kube-apiserver',{'authorization-mode':value})
 status,_,finding,_=evaluate_native('k8s.ports.'+kind+'.container_argument_authorization_mode_no_always_allow',row)
 assert status=='UNKNOWN',finding

@pytest.mark.parametrize('argv',[
 ['/bin/sh','-c','/usr/local/bin/kube-apiserver'],
 ['/usr/bin/env','/usr/local/bin/kube-apiserver'],
])
def test_native_wrapped_absolute_component_without_name_or_labels_is_unresolved(argv):
 cid='k8s.ports.pod.container_argument_api_server_anonymous_auth_disabled'
 row=native_object('pod','kube-apiserver',{})
 row['metadata']['labels']={}
 containers(row,'pod')[0].update(name='control',command=argv,args=[])
 status,_,finding,_=evaluate_native(cid,row)
 assert status=='UNKNOWN',finding

@pytest.mark.parametrize('value',[
 'RotateKubeletServerCertificate=true,RotateKubeletServerCertificate=false',
 'RotateKubeletServerCertificate=false,RotateKubeletServerCertificate=true',
])
def test_native_duplicate_feature_gate_does_not_become_set_membership_pass(value):
 row=native_object('pod','kubelet',{'feature-gates':value})
 status,_,finding,_=evaluate_native('k8s.ports.pod.container_argument_rotate_kubelet_server_certificate_enabled',row)
 assert status=='UNKNOWN',finding

@pytest.mark.parametrize('kind',list(KINDS))
@pytest.mark.parametrize('case',['empty','missing_spec','wrong_kind','wrong_api','duplicate_names','bad_uid_namespace','two_pages'])
def test_native_workload_binding_and_pagination(kind,case):
 cid='k8s.ports.'+kind+'.container_argument_api_server_anonymous_auth_disabled'
 row=native_object(kind,'kube-apiserver',{'anonymous-auth':'false'})
 payloads=None;wanted='UNKNOWN'
 if case=='empty':payloads=[native_list(kind,[])];wanted='EMPTY'
 if case=='missing_spec':row.pop(KINDS[kind][3].split('.')[0])
 if case=='wrong_kind':row['kind']='Secret'
 if case=='wrong_api':row['apiVersion']='foreign.example/v1'
 if case=='duplicate_names':containers(row,kind).append(deepcopy(containers(row,kind)[0]))
 if case=='bad_uid_namespace':row['metadata']['namespace']='another-namespace'
 if case=='two_pages':
  other=deepcopy(row);other['metadata'].update(uid='native-uid-2',name='second')
  payloads=[native_list(kind,[row],token='next'),native_list(kind,[other])];wanted='PASS'
  snapshot,calls=collect_native(kind,payloads)
  assert len(calls)==2 and calls[1][2]['continue']=='next'
  findings=evaluate_snapshot(snapshot,checks=[cid])['findings']
  assert len(findings)==2 and all(f['status']==wanted for f in findings),findings
  return
 status,_,finding,_=evaluate_native(cid,row,payloads=payloads)
 assert status==wanted,finding

@pytest.mark.parametrize('kind',list(KINDS))
@pytest.mark.parametrize('limit',['argv','value','resource'])
def test_native_component_bounds_are_not_clean_pass(kind,limit):
 cid='k8s.ports.'+kind+'.container_argument_api_server_anonymous_auth_disabled'
 row=native_object(kind,'kube-apiserver',{'anonymous-auth':'false'})
 options=None
 if limit=='argv':containers(row,kind)[0]['args']+=['opaque']*1024
 if limit=='value':containers(row,kind)[0]['args']+=['--audit-log-path='+'a'*2049]
 if limit=='resource':options={'max_resources':1};other=deepcopy(row);other['metadata']['uid']='second'
 payloads=[native_list(kind,[row,other])] if limit=='resource' else None
 status,snapshot,finding,_=evaluate_native(cid,row,payloads=payloads,options=options)
 assert status==('PASS' if limit=='resource' else 'UNKNOWN'),finding
 if limit=='resource':assert snapshot['collections'][0]['status']=='partial'

@pytest.mark.parametrize('value,wanted', [('false','PASS'),('FALSE','PASS'),('False','PASS'),('0','PASS'),('f','PASS'),('F','PASS'),
                                         ('true','FAIL'),('TRUE','FAIL'),('1','FAIL'),('T','FAIL'),('t','FAIL'),('bogus','UNKNOWN')])
def test_native_bool_spellings_match_go_bool_parser(value,wanted):
 row=native_object('pod','kube-apiserver',{'anonymous-auth':value})
 status,_,finding,_=evaluate_native('k8s.ports.pod.container_argument_api_server_anonymous_auth_disabled',row)
 assert status==wanted,finding

@pytest.mark.parametrize('binary,field,cid,value,wanted',[
 ('kube-apiserver','anonymous-auth','container_argument_api_server_anonymous_auth_disabled','false','PASS'),
 ('kube-apiserver','token-auth-file','container_token_auth_file_not_configured','/etc/tokens.csv','FAIL'),
 ('kubelet','read-only-port','container_argument_kubelet_read_only_port_0','0','PASS'),
])
def test_native_kubernetes_underscore_alias_is_same_flag(binary,field,cid,value,wanted):
 row=native_object('pod',binary,{field.replace('-','_'):value})
 status,_,finding,_=evaluate_native('k8s.ports.pod.'+cid,row)
 assert status==wanted,finding

@pytest.mark.parametrize('field,value', [('audit-log-path','/var/log/audit.log'),('audit-log-maxage','30')])
def test_native_nonbool_space_values_are_consumed(field,value):
 suffix='container_argument_audit_log_path_configured' if field=='audit-log-path' else 'container_argument_audit_log_maxage_greater_than_30'
 row=native_object('pod','kube-apiserver',{})
 containers(row,'pod')[0]['args']=['--'+field,value]
 assert evaluate_native('k8s.ports.pod.'+suffix,row)[0]=='PASS'

@pytest.mark.parametrize('field',['audit-log-path','audit-log-maxage'])
def test_native_nonbool_without_value_is_unresolved(field):
 row=native_object('pod','kube-apiserver',{'anonymous-auth':'false'})
 containers(row,'pod')[0]['args'].append('--'+field)
 assert evaluate_native('k8s.ports.pod.container_argument_api_server_anonymous_auth_disabled',row)[0]=='UNKNOWN'

@pytest.mark.parametrize('kind',list(KINDS))
@pytest.mark.parametrize('version,plugins,wanted',[
 ('v1.24.0','PodSecurityPolicy','PASS'),('v1.24.0','NamespaceLifecycle','FAIL'),
 ('v1.25.0','PodSecurityPolicy','FAIL'),('v1.25.0','SecurityContextDeny','PASS'),
 ('v1.29.1','SecurityContextDeny','PASS'),('v1.30.0','SecurityContextDeny','NOT_APPLICABLE'),
 ('v1.25.0-alpha.1','SecurityContextDeny','UNKNOWN'),
])
def test_native_legacy_admission_version_bands(kind,version,plugins,wanted):
 row=native_object(kind,'kube-apiserver',{'enable-admission-plugins':plugins},version=version)
 status,_,finding,_=evaluate_native('k8s.ports.'+kind+'.container_argument_security_context_deny_enabled',row)
 assert status==wanted,finding

@pytest.mark.parametrize('kind',list(KINDS))
@pytest.mark.parametrize('version,value,wanted',[
 ('v1.18.0','true','PASS'),('v1.18.0','false','FAIL'),
 ('v1.19.0','true','NOT_APPLICABLE'),('v1.19.0','false','NOT_APPLICABLE'),
 ('v1.22.0','true','NOT_APPLICABLE'),('v1.37.0','false','NOT_APPLICABLE'),
 ('v1.19.0-alpha.1','true','UNKNOWN'),(None,'true','UNKNOWN'),
])
def test_native_kubelet_https_effective_flag_version_boundary(kind,version,value,wanted):
 row=native_object(kind,'kube-apiserver',{'kubelet-https':value},version=version or 'v1.18.0')
 if version is None:containers(row,kind)[0]['image']='custom.invalid/control-plane@sha256:'+'0'*64
 status,_,finding,_=evaluate_native('k8s.ports.'+kind+'.container_argument_kubelet_https_enabled',row)
 assert status==wanted,finding
