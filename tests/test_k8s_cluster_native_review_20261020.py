"""Independent native HTTP -> official Kubernetes SDK -> collector -> engine proofs.

No historical CASES are provider inputs. These fixtures describe API objects,
not running processes, CNI behavior, effective authorization, or secret values.
"""
from copy import deepcopy
from hashlib import sha256
import gzip
import inspect
import io
import json
import os
from pathlib import Path
import socket
import sys
from urllib.parse import urlsplit

import pytest
import urllib3
from kubernetes import client, config

from peaso.checks import CHECKS
from peaso.collectors import k8s
from peaso.engine import evaluate_snapshot, plan_collection

ROOT = Path(__file__).resolve().parents[1]
QUEUE = json.loads((ROOT / 'docs/check-review/k8s-review-queue-20261020.json').read_text())
BATCHES = {b['name']: b['ids'] for b in QUEUE['batches'] if b['name'].startswith('cluster_and_native_')}
IDS = tuple(cid for rows in BATCHES.values() for cid in rows)
TEST_IDS = BATCHES.get(os.environ.get('K8S_CLUSTER_BATCH'), IDS)
REGISTRY = {c.id: c for c in CHECKS if c.id in IDS}
RECEIPTS = []
WORKLOADS = {'pod': ('v1', 'Pod', 'spec'), 'podtemplate': ('v1', 'PodTemplate', 'template.spec'),
    'replicationcontroller': ('v1', 'ReplicationController', 'spec.template.spec'),
    **{k: ('apps/v1', v, 'spec.template.spec') for k, v in [('deployment','Deployment'),('daemonset','DaemonSet'),('statefulset','StatefulSet'),('replicaset','ReplicaSet')]},
    'job': ('batch/v1','Job','spec.template.spec'), 'cronjob': ('batch/v1','CronJob','spec.jobTemplate.spec.template.spec')}
GVK = {**{k:v[:2] for k,v in WORKLOADS.items()},
    'namespace':('v1','Namespace'), 'node':('v1','Node'), 'service':('v1','Service'), 'serviceaccount':('v1','ServiceAccount'),
    'role':('rbac.authorization.k8s.io/v1','Role'), 'clusterrole':('rbac.authorization.k8s.io/v1','ClusterRole'),
    'rolebinding':('rbac.authorization.k8s.io/v1','RoleBinding'), 'clusterrolebinding':('rbac.authorization.k8s.io/v1','ClusterRoleBinding'),
    'ingress':('networking.k8s.io/v1','Ingress'), 'ingressclass':('networking.k8s.io/v1','IngressClass'),
    'networkpolicy':('networking.k8s.io/v1','NetworkPolicy'), 'resourcequota':('v1','ResourceQuota'), 'limitrange':('v1','LimitRange'),
    'endpointslice':('discovery.k8s.io/v1','EndpointSlice'), 'secret_metadata':('meta.k8s.io/v1','PartialObjectMetadata'),
    'configmap_metadata':('meta.k8s.io/v1','PartialObjectMetadata'), 'podsecuritypolicy':('policy/v1beta1','PodSecurityPolicy')}


@pytest.fixture(autouse=True)
def hard_block_network_auth(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('live network, DNS, or credential discovery attempted')
    for name in ('connect','connect_ex'):
        monkeypatch.setattr(socket.socket, name, blocked)
    for name in ('create_connection','getaddrinfo','gethostbyname','gethostbyname_ex'):
        monkeypatch.setattr(socket, name, blocked)
    for name in ('load_kube_config','load_incluster_config','new_client_from_config'):
        monkeypatch.setattr(config, name, blocked)
    monkeypatch.setattr(k8s, '_new_api', blocked)


@pytest.fixture(scope='session', autouse=True)
def write_receipts():
    yield
    destination = os.environ.get('K8S_CLUSTER_REVIEW_RECEIPTS')
    if destination:
        p = Path(destination); p.mkdir(parents=True, exist_ok=True)
        (p / 'native-cases.json').write_text(json.dumps(RECEIPTS, separators=(',',':'))+'\n')


def put(row, path, value):
    parts = path.split('.')
    for key in parts[:-1]:row = row.setdefault(key,{})
    row[parts[-1]] = value


def obj(kind, **fields):
    version, typ = GVK[kind]
    namespaced = kind not in {'namespace','node','clusterrole','clusterrolebinding','ingressclass','podsecuritypolicy'}
    row = {'apiVersion':version,'kind':typ,'metadata':{'name':'application','uid':'7b230084-289d-4b8f-a743-f5f3a7ed4435','resourceVersion':'71',
        **({'namespace':'apps'} if namespaced else {})}, **deepcopy(fields)}
    if kind=='namespace':row['metadata']['name']='apps'
    if kind in WORKLOADS:
        spec={'containers':[{'name':'web','image':'registry.example.test/team/web:v2','imagePullPolicy':'Always'}], 'os':{'name':'linux'}}
        put(row, WORKLOADS[kind][2], spec)
        if kind not in ('pod','podtemplate'):
            row['spec']['selector']={'matchLabels':{'app':'web'}} if kind not in ('replicationcontroller','job','cronjob') else {'app':'web'}
            template = row['spec']['jobTemplate']['spec']['template'] if kind=='cronjob' else row['spec']['template']
            template['metadata']={'labels':{'app':'web'}}
            if kind in ('job','cronjob'):template['spec']['restartPolicy']='Never'
            if kind=='cronjob':row['spec']['schedule']='0 * * * *'
            if kind=='statefulset':row['spec']['serviceName']='web'
    return row


def spec_of(row, kind):
    for part in WORKLOADS[kind][2].split('.'):row = row[part]
    return row


def rule(group='', resource='configmaps', verb='get'):
    return {'apiGroups':[group],'resources':[resource],'verbs':[verb]}


# Independently written CEL declarations exercising the documented VAP subset.
CONTAINER_CEL = {
 'allowprivilegeescalation':'has(c.securityContext) && has(c.securityContext.allowPrivilegeEscalation) && c.securityContext.allowPrivilegeEscalation == false',
 'capabilities_add':'!has(c.securityContext) || !has(c.securityContext.capabilities) || !has(c.securityContext.capabilities.add) || size(c.securityContext.capabilities.add) == 0',
 'capabilities_add_net_raw':'!has(c.securityContext) || !has(c.securityContext.capabilities) || !has(c.securityContext.capabilities.add) || !c.securityContext.capabilities.add.exists(x, x == "NET_RAW")',
 'capabilities_drop':'has(c.securityContext) && has(c.securityContext.capabilities) && has(c.securityContext.capabilities.drop) && c.securityContext.capabilities.drop.exists(x, x == "ALL")',
 'container_ports_hostport':'!has(c.ports) || c.ports.all(p, !has(p.hostPort) || p.hostPort == 0)',
 'privileged':'!has(c.securityContext) || !has(c.securityContext.privileged) || c.securityContext.privileged == false',
 'runasnonroot':'((has(c.securityContext) && has(c.securityContext.runAsNonRoot)) ? c.securityContext.runAsNonRoot == true : (has(object.spec.securityContext) && has(object.spec.securityContext.runAsNonRoot) && object.spec.securityContext.runAsNonRoot == true))',
 'windowsoptions_hostprocess':'!has(c.securityContext) || !has(c.securityContext.windowsOptions) || !has(c.securityContext.windowsOptions.hostProcess) || c.securityContext.windowsOptions.hostProcess == false'}


def admission_rows(cid, good):
    suffix=cid.removeprefix('k8s.cis.admission_')
    if suffix in ('hostipc','hostpid','hostnetwork'):
        field={'hostipc':'hostIPC','hostpid':'hostPID','hostnetwork':'hostNetwork'}[suffix]
        expression=f'!has(object.spec.{field}) || object.spec.{field} == false'
    elif suffix=='hostpath':expression='!has(object.spec.volumes) || object.spec.volumes.all(v, !has(v.hostPath))'
    else:
        check=CONTAINER_CEL[suffix]
        expression=' && '.join([f'object.spec.containers.all(c, {check})',f'(!has(object.spec.initContainers) || object.spec.initContainers.all(c, {check}))',f'(!has(object.spec.ephemeralContainers) || object.spec.ephemeralContainers.all(c, {check}))'])
        if suffix=='windowsoptions_hostprocess':
            expression='(!has(object.spec.securityContext) || !has(object.spec.securityContext.windowsOptions) || !has(object.spec.securityContext.windowsOptions.hostProcess) || object.spec.securityContext.windowsOptions.hostProcess == false) && '+expression
    policy={'apiVersion':'admissionregistration.k8s.io/v1','kind':'ValidatingAdmissionPolicy',
        'metadata':{'name':'restrict-workloads','uid':'policy-uid','resourceVersion':'71'},
        'spec':{'failurePolicy':'Fail','matchConstraints':{'resourceRules':[{'apiGroups':[''],'apiVersions':['v1'],'operations':['CREATE','UPDATE'],'resources':['pods']}]},'validations':[{'expression':expression}]}}
    binding={'apiVersion':'admissionregistration.k8s.io/v1','kind':'ValidatingAdmissionPolicyBinding',
        'metadata':{'name':'restrict-workloads','uid':'binding-uid','resourceVersion':'71'},
        'spec':{'policyName':'restrict-workloads','validationActions':['Deny' if good else 'Audit']}}
    return {'admission_policy':[policy,binding],'namespace':[obj('namespace',spec={})]}


def recipe(cid, good=True):
    """Explicit native configurations, selected by control meaning, never CASES."""
    check=REGISTRY[cid]; kind=check.kind; slug=cid.rsplit('.',1)[-1]
    if kind=='admission_policy':return admission_rows(cid,good), 'PASS' if good else 'FAIL'
    if kind=='k8s_selected_literals':return {}, 'UNKNOWN'
    row=obj(kind); rows={kind:[row]}; wanted='PASS' if good else 'FAIL'
    if kind in ('role','clusterrole'):
        group,resource,verb='', 'configmaps','get'
        if not good:
            if 'wildcard' in cid:resource='*'
            elif 'no_bind' in cid:group,resource,verb='rbac.authorization.k8s.io','roles','bind'
            elif 'no_pod_create' in cid:resource,verb='pods','create'
            elif 'no_secret_read' in cid:resource='secrets'
            elif 'no_impersonation' in cid:resource,verb='users','impersonate'
            elif 'interactive' in cid:resource,verb='pods/exec','create'
            elif 'service_status' in cid:resource,verb='services/status','patch'
            elif 'workload_controller' in cid:group,resource,verb='apps','deployments','create'
            elif 'escalate' in cid:group,resource,verb='rbac.authorization.k8s.io','roles','escalate'
            elif 'approve_certificate' in cid:group,resource,verb='certificates.k8s.io','signers','approve'
            elif 'admission_webhook' in cid:group,resource,verb='admissionregistration.k8s.io','validatingwebhookconfigurations','patch'
            elif 'default_namespace' not in cid:raise AssertionError(cid)
        row['rules']=[rule(group,resource,verb)]
    elif kind in ('rolebinding','clusterrolebinding'):
        row['roleRef']={'apiGroup':'rbac.authorization.k8s.io','kind':'ClusterRole','name':'reviewed-role'}
        subject={'kind':'User','name':'alice','apiGroup':'rbac.authorization.k8s.io'}
        if 'default_service_account' in cid:
            subject={'kind':'ServiceAccount','name':'application' if good else 'default','namespace':'apps'}
        elif 'anonymous' in cid:subject['name']='alice' if good else 'system:anonymous'
        elif 'review_' in cid and not good:subject={'kind':'Group','name':'system:authenticated','apiGroup':'rbac.authorization.k8s.io'}
        elif 'system_masters' in cid:
            rows['rolebinding']=[]
            if good:wanted='UNKNOWN'
            else:subject={'kind':'Group','name':'system:masters','apiGroup':'rbac.authorization.k8s.io'}
        elif 'psp_binding' in cid:
            return {'api_discovery':[]}, 'NOT_APPLICABLE'
        if 'no_human' in cid:
            permissions={'no_human_csr_approval':('certificates.k8s.io','certificatesigningrequests/approval','update'),
                'no_human_node_proxy':('','nodes/proxy','get'),'no_human_pv_create':('','persistentvolumes','create'),
                'no_human_serviceaccount_token_create':('','serviceaccounts/token','create'),
                'no_human_webhook_config_write':('admissionregistration.k8s.io','validatingwebhookconfigurations','create')}
            cr=obj('clusterrole',rules=[rule() if good else rule(*permissions[slug])]);cr['metadata']['name']='reviewed-role'; rows['clusterrole']=[cr]
        row['subjects']=[subject]
    elif kind in WORKLOADS:
        s=spec_of(row,kind);c=s['containers'][0]
        if 'dashboard_not_deployed' in cid:c['image']='registry.example.test/team/web:v2' if good else 'docker.io/kubernetesui/dashboard:v2.7.0'
        elif 'no_privileged_port' in cid:c['ports']=[{'containerPort':8080 if good else 80}]
        elif 'secrets_as_files' in cid or 'no_secret_env' in cid:
            c['env']=[{'name':'MODE','value':'production'}] if good else [{'name':'DB_PASSWORD','valueFrom':{'secretKeyRef':{'name':'database','key':'password'}}}]
        elif 'no_literal_secret_env' in cid:c['env']=[{'name':'MODE' if good else 'DB_PASSWORD','value':'sample-only-literal'}]
        elif 'effective_runtime_default_seccomp' in cid or 'runtime_default_seccomp' in cid or cid=='k8s.pod.seccomp':
            s['securityContext']={'seccompProfile':{'type':'RuntimeDefault' if good else 'Unconfined'}}
        elif cid=='k8s_deployment_available_condition':
            s['containers'][0]['ports']=[{'containerPort':8080}];row['spec']['replicas']=3
            row['status']={'availableReplicas':3 if good else 1,'conditions':[{'type':'Available','status':'True' if good else 'False'}]}
        elif 'replicas_minimum_3' in cid:row['spec']['replicas']=3 if good else 1
        elif 'controller_manager_gc_threshold' in cid or 'rotate_kubelet_server_certificate' in cid:
            c.update(name='kube-controller-manager',image='registry.k8s.io/kube-controller-manager:v1.30.0',command=['kube-controller-manager'],args=[('--terminated-pod-gc-threshold='+('12000' if good else '0')) if 'gc_threshold' in cid else '--feature-gates=RotateKubeletServerCertificate='+('true' if good else 'false')])
        elif 'extend_token_expiration' in cid or '.gap.apiserver.' in cid:
            flag='--service-account-extend-token-expiration='+('false' if good else 'true')
            if '.gap.apiserver.' in cid:flag='--enable-admission-plugins='+('DenyServiceExternalIPs' if 'external_ips' in cid else 'EventRateLimit') if good else '--enable-admission-plugins=NodeRestriction'
            c.update(name='kube-apiserver',image='registry.k8s.io/kube-apiserver:v1.30.0',command=['kube-apiserver'],args=[flag])
        elif 'consider_external_secret_storage' in cid:
            s['volumes']=[{'name':'native-secret','secret':{'secretName':'database'}}]
            if good:s['volumes'].append({'name':'external-secret','csi':{'driver':'secrets-store.csi.k8s.io','readOnly':True,'volumeAttributes':{'secretProviderClass':'database'}}})
        elif 'serviceaccount_has_rbac_binding' in cid:
            s['serviceAccountName']='application'
            b=obj('rolebinding',roleRef={'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':'reader'},subjects=[{'kind':'ServiceAccount','name':'application' if good else 'other','namespace':'apps'}]);rows.update(rolebinding=[b],clusterrolebinding=[])
        elif 'secret_pod_rule' in cid:s['imagePullSecrets']=[{'name':'registry'}] if good else []
        elif 'direct_internet_access' in cid:row['status']={'podIPs':[{'ip':'10.12.0.7' if good else '8.8.8.8'}]}
        elif 'effective_run_as_user_nonzero' in cid or 'no_root_user' in cid or 'run_as_user_10000' in cid:c['securityContext']={'runAsUser':12000 if good else 0}
        elif 'no_host_namespaces' in cid:s.update(hostNetwork=not good,hostIPC=False,hostPID=False)
        elif 'no_host_network' in cid:s['hostNetwork']=not good
        elif 'no_host_ipc' in cid:s['hostIPC']=not good
        elif 'no_host_pid' in cid:s['hostPID']=not good
        elif 'no_host_ports' in cid:c['ports']=[{'containerPort':8080,'hostPort':0 if good else 8443}]
        elif 'no_privileged' in cid:c['securityContext']={'privileged':not good}
        elif 'non_root' in cid:c['securityContext']={'runAsNonRoot':good,'runAsUser':10001 if good else 0}
        elif 'no_privilege_escalation' in cid:c['securityContext']={'allowPrivilegeEscalation':not good}
        elif 'read_only_root' in cid:c['securityContext']={'readOnlyRootFilesystem':good}
        elif 'restrict_token_automount' in cid:s['automountServiceAccountToken']=not good
        elif 'no_default_serviceaccount' in cid:s['serviceAccountName']='application' if good else 'default'
        elif 'no_hostpath' in cid:s['volumes']=[] if good else [{'name':'host','hostPath':{'path':'/var/log','type':'Directory'}}]
        elif 'default_proc_mount' in cid:c['securityContext']={'procMount':'Default' if good else 'Unmasked'}
        elif 'restrict_selinux_identity' in cid:c['securityContext']={'seLinuxOptions':{} if good else {'user':'custom_u'}}
        elif 'windows_host_process' in cid:c['securityContext']={'windowsOptions':{'hostProcess':not good}}
        elif any(x in cid for x in ('capabilities','net_raw')):
            caps={'drop':['ALL']} if good else {'add':['NET_RAW']}
            if cid=='k8s.pod.restrict_added_capabilities':caps={'add':['NET_BIND_SERVICE' if good else 'SYS_ADMIN']}
            c['securityContext']={'capabilities':caps}
        elif any(x in cid for x in ('cpu_limits','cpu_requests','memory_limits','memory_requests')):
            group='limits' if 'limits' in cid else 'requests';field='cpu' if 'cpu_' in cid else 'memory'
            c['resources']={group:{field:'250m' if field=='cpu' else '96Mi'}} if good else {}
        elif 'probe_configured' in cid:
            if good:c['livenessProbe' if 'liveness' in cid else 'readinessProbe']={'httpGet':{'path':'/ready','port':8080}}
        elif 'default_namespace' not in cid:raise AssertionError(cid)
    elif kind=='namespace':
        if cid=='k8s.namespace.restricted_admission':row['metadata']['labels']={'pod-security.kubernetes.io/enforce':'restricted' if good else 'privileged'}
        elif 'network_policy_default_deny' in cid:
            direction='Egress' if 'egress' in cid else 'Ingress'
            rows['networkpolicy']=[obj('networkpolicy',spec={'podSelector':{},'policyTypes':[direction],direction.lower():[] if good else [{}]})]
        else:
            resource='memory' if 'memory' in cid else 'cpu';request='request' in cid;dep='limitrange' if 'limit_range' in cid else 'resourcequota'
            quantity='96Mi' if resource=='memory' else '2'
            spec={'limits':[{'type':'Container',('defaultRequest' if request else 'default'):{resource:quantity}}]} if dep=='limitrange' else {'hard':{('requests.' if request else 'limits.')+resource:quantity}}
            rows[dep]=[obj(dep,spec=spec)] if good else []
    elif kind=='networkpolicy':
        direction='Egress' if 'egress' in cid else 'Ingress';field=direction.lower();peer='to' if direction=='Egress' else 'from'
        spec={'podSelector':{},'policyTypes':[direction],field:[{peer:[{'podSelector':{'matchLabels':{'app':'backend'}}}],'ports':[{'port':443,'protocol':'TCP'}]}] if good else [{}]}
        if 'has_ingress_rules' in cid:spec[field]=[{'from':[{'podSelector':{}}]}] if good else []
        if 'associated_podselectors' in cid:spec['podSelector']={'matchLabels':{'app':'web'}} if good else {}
        row['spec']=spec
    elif kind=='ingress':
        backend={'service':{'name':'backend','port':{'number':443}}}
        row['spec']={'ingressClassName':'nginx','tls':[{'hosts':['web.example.test'],'secretName':'tls-web'}], 'rules':[{'host':'web.example.test','http':{'paths':[{'path':'/','pathType':'Prefix','backend':backend}]}}]}
        if 'snippet' in cid:
            row['metadata']['annotations']={} if good else {'nginx.ingress.kubernetes.io/server-snippet':'location /static { alias /var/data; content_by_lua_block {} }'}
            wanted='UNKNOWN'  # Deliberately filtered content; no invented complete marker.
        elif cid=='k8s_ingress_sni_hosts':
            if not good:row['spec']['tls'][0]['hosts']=['other.example.test']
        elif cid=='k8s_ingress_tls_configured':
            sec=obj('secret_metadata');sec['metadata']['name']='tls-web';sec['type']='kubernetes.io/tls' if good else 'Opaque';rows['secret_metadata']=[sec]
        elif cid=='k8s_ingress_backend_https':
            row['metadata']['annotations']={'nginx.ingress.kubernetes.io/backend-protocol':'HTTPS' if good else 'HTTP'}
            svc=obj('service',spec={'type':'ClusterIP','ports':[{'port':443}]});svc['metadata']['name']='backend';rows['service']=[svc]
            ic=obj('ingressclass',spec={'controller':'k8s.io/ingress-nginx'});ic['metadata']['name']='nginx';rows['ingressclass']=[ic]
        elif 'redirect_http' in cid:
            row['metadata']['annotations']={'nginx.ingress.kubernetes.io/ssl-redirect':'true' if good else 'false'}
            ic=obj('ingressclass',spec={'controller':'k8s.io/ingress-nginx'});ic['metadata']['name']='nginx';rows['ingressclass']=[ic]
        elif 'associated_ingress' in cid:
            if not good:row['spec']['rules']=[]
        elif 'default_namespace' not in cid:raise AssertionError(cid)
    elif kind=='endpointslice':
        row['metadata'].update(namespace='default',labels={'kubernetes.io/service-name':'kubernetes'})
        row.update(addressType='IPv4',endpoints=[{'addresses':['10.0.0.1']}],ports=[{'name':'https' if good else 'http','port':6443 if good else 8080,'protocol':'TCP'}])
    elif kind=='node':row['status']={'addresses':[{'type':'ExternalIP','address':'10.0.0.7' if good else '8.8.8.8'}]}
    elif kind=='service':
        row['spec']={'type':'ClusterIP','ports':[{'port':8080,'protocol':'TCP'}],'selector':{'app':'web'}}
        if cid=='k8s.service.review_public_type':row['spec']['type']='ClusterIP' if good else 'NodePort'
        elif 'no_external_ips' in cid:row['spec']['externalIPs']=[] if good else ['203.0.113.7']
        elif 'no_tiller_labels' in cid:row['metadata']['labels']={'app':'web' if good else 'helm'}
        elif 'no_tiller_selector' in cid:row['spec']['selector']={'app':'web'} if good else {'tiller':'enabled'}
        elif 'ftp_endpoint' in cid:row['spec']['ports'][0]['port']=443 if good else 21
        elif 'service_type_forbidden' in cid:row['spec']['type']='ClusterIP' if good else 'LoadBalancer'
    elif kind=='serviceaccount':row['automountServiceAccountToken']=not good
    elif kind=='secret_metadata':
        row['type']='kubernetes.io/tls' if good else 'kubernetes.io/service-account-token'
        if 'no_deletion_timestamp' in cid:
            if not good:row['metadata']['deletionTimestamp']='2026-10-19T12:00:00Z'
    elif kind=='podsecuritypolicy':
        row['spec']={'privileged':not good,'hostPID':not good,'hostIPC':not good,'hostNetwork':not good,'allowPrivilegeEscalation':not good,'readOnlyRootFilesystem':good,'runAsUser':{'rule':'MustRunAsNonRoot' if good else 'RunAsAny'},'seLinux':{'rule':'MustRunAs' if good else 'RunAsAny'},'supplementalGroups':{'rule':'RunAsAny'},'fsGroup':{'rule':'RunAsAny'},'volumes':['hostPath' if good else '*']}
        if good:row['spec']['allowedHostPaths']=[{'pathPrefix':'/var/log','readOnly':True}]
        if 'default_seccomp' in cid or 'security_services' in cid:wanted='UNKNOWN' if 'default_seccomp' in cid or not good else 'PASS'
        # default seccomp annotation is filtered; SELinux native MustRunAs is independent.
        row['metadata']['annotations']={'seccomp.security.alpha.kubernetes.io/defaultProfileName':'runtime/default'} if good else {}
    if 'default_namespace_used' in cid and not good:row['metadata']['namespace']='default'
    return rows,wanted


class Wire:
    def __init__(self,rows,primary,mode,scope,legacy=False,fault_kind=None):
        self.rows,self.primary,self.mode,self.scope,self.legacy=rows,primary,mode,scope,legacy
        self.calls=[];self.documents=[];self.routes={}
        self.fault_kind=fault_kind
        for kind in rows:
            if kind in ('api_discovery','admission_policy'):continue
            if kind in ('secret_metadata','configmap_metadata'):
                path='/api/v1/namespaces/'+scope+('/secrets' if kind=='secret_metadata' else '/configmaps')
            else:
                path,namespaced=k8s.ENDPOINTS.get(kind,('/apis/policy/v1beta1/podsecuritypolicies',False))
                if namespaced and scope!='*':a,b=path.rsplit('/',1);path=a+'/namespaces/'+scope+'/'+b
                if kind=='namespace' and scope!='*':path+='/'+scope
            self.routes[path]=kind
    def request(self,method,url,**kwargs):
        u=urlsplit(url);fields=dict(kwargs.get('fields')or{})
        assert method=='GET' and u.scheme=='https' and u.netloc=='native-cluster.invalid' and not u.query
        assert kwargs.get('body') is None and kwargs.get('redirect') is False and kwargs.get('retries') is False
        self.calls.append({'method':method,'host':u.netloc,'path':u.path,'query':fields,'accept':kwargs.get('headers',{}).get('Accept')})
        path=u.path;code=200
        request_kind=self.routes.get(path)
        if path.startswith('/apis/admissionregistration.k8s.io/v1/validatingadmission'):request_kind='admission_policy'
        if self.mode=='denied' or fields.get('continue')=='next' or (self.mode=='dependency_denied' and request_kind==self.fault_kind):
            doc={'apiVersion':'v1','kind':'Status','status':'Failure','reason':'Forbidden','code':403};code=403
        elif path=='/version':doc={'gitVersion':'v1.24.17' if self.legacy else 'v1.32.0'}
        elif path=='/apis':
            groups=[]
            if 'admission_policy' in self.rows:groups.append({'name':'admissionregistration.k8s.io','versions':[{'groupVersion':'admissionregistration.k8s.io/v1','version':'v1'}],'preferredVersion':{'groupVersion':'admissionregistration.k8s.io/v1','version':'v1'}})
            if self.legacy:groups.append({'name':'policy','versions':[{'groupVersion':'policy/v1beta1','version':'v1beta1'}]})
            doc={'apiVersion':'v1','kind':'APIGroupList','groups':groups}
        elif path=='/apis/admissionregistration.k8s.io/v1':doc={'apiVersion':'v1','kind':'APIResourceList','groupVersion':'admissionregistration.k8s.io/v1','resources':[{'name':x,'kind':y,'namespaced':False,'verbs':['get','list']} for x,y in [('validatingadmissionpolicies','ValidatingAdmissionPolicy'),('validatingadmissionpolicybindings','ValidatingAdmissionPolicyBinding')]]}
        elif path=='/apis/policy/v1beta1':doc={'apiVersion':'v1','kind':'APIResourceList','groupVersion':'policy/v1beta1','resources':[{'name':'podsecuritypolicies','kind':'PodSecurityPolicy','namespaced':False,'verbs':['get','list']}]}
        elif path.startswith('/apis/admissionregistration.k8s.io/v1/validatingadmission'):
            typ='ValidatingAdmissionPolicyBinding' if path.endswith('bindings') else 'ValidatingAdmissionPolicy'
            doc={'apiVersion':'admissionregistration.k8s.io/v1','kind':typ+'List','metadata':{'resourceVersion':'71'},'items':[r for r in self.rows['admission_policy'] if r['kind']==typ]}
            if self.mode=='empty':doc['items']=[]
            if self.mode=='partial':doc['metadata']['continue']='next'
        else:
            assert path in self.routes,(path,self.routes)
            kind=self.routes[path];items=deepcopy(self.rows[kind]);version,typ=GVK[kind]
            if self.mode=='empty' and kind==self.primary:items=[]
            if kind=='namespace' and self.scope!='*':
                assert len(items)==1
                doc=items[0]
            elif kind in ('secret_metadata','configmap_metadata'):
                accept=kwargs.get('headers',{}).get('Accept','')
                if 'as=Table;' in accept:
                    assert kind=='secret_metadata' and fields['includeObject']=='None' and fields['resourceVersion']=='71'
                    doc={'apiVersion':'meta.k8s.io/v1','kind':'Table','metadata':{'resourceVersion':'71'},'columnDefinitions':[{'name':'Name','type':'string'},{'name':'Type','type':'string'}], 'rows':[{'cells':[r['metadata']['name'],r.get('type')]} for r in items]}
                else:
                    assert 'as=PartialObjectMetadataList;' in accept
                    doc={'apiVersion':'meta.k8s.io/v1','kind':'PartialObjectMetadataList','metadata':{'resourceVersion':'71'},'items':[{k:v for k,v in r.items() if k in ('apiVersion','kind','metadata')} for r in items]}
            else:doc={'apiVersion':version,'kind':typ+'List','metadata':{'resourceVersion':'71'},'items':items}
            if self.mode=='partial' and kind==self.primary and 'items' in doc:doc['metadata']['continue']='next'
            if self.mode=='wrong_list_type' and 'items' in doc:doc.update(kind='SecretList',apiVersion='v9')
        if self.mode=='dependency_partial' and request_kind==self.fault_kind and 'items' in doc:
            doc['metadata']['continue']='next'
        self.documents.append({'path':path,'status':code,'body':deepcopy(doc)})
        return urllib3.response.HTTPResponse(body=io.BytesIO(json.dumps(doc).encode()),status=code,headers={'Content-Type':'application/json'},preload_content=False)


def run(cid,branch='positive', *, mutate=None, legacy=None, explicit_inventories=None,fault_kind=None):
    check=REGISTRY[cid];kind=check.kind;rows,expected=recipe(cid,branch!='negative')
    legacy=kind=='podsecuritypolicy' if legacy is None else legacy
    scope='default' if kind=='endpointslice' or ('default_namespace_used' in cid and branch=='negative') else 'apps'
    if kind in ('rolebinding','clusterrolebinding') and 'system_masters' in cid:scope='*'
    if cid=='k8s.cis.psp_binding_enforced':kind='api_discovery'
    if mutate:mutate(rows)
    if branch=='wrong_type' and kind in rows and rows[kind]:
        rows[kind][0].update(kind='ForeignObject',apiVersion='foreign.example.test/v1')
    if branch in ('missing','malformed','foreign') and kind in rows and rows[kind]:
        row=rows[kind][0]
        if branch=='foreign':row['metadata']['namespace']='foreign'  # invalid for cluster scoped types too
        elif 'default_namespace_used' in cid:
            if branch=='missing':row['metadata'].pop('namespace',None)
            else:row['metadata']['namespace']=123
        elif branch=='missing':
            field='rules' if kind in ('role','clusterrole') else 'subjects' if kind in ('rolebinding','clusterrolebinding') else 'spec'
            if kind in ('secret_metadata','configmap_metadata','namespace'):row['metadata'].pop('name',None)
            elif kind=='endpointslice':row.pop('ports',None)
            elif kind=='node':row.pop('status',None)
            elif kind=='serviceaccount':row['automountServiceAccountToken']=None
            elif kind=='podtemplate':row['template'].pop('spec',None)
            elif 'direct_internet_access' in cid:row.pop('status',None)
            elif 'no_tiller' in cid:row['metadata'].pop('name',None)
            else:row.pop(field,None)
        else:
            field='rules' if kind in ('role','clusterrole') else 'subjects' if kind in ('rolebinding','clusterrolebinding') else 'spec'
            if kind in ('secret_metadata','configmap_metadata','namespace'):row['metadata']['name']=123
            elif kind=='endpointslice':row['ports']='malformed'
            elif kind=='node':row['status']={'addresses':'malformed'}
            elif kind=='serviceaccount':row['automountServiceAccountToken']='false'
            elif kind=='podtemplate':row['template']['spec']='malformed'
            elif 'direct_internet_access' in cid:row['status']={'podIPs':'malformed'}
            elif 'no_tiller' in cid:row['metadata']['labels']='malformed'
            else:row[field]='malformed'
    wire=Wire(rows,kind,branch,scope,legacy)
    configuration=client.Configuration();configuration.host='https://native-cluster.invalid';configuration.api_key={}
    sdk=client.ApiClient(configuration);sdk.rest_client.pool_manager=wire
    connector={'provider':'k8s','auth':{'cluster_id':'native-reviewed-cluster'},'scopes':[scope], 'options':{'workers':1,'page_size':500,'max_retries':0}}
    if cid=='k8s.claude.podsecuritypolicy.security_services_hardening' and branch=='positive':
        # The admitted native annotation successor requires a configured read
        # session even when SELinux MustRunAs supplies the positive criterion.
        # Preserve historical unavailable branches; the dedicated annotation
        # admission tests cover authenticated negatives and context tampering.
        configuration.api_key['authorization']='Bearer synthetic-offline-native-review'
        connector['auth']['token']='synthetic-offline-native-review'
    if explicit_inventories is not None:connector['options']['inventories']=explicit_inventories
    requirements=plan_collection({'connector':connector,'checks':[cid]})
    # No fabricated supporting inventory: public planner decides the reads.
    for dep in requirements:
        if dep in GVK and dep not in rows:rows[dep]=[obj('namespace')] if dep=='namespace' else []
    wire=Wire(rows,kind,branch,scope,legacy,fault_kind);sdk.rest_client.pool_manager=wire
    snapshot=k8s.collect(connector,requirements,api=k8s._wrap_client(sdk))
    captures=[];code=inspect.unwrap(check.evaluate).__code__
    def capture(frame,event,arg):
        if event=='call' and frame.f_code is code and 'item' in frame.f_locals and 'index' in frame.f_locals:
            captures.append({'item':deepcopy(frame.f_locals['item']),'index':deepcopy(dict(frame.f_locals['index']))})
    previous=sys.getprofile();sys.setprofile(capture)
    try:out=evaluate_snapshot(snapshot,checks=[cid])
    finally:sys.setprofile(previous)
    statuses=sorted({r['status'] for r in out['findings']})
    receipt={'id':cid,'branch':branch,'statuses':statuses,'expected_semantic':expected,'requirements':requirements,
        'requests':wire.calls,'native_http':wire.documents,'collections':[{'type':r['type'],'scope':r['scope'],'status':r['status'],'error':r.get('error')} for r in snapshot['collections']],
        'findings':[{'status':r['status'],'evidence':r['evidence']} for r in out['findings']]}
    destination=os.environ.get('K8S_CLUSTER_REVIEW_RECEIPTS')
    if destination and branch in ('positive','negative'):
        path=Path(destination)/(sha256((cid+branch).encode()).hexdigest()[:20]+'.json.gz');path.parent.mkdir(parents=True,exist_ok=True)
        payload=json.dumps({'snapshot':snapshot,'evaluator_arguments':captures},separators=(',',':')).encode()
        with gzip.GzipFile(filename=str(path),mode='wb',mtime=0) as f:f.write(payload)
        receipt['capture']=str(path);receipt['capture_sha256']=sha256(path.read_bytes()).hexdigest()
    RECEIPTS.append(receipt)
    return statuses,expected,snapshot


@pytest.mark.parametrize('cid',TEST_IDS)
@pytest.mark.parametrize('branch',['positive','negative','missing','malformed','denied','partial','foreign','wrong_type'])
def test_each_native_control(cid,branch,request):
    statuses,expected,snapshot=run(cid,branch)
    RECEIPTS[-1]['testnode']=request.node.nodeid
    kind=REGISTRY[cid].kind
    if branch in ('positive','negative'):
        assert statuses==[expected],RECEIPTS[-1]
    elif kind=='k8s_selected_literals':assert statuses==['UNKNOWN']
    elif branch=='denied':assert not set(statuses)&{'PASS','FAIL'},RECEIPTS[-1]
    elif branch=='partial':
        # A selected Namespace is GET, not paginated. A known row can retain a
        # verdict beside explicit UNKNOWN coverage; absence cannot turn clean.
        if any(r['status']=='partial' for r in snapshot['collections']):assert 'UNKNOWN' in statuses,RECEIPTS[-1]
        else:assert statuses==[expected],RECEIPTS[-1]
    elif cid=='k8s.cis.psp_binding_enforced':
        assert statuses==[expected],RECEIPTS[-1]
    elif branch=='missing' and ('no_human_' in cid or 'no_anonymous_user' in cid):
        # Binding.subjects is optional; omission is an empty grant, not lost
        # evidence. Human-specific controls then have no applicable subject.
        assert statuses==['NOT_APPLICABLE' if 'no_human_' in cid else 'PASS'],RECEIPTS[-1]
    else:assert statuses==['UNKNOWN'],RECEIPTS[-1]


@pytest.mark.parametrize('branch',['regular','init','ephemeral'])
def test_runtime_default_container_override(branch,request):
    cid='k8s.claude.pod.runtime_default_seccomp'
    def mutate(rows):
        s=rows['pod'][0]['spec'];bad={'name':'override','image':'registry.example.test/team/web:v2','securityContext':{'seccompProfile':{'type':'Unconfined'}}}
        if branch=='regular':s['containers']=[bad]
        else:s['initContainers' if branch=='init' else 'ephemeralContainers']=[bad]
    statuses,_,_=run(cid,'override_'+branch,mutate=mutate)
    RECEIPTS[-1]['testnode']=request.node.nodeid
    assert statuses==['FAIL'],RECEIPTS[-1]


def test_hostport_zero_has_no_publication(request):
    cid='k8s.claude.pod.no_host_ports'
    statuses,_,_=run(cid,'hostport_zero')
    RECEIPTS[-1]['testnode']=request.node.nodeid
    assert statuses==['PASS'],RECEIPTS[-1]


@pytest.mark.parametrize('direction',['ingress','egress'])
def test_empty_selector_equivalence(direction,request):
    cid='k8s.ports.namespace.network_policy_default_deny_'+direction
    def mutate(rows):rows['networkpolicy'][0]['spec']['podSelector']={'matchLabels':{},'matchExpressions':[]}
    statuses,_,_=run(cid,'empty_selector_equivalence',mutate=mutate)
    RECEIPTS[-1]['testnode']=request.node.nodeid
    assert statuses==['PASS'],RECEIPTS[-1]


def test_ingress_unresolved_default_backend(request):
    cid='k8s_ingress_backend_https'
    def mutate(rows):rows['ingress'][0]['spec']['defaultBackend']={'service':{'name':'unresolved','port':{'number':443}}}
    statuses,_,_=run(cid,'unresolved_default_backend',mutate=mutate)
    RECEIPTS[-1]['testnode']=request.node.nodeid
    assert statuses==['UNKNOWN'],RECEIPTS[-1]


@pytest.mark.parametrize('cid',[cid for cid in IDS if REGISTRY[cid].kind in WORKLOADS and 'effective_runtime_default_seccomp' in cid])
@pytest.mark.parametrize('branch',['windows','unresolved_os','container_override','init_override','unresolved_profile'])
def test_cis_seccomp_applicability_inheritance(cid,branch,request):
    def mutate(rows):
        kind=REGISTRY[cid].kind;s=spec_of(rows[kind][0],kind)
        if branch=='windows':s['os']={'name':'windows'}
        elif branch=='unresolved_os':s.pop('os')
        elif branch=='unresolved_profile':s.pop('securityContext')
        elif branch=='container_override':s['containers'][0]['securityContext']={'seccompProfile':{'type':'Unconfined'}}
        else:s['initContainers']=[{'name':'setup','image':'registry.example.test/team/setup:v2','securityContext':{'seccompProfile':{'type':'Unconfined'}}}]
    statuses,_,_=run(cid,branch,mutate=mutate)
    RECEIPTS[-1]['testnode']=request.node.nodeid
    assert statuses==[{'windows':'NOT_APPLICABLE','unresolved_os':'UNKNOWN','container_override':'FAIL','init_override':'FAIL','unresolved_profile':'UNKNOWN'}[branch]],RECEIPTS[-1]


@pytest.mark.parametrize('cid',[cid for cid in IDS if REGISTRY[cid].kind=='admission_policy'])
@pytest.mark.parametrize('case',['parameterized','conditional','only_create','warn','invalid_namespace_selector','foreign_policy_type'])
def test_admission_declared_subset_boundaries(cid,case,request):
    def mutate(rows):
        p,b=rows['admission_policy']
        if case=='parameterized':p['spec']['paramKind']={'apiVersion':'v1','kind':'ConfigMap'}
        elif case=='conditional':p['spec']['matchConditions']=[{'name':'skip-system','expression':'request.userInfo.username != "system:serviceaccount:apps:deployer"'}]
        elif case=='only_create':p['spec']['matchConstraints']['resourceRules'][0]['operations']=['CREATE']
        elif case=='warn':b['spec']['validationActions']=['Warn']
        elif case=='invalid_namespace_selector':b['spec']['matchResources']={'namespaceSelector':{'matchLabels':{'environment':123}}}
        else:p['apiVersion']='other.example.test/v1'
    statuses,_,_=run(cid,case,mutate=mutate)
    RECEIPTS[-1]['testnode']=request.node.nodeid
    assert statuses==['FAIL' if case in ('only_create','warn') else 'UNKNOWN'],RECEIPTS[-1]


@pytest.mark.parametrize('cid',[cid for cid in IDS if REGISTRY[cid].kind=='podsecuritypolicy'])
def test_removed_psp_api_not_applicable(cid,request):
    statuses,_,_=run(cid,'removed_api',legacy=False)
    RECEIPTS[-1]['testnode']=request.node.nodeid
    assert statuses==['NOT_APPLICABLE'],RECEIPTS[-1]


@pytest.mark.parametrize('good',[True,False])
def test_legacy_psp_binding_explicit_native_support(good,request):
    cid='k8s.cis.psp_binding_enforced'
    def mutate(rows):
        policy=obj('podsecuritypolicy',spec={'privileged':False,'runAsUser':{'rule':'MustRunAsNonRoot'},'seLinux':{'rule':'RunAsAny'},'supplementalGroups':{'rule':'RunAsAny'},'fsGroup':{'rule':'RunAsAny'}})
        policy['metadata']['name']='locked'
        role=obj('role',rules=[rule('','pods','create')]+([{'apiGroups':['policy'],'resources':['podsecuritypolicies'],'verbs':['use'],'resourceNames':['locked']}] if good else []));role['metadata']['name']='deployer'
        binding=obj('rolebinding',roleRef={'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':'deployer'},subjects=[{'kind':'ServiceAccount','name':'deployer','namespace':'apps'}])
        rows.update(podsecuritypolicy=[policy],namespace=[obj('namespace')],role=[role],clusterrole=[],rolebinding=[binding],clusterrolebinding=[])
    inventories=['api_discovery','podsecuritypolicy','namespace','role','clusterrole','rolebinding','clusterrolebinding']
    statuses,_,_=run(cid,'legacy_grant' if good else 'legacy_missing_grant',mutate=mutate,legacy=True,explicit_inventories=inventories)
    RECEIPTS[-1]['testnode']=request.node.nodeid
    assert statuses==['PASS' if good else 'FAIL'],RECEIPTS[-1]


def test_legacy_psp_default_planner_missing_support_is_unknown(request):
    statuses,_,_=run('k8s.cis.psp_binding_enforced','legacy_default_plan',legacy=True)
    RECEIPTS[-1]['testnode']=request.node.nodeid
    assert statuses==['UNKNOWN'],RECEIPTS[-1]


@pytest.mark.parametrize('cid',[cid for cid in IDS if REGISTRY[cid].kind not in ('namespace','k8s_selected_literals') and cid!='k8s.cis.psp_binding_enforced'])
def test_complete_empty_primary_inventory(cid,request):
    statuses,_,_=run(cid,'empty')
    RECEIPTS[-1]['testnode']=request.node.nodeid
    wanted='UNKNOWN' if 'system_masters' in cid else 'FAIL' if REGISTRY[cid].kind=='admission_policy' else 'EMPTY'
    assert statuses==[wanted],RECEIPTS[-1]


JOIN_CASES=[(cid,dep) for cid in IDS for dep in REGISTRY[cid].dependencies if dep!=REGISTRY[cid].kind and dep!='api_discovery']


@pytest.mark.parametrize('cid,dependency,mode',[(cid,dep,mode) for cid,dep in JOIN_CASES
    for mode in ('dependency_denied','dependency_partial','dependency_foreign')
    if not (dep=='namespace' and mode=='dependency_partial')])
def test_supporting_native_inventory_guards(cid,dependency,mode,request):
    def mutate(rows):
        if mode=='dependency_foreign':
            if not rows.get(dependency):rows[dependency]=[obj(dependency)]
            for row in rows[dependency]:row['metadata']['namespace']='foreign'
    statuses,_,_=run(cid,mode,mutate=mutate,fault_kind=dependency)
    RECEIPTS[-1]['testnode']=request.node.nodeid
    assert 'PASS' not in statuses and 'FAIL' not in statuses,RECEIPTS[-1]


@pytest.mark.parametrize('cid',['k8s.cis.networkpolicy_no_default_allow_ingress','k8s.cis.networkpolicy_no_default_allow_egress',
    'k8s_networkpolicy_no_world_ingress','k8s_networkpolicy_no_world_ssh_rdp'])
def test_native_omitted_networkpolicy_rules_mean_no_allow_rules(cid,request):
    def mutate(rows):
        spec=rows['networkpolicy'][0]['spec'];spec.pop('egress' if 'egress' in cid else 'ingress')
    statuses,_,_=run(cid,'native_omitted_rule_list',mutate=mutate)
    RECEIPTS[-1]['testnode']=request.node.nodeid
    assert statuses==['PASS'],RECEIPTS[-1]


def test_native_tls_ingress_default_backend_only(request):
    cid='k8s_ingress_backend_https'
    def mutate(rows):
        spec=rows['ingress'][0]['spec'];spec['defaultBackend']=spec.pop('rules')[0]['http']['paths'][0]['backend']
    statuses,_,_=run(cid,'default_backend_only',mutate=mutate)
    RECEIPTS[-1]['testnode']=request.node.nodeid
    assert statuses==['PASS'],RECEIPTS[-1]
