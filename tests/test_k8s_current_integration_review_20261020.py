"""Current K8s presentation/fixture integration; native inputs retain real lineage."""
from copy import deepcopy
import json
from pathlib import Path
import socket
import pytest
from peaso.checks import CHECKS
from peaso.checks import k8s_literal_secret_review_20261020 as literal
from peaso.checks.k8s_workload_finding_summary import workload_evidence_summary
from peaso.checks.selected_content_observed import observation
from tests import test_k8s_cluster_native_review_20261020 as cluster
from tests import test_k8s_controller_literal_secret_review_20261020 as controllers

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = {c.id:c for c in CHECKS}
LITERALS = json.loads((ROOT/'tests/fixtures/k8s_controller_literal_secret_review_20261020.json').read_text())['cases']


@pytest.fixture(autouse=True)
def hard_guard(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('actual socket/DNS/credential discovery forbidden')
    for key in ('connect','connect_ex'):monkeypatch.setattr(socket.socket,key,blocked)
    for key in ('create_connection','getaddrinfo','gethostbyname','gethostbyname_ex'):monkeypatch.setattr(socket,key,blocked)
    from kubernetes import config
    for key in ('load_kube_config','load_incluster_config','new_client_from_config'):monkeypatch.setattr(config,key,blocked)
    monkeypatch.setattr(cluster.k8s,'_new_api',blocked)
    from peaso import secret_scanning
    secret_scanning._RESULTS.clear()
    yield
    secret_scanning._RESULTS.clear()


@pytest.mark.parametrize('kind',sorted(controllers.NATIVE))
@pytest.mark.parametrize('hit',[False,True])
def test_exact_targets_inside_all_namespace_scan_native(monkeypatch,kind,hit,request):
    selected=controllers.target(kind)
    snapshot, result, trace=controllers.capture(monkeypatch,[selected],
        documents={controllers.route(selected):controllers.native(selected,hit)},
        req_change=lambda req:req['connector'].update(scopes=['*']),testnode=request.node.nodeid)
    assert {r['status']for r in result['findings']}==({'FAIL'}if hit else{'PASS'})
    assert len(trace.calls)==2 and all(r['path_binding']==controllers.source._fingerprint(controllers.route(selected)) for r in trace.calls)
    assert all(c['scope']=='*'for c in snapshot['collections'])


@pytest.mark.parametrize('row',LITERALS,ids=lambda row:row['kind']+'-'+row['case'])
def test_prior_actual_controller_input_replays_and_brief_subject_is_current(row):
    before=deepcopy(row)
    status,evidence=literal.evaluate(row['input']['item'],row['input']['index'])
    assert status==row['status']
    finding={'provider':'k8s','check_id':literal.CHECK,'status':status,'evidence':evidence}
    text=observation(finding)
    if status in ('PASS','FAIL') and evidence.get('complete') is True:
        assert 'selected workload and ConfigMap literals' in text
        assert len(text.split())<30
    else:assert text is None
    assert row==before


@pytest.mark.parametrize('container_class',['containers','initContainers','ephemeralContainers'])
@pytest.mark.parametrize('profile',['RuntimeDefault','Localhost','Unconfined'])
def test_override_observation_uses_actual_native_seccomp_evidence(container_class,profile,request):
    cid='k8s.claude.pod.runtime_default_seccomp'
    def mutate(rows):
        spec=rows['pod'][0]['spec'];spec['securityContext']={'seccompProfile':{'type':'RuntimeDefault'}}
        row={'name':'override','image':'registry.example.test/review:v1','securityContext':{'seccompProfile':{'type':profile}}}
        if container_class=='containers':spec['containers']=[row]
        else:spec[container_class]=[row]
    statuses,_,_=cluster.run(cid,'current-copy-'+container_class+'-'+profile,mutate=mutate)
    finding=cluster.RECEIPTS[-1]['findings'][0]
    text=workload_evidence_summary({'provider':'k8s','check_id':cid,**finding})
    if profile=='RuntimeDefault':assert statuses==['PASS'] and text is None
    else:
        assert statuses==['FAIL'] and profile in text
        assert 'regular, init or ephemeral' in text
        assert 'Neither the Pod' not in text and 'enforced' not in text


@pytest.mark.parametrize('kind',('pod','deployment','daemonset','statefulset','replicaset','replicationcontroller','job','cronjob'))
def test_cis_linux_seccomp_observation_names_actual_override(kind):
    # Only assigned CIS kinds exist; PodTemplate is not a CIS seccomp target.
    cid='k8s.cis.'+kind+'_effective_runtime_default_seccomp'
    if cid not in REGISTRY:
        pytest.fail('Unexpected unassigned CIS kind: '+kind)
    def mutate(rows):
        spec=cluster.spec_of(rows[kind][0],kind)
        spec['os']={'name':'linux'};spec['securityContext']={'seccompProfile':{'type':'RuntimeDefault'}}
        spec['initContainers']=[{'name':'setup','image':'registry.example.test/review:v1',
            'securityContext':{'seccompProfile':{'type':'Unconfined'}}}]
    statuses,_,_=cluster.run(cid,'current-copy-init-override',mutate=mutate)
    assert statuses==['FAIL']
    finding=cluster.RECEIPTS[-1]['findings'][0]
    text=workload_evidence_summary({'provider':'k8s','check_id':cid,**finding})
    assert '“setup”' in text and 'Unconfined' in text and 'declares or inherits' in text


@pytest.mark.parametrize('port',[0,443])
def test_regular_hostport_summary_uses_native_numeric_declaration(port):
    cid='k8s.claude.pod.no_host_ports'
    def mutate(rows):rows['pod'][0]['spec']['containers'][0]['ports']=[{'containerPort':443,'hostPort':port}]
    statuses,_,_=cluster.run(cid,'current-copy-hostport-'+str(port),mutate=mutate)
    finding=cluster.RECEIPTS[-1]['findings'][0]
    text=workload_evidence_summary({'provider':'k8s','check_id':cid,**finding})
    if port==0:assert statuses==['PASS'] and text is None
    else:assert statuses==['FAIL'] and 'declares hostPort 443' in text and 'reachable'not in text


@pytest.mark.parametrize('cid,evidence',[
    ('k8s.claude.pod.runtime_default_seccomp',{}),
    ('k8s.claude.pod.runtime_default_seccomp',{'pod_profile':'RuntimeDefault','container_profiles':[None]}),
    ('k8s.claude.pod.runtime_default_seccomp',{'pod_profile':'RuntimeDefault','container_profiles':['wrong']}),
    ('k8s.cis.pod_effective_runtime_default_seccomp',{'non_runtime_default':[{'container':'bad','effective_profile':'wrong'}]}),
    ('k8s.claude.pod.no_host_ports',{'violations':[{'container':'web','host_ports':[0]}]}),
    ('k8s.claude.pod.no_host_ports',{'violations':[{'container':'web','host_ports':[True]}]})])
def test_missing_or_inconsistent_summary_facts_do_not_invent_failure(cid,evidence):
    assert workload_evidence_summary({'provider':'k8s','check_id':cid,'status':'FAIL','evidence':evidence})is None


@pytest.mark.parametrize('status',['PASS','UNKNOWN','DENIED','NOT_APPLICABLE'])
def test_status_alone_never_invents_observed_failure(status):
    assert workload_evidence_summary({'provider':'k8s','check_id':'k8s.claude.pod.runtime_default_seccomp',
        'status':status,'evidence':{'pod_profile':'Unconfined','container_profiles':[None]}})is None


