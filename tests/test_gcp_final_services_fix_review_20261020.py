"""Directed native fix boundaries; transport remains offline and exact-route bound."""
from copy import deepcopy
import ast
import hashlib
import inspect
import json
import os
from pathlib import Path
import socket

import pytest
from peaso.checks import CHECKS
from peaso.checks.native_only import automated_checks, exclusions
from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot, get_catalog
from tests import test_gcp_final_services_review_20261020 as native

ROOT=Path(__file__).resolve().parents[1] / '.wave2-receipts/final-services-fixes'
HISTORY = Path(__file__).parent / 'fixtures/gcp-wave2-final-services-history-20261020'
RECEIPTS=[]
ARCHIVED=('gcp_certificate_renewal_30_days','gcp_certificate_rotation_180_days',
          'gcp_certificate_rotation_90_days','gcp_lb_server_header_rewrite')

@pytest.fixture(autouse=True)
def no_network_or_auth(monkeypatch):
    calls=[]
    def blocked(*args,**kwargs):
        calls.append('forbidden_network_or_credentials')
        raise AssertionError('Native fix review forbids network, DNS and auth')
    for target,attr in [(socket,'create_connection'),(socket,'getaddrinfo'),(socket,'gethostbyname'),
                        (socket.socket,'connect'),(socket.socket,'connect_ex'),(gcp,'Credentials')]:
        monkeypatch.setattr(target,attr,blocked)
    yield
    assert not calls,calls

@pytest.fixture(scope='session',autouse=True)
def receipts():
    ROOT.mkdir(parents=True,exist_ok=True)
    paths=[Path(__file__),Path(native.__file__),Path('peaso/checks/batch_remaining_gcp.py'),
           Path('peaso/checks/compliance_new_sw52.py'),Path('peaso/collectors/gcp_compliance_wave.py'),
           Path('peaso/checks/native_only.json'),Path('peaso/checks/bulk_pending.py')]
    (ROOT/'fix-tested-source-hashes.json').write_text(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},indent=2)+'\n')
    yield
    (ROOT/'fix-native-cases.json').write_text(json.dumps(RECEIPTS,indent=2)+'\n')

def check(case,scenario,expected,mutate=None,branch='good',deny=None):
    snap,tr=native.capture(case,branch,mutate=mutate,deny=deny)
    before=deepcopy(snap)
    findings=evaluate_snapshot(snap,checks=[case['id']])['findings']
    assert before==snap
    actual=[f['status'] for f in findings];want=expected if isinstance(expected,list) else [expected]
    RECEIPTS.append({'check_id':case['id'],'scenario':scenario,'test_nodeid':os.environ.get('PYTEST_CURRENT_TEST','').removesuffix(' (call)'),
        'expected':want,'statuses':actual,'findings':findings,'collections':snap['collections'],'native_responses':tr.native})
    assert sorted(actual)==sorted(want),findings
    return snap

@pytest.mark.parametrize('variant,expected',[
 ('plain','PASS'),('deny404','PASS'),('preview','FAIL'),('sensitivity0','FAIL'),('sensitivity1','PASS'),
 ('opt_out','UNKNOWN'),('substring','UNKNOWN'),('negation','UNKNOWN'),('or_true','UNKNOWN'),('and_path','UNKNOWN'),
 ('allow_action','FAIL'),('bare_deny','UNKNOWN'),('earlier_allow_all','FAIL'),('earlier_allow_cidr','UNKNOWN'),
 ('earlier_deny_cidr','UNKNOWN'),('earlier_preview_allow','PASS'),('earlier_custom_cel','UNKNOWN'),
 ('request_exclusions','UNKNOWN'),('internal_backend','NOT_APPLICABLE'),('no_attachment','NOT_APPLICABLE'),
 ('missing_scheme','UNKNOWN'),('foreign_attachment','UNKNOWN'),('foreign_authority','UNKNOWN'),
 ('duplicate_priority','UNKNOWN'),('missing_default','UNKNOWN'),('default_preview','UNKNOWN'),
 ('malformed_preview','UNKNOWN'),('duplicate_backend_alias','UNKNOWN'),('duplicate_policy_alias',['UNKNOWN','UNKNOWN']),
 ('unsupported_ruleset','UNKNOWN'),('backend_denied','UNKNOWN'),('backend_partial','UNKNOWN'),('policy_denied','DENIED')])
def test_waf_declared_configuration(variant,expected):
    case=native.find('gcp_cloud_armor_waf_enabled')
    def mutate(row,routes):
        rules=row['rules'];waf=rules[0]
        backend=routes[native.C+'/aggregated/backendServices']['data']['items']['global']['backendServices'][0]
        if variant=='deny404':waf['action']='deny(404)'
        if variant=='preview':waf['preview']=True
        if variant in ('sensitivity0','sensitivity1'):waf['match']['expr']['expression']="evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': "+variant[-1]+"})"
        if variant=='opt_out':waf['match']['expr']['expression']="evaluatePreconfiguredWaf('sqli-v33-stable', {'opt_out_rule_ids': ['owasp-crs-v030301-id942100-sqli']})"
        if variant=='substring':waf['match']['expr']['expression']='"evaluatePreconfiguredWaf" == "evaluatePreconfiguredWaf"'
        if variant=='negation':waf['match']['expr']['expression']='!'+waf['match']['expr']['expression']
        if variant=='or_true':waf['match']['expr']['expression']+=' || true'
        if variant=='and_path':waf['match']['expr']['expression']+=' && request.path == "/admin"'
        if variant=='allow_action':waf['action']='allow'
        if variant=='bare_deny':waf['action']='deny'
        if variant.startswith('earlier_'):
            prior={'priority':100,'action':'deny(403)' if variant=='earlier_deny_cidr' else 'allow',
                   'match':{'versionedExpr':'SRC_IPS_V1','config':{'srcIpRanges':['*'] if variant in ('earlier_allow_all','earlier_preview_allow') else ['10.0.0.0/8']}}}
            if variant=='earlier_preview_allow':prior['preview']=True
            if variant=='earlier_custom_cel':prior['match']={'expr':{'expression':'request.path.startsWith("/admin")'}}
            rules.append(prior)
        if variant=='request_exclusions':waf['preconfiguredWafConfig']={'exclusions':[{'targetRuleSet':'sqli-v33-stable','requestHeadersToExclude':[{'op':'EQUALS_ANY'}]}]}
        if variant=='internal_backend':backend['loadBalancingScheme']='INTERNAL_MANAGED'
        if variant=='no_attachment':backend.pop('securityPolicy')
        if variant=='missing_scheme':backend.pop('loadBalancingScheme')
        if variant=='foreign_attachment':backend['securityPolicy']=native.ARMOR.replace(native.P, 'projects/p-other')
        if variant=='foreign_authority':backend['securityPolicy']=native.ARMOR.replace('compute.googleapis.com','attacker.example')
        if variant=='duplicate_priority':rules.append(deepcopy(waf))
        if variant=='missing_default':rules.pop()
        if variant=='default_preview':rules[-1]['preview']=True
        if variant=='malformed_preview':waf['preview']='false'
        if variant=='duplicate_backend_alias':
            other=deepcopy(backend);other['selfLink']=native.BACK.replace('compute.googleapis.com','www.googleapis.com');other['name']='review';routes[native.C+'/aggregated/backendServices']['data']['items']['global']['backendServices'].append(other)
        if variant=='duplicate_policy_alias':
            other=deepcopy(row);other['selfLink']=native.ARMOR.replace('compute.googleapis.com','www.googleapis.com');routes[native.C+'/global/securityPolicies']['data']['items'].append(other)
        if variant=='unsupported_ruleset':waf['match']['expr']['expression']="evaluatePreconfiguredWaf('future-rule-v999-stable')"
        if variant=='backend_partial':
            next(r for r in routes.values() if r['primary'])['primary']=False
            routes[native.C+'/aggregated/backendServices']['primary']=True
    deny=native.C+'/aggregated/backendServices' if variant=='backend_denied' else None
    snap=check(case,'waf:'+variant,expected,mutate,branch='denied' if variant=='policy_denied' else 'partial' if variant=='backend_partial' else 'good',deny=deny)
    assert all('internetFacing' not in r for c in snap['collections'] for r in c['items'])

@pytest.mark.parametrize('variant,expected',[
 ('legacy_zones_link','PASS'),('foreign_project','UNKNOWN'),('foreign_host','UNKNOWN'),('name_conflict','UNKNOWN'),
 ('location_conflict','UNKNOWN'),('group_www_alias','PASS'),('group_partial','PASS'),('group_foreign_host','UNKNOWN'),
 ('group_foreign_project','UNKNOWN'),('group_other_region','UNKNOWN'),('duplicate_group','UNKNOWN'),
 ('duplicate_manager_alias','UNKNOWN'),('three_nodes_disabled','PASS'),('manager_denied','UNKNOWN'),('negative_target','UNKNOWN')])
def test_gke_independent_native_identity_and_groups(variant,expected):
    case=native.find('gcp_gke_small_cluster_auto_upgrade')
    def mutate(row,routes):
        pool=row['nodePools'][0]
        managers=next(iter(routes[native.C+'/aggregated/instanceGroupManagers']['data']['items'].values()))['instanceGroupManagers']
        if variant=='legacy_zones_link':row['selfLink']=row['selfLink'].replace('/locations/','/zones/')
        if variant=='foreign_project':row['selfLink']=row['selfLink'].replace(native.P, 'projects/p-other')
        if variant=='foreign_host':row['selfLink']=row['selfLink'].replace('container.googleapis.com','attacker.example')
        if variant=='name_conflict':row['name']='other'
        if variant=='location_conflict':row['location']='us-east1-a'
        if variant=='group_www_alias':pool['instanceGroupUrls'][0]=native.GROUP.replace('compute.googleapis.com','www.googleapis.com')
        if variant=='group_partial':pool['instanceGroupUrls'][0]=native.GROUP.split('/compute/v1/')[1]
        if variant=='group_foreign_host':pool['instanceGroupUrls'][0]=native.GROUP.replace('compute.googleapis.com','attacker.example')
        if variant=='group_foreign_project':pool['instanceGroupUrls'][0]=native.GROUP.replace(native.P, 'projects/p-other')
        if variant=='group_other_region':pool['instanceGroupUrls'][0]=native.GROUP.replace('us-central1-a','us-east1-a')
        if variant=='duplicate_group':row['nodePools'].append({**deepcopy(pool),'name':'other-pool'})
        if variant=='duplicate_manager_alias':
            other=deepcopy(managers[0]);other.update(name='other',selfLink=native.MIG+'-other',instanceGroup=native.GROUP.replace('compute.googleapis.com','www.googleapis.com'));managers.append(other)
        if variant=='three_nodes_disabled':pool['management']['autoUpgrade']=False;managers[0]['targetSize']=3
        if variant=='negative_target':managers[0]['targetSize']=-1
    check(case,'gke_binding:'+variant,expected,mutate,deny=native.C+'/aggregated/instanceGroupManagers' if variant=='manager_denied' else None)

@pytest.mark.parametrize('variant,expected',[
 ('partial_refs','PASS'),('www_refs','PASS'),('foreign_backend_ref','UNKNOWN'),('foreign_map_host','UNKNOWN'),
 ('duplicate_map_alias','UNKNOWN'),('duplicate_policy_alias','UNKNOWN'),('weak_tls','FAIL'),('tls13','PASS'),
 ('unknown_tls','UNKNOWN'),('missing_policy','UNKNOWN')])
def test_cdn_full_native_provenance_and_exact_joins(variant,expected):
    case=native.find('gcp_pci_backend_service_2ce96d36d0bf')
    def mutate(row,routes):
        mapping=routes[native.C+'/aggregated/urlMaps']['data']['items']['global']['urlMaps'][0]
        proxy=routes[native.C+'/aggregated/targetHttpsProxies']['data']['items']['global']['targetHttpsProxies'][0]
        policies=routes[native.C+'/aggregated/sslPolicies']['data']['items']['global']['sslPolicies']
        policy=policies[0]
        if variant=='partial_refs':
            mapping['defaultService']='global/backendServices/review';proxy['urlMap']=native.P+'/global/urlMaps/review';proxy['sslPolicy']='global/sslPolicies/review'
        if variant=='www_refs':
            mapping['defaultService']=native.BACK.replace('compute.googleapis.com','www.googleapis.com');proxy['urlMap']=native.MAP.replace('compute.googleapis.com','www.googleapis.com');proxy['sslPolicy']=native.SSL.replace('compute.googleapis.com','www.googleapis.com')
        if variant=='foreign_backend_ref':mapping['defaultService']=native.BACK.replace(native.P, 'projects/p-other')
        if variant=='foreign_map_host':proxy['urlMap']=native.MAP.replace('compute.googleapis.com','attacker.example')
        if variant=='duplicate_map_alias':
            other=deepcopy(mapping);other['selfLink']=native.MAP.replace('compute.googleapis.com','www.googleapis.com');routes[native.C+'/aggregated/urlMaps']['data']['items']['global']['urlMaps'].append(other)
        if variant=='duplicate_policy_alias':
            other=deepcopy(policy);other['selfLink']=native.SSL.replace('compute.googleapis.com','www.googleapis.com');policies.append(other)
        if variant=='weak_tls':policy['minTlsVersion']='TLS_1_1'
        if variant=='tls13':policy['minTlsVersion']='TLS_1_3'
        if variant=='unknown_tls':policy['minTlsVersion']='FUTURE_TLS'
        if variant=='missing_policy':proxy.pop('sslPolicy')
    check(case,'cdn_join:'+variant,expected,mutate)

@pytest.mark.parametrize('variant,expected',[
 ('native_kind','PASS'),('partial_refs','PASS'),('false_redirect','FAIL'),('omitted_https','FAIL'),
 ('empty_redirect','UNKNOWN'),('conflicting_destination','UNKNOWN'),('missing_default','UNKNOWN'),
 ('path_redirects','PASS'),('path_backend','FAIL'),('unbound_matcher','UNKNOWN'),('route_redirects','PASS'),
 ('route_backend','FAIL'),('missing_route_match','UNKNOWN'),('duplicate_priority','UNKNOWN'),
 ('foreign_proxy','UNKNOWN'),('kind_conflict','UNKNOWN'),('unresolved_frontend','UNKNOWN'),('no_frontend','NOT_APPLICABLE'),
 ('frontends_denied','UNKNOWN')])
def test_http_redirect_complete_native_routes(variant,expected):
    case=native.find('gcp_pci_url_map_9ed56c323a05')
    def mutate(row,routes):
        proxy=routes[native.C+'/aggregated/targetHttpProxies']['data']['items']['global']['targetHttpProxies'][0]
        front=routes[native.C+'/aggregated/forwardingRules']['data']['items']['global']['forwardingRules']
        if variant=='native_kind':proxy['kind']='compute#targetHttpProxy'
        if variant=='partial_refs':proxy['urlMap']='global/urlMaps/review';front[0]['target']=native.P+'/global/targetHttpProxies/review'
        if variant=='false_redirect':row['defaultUrlRedirect']['httpsRedirect']=False
        if variant=='omitted_https':row['defaultUrlRedirect']={'stripQuery':False}
        if variant=='empty_redirect':row['defaultUrlRedirect']={}
        if variant=='conflicting_destination':row['defaultService']=native.BACK
        if variant=='missing_default':row.pop('defaultUrlRedirect')
        if variant in ('path_redirects','path_backend','unbound_matcher','route_redirects','route_backend','missing_route_match','duplicate_priority'):
            row['hostRules']=[{'hosts':['example.invalid'],'pathMatcher':'paths'}]
            matcher={'name':'paths','defaultUrlRedirect':{'httpsRedirect':True}}
            row['pathMatchers']=[matcher]
            if variant in ('path_redirects','path_backend','unbound_matcher'):
                matcher['pathRules']=[{'paths':['/review/*'],'urlRedirect':{'httpsRedirect':True}}]
                if variant=='path_backend':matcher['pathRules'][0]={'paths':['/review/*'],'service':native.BACK}
                if variant=='unbound_matcher':row['hostRules'][0]['pathMatcher']='missing'
            else:
                rule={'priority':1,'matchRules':[{'prefixMatch':'/review/'}],'urlRedirect':{'httpsRedirect':True}}
                matcher['routeRules']=[rule]
                if variant=='route_backend':rule.pop('urlRedirect');rule['service']=native.BACK
                if variant=='missing_route_match':rule['matchRules']=[{}]
                if variant=='duplicate_priority':matcher['routeRules'].append(deepcopy(rule))
        if variant=='foreign_proxy':proxy['urlMap']=native.MAP.replace(native.P, 'projects/p-other')
        if variant=='kind_conflict':proxy['kind']='compute#targetHttpsProxy'
        if variant=='unresolved_frontend':front[0]['target']=front[0]['target']+'-missing'
        if variant=='no_frontend':front.clear()
    check(case,'http_routes:'+variant,expected,mutate,deny=native.C+'/aggregated/forwardingRules' if variant=='frontends_denied' else None)

@pytest.mark.parametrize('variant,expected',[
 ('count_samples','FAIL'),('sum','PASS'),('gauge','UNKNOWN'),('missing_descriptor','UNKNOWN'),
 ('reducer_mean','UNKNOWN'),('missing_principal_group','FAIL'),('no_reducer','FAIL'),('chain','UNKNOWN'),
 ('retest_window','UNKNOWN'),('multi_series_trigger','UNKNOWN'),('and_extra_condition','UNKNOWN'),
 ('ratio','UNKNOWN'),('descriptor_identity','UNKNOWN'),('instance_grouping','FAIL'),('boolean_trigger','UNKNOWN'),('boolean_threshold','UNKNOWN')])
def test_enumeration_event_volume_semantics(variant,expected):
    case=native.find('gcp_logging_enumeration_alert')
    def mutate(row,routes):
        policy=routes['https://monitoring.googleapis.com/v3/'+native.P+'/alertPolicies']['data']['alertPolicies'][0]
        threshold=policy['conditions'][0]['conditionThreshold'];aggregation=threshold['aggregations'][0]
        aggregation['crossSeriesReducer']='REDUCE_SUM'
        if variant=='count_samples':aggregation['perSeriesAligner']='ALIGN_COUNT'
        if variant=='gauge':row['metricDescriptor']['metricKind']='GAUGE'
        if variant=='missing_descriptor':row.pop('metricDescriptor')
        if variant=='reducer_mean':aggregation['crossSeriesReducer']='REDUCE_MEAN'
        if variant=='missing_principal_group':aggregation['groupByFields']=['resource.type']
        if variant=='no_reducer':aggregation.pop('crossSeriesReducer');aggregation.pop('groupByFields')
        if variant=='chain':threshold['aggregations'].append(deepcopy(aggregation))
        if variant=='retest_window':threshold['duration']='300s'
        if variant=='multi_series_trigger':threshold['trigger']={'count':2}
        if variant=='and_extra_condition':policy['combiner']='AND';policy['conditions'].append(deepcopy(policy['conditions'][0]))
        if variant=='ratio':threshold['denominatorFilter']='metric.type="logging.googleapis.com/user/other"'
        if variant=='descriptor_identity':row['metricDescriptor']['type']='logging.googleapis.com/user/other'
        if variant=='instance_grouping':aggregation['groupByFields'].append('resource.label.instance_id')
        if variant=='boolean_trigger':threshold['trigger']={'count':True}
        if variant=='boolean_threshold':threshold['thresholdValue']=True
    check(case,'enumeration_volume:'+variant,expected,mutate)

@pytest.mark.parametrize('variant,expected',[('valid','PASS'),('missing','UNKNOWN'),('empty','UNKNOWN'),('wrong_type','UNKNOWN')])
def test_audit_resource_type_safe_projection(variant,expected):
    case=native.find('gcp_c5_log_event_fields')
    def mutate(row,routes):
        row['resource']['labels']['nonessential']='private-label-not-retained'
        row['protoPayload']['request']={'private':'request-not-retained'}
        if variant=='missing':row['resource'].pop('type')
        if variant=='empty':row['resource']['type']=''
        if variant=='wrong_type':row['resource']['type']=False
    snap=check(case,'audit_resource:'+variant,expected,mutate)
    serialized=json.dumps(snap)
    assert 'private-label-not-retained' not in serialized and 'request-not-retained' not in serialized
    if variant=='valid':
        row=next(c for c in snap['collections'] if c['type']=='log_entry')['items'][0]
        assert row['resource']=={'type':'gce_instance'}

@pytest.mark.parametrize('cid',ARCHIVED)
def test_exact_unsupported_exclusions_preserve_registration(cid):
    assert cid in {c.id for c in CHECKS}
    assert cid not in {c.id for c in automated_checks(CHECKS)}
    assert exclusions()[cid]['disposition']=='unsupported_exact_contract'
    assert exclusions()[cid]['mandatory_external_fields']==[]
    assert len(exclusions()[cid]['reason'])>100
    case=native.find(cid);snap,tr=native.capture(case)
    with pytest.raises(ValueError,match='not available for automated scans'):
        evaluate_snapshot(snap,checks=[cid])
    assert cid not in {c['id'] for c in get_catalog()['checks']}
    RECEIPTS.append({'check_id':cid,'scenario':'unsupported_exact_exclusion','test_nodeid':os.environ.get('PYTEST_CURRENT_TEST','').removesuffix(' (call)'),
                     'expected':['ARCHIVED'],'statuses':['ARCHIVED'],'exclusion':exclusions()[cid]})

def test_only_four_exclusions_added_and_prior_records_unchanged():
    before_raw=(HISTORY/'before-native_only.json').read_bytes()
    assert hashlib.sha256(before_raw).hexdigest()=='6a6f70a1d1162d9962c485a2c01659e15eb8bda36b194388e9b312b2ae6b49da'
    before=json.loads(before_raw)
    current=json.loads(Path('peaso/checks/native_only.json').read_text())
    # Retain the exact historical baseline while allowing independently reviewed
    # Azure additions; this GCP review contributes exactly these four IDs.
    assert {k:current['checks'][k] for k in before['checks']} == before['checks']
    assert {k for k in current['checks'] if k.startswith('gcp')}-set(before['checks']) == set(ARCHIVED)
    assert {k:v for k,v in current.items() if k!='checks'}=={k:v for k,v in before.items() if k!='checks'}
    review=json.loads(Path('docs/gcp-review/recheck-20261020/final-services-fixes.json').read_text())
    assert set(review['summary']['new_exclusion_ids']) == set(ARCHIVED)
    assert 'gcp_cloud_armor_waf_enabled' not in exclusions()


def test_original_review_and_source_predecessors_are_immutable():
    before=json.loads((HISTORY/'predecessor-hashes.json').read_text())
    path=Path('docs/gcp-review/recheck-20261020/final-services-review.json')
    # The frozen fixture keeps the original review digest. The 2026-10-25 source
    # re-pin (9e2f0e7e) moved that record once; accept the current bytes only via
    # the same explicit before/after successor pin the source reconciliation uses.
    successor={'before_sha256':'68587d9f932c0cb49c964755d393e425596631fe510eb5e355800e8fb0cbc701',
               'after_sha256':'e4f4fee07e5df95167b3795fba393af12fb51af2de3ddd01222bee9cd0565aa0'}
    assert before[str(path)]==successor['before_sha256']
    assert hashlib.sha256(path.read_bytes()).hexdigest()==successor['after_sha256']
    manifest=json.loads(Path('peaso/checks/bulk_pending.json').read_text())
    assert manifest['modules']['compliance_new_sw52']==before['peaso/checks/compliance_new_sw52.py']


def test_bulk_source_successor_is_exact_and_reversible():
    from peaso.checks.bulk_pending import _reviewed_source_admitted
    original=(HISTORY/'before-compliance_new_sw52.py').read_bytes()
    current=Path('peaso/checks/compliance_new_sw52.py').read_bytes()
    pin=hashlib.sha256(original).hexdigest()
    assert _reviewed_source_admitted('compliance_new_sw52',original,pin)
    assert _reviewed_source_admitted('compliance_new_sw52',current,pin)
    assert not _reviewed_source_admitted('compliance_new_sw52',current+b'\n',pin)
    assert not _reviewed_source_admitted('compliance_new_sw51',current,pin)
    assert not _reviewed_source_admitted('compliance_new_sw52',current,'0'*64)
    assert not _reviewed_source_admitted('compliance_new_sw52',current.replace(b'resource.type',b'resource.other',1),pin)
