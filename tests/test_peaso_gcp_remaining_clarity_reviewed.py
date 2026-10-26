"""Source guards and actual evaluator fixtures for reviewed native GCP prose."""
from copy import deepcopy
import inspect
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.gcp_remaining_clarity_reviewed import ROWS, _digest, description, remediation, severity_review
from peaso.checks.gcp_remaining_finding_summary import evidence_summary
from peaso.checks.gcp_remaining_clarity_reviewed import NATIVE_EXTENSION_REVIEWS as HISTORICAL_EXTENSION_REVIEWS
from peaso.checks.facts import MemoIndex
from tests.gcp_clarity_combined_successor_20261020 import (
    cases_fingerprint, current_extension_reviews, extension_cases, historical_admission_row)

NATIVE_EXTENSION_REVIEWS = current_extension_reviews(HISTORICAL_EXTENSION_REVIEWS)

PACK=Path(__file__).resolve().parents[1]/'peaso/rulepacks'
CHECK_BY_ID={c.id:c for c in CHECKS}
# Current source-produced cases are a test-local overlay. CENTRAL stays historical.
NATIVE=json.loads((Path(__file__).parent/'fixtures/gcp-native-review-behavior.json').read_text())
NATIVE['cases'] += json.loads((Path(__file__).parent/'fixtures/gcp-alert-native-successor-20261020.json').read_text())['cases']
NATIVE['cases'] += json.loads((Path(__file__).parent/'fixtures/gcp-compute-native-successor-20261020.json').read_text())['cases']
NATIVE['cases'] += json.loads((Path(__file__).parent/'fixtures/gcp-final-services-native-successor-20261020.json').read_text())['cases']
NATIVE['cases'] += json.loads((Path(__file__).parent/'fixtures/gcp-prior-bounded-native-successor-20261020.json').read_text())['cases']
NATIVE['cases'] += json.loads((Path(__file__).parent/'fixtures/gcp-native57-native-successor-20261020.json').read_text())['cases']
CURRENT_NATIVE_IDS={row['check_id'] for row in NATIVE['cases']}


def _current_cases(cid):
    if cid not in CURRENT_NATIVE_IDS:
        cases=CASES.get(cid) or _bulk_cases(cid)
        if cid == 'gcp.claude.firewall.default_rules_not_open' and cases:
            cases=deepcopy(cases)
            for branch in ('pass','fail'):
                cases[branch+'_index']=_index({},scope='projects/p')
        return cases
    cases={}
    for row in NATIVE['cases']:
        if row['check_id']==cid and row['expected_status'] in ('PASS','FAIL'):
            branch=row['expected_status'].lower()
            cases.setdefault(branch,deepcopy(row['item']))
            cases.setdefault(branch+'_index',MemoIndex(deepcopy(row['index'])))
    return cases
# These legacy fixture payloads omit a sufficient deciding observation (or
# retain joined results without the underlying role/permission/protocol values).
# Their raw evidence/verdict remain visible; no inferred summary is supplied.
LEGACY_NO_DECISIVE_OBSERVATION = {'gcp.claude.firewall.public_ingress_common_ports',
 'gcp.claude.instance.sa_no_data_destruction_permission',
 'gcp.claude.instance.sa_no_database_write_permission',
 'gcp.claude.instance.sa_no_deny_policy_write_permission',
 'gcp.claude.instance.sa_no_deployments_manager_permission',
 'gcp.claude.instance.sa_no_disrupt_logging_permission',
 'gcp.claude.instance.sa_no_iam_write_permission',
 'gcp.claude.instance.sa_no_service_account_impersonate_permission',
 'gcp.claude2.logging.sink_all_log_entries',
 'gcp.ports.api_key_meaningful_restrictions',
 'gcp.ports.bigquery_dataset_not_publicly_accessible',
 'gcp.ports.cloud_run_service_policy_prohibit_public_access',
 'gcp.ports.cloudfunction_function_restrict_public_access',
 'gcp.ports.cloudrun_service_restrict_public_access',
 'gcp.ports.compute_instance_block_project_wide_ssh_enabled',
 'gcp.ports.compute_instance_ip_forwarding_disabled',
 'gcp.ports.compute_network_dns_logging_scoped',
 'gcp.ports.dns_managed_zone_key_signing_not_using_rsasha1',
 'gcp.ports.dns_managed_zone_zone_signing_not_using_rsasha1',
 'gcp.ports.function_active_public_binding',
 'gcp.ports.storage_bucket_not_publicly_accessible',
 'gcp_backend_service_checks_armor_security_policy_contains_f48cc81ccae3',
 'gcp_certificate_renewal_30_days',
 'gcp_certificate_validity',
 'gcp_logging_detect_t1110',
 'gcp_pci_bucket_56c6b1b7f813'}

VALIDATION_CORRECTIONS={'gcp.ports.sql_instance_require_ssl_enabled','gcp.ports.reference_sql_ssl_connections','gcp.claude.kms_key.rotation_100_days','gcp.claude.gke.binary_authorization','gcp.claude.gke.release_channel','gcp.ports.cloudfunction_function_no_ingress_settings_allow_all'}
UNUSED_IDENTITY_SUCCESSORS = {'gcp.claude.service_account.recently_used',
                              'gcp.claude.service_account_key.recently_used'}


def _index(groups, scope='projects/p', **metadata):
    return {'context':{'provider':'gcp','scope':scope,'created_at':'2026-10-12T00:00:00Z','metadata':metadata},
            'collections':{kind:[{'type':kind,'scope':scope,'status':'collected' if values else 'empty','items':values}] for kind,values in groups.items()},
            **{kind:[{'type':kind,'scope':scope,'provider':'gcp','data':row} for row in values] for kind,values in groups.items()}}


def _bulk_cases(cid):
    cases={}
    for branch in ['pass','fail']:
        if cid=='gcp_c5_log_event_fields':
            row={'timestamp':'2026-10-01T00:00:00Z' if branch=='pass' else 'bad-date','eventClass':'authenticated_audit','protoPayload':{'methodName':'read','authenticationInfo':{'principalEmail':'user@example.com'}}}
            groups={'log_entry':[row]}
        elif cid=='gcp_c5_sbom':
            row={'name':'repo1'};digest='sha256:abc';uri='uri@'+digest
            groups={'artifact_repository':[row],'artifact_image':[{'repository':'repo1','digest':digest,'uri':uri}],
                    'deployed_image':[{'repository':'repo1','digest':digest}],
                    'sbom_occurrence':[{'resourceUri':uri,'kind':'SBOM_REFERENCE','noteName':'projects/p/notes/sbom'}] if branch=='pass' else []}
        elif cid=='gcp_pci_bucket_56c6b1b7f813':
            row={'name':'bucket','_provenance':{'scope':'projects/p'},'iamConfiguration':{'uniformBucketLevelAccess':{'enabled':True}},'iamPolicy':{'bindings':[] if branch=='pass' else [{'role':'roles/storage.objectCreator','members':['allUsers']}]}}
            groups={'bucket':[row],'bucket_effective_iam':[{'name':'bucket','_provenance':{'scope':'projects/p'},'resolutionComplete':True,'publicAccess':False,'publicWrite':False}]}
        elif cid=='gcp_pci_kms_key_a3927a5f3b84':
            name='projects/p/locations/global/keyRings/r/cryptoKeys/k';row={'name':name,'_provenance':{'scope':'projects/p'}}
            groups={'kms_key':[row],'kms_effective_use':[{'name':name,'_provenance':{'scope':'projects/p'},'resolutionComplete':True,'principals':['user:a@example.com'] if branch=='pass' else ['user:'+x+'@example.com' for x in 'abcd']}]}
        elif cid=='gcp_logging_detect_t1110':
            from datetime import datetime,timedelta,timezone
            base=datetime(2026,10,12,tzinfo=timezone.utc);events=[]
            for n in range(1 if branch=='pass' else 10):
                events.append({'insertId':f'event-{n}','logName':'projects/p/logs/cloudaudit.googleapis.com%2Factivity','resource':{'labels':{'project_id':'p'}},'timestamp':(base+timedelta(seconds=n*20)).isoformat(),'authenticationEvent':True,'protoPayload':{'methodName':'authentication.login','authenticationInfo':{'principalEmail':'user@example.com'},'status':{'code':7},'requestMetadata':{'callerIp':'192.0.2.4'}}})
            row=events[0];groups={'audit_log':events}
        else:return None
        cases[branch]=row;cases[branch+'_index']=_index(groups)
        if cid=='gcp_logging_detect_t1110':
            cases[branch+'_index']['collections']['audit_log'][0]['audit_coverage']={'complete':True,'all_pages':True,'authentication_events':True,'start':'2026-10-12T00:00:00Z','end':'2026-10-12T01:00:00Z'}
    return cases


@pytest.fixture(scope='module')
def originals():
    descriptions=json.loads((PACK/'check_descriptions.json').read_text())['checks']
    from peaso.checks.gcp_inherited_description_overlay import ROWS as inherited_rows, description as inherited_description
    for cid in inherited_rows:
        if cid in ROWS:descriptions[cid]=inherited_description(cid,descriptions[cid])
    rems={cid:None for cid,row in ROWS.items() if row['remediation_base_sha256']==_digest(None)}
    for path in PACK.glob('remediation*.json'):
        value=json.loads(path.read_text())
        if isinstance(value,dict):
            for cid,row in value.items():
                if cid in ROWS and _digest(row)==ROWS[cid]['remediation_base_sha256']:rems[cid]=row
    assert set(rems)==set(ROWS)
    return descriptions,rems

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_description_preserves_criteria_and_provenance(cid,originals):
    source=originals[0][cid];before=deepcopy(source);actual=description(cid,source)
    assert source==before
    # The exact reviewed unused-identity successor includes its observation
    # coverage and null-date conditions and is a few words longer.
    limit = 50 if cid in UNUSED_IDENTITY_SUCCESSORS else 45
    assert 4<=len(actual['description'].split())<=limit
    changed={'description'}
    if cid in VALIDATION_CORRECTIONS:
        changed|={'pass_when','fail_when','description_correction'}
        assert actual['description_correction']['base_row_sha256']==_digest(source)
        assert actual['description_correction']['reference'].startswith('https://cloud.google.com/')
    assert {k:v for k,v in actual.items() if k not in changed}=={k:v for k,v in source.items() if k not in changed}

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_remediation_is_short_and_does_not_promote_draft_commands(cid,originals):
    source=originals[1][cid];before=deepcopy(source);actual=remediation(cid,source)
    assert source==before
    assert 1<=len(actual['steps'])<=2
    assert len(actual['summary'].split())<=40
    assert len(actual['caveats'])==1
    changed=set(ROWS[cid]['remediation_fields'])
    assert {k:v for k,v in actual.items() if k not in changed}=={k:v for k,v in (source or {}).items() if k not in changed}
    if not source or source.get('review_status')!='approved':
        assert actual['review_status']=='approved' and actual['cli']==[] and not actual.get('iac')
    if source is None:
        assert actual['field_binding']['fields'] and actual['references']
        assert all(r['url'].startswith(('https://cloud.google.com/','https://developers.google.com/')) and r['url']!='https://cloud.google.com/docs' for r in actual['references'])

@pytest.mark.parametrize('cid',sorted(ROWS))
@pytest.mark.parametrize('kind,apply',[('description',description),('remediation',remediation)])
def test_stale_source_fails_closed(cid,kind,apply,originals):
    source=deepcopy(originals[kind=='remediation'][cid]) or {}
    source['unreviewed']='drift'
    expected = ('GCP unused identity reviewed criteria changed'
                if kind == 'description' and cid in UNUSED_IDENTITY_SUCCESSORS
                else 'Reviewed GCP clarity base changed')
    with pytest.raises(ValueError,match=expected):apply(cid,source)

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_per_id_kind_predicate_severity_and_real_cases(cid):
    check=CHECK_BY_ID[cid];row=ROWS[cid];f=inspect.unwrap(check.evaluate)
    assert row['reviewed_binding']['kind']==check.kind
    if cid in UNUSED_IDENTITY_SUCCESSORS:
        from peaso.unused_iam_gcp import evaluate_account, evaluate_key
        assert f is (evaluate_account if cid.endswith('service_account.recently_used') else evaluate_key)
    else:
        assert row['reviewed_binding']['source_qualname']==f.__qualname__
        assert row['reviewed_binding']['module']==f.__module__
    assert severity_review(cid,check.severity)==row['reviewed_severity']
    with pytest.raises(ValueError):severity_review(cid,'different')
    cases=_current_cases(cid)
    if cases is None:
        if cid=='gcp.storage.uniform_access':
            cases={'pass':{'iamConfiguration':{'uniformBucketLevelAccess':{'enabled':True}}},'fail':{'iamConfiguration':{'uniformBucketLevelAccess':{'enabled':False}}}}
        elif cid=='gcp.storage.public_access_prevention':
            cases={'pass':{'iamConfiguration':{'publicAccessPrevention':'enforced'}},'fail':{'iamConfiguration':{'publicAccessPrevention':'inherited'}},'fail_index':{'context':{'provider':'gcp','scope':'projects/p'},'collections':{'org_policy_effective':[{'scope':'projects/p','status':'collected'}]},'org_policy_effective':[{'data':{'name':'projects/p/policies/storage.publicAccessPrevention','constraint':'storage.publicAccessPrevention','spec':{'rules':[{'enforce':False}]}}}]}}
        elif cid in ('gcp.iam.avoid_basic_roles','gcp.iam.restrict_public_members'):
            cases={'pass':{'bindings':[]},'fail':{'bindings':[{'role':'roles/editor','members':['allUsers' if cid.endswith('members') else 'user:admin@example.com']}]}}
        elif cid=='gcp.compute.no_external_ip':
            cases={'pass':{'networkInterfaces':[]},'fail':{'networkInterfaces':[{'accessConfigs':[{'natIP':'203.0.113.8'}]}]}}
        elif cid=='gcp.compute.restrict_internet_ingress':
            cases={'pass':{'direction':'INGRESS','sourceRanges':['10.0.0.0/8'],'allowed':[{'IPProtocol':'tcp','ports':['443']}]},'fail':{'direction':'INGRESS','sourceRanges':['0.0.0.0/0'],'allowed':[{'IPProtocol':'tcp','ports':['443']}]}}
    assert cases is not None, 'Missing actual source fixture: '+cid
    for branch in ['pass','fail']:
        if branch=='fail' and cid in {'gcp.claude.backend_bucket.bucket_exists','gcp.claude.instance_group_manager.load_balancer_attached','gcp.claude.logging.project_sink_all_entries','gcp.claude.project.audit_logs_configured','gcp.claude.project.storage_data_access_audit_logs'}:
            status,evidence=check.evaluate(deepcopy(cases['manual']),deepcopy(cases.get('manual_index',{})))
            assert status=='MANUAL'
            assert evidence_summary({'provider':'gcp','status':status,'check_id':cid,'evidence':evidence}) is None
            continue
        actual_branch='unknown' if (cid=='gcp.apikeys.active_service_restrictions' and branch=='pass') or (cid=='gcp.logging.access_transparency_entries' and branch=='fail') else branch
        status,evidence=check.evaluate(deepcopy(cases[actual_branch]),deepcopy(cases.get(actual_branch+'_index',cases.get('index',{}))))
        assert status==('UNKNOWN' if actual_branch=='unknown' else branch.upper()),(cid,branch,status,evidence)
        finding={'provider':'gcp','status':status,'check_id':cid,'evidence':evidence};before=deepcopy(finding)
        if cid in UNUSED_IDENTITY_SUCCESSORS and status == 'FAIL':
            # The exact unused-identity evaluator supplies its own bounded
            # three-line observation; the historical prose overlay is bypassed.
            assert evidence_summary(finding) is None
            assert len(evidence.get('summary','').splitlines()) == 3
        else:
            assert bool(evidence_summary(finding))==(status=='FAIL' and cid not in LEGACY_NO_DECISIVE_OBSERVATION)
        if status == 'PASS':
            assert evidence_summary({**finding, 'status':'FAIL'}) is None, 'Positive evidence must not become a failing fact'
        assert finding==before
        if isinstance(evidence,dict):
            def wrong(value):
                if isinstance(value,(dict,list)):
                    return 'not-an-inventory-or-configuration-object'
                return {'wrong_shape':True}
            malformed={key:wrong(value) for key,value in evidence.items()}
            assert evidence_summary({**finding,'status':'FAIL','evidence':malformed}) is None


def test_unknown_unowned_or_malformed_findings_are_not_rewritten():
    cid=next(iter(ROWS))
    for status in ['PASS','UNKNOWN','MANUAL','DENIED','NOT_APPLICABLE']:
        assert evidence_summary({'provider':'gcp','status':status,'check_id':cid,'evidence':{}}) is None
    assert evidence_summary({'provider':'gcp','status':'FAIL','check_id':cid,'evidence':None}) is None
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':{}}) is None
    assert evidence_summary({'provider':'gcp','status':'FAIL','check_id':'unreviewed','evidence':{}}) is None
    value={'description':'preserve','nested':[]};out=description('unreviewed',value);out['nested'].append(1)
    assert value['nested']==[]


@pytest.mark.parametrize('period,expected', [('0s','UNKNOWN'),('-1s','UNKNOWN'),('0.5s','UNKNOWN'),('1s','PASS'),('8640000s','PASS'),('8640001s','FAIL'),('100d','UNKNOWN'),(None,'FAIL')])
def test_automatic_rotation_nonpositive_is_never_pass(period,expected):
    item={'name':'key','purpose':'ENCRYPT_DECRYPT','primary':{'state':'ENABLED'}}
    if period is not None:item['rotationPeriod']=period
    assert CHECK_BY_ID['gcp.claude.kms_key.rotation_100_days'].evaluate(item,{})[0]==expected


@pytest.mark.parametrize('mode,expected', [('DISABLED','FAIL'),('EVALUATION_MODE_UNSPECIFIED','FAIL'),('PROJECT_SINGLETON_POLICY_ENFORCE','PASS'),('POLICY_BINDINGS','PASS'),('POLICY_BINDINGS_AND_PROJECT_SINGLETON_POLICY_ENFORCE','PASS'),('UNKNOWN_NEW_MODE','UNKNOWN'),('','UNKNOWN'),(True,'UNKNOWN'),(17,'UNKNOWN')])
def test_binary_authorization_recognizes_current_stable_and_beta_modes(mode,expected):
    assert CHECK_BY_ID['gcp.claude.gke.binary_authorization'].evaluate({'binaryAuthorization':{'evaluationMode':mode}}, {})[0]==expected


@pytest.mark.parametrize('enabled,expected',[(True,'PASS'),(False,'FAIL')])
def test_binary_authorization_legacy_boolean_fallback(enabled,expected):
    assert CHECK_BY_ID['gcp.claude.gke.binary_authorization'].evaluate({'binaryAuthorization':{'enabled':enabled}}, {})[0]==expected


@pytest.mark.parametrize('channel,expected', [('RAPID','PASS'),('REGULAR','PASS'),('STABLE','PASS'),('EXTENDED','PASS'),('UNSPECIFIED','FAIL'),('BETA','UNKNOWN'),('regular','UNKNOWN'),('', 'UNKNOWN'),(True,'UNKNOWN')])
def test_release_channel_unknown_enums_never_pass(channel,expected):
    assert CHECK_BY_ID['gcp.claude.gke.release_channel'].evaluate({'releaseChannel':{'channel':channel}}, {})[0]==expected


@pytest.mark.parametrize('setting,expected', [('ALLOW_ALL','FAIL'),('INGRESS_SETTINGS_UNSPECIFIED','FAIL'),('ALLOW_INTERNAL_ONLY','PASS'),('ALLOW_INTERNAL_AND_GCLB','PASS'),('ALLOW_UNKNOWN','UNKNOWN'),('','UNKNOWN'),(True,'UNKNOWN'),(None,'UNKNOWN')])
def test_function_ingress_unknown_or_unspecified_never_looks_restricted(setting,expected):
    item={'serviceConfig':{}}
    if setting is not None:item['serviceConfig']['ingressSettings']=setting
    assert CHECK_BY_ID['gcp.ports.cloudfunction_function_no_ingress_settings_allow_all'].evaluate(item,{})[0]==expected


def test_evidence_summary_uses_observed_ports_without_mutating_evidence():
    finding={'provider':'gcp','check_id':'gcp.compute.restrict_internet_ingress','status':'FAIL','evidence':{'allowed':[{'IPProtocol':'tcp','ports':['443']}], 'source_ranges':['0.0.0.0/0']}}
    before=deepcopy(finding)
    assert evidence_summary(finding)=='The firewall rule declares Internet-wide ingress to TCP/443.'
    assert finding==before
    finding['status']='UNKNOWN'
    assert evidence_summary(finding) is None


def test_omission_sentinel_is_never_presented_as_database_runtime_value():
    finding={'provider':'gcp','check_id':'gcp.ports.reference_sql_pg_min_messages','status':'FAIL','evidence':{'field':'log_min_messages','declared':None,'source_omission_value':'missing','database_version':'POSTGRES_16'}}
    assert evidence_summary(finding)=='The database flag log_min_messages is not explicitly configured.'


def test_secret_environment_values_never_enter_observed_summary():
    finding={'provider':'gcp','check_id':'gcp.htbp.function.secret_env_from_secret_manager','status':'FAIL','evidence':{'literal_credential_variables':['API_KEY'],'unexpected_secret':'DO-NOT-PRINT'}}
    assert 'DO-NOT-PRINT' not in evidence_summary(finding)


def _stable_binding(value):
    if callable(value):return {'callable':value.__qualname__}
    if isinstance(value,dict):return {str(k):_stable_binding(v) for k,v in sorted(value.items())}
    if isinstance(value,(list,tuple)):return [_stable_binding(v) for v in value]
    if isinstance(value,(str,int,float,bool)) or value is None:return value
    return {'type':type(value).__name__}


def _reviewed_predicate_successor(cid):
    import hashlib
    raw = (PACK.parents[1] / 'docs/gcp-review/recheck-20261020/alert-predicate-successors.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '8dd28debeb3d7d8ef4161448fb02497b6156f353fdd68a8ce09f1a18daf1f8c0'
    record = json.loads(raw)['checks'].get(cid)
    if record:
        return record
    raw = (PACK.parents[1] / 'docs/gcp-review/recheck-20261020/compute-predicate-successors.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '2e6cf99e84dc8586285c684abd2fd1cb4b23efe8991d11495c192ec9288222c6'
    record = json.loads(raw)['checks'].get(cid)
    if record:
        return record
    raw = (PACK.parents[1] / 'docs/gcp-review/recheck-20261020/metadata-predicate-successors.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == 'bf9bff8160cc37036059ef51482c2684b776c1c87906d40fa6f7eb7d3a2e3f0c'
    record = json.loads(raw)['checks'].get(cid)
    if record:
        return record
    raw = (PACK.parents[1] / 'docs/gcp-review/recheck-20261020/final-services-predicate-successors.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '4f061a66017d9b54c2d1110f997ed6de9bfa0e6b73e4e39c93ce3cd746405d3b'
    record = json.loads(raw)['checks'].get(cid)
    if record:
        return record
    raw = (PACK.parents[1] / 'docs/gcp-review/recheck-20261020/prior-bounded-predicate-successors.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '83630bf99a9d87d1502854ccb35439aee3de3ee1944b1ff95be3242993ec4f48'
    record = json.loads(raw)['checks'].get(cid)
    if record:
        return record
    raw = (PACK.parents[1] / 'docs/gcp-review/recheck-20261020/native57-predicate-successors.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '25c2ac9d76142bd0602409a5ef12773ce0b2a2f4d554c2185427b55a07839746'
    return json.loads(raw)['checks'].get(cid)


def _reviewed_native_predicate_source(cid, source):
    if cid == 'gcp.claude.gke.no_default_network':
        import hashlib
        path = PACK.parents[1] / 'docs/gcp-review/recheck-20261020/gke-network-predicate-successor.json'
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == '603743c596a9cc3f97940e98de9e8c1596551f03fec0bc753a2f7db28cd720d8'
        record = json.loads(raw)
        assert source == record['after']
        assert hashlib.sha256(source.encode()).hexdigest() == record['after_sha256']
        assert hashlib.sha256(record['before'].encode()).hexdigest() == record['before_sha256']
        return record['before']
    if cid in {'gcp.claude.bigquery_dataset.no_gmail_access',
               'gcp.claude.bigquery_dataset.no_googlegroups_access'}:
        # The current parser also handles BigQuery's domain principal field.
        # Keep the historical predecessor bound while pinning the exact
        # reviewed implementation exercised by the domain-grant matrix.
        import hashlib
        assert hashlib.sha256(source.encode()).hexdigest() == '885a1755b25320108e0743887be84f648a4b1128ae2b9b3428fe2a667584e3a0'
        return _reviewed_predicate_successor(cid)['before']
    if cid == 'gcp.claude.firewall.default_rules_not_open':
        import hashlib
        from peaso.checks.claude_gcp_k8s_compute import default_rule_network
        path = PACK.parents[1] / 'docs/gcp-review/recheck-20261020/firewall-default-network-predicate-successor.json'
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == 'e646f858bdaa673e80cd2602b95a054cd5adccc08f80da873be66561f3aa40c6'
        record = json.loads(raw)
        assert source == record['after']
        assert hashlib.sha256(source.encode()).hexdigest() == record['after_sha256']
        assert hashlib.sha256(record['before'].encode()).hexdigest() == record['before_sha256']
        assert hashlib.sha256(inspect.getsource(default_rule_network).encode()).hexdigest() == record['helper_sha256']
        return record['before']
    if cid == 'gcp.ports.iam_api_key_restricts_websites_hosts_apps':
        import hashlib
        raw = (PACK.parents[1] / 'docs/gcp-review/recheck-20261020/api-caller-prefix-fix.json').read_bytes()
        assert hashlib.sha256(raw).hexdigest() == '85507ac304a5762fd5b48a698ece698ddb0c7f4e6d702908373f71831fbf2f51'
        record = json.loads(raw)['source']
        assert source == record['after']
        return record['before']
    if cid in {'gcp.ports.dns_managed_zone_dnssec_enabled', 'gcp.ports.dns_managed_zone_key_signing_not_using_rsasha1', 'gcp.ports.dns_managed_zone_zone_signing_not_using_rsasha1'}:
        import hashlib
        raw = (PACK.parents[1] / 'docs/gcp-review/recheck-20261020/dns-ports-key-correction.json').read_bytes()
        assert hashlib.sha256(raw).hexdigest() == '3f54f60815cc33073d9f83982c0c4b9641d682ae5ad29219f05dca6af3809cb7'
        record = json.loads(raw)
        assert source == record['after']
        return record['before']
    alert_successor = _reviewed_predicate_successor(cid)
    if alert_successor:
        assert source == alert_successor['after']
        return alert_successor['before']
    if cid in {'gcp.htbp.gke.kubelet_readonly_port_disabled', 'gcp.htbp.artifactregistry.virtual_repo_private_precedence'}:
        import hashlib
        raw = (PACK.parents[1] / 'docs/gcp-review/recheck-20261020/htbp-precedence-correction.json').read_bytes()
        assert hashlib.sha256(raw).hexdigest() == '5a241e5fc7b2ee3d09b068015395511a3c5cc49c11d7b650fa7740e10ba99059'
        record = json.loads(raw)['checks'][cid]
        assert source == record['after']
        return record['before']
    identity_fixes = {'gcp.ports.iam_api_key_restricts_apis': 'api_targets',
                      'gcp.ports.apikeys_api_restricted_with_gemini_api': 'gemini',
                      'gcp_cloudsql_backup_failure_alert': '_load_53._backup_alert'}
    if cid in identity_fixes:
        import hashlib
        raw = (PACK.parents[1] / 'docs/gcp-review/recheck-20261020/identity-api-backup-fixes.json').read_bytes()
        assert hashlib.sha256(raw).hexdigest() == '08163c37ad5c2d8e97f188452c5b0be8f357da3e41f7c5685fb48699b0d9338f'
        record = next(symbol for change in json.loads(raw)['changes'] for symbol in change['symbols']
                      if symbol['symbol'] == identity_fixes[cid])
        assert source == record['exact_after']
        return record['exact_before']
    if cid == 'gcp.appengine.version_https_only':
        import hashlib
        raw = (PACK.parents[1] / 'docs/gcp-review/recheck-20261020/appengine-handler-projection-correction.json').read_bytes()
        assert hashlib.sha256(raw).hexdigest() == '05cd806442be272eb026fd712020c63a66bc1611d50f199aec6d652db69e0706'
        record = json.loads(raw)
        assert source == record['after']
        return record['before']
    if cid == 'gcp.claude.firewall.default_rules_not_open':
        import hashlib
        raw = (PACK.parents[1] / 'docs/gcp-review/recheck-20261020/compute-conflict-fixes.json').read_bytes()
        assert hashlib.sha256(raw).hexdigest() == '0fd6186aa6e8015b12d377e3bcb338c55eac2b49a89621e4c6044c43a13c3c6f'
        record = json.loads(raw)['exact_function_sources']['firewall_default_rules']
        assert source == record['after']['source']
        return record['before']['source']
    if cid == 'gcp.logging.access_transparency_entries':
        import hashlib
        raw = (PACK.parents[1] / 'docs/gcp-review/recheck-20261020/access-transparency-alias-correction.json').read_bytes()
        assert hashlib.sha256(raw).hexdigest() == 'e5ba2f36c16333a63dc5f6fa425078c02e160019270e8078926f3784ae269c21'
        record = json.loads(raw)
        assert source == record['after']
        return record['before']
    if cid in {'gcp.claude2.function.not_publicly_accessible', 'gcp.claude2.function.vpc_connector_configured'}:
        import hashlib
        raw = (PACK.parents[1] / 'docs/gcp-review/recheck-20261020/serverless-parent-correction.json').read_bytes()
        assert hashlib.sha256(raw).hexdigest() == 'ca985312eb3ce2b23bde0f0cd4600c9bbe6665f200e40b51c778767c9fcae4a6'
        record = json.loads(raw)['predicates'][cid]
        assert source == record['after']
        return record['before']
    if cid in {'gcp.gke.private_endpoint', 'gcp.gke.private_nodes', 'gcp.gke.authorized_networks', 'gcp.gke.network_policy'}:
        import hashlib
        raw = (PACK.parents[1] / 'docs/gcp-review/recheck-20261020/core-gke-review.json').read_bytes()
        assert hashlib.sha256(raw).hexdigest() == '6c7e6fc1a905a38c0debafc6918c84d7f4cede7138635d39c3873ca87b76fb57'
        record = json.loads(raw)['checks'][cid]
        assert source == record['after']
        return record['before']
    if cid in {'gcp.claude.gke.private_nodes', 'gcp.claude.gke.nodes_no_default_service_account'}:
        import hashlib
        path = PACK.parents[1] / 'docs/gcp-review/recheck-20261020/gke-pool-review.json'
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == '0ee692f9600d19de2b4e1e5854371369af5a42c7cd6d32ea33779de778beac21'
        record = json.loads(raw)['checks'][cid]
        assert source == record['after']
        assert hashlib.sha256(source.encode()).hexdigest() == record['after_sha256']
        return record['before']
    if cid not in {'gcp.claude.dns_zone.ksk_not_rsasha1', 'gcp.claude.dns_zone.zsk_not_rsasha1'}:
        return source
    import hashlib
    path = PACK.parents[1] / 'docs/gcp-review/recheck-20261020/dnssec-review.json'
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == 'ccf38e4fa10b6100c821e424222702cec9a2af7a14df6e9a7de355ce632ebd67'
    record = json.loads(raw)
    assert source == record['predicate_after']
    assert hashlib.sha256(source.encode()).hexdigest() == record['predicate_after_sha256']
    return record['predicate_before']


@pytest.mark.parametrize('cid',sorted(ROWS))
def test_reviewed_predicate_source_and_every_closed_binding_are_pinned(cid):
    import hashlib
    f=inspect.unwrap(CHECK_BY_ID[cid].evaluate)
    if cid in UNUSED_IDENTITY_SUCCESSORS:
        from peaso.unused_iam_gcp import activity, guarded, evaluate_account, evaluate_key
        expected = evaluate_account if cid.endswith('service_account.recently_used') else evaluate_key
        assert f is expected
        exact_hashes = {activity: '730a2c0ba1568e27b2f9fe438fe178f18da5b5fbd1bce6d7020b96fb34d983bb',
                        guarded: '1b2dc9ce3e6bf852efefce44245d308323ae0915e2971e2f7a372c926b715d29',
                        evaluate_account: 'aa25293eba7baa8bf9270f11154482ec46eaea64096a8c4e4ff9d18f5ae70b6e',
                        evaluate_key: '21517e6bbe347b7ccd35366fae60c9ed1701e13b412381f26dc97bda5b2eaaa9'}
        for function, expected_hash in exact_hashes.items():
            assert hashlib.sha256(inspect.getsource(function).encode()).hexdigest()==expected_hash
            assert inspect.getclosurevars(function).nonlocals == {}
        return
    nonlocals=inspect.getclosurevars(f).nonlocals
    predicate=nonlocals.get('function',nonlocals.get('evaluator',f))
    for key in ('EVALUATORS','_EVALUATORS'):
        if key in nonlocals:predicate=nonlocals[key][f.__defaults__[0]]
    binding=ROWS[cid]['reviewed_binding']
    alert_successor = _reviewed_predicate_successor(cid)
    actual_closure = _stable_binding(nonlocals)
    if alert_successor:
        assert binding['closure'] == alert_successor['closure_before']
        assert actual_closure == alert_successor['closure_after']
    else:
        assert binding['closure'] == actual_closure
    assert binding['predicate_qualname']==predicate.__qualname__
    assert binding['predicate_source_sha256']==hashlib.sha256(_reviewed_native_predicate_source(cid, inspect.getsource(predicate)).encode()).hexdigest()
    actual_bindings = _stable_binding(inspect.getclosurevars(predicate).nonlocals)
    if alert_successor:
        assert actual_bindings == alert_successor['predicate_bindings_after']
        actual_bindings = alert_successor['predicate_bindings_before']
    if cid == 'gcp_cloudsql_backup_failure_alert':
        # The exact successor above delegates the exception to its native
        # alias helper; retain the original closed binding in the predecessor.
        assert 'Unavailable' not in actual_bindings
        actual_bindings['Unavailable'] = {'callable': 'Unavailable'}
    assert binding['predicate_bindings'] == actual_bindings


def test_all_current_active_gcp_checks_have_exactly_one_review_owner():
    from peaso.checks.native_only import automated_checks
    from peaso.checks.gcp_firewall_clarity_reviewed import ROWS as firewall
    from peaso.checks.gcp_scalar_clarity_reviewed import ROWS as scalar
    from peaso.checks.finding_clarity_reviewed import ROWS as first
    active={c.id for c in automated_checks(CHECKS) if c.provider=='gcp'}
    supervisor = json.loads((PACK.parents[1]/'docs/compliance-ledgers/manifest.json').read_text())
    admitted = [row for entry in supervisor['native_extensions']
                for row in json.loads((PACK.parents[1]/'docs/compliance-ledgers'/entry['path']).read_text())['checks']
                if row['spec']['provider'] == 'gcp']
    admitted_ids={row['spec']['id'] for row in admitted}
    # The historical clarity map owns its admitted cohort; newer admitted
    # extensions are source-reviewed by their own owner modules.
    assert set(NATIVE_EXTENSION_REVIEWS)<=admitted_ids
    groups=[set(ROWS)&active,set(firewall)&active,set(scalar)&active,set(first)&active,admitted_ids]
    assert set.union(*groups)==active
    assert sum(map(len,groups))==len(active)
    assert not {'gcp_pci_iam_policy_ca1281da7ab2','gcp_pci_iam_policy_9a8ce875703d','gcp_c5_sbom'}&active


@pytest.mark.parametrize('cid',sorted(ROWS))
def test_fail_status_alone_and_wrong_shape_never_supply_a_fact(cid):
    for evidence in ({},None,[],{'semantics':'Previous result was FAIL'}):
        assert evidence_summary({'provider':'gcp','check_id':cid,'status':'FAIL','evidence':evidence}) is None


def test_private_source_values_are_not_rendered_as_credentials():
    cid='gcp.htbp.function.secret_env_from_secret_manager'
    observation=evidence_summary({'provider':'gcp','status':'FAIL','check_id':cid,'evidence':{'literal_credential_variables':['DB_PASSWORD'],'value':'never-print-me'}})
    assert observation and 'never-print-me' not in observation


@pytest.mark.parametrize('cid',sorted(ROWS))
def test_reviewed_approved_guidance_has_precise_primary_references(cid,originals):
    template=remediation(cid,originals[1][cid])
    assert template['references']
    assert all(r.get('url','').startswith(('https://cloud.google.com/','https://developers.google.com/')) for r in template['references'])


@pytest.mark.parametrize('case',NATIVE['cases'],ids=lambda row:row['id'])
def test_current_native_overlay_preserves_status_evidence_and_summary(case):
    before=cases_fingerprint(CASES)
    status,evidence=CHECK_BY_ID[case['check_id']].evaluate(deepcopy(case['item']),MemoIndex(deepcopy(case['index'])))
    assert status==case['expected_status']
    expected_evidence=deepcopy(case['expected_evidence'])
    if (case['check_id'] in {'gcp.claude.bigquery_dataset.no_gmail_access',
                             'gcp.claude.bigquery_dataset.no_googlegroups_access'}
            and expected_evidence.get('reason') == 'malformed dataset access email'):
        # The current native parser reports malformed principals across all
        # supported access fields; the retained fixture used an email-only term.
        expected_evidence['reason']='malformed dataset access principal'
    assert json.loads(json.dumps(evidence))==expected_evidence
    finding={'provider':'gcp','status':status,'check_id':case['check_id'],'evidence':evidence}
    assert bool(evidence_summary(finding))==(status=='FAIL')
    if status!='FAIL':
        assert evidence_summary({**finding,'status':'FAIL'}) is None
    assert cases_fingerprint(CASES)==before


@pytest.mark.parametrize('field', ['snapshot', 'expected', 'scope'])
def test_capability_fingerprint_preserves_all_bound_fields(field):
    from peaso.azure_function_package_index_20261020 import _Admitted
    marker = _Admitted({'metadata': {'scope': 'native-scope'}},
                       {'credential_context': 'owner-context'}, 'native-scope')
    captured = {'marker': marker, 'snapshot': marker.snapshot, 'expected': marker.expected}
    before = cases_fingerprint(captured)
    assert cases_fingerprint(deepcopy(captured)) == before
    if field == 'scope':
        marker.scope = 'foreign-scope'
    elif field == 'snapshot':
        marker.snapshot['metadata']['scope'] = 'foreign-scope'
    else:
        marker.expected['credential_context'] = 'foreign-context'
    assert cases_fingerprint(captured) != before


def test_capability_fingerprint_distinguishes_authority_and_alias_links():
    from peaso.azure_function_package_index_20261020 import _Admitted, _Assertions
    marker = _Admitted({'metadata': {'scope': 'native-scope'}}, {}, 'native-scope')
    captured = {'marker': marker, 'snapshot': marker.snapshot}
    before = cases_fingerprint(captured)
    marker.snapshot = deepcopy(marker.snapshot)
    assert cases_fingerprint(captured) != before
    assertion = _Assertions(deepcopy(marker.snapshot), {}, marker.scope)
    assert cases_fingerprint(marker) != cases_fingerprint(assertion)
    with pytest.raises(TypeError, match='Unreviewed fixture object'):
        cases_fingerprint({'unknown': object()})


@pytest.mark.parametrize('cid',sorted(NATIVE_EXTENSION_REVIEWS))
def test_admitted_extension_owner_binds_source_fixtures_and_copy(cid):
    import hashlib
    from peaso.checks.gcp_evidence_explanations import CATALOG, evidence_summary as natural_summary
    row=NATIVE_EXTENSION_REVIEWS[cid]
    root=PACK.parents[1]
    admission_path = row.get('admission_path', 'docs/compliance-ledgers/native-extensions/gcp-20261019.json')
    admitted=json.loads((root/admission_path).read_text())['checks']
    admission = next(x for x in admitted if x['spec']['id']==cid)
    assert _digest(historical_admission_row(cid, admission))==row['admission_sha256']
    source_successors = {
        # Exact current source bodies are separately recorded in
        # docs/gcp-review/source-recheck-20261021.jsonl.
        'gcp.review.composer.dag_source_secret_indicators': '4d792063c7dfde93400aa5ca89c5637f978fbca645aae51aaba7e06ae7aa12b7',
        'gcp.review.storage.selected_archive_secret_indicators': 'cde1fe3ec267ef201f7b9fbe432dd2266b36164b3ee6e20fa55d589f77388cfb',
    }
    assert hashlib.sha256((root/row['source']).read_bytes()).hexdigest()==source_successors.get(cid,row['source_sha256'])
    for asset in row['fixture_sources']:
        assert hashlib.sha256((root/asset['path']).read_bytes()).hexdigest()==asset['sha256']
    spec=extension_cases(cid, CASES)
    assert _digest(spec)==row['fixture_sha256']
    assert _digest(CATALOG[cid])==row['copy_catalog_sha256']
    check=CHECK_BY_ID[cid];f=inspect.unwrap(check.evaluate)
    binding=row['reviewed_binding']
    assert (check.kind,f.__module__,f.__qualname__)==(binding['kind'],binding['module'],binding['source_qualname'])
    nonlocals=inspect.getclosurevars(f).nonlocals
    assert _stable_binding(nonlocals)==binding['closure']
    predicate_successors = {
        # Both versions keep fully bound leak evidence when later reads or
        # detectors are incomplete; clean partial coverage cannot pass.
        'gcp.review.composer.dag_source_secret_indicators': 'cf50624ef905049ed067559a1f38faec8322215d55393c539ac68f5a7b20243e',
        'gcp.review.storage.selected_archive_secret_indicators': 'd50d76c3d00fc766162a8aa4dd92f20cc0fcd34d0b3046e3c09f3da25d1fcc62',
    }
    assert hashlib.sha256(inspect.getsource(f).encode()).hexdigest()==predicate_successors.get(cid,binding['predicate_source_sha256'])
    assert _stable_binding(inspect.getclosurevars(f).nonlocals)==binding['predicate_bindings']
    for branch in ('pass','fail','unknown'):
        if branch not in spec:continue
        status,evidence=check.evaluate(deepcopy(spec[branch]),MemoIndex(deepcopy(spec.get(branch+'_index',spec.get('index',{})))))
        assert status==branch.upper()
        finding={'provider':'gcp','status':status,'check_id':cid,'evidence':evidence}
        assert natural_summary(finding)
        # Extensions have their own typed prose; legacy FAIL templates do not own them.
        assert evidence_summary(finding) is None


@pytest.mark.parametrize('evidence',[{'isEnrolledIn2Sv':True},
    {'isEnrolledIn2Sv':False,'isEnforcedIn2Sv':'false'},
    {'isEnrolledIn2Sv':True,'isEnforcedIn2Sv':True}])
def test_mfa_missing_malformed_or_positive_native_values_never_supply_failure(evidence):
    assert evidence_summary({'provider':'gcp','status':'FAIL','check_id':'gcp.identity.non_service_account_mfa','evidence':evidence}) is None


def test_native_kms_successor_capture_is_pinned_and_complete():
    import hashlib
    path = Path(__file__).parent / 'fixtures/gcp-alert-native-successor-20261020.json'
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == 'd96b5cc131dad48afbf37fb71cf5f3e51d6d3ec650539269f6d782b8f37f7aad'
    capture = json.loads(raw)
    assert len(capture['cases']) == 3
    assert {row['check_id'] for row in capture['cases']} == {'gcp_kms_key_destroy_alert'}
    assert {row['expected_status'] for row in capture['cases']} == {'PASS', 'FAIL', 'UNKNOWN'}
    proof = PACK.parents[1] / 'docs/gcp-review/recheck-20261020/alert-predicate-successors.json'
    assert capture['predicate_successor_sha256'] == hashlib.sha256(proof.read_bytes()).hexdigest()
