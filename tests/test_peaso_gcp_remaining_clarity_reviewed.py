"""Actual evaluator fixtures and observed summaries for reviewed native GCP checks."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.gcp_remaining_clarity_reviewed import ROWS, description
from peaso.checks.gcp_remaining_finding_summary import evidence_summary
from peaso.checks.gcp_remaining_clarity_reviewed import NATIVE_EXTENSION_REVIEWS as HISTORICAL_EXTENSION_REVIEWS
from peaso.checks.facts import MemoIndex
from tests.gcp_clarity_combined_successor_20261020 import (
    cases_fingerprint, current_extension_reviews, extension_cases)

NATIVE_EXTENSION_REVIEWS = current_extension_reviews(HISTORICAL_EXTENSION_REVIEWS)

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


@pytest.mark.parametrize('cid',sorted(ROWS))
def test_per_id_real_cases_verdicts_and_observed_summary(cid):
    check=CHECK_BY_ID[cid]
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


@pytest.mark.parametrize('cid',sorted(ROWS))
def test_fail_status_alone_and_wrong_shape_never_supply_a_fact(cid):
    for evidence in ({},None,[],{'semantics':'Previous result was FAIL'}):
        assert evidence_summary({'provider':'gcp','check_id':cid,'status':'FAIL','evidence':evidence}) is None


def test_private_source_values_are_not_rendered_as_credentials():
    cid='gcp.htbp.function.secret_env_from_secret_manager'
    observation=evidence_summary({'provider':'gcp','status':'FAIL','check_id':cid,'evidence':{'literal_credential_variables':['DB_PASSWORD'],'value':'never-print-me'}})
    assert observation and 'never-print-me' not in observation


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


@pytest.mark.parametrize('cid',sorted(NATIVE_EXTENSION_REVIEWS))
def test_admitted_extension_cases_evaluate_with_typed_summary(cid):
    from peaso.checks.gcp_evidence_explanations import evidence_summary as natural_summary
    spec=extension_cases(cid, CASES)
    check=CHECK_BY_ID[cid]
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


