"""Isolated signed GCP sw52 predicate tests; run with --noconftest."""
from __future__ import annotations

import pytest

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_sw52 as sw52
from peaso.checks import CHECKS, evaluate_check

SCOPE = 'projects/demo'
META = {'status': 'collected', 'scope': SCOPE}

def snapshot(rows, **policy):
    return {'context': {'provider': 'gcp', 'scope': SCOPE,
                        'metadata': {'sw52': {**META, **policy}}},
            'collections': {kind: [{'type': kind, 'scope': SCOPE,
                                     'status': 'collected' if values else 'empty',
                                     'items': values}]
                            for kind, values in rows.items()},
            **{kind: [{'type': kind, 'scope': SCOPE, 'data': value}
                      for value in values] for kind, values in rows.items()}}

def case(check_id):
    u = {'id':'u1','primaryEmail':'root@example.com','suspended':False,
         'recoveryEmail':'rescue@example.com','_representation':'full',
         'identityProvider':'workspace','inDomain':True,'isEnrolledIn2Sv':True}
    role = {'roleId':'r1','isSuperAdminRole':True}
    assignment = {'roleAssignmentId':'a1','roleId':'r1','assignedTo':'u1'}
    group = {'id':'g1','email':'rescue@example.com'}
    members = [{'groupId':'g1','email':f'p{i}@example.com','status':'ACTIVE'} for i in (1,2)]
    iam = {'name':SCOPE,'bindings':[{'role':'roles/viewer','members':['user:root@example.com']}]}
    if check_id == 'gcp.identity.non_service_account_mfa':
        return u, {'workspace_user':[u], 'iam_policy':[iam]}, {}, lambda r: r.update(isEnrolledIn2Sv=False), None
    if check_id == 'gcp.identity.super_admin_recovery_group':
        return u, {'workspace_user':[u], 'workspace_role':[role], 'workspace_role_assignment':[assignment],
                   'group':[group], 'group_membership':members}, {}, lambda r: r.update(recoveryEmail='missing@example.com'), lambda r: r.update(suspended=True)
    if check_id == 'gcp.identity.super_admin_separation':
        rows_roles = [role]
        return (assignment, {'workspace_role_assignment':[assignment], 'workspace_role':rows_roles, 'workspace_user':[u],
                            'iam_policy':[iam], 'group_membership':[]},
               {'iam_policy_levels':['project','folder','organization'], 'iam_policy_resource_names':[SCOPE]},
               lambda r: iam['bindings'].append({'role':'roles/owner','members':['user:root@example.com']}),
               lambda r: (rows_roles.append({'roleId':'r2','isSuperAdminRole':False}), r.update(roleId='r2')))
    if check_id == 'gcp.orgpolicy.central_constraints':
        row={'constraint':'compute.requireOsLogin','spec':{'rules':[{'enforce':True}]}}
        return ({'scope':SCOPE}, {'org_policy_effective':[row]}, {'required_constraints':{'compute.requireOsLogin':{'type':'boolean'}}},
               lambda r:row['spec']['rules'][0].update(enforce=False), None)
    if check_id == 'gcp.network.private_service_connect_google_apis':
        rule={'name':'psc','network':'n1','target':'all-apis','IPAddress':'10.0.0.1'}
        dns={'network':'n1','name':'private.googleapis.com.','type':'A','rrdatas':['10.0.0.1']}
        return ({'scope':SCOPE}, {'forwarding_rule':[rule], 'dns_record':[dns]}, {'required_vpcs':['n1'], 'required_google_api_hostnames':['private.googleapis.com']},
               lambda r:rule.update(target='other'), None)
    if check_id == 'gcp_cloud_armor_waf_enabled':
        row={'selfLink':'p1','rules':[{'action':'deny','match':{'expr':{'expression':'evaluatePreconfiguredWaf("sqli")'}}}]}
        backend={'name':'b1','securityPolicy':'p1','internetFacing':True}
        return row, {'security_policy':[row], 'backend_service':[backend]}, {}, lambda r:r['rules'].clear(), lambda r:backend.update(internetFacing=False)
    if check_id == 'gcp_cloudbuild_private_pool':
        row={'name':'p1','state':'RUNNING','privatePoolV1Config':{'networkConfig':{'peeredNetwork':'net1'}}}
        return (row, {'worker_pool':[row]}, {'approved_worker_networks':['net1']},
               lambda r:r['privatePoolV1Config']['networkConfig'].update(peeredNetwork='net2'), lambda r:r.update(state='DELETED'))
    if check_id == 'gcp_source_repo_access_restricted':
        row={'name':'r1','iamPolicy':{'bindings':[{'role':'roles/source.reader','members':['user:dev@example.com']}]}}
        return (row, {'source_repository':[row]}, {'approved_developers':['user:dev@example.com']},
               lambda r:r['iamPolicy']['bindings'][0].update(members=['allUsers']), None)
    if check_id == 'gcp_c5_secret_access':
        row={'name':'projects/demo/secrets/cred','iamPolicy':{'bindings':[{'role':'roles/secretmanager.secretAccessor','members':['user:dev@example.com']}]}}
        return (row, {'secret':[row], 'iam_policy':[{'name':SCOPE,'bindings':[]}]},
               {'credential_secrets':[row['name']], 'approved_secret_readers':['user:dev@example.com'],
                'complete_iam_policy_levels':['project','folder','organization'],
                'iam_policy_resource_names':[SCOPE]},
               lambda r:r['iamPolicy']['bindings'][0].update(members=['allUsers']), None)
    if check_id == 'gcp_c5_sbom':
        row={'name':'repo1'}
        image={'repository':'repo1','digest':'sha256:abc','uri':'uri@sha256:abc'}
        occurrence={'resourceUri':'uri@sha256:abc','kind':'SBOM_REFERENCE','noteName':'note1'}
        deployed={'repository':'repo1','digest':'sha256:abc'}
        return (row, {'artifact_repository':[row], 'artifact_image':[image], 'sbom_occurrence':[occurrence], 'deployed_image':[deployed]}, {},
               lambda r:occurrence.update(kind='OTHER'), None)
    if check_id == 'gcp_c5_log_event_fields':
        row={'timestamp':'2026-01-01T00:00:00Z','eventClass':'authenticated_audit',
             'protoPayload':{'methodName':'read','authenticationInfo':{'principalEmail':'user@example.com'}}}
        return row, {'log_entry':[row]}, {}, lambda r:r.update(timestamp='invalid'), None
    if check_id == 'gcp_c5_security_event_route':
        row={'name':'alert1','enabled':True,'conditions':[{'conditionThreshold':{'filter':'metric.type="logging.googleapis.com/user/sec"'}}],
             'notificationChannels':['channel1']}
        return ({'scope':SCOPE}, {'monitoring_alert_policy':[row], 'logging_metric':[{'name':'projects/demo/metrics/sec'}],
                     'monitoring_notification_channel':[{'name':'channel1','enabled':True}]},
               {'approved_security_event_metrics':['projects/demo/metrics/sec']}, lambda r:row.update(enabled=False), None)
    if check_id == 'gcp_lb_server_header_rewrite':
        action={'responseHeadersToAdd':[{'headerName':'Server','headerValue':'lb','replace':True}]}
        row={'name':'map1','internetFacing':True,'routeCoverageComplete':True,
             'effectiveRoutes':[{'routeId':'default', **action}]}
        return row, {'url_map':[row]}, {}, lambda r:action['responseHeadersToAdd'][0].update(replace=False), lambda r:r.update(internetFacing=False)
    if check_id == 'gcp_pci_url_map_9ed56c323a05':
        row={'selfLink':'map1','routeCoverageComplete':True,'defaultUrlRedirect':{'httpsRedirect':True},'pathMatchers':[]}
        proxy={'proxyType':'HTTP','selfLink':'proxy1','urlMap':'map1'}
        frontend={'target':'proxy1'}
        return (row, {'url_map':[row], 'target_proxy':[proxy], 'forwarding_rule':[frontend]}, {},
               lambda r:r['defaultUrlRedirect'].update(httpsRedirect=False), lambda r:frontend.update(target='other'))
    raise AssertionError(check_id)

@pytest.mark.parametrize('check_id', list(sw52.SPECS))
def test_pass_fail_unknown_and_not_applicable(check_id):
    row, rows, policy, fail, na = case(check_id)
    good = snapshot(rows, **policy)
    assert evaluate_check(check_id, row, good)[0] == 'PASS'
    fail(row)
    assert evaluate_check(check_id, row, snapshot(rows, **policy))[0] == 'FAIL'
    row, rows, policy, fail, na = case(check_id)
    incomplete = snapshot(rows, **policy)
    first = next(iter(rows))
    incomplete['collections'][first][0]['status'] = 'partial'
    assert evaluate_check(check_id, row, incomplete)[0] == 'UNKNOWN'
    missing = snapshot(rows, **policy)
    missing['collections'].pop(first)
    missing.pop(first)
    assert evaluate_check(check_id, row, missing)[0] == 'UNKNOWN'
    assert evaluate_check(check_id, {'_coverage': 'bad'}, snapshot(rows, **policy))[0] == 'UNKNOWN'
    foreign = snapshot(rows, **policy)
    foreign['collections'][first][0]['scope'] = 'projects/foreign'
    assert evaluate_check(check_id, row, foreign)[0] == 'UNKNOWN'
    if na:
        na(row)
        assert evaluate_check(check_id, row, snapshot(rows, **policy))[0] == 'NOT_APPLICABLE'


def test_complete_empty_scope_inventories_are_not_silently_safe():
    item, rows, policy, *_ = case('gcp.network.private_service_connect_google_apis')
    rows['forwarding_rule'] = []
    assert evaluate_check('gcp.network.private_service_connect_google_apis', item, snapshot(rows, **policy))[0] == 'FAIL'
    item, rows, policy, *_ = case('gcp_c5_security_event_route')
    rows['monitoring_alert_policy'] = []
    assert evaluate_check('gcp_c5_security_event_route', item, snapshot(rows, **policy))[0] == 'FAIL'
    item, rows, policy, *_ = case('gcp.orgpolicy.central_constraints')
    rows['org_policy_effective'] = []
    assert evaluate_check('gcp.orgpolicy.central_constraints', item, snapshot(rows, **policy))[0] == 'UNKNOWN'


def test_absent_route_actions_fail_only_with_complete_coverage():
    item, rows, policy, *_ = case('gcp_lb_server_header_rewrite')
    item['effectiveRoutes'][0].pop('responseHeadersToAdd')
    assert evaluate_check('gcp_lb_server_header_rewrite', item, snapshot(rows, **policy))[0] == 'FAIL'
    item['routeCoverageComplete'] = False
    assert evaluate_check('gcp_lb_server_header_rewrite', item, snapshot(rows, **policy))[0] == 'UNKNOWN'
    item, rows, policy, *_ = case('gcp_pci_url_map_9ed56c323a05')
    item.pop('defaultUrlRedirect')
    assert evaluate_check('gcp_pci_url_map_9ed56c323a05', item, snapshot(rows, **policy))[0] == 'FAIL'
    item['routeCoverageComplete'] = False
    assert evaluate_check('gcp_pci_url_map_9ed56c323a05', item, snapshot(rows, **policy))[0] == 'UNKNOWN'


def test_missing_signed_inputs_stay_unknown():
    for check_id in ('gcp_cloudbuild_private_pool', 'gcp_source_repo_access_restricted',
                     'gcp_c5_secret_access', 'gcp_c5_security_event_route'):
        item, rows, policy, *_ = case(check_id)
        facts = snapshot(rows, **policy)
        facts['context']['metadata'].pop('sw52')
        assert evaluate_check(check_id, item, facts)[0] == 'UNKNOWN'
    item, rows, policy, *_ = case('gcp.identity.super_admin_recovery_group')
    item.pop('recoveryEmail')
    assert evaluate_check('gcp.identity.super_admin_recovery_group', item, snapshot(rows, **policy))[0] == 'FAIL'
    item.pop('_representation')
    assert evaluate_check('gcp.identity.super_admin_recovery_group', item, snapshot(rows, **policy))[0] == 'UNKNOWN'
