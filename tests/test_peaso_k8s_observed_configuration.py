"""Replay every active K8s predicate, keeping declarations distinct from runtime."""
from copy import deepcopy
from functools import lru_cache
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.native_only import automated_checks
from peaso.finding_observation import evidence_summary

CHECK_BY_ID={c.id:c for c in automated_checks(CHECKS) if c.provider=='k8s'}


@lru_cache(maxsize=1)
def current_native_cases():
    """Current native annotation and kubelet inputs; never mutate global historical CASES."""
    import json
    from pathlib import Path
    from peaso.checks import k8s_kubelet_configmap_admission_20261020 as kubelet
    from tests.generic_k8s_behavior_successors_20261020 import annotation_native_cases
    annotation_cases = annotation_native_cases()
    kubelet_cases = json.loads((Path(kubelet.__file__).with_name(kubelet.CASES_FILE)).read_text())
    assert set(annotation_cases).isdisjoint(kubelet_cases)
    return {**annotation_cases, **kubelet_cases}


SELECTED_SECRET_IDS = {
    'k8s.review.selected_flux_artifact_secret_indicators',
    'k8s.review.selected_container_logs.secret_indicators',
    'k8s.review.selected_literals.secret_indicators',
    'k8s.review.selected_metadata.secret_indicators',
}
AUTHORIZATION_FIXTURE_IDS = {
    'k8s.ports.' + kind + '.container_argument_kubelet_authorization_mode_no_always_allow'
    for kind in ('cronjob', 'daemonset', 'deployment', 'job', 'pod', 'podtemplate',
                 'replicaset', 'replicationcontroller', 'statefulset')
}


def assert_observation_lines(text):
    """Observed evidence is one legacy sentence or AGENTS.md's 3-5 connected lines."""
    lines = text.split('\n')
    assert len(lines) == 1 or 3 <= len(lines) <= 5, text
    assert all(line.strip() for line in lines) and len(text) < 600, text


def recorded_observation(finding, summary):
    """Test accounting only: explicitly distinguish saved evidence from rendering.

    This does not add a public formatter fallback. For admitted new contracts,
    the actual evaluator's canonical text remains in the technical evidence.
    """
    if summary is not None:
        return summary
    cid, status, evidence = finding['check_id'], finding['status'], finding['evidence']
    allowed = SELECTED_SECRET_IDS | {cid for cid in current_native_cases() if cid.startswith('k8s.claude.')}
    assert cid in allowed, finding
    observed = evidence.get('observed')
    assert isinstance(observed, str) and observed
    assert_observation_lines(observed)
    if status == 'UNKNOWN':
        assert any(word in observed.lower() for word in ('unbound', 'not be bound', 'unavailable', 'incomplete'))
    return observed

# Eleven small supplemental fixtures already accepted by the workload review;
# all other cases use the existing registry fixture authority without copies.
SUPPLEMENTAL_IDS = {
    "k8s.rbac.no_wildcards", "k8s.rbac.role_no_wildcards",
    "k8s.rbac.review_broad_subjects", "k8s.rbac.review_namespaced_subjects",
    "k8s.pod.no_privileged_containers", "k8s.pod.no_host_namespaces",
    "k8s.service.review_public_type",
    "k8s_ingress_ingress_has_any_associated_ingress_93579100f9",
    "k8s_networkpolicy_has_ingress_rules",
    "k8s_networkpolicy_network_policy_associated_podselectors_that_92dbc93b4c",
    "k8s_pod_secret_pod_rule_non_compliant_fcdc38e543",
}
def cases_for(check_id,check):
    if check_id in current_native_cases():
        return current_native_cases()[check_id]
    if check_id in AUTHORIZATION_FIXTURE_IDS:
        # Kubelet accepts Webhook, not the historical API-server-only RBAC
        # enum. Keep that exact old input as an UNKNOWN witness; never mutate
        # CASES or claim that a malformed mode establishes authorization.
        cases = deepcopy(CASES[check_id])
        cases['unknown'] = deepcopy(cases['pass'])
        cases['unknown_index'] = deepcopy(cases.get('pass_index', cases.get('index', {})))
        changes = []
        def replace_mode(value, expected, replacement):
            if isinstance(value, dict):
                config = value.get('_component_config')
                if isinstance(config, dict) and config.get('component') == 'kubelet':
                    assert config['flags_complete'] is True and config['flags']['authorization-mode'] == expected
                    config['flags']['authorization-mode'] = replacement
                    changes.append(True)
                for child in value.values():
                    replace_mode(child, expected, replacement)
            elif isinstance(value, list):
                for child in value:
                    replace_mode(child, expected, replacement)
        # Older saved fixtures used RBAC as a malformed kubelet mode; the
        # current native fixture already uses Webhook. Keep one valid PASS and
        # one unchanged historical malformed UNKNOWN in either case.
        def modes(value):
            if isinstance(value, dict):
                config = value.get('_component_config')
                found = ([config['flags']['authorization-mode']] if isinstance(config, dict)
                    and config.get('component') == 'kubelet' else [])
                return found + [mode for child in value.values() for mode in modes(child)]
            if isinstance(value, list):
                return [mode for child in value for mode in modes(child)]
            return []
        mode, = modes(cases['pass'])
        assert mode in ('RBAC', 'Webhook')
        if mode == 'RBAC':
            replace_mode(cases['pass'], 'RBAC', 'Webhook')
        else:
            replace_mode(cases['unknown'], 'Webhook', 'RBAC')
        assert changes == [True]
        return cases
    cases = None if check_id in SUPPLEMENTAL_IDS else CASES.get(check_id)
    if cases is None:
        if check_id in ("k8s.rbac.no_wildcards", "k8s.rbac.role_no_wildcards"):
            cases = {"pass": {"rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]},
                     "fail": {"rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["*"]}]}}
        elif check_id in ("k8s.rbac.review_broad_subjects", "k8s.rbac.review_namespaced_subjects"):
            cases = {"pass": {"roleRef": {"name": "view"}, "subjects": [{"kind": "User", "name": "alice"}]},
                     "fail": {"roleRef": {"name": "view"}, "subjects": [{"kind": "Group", "name": "system:authenticated"}]}}
        elif check_id == "k8s.pod.no_privileged_containers":
            cases = {"pass": {"spec": {"containers": [{"name": "app", "securityContext": {"privileged": False}}]}},
                     "fail": {"spec": {"containers": [{"name": "app", "securityContext": {"privileged": True}}]}}}
        elif check_id == "k8s.pod.no_host_namespaces":
            cases = {"pass": {"spec": {"hostNetwork": False}}, "fail": {"spec": {"hostNetwork": True}}}
        elif check_id == "k8s.service.review_public_type":
            cases = {"pass": {"spec": {"type": "ClusterIP"}}, "fail": {"spec": {"type": "NodePort"}}}
        elif check_id in {"k8s_ingress_ingress_has_any_associated_ingress_93579100f9",
                          "k8s_networkpolicy_has_ingress_rules",
                          "k8s_networkpolicy_network_policy_associated_podselectors_that_92dbc93b4c",
                          "k8s_pod_secret_pod_rule_non_compliant_fcdc38e543"}:
            from peaso.collectors.k8s import _native
            good_spec, bad_spec = ({"rules": [{}]}, {"rules": []}) if check.kind == "ingress" else (
                ({"imagePullSecrets": [{"name": "registry"}], "containers": [{"name": "app"}]},
                 {"imagePullSecrets": [], "containers": [{"name": "app"}]}) if check.kind == "pod" else
                ({"podSelector": {"matchLabels": {"app": "web"}}}, {"podSelector": {}}) if "podselectors" in check_id else
                ({"ingress": [{}]}, {"ingress": []}))
            cases = {}
            for branch, spec in [("pass", good_spec), ("fail", bad_spec)]:
                row = _native({"kind": {"pod": "Pod", "networkpolicy": "NetworkPolicy", "ingress": "Ingress"}[check.kind], "metadata": {"name": "target", "uid": "target-uid", "namespace": "apps"}, "spec": spec}, check.kind, "fixture", "*", True)
                index = {"context": {"provider": "k8s", "scope": "*", "metadata": {"cluster_id": "fixture"}},
                         "collections": {check.kind: [{"type": check.kind, "scope": "*", "status": "collected", "items": [row]}]},
                         check.kind: [{"type": check.kind, "scope": "*", "provider": "k8s", "data": row}]}
                cases[branch], cases[branch + "_index"] = row, index
        else:
            pytest.fail("Missing reviewed actual predicate fixture: " + check_id)
    return cases


@pytest.fixture(scope="module")
def actual_observations():
    rows=[]
    for cid,check in CHECK_BY_ID.items():
        cases=cases_for(cid,check)
        for branch in ('pass','fail','unknown','malformed'):
            if branch not in cases:continue
            status,evidence=check.evaluate(deepcopy(cases[branch]),deepcopy(cases.get(branch+'_index',cases.get('index',{}))))
            rows.append({'provider':'k8s','check_id':cid,'status':status,'evidence':evidence,'fixture_state':branch})
    return rows


def test_every_current_active_control_has_accounted_actual_observations(actual_observations):
    missing=[]
    witnesses = {}
    for finding in actual_observations:
        before=deepcopy(finding)
        rendered=evidence_summary(finding)
        summary=recorded_observation(finding, rendered)
        if not isinstance(summary,str) or not summary:
            missing.append(finding)
        else:
            assert_observation_lines(summary)
        assert finding==before
        witnesses.setdefault(finding['check_id'], {})[finding['fixture_state']] = finding['status']
    assert not missing, 'All missing observations: '+repr(missing)
    assert set(witnesses) == set(CHECK_BY_ID)
    for cid, states in witnesses.items():
        assert states.get('fail') == 'FAIL', (cid, states)
        if 'pass' in states:
            assert states['pass'] == 'PASS', (cid, states)
        else:
            assert cid == 'k8s.cis.avoid_use_of_system_masters_group'
            assert set(states) == {'fail', 'unknown', 'malformed'}


@pytest.mark.parametrize('cid',sorted(CHECK_BY_ID))
def test_empty_and_badly_shaped_payloads_never_supply_facts(cid):
    for status in ('PASS','FAIL','UNKNOWN'):
        assert evidence_summary({'provider':'k8s','check_id':cid,'status':status,'evidence':{}}) is None
    for bad in (None,False,0,'broken',[],[{}]):
        assert evidence_summary({'provider':'k8s','check_id':cid,'status':'FAIL','evidence':bad}) is None


def test_every_present_field_rejects_malformed_containers_without_exceptions(actual_observations):
    for finding in actual_observations:
        if finding['status'] not in ('PASS','FAIL'):continue
        malformed={**finding,'evidence':{key:([None] if isinstance(value,dict) else {}) for key,value in finding['evidence'].items()}}
        assert evidence_summary(malformed) is None, malformed


def test_opposite_status_cannot_invent_opposite_configuration(actual_observations):
    # An observation may remain factual with either status (e.g. a recorded UID),
    # but it must not turn a positive witness into a different negative fact.
    allowed={'k8s.claude.podsecuritypolicy.security_services_hardening'}
    for finding in actual_observations:
        if finding['status'] not in ('PASS','FAIL'):continue
        other={**finding,'status':'FAIL' if finding['status']=='PASS' else 'PASS'}
        summary=evidence_summary(other)
        assert summary is None or summary==evidence_summary(finding) or finding['check_id'] in allowed,(finding,summary)


@pytest.mark.parametrize('status,rule,observation', [
    ('FAIL', 'RunAsAny', 'The legacy Pod security policy allows any SELinux label.'),
    ('PASS', 'MustRunAs', 'The legacy Pod security policy requires configured SELinux labels.'),
])
def test_psp_selinux_does_not_infer_absent_apparmor_or_seccomp(status,rule,observation):
    cid='k8s.claude.podsecuritypolicy.security_services_hardening'
    finding={'provider':'k8s','check_id':cid,'status':status,'evidence':{'selinux_rule':rule}}
    before=deepcopy(finding)
    summary=evidence_summary(finding)
    assert summary and summary.startswith(observation)
    assert 'AppArmor' not in summary and 'seccomp' not in summary
    assert finding==before


def test_secret_content_is_never_formatted(actual_observations):
    marker='UNIQUE-PRIVATE-SECRET-VALUE-DO-NOT-RENDER'
    for f in actual_observations:
        if 'secret' not in f['check_id']:continue
        changed={**f,'evidence':{**f['evidence'],'secret_value':marker,'private_key':marker}}
        assert marker not in (evidence_summary(changed) or '')


    # This is a source identity assertion. Current native behavior is replayed
    # separately above; no current source is labeled evidence-only enrichment.


def test_real_incomplete_ingress_inventory_has_specific_unknown_observation():
    cid='k8s_ingress_ingress_has_any_associated_ingress_93579100f9'
    check=CHECK_BY_ID[cid];case=cases_for(cid,check)
    item=deepcopy(case['pass']);index=deepcopy(case.get('pass_index',case.get('index',{})))
    index['collections']['ingress'][0]['status']='partial'
    status,evidence=check.evaluate(item,index)
    assert status=='UNKNOWN'
    assert evidence=={'reason':'incomplete or foreign-scope ingress inventory'}
    finding={'provider':'k8s','check_id':cid,'status':status,'evidence':evidence}
    before=deepcopy(finding)
    assert evidence_summary(finding).startswith('The ingress inventory is incomplete or belongs to another scope.')
    assert finding==before


def test_omitted_pull_secret_field_is_unknown_without_full_native_provenance():
    cid='k8s_pod_secret_pod_rule_non_compliant_fcdc38e543'
    check=CHECK_BY_ID[cid];case=cases_for(cid,check)
    item=deepcopy(case['pass']);index=deepcopy(case.get('pass_index',case.get('index',{})))
    item['spec'].pop('imagePullSecrets')
    item['provenance']['evidence']='partial'
    index['collections']['pod'][0]['items']=[item]
    index['pod'][0]['data']=item
    status,evidence=check.evaluate(item,index)
    assert status=='UNKNOWN'
    assert evidence=={'reason':'omitted field without full native representation: imagePullSecrets'}
    finding={'provider':'k8s','check_id':cid,'status':status,'evidence':evidence}
    before=deepcopy(finding)
    assert evidence_summary(finding).startswith('The Pod record omits image-pull Secret references and is not marked as a complete native record.')
    assert finding==before
