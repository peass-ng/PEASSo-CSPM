"""Replay every active K8s predicate, keeping declarations distinct from runtime."""
from copy import deepcopy
from collections import Counter
from functools import lru_cache
import gzip
import hashlib
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.native_only import automated_checks
from peaso.finding_observation import evidence_summary

CHECK_BY_ID={c.id:c for c in automated_checks(CHECKS) if c.provider=='k8s'}
PREDECESSORS = Path(__file__).with_name('fixtures') / 'k8s_public_observation_compatibility_predecessors_20261020.json.gz'
PREDECESSORS_SHA256 = 'df506a1a368d8ceeeaa563ba342eb0f758479bbde885d87c6583c33c6c6175ad'


@lru_cache(maxsize=1)
def preserved_predecessors():
    raw = PREDECESSORS.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PREDECESSORS_SHA256
    data = json.loads(gzip.decompress(raw))
    for row in data['files'].values():
        assert hashlib.sha256(row['source'].encode()).hexdigest() == row['sha256']
    for row in data['native_sources'].values():
        for version in ('original', 'enriched', 'current_at_capture'):
            assert hashlib.sha256(row[version]['source'].encode()).hexdigest() == row[version]['sha256']
    return data


@lru_cache(maxsize=1)
def current_native_cases():
    """Verified test-only native inputs; never mutate global historical CASES."""
    import sys
    from peaso.checks import k8s_annotation_native_source_successor_20261021 as annotation
    from peaso.checks import k8s_kubelet_configmap_source_successor_20261021 as kubelet
    annotation._self_proof()
    annotation._source_proofs()
    kubelet._receipt()
    previous = sys.modules.get(annotation._PRIVATE_NAME)
    current = sys.modules.get(kubelet.PRIVATE_NAME)
    assert previous is not None and current is not None
    annotation_cases = previous._reviewed_inputs()[1]
    kubelet_cases = current.reviewed_inputs()[1]
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


@lru_cache(maxsize=1)
def compatibility_receipt():
    return json.loads((Path(__file__).parents[1] / 'docs/check-review/k8s-public-observation-compatibility-20261020.json').read_text())


# Active controls registered after the frozen 2026-10-20 receipt. The receipt
# stays immutable; each successor is replayed here with its own fixture branches.
SUCCESSOR_BRANCH_STATUSES = {
    'k8s.iam.clusterrole_has_declared_consumers': {'pass': 'PASS', 'fail': 'FAIL'},
    'k8s.iam.clusterrolebinding_subjects_exist': {'pass': 'PASS', 'fail': 'FAIL'},
    'k8s.iam.legacy_serviceaccount_token_recently_used': {'pass': 'PASS', 'fail': 'FAIL'},
    'k8s.iam.role_has_declared_consumers': {'pass': 'PASS', 'fail': 'FAIL'},
    'k8s.iam.rolebinding_subjects_exist': {'pass': 'PASS', 'fail': 'FAIL'},
    'k8s.iam.serviceaccount_has_declared_consumers': {'pass': 'PASS', 'fail': 'FAIL'},
    'k8s.network.endpoints_controller_service_reference_resolves': {'pass': 'PASS', 'fail': 'FAIL'},
    'k8s.network.endpointslice_service_reference_resolves': {'pass': 'PASS', 'fail': 'FAIL'},
    'k8s.network.ingress_service_backends_resolve': {'pass': 'PASS', 'fail': 'FAIL'},
    'k8s.network.networkpolicy_selects_current_pod': {'pass': 'PASS', 'fail': 'FAIL'},
    'k8s.network.service_has_current_backend_declaration': {'pass': 'PASS', 'fail': 'FAIL'},
    'k8s.review.selected_flux_artifact_secret_indicators': {'pass': 'PASS', 'fail': 'FAIL', 'unknown': 'UNKNOWN'},
    'k8s.review.selected_registry_image_high_vulnerabilities': {'pass': 'PASS', 'fail': 'FAIL', 'unknown': 'UNKNOWN'},
    'k8s.review.selected_registry_image_secret_indicators': {'pass': 'PASS', 'fail': 'FAIL', 'unknown': 'UNKNOWN'},
    'k8s.review.selected_text_content.secret_indicators': {'pass': 'PASS', 'fail': 'FAIL', 'unknown': 'UNKNOWN'},
}


def current_receipt():
    receipt = deepcopy(compatibility_receipt())
    assert not set(SUCCESSOR_BRANCH_STATUSES) & set(receipt['active_ids'])
    receipt['active_ids'] = sorted(set(receipt['active_ids']) | set(SUCCESSOR_BRANCH_STATUSES))
    receipt['active_branch_statuses'] = {**receipt['active_branch_statuses'], **SUCCESSOR_BRANCH_STATUSES}
    counts = Counter(receipt['active_status_counts'])
    for states in SUCCESSOR_BRANCH_STATUSES.values():
        counts.update(states.values())
    receipt['active_status_counts'] = dict(counts)
    return receipt


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
    receipt = current_receipt()
    assert set(CHECK_BY_ID) == set(receipt['active_ids'])
    assert len(CHECK_BY_ID) == 938 + len(SUCCESSOR_BRANCH_STATUSES)
    counts=Counter()
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
        counts[finding['status']]+=1
        witnesses.setdefault(finding['check_id'], {})[finding['fixture_state']] = finding['status']
    assert not missing, 'All missing observations: '+repr(missing)
    assert witnesses == receipt['active_branch_statuses']
    assert dict(counts) == receipt['active_status_counts']
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


# Reconstruct the exact approved pre-enrichment bytes without git/network access.
# Hashing ast.dump across Python versions is unsafe: Python3.13 omits empty
# fields by default. Both trees below are parsed/dumped in the SAME interpreter.
@pytest.mark.parametrize("filename,fields,original_source_sha256,added_fragments", [('batch_remaining_k8s.py', ['extend_serviceaccount_token_expiration', 'matching_serviceaccount_binding', 'native_secret_reference', 'rotate_kubelet_server_certificate', 'secrets_store_csi_declared', 'selector_expression_count', 'selector_label_count'], '0f0c92c50a05e92bfd0357767066e4e481c03320c2f582ff10194d8cc25dd578', [', matching_serviceaccount_binding=matched', ', native_secret_reference=True, secrets_store_csi_declared=csi', ", rotate_kubelet_server_certificate=pairs['RotateKubeletServerCertificate']", ', extend_serviceaccount_token_expiration=value', ', selector_label_count=len(labels), selector_expression_count=len(expressions)']), ('compliance_new_sw10.py', ['extend_serviceaccount_token_expiration', 'matching_serviceaccount_binding', 'native_secret_reference', 'rotate_kubelet_server_certificate', 'secrets_store_csi_declared', 'selector_expression_count', 'selector_label_count'], '6dcd76069c450e4d0291229dd3eeff307fe34b7f5c1061cb9a05b028df2fd986', [', matching_serviceaccount_binding=matched', ', native_secret_reference=True, secrets_store_csi_declared=csi', ", rotate_kubelet_server_certificate=pairs['RotateKubeletServerCertificate']", ', extend_serviceaccount_token_expiration=value', ', selector_label_count=len(labels), selector_expression_count=len(expressions)']), ('k8s_ports_cluster.py', ['unrestricted_rule_indexes'], 'c62ae49c74cc9930c2652991d6a9929628175cc97c4938285426791affd7c5ce', [' unrestricted_rule_indexes=[i for i, rule in enumerate(rules) if rule == {}],']), ('compliance_new_k8s_network.py', ['all_source_rules', 'all_source_tcp_remote_admin_rules'], '5afc05fb25ba7ddc1ddd43098dc912c3158ab83b8fde1ce8c6d79a4d3cfce72c', [' all_source_rules=[],', ' all_source_tcp_remote_admin_rules=[],']), ('claude_gcp_k8s_k8s.py', ['literal_credential_env'], '7f589b98b6d488b8ca99cc673381701e91bdac57adf413e0569af12f981f63d2', [', literal_credential_env=[]'])])
def test_native_enrichment_only_adds_explicit_result_evidence(filename,fields,original_source_sha256,added_fragments):
    import ast,hashlib
    from pathlib import Path
    # This historical assertion applies to the exact accepted 91b2c4e bytes,
    # not later native predicate successors. Original hashes remain unchanged.
    record = preserved_predecessors()['native_sources'][filename]
    assert record['original']['revision'] == '787fcfdc93d719559ad679834bbbf32b4eaca6b8'
    assert record['enriched']['revision'] == '91b2c4ed88bf799fb4f11a437f6557c7dd3dcf34'
    candidate=record['enriched']['source']
    original=candidate
    for fragment in added_fragments:
        assert original.count(fragment)==1,(filename,fragment)
        original=original.replace(fragment,'',1)
    # Original byte hashes are from accepted source787fcfd, not a new baseline.
    assert hashlib.sha256(original.encode()).hexdigest()==original_source_sha256
    assert original == record['original']['source']
    tree=ast.parse(candidate)
    for node in ast.walk(tree):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='result' and (filename not in ('compliance_new_k8s_network.py','claude_gcp_k8s_k8s.py') or node.args and isinstance(node.args[0],ast.Constant) and node.args[0].value is False):
            node.keywords=[k for k in node.keywords if k.arg not in fields]
    assert ast.dump(tree)==ast.dump(ast.parse(original))


@pytest.mark.parametrize('filename', ['batch_remaining_k8s.py', 'compliance_new_sw10.py', 'k8s_ports_cluster.py',
                                      'compliance_new_k8s_network.py', 'claude_gcp_k8s_k8s.py'])
def test_current_native_sources_are_separately_bound_from_historical_enrichment(filename):
    record = preserved_predecessors()['native_sources'][filename]
    raw = (Path(__file__).parents[1] / record['path']).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == record['current_at_capture']['sha256']
    assert raw == record['current_at_capture']['source'].encode()
    assert (raw == record['enriched']['source'].encode()) is record['current_is_historical_enrichment']
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
