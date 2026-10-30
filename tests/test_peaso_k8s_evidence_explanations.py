"""Every registered Kubernetes ID is reviewed against actual evaluator output."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.native_only import exclusions
from peaso.checks.k8s_evidence_explanations import (evidence_summary, review_rows, current_review_rows,
    all_review_rows, reviewed_explanation)
from tests.test_peaso_k8s_observed_configuration import (
    cases_for, current_native_cases, preserved_predecessors, compatibility_receipt,
    recorded_observation, SELECTED_SECRET_IDS, AUTHORIZATION_FIXTURE_IDS)

K8S = {c.id: c for c in CHECKS if c.provider == 'k8s'}
# 45112721 made component Unavailable reasons per container, so one malformed
# container no longer hides another container's FAIL. The frozen receipt keeps
# the earlier whole-check reason; this is the exact reviewed later evidence.
KUBELET_UNKNOWN_SUCCESSOR = {
    'historical_evidence_sha256': 'eb2a517018de735a62d31a52d4b67bc2823cd0530423bba3ec452c92342a4e25',
    'historical_evidence': {'reason': 'malformed native authorization mode declaration'},
    'current_evidence': {'containers': ['component'],
                         'reason': 'component applicability/configuration declarations unavailable'},
}
STATES = ('pass', 'fail', 'unknown', 'malformed', 'missing', 'manual', 'not_applicable')


def _supplemental_index(groups, cluster='fixture'):
    from peaso.checks.facts import MemoIndex
    context = {'provider': 'k8s', 'scope': '*', 'created_at': '2026-10-12T00:00:00Z',
               'metadata': {'cluster_id': cluster, 'compliance_policy': {'status': 'collected', 'cluster_id': cluster,
                 'in_scope_service_names': ['edge'], 'required_external_traffic_policy': 'Local', 'approved_clock_skew': 2}}}
    out = {'context': context, 'collections': {}}
    for kind, values in groups.items():
        for value in values:
            value.setdefault('provenance', {'cluster_id': cluster, 'evidence': 'read-only list'})
        out['collections'][kind] = [{'type': kind, 'scope': '*', 'status': 'collected', 'items': values}]
        out[kind] = [{'type': kind, 'scope': '*', 'data': value} for value in values]
    return MemoIndex(out)


def supplemental_cases(cid):
    """Four catalog IDs have dedicated tests rather than global CASES entries."""
    if cid == 'k8s.network.namespace_policy_inventory':
        item = {'metadata': {'name': 'apps'}}
        policy = {'metadata': {'name': 'p', 'namespace': 'apps'}}
        return {'fail': item, 'fail_index': {'collections': {'networkpolicy': [{'scope': '*', 'status': 'empty', 'items': []}]}},
                'manual': item, 'manual_index': {'collections': {'networkpolicy': [{'scope': '*', 'status': 'collected', 'items': [policy]}]}},
                'unknown': item, 'malformed': None}
    if cid == 'k8s_service_external_traffic_policy_matches_required':
        row = {'metadata': {'name': 'edge', 'namespace': 'apps'}, 'spec': {'type': 'LoadBalancer', 'externalTrafficPolicy': 'Local'}}
        bad = deepcopy(row); bad['spec']['externalTrafficPolicy'] = 'Cluster'
        return {'pass': row, 'pass_index': _supplemental_index({'service': [row]}), 'fail': bad, 'fail_index': _supplemental_index({'service': [bad]}),
                'unknown': row, 'malformed': None}
    if cid == 'k8s_cluster_clocks_information_processing_systems_used_by_82e06ff4':
        node = {'metadata': {'name': 'node1'}, 'provenance': {'cluster_id': 'cluster-57', 'evidence': 'read-only list'}}
        clock = {'node_name': 'node1', 'source_operation': 'GET /api/v1/nodes/{name}/proxy/healthz',
                 'date_header': 'Mon, 12 Oct 2026 00:00:00 GMT', 'node_response_verified': True,
                 'trusted_clock_verified': True, 'trusted_utc_at_response': '2026-10-12T00:00:00Z',
                 'provenance': {'cluster_id': 'cluster-57'}}
        good = _supplemental_index({'node': [node], 'node_clock': [clock]}, 'cluster-57')
        bad_clock = deepcopy(clock); bad_clock['date_header'] = 'Mon, 12 Oct 2026 00:00:10 GMT'
        bad = _supplemental_index({'node': [node], 'node_clock': [bad_clock]}, 'cluster-57')
        unknown = _supplemental_index({'node': [node]}, 'cluster-57')
        return {'pass': good['context'], 'pass_index': good, 'fail': bad['context'], 'fail_index': bad,
                'unknown': unknown['context'], 'unknown_index': unknown}
    if cid == 'k8s.cis.configure_image_provenance_using_imagepolicywebhook_admission_controller':
        row = {'kind': 'Pod', 'metadata': {'name': 'api', 'namespace': 'apps', 'uid': 'api-uid'},
               'spec': {'containers': [{'name': 'api', '_component_config': {'component': 'kube-apiserver', 'flags_complete': True,
                 'flags': {'enable-admission-plugins': 'ImagePolicyWebhook', 'disable-admission-plugins': 'Other',
                           'admission-control-config-file': '/etc/admission.yaml'}}}]}}
        file = {'pod_uid': 'api-uid', 'path': '/etc/admission.yaml', 'verification_status': 'verified',
                'plugins': [{'name': 'ImagePolicyWebhook', 'configuration': {'kubeConfigFile': '/etc/webhook.conf'}}]}
        bad_file = deepcopy(file); bad_file['plugins'] = []
        return {'pass': row, 'pass_index': _supplemental_index({'pod': [row], 'admission_configuration_file': [file]}),
                'fail': row, 'fail_index': _supplemental_index({'pod': [row], 'admission_configuration_file': [bad_file]}),
                'unknown': row, 'unknown_index': _supplemental_index({'pod': [row]}), 'malformed': None}
    return None


def reviewed_cases(cid):
    if cid in exclusions():
        return supplemental_cases(cid) or CASES.get(cid)
    return cases_for(cid, K8S[cid])


def observations_for(cid):
    check, cases = K8S[cid], reviewed_cases(cid)
    assert cases, cid
    for state in STATES:
        if state not in cases:
            continue
        status, evidence = check.evaluate(deepcopy(cases[state]), deepcopy(cases.get(state + '_index', cases.get('index', {}))))
        if cid in ('k8s.cis.configure_image_provenance_using_imagepolicywebhook_admission_controller', 'k8s_cluster_clocks_information_processing_systems_used_by_82e06ff4', 'k8s_service_external_traffic_policy_matches_required') and state in ('pass', 'fail'):
            assert status == state.upper(), (cid, state, status, evidence)
        yield state, {'provider': 'k8s', 'check_id': cid, 'status': status, 'evidence': evidence}


def test_every_current_registered_id_has_exact_review_records():
    assert len(K8S) == 1031
    assert len(review_rows()) == 1016
    assert len(current_review_rows()) == 15
    assert set(review_rows()).isdisjoint(current_review_rows())
    assert set(all_review_rows()) == set(K8S)
    assert set(compatibility_receipt()['registered_ids']) == set(review_rows())
    assert review_rows() == json.loads(preserved_predecessors()['files']['peaso/checks/k8s_evidence_explanations.json']['source'])
    for cid, row in review_rows().items():
        if cid.startswith('k8s.review.kubelet_configmap.'):
            assert cid in current_native_cases() and row['renderer'] == 'native_declaration'
        elif cid in ('k8s.review.selected_container_logs.secret_indicators', 'k8s.review.selected_metadata.secret_indicators'):
            expected = ('selected_log_content' if 'selected_container_logs' in cid else 'selected_metadata_content')
            assert row['renderer'] == expected and row.get('limit') is None
            assert row['purpose'].endswith('.') and len(row['purpose']) < 160
            continue
        else:
            assert row['renderer'] in ('native', 'external'), cid
        assert row['purpose'].endswith('.') and row['limit'].endswith('.'), cid
        assert len(row['purpose']) < 160 and len(row['limit']) < 150, cid


@pytest.mark.parametrize('cid', sorted(review_rows()))
def test_every_existing_status_witness_has_short_explanatory_output(cid):
    observed = list(observations_for(cid))
    assert observed
    for state, finding in observed:
        before = deepcopy(finding)
        rendered = evidence_summary(finding)
        summary = recorded_observation(finding, rendered)
        assert isinstance(summary, str) and summary, (cid, state, finding)
        if cid in current_native_cases() or cid in SELECTED_SECRET_IDS:
            expected = compatibility_receipt()['current_native_contracts'][cid][state]
            assert (finding['status'], rendered, summary) == (expected['status'], expected['generic_summary'], expected['recorded_observation'])
            assert hashlib.sha256(json.dumps(finding['evidence'], sort_keys=True).encode()).hexdigest() == expected['evidence_sha256']
            assert '\n' not in summary and len(summary.split()) <= 55
            if rendered is None:
                assert expected['generic_support'] == 'unsupported_canonical_evidence_only'
            else:
                assert expected['generic_support'] == 'supported'
        else:
            assert '\n' not in summary and len(summary) <= 240, (cid, state, summary)
            assert review_rows()[cid]['purpose'] in summary
            assert summary == reviewed_explanation(cid, summary, finding['status'])
        assert finding == before


@pytest.mark.parametrize('cid', sorted(K8S))
def test_empty_or_wrongly_typed_evidence_never_establishes_configuration(cid):
    for bad in ({}, None, False, 42, [], 'unusable'):
        for status in ('PASS', 'FAIL', 'UNKNOWN', 'MANUAL', 'NOT_APPLICABLE'):
            assert evidence_summary({'provider': 'k8s', 'check_id': cid, 'status': status, 'evidence': bad}) is None


def test_digest_pull_acceptance_does_not_claim_always_was_declared():
    cid = 'k8s.ports.cronjob.always_pull'
    _, f = next((state, f) for state, f in observations_for(cid) if f['status'] == 'PASS')
    result = evidence_summary(f)
    assert 'accepted SHA256 digest or the Always' in result
    assert 'declare the Always' not in result


def test_grpcs_is_reported_as_observed_without_claiming_https():
    cid = 'k8s_ingress_backend_https'
    cases = reviewed_cases(cid)
    row = deepcopy(cases['pass'])
    row['metadata']['annotations']['nginx.ingress.kubernetes.io/backend-protocol'] = 'GRPCS'
    status, evidence = K8S[cid].evaluate(row, deepcopy(cases.get('pass_index', cases.get('index', {}))))
    assert status == 'PASS'
    text = evidence_summary({'provider': 'k8s', 'check_id': cid, 'status': status, 'evidence': evidence})
    assert '“GRPCS”' in text
    assert 'declares HTTPS' not in text


def test_wildcard_subresource_pattern_is_not_dropped():
    cid = 'k8s.ports.clusterrole.role_with_wildcards_used'
    status, evidence = K8S[cid].evaluate({'rules': [{'apiGroups': [''], 'resources': ['pods/*'], 'verbs': ['get']}]}, {})
    assert status == 'FAIL'
    assert '“pods/*”' in evidence_summary({'provider': 'k8s', 'check_id': cid, 'status': status, 'evidence': evidence})


def test_explicit_hostport_zero_is_not_reported_as_nonzero():
    cid = 'k8s.ports.cronjob.no_host_ports'
    # This source predicate rejects any declared hostPort, including zero.
    cases = reviewed_cases(cid); row = deepcopy(cases['fail'])
    row['spec']['jobTemplate']['spec']['template']['spec']['containers'][0]['ports'] = [{'containerPort': 8080, 'hostPort': 0}]
    status, evidence = K8S[cid].evaluate(row, {})
    assert status == 'FAIL'
    text = evidence_summary({'provider': 'k8s', 'check_id': cid, 'status': status, 'evidence': evidence})
    assert 'hostPort field' in text and 'nonzero' not in text


def test_implicit_uid_and_partial_capability_drops_are_not_overstated():
    for cid, item, expected in [
        ('k8s.claude.pod.no_root_user', {'spec': {'containers': [{'name': 'app'}]}}, 'explicitly declares UID zero'),
        ('k8s.claude.pod.capabilities_dropped', {'spec': {'containers': [{'name': 'app', 'securityContext': {'capabilities': {'drop': ['NET_RAW']}}}]}}, 'empty drop list'),
    ]:
        status, evidence = K8S[cid].evaluate(item, {})
        assert status == 'PASS'
        text = evidence_summary({'provider': 'k8s', 'check_id': cid, 'status': status, 'evidence': evidence})
        assert expected in text
        assert 'declare a non-root restriction' not in text
        assert 'drop all' not in text.lower()


def test_review_ledger_accounts_for_each_id_and_replays_every_saved_explanation():
    path = Path(__file__).parents[1] / 'docs/evidence-reviews/k8s.json'
    original = preserved_predecessors()['files']['docs/evidence-reviews/k8s.json']['source']
    assert path.read_text() == original
    ledger = json.loads(original)
    assert set(ledger['checks']) == set(review_rows())
    for cid, entry in ledger['checks'].items():
        if cid in current_native_cases() or cid in SELECTED_SECRET_IDS:
            # Exact historical entries remain preserved, including older text
            # and branch schemas. Current native contracts are separate receipts.
            assert cid in compatibility_receipt()['current_native_contracts']
            replay = {state: finding for state, finding in observations_for(cid)}
            current = compatibility_receipt()['current_native_contracts'][cid]
            assert set(replay) == set(current)
            for state, finding in replay.items():
                assert finding['status'] == current[state]['status']
                assert recorded_observation(finding, evidence_summary(finding)) == current[state]['recorded_observation']
            continue
        if cid in AUTHORIZATION_FIXTURE_IDS:
            assert cid in compatibility_receipt()['current_legacy_successor_contracts']
            replay = dict(observations_for(cid))
            current = compatibility_receipt()['current_legacy_successor_contracts'][cid]
            assert set(replay) == set(current)
            for state, finding in replay.items():
                assert finding['status'] == current[state]['status']
                assert evidence_summary(finding) == current[state]['generic_summary']
                recorded = current[state]['evidence_sha256']
                if state == 'unknown' and recorded == KUBELET_UNKNOWN_SUCCESSOR['historical_evidence_sha256']:
                    historical = KUBELET_UNKNOWN_SUCCESSOR['historical_evidence']
                    assert hashlib.sha256(json.dumps(historical, sort_keys=True).encode()).hexdigest() == recorded
                    assert finding['evidence'] == KUBELET_UNKNOWN_SUCCESSOR['current_evidence']
                    continue
                assert hashlib.sha256(json.dumps(finding['evidence'], sort_keys=True).encode()).hexdigest() == recorded
            continue
        assert entry['disposition'] == 'rewritten'
        assert entry['missing_fixtures'] == []
        replay = {state: finding for state, finding in observations_for(cid)}
        assert set(replay) == {b['fixture_state'] for b in entry['branches']}
        for branch in entry['branches']:
            finding = replay[branch['fixture_state']]
            assert branch['observed_status'] == finding['status']
            assert branch['explanation'] == evidence_summary(finding)


def test_unhashable_identifiers_and_reason_payloads_do_not_crash():
    for check_id in ([], {}, 5, None):
        assert evidence_summary({'provider': 'k8s', 'check_id': check_id, 'status': 'FAIL', 'evidence': {'reason': 'unavailable'}}) is None
    cid = 'k8s.cis.configure_image_provenance_using_imagepolicywebhook_admission_controller'
    for reason in ([], {}, True, None):
        assert evidence_summary({'provider': 'k8s', 'check_id': cid, 'status': 'FAIL', 'evidence': {'reason': reason}}) is None


@pytest.mark.parametrize('cid', sorted(review_rows()))
def test_observations_are_sentences_not_raw_field_label_tables(cid):
    import re
    for state, finding in observations_for(cid):
        text = recorded_observation(finding, evidence_summary(finding))
        assert not re.match(r'^(?:Supplied|Imported|Unrestricted)[^.“”]+:\s*(?:[-0-9]|enabled|disabled)', text), (cid, state, text)
        for internal in ('runAsNonRoot=true', 'feature-gate declaration', 'authorization-mode list', 'cipher-suite declaration', 'IPAddressDeny='):
            assert internal not in text, (cid, state, text)


@pytest.mark.parametrize('cid,field,good,bad,good_words,bad_words', [
    ('k8s.ports.configuration.kubelet_disable_anonymous_auth', 'configured', False, True, 'disables anonymous authentication', 'allows unauthenticated requests'),
    ('k8s.ports.configuration.kubelet_disable_read_only_port', 'configured', 0, 10255, 'disables its unauthenticated read-only listener', 'on port 10255'),
    ('k8s.cis.the_seccomp_default_parameter_is_set_to_true', 'configured_seccomp_default', True, False, 'enables default seccomp filtering', 'disables default seccomp filtering'),
])
def test_boolean_and_zero_port_meanings_are_written_as_plain_sentences(cid, field, good, bad, good_words, bad_words):
    for value, expected, status in ((good, good_words, 'PASS'), (bad, bad_words, 'FAIL')):
        text = evidence_summary({'provider': 'k8s', 'check_id': cid, 'status': status, 'evidence': {field: value}})
        assert expected in text
        assert ': 0' not in text and ': 1' not in text
    assert evidence_summary({'provider': 'k8s', 'check_id': cid, 'status': 'FAIL', 'evidence': {}}) is None


def test_unset_automount_never_turns_into_disabled_automount():
    cid = 'k8s.pod.restrict_token_automount'
    status, evidence = K8S[cid].evaluate({'spec': {}}, {})
    assert status == 'UNKNOWN'
    text = evidence_summary({'provider': 'k8s', 'check_id': cid, 'status': status, 'evidence': evidence})
    assert 'disabled' not in text and 'disables' not in text
    status, evidence = K8S[cid].evaluate({'spec': {'automountServiceAccountToken': False}}, {})
    assert status == 'PASS'
    assert 'disables' in evidence_summary({'provider': 'k8s', 'check_id': cid, 'status': status, 'evidence': evidence})


def test_supplied_permission_bits_and_duration_are_explained():
    cid = 'k8s.claude.file_metadata.kubelet_conf_permissions'
    for mode, words in (('0o600', 'allows only the owner to read and write'), ('0o644', 'allows everyone to read and only the owner to write')):
        text = evidence_summary({'provider': 'k8s', 'check_id': cid, 'status': 'FAIL', 'evidence': {'path': '/etc/kubernetes/kubelet.conf', 'mode': mode}})
        assert words in text
    cid = 'k8s.claude.configuration.kubelet_streaming_timeout'
    text = evidence_summary({'provider': 'k8s', 'check_id': cid, 'status': 'PASS', 'evidence': {'streaming_connection_idle_timeout': '4h0m0s'}})
    assert '4 hours' in text and '4h0m0s' not in text


@pytest.mark.parametrize('cid', sorted(SELECTED_SECRET_IDS))
def test_current_selected_secret_saved_public_summary_retains_actual_hit(cid):
    from peaso.secret_findings import deduplicate_secret_findings
    from peaso.finding_observation import evidence_summary as public_summary
    case = reviewed_cases(cid)
    item = deepcopy(case['fail'])
    index = deepcopy(case.get('fail_index', case.get('index', {})))
    status, evidence = K8S[cid].evaluate(item, index)
    assert status == 'FAIL' and evidence['secret_leaks']
    native = {'id': 'current-native-hit', 'provider': 'k8s', 'check_id': cid,
              'resource_id': item['id'], 'scope': index['context']['scope'],
              'status': status, 'evidence': evidence, 'frameworks': []}
    before = deepcopy(native)
    saved, = deduplicate_secret_findings([native])
    saved_before = deepcopy(saved)
    generic = public_summary(saved)
    assert generic is None or isinstance(generic, str) and generic
    assert saved['evidence_summary'] == saved['evidence']['observed']
    assert saved['evidence_summary'].startswith('The same secret was detected in ')
    assert saved['status'] == 'FAIL' and saved['evidence']['secret_leaks']
    assert saved['linked_check_ids'] == [cid]
    assert saved == saved_before and native == before
    # Simulate the saved canonical branch used by the public inspector: a
    # missing generic observation cannot replace the stored per-secret summary.
    assert (generic or saved['evidence_summary'])


@pytest.mark.parametrize('cid', sorted(SELECTED_SECRET_IDS))
def test_selected_clean_partial_inventory_remains_unknown(cid):
    case = reviewed_cases(cid)
    item = deepcopy(case['pass'])
    index = deepcopy(case.get('pass_index', case.get('index', {})))
    own, = index['collections'][K8S[cid].kind]
    own['status'] = 'partial'
    status, evidence = K8S[cid].evaluate(item, index)
    assert status == 'UNKNOWN' and not evidence.get('secret_leaks')
    finding = {'provider': 'k8s', 'check_id': cid, 'status': status, 'evidence': evidence}
    assert 'unbound' in recorded_observation(finding, evidence_summary(finding)).lower() or 'incomplete' in evidence['observed'].lower()


@pytest.mark.parametrize('cid', [
    'k8s.claude.ingress.no_nginx_snippets', 'k8s.claude.ingress.no_nginx_snippet_alias',
    'k8s.claude.ingress.no_nginx_snippet_lua', 'k8s.claude.podsecuritypolicy.default_seccomp_profile',
    'k8s.claude.podsecuritypolicy.security_services_hardening'])
def test_old_annotation_fixtures_never_establish_current_native_absence(cid):
    # Historical annotations_complete test data is not authenticated native proof.
    for branch in ('pass', 'fail'):
        case = CASES[cid]
        status, evidence = K8S[cid].evaluate(deepcopy(case[branch]), deepcopy(case.get(branch + '_index', case.get('index', {}))))
        assert status == 'UNKNOWN'
        finding = {'provider': 'k8s', 'check_id': cid, 'status': status, 'evidence': evidence}
        assert evidence_summary(finding) is None
        assert 'could not be bound' in recorded_observation(finding, None)
    native = current_native_cases()[cid]
    item = deepcopy(native['pass'])
    index = deepcopy(native['pass_index'])
    own, = index['collections'][K8S[cid].kind]
    own['status'] = 'partial'
    assert K8S[cid].evaluate(item, index)[0] == 'UNKNOWN'


def test_current_canonical_evidence_and_saved_secret_summary_reach_actual_frontend_fallback():
    """Run the real pure TS formatter and inspector expression in memory only."""
    import subprocess
    from peaso.secret_findings import deduplicate_secret_findings
    samples = []
    for cid in sorted(set(current_native_cases()) | SELECTED_SECRET_IDS):
        for state, finding in observations_for(cid):
            if state in ('pass', 'fail', 'unknown'):
                samples.append(finding)
    for cid in sorted(SELECTED_SECRET_IDS):
        case = reviewed_cases(cid)
        item, index = deepcopy(case['fail']), deepcopy(case.get('fail_index', case.get('index', {})))
        status, evidence = K8S[cid].evaluate(item, index)
        native = {'id': 'native-hit', 'provider': 'k8s', 'check_id': cid, 'status': status,
                  'evidence': evidence, 'resource_id': item['id'], 'scope': index['context']['scope'], 'frameworks': []}
        saved, = deduplicate_secret_findings([native])
        samples.append(saved)
    script = r'''
const fs = require('node:fs');
const path = require('node:path');
const ts = require(path.join(process.cwd(), 'frontend/node_modules/typescript'));
const base = path.join(process.cwd(), 'frontend/src');
function load(name) {
  if (!['findingExplanation', 'awsReviewedCheckIds'].includes(name)) throw Error('Unexpected import');
  const raw = fs.readFileSync(path.join(base, name + '.ts'), 'utf8');
  const code = ts.transpileModule(raw, {compilerOptions: {module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022}}).outputText;
  const module = {exports: {}};
  new Function('require', 'exports', 'module', code)((request) => {
    if (request !== './awsReviewedCheckIds') throw Error('Unexpected import');
    return load('awsReviewedCheckIds');
  }, module.exports, module);
  return module.exports;
}
const actual = load('findingExplanation').explainFindingEvidence;
const inspector = ts.createSourceFile('Findings.tsx', fs.readFileSync(path.join(base, 'Findings.tsx'), 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
const candidates = [];
function visit(node) {
  if (ts.isVariableDeclaration(node) && node.name.getText(inspector) === 'observation' && node.initializer
      && node.initializer.getText(inspector).includes('observed.evidence_summary')) candidates.push(node.initializer.getText(inspector));
  ts.forEachChild(node, visit);
}
visit(inspector);
if (candidates.length !== 1) throw Error('Inspector observation expression changed');
const inspectorObservation = new Function('observed', 'allowCurrentSummary', 'internetExposure', 'exposure',
  'explainAzureNativeEvidenceObservation', 'explainAzureFindingEvidence', 'explainGcpFindingEvidence', 'explainFindingEvidence',
  'return (' + candidates[0] + ');');
const samples = JSON.parse(fs.readFileSync(0, 'utf8'));
for (const row of samples) {
  const observed = row.evidence.observed;
  if (typeof observed !== 'string' || !observed) throw Error('Missing actual canonical native observation');
  const expected = observed + (row.status === 'UNKNOWN' ? ' The overall assessment remains undetermined.' : '');
  if (actual(row.evidence, row.status, row.check_id) !== expected) throw Error('Canonical evidence fallback changed');
  for (const allow of [true, false]) {
    const result = inspectorObservation(row, allow, false, undefined, () => undefined, () => undefined, () => undefined, actual);
    if (row.evidence_summary && result !== row.evidence_summary) throw Error('Saved canonical secret summary was lost');
    if (allow && !row.evidence_summary && result !== expected) throw Error('Native observed fallback was lost');
  }
}
process.stdout.write(JSON.stringify({cases: samples.length, canonical_and_saved_summary: true}));
'''
    run = subprocess.run(['node', '-e', script], input=json.dumps(samples), text=True, capture_output=True,
                         cwd=Path(__file__).parents[1], timeout=30)
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout) == {'cases': len(samples), 'canonical_and_saved_summary': True}


@pytest.mark.parametrize('cid', sorted(AUTHORIZATION_FIXTURE_IDS))
def test_kubelet_webhook_fixture_is_decisive_and_old_rbac_mode_is_unknown(cid):
    before = deepcopy(CASES[cid])
    for state, expected in (('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')):
        cases = reviewed_cases(cid)
        status, _ = K8S[cid].evaluate(deepcopy(cases[state]), deepcopy(cases.get(state + '_index', cases.get('index', {}))))
        assert status == expected
    # 45112721 changed the registry fixture to the valid kubelet Webhook mode;
    # the old API-server-only RBAC input stays an UNKNOWN witness.
    registry = deepcopy(CASES[cid]['pass'])
    index = deepcopy(CASES[cid].get('pass_index', CASES[cid].get('index', {})))
    assert K8S[cid].evaluate(deepcopy(registry), deepcopy(index))[0] == 'PASS'
    old_mode = json.loads(json.dumps(registry).replace('"authorization-mode": "Webhook"', '"authorization-mode": "RBAC"'))
    assert old_mode != registry
    status, evidence = K8S[cid].evaluate(old_mode, index)
    assert (status, evidence) == ('UNKNOWN', KUBELET_UNKNOWN_SUCCESSOR['current_evidence'])
    assert CASES[cid] == before
