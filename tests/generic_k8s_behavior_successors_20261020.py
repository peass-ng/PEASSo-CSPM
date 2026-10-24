"""Finite current native inputs; never rewrite historical CASES or admissions."""
from copy import deepcopy
import gzip
import hashlib
import inspect
import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKLOAD = 'aws.review.workload.selected_command_literal_secret_indicators'
JOB_IMAGE = 'gcp.review.cloudrun_job.declared_image_secret_indicators'
PACKAGE = 'azure.review.function.selected_package_source_secret_indicators'
AUTHORIZATION_IDS = frozenset('k8s.ports.' + kind +
    '.container_argument_kubelet_authorization_mode_no_always_allow'
    for kind in ('cronjob', 'daemonset', 'deployment', 'job', 'pod', 'podtemplate',
                 'replicaset', 'replicationcontroller', 'statefulset'))
AKS_IDS = frozenset({'azure_aks_cluster_7_2_1_6_93c4fab',
                     'azure_aks_cluster_aks_cluster_rbac_enabled_db12524'})
PINS = {
    'peaso/unused_network_gcp.py': 'c400e93b47669dc157cb62be05e4baeef46e1fa429dab70237db74ca21e665db',
    'peaso/checks/claude_gcp_k8s_compute.py': '071adbccfe52668da08440632d9f5d3ef4b74781a8ba8570442b02a7fdc69952',
    'peaso/checks/k8s_ports_components.py': '0b717883a125ed880899da71f58053d6b59756c8f18f0b5ea5b9f4d44fd5538e',
    'peaso/checks/azure_aks_legacy_projection_review_20261020_fixtures.json': '7e4233f962bc14aa19ddeb4cf9f9c0d3d26a78ca0f600dde3600fa372e06e3a6',
    'docs/check-review/aws-workload-commands-current-native-witnesses-20261020.json.gz': 'b7e7e7d00d2aec8dfd2ffe386fa29a2918436de0aac572866a140fc5bc791a10',
    'docs/check-review/gcp-cloudrun-job-image-current-native-witnesses-20261020.json.gz': 'fcefb8902ed785450b974a54bbefd938ed436042b5da2719412f0c3f9b085670',
    'tests/test_aws_workload_command_runtime_20261020.py': 'db1cef420bb43fc4cdc24317c7bc347bfd98571e04f317da20ce21a6b57a4ad5',
    'peaso/checks/k8s_kubelet_configmap_review_20261020.py': '9ea66a3c6a0c48dbfb743508d490d4c7b5de8bb4a32bee0031f39daf48d192a9',
    'peaso/checks/k8s_kubelet_configmap_admission_log_successor_20261020.json': '5999cddf4f03aeaf0a43d4acc722f86147490e1372c388efe8f31890d9075b79',
}


def checked(path):
    raw = (ROOT / path).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PINS[path], path
    return raw


def current_annotation_admission():
    """Use the installed finite successor; historical proof stays unmodified."""
    from peaso.checks import k8s_annotation_native_admission_20261020 as original
    from peaso.checks import k8s_annotation_native_source_successor_20261021 as successor
    successor._self_proof()
    raw, _ = successor._source_proofs()
    successor._current_functions(raw)
    installed = sys.modules.get(successor._PRIVATE_NAME)
    assert isinstance(installed, types.ModuleType)
    assert installed.__file__ == original.__file__
    assert installed._trusted_definition is not original._trusted_definition
    return installed


def current_kubelet_admission():
    from peaso.checks import k8s_kubelet_configmap_source_successor_20261021 as successor
    successor._receipt()
    installed = sys.modules.get(successor.PRIVATE_NAME)
    assert isinstance(installed, types.ModuleType)
    assert installed.proof is current_annotation_admission()
    return installed


def current_cases(check, historical):
    result = deepcopy(historical)
    if check.id == 'gcp.claude.firewall.default_rules_not_open':
        checked('peaso/checks/claude_gcp_k8s_compute.py')
        # The rule's native VPC must belong to the scope used for evaluation.
        # Historical items declared projects/p but omitted that authority.
        for branch in ('pass', 'fail'):
            assert result[branch]['network'] == 'projects/p/global/networks/default'
            result[branch + '_index'] = {'context': {'provider':'gcp','scope':'projects/p'}}
    if check.id in {'gcp.network.http_proxy_forwarding_rule_reference',
                     'gcp.network.https_proxy_forwarding_rule_reference'}:
        checked('peaso/unused_network_gcp.py')
        # An empty local reference set cannot exclude a cross-project consumer.
        # Preserve the historical fixture while testing its current UNKNOWN.
        assert 'unknown' not in result and 'unknown_index' not in result
        result['unknown'] = result.pop('fail')
        result['unknown_index'] = result.pop('fail_index')
    if check.id in AUTHORIZATION_IDS:
        from peaso.checks import k8s_ports_components as ports
        checked('peaso/checks/k8s_ports_components.py')
        # The current native fixture already declares the supported kubelet
        # mode; require that declaration rather than rewriting its evidence.
        _, containers = ports.pod_spec(result['pass'], check.kind)
        flags = containers[0]['_component_config']['flags']
        assert flags['authorization-mode'] == 'Webhook'
    from peaso.checks import k8s_annotation_native_admission_20261020 as annotation
    if check.id in annotation.IDS:
        # This validates the actual current admission, source and native fixture
        # hashes; caller annotations_complete is deliberately not accepted.
        _, native = current_annotation_admission()._reviewed_inputs()
        result.update(deepcopy(native[check.id]))
    if check.id in AKS_IDS:
        native = json.loads(checked(
            'peaso/checks/azure_aks_legacy_projection_review_20261020_fixtures.json'))
        result.update(deepcopy(native[check.id]))
    if check.id == JOB_IMAGE:
        witnesses = json.loads(gzip.decompress(checked(
            'docs/check-review/gcp-cloudrun-job-image-current-native-witnesses-20261020.json.gz')))
        assert witnesses['check_id'] == check.id
        for captured in witnesses['witnesses']:
            branch = captured['status'].lower()
            assert branch in ('pass', 'fail') and branch not in result
            snapshot = captured['snapshot']
            collection, = [c for c in snapshot['collections'] if c['type'] == check.kind]
            item, = collection['items']
            result[branch] = deepcopy(item)
            result[branch + '_index'] = deepcopy({
                'context': {'provider': snapshot['provider'], 'scope': collection['scope'],
                            'metadata': snapshot['metadata']},
                'collections': {check.kind: [collection]},
            })
        assert {'pass', 'fail'} <= result.keys()
    return result


def dependency_state(check_id, index):
    """Compare all facts and the exact opaque owner token, not copied identity."""
    if check_id != PACKAGE:
        return deepcopy(index)
    from peaso import azure_function_package_index_20261020 as owner
    if owner.INDEX_KEY not in index:
        return deepcopy(index)
    admitted = index[owner.INDEX_KEY]
    assert type(admitted) in (owner._Admitted, owner._Assertions)
    return (deepcopy({k: v for k, v in index.items() if k != owner.INDEX_KEY}),
            id(admitted), type(admitted), deepcopy(admitted.snapshot),
            deepcopy(admitted.expected), deepcopy(admitted.scope))


def assert_workload_native_behavior(check, monkeypatch):
    """Real SDK clean/empty branches plus signed actual FAIL, no invented PASS."""
    assert check.id == WORKLOAD
    checked('tests/test_aws_workload_command_runtime_20261020.py')
    from tests import test_aws_workload_command_runtime_20261020 as native
    # Reuse the accepted branch test with its actual offline fixture/cleanup.
    # The fixture denies network, credentials and unbound sessions; Stubber and
    # the real offline scanners supply only the reviewed native capture path.
    with monkeypatch.context() as scoped:
        fixture = native.offline.__wrapped__(scoped)
        next(fixture)
        try:
            for empty in (False, True):
                native.test_native_clean_and_explicit_empty_complete(scoped, empty)
        finally:
            next(fixture, None)
    witness = json.loads(gzip.decompress(checked(
        'docs/check-review/aws-workload-commands-current-native-witnesses-20261020.json.gz')))
    assert witness['check_id'] == check.id and witness['witnesses']
    from peaso.engine import evaluate_snapshot
    for captured in witness['witnesses']:
        snapshot = deepcopy(captured['snapshot'])
        before = deepcopy(snapshot)
        actual = evaluate_snapshot(snapshot, checks=[check.id])['findings']
        assert actual and all(row['status'] == captured['status'] == 'FAIL' for row in actual)
        assert actual == captured['findings']
        assert snapshot == before


def assert_kubelet_empty_contract(check, finding):
    """The exact eight signed declarations have an explicit UNKNOWN callback."""
    from peaso.checks import k8s_kubelet_configmap_admission_20261020 as admission
    from peaso.checks import k8s_kubelet_configmap_review_20261020 as candidate
    assert check.id in admission.IDS and len(admission.IDS) == 8
    checked('peaso/checks/k8s_kubelet_configmap_review_20261020.py')
    checked('peaso/checks/k8s_kubelet_configmap_admission_log_successor_20261020.json')
    current_kubelet_admission().reviewed_inputs()  # Proves the installed source-aware callback lineage.
    assert getattr(check.evaluate, admission.MARK) == check.id
    assert inspect.unwrap(check.evaluate).evaluate_empty_inventory is candidate.evaluate_empty
    assert finding['status'] == 'UNKNOWN'
    assert finding['evidence']['observed'] == (
        'No matching kubelet-config ConfigMap declaration was collected in this scope. '
        'Node configuration was not assessed.')
