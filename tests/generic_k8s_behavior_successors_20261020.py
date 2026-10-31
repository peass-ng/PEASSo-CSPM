"""Finite current native inputs; never rewrite historical CASES or admissions."""
from copy import deepcopy
from functools import lru_cache
import gzip
import inspect
import json
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
NATIVE_ANNOTATION_CASES = 'tests/fixtures/k8s_annotation_native_current_fixtures_20261020.json'


def checked(path):
    return (ROOT / path).read_bytes()


@lru_cache(maxsize=1)
def annotation_native_cases():
    """Current native-field annotation fixtures captured from the real producer."""
    return json.loads(checked(NATIVE_ANNOTATION_CASES))


def current_cases(check, historical):
    result = deepcopy(historical)
    if check.id == 'gcp.claude.firewall.default_rules_not_open':
        # The rule's native VPC must belong to the scope used for evaluation.
        # Historical items declared projects/p but omitted that authority.
        for branch in ('pass', 'fail'):
            assert result[branch]['network'] == 'projects/p/global/networks/default'
            result[branch + '_index'] = {'context': {'provider':'gcp','scope':'projects/p'}}
    if check.id in {'gcp.network.http_proxy_forwarding_rule_reference',
                     'gcp.network.https_proxy_forwarding_rule_reference'}:
        # An empty local reference set cannot exclude a cross-project consumer.
        # Preserve the historical fixture while testing its current UNKNOWN.
        assert 'unknown' not in result and 'unknown_index' not in result
        result['unknown'] = result.pop('fail')
        result['unknown_index'] = result.pop('fail_index')
    if check.id in AUTHORIZATION_IDS:
        from peaso.checks import k8s_ports_components as ports
        # The current native fixture already declares the supported kubelet
        # mode; require that declaration rather than rewriting its evidence.
        _, containers = ports.pod_spec(result['pass'], check.kind)
        flags = containers[0]['_component_config']['flags']
        assert flags['authorization-mode'] == 'Webhook'
    from peaso.checks import k8s_annotation_native_admission_20261020 as annotation
    if check.id in annotation.IDS:
        # Native-field successors read the producer's annotation fields;
        # caller annotations_complete is deliberately not accepted.
        result.update(deepcopy(annotation_native_cases()[check.id]))
    if check.id in AKS_IDS:
        native = json.loads(checked(
            'peaso/checks/azure_aks_legacy_projection_review_20261020_fixtures.json'))
        result.update(deepcopy(native[check.id]))
    if check.id == JOB_IMAGE:
        witnesses = json.loads(gzip.decompress(checked(
            'tests/fixtures/native_witnesses/gcp-cloudrun-job-image-current-native-witnesses-20261020.json.gz')))
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
        'tests/fixtures/native_witnesses/aws-workload-commands-current-native-witnesses-20261020.json.gz')))
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
    assert getattr(check.evaluate, admission.MARK) == check.id
    assert inspect.unwrap(check.evaluate).evaluate_empty_inventory is candidate.evaluate_empty
    assert finding['status'] == 'UNKNOWN'
    assert finding['evidence']['observed'] == (
        'No matching kubelet-config ConfigMap declaration was collected in this scope. '
        'Node configuration was not assessed.')
