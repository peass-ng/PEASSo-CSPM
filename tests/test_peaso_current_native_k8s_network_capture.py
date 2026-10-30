"""Current native local-kind regression; never substitutes directive13/47fb capture.

Collected from one nonce-owned local cluster using list-only ServiceAccount.
The cluster was deleted after capture. No live cluster/network is needed here.
"""
import json
from pathlib import Path

from peaso.analysis.common import analysis_context
from peaso.analysis.internet_exposure import annotate_network
from peaso.analysis.network import build_network
from peaso.engine import evaluate_snapshot
from peaso.snapshot import resources, validate

CLUSTER = 'kind-owned:peaso-v27-434ea956da40c754774b'
NAMESPACE = 'peaso-net-434ea956da40c754774b'
CID = 'k8s_service_service_uses_ftp_endpoint_connection_e9b0a5f836'


def test_current_native_kind_network_capture_replays_without_mutation():
    path = Path(__file__).parent / 'fixtures/native-kind-network-v27.json'
    original = path.read_bytes()
    snapshot = validate(json.loads(original))
    assert snapshot['provider'] == 'k8s'
    assert snapshot['metadata']['cluster_id'] == CLUSTER
    assert snapshot['scopes'] == [NAMESPACE]
    before = json.dumps(snapshot, sort_keys=True)
    collections = {row['type']: row for row in snapshot['collections']}
    assert {kind: len(row['items']) for kind, row in collections.items()} == {
        'deployment': 2, 'endpointslice': 1, 'namespace': 1, 'networkpolicy': 1,
        'node': 1, 'pod': 3, 'service': 1, 'network_interface': 4,
    }
    assert all(row['status'] == 'collected' for row in collections.values())
    for row in collections.values():
        for item in row['items']:
            assert item['provenance']['cluster_id'] == CLUSTER
    inventory = resources(snapshot)
    with analysis_context(snapshot):
        graph = annotate_network(build_network(snapshot, inventory), snapshot, inventory)
    nodes = {node['id']: node for node in graph['nodes']}
    service = next(n for n in nodes.values() if n['type'] == 'service' and n['label'] == 'frontend')
    selector = next(e['target'] for e in graph['edges'] if e['source'] == service['id'] and e['type'] == 'declared_selector')
    matched = {nodes[e['target']]['label'] for e in graph['edges'] if e['source'] == selector and e['type'] == 'matches_pod'}
    assert matched == {'frontend-7d654d8dbb-5rrxd', 'frontend-7d654d8dbb-bh7nm'}
    assert not any(name.startswith('other-') for name in matched)
    pods = collections['pod']['items']
    selected = [p for p in pods if p['metadata']['name'] in matched]
    assert len(selected) == 2 and all(p['metadata']['namespace'] == NAMESPACE for p in selected)
    addresses = {p['status']['podIP'] for p in selected}
    uid_by_name = {p['metadata']['name']: p['metadata']['uid'] for p in selected}
    endpoints = [e for item in collections['endpointslice']['items'] for e in item['endpoints']]
    assert {a for e in endpoints for a in e['addresses']} == addresses
    assert {e['targetRef']['name']: e['targetRef']['uid'] for e in endpoints} == uid_by_name
    interfaces = [n for n in nodes.values() if n['type'] == 'network_interface']
    assert len(interfaces) == 4
    for interface in interfaces:
        assert interface['evidence']['attachment']['status'] == 'resolved'
        assert any(e['type'] == 'attached_interface' and e['target'] == interface['id'] for e in graph['edges'])
    # The native NetworkPolicy is a declaration, never a CNI enforcement proof.
    assert snapshot['metadata']['network_policy_enforcement']['status'] == 'unknown'
    report = evaluate_snapshot(snapshot, checks=[CID])
    findings = [f for f in report['findings'] if f['check_id'] == CID]
    assert len(findings) == 1 and findings[0]['status'] == 'PASS'
    assert json.dumps(snapshot, sort_keys=True) == before
    assert path.read_bytes() == original
    assert 'PRIVATE KEY' not in before and 'client-key-data' not in before
