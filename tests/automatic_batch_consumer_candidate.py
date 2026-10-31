"""Offline registered automatic-batch projection witness for the amended engine seam."""
from copy import deepcopy
import json
from pathlib import Path

from peaso import engine
from peaso.checks import aws_lambda_environment_secret_review_20261020 as leaf
from peaso.checks import automatic_workload_batch as batch
from peaso.checks import CHECKS
from peaso.collectors import workload_environment_discovery as discovery
from peaso.snapshot import make_snapshot

root = Path(__file__).resolve().parents[1]
case = next(iter(json.loads((root / 'peaso/checks/aws_lambda_environment_secret_review_20261020_fixtures.json').read_text()).values()))
assert leaf.CHECK in {check.id for check in CHECKS}
kind = leaf.KIND
scope = case['pass_index']['context']['scope']
base = case['pass']
index = deepcopy(case['pass_index'])
metadata = index['context']['metadata']
parent = index['collections'][kind][0]
items = []
for number in range(32):
    row = deepcopy(base)
    ident = kind + ':' + f'{number + 1:064x}'
    row['id'] = ident
    row[leaf.MARKER]['identity'] = ident
    row[leaf.MARKER]['request']['identity'] = ident
    items.append(row)
metadata[kind + '_selection'][scope] = [item['id'] for item in items]
assert leaf.evaluate(items[0], index)[0] == 'UNKNOWN'  # historical bound is eight
collections = []
receipts = []
for number, chunk in enumerate(discovery.batches(items, 8), 1):
    batch_id = kind + ':' + str(number)
    envelope = deepcopy(parent)
    envelope['items'] = list(chunk)
    envelope['automatic_batch'] = batch_id
    collections.append(envelope)
    selected = {key: deepcopy(value) for key, value in metadata.items() if key.startswith(kind + '_')}
    selected[kind + '_selection'][scope] = [row['id'] for row in chunk]
    receipts.append({'id': batch_id, 'scope': scope, 'metadata': selected})
discovery.fold_collections(collections, kind, receipts)
assert len(collections) == 1 and len(collections[0]['items']) == 32
assert len(receipts) == 4 and [len(row['ids']) for row in receipts] == [8] * 4
metadata['automatic_workload_environment_batches'] = {kind: receipts}
metadata['automatic_workload_environment_coverage'] = {kind: {'complete': False, 'discovered': 34,
    'inspected': 33, 'uninspected': 1, 'reason': 'unrelated_denied_target'}}
other_scope = '123456789012/us-west-2'
other = deepcopy(base)
other['id'] = kind + ':' + f'{33:064x}'
other['Region'] = 'us-west-2'
other[leaf.MARKER]['identity'] = other['id']
other[leaf.MARKER]['scope'] = other_scope
other[leaf.MARKER]['region'] = 'us-west-2'
other[leaf.MARKER]['request']['identity'] = other['id']
other[leaf.MARKER]['request']['scope'] = other_scope
other['_provenance']['scope'] = other_scope
other_collection = deepcopy(parent)
other_collection['scope'] = other_scope
other_collection['items'] = [other]
other_metadata = {key: deepcopy(value) for key, value in metadata.items() if key.startswith(kind + '_')}
other_metadata[kind + '_selection'] = {other_scope: [other['id']]}
foreign = {'id': kind + ':5', 'scope': other_scope, 'metadata': other_metadata,
    'ids': [other['id']], 'status': 'collected', 'error': None}
metadata[kind + '_selection'][other_scope] = [other['id']]
metadata['automatic_workload_environment_batches'][kind].append(foreign)
snapshot = make_snapshot('aws', [scope, other_scope],
    [collections[0], other_collection, *index['collections']['aws_account']], metadata=metadata)
original_prepare = batch.prepare
calls = []
def counted(scoped, check_id):
    calls.append((scoped['context']['scope'], check_id))
    return original_prepare(scoped, check_id)
batch.prepare = counted
try:
    report = engine.evaluate_snapshot(snapshot, checks=[leaf.CHECK])
finally:
    batch.prepare = original_prepare
results = [finding for finding in report['findings'] if finding['native_resource_id'] in {item['id'] for item in items}]
assert len(results) == 32, (len(results), report['findings'][:2])
assert all(finding['status'] == 'PASS' for finding in results), [f['status'] for f in results]
assert calls.count((scope, leaf.CHECK)) == 1 and calls.count((other_scope, leaf.CHECK)) == 1, calls
assert any(row.get('native_resource_id') == other['id'] and row['status'] == 'PASS'
    for row in report['findings']), report['findings']
assert snapshot['metadata']['automatic_workload_environment_coverage'][kind]['complete'] is False
partial_receipts = deepcopy(receipts[:-1])
partial_receipts[0]['ids'] = []
partial_receipts[0]['status'] = 'denied'
partial_receipts[0]['error'] = {'code': 'AccessDeniedException'}
partial_collection = deepcopy(collections[0])
partial_collection['items'] = items[8:]
partial_collection['status'] = 'partial'
partial_metadata = deepcopy(metadata)
partial_metadata['automatic_workload_environment_batches'] = {kind: partial_receipts}
partial_snapshot = make_snapshot('aws', [scope], [partial_collection, *index['collections']['aws_account']], metadata=partial_metadata)
partial_report = engine.evaluate_snapshot(partial_snapshot, checks=[leaf.CHECK])
partial_findings = [finding for finding in partial_report['findings'] if finding.get('native_resource_id') in {item['id'] for item in items[8:]}]
assert len(partial_findings) == 24 and all(row['status'] == 'PASS' for row in partial_findings)
assert any(row['level'] == 'check' and row['status'] == 'partial' for row in partial_report['coverage'])
from peaso.collection_events import SettledCollections
events = []
deferred = SettledCollections(events.append, deferred={kind})
for chunk in discovery.batches(items, 8):
    raw = deepcopy(parent)
    raw['items'] = list(chunk)
    deferred.append(raw)
assert events == []
replayed = engine.collect_snapshot({'connector': {'provider': 'aws', 'scopes': [scope, foreign['scope']],
    'options': {'snapshot': snapshot}}, 'checks': [leaf.CHECK], '_collection_callback': events.append})
assert replayed['snapshot_id'] == snapshot['snapshot_id']
assert len(events) == 3 and len([row for row in events if row['type'] == kind]) == 2
assert len(next(row for row in events if row['type'] == kind and row['scope'] == scope)['items']) == 32
assert len({(row['type'], row['scope']) for row in events}) == len(events)
print('PASS: 32 registered Lambda findings from four bounded receipts; one preparation per region; unrelated incomplete coverage preserves own PASS')
print('PASS: 24 clean workloads survive a denied sibling batch while check coverage is partial; deferred event publishes one folded 32-row scope')
