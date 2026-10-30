"""Strict SW46 joins through their real registered bulk namespace."""
import copy
import sys
import pytest
from peaso.checks import CHECKS
from peaso.checks.facts import MemoIndex, Unavailable
from peaso.snapshot import freeze

MODULE = sys.modules['peaso.checks._bulk_pending_compliance_new_sw46']
SCOPE = '123456789012/us-east-1'
PREDECESSOR = 'def _items(index, kind):\n    scope, _, _ = _context(index)\n    envelopes = get(index, "collections", dict).get(kind)\n    if (not isinstance(envelopes, list) or len(envelopes) != 1 or\n            not isinstance(envelopes[0], dict) or envelopes[0].get("type") != kind or\n            envelopes[0].get("scope") != scope):\n        raise Unavailable("collection scope authority unavailable: " + kind)\n    rows = complete_items(index, kind)\n    if envelopes[0].get("items") != rows:\n        raise Unavailable("collection envelope disagrees with resource inventory: " + kind)\n    wrappers = get(index, kind, list)\n    if len(wrappers) != len(rows) or any(\n        not isinstance(w, dict) or w.get("type") != kind or w.get("scope") != scope or\n        w.get("data") != row for w, row in zip(wrappers, rows)\n    ):\n        raise Unavailable("malformed or foreign-scope resource wrappers: " + kind)\n    return rows\n\ndef _resource(item, index, kind):\n    rows = _items(index, kind)\n    key = _IDS[kind]\n    identity = get(item, key, str)\n    if not identity:\n        raise Unavailable("missing resource identity")\n    seen = []\n    for row in rows:\n        value = get(row, key, str)\n        if not value:\n            raise Unavailable("empty inventory identity")\n        seen.append(value)\n    if len(seen) != len(set(seen)) or seen.count(identity) != 1 or rows[seen.index(identity)] != item:\n        raise Unavailable("ambiguous or foreign resource identity")\n    return identity'
oracle = dict(MODULE.__dict__)
exec(compile(PREDECESSOR, '<predecessor-sw46-joins>', 'exec'), oracle)


def index_for(rows=None, kind='instance', index_type=MemoIndex):
    rows = copy.deepcopy(rows if rows is not None else [{'InstanceId': 'i-z', 'setting': 1}, {'InstanceId': 'i-a', 'setting': 2}])
    native = [freeze(row) for row in rows]
    return index_type({'context': freeze({'provider': 'aws', 'scope': SCOPE}),
        'collections': {kind: [{'type': kind, 'scope': SCOPE, 'status': 'collected', 'items': native}]},
        kind: [{'type': kind, 'scope': SCOPE, 'data': row} for row in native]})


def outcome(fn, item, index, kind='instance'):
    try:
        return 'return', fn(item, index, kind)
    except Exception as exc:
        return 'raise', type(exc), exc.args




@pytest.mark.parametrize('index_type', [dict, MemoIndex])
@pytest.mark.parametrize('kind,key', [('instance', 'InstanceId'), ('cloudwatch_alarm', 'AlarmArn'),
    ('guardduty_detector', 'DetectorId'), ('sns_topic', 'TopicArn'), ('iam_role', 'Arn')])
def test_all_supported_identity_kinds_keep_native_order_and_equal_payloads(index_type, kind, key):
    index = index_for([{key: 'z', 'setting': 1}, {key: 'a', 'setting': 2}], kind, index_type)
    for row in index[kind]:
        item = row['data']
        assert outcome(MODULE._resource, item, index, kind) == outcome(oracle['_resource'], item, index, kind)
    original = MODULE._items(index, kind)
    assert original == oracle['_items'](index, kind)
    original.reverse()
    original.clear()
    assert [row[key] for row in MODULE._items(index, kind)] == ['z', 'a']


@pytest.mark.parametrize('index_type', [dict, MemoIndex])
@pytest.mark.parametrize('change', ['missing_collection', 'denied', 'collection_type', 'collection_scope',
    'multiple_envelopes', 'wrapper_type', 'wrapper_scope', 'wrapper_payload', 'envelope_payload',
    'duplicate_identity', 'missing_identity', 'empty_identity', 'typed_identity', 'malformed_coverage',
    'foreign_item', 'missing_item_identity', 'item_error_before_bad_inventory', 'late_error_before_duplicate'])
def test_negative_error_and_payload_parity(index_type, change):
    index = index_for(index_type=index_type)
    collection = index['collections']['instance'][0]
    item = index['instance'][0]['data']
    if change == 'missing_collection': index['collections'] = {}
    elif change == 'denied': collection['status'] = 'denied'
    elif change == 'collection_type': collection['type'] = 'bucket'
    elif change == 'collection_scope': collection['scope'] = '999999999999/us-east-1'
    elif change == 'multiple_envelopes': index['collections']['instance'].append(dict(collection))
    elif change == 'wrapper_type': index['instance'][1]['type'] = 'bucket'
    elif change == 'wrapper_scope': index['instance'][1]['scope'] = '999999999999/us-east-1'
    elif change == 'wrapper_payload': index['instance'][1]['data'] = freeze({'InstanceId': 'foreign'})
    elif change == 'envelope_payload': collection['items'] = [item]
    elif change == 'foreign_item': item = dict(item, setting=999)
    elif change == 'missing_item_identity': item = {'setting': 1}
    else:
        rows = [{'InstanceId': 'i-z'}, {'InstanceId': 'i-a'}]
        if change == 'duplicate_identity': rows[1]['InstanceId'] = 'i-z'
        elif change == 'missing_identity': rows[1] = {}
        elif change == 'empty_identity': rows[1]['InstanceId'] = ''
        elif change == 'typed_identity': rows[1]['InstanceId'] = 42
        elif change == 'malformed_coverage': rows[1]['_coverage'] = {'InstanceId': {'status': 'denied'}}
        elif change == 'item_error_before_bad_inventory': rows[1]['InstanceId'] = 42
        elif change == 'late_error_before_duplicate': rows = [{'InstanceId': 'i-z'}, {'InstanceId': 'i-z'}, {'InstanceId': ''}]
        index = index_for(rows, index_type=index_type)
        item = {} if change == 'item_error_before_bad_inventory' else index['instance'][0]['data']
    expected = outcome(oracle['_resource'], item, index)
    assert expected[0] == 'raise', change
    assert outcome(MODULE._resource, item, index) == expected
    assert outcome(MODULE._resource, item, index) == expected


def test_dictionary_and_subclass_paths_revalidate_live_envelopes():
    class Subclass(MemoIndex):
        pass
    for index_type in (dict, Subclass):
        index = index_for(index_type=index_type)
        item = index['instance'][0]['data']
        assert MODULE._resource(item, index, 'instance') == 'i-z'
        index['collections']['instance'][0]['scope'] = '999999999999/us-east-1'
        assert outcome(MODULE._resource, item, index) == outcome(oracle['_resource'], item, index)
        with pytest.raises(Unavailable, match='collection scope authority'):
            MODULE._resource(item, index, 'instance')
        if isinstance(index, MemoIndex):
            assert index.memo == {}


def test_cached_unavailable_raises_fresh_exceptions():
    index = index_for([{'InstanceId': 'i-z'}, {'InstanceId': ''}])
    item = index['instance'][0]['data']
    errors = []
    for _ in range(2):
        try:
            MODULE._resource(item, index, 'instance')
        except Unavailable as exc:
            errors.append(exc)
    assert len(errors) == 2 and errors[0] is not errors[1]
    assert errors[0].args == errors[1].args == ('empty inventory identity',)
