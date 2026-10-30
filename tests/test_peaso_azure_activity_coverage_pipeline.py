"""Native Activity window coverage reuses one list and preserves unavailable reads."""
from datetime import datetime
from urllib.parse import parse_qs, urlsplit
import re
import pytest
from peaso.collectors import azure, collect_live
from tests.archived_check_contract import evaluate_snapshot, plan_collection

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
CHECK = 'azure.other.change_approval_trace'


class API:
    tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'
    def __init__(self, mode): self.mode, self.calls, self.closed = mode, [], False
    def close(self): self.closed = True
    def request(self, url, *, body=None, audience=azure.ARM):
        self.calls.append((url, body)); assert audience == azure.ARM
        if body is not None:
            assert urlsplit(url).path == '/providers/Microsoft.ResourceGraph/resources'
            return {'data': [], 'resultTruncated': False}
        assert urlsplit(url).path == SCOPE + '/providers/Microsoft.Insights/eventtypes/management/values'
        query = parse_qs(urlsplit(url).query)
        if self.mode == 'denied' or ('page' in query and self.mode not in ('overlap', 'changed_overlap')):
            raise azure.AzureReadError('fixture_denied', 403)
        assert ' le ' in query['$filter'][0] and ' lt ' not in query['$filter'][0]
        start, end = re.findall("'([^']+)'", query['$filter'][0])
        self.window = start, end
        row = {'eventDataId': 'event-1', 'eventTimestamp': start,
            'resourceId': SCOPE + '/resourceGroups/rg/providers/Microsoft.Web/sites/app',
            'operationName': {'value': 'Microsoft.Web/sites/write'},
            'status': {'value': 'Succeeded'}, 'correlationId': 'corr'}
        if 'page' in query:
            changed = dict(row)
            if self.mode == 'changed_overlap':changed['correlationId'] = 'changed'
            return {'value': [changed, {**row, 'eventDataId': 'event-2'}]}
        if self.mode == 'foreign': row['resourceId'] = row['resourceId'].replace('11111111', '33333333')
        if self.mode == 'outside': row['eventTimestamp'] = end
        rows = [] if self.mode == 'empty' else [row]
        if self.mode == 'duplicate': rows.append(dict(row))
        result = {'value': rows}
        if self.mode in ('partial', 'overlap', 'changed_overlap'): result['nextLink'] = url + '&page=2'
        return result


@pytest.mark.parametrize('mode,expected', [
    ('complete', 'collected'), ('empty', 'collected'), ('denied', 'denied'),
    ('partial', 'partial'), ('duplicate', 'malformed'), ('foreign', 'malformed'),
    ('outside', 'collected'), ('overlap', 'collected'), ('changed_overlap', 'partial'), ('retention', 'malformed')])
def test_normal_native_activity_coverage_pipeline(monkeypatch, mode, expected):
    api = API(mode); monkeypatch.setattr(azure, 'AzureTransport', lambda auth: api);monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: api)
    connector = {'provider': 'azure', 'scopes': [SCOPE],
        'auth': {'method': 'token', 'arm_token': 'inert'},
        'options': {'concurrency': 1, 'retries': 0, 'activity_days': 90 if mode == 'retention' else 30}}
    required = plan_collection({'connector': connector, 'checks': [CHECK]})
    assert 'activity_log_coverage' in required
    snapshot = collect_live(connector, required)
    sources = [c for c in snapshot['collections'] if c['type'] == 'activity_log_coverage']
    assert len(sources) == 1 and sources[0]['status'] == expected, sources
    if expected == 'collected':
        row = sources[0]['items'][0]
        assert row['id'] == SCOPE
        assert (row['retainedFrom'], row['collectedThrough']) == api.window
        assert row['_provenance']['basis'].startswith('complete native query window')
        assert row['_provenance']['event_count'] == (2 if mode == 'overlap' else int(mode not in ('empty', 'outside')))
        assert datetime.fromisoformat(row['_provenance']['captured_at']) <= datetime.fromisoformat(snapshot['created_at'])
    else:
        assert sources[0]['items'] == []
    assert api.closed
    assert sum(body is None for url, body in api.calls) == (2 if mode in ('partial','overlap','changed_overlap') else 1)
    if mode == 'outside':
        source = next(c for c in snapshot['collections'] if c['type'] == 'activity_log')
        assert source['status'] == 'empty' and source['items'] == []
    report = evaluate_snapshot(snapshot, checks=[CHECK])
    assert report['findings'] and all(f['status'] not in ('PASS', 'FAIL') for f in report['findings'])
    assert all(not c['items'] for c in snapshot['collections'] if c['type'] == 'change_approval_record')
