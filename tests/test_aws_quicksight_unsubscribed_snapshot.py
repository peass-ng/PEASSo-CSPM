"""An account without QuickSight, or a reader returning an odd status, still yields a valid snapshot."""
import pytest

from test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION  # noqa: F401
from peaso.collectors import aws, collect_live
from peaso.collectors import aws_quicksight_dashboard_shares as shares

SCOPE = ACCOUNT + '/' + REGION


def _collect(session, add, monkeypatch):
    sts = add('sts')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT, 'Arn': 'arn:aws:iam::' + ACCOUNT + ':user/reader',
                                             'UserId': 'reader'}, {})
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture-pinned'))
    connector = {'provider': 'aws', 'scopes': [SCOPE], 'options': {'retry_attempts': 1, 'service_concurrency': 1}}
    snapshot = collect_live(connector, [shares.KIND])
    return next(c for c in snapshot['collections'] if c['type'] == shares.KIND)


def test_unsubscribed_account_has_no_dashboards_to_share(sdk, monkeypatch):
    session, add = sdk
    quicksight = add('quicksight')
    quicksight.add_client_error('describe_account_settings', 'ResourceNotFoundException',
                                'Account settings not found')
    quicksight.add_client_error('list_dashboards', 'UnsupportedUserEditionException',
                                'Account ' + ACCOUNT + ' is not subscribed for QuickSight')
    collection = _collect(session, add, monkeypatch)
    assert collection['items'] == []
    assert collection['status'] in {'empty', 'unknown'}


def test_dashboards_without_sharing_setting_are_partial(sdk, monkeypatch):
    session, add = sdk
    quicksight = add('quicksight')
    arn = 'arn:aws:quicksight:' + REGION + ':' + ACCOUNT + ':dashboard/d1'
    quicksight.add_client_error('describe_account_settings', 'AccessDeniedException')
    quicksight.add_response('list_dashboards', {'DashboardSummaryList': [{'Arn': arn, 'DashboardId': 'd1'}]})
    quicksight.add_response('describe_dashboard_permissions', {'DashboardId': 'd1', 'DashboardArn': arn,
                                                               'Permissions': []})
    collection = _collect(session, add, monkeypatch)
    assert collection['status'] == 'partial' and len(collection['items']) == 1
    assert collection['items'][0]['AccountPublicSharing'] is None


def test_reader_with_unexpected_status_does_not_abort_the_snapshot(sdk, monkeypatch):
    session, add = sdk
    monkeypatch.setitem(aws.FETCHERS, shares.KIND,
                        lambda *args: aws.ReadResult([], 'not_a_status', {'code': 'synthetic'}))
    collection = _collect(session, add, monkeypatch)
    assert collection['status'] == 'unknown' and collection['items'] == []
