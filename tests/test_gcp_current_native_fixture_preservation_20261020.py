"""Keep malformed historical evidence distinct from current native witnesses."""
from copy import deepcopy
import pytest
from peaso.checks import evaluate_check
from peaso.checks.fixtures import CASES


@pytest.mark.parametrize('cid',['gcp.claude.bigquery_dataset.no_gmail_access','gcp.claude.bigquery_dataset.no_googlegroups_access'])
def test_old_non_mailbox_fail_fixture_is_preserved_and_unresolved(cid):
    old=CASES[cid]
    assert '@'not in old['fail']['access'][0]['userByEmail']
    assert evaluate_check(cid,deepcopy(old['fail']),deepcopy(old.get('fail_index',old.get('index',{}))))[0]=='UNKNOWN'
