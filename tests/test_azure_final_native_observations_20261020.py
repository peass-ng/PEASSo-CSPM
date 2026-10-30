"""Native replay/status binding and concise observed evidence after admission."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from peaso.checks import evaluate_check
from peaso.checks.fixtures import CASES
from peaso.checks.azure_review_observed_20261020 import observation

ROWS=json.loads((Path(__file__).parent/'fixtures/azure-final-native-evidence-review-20261020.json').read_text())

@pytest.mark.parametrize('cid',sorted(ROWS))
@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_admitted_native_witness_and_short_observation(cid,branch):
    sample=CASES[cid]
    status,evidence=evaluate_check(cid,deepcopy(sample[branch]),deepcopy(sample[branch+'_index']))
    assert status==branch.upper()
    finding={'provider':'azure','check_id':cid,'status':status,'evidence':evidence}
    if status!='UNKNOWN':
        assert observation(finding)
        assert observation({**finding,'status':'PASS' if status=='FAIL' else 'FAIL'}) is None
        assert observation({**finding,'evidence':{**evidence,'native_declaration_id':'unreviewed','observed':'Fully protected.'}}) is None
