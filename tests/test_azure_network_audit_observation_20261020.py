"""Brief observations preserve current native outcomes and reject contradictions."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from peaso.checks.azure_review_observed_20261020 import observation

ROWS=json.loads((Path(__file__).parent/'fixtures/azure-network-audit-evidence-review-20261020.json').read_text())


@pytest.mark.parametrize('cid',ROWS)
def test_unreviewed_marker_cannot_promote_arbitrary_observed_text(cid):
    row=deepcopy(ROWS[cid][0]);row['evidence']['criterion']='unreviewed';row['evidence']['observed']='Everything is fully protected.'
    assert observation({'provider':'azure','check_id':cid,**row}) is None
