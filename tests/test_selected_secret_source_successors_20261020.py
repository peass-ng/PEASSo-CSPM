"""Current helper admission requires exact proof and retained predecessor bytes."""
from pathlib import Path
import shutil
import pytest
from tests.selected_secret_source_successors_20261020 import SUCCESSORS,CHAINED_SUCCESSORS,PRIVATE_NATIVE_SOURCE,RAWV2_SCANNER_SOURCE,ROOT,assert_source_receipt
PATH='peaso/secret_findings.py'
OLD=next(old for path,old in SUCCESSORS if path==PATH)





def test_another_prior_digest_cannot_be_promoted():
    with pytest.raises(AssertionError,match='No reviewed source successor'):
        assert_source_receipt(PATH,'f'*64)








