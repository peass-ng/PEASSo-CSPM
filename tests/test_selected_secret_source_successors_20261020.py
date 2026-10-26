"""Current helper admission requires exact proof and retained predecessor bytes."""
from pathlib import Path
import shutil
import pytest
from tests.selected_secret_source_successors_20261020 import SUCCESSORS,CHAINED_SUCCESSORS,PRIVATE_NATIVE_SOURCE,RAWV2_SCANNER_SOURCE,ROOT,assert_source_receipt
PATH='peaso/secret_findings.py'
OLD=next(old for path,old in SUCCESSORS if path==PATH)


def test_current_source_has_explicit_historical_successor():
    assert_source_receipt(PATH,OLD)

@pytest.mark.parametrize('target',['current','proof','retained'])
def test_unreviewed_current_proof_or_predecessor_is_rejected(tmp_path,target):
    proof=SUCCESSORS[(PATH,OLD)][0]
    files=[PATH,proof,'tests/fixtures/secret_findings_pre_incomplete_20261020.py.gz']
    for name in files:
        p=tmp_path/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,p)
    changed=tmp_path/files[['current','proof','retained'].index(target)]
    changed.write_bytes(changed.read_bytes()+b'\n')
    with pytest.raises(AssertionError):assert_source_receipt(PATH,OLD,root=tmp_path)


def test_another_prior_digest_cannot_be_promoted():
    with pytest.raises(AssertionError,match='No reviewed source successor'):
        assert_source_receipt(PATH,'f'*64)


def test_private_native_transition_preserves_exact_lambda_predecessor():
    path, prior = PRIVATE_NATIVE_SOURCE
    assert_source_receipt(path, prior)


def test_private_native_transition_rejects_changed_source_and_prior(tmp_path):
    from peaso.private_secret_source_epoch_20261021 import AdmissionError
    path, prior = PRIVATE_NATIVE_SOURCE
    dependency = tmp_path / 'peaso/secret_evidence.py'
    dependency.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / 'peaso/secret_evidence.py', dependency)
    target = tmp_path / path
    target.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / path, target)
    target.write_bytes(target.read_bytes() + b'\n# unreviewed native source\n')
    with pytest.raises(AdmissionError, match='current source mismatch'):
        assert_source_receipt(path, prior, root=tmp_path)
    with pytest.raises(AssertionError, match='No reviewed source successor'):
        assert_source_receipt(path, 'f' * 64)


def test_rawv2_scanner_transition_rejects_changed_source_and_prior(tmp_path):
    path, prior = RAWV2_SCANNER_SOURCE
    target = tmp_path / path
    target.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / path, target)
    target.write_bytes(target.read_bytes() + b'\n# unreviewed scanner source\n')
    with pytest.raises(RuntimeError, match='RawV2 scanner source pin changed'):
        assert_source_receipt(path, prior, root=tmp_path)
    with pytest.raises(AssertionError, match='No reviewed source successor'):
        assert_source_receipt(path, 'f' * 64)

@pytest.mark.parametrize('path,prior',sorted(SUCCESSORS))
def test_every_current_successor_preserves_exact_admitted_predecessor(path,prior):
    assert_source_receipt(path,prior)

@pytest.mark.parametrize('path,prior',sorted(SUCCESSORS))
@pytest.mark.parametrize('changed_part',['current','proof','retained'])
def test_each_successor_rejects_current_proof_and_retained_tampering(tmp_path,path,prior,changed_part):
    import json
    proof=SUCCESSORS[(path,prior)][0]
    document=json.loads((ROOT/proof).read_text())
    row,=[r for r in document.get('sources',[document])if r['source_path']==path and r['prior_sha256']==prior]
    retained=row['retained_predecessor']['path']
    files={'current':path,'proof':proof,'retained':retained}
    # Unchanged dependencies the successor proof also reads from the root.
    dependencies=['peaso/secret_evidence.py']
    if (path,row['current_sha256']) in CHAINED_SUCCESSORS:
        chained=CHAINED_SUCCESSORS[(path,row['current_sha256'])][0]
        chained_row,=json.loads((ROOT/chained).read_text())['sources']
        dependencies+=[chained,chained_row['retained_predecessor']['path']]
    for name in [*files.values(),*dependencies]:
        target=tmp_path/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
    changed=tmp_path/files[changed_part];changed.write_bytes(changed.read_bytes()+b'\n')
    with pytest.raises(AssertionError):assert_source_receipt(path,prior,root=tmp_path)
