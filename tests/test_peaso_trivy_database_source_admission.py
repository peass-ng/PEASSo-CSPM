"""Finite DB diagnostic delta preserves the original pin and rejects new bytes."""
import hashlib
from pathlib import Path
import pytest
from peaso.checks import private_secret_shared_source_successor_20261021 as owner
from peaso.checks import provider_group_install_20261021 as group

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/'peaso/trivy_database_20261021.py'


def test_current_db_reconstructs_original_dependency_without_repinning():
    original=group.AWS_DEPENDENCIES['peaso/trivy_database_20261021.py']
    assert original=='5e3686c4712175557ab4b1182e2bb82d155a78e4f39aa6c28ec0373860fe5987'
    assert hashlib.sha256(PATH.read_bytes()).hexdigest()!=original
    assert group._digest(PATH)==original
    row=owner._private_receipt()['image_capture_admission']['files']['peaso/trivy_database_20261021.py']
    restored=owner._reverse(PATH.read_text(),row).encode()
    assert hashlib.sha256(restored).hexdigest()==original


def test_unreviewed_db_bytes_rejected_even_after_successful_proof():
    assert group._digest(PATH)==group.AWS_DEPENDENCIES['peaso/trivy_database_20261021.py']
    raw=PATH.read_bytes()
    try:
        PATH.write_bytes(raw+b'\n# unreviewed diagnostic mutation\n')
        with pytest.raises(RuntimeError,match='Image capture admitted source changed'):
            owner._private_self()
        with pytest.raises(RuntimeError,match='Image capture admitted source changed'):
            group._digest(PATH)
    finally:PATH.write_bytes(raw)
    assert group._digest(PATH)==group.AWS_DEPENDENCIES['peaso/trivy_database_20261021.py']
