"""Current-source reconciliation is evidence, never implicit equivalence."""

import pytest

from scripts.audit_aws_prowler_parity import verified_bytes

def test_cached_source_path_cannot_escape_cache(tmp_path):
    with pytest.raises(ValueError, match='unsafe cached source path'):
        verified_bytes(tmp_path, {'path': '../outside.py'})
    with pytest.raises(ValueError, match='unsafe cached source path'):
        verified_bytes(tmp_path, {'path': '/outside.py'})
