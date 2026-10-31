"""Pinned successor evidence must not break authentic historical ledgers."""
from pathlib import Path
import pytest
from scripts.peaso_compliance_compile import SOURCE_ERRATA, verify_source_errata

RELATIVE, (CHECK, SPEC, _) = next(iter(SOURCE_ERRATA.items()))
CURRENT = {CHECK: {'proposal_provenance': {'source_correction': {
    'current_canonical_spec_sha256': SPEC}}}}






def test_changed_record_rejected_even_for_historical_catalog(tmp_path):
    (tmp_path / RELATIVE).write_text('{}')
    with pytest.raises(ValueError, match='Source erratum hash mismatch'):
        verify_source_errata(tmp_path, {})


def test_exact_reviewed_record_is_accepted(tmp_path):
    source = Path(__file__).resolve().parent / 'fixtures' / RELATIVE
    (tmp_path / RELATIVE).write_bytes(source.read_bytes())
    verify_source_errata(tmp_path, CURRENT)
