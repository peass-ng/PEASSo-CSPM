"""External or provider-impossible contracts stay outside automated scans."""
from pathlib import Path
from datetime import date
import json

import pytest

from peaso.checks import CHECKS
from peaso.checks.native_only import automated_checks, exclusions
from peaso.engine import _selection

ROOT = Path(__file__).resolve().parents[1]
CHECK_BY_ID = {c.id: c for c in CHECKS}
ARCHIVED = {cid: row for cid, row in exclusions().items()
            if CHECK_BY_ID[cid].provider in ('azure', 'k8s')}


@pytest.mark.parametrize('cid', sorted(ARCHIVED))
def test_each_external_contract_has_source_reason_and_is_rejected_before_scanning(cid):
    entry = ARCHIVED[cid]
    assert isinstance(entry['reason'], str) and entry['reason'].strip()
    fields = entry['mandatory_external_fields']
    if entry.get('disposition') == 'unsupported_exact_contract':
        assert fields == []
        assert entry.get('native_alternative') in CHECK_BY_ID
        assert entry['native_alternative'] not in exclusions()
    elif entry.get('disposition') == 'superseded_native_criterion':
        assert fields == []
        assert cid == 'azure.review.managed_hsm.audit_storage_destination'
        assert entry['native_alternative'] == 'azure.logging.managed_hsm_audit_destination_declared'
        assert entry['native_alternative'] in CHECK_BY_ID
        assert entry['native_alternative'] not in exclusions()
    elif entry.get('disposition') == 'retired_native_service':
        assert fields == []
        assert CHECK_BY_ID[cid].provider == 'azure'
        assert entry['cloud'] == 'AzurePublic'
        assert entry['retired_resource_kind'] in {CHECK_BY_ID[cid].kind, *CHECK_BY_ID[cid].dependencies}
        assert entry['retired_resource_type']
        assert entry['official_reference'].startswith('https://learn.microsoft.com/')
        date.fromisoformat(entry['retirement_date'])
    else:
        assert isinstance(fields, list) and fields and all(isinstance(f, str) and f for f in fields)
    with pytest.raises(ValueError, match='not available for automated scans'):
        _selection(CHECK_BY_ID[cid].provider, None, [cid], None)


@pytest.mark.parametrize('provider', ['azure', 'k8s'])
def test_default_roster_retains_every_native_control_and_excludes_external_contracts(provider):
    all_ids = {c.id for c in CHECKS if c.provider == provider}
    active_ids = {c.id for c in automated_checks(CHECKS) if c.provider == provider}
    assert active_ids == all_ids - ARCHIVED.keys()
