"""Exact native reference parity for the API-only presentation successor."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]

def test_all_registered_and_analysis_templates_preserve_presentation_inputs():
    from peaso.checks import CHECKS, CHECK_ALIASES
    from peaso.analysis import ANALYSIS_CHECKS
    from peaso.remediation import template
    from peaso.finding_presentation import _approved_text
    from peaso.server.materialized_catalog import template_for
    for check in CHECKS:
        expected, actual = template(check.id, check.provider), template_for(check.id, check.provider)
        assert _approved_text(actual) == _approved_text(expected), check.id
        if actual is not None:
            original = deepcopy(actual)
            actual['summary'] = 'caller mutation'
            assert template_for(check.id, check.provider) == original
    for cid in [*(row['id'] for row in ANALYSIS_CHECKS), *CHECK_ALIASES,
                'gcp_cloudsql_failed_attempts_lockout', 'azure_vm_8_2_1_1_712e1ad', 'unknown', 'analysis.unknown']:
        for provider in (None, 'aws', 'gcp', 'azure', 'k8s', 'other'):
            assert _approved_text(template_for(cid, provider)) == _approved_text(template(cid, provider)), (cid, provider)


def test_native_free_lookup_then_real_native_import_in_same_process():
    script = r'''
import importlib.abc, sys
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in ('peaso.checks','peaso.engine','peaso.analysis') or fullname.startswith(('peaso.checks.','peaso.analysis.')):
            raise AssertionError(fullname)
guard = Guard(); sys.meta_path.insert(0, guard)
from peaso.server.materialized_catalog import template_for
from peaso.server.remediation_presentation_static_20261020 import bind_command
assert template_for('aws.iam.root_mfa', 'aws')
bind_command('inspect <ACCOUNT_ID>', {'provider':'aws','scope':'123456789012','check_id':'aws.iam.root_mfa'})
assert not any(name in ('peaso.checks','peaso.engine','peaso.analysis') for name in sys.modules)
sys.meta_path.remove(guard)
from peaso.checks import CHECKS
assert len(CHECKS) > 4000
'''
    result = subprocess.run([sys.executable, '-c', script], cwd=ROOT, capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
