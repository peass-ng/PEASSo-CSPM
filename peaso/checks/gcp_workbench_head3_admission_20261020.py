"""Register the three Workbench configuration declarations and their native cases.

The runtime declaration file records the explicit metadata decision; no numbered
mapping is installed.
"""
from copy import deepcopy
import json
from pathlib import Path

from . import gcp_workbench_head3_proposal_20261020 as candidate

CASES_FILE = 'gcp_workbench_head3_admission_cases_20261020.json'
CHECK_IDS = (
    'gcp.review.workbench.terminal_access_disabled',
    'gcp.review.workbench.file_download_disabled',
    'gcp.review.workbench.auto_upgrade_schedule_declared',
)
DECLARATIONS = tuple(json.loads((Path(__file__).with_name(
    'gcp_workbench_head3_admission_declarations_20261020.json')).read_bytes())['declarations'])


def _checked(cid, item, index):
    try:
        return candidate.EVALUATORS[cid](item, index)
    except Exception:
        return 'UNKNOWN', {'observed': 'The Workbench configuration predicate could not read the recorded instance settings.'}


def terminal_access_disabled(item, index):
    return _checked(CHECK_IDS[0], item, index)


def file_download_disabled(item, index):
    return _checked(CHECK_IDS[1], item, index)


def auto_upgrade_schedule_declared(item, index):
    return _checked(CHECK_IDS[2], item, index)


EVALUATORS = dict(zip(CHECK_IDS, (terminal_access_disabled, file_download_disabled,
                                auto_upgrade_schedule_declared)))


def install_bundle():
    from . import CHECKS, register
    from .fixtures import CASES
    cases = json.loads(Path(__file__).with_name(CASES_FILE).read_text())
    for row in DECLARATIONS:
        cid = row['id']
        if not any(check.id == cid for check in CHECKS):
            register(cid, 'gcp', 'hardening', 'workbench_instance', row['title'], row['severity'],
                     'security_configuration', row['remediation'], dependencies=['workbench_instance'])(EVALUATORS[cid])
        if cid not in CASES:
            CASES[cid] = deepcopy(cases[cid])
