"""Explicit admission boundary for reviewed native Azure successors.

Importing this module has no effect; install() registers the declarations and
their native cases.
"""
from copy import deepcopy
from functools import wraps
import importlib
import inspect
import json
from pathlib import Path


def _cases():
    return json.loads(Path(__file__).with_name('azure_final_native_admission_20261020_fixtures.json').read_text())


def _declarations():
    aks = importlib.import_module('.azure_aks_legacy_projection_review_20261020', __package__)
    hsm = importlib.import_module('.azure_hsm_audit_destination_review_20261020', __package__)
    encryption = importlib.import_module('.azure_native_contract_closure_20261020', __package__)
    declarations = [(aks.DECLARATIONS[0], aks.diagnostic_declaration),
                    (hsm.DECLARATIONS[0], hsm.evaluate)]
    for proposal in encryption.PROPOSALS:
        # Encryption is the existing presentation group, not a registry category.
        metadata = {**proposal, 'category': 'hardening', 'finding_type': 'encryption',
                    'ui_group': 'Encryption', 'requirements': []}
        declarations.append((metadata, proposal['evaluate']))
    return aks, declarations


def _display_result(function, check_id):
    @wraps(function)
    def evaluate(item, index):
        status, evidence = function(item, index)
        if status in ('PASS', 'FAIL'):
            evidence = {**evidence, 'native_declaration_id': check_id,
                        'native_declaration_satisfied': status == 'PASS',
                        'effective_access': 'not_tested'}
        return status, evidence
    evaluate._native_final_admission_20261020 = check_id
    return evaluate


def install():
    """Install the native declarations and SW30 bridges."""
    from . import CHECKS, register
    from .fixtures import CASES

    cases = _cases()
    aks, declarations = _declarations()
    before = tuple(CHECKS)
    previous_originals = dict(aks._ORIGINALS)
    previous_cases = {ident: deepcopy(CASES[ident]) for ident in cases if ident in CASES}
    try:
        aks.install_successors()
        for metadata, function in declarations:
            ident = metadata['id']
            existing = next((check for check in CHECKS if check.id == ident), None)
            if existing is not None:
                if (inspect.unwrap(existing.evaluate) is not inspect.unwrap(function)
                        or getattr(existing.evaluate, '_native_final_admission_20261020', None) != ident):
                    raise RuntimeError('Native Azure admission overlaps another evaluator')
                continue
            hint = metadata['remediation']
            if isinstance(hint, (tuple, list)):
                hint = ' '.join(hint)
            register(ident, 'azure', metadata['category'], metadata['kind'],
                     metadata['title'], metadata['severity'], 'security_configuration', hint,
                     dependencies=metadata['dependencies'])(_display_result(function, ident))
            CASES[ident] = deepcopy(cases[ident])
    except Exception:
        CHECKS[:] = before
        aks._ORIGINALS.clear()
        aks._ORIGINALS.update(previous_originals)
        for ident in cases:
            if ident in previous_cases:
                CASES[ident] = previous_cases[ident]
            else:
                CASES.pop(ident, None)
        raise
