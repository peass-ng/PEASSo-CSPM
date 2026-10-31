"""Shared helpers for current native AWS and Kubernetes test inputs."""
from copy import deepcopy
import importlib
from peaso import checks


def case_state(value):
    """Snapshot both opaque owner identity and every mutable assertion field."""
    from peaso import azure_function_package_index_20261020 as owner
    if type(value) in (owner._Admitted, owner._Assertions):
        return ('owner_admission', type(value), id(value), case_state(value.snapshot),
                case_state(value.expected), case_state(value.scope))
    if isinstance(value, dict):
        return {key: case_state(member) for key, member in value.items()}
    if isinstance(value, list):
        return [case_state(member) for member in value]
    if isinstance(value, tuple):
        return tuple(case_state(member) for member in value)
    return deepcopy(value)


def replace_registry_checks(monkeypatch, rows):
    """Rebind the check registry list everywhere it is imported by name.

    Admission guards verify that modules which imported ``CHECKS`` still hold
    the live registry list, so a test fault must replace every binding at once.
    """
    import sys
    old = checks.CHECKS
    for module in list(sys.modules.values()):
        namespace = getattr(module, '__dict__', None)
        if module is not checks and isinstance(namespace, dict) and namespace.get('CHECKS') is old:
            monkeypatch.setattr(module, 'CHECKS', rows)
    monkeypatch.setattr(checks, 'CHECKS', rows)
    return rows


def annotation_current_cases(check_id, historical):
    """Overlay the current native-field fixtures on the five annotation checks."""
    from peaso.checks import k8s_annotation_native_admission_20261020 as admission
    if check_id not in admission.IDS:
        return historical
    from tests.generic_k8s_behavior_successors_20261020 import annotation_native_cases
    result = deepcopy(historical)
    result.update(deepcopy(annotation_native_cases()[check_id]))
    return result


def selected_content_pairs(provider):
    """Explicit admitted provider modules; no default metadata kind is inferred."""
    if provider == 'k8s':
        modules = ('k8s_literal_secret_indicators', 'k8s_selected_log_sample_secret_indicators',
                   'k8s_selected_metadata_runtime_20261020')
        profiles = ()
    else:
        assert provider == 'azure'
        modules = ('azure_app_settings_secret_indicators', 'azure_acr_image_secret_indicators',
                   'azure_selected_configuration_secret_indicators', 'azure_selected_storage_secret_indicators',
                   'azure_devops_selected_content_secret_indicators', 'azure_ml_selected_job_secret_indicators',
                   'azure_databricks_notebook_secret_indicators', 'azure_function_package_integration_20261020')
        profiles = ('azure_selected_declaration_secret_indicators', 'azure_selected_log_sample_secret_indicators',
                    'azure_ml_selected_asset_secret_indicators')
    pairs = [(module.CHECK, module.KIND) for name in modules
             for module in (importlib.import_module('peaso.collectors.' + name),)]
    for name in profiles:
        module = importlib.import_module('peaso.collectors.' + name)
        pairs.extend((profile['check'], profile['kind']) for profile in module.PROFILES.values())
    assert len({cid for cid, _ in pairs}) == len(pairs)
    registry = {check.id: check for check in checks.CHECKS}
    assert all(registry[cid].kind == kind and registry[cid].provider == provider for cid, kind in pairs)
    return pairs


def assert_modern_psp_native_applicability(check_id, monkeypatch):
    """Actual discovery/version HTTP proof replaces an unbound old PSP DTO."""
    from tests import test_k8s_annotation_psp_closure_20261020 as native
    statuses, _, pool, _ = native.execute(monkeypatch, check_id, modern=True, install=False)
    assert statuses == ['NOT_APPLICABLE']
    assert len(pool.calls) == 2
    assert all('podsecuritypolicies' not in str(call) for call in pool.calls)
