"""Register the selected Workbench referenced-source secret check and its native cases."""
from . import selected_admission

CHECK_IDS = ('gcp.review.workbench.selected_referenced_source_secret_indicators_20261020',)


def install():
    from . import gcp_workbench_source_runtime_consumer_20261020 as module
    cases = selected_admission.load_cases('gcp_workbench_source_runtime_cases_20261020.json')
    selected_admission.install('gcp', [(metadata, module.referenced_source) for metadata in module.DECLARATIONS], cases)
