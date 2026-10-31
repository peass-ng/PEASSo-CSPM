"""Register the two selected Dataproc referenced-source secret checks and their native cases."""
from . import selected_admission

CHECK_IDS = ('gcp.review.dataproc.selected_job_referenced_source_secret_indicators',
             'gcp.review.dataproc.selected_initialization_referenced_source_secret_indicators')
EVALUATORS = dict(zip(CHECK_IDS, ('job_source', 'initialization_source')))


def install():
    from . import gcp_dataproc_referenced_source_secret_review_20261020 as module
    declarations = [(metadata, getattr(module, EVALUATORS[metadata['id']])) for metadata in module.DECLARATIONS]
    cases = selected_admission.load_cases('gcp_dataproc_source_runtime_cases_20261020.json')
    selected_admission.install('gcp', declarations, cases)
