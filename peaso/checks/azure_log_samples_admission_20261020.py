"""Register the two selected Azure log-sample secret checks and their native cases."""
from . import selected_admission

EVALUATORS = {
    'azure.review.log_analytics.selected_message_sample_secret_indicators': 'workspace',
    'azure.review.application_insights.selected_trace_sample_secret_indicators': 'application',
}


def install():
    from . import azure_selected_log_sample_secret_review_20261020 as module
    declarations = [(metadata, getattr(module, EVALUATORS[metadata['id']])) for metadata in module.DECLARATIONS]
    cases = selected_admission.load_cases('azure_log_samples_admission_20261020_fixtures.json')
    selected_admission.install('azure', declarations, cases)
