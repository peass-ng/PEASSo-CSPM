"""Register the selected Azure ML environment and code-file secret checks and their native cases."""
from . import selected_admission

EVALUATORS = {
    'azure.review.machine_learning.selected_environment_conda_secret_indicators': 'environment',
    'azure.review.machine_learning.selected_code_file_secret_indicators': 'code',
}


def install():
    from . import azure_ml_selected_asset_secret_review_20261020 as module
    declarations = [(metadata, getattr(module, EVALUATORS[metadata['id']])) for metadata in module.DECLARATIONS]
    cases = selected_admission.load_cases('azure_ml_asset_secrets_admission_20261020_fixtures.json')
    selected_admission.install('azure', declarations, cases)
