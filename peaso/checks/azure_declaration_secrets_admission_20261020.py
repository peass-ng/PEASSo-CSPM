"""Register the three selected Azure declaration secret checks and their native cases."""
from . import selected_admission

EVALUATORS = {
    'azure.review.app_configuration.selected_value_secret_indicators': 'app_configuration',
    'azure.review.data_factory.selected_declaration_secret_indicators': 'data_factory',
    'azure.review.synapse.selected_pipeline_secret_indicators': 'synapse',
}


def install():
    from . import azure_selected_declaration_secret_review_20261020 as module
    declarations = [(metadata, getattr(module, EVALUATORS[metadata['id']])) for metadata in module.DECLARATIONS]
    cases = selected_admission.load_cases('azure_declaration_secrets_admission_20261020_fixtures.json')
    selected_admission.install('azure', declarations, cases)
