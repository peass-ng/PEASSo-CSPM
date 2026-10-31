"""Register the three selected Azure content secret checks and their native cases."""
import importlib

from . import selected_admission

MODULES = ('azure_selected_configuration_secret_review_20261020', 'azure_selected_storage_secret_review_20261020',
           'azure_devops_selected_content_secret_review_20261020')


def install():
    declarations = []
    for name in MODULES:
        module = importlib.import_module('.' + name, __package__)
        declarations.append((module.DECLARATIONS[0], module.evaluate))
    cases = selected_admission.load_cases('azure_selected_secrets_admission_20261020_fixtures.json')
    selected_admission.install('azure', declarations, cases, severity='high')
