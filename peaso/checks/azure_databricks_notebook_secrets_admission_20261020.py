"""Register the selected Azure Databricks notebook secret check and its native cases."""
from . import selected_admission


def install():
    from . import azure_databricks_notebook_secret_review_20261020 as module
    cases = selected_admission.load_cases('azure_databricks_notebook_secrets_admission_20261020_fixtures.json')
    selected_admission.install('azure', [(module.DECLARATION, module.evaluate)], cases)
