"""Register the selected Azure ML Command-job secret check and its native cases."""
from . import selected_admission


def install():
    from . import azure_ml_selected_job_secret_review_20261020 as module
    cases = selected_admission.load_cases('azure_ml_job_secrets_admission_20261020_fixtures.json')
    selected_admission.install('azure', [(module.DECLARATION, module.evaluate)], cases)
