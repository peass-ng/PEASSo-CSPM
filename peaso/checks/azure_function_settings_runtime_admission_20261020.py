"""Register the two selected Function declaration checks and their native cases."""
from . import azure_function_settings_runtime_consumer_20261020 as candidate
from . import selected_admission


def install():
    cases = selected_admission.load_cases('azure_function_settings_runtime_cases_20261020.json')
    selected_admission.install(
        'azure', [(d, d['evaluate']) for d in candidate.PROPOSALS], cases,
        allow_incomplete_failure=False, remediation=lambda d: '\n'.join(d['remediation']))
