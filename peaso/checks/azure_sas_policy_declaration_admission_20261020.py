"""Register the bounded SAS-policy declaration check and its native cases."""
from . import azure_sas_expiry_policy_declaration_proposal_20261020 as candidate
from . import selected_admission


def install():
    d = candidate.DECLARATION
    cases = selected_admission.load_cases('azure_sas_expiry_policy_declaration_native_cases_20261020.json')
    selected_admission.install(d['provider'], [(d, candidate.evaluate)], cases, allow_incomplete_failure=False)
