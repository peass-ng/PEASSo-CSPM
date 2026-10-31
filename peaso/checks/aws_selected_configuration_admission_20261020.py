"""Register the selected AWS configuration content secret check and its native cases."""
from copy import deepcopy

from .selected_admission import load_cases


def install():
    from . import CHECKS, register
    from .fixtures import CASES
    from . import aws_selected_configuration_secret_review_20261020 as reviewed
    cases = load_cases('aws_selected_configuration_secret_review_20261020_fixtures.json')
    if not any(check.id == reviewed.CHECK for check in CHECKS):
        reviewed.install(register)
    CASES[reviewed.CHECK] = deepcopy(cases[reviewed.CHECK])
