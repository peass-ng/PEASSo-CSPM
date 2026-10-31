"""The optional AWS selected configuration reader registers once and stays outside default grants."""
import inspect
import pytest
from peaso.checks import CHECKS,fixtures,aws_selected_configuration_admission_20261020 as admission
from peaso.checks import aws_selected_configuration_secret_review_20261020 as reviewed
from peaso.server.validation import OPTIONS,validate_connector
from fastapi import HTTPException


def test_registry_and_native_three_branch_inputs_are_the_reviewed_reader():
    check,=[c for c in CHECKS if c.id==reviewed.CHECK]
    assert inspect.unwrap(check.evaluate)is reviewed.evaluate
    assert check.kind=='configuration_selected_content' and check.allow_incomplete_failure
    assert 'selected_aws_configuration_content'in OPTIONS
    before=tuple(CHECKS);admission.install();assert tuple(CHECKS)==before
    inputs=fixtures.CASES[reviewed.CHECK]
    assert {reviewed.evaluate(inputs[b],inputs[b+'_index'])[0]for b in ('pass','fail','unknown')}=={'PASS','FAIL','UNKNOWN'}


def test_optional_selector_rejects_wrong_provider_before_auth():
    with pytest.raises(HTTPException)as error:
        validate_connector('gcp',{}, {'selected_aws_configuration_content':[]}, {},scopes=['project'])
    assert error.value.status_code==422
