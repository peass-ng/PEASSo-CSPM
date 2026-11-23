"""New AI plans require impact and effort while archived plans remain readable."""
import pytest
from peaso.ai.contracts import Recommendations, validate_actions
from peaso.ai.output_validation import validate

REPORT={'findings':[{'id':'f1','status':'FAIL','category':'hardening'}]}
LEGACY={'rank':1,'title':'Restrict ingress','finding_ids':['f1'],'rationale':'The rule permits public access.','steps':['Restrict the source.'],'verification':'Read the updated rule.'}


def test_new_plan_requires_both_assessments_and_preserves_them():
    data={'actions':[dict(LEGACY,severity='high',effort='low')],'limitations':[]}
    assert validate_actions(data,REPORT,[],require_assessment=True)==data
    assert validate('priorities',data,{'report':REPORT,'reviews':[]})==data
    for missing in ('severity','effort'):
        value={**data,'actions':[{k:v for k,v in data['actions'][0].items() if k!=missing}]}
        with pytest.raises(ValueError):validate_actions(value,REPORT,[],require_assessment=True)


@pytest.mark.parametrize('field,value',[('severity','urgent'),('effort','critical'),('severity',None),('effort',None)])
def test_new_assessments_reject_unknown_or_null_values(field,value):
    action=dict(LEGACY,severity='high',effort='low');action[field]=value
    with pytest.raises(ValueError):validate_actions({'actions':[action],'limitations':[]},REPORT,[],require_assessment=True)


def test_old_report_is_not_assigned_fabricated_assessments():
    data={'actions':[LEGACY],'limitations':[]}
    assert validate_actions(data,REPORT,[])==data
    with pytest.raises(ValueError):validate('priorities',data,{'report':REPORT,'reviews':[]})


def test_producer_schema_requires_assessments():
    schema=Recommendations.model_json_schema()
    assert {'severity','effort'}<=set(schema['$defs']['Action']['required'])


def test_new_plans_cap_actions_at_ten_and_archives_still_accept_fifteen():
    actions = [dict(LEGACY, rank=rank, title=f'Action {rank}', severity='high', effort='low')
               for rank in range(1, 16)]
    data = {'actions': actions, 'limitations': []}
    assert validate_actions(data, REPORT, []) == data
    assert validate_actions(dict(data, actions=actions[:10]), REPORT, [], require_assessment=True)['actions'] == actions[:10]
    with pytest.raises(ValueError):
        validate_actions(dict(data, actions=actions[:11]), REPORT, [], require_assessment=True)
    schema = Recommendations.model_json_schema()
    assert schema['properties']['actions']['maxItems'] == 10
    assert schema['$defs']['Action']['properties']['rank']['maximum'] == 10
