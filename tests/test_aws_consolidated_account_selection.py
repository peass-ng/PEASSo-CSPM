"""A complete account selection enters the public hosted planner without splitting."""
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso.server.validation import validate_connector
from peaso.engine import plan_collection
from peaso import aws_image_selection_20261021 as image
from peaso.collectors import aws_selected_configuration_secret_indicators as config
from peaso.collectors import aws_s3_selected_source_secret_indicators as source

ACCOUNT='123456789012';SCOPE=ACCOUNT+'/us-east-1'

def options():
 return {'content_secret_scans':True,'image_vulnerability_scans':True,
  config.OPTION:[{'scope':SCOPE,'surface':'ssm_document','resource_id':f'arn:aws:ssm:us-east-1:{ACCOUNT}:document/audit-{n}','version':1}for n in range(22)],
  source.OPTION:[{'scope':SCOPE,'bucket':'account-audit-state','key':f'state-{n}.tfstate','format':'text'}for n in range(5)],
  image.OPTION:[{'scope':SCOPE,'repository_name':f'audit/image-{n}','image_digest':'sha256:'+'a'*64}for n in range(12)]}

def validate(value):
 auth={'method':'assume_role','role_arn':f'arn:aws:iam::{ACCOUNT}:role/reader','external_id':'peaso-synthetic-external'}
 validate_connector('aws',auth,value,SimpleNamespace(auth_mode='cognito'),server_external_id=True,scopes=[SCOPE])

def test_full_account_configuration_images_and_states_fit_one_assessment():
 value=options();validate(value)
 assert len(config.selected_targets(value,[SCOPE]))==22
 assert len(source.selected_targets(value,[SCOPE]))==5
 assert len(image.selections(value,[SCOPE]))==12
 plan=plan_collection({'connector':{'provider':'aws','scopes':[SCOPE],'options':value},'checks':[config.CHECK,source.CHECK,image.CHECK]})
 assert {config.KIND,source.KIND,image.KIND}<=set(plan)

@pytest.mark.parametrize('key',[config.OPTION,source.OPTION,image.OPTION])
def test_consolidation_does_not_remove_selection_admission_bounds(key):
 value=options();value[key]=value[key]*100
 with pytest.raises(HTTPException)as exc:validate(value)
 assert exc.value.status_code==422
