"""Public priority decisions cannot rewrite signed compiler/audit source ratings."""
from copy import deepcopy
import hashlib
import json
import pytest
from peaso.checks import CHECKS
from peaso.finding_priority import source_priority, review_metadata
from scripts.peaso_catalog_audit import audit_documents
from tests.test_peaso_catalog_audit import catalogs, reviewed_catalogs, refresh_reviewed_lookup
from tests import test_peaso_rds_signed_alias_compiler as rds

CID='aws.s3.versioning'

def row():
 check=next(c for c in CHECKS if c.id==CID)
 value=check.public()
 assert check.severity=='medium' and value['severity']=='low'
 return value


def test_legacy_source_ratings_and_exact_trusted_reviews_are_distinct():
 assert source_priority({'id':CID,'severity':'medium'})=='medium'
 assert source_priority(row())=='medium'
 assert source_priority({'id':'unreviewed','severity':'high'})=='high'

@pytest.mark.parametrize('field,value',[('version','future'),('source_severity','critical'),('severity','critical'),('reason','unreviewed reason')])
def test_altered_review_provenance_is_rejected(field,value):
 value_row=row();value_row['severity_review'][field]=value
 with pytest.raises(ValueError,match='priority provenance'):source_priority(value_row)

@pytest.mark.parametrize('mutation',['rating','null_review','unknown_id','extra_review_field','missing_review_field'])
def test_claimed_review_never_bypasses_current_rating_or_identity(mutation):
 value=row()
 if mutation=='rating':value['severity']='critical'
 elif mutation=='null_review':value['severity_review']=None
 elif mutation=='unknown_id':value['id']='unknown'
 elif mutation=='extra_review_field':value['severity_review']['unreviewed']='text'
 else:del value['severity_review']['reason']
 with pytest.raises(ValueError,match='priority provenance'):source_priority(value)


def documents():
 # Reuse the complete source/reference fixture; change only the named source ID.
 value=reviewed_catalogs(catalogs.__wrapped__())
 value=json.loads(json.dumps(value).replace('aws.ebs.encryption',CID))
 native=value['native_catalog.json']['checks'][0]
 native.update(severity='low',severity_review=review_metadata(CID,'medium'))
 spec={'id':CID,'provider':'aws','severity':'medium','category':'hardening','resource_kind':'bucket','predicate':'Versioning.Status is Enabled'}
 value['compliance_requirements.json']['proposed_checks']=[spec]
 native['proposal_provenance']={'signed_spec_sha256':hashlib.sha256(json.dumps(spec,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest(),'signed_provider':'aws','signed_severity':'medium','signed_category':'hardening','signed_resource_kind':'bucket','source_manifest_sha256':value['compliance_requirements.json']['source_manifest_sha256']}
 refresh_reviewed_lookup(value)
 return value


def test_catalog_audit_accepts_verified_review_without_rewriting_signed_spec():
 value=documents();before=deepcopy(value)
 assert audit_documents(value)['catalog_consistent']
 assert value==before

@pytest.mark.parametrize('mutation',['public_rating','review_version','source_rating','signed_rating'])
def test_catalog_audit_rejects_forged_rating_or_review(mutation):
 value=documents();native=value['native_catalog.json']['checks'][0]
 if mutation=='public_rating':native['severity']='critical'
 elif mutation=='review_version':native['severity_review']['version']='future'
 elif mutation=='source_rating':native['severity_review']['source_severity']='low'
 else:value['compliance_requirements.json']['proposed_checks'][0]['severity']='low'
 result=audit_documents(value)
 assert not result['catalog_consistent']
 assert {'invalid_reviewed_priority_provenance','signed_proposal_severity_mismatch'} & {issue['code'] for issue in result['issues']}


def test_rds_compiler_accepts_actual_public_priority_and_preserves_original_source():
 inputs=rds.inputs.__wrapped__();_,proposals,check=inputs
 native={rds.SURVIVOR:check.public()}
 assert source_priority(native[rds.SURVIVOR])==check.severity
 assert rds.resolve(proposals,native)==rds.SURVIVOR
 if 'severity_review' in native[rds.SURVIVOR]:
  native[rds.SURVIVOR]['severity_review']['version']='untrusted'
  with pytest.raises(ValueError):rds.resolve(proposals,native)


def test_unsigned_catalog_review_still_rejects_forged_metadata():
 value=documents();value['compliance_requirements.json']['proposed_checks']=[]
 value['native_catalog.json']['checks'][0]['severity_review']['version']='untrusted'
 assert 'invalid_reviewed_priority_provenance' in {i['code'] for i in audit_documents(value)['issues']}


def test_compiler_registry_input_validates_the_entire_review_record():
 from scripts.peaso_compliance_compile import catalog_with_registered_checks
 check=next(c for c in CHECKS if c.id==CID);native={'checks':[row()]}
 compiled=catalog_with_registered_checks(native,[check])['checks'][0]
 assert {key:value for key,value in compiled.items() if key!='_registered_contract'}==native['checks'][0]
 assert compiled['_registered_contract']=={'type':check.kind,'category':check.category,
     'severity':check.severity,'target':check.target}
 native['checks'][0]['severity_review']['version']='untrusted'
 with pytest.raises(ValueError):catalog_with_registered_checks(native,[check])


