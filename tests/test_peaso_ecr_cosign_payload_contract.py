"""Cosign regressions execute in one child without importing drafts in pytest's parent."""
from pathlib import Path
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

# Preserve all 46 actual assertions, including six Snapshot -> engine cases.
# A child is required because SW43 is intentionally not imported by the parent.
CHILD_SOURCE = r'''"""Official Cosign Simple Signing binds unchanged signed bytes to image content."""
import ast,base64,copy,json
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import peaso.checks as registry
# Signed source tests are isolated from already admitted registrar proxies.
node=ast.parse((Path(registry.__file__).parent/'compliance_new_sw43.py').read_text())
ids=set(next(ast.literal_eval(n.value)for n in node.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='SPECS'for t in n.targets)))
registry.CHECKS[:]=[c for c in registry.CHECKS if c.id not in ids]
for check_id in ids:registry.CHECK_ALIASES.pop(check_id,None)
from peaso.checks import compliance_new_sw43 as sw

ACCOUNT='123456789012';REGION='us-east-1';SCOPE=ACCOUNT+'/'+REGION;DIGEST='sha256:'+'a'*64
CHECK='aws_ecr_image_provenance';TYPE='application/vnd.dev.cosign.simplesigning.v1+json'
KEY=Ed25519PrivateKey.generate();PEM=KEY.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()

def body():
 return {'critical':{'identity':{'docker-reference':'123456789012.dkr.ecr.us-east-1.amazonaws.com/workload'},'image':{'docker-manifest-digest':DIGEST},'type':'cosign container image signature'},'optional':None}

def facts(payload,*,sign_bytes=None):
 image={'imageDigest':DIGEST};artifact={'artifactDigest':'sha256:'+'b'*64,'artifactType':TYPE,'subject':{'digest':DIGEST},'payload':payload,'signature':base64.b64encode(KEY.sign(payload.encode()if sign_bytes is None else sign_bytes)).decode(),'keyId':'approved-key'}
 context={'provider':'aws','scope':SCOPE,'metadata':{'deployed_image_digests':[DIGEST],'approved_signing_public_keys':[{'KeyId':'approved-key','PublicKeyPem':PEM}]}}
 index={'context':context,'collections':{}}
 for kind,rows in [('ecr_image',[image]),('ecr_oci_artifact',[artifact])]:
  index['collections'][kind]=[{'type':kind,'scope':SCOPE,'status':'collected','items':rows}]
  index[kind]=[{'type':kind,'scope':SCOPE,'data':row}for row in rows]
 return image,index,artifact

def evaluate(image,index):
 matches=[c for c in registry.CHECKS if c.id==CHECK];assert len(matches)==1
 return matches[0].evaluate(image,index)[0]

@pytest.mark.parametrize('pretty',[False,True])
def test_official_cosign_payload_verifies_original_signed_bytes(pretty):
 payload=json.dumps(body(),indent=2 if pretty else None)
 image,index,_=facts(payload)
 assert evaluate(image,index)=='PASS'

def test_schema_adapter_must_not_reserialize_signed_payload():
 original=json.dumps(body(),indent=2);normalized=json.dumps(body(),separators=(',',':'))
 image,index,_=facts(normalized,sign_bytes=original.encode())
 assert evaluate(image,index)=='FAIL'

@pytest.mark.parametrize('mode,expected',[('foreign_digest','FAIL'),('foreign_subject','FAIL'),('wrong_type','UNKNOWN'),('bad_signature','FAIL'),('unapproved_key','FAIL'),('invalid_signature_encoding','UNKNOWN'),('missing_trust','UNKNOWN'),('bad_key','UNKNOWN'),('legacy_shape','UNKNOWN'),('critical_list','UNKNOWN'),('critical_none','UNKNOWN'),('image_list','UNKNOWN'),('image_none','UNKNOWN'),('digest_number','UNKNOWN'),('digest_invalid','UNKNOWN'),('identity_list','UNKNOWN'),('reference_number','UNKNOWN'),('type_number','UNKNOWN'),('invalid_json','UNKNOWN'),('body_list','UNKNOWN'),('duplicate_critical','UNKNOWN'),('foreign_collection','UNKNOWN'),('foreign_wrapper','UNKNOWN'),('partial','UNKNOWN'),('unknown_critical','UNKNOWN'),('unknown_image','UNKNOWN'),('unknown_identity','UNKNOWN'),('unknown_top','UNKNOWN'),('optional_list','UNKNOWN'),('capital_digest','UNKNOWN')])
def test_invalid_untrusted_or_foreign_evidence_does_not_verify(mode,expected):
 value=body()
 if mode=='unknown_critical':value['critical']['future']=True
 if mode=='unknown_image':value['critical']['image']['future']=True
 if mode=='unknown_identity':value['critical']['identity']['future']=True
 if mode=='unknown_top':value['future']=True
 if mode=='optional_list':value['optional']=[]
 if mode=='capital_digest':value['critical']['image']={'Docker-manifest-digest':DIGEST}
 if mode=='foreign_digest':value['critical']['image']['docker-manifest-digest']='sha256:'+'c'*64
 if mode=='wrong_type':value['critical']['type']='unrelated signature'
 if mode=='legacy_shape':value={'subject':{'digest':DIGEST}}
 if mode=='critical_list':value['critical']=[]
 if mode=='critical_none':value['critical']=None
 if mode=='image_list':value['critical']['image']=[]
 if mode=='image_none':value['critical']['image']=None
 if mode=='digest_number':value['critical']['image']['docker-manifest-digest']=1
 if mode=='digest_invalid':value['critical']['image']['docker-manifest-digest']='not-sha256'
 if mode=='identity_list':value['critical']['identity']=[]
 if mode=='reference_number':value['critical']['identity']['docker-reference']=1
 if mode=='type_number':value['critical']['type']=1
 if mode=='body_list':value=[]
 payload='{broken'if mode=='invalid_json'else json.dumps(value)
 if mode=='duplicate_critical':payload=payload.replace('"critical":','"critical":{"type":"unrelated"},"critical":',1)
 image,index,artifact=facts(payload)
 if mode=='foreign_subject':artifact['subject']['digest']='sha256:'+'c'*64
 if mode=='bad_signature':artifact['signature']=base64.b64encode(b'wrong-signature').decode()
 if mode=='invalid_signature_encoding':artifact['signature']='!invalid'
 if mode=='unapproved_key':artifact['keyId']='not-approved'
 if mode=='missing_trust':index['context']['metadata'].pop('approved_signing_public_keys')
 if mode=='bad_key':index['context']['metadata']['approved_signing_public_keys'][0]['PublicKeyPem']='not-a-public-key'
 if mode=='foreign_collection':index['collections']['ecr_oci_artifact'][0]['scope']='999999999999/'+REGION
 if mode=='foreign_wrapper':index['ecr_oci_artifact'][0]['scope']='999999999999/'+REGION
 if mode=='partial':index['collections']['ecr_oci_artifact'][0]['status']='partial'
 assert evaluate(image,index)==expected

def test_docker_reference_is_not_a_repository_trust_policy():
 value=body();value['critical']['identity']['docker-reference']='different.example/portable/same-content'
 image,index,_=facts(json.dumps(value));assert evaluate(image,index)=='PASS'

@pytest.fixture(scope='module',autouse=True)
def restore_direct_registrations():
 yield
 registry.CHECKS[:]=[c for c in registry.CHECKS if c.id not in ids]
for check_id in ids:registry.CHECK_ALIASES.pop(check_id,None)

@pytest.mark.parametrize('mode,expected', [('official','PASS'),('legacy','UNKNOWN'),('foreign_digest','FAIL'),('bad_signature','FAIL'),('foreign_scope','UNKNOWN'),('partial','UNKNOWN')])
def test_sealed_snapshot_to_engine(mode, expected):
 from peaso.snapshot import make_snapshot
 from tests.archived_check_contract import evaluate_snapshot
 value=body()
 if mode=='legacy':value={'subject':{'digest':DIGEST}}
 if mode=='foreign_digest':value['critical']['image']['docker-manifest-digest']='sha256:'+'c'*64
 image,index,artifact=facts(json.dumps(value))
 if mode=='bad_signature':artifact['signature']=base64.b64encode(b'not-a-signature').decode()
 collections=[collection for rows in index['collections'].values()for collection in rows]
 if mode=='foreign_scope':collections[1]['scope']='999999999999/'+REGION
 if mode=='partial':collections[1]['status']='partial'
 # A foreign collection needs an explicitly selected foreign scope to be a
 # valid snapshot, but must never satisfy the local image's provenance.
 scopes=[SCOPE]+([collections[1]['scope']]if mode=='foreign_scope'else [])
 snapshot=make_snapshot('aws',scopes,collections,metadata=index['context']['metadata'])
 findings=evaluate_snapshot(snapshot,checks=[CHECK])['findings']
 assert len(findings)==1
 assert findings[0]['status']==expected

@pytest.mark.parametrize('optional',[{}, {'creator':'external-cosign','unsupported-future-claim':{'nested':True}}])
def test_optional_object_claims_are_not_rewritten_or_required(optional):
 value=body();value['optional']=optional
 image,index,_=facts(json.dumps(value));assert evaluate(image,index)=='PASS'

@pytest.mark.parametrize('payload',[
 '{"critical":{},"optional":{},"optional":null}',
 json.dumps(body()).replace('"docker-manifest-digest":','"docker-manifest-digest":"sha256:wrong","docker-manifest-digest":'),
 json.dumps(body()).replace('"optional": null','"optional":{"nan":NaN}'),
 json.dumps(body()).replace('"optional": null','"optional":{"infinite":Infinity}')])
def test_ambiguous_or_non_json_bytes_never_verify(payload):
 image,index,_=facts(payload);assert evaluate(image,index)=='UNKNOWN'
'''

CASES = ['test_official_cosign_payload_verifies_original_signed_bytes[False]', 'test_official_cosign_payload_verifies_original_signed_bytes[True]', 'test_schema_adapter_must_not_reserialize_signed_payload', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[foreign_digest-FAIL]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[foreign_subject-FAIL]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[wrong_type-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[bad_signature-FAIL]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[unapproved_key-FAIL]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[invalid_signature_encoding-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[missing_trust-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[bad_key-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[legacy_shape-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[critical_list-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[critical_none-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[image_list-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[image_none-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[digest_number-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[digest_invalid-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[identity_list-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[reference_number-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[type_number-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[invalid_json-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[body_list-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[duplicate_critical-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[foreign_collection-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[foreign_wrapper-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[partial-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[unknown_critical-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[unknown_image-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[unknown_identity-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[unknown_top-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[optional_list-UNKNOWN]', 'test_invalid_untrusted_or_foreign_evidence_does_not_verify[capital_digest-UNKNOWN]', 'test_docker_reference_is_not_a_repository_trust_policy', 'test_sealed_snapshot_to_engine[official-PASS]', 'test_sealed_snapshot_to_engine[legacy-UNKNOWN]', 'test_sealed_snapshot_to_engine[foreign_digest-FAIL]', 'test_sealed_snapshot_to_engine[bad_signature-FAIL]', 'test_sealed_snapshot_to_engine[foreign_scope-UNKNOWN]', 'test_sealed_snapshot_to_engine[partial-UNKNOWN]', 'test_optional_object_claims_are_not_rewritten_or_required[optional0]', 'test_optional_object_claims_are_not_rewritten_or_required[optional1]', 'test_ambiguous_or_non_json_bytes_never_verify[{"critical":{},"optional":{},"optional":null}]', 'test_ambiguous_or_non_json_bytes_never_verify[{"critical": {"identity": {"docker-reference": "123456789012.dkr.ecr.us-east-1.amazonaws.com/workload"}, "image": {"docker-manifest-digest":"sha256:wrong","docker-manifest-digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "type": "cosign container image signature"}, "optional": null}]', 'test_ambiguous_or_non_json_bytes_never_verify[{"critical": {"identity": {"docker-reference": "123456789012.dkr.ecr.us-east-1.amazonaws.com/workload"}, "image": {"docker-manifest-digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "type": "cosign container image signature"}, "optional":{"nan":NaN}}]', 'test_ambiguous_or_non_json_bytes_never_verify[{"critical": {"identity": {"docker-reference": "123456789012.dkr.ecr.us-east-1.amazonaws.com/workload"}, "image": {"docker-manifest-digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "type": "cosign container image signature"}, "optional":{"infinite":Infinity}}]']

@pytest.fixture(scope="module")
def cosign_child_results(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    temporary = tmp_path_factory.mktemp("cosign-contract-child")
    test_file = temporary / "test_cosign_child.py"
    xml_file = temporary / "cosign.xml"
    test_file.write_text(CHILD_SOURCE)
    runner = """
import sys
sys.path.insert(0, sys.argv[1])
import pytest
raise SystemExit(pytest.main(['--noconftest', '-p', 'no:cacheprovider',
    sys.argv[2], '-q', '--junitxml=' + sys.argv[3]]))
"""
    child_env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    child_env.pop("PYTEST_PLUGINS", None)
    child_env.pop("PYTEST_ADDOPTS", None)
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", runner, str(root), str(test_file), str(xml_file)],
        cwd=root, env=child_env,
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    suites = ET.parse(xml_file).getroot()
    cases = list(suites.iter("testcase"))
    assert len(cases) == len(CASES) == 46
    results = {}
    for case in cases:
        assert case.get("name") not in results
        results[case.get("name")] = not any(
            case.find(tag) is not None for tag in ("failure", "error", "skipped"))
    assert set(results) == set(CASES)
    return results

@pytest.mark.parametrize("case", CASES)
def test_official_cosign_contract_in_isolated_child(case, cosign_child_results):
    assert cosign_child_results[case]
