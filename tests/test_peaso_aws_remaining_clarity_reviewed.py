"""Review contracts and genuine registered predicate fixtures for AWS guidance."""
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS, CHECK_ALIASES
from peaso.checks.fixtures import CASES
from peaso.checks.aws_remaining_clarity_reviewed import ROWS, _digest, description
from peaso.checks.aws_remaining_finding_summary import evidence_summary

ROOT=Path(__file__).resolve().parents[1]
CHECK_BY_ID={c.id:c for c in CHECKS}
RETIRED_SNS='aws.cb.sns.policy_prohibit_public_access_perimeter'
ACTIVE_SNS='aws.cb.sns.policy_no_unrestricted_wildcard'


def _current_id(cid):
    if cid == RETIRED_SNS:
        assert CHECK_ALIASES[cid] == ACTIVE_SNS
        return ACTIVE_SNS
    return cid


def _retired_sns_source():
    old = ROWS[RETIRED_SNS]['reviewed_binding']
    current = ROWS[ACTIVE_SNS]['reviewed_binding']
    relative = 'tests/fixtures/aws_retired_sns_perimeter_source_20261022.py.txt'
    source = (ROOT / relative).read_bytes()
    assert old['module'] == current['module'] == 'peaso.checks.claude_aws_b_messaging'
    assert old['source_qualname'] == 'sns_public_x' and current['source_qualname'] == 'sns_public_c'
    assert hashlib.sha256(source).hexdigest() == old['predicate_sources'][old['module'] + '.sns_public_x']
    for name, digest in old['predicate_sources'].items():
        if name != old['module'] + '.sns_public_x':
            assert current['predicate_sources'][name] == digest

@pytest.fixture(scope='module')
def originals():
    descriptions=json.loads((ROOT/'peaso/rulepacks/check_descriptions.json').read_text())['checks']
    rems={cid:None for cid,r in ROWS.items() if r['remediation_base_sha256']==_digest(None)}
    for path in (ROOT/'peaso/rulepacks').glob('remediation*.json'):
        rows=json.loads(path.read_text())
        if isinstance(rows,dict):
            for cid,value in rows.items():
                if cid in ROWS and _digest(value)==ROWS[cid]['remediation_base_sha256']:rems[cid]=value
    assert set(rems)==set(ROWS)
    return descriptions,rems


def _stable(v):
    if callable(v):return {'callable':v.__qualname__}
    if isinstance(v,dict):return {str(k):_stable(x) for k,x in sorted(v.items())}
    if isinstance(v,(list,tuple)):return [_stable(x) for x in v]
    if isinstance(v,(set,frozenset)):return sorted(_stable(x) for x in v)
    if isinstance(v,(str,int,float,bool)) or v is None:return v
    if hasattr(v,'isoformat') and v.__class__.__module__=='datetime':return {'datetime':v.isoformat()}
    return {'type':type(v).__name__}


# These native corrections were accepted after the copy-only review. Reconstruct
# only their exact inverse, then compare with the ORIGINAL immutable binding.
# The successor hash also rejects any additional, unreviewed function change.
# Acceptance: docs/aws-review/{network-sdk-closure-review,data-sdk-closure-review,
# services-closure-review,network-semantic-review}.{json,md}; integrated in
# 15842280dfb336f356497451d94ec46b2ba5d4ee. This does not execute old predicates.
_NATIVE_SOURCE_SUCCESSORS = {
    # Approved managed-default identity fix: retain the original reviewed digest.
    'peaso.checks.aws_documents': (
        '8815ab5071a819f27ff1d00fd57dde6dd9c416dd5c93e1ac10da54b3c26efe40',
        'def aws_documents(item):\n    documents, unresolved = [], 0\n    try:\n        direct = optional(item, "PolicyDocument", None)\n        if "PolicyDocument" in item:\n            documents.append(direct)\n    except (Unavailable, ValueError):\n        unresolved += 1\n    if "PolicyVersionList" in item or "DefaultVersionId" in item:\n        try:\n            default_id = get(item, "DefaultVersionId", str)\n            versions = list_of_objects(get(item, "PolicyVersionList", list))\n            version_ids = [get(version, "VersionId", str) for version in versions]\n            flags = [get(version, "IsDefaultVersion", bool) for version in versions]\n            if (not default_id.strip() or any(not ident.strip() for ident in version_ids)\n                    or len(version_ids) != len(set(version_ids))):\n                raise Unavailable("managed policy version identity is incomplete or duplicated")\n            selected = [version for version, flag in zip(versions, flags) if flag]\n            if len(selected) != 1 or get(selected[0], "VersionId", str) != default_id:\n                raise Unavailable("managed policy default version is inconsistent")\n            # Do not consume any managed document until all version identities\n            # and flags agree with the policy\'s selected native default.\n            documents.append(get(selected[0], "Document"))\n        except (Unavailable, ValueError):\n            unresolved += 1\n    for key in ("UserPolicyList", "RolePolicyList", "GroupPolicyList"):\n        try:\n            policies = list_of_objects(optional(item, key, [], list))\n        except (Unavailable, ValueError):\n            unresolved += 1\n            continue\n        for policy in policies:\n            try:\n                documents.append(get(policy, "PolicyDocument"))\n            except (Unavailable, ValueError):\n                unresolved += 1\n    return documents, unresolved\n',
        'def aws_documents(item):\n    documents, unresolved = [], 0\n    try:\n        direct = optional(item, "PolicyDocument", None)\n        if "PolicyDocument" in item:\n            documents.append(direct)\n    except (Unavailable, ValueError):\n        unresolved += 1\n    try:\n        versions = list_of_objects(optional(item, "PolicyVersionList", [], list))\n    except (Unavailable, ValueError):\n        versions, unresolved = [], unresolved + 1\n    for version in versions:\n        try:\n            if get(version, "IsDefaultVersion", bool):\n                documents.append(get(version, "Document"))\n        except (Unavailable, ValueError):\n            unresolved += 1\n    for key in ("UserPolicyList", "RolePolicyList", "GroupPolicyList"):\n        try:\n            policies = list_of_objects(optional(item, key, [], list))\n        except (Unavailable, ValueError):\n            unresolved += 1\n            continue\n        for policy in policies:\n            try:\n                documents.append(get(policy, "PolicyDocument"))\n            except (Unavailable, ValueError):\n                unresolved += 1\n    return documents, unresolved\n',
    ),
    'peaso.checks.aws_b_apigateway._presence.<locals>.evaluate': (
        '684156f198306a7b99191532641b6c8c211ca4e6b7bd89a0800eee77930479b7',
        'return result(not value, field=field,',
        'return result(value is None, field=field,',
    ),  # SDK-STAGE-EMPTY-REFERENCE: empty native references must fail.
    'peaso.checks.aws_b_apigateway.method_settings': (
        '4c69f081e107ab29a504888474ccbe591e97424e5c65eb877eebd08d7d3f1b2e',
        '    if "/*/*" in settings and "*/*" in settings:\n'
        '        raise ValueError("duplicate wildcard method settings")\n'
        '    wildcard = settings.get("/*/*", settings.get("*/*", {}))\n',
        '    wildcard = settings.get("*/*", {})\n',
    ),  # SDK-STAGE-NATIVE-METHOD-KEYS: honor AWS's documented slash key.
    'peaso.checks.claude_aws_b_common.selection_resources': (
        '59ccc20398073cddc5f49304a8170d4ce3f68ade98de87d032aa9556e5777826',
        '            if optional(body, "NotResources", [], list) or optional(body, "Conditions", {}, dict):\n'
        '                raise Unavailable("backup selection exclusions or conditions require separate matching proof")\n',
        '',
    ),  # D-BACKUP-EXCLUSION: an included ARN alone cannot prove selection.
    'peaso.checks.claude_aws_b_messaging._topic_policy': (
        '4f79e5eba810e50d668bacd2d9dc5daf48e882dcb68d1a5c2b48ac5bef96b4a3',
        '    # GetTopicAttributes properties depend on caller authorization. TopicArn\n'
        '    # authenticates identity, but cannot prove an omitted policy is absent.\n',
        '    if "Policy" not in attrs and "Policy" not in attrs.get("_coverage", {}):\n'
        '        return None\n',
    ),  # sns-omitted-policy: omitted authorization-dependent facts are UNKNOWN.
    'peaso.checks.claude_aws_a_ec2.eni_unused': (
        'a10ea462234541402fa89f01dea35a75b048b7f64f34450e4680877cb4bf5595',
        '    if status not in ("available", "associated", "attaching", "in-use", "detaching"):\n'
        '        raise Unavailable("unrecognized network interface status")\n',
        '',
    ),  # ENI-status-enum: reject unrecognized native status values.
}


def _reviewed_predicate_digest(key, function):
    source = inspect.getsource(function)
    if key in _NATIVE_SOURCE_SUCCESSORS:
        successor_hash, after, before = _NATIVE_SOURCE_SUCCESSORS[key]
        assert hashlib.sha256(source.encode()).hexdigest() == successor_hash, key
        assert source.count(after) == 1, key
        source = source.replace(after, before, 1)
    return hashlib.sha256(source.encode()).hexdigest()


def _cases(cid):
    # These two existing registry fixtures live in test_peaso_checks.py.
    if cid=='aws.iam.no_full_admin':
        return {'pass':{'PolicyDocument':{'Statement':[]}},'fail':{'PolicyDocument':{'Statement':[{'Effect':'Allow','Action':'*','Resource':'*'}]}}}
    if cid=='aws.ec2.restrict_internet_ingress':
        return {'pass':{'IpPermissions':[]},'fail':{'IpPermissions':[{'IpProtocol':'tcp','FromPort':22,'ToPort':22,'IpRanges':[{'CidrIp':'0.0.0.0/0'}]}]}}
    return CASES[_current_id(cid)]

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_registered_positive_negative_or_explicit_review_branches(cid):
    cases=_cases(cid)
    branches=['pass','fail']
    if cid in {'aws.b.acm.pending_validation_review','aws.claude2_a.config.aggregation_authorization_trusted','aws.claude2_a.dlm.snapshot_sharing_trusted_accounts'}:
        branches=['pass','manual']
    for branch in branches:
        status,evidence=CHECK_BY_ID[_current_id(cid)].evaluate(deepcopy(cases[branch]),deepcopy(cases.get(branch+'_index',cases.get('index',{}))))
        expected='UNKNOWN' if cid=='aws.c2b.ecs.container_instance_in_vpc' and branch=='fail' else branch.upper()
        assert status==expected,(cid,branch,status,evidence)
        finding={'provider':'aws','status':status,'check_id':cid,'evidence':evidence};before=deepcopy(finding)
        summary=evidence_summary(finding)
        if status != 'FAIL':assert summary is None
        if summary:assert isinstance(summary,str) and len(summary)<300
        assert finding==before


def test_unknown_unowned_and_nonfailure_observations_are_not_fabricated():
    cid=next(iter(ROWS))
    for status in ['PASS','UNKNOWN','MANUAL','DENIED','NOT_APPLICABLE']:
        assert evidence_summary({'provider':'aws','status':status,'check_id':cid,'evidence':{}}) is None
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':None}) is None
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':'other','evidence':{}}) is None
    assert evidence_summary({'provider':'gcp','status':'FAIL','check_id':cid,'evidence':{}}) is None
    value={'nested':[]};result=description('unreviewed',value);result['nested'].append(1)
    assert value['nested']==[]

@pytest.mark.parametrize('port',[22,443,5432])
def test_broad_ingress_observation_names_protocol_port_without_claiming_reachability(port):
    finding={'provider':'aws','status':'FAIL','check_id':'aws.ec2.restrict_internet_ingress','evidence':{'internet_ingress':[{'protocol':'tcp','from_port':port,'to_port':port,'source':'0.0.0.0/0'}]}}
    assert evidence_summary(finding)==f'The security group allows Internet ingress to tcp/{port}.'


def test_longer_kinesis_retention_is_not_described_as_short_retention():
    finding={'provider':'aws','status':'FAIL','check_id':'aws.cb.kinesis.retention_exactly_168h','evidence':{'retention_hours':8760}}
    assert evidence_summary(finding)=='Kinesis retention is 8760 hours; this profile prefers exactly 168.'


def test_aws_managed_key_does_not_become_plaintext_claim():
    finding={'provider':'aws','status':'FAIL','check_id':'aws.cb.sqs.cmk_encryption','evidence':{'kms_master_key_id':'alias/aws/sqs'}}
    assert evidence_summary(finding)=='The queue declares the AWS-managed SQS KMS alias; this profile prefers a customer-managed key.'


def test_redshift_disabled_and_encrypted_missing_reference_are_distinct_observations():
    finding={'provider':'aws','status':'FAIL','check_id':'aws.b.redshift.kms_key_declared','evidence':{'encrypted':False}}
    assert evidence_summary(finding)=='The Redshift cluster declares storage encryption disabled.'
    finding['evidence']={'encrypted':True,'kms_key_id':None}
    assert evidence_summary(finding)=='The encrypted Redshift cluster has no KMS key reference in the complete native inventory.'


def test_expired_certificate_uses_past_tense():
    finding={'provider':'aws','status':'FAIL','check_id':'aws.b.acm.expiry_thirty_days','evidence':{'remaining_calendar_days':-4}}
    assert evidence_summary(finding)=='The certificate expired 4 calendar days before the snapshot date.'


@pytest.mark.parametrize('cid',sorted(ROWS))
@pytest.mark.parametrize('evidence',[{}, {'unrelated':True}, {'internet_ingress':[None]}, {'configured':True}, {'short_retention_rules':[{'delete_after_days':'7'}]}])
def test_incomplete_or_malformed_facts_do_not_get_static_failure_claims(cid,evidence):
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':evidence}) is None

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_native_positive_evidence_relabelled_fail_does_not_invent_weakness(cid):
    fixture=_cases(cid)
    status,evidence=CHECK_BY_ID[_current_id(cid)].evaluate(deepcopy(fixture['pass']),deepcopy(fixture.get('pass_index',fixture.get('index',{}))))
    if status=='PASS':assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':evidence}) is None
