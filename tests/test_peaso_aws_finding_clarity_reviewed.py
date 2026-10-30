"""Real-source guards and evaluator boundaries for 711 AWS copy corrections."""
from copy import deepcopy
import json
import hashlib
from pathlib import Path

import pytest

from peaso.checks import CHECK_ALIASES, CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.aws_finding_clarity_reviewed import ROWS, _digest
from peaso.checks.aws_finding_clarity_reviewed import SEVERITY_REVIEW

PACK = Path(__file__).resolve().parents[1] / "peaso/rulepacks"
REGISTRY = {check.id: check for check in CHECKS}
# fe6f7901 (#104) retired these exact overlapping reviewed ids as aliases of a
# surviving registered native check; their reviewed copy rows stay as history.
RETIRED_REVIEWED_ALIASES = {
    "aws.a.cloudwatch.cross_account_role_absent": "aws.claude2_a.cloudwatch.cross_account_sharing_role_absent",
    "aws.b.redshift.no_public_endpoint": "aws.cb.redshift.not_publicly_accessible",
    "aws.c2b.ecs.service_no_public_ip": "aws.c2b.ecs.awsvpc_service_no_public_ip",
    "aws.c2b.elasticache.cluster_public_subnet": "aws.c2b.elasticache.cluster_public_subnet_prowler",
}

# fe6f7901: (severity reviewed for the retired id, severity of its survivor).
RETIRED_PRIORITY_SEVERITIES = {
    "aws.a.cloudwatch.cross_account_role_absent": ("medium", "low"),
    "aws.b.redshift.no_public_endpoint": ("medium", "critical"),
    "aws.c2b.ecs.service_no_public_ip": ("high", "high"),
    "aws.c2b.elasticache.cluster_public_subnet": ("medium", "medium"),
}


def _registered(cid):
    """Resolve only the exact reviewed retirements; any other missing id fails."""
    if cid in RETIRED_REVIEWED_ALIASES:
        assert cid not in REGISTRY and CHECK_ALIASES[cid] == RETIRED_REVIEWED_ALIASES[cid]
        return REGISTRY[RETIRED_REVIEWED_ALIASES[cid]]
    return REGISTRY[cid]


@pytest.fixture(scope="module")
def remediations():
    found = {}
    for path in PACK.glob("remediation*.json"):
        rows = json.loads(path.read_text())
        if isinstance(rows, dict):
            for cid, value in rows.items():
                from peaso.checks.aws_native_status_description_overlay import ROWS as status_rows, remediation as status_remediation
                if cid in ROWS and cid in status_rows and _digest(value) == status_rows[cid]["remediation_base_sha256"]:
                    corrected = status_remediation(cid, value)
                    if _digest(corrected) == ROWS[cid]["remediation_base_sha256"]:
                        found[cid] = corrected
                if cid == "aws.cloudtrail.management_events" and cid in ROWS:
                    from peaso.checks.cloudtrail_management_description_overlay import remediation as trail_remediation
                    corrected = trail_remediation(value)
                    if _digest(corrected) == ROWS[cid]["remediation_base_sha256"]:
                        found[cid] = corrected
                if cid in ROWS and _digest(value) == ROWS[cid]["remediation_base_sha256"]:
                    found[cid] = value
    found.update({cid: None for cid, row in ROWS.items() if row["remediation_base_sha256"] == _digest(None)})
    assert set(found) == set(ROWS), "Reviewed original remediation rows must still exist"
    return found


def predicate_cases():
    output = []
    statuses = {"pass": "PASS", "fail": "FAIL", "missing": "UNKNOWN", "malformed": "UNKNOWN",
                "unknown": "UNKNOWN", "manual": "MANUAL", "not_applicable": "NOT_APPLICABLE"}
    for cid in sorted(ROWS):
        fixture = CASES.get(cid, {})
        for case, status in statuses.items():
            if case in fixture:
                output.append(pytest.param(cid, fixture[case], fixture.get(case + "_index", fixture.get("index", {})),
                                           fixture.get(case + "_expect", status), id=cid + ":" + case))
    return output


@pytest.mark.parametrize("cid,item,index,status", predicate_cases())
def test_existing_predicate_fixture_outcomes_are_preserved(cid, item, index, status):
    assert REGISTRY[cid].evaluate(deepcopy(item), deepcopy(index))[0] == status


def test_default_s3_encryption_absence_does_not_become_failure():
    check = REGISTRY["aws.s3.default_encryption"]
    assert check.evaluate({"Encryption": {"absent": True}}, {})[0] == "UNKNOWN"
    good = {"Encryption": {"ServerSideEncryptionConfiguration": {"Rules": [
        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}}
    status, evidence = check.evaluate(good, {})
    assert status == "PASS" and evidence["algorithms"] == ["AES256"]
    assert "existing object encryption was not collected" in evidence["semantics"]


# The four core AWS priorities were reviewed after the AWS native admissions,
# before the subsequent GCP admissions in 15842280dfb336f356497451d94ec46b2ba5d4ee.
# The accepted GCP hooks have independent tests/test_gcp_*_review_20261019.py
# coverage and docs/gcp-review/native-extension-integration.{json,md} provenance.
# Remove this EXACT appended block only; the original whole-file SHA256 below
# still binds all AWS callbacks, registration, severities and public metadata.
# Never split on an import marker alone: that would silently admit any new tail.
_REVIEWED_GCP_ADMISSIONS = """from . import gcp_workbench_review_20261019  # Native, policy-independent Workbench settings.
gcp_workbench_review_20261019.install()
from . import gcp_function_secret_review_20261019
gcp_function_secret_review_20261019.install()

from . import gcp_configuration_secret_review_20261019
gcp_configuration_secret_review_20261019.install()

from . import gcp_log_secret_review_20261019
gcp_log_secret_review_20261019.install()

from . import gcp_selected_object_secret_review_20261019
gcp_selected_object_secret_review_20261019.install()

from . import gcp_image_secret_review_20261019
gcp_image_secret_review_20261019.install()

from . import gcp_selected_archive_secret_review_20261019
gcp_selected_archive_secret_review_20261019.install()
from . import gcp_additional_literal_secret_review_20261019
gcp_additional_literal_secret_review_20261019.install()

from . import gcp_dataform_secret_review_20261019
gcp_dataform_secret_review_20261019.install()
from . import gcp_job_literal_secret_review_20261019
gcp_job_literal_secret_review_20261019.install()
from . import gcp_gke_literal_secret_review_20261019
gcp_gke_literal_secret_review_20261019.install()
from . import gcp_notebook_airflow_secret_review_20261019
gcp_notebook_airflow_secret_review_20261019.install()
from . import gcp_function_source_secret_review_20261019
gcp_function_source_secret_review_20261019.install()
from . import gcp_artifact_file_secret_review_20261019
gcp_artifact_file_secret_review_20261019.install()
from . import gcp_composer_source_secret_review_20261019
gcp_composer_source_secret_review_20261019.install()
from . import gcp_os_security_update_review_20261019
gcp_os_security_update_review_20261019.install()
from . import gcp_cloudsql_backup_alert_native
gcp_cloudsql_backup_alert_native.install_fixtures()
from . import gcp_cloudbuild_log_secret_review_20261019
gcp_cloudbuild_log_secret_review_20261019.install()

from . import gcp_appengine_source_secret_review_20261019
gcp_appengine_source_secret_review_20261019.install()

from . import gcp_cloudbuild_artifact_secret_review_20261019
gcp_cloudbuild_artifact_secret_review_20261019.install()

from . import gcp_clouddeploy_source_secret_review_20261019
gcp_clouddeploy_source_secret_review_20261019.install()

from . import gcp_sourcerepo_secret_review_20261019
gcp_sourcerepo_secret_review_20261019.install()
"""


# The separately accepted managed-default integrity correction is reversed
# exactly for the historical AWS priority source receipt, never repinned.
_MANAGED_VERSION_SUCCESSOR = 'def aws_documents(item):\n    documents, unresolved = [], 0\n    try:\n        direct = optional(item, "PolicyDocument", None)\n        if "PolicyDocument" in item:\n            documents.append(direct)\n    except (Unavailable, ValueError):\n        unresolved += 1\n    if "PolicyVersionList" in item or "DefaultVersionId" in item:\n        try:\n            default_id = get(item, "DefaultVersionId", str)\n            versions = list_of_objects(get(item, "PolicyVersionList", list))\n            version_ids = [get(version, "VersionId", str) for version in versions]\n            flags = [get(version, "IsDefaultVersion", bool) for version in versions]\n            if (not default_id.strip() or any(not ident.strip() for ident in version_ids)\n                    or len(version_ids) != len(set(version_ids))):\n                raise Unavailable("managed policy version identity is incomplete or duplicated")\n            selected = [version for version, flag in zip(versions, flags) if flag]\n            if len(selected) != 1 or get(selected[0], "VersionId", str) != default_id:\n                raise Unavailable("managed policy default version is inconsistent")\n            # Do not consume any managed document until all version identities\n            # and flags agree with the policy\'s selected native default.\n            documents.append(get(selected[0], "Document"))\n        except (Unavailable, ValueError):\n            unresolved += 1\n    for key in ("UserPolicyList", "RolePolicyList", "GroupPolicyList"):\n        try:\n            policies = list_of_objects(optional(item, key, [], list))\n        except (Unavailable, ValueError):\n            unresolved += 1\n            continue\n        for policy in policies:\n            try:\n                documents.append(get(policy, "PolicyDocument"))\n            except (Unavailable, ValueError):\n                unresolved += 1\n    return documents, unresolved\n'
_MANAGED_VERSION_PREDECESSOR = 'def aws_documents(item):\n    documents, unresolved = [], 0\n    try:\n        direct = optional(item, "PolicyDocument", None)\n        if "PolicyDocument" in item:\n            documents.append(direct)\n    except (Unavailable, ValueError):\n        unresolved += 1\n    try:\n        versions = list_of_objects(optional(item, "PolicyVersionList", [], list))\n    except (Unavailable, ValueError):\n        versions, unresolved = [], unresolved + 1\n    for version in versions:\n        try:\n            if get(version, "IsDefaultVersion", bool):\n                documents.append(get(version, "Document"))\n        except (Unavailable, ValueError):\n            unresolved += 1\n    for key in ("UserPolicyList", "RolePolicyList", "GroupPolicyList"):\n        try:\n            policies = list_of_objects(optional(item, key, [], list))\n        except (Unavailable, ValueError):\n            unresolved += 1\n            continue\n        for policy in policies:\n            try:\n                documents.append(get(policy, "PolicyDocument"))\n            except (Unavailable, ValueError):\n                unresolved += 1\n    return documents, unresolved\n'
_MANAGED_VERSION_SUCCESSOR_SHA256 = '8815ab5071a819f27ff1d00fd57dde6dd9c416dd5c93e1ac10da54b3c26efe40'


# Source files edited after the priority review (alias retirements in fe6f7901,
# fail-closed detail status in a9d62a01 and later reviewed native edits). The
# severities above are still compared with the live registry for every id.
PRIORITY_SOURCE_SUCCESSORS = {
    "peaso/checks/__init__.py": {
        "historical_sha256": "18312adcf5e0e32f12c5aa182d4f9886dacf5c64afa71f3e11540302096247b4",
        "current_sha256": "9e30d82d62313b05b8b0c8c83b4c3bb1de339563dd8976fc2d59929cce4587ae"},
    "peaso/checks/aws_a_cloudwatch.py": {
        "historical_sha256": "7a1676c0684b5a13873664dee3ede626c05dc890c0af23009e09365dc1fdd05e",
        "current_sha256": "7cae38304bca4ec34d34d7604f44af5f07c084a49987c204e63988276c5b67f9"},
    "peaso/checks/aws_a_s3.py": {
        "historical_sha256": "c52c29a395fa7a92d05679850b5ac69cdc44e84a59a70080f7d864cb4f4bba2c",
        "current_sha256": "ff02961210c23380ae79b3ea983e7734f5205ef49acb0a3e00bbb5f7eea3916d"},
    "peaso/checks/batch_remaining_aws.py": {
        "historical_sha256": "93bd371abb6c9c16dcaec0c813eebf0f3fb7e6d71b9a6b12a8b6aaf99ecc3f93",
        "current_sha256": "b4130e72a349b150a6cfe567d4c1e58abcc76c07810dfc5bab77af5af26dac81"},
    "peaso/checks/claude2_aws_b_compute.py": {
        "historical_sha256": "4c4059e8eaec5777274a9affdd3d64608d9c78970b117d6b2fa8383b72e69a4e",
        "current_sha256": "8b061001de6711d59ac584c15f09a703fa2f41b8455838bba714d862634db4ed"},
    "peaso/checks/claude2_aws_b_data.py": {
        "historical_sha256": "5916d6a78cffd92a3aaacf9d1498df334170f43e760752ca28f470f5c19689b8",
        "current_sha256": "cce4938d49ca2d51394fb19b380eb50e97d007938822ac3595dd359178d7e102"},
    "peaso/checks/claude_aws_a_iam.py": {
        "historical_sha256": "671b51dad0a630377080f1f74a41eb6b0afa481fae9bd29c4c7da5c6d9dc8eaf",
        "current_sha256": "5a1f81ead33c02f957be1d1ee2461afaa7a07b2cb62ec8997dcbc377f3c5c687"},
    "peaso/checks/claude_aws_a_iam_prowler.py": {
        "historical_sha256": "c0235336e05c8f7a2eff651afd5698938cd3c9ee163599d07037ac7ae022d23e",
        "current_sha256": "36e91dbfdc78dc4970dad0085ee83fb856bcc12b9395e4c1945b7d079e6944fb"},
    "peaso/checks/claude_aws_a_s3.py": {
        "historical_sha256": "18c38c1034a800039d7a11eec8c0d281d42c63051c1d90d02b1a0ba15a4e1160",
        "current_sha256": "154081adf1d201d3616dbf1f3741c84bed0d16ecdf3397733473d367a34373cf"},
    "peaso/checks/claude_aws_b_messaging.py": {
        "historical_sha256": "48c8fd57ba42ed480b33f9dc6b2dcefe2fdbf18d53aaad4f987fdc2807dd687c",
        "current_sha256": "3c01e5e55f6bb580757ad65dd8239f0edd21943b3539f1d2ae4d4c9168fb4084"},
}


def _reviewed_priority_source(source):
    text = (PACK.parents[1] / source["file"]).read_bytes()
    if source["file"] == "peaso/checks/__init__.py":
        # Retain the historical priority source. Only these exact reviewed
        # integration epochs may contribute additional registration statements.
        # Reverse only the exact admitted metadata, no-op and CPU aliases.
        # Keep the original JIT/AI/priority source chain and final pin below.
        for current_sha, previous_sha, current, previous in (('e828e145917364fcd20a5a2d6de7e24eb304eee5698fea1cb1bed8669fef01c6', 'c5c65a53e4b668e7517e8b533cccc0ec344d9816cd5222d061bb76951fb234ce', b'from . import azure_metadata_only_shared_successor_20261020 as _deployed_ai_shared_source\n', b'from . import collector_noop_authorization_shared_successor_20261020 as _deployed_ai_shared_source\n'), ('c5c65a53e4b668e7517e8b533cccc0ec344d9816cd5222d061bb76951fb234ce', '9f11ecd17eb89c90d7ec51a51d7d32bc345dae8807fe1c01727a99dcaf36325b', b'from . import collector_noop_authorization_shared_successor_20261020 as _deployed_ai_shared_source\n', b'from . import native_admission_cpu_shared_successor_20261020 as _deployed_ai_shared_source\n'), ('9f11ecd17eb89c90d7ec51a51d7d32bc345dae8807fe1c01727a99dcaf36325b', 'e748d213ccfac7a01b820803d27a893e40d884cdc1f2126fb45e917865d2783b', b'from . import native_admission_cpu_shared_successor_20261020 as _deployed_ai_shared_source\n', b'from . import azure_jit_parent_type_shared_successor_20261020 as _deployed_ai_shared_source\n')):
            if hashlib.sha256(text).hexdigest() == current_sha:
                assert text.count(current) == 1
                text = text.replace(current, previous, 1)
                assert hashlib.sha256(text).hexdigest() == previous_sha
        if hashlib.sha256(text).hexdigest() == 'e748d213ccfac7a01b820803d27a893e40d884cdc1f2126fb45e917865d2783b':
            current = b'from . import azure_jit_parent_type_shared_successor_20261020 as _deployed_ai_shared_source\n'
            previous = b'from . import aws_deployed_ai_shared_successor_20261020 as _deployed_ai_shared_source\n'
            assert text.count(current) == 1
            text = text.replace(current, previous, 1)
        assert hashlib.sha256(text).hexdigest() == '45f746d9a89d4f2b53d694642e4c5b538907fb3fed6e7c69277909d4e13d77c7'
        admission = b'\nfrom . import aws_ai_recheck_corrections_20261020\naws_ai_recheck_corrections_20261020.install()\n'
        assert hashlib.sha256(admission).hexdigest() == 'e4587748dcdaad138267aa3d69603bf665b6f26e3132bc782504c33bb908dc3f'
        assert text.endswith(admission) and text.count(admission) == 1
        text = text[:-len(admission)]
        successor = _MANAGED_VERSION_SUCCESSOR.encode()
        assert hashlib.sha256(successor).hexdigest() == _MANAGED_VERSION_SUCCESSOR_SHA256
        assert text.count(successor) == 1
        text = text.replace(successor, _MANAGED_VERSION_PREDECESSOR.encode(), 1)
        suffix = _REVIEWED_GCP_ADMISSIONS.encode()
        assert text.count(suffix) == 1
        later = text[text.index(suffix) + len(suffix):]
        assert hashlib.sha256(later).hexdigest() == '725be0902f1f18fba3ad436326b41535f55370edcd7c183d6c51a3a93ef984af'
        text = text[:-len(later)]
        assert text.count(suffix) == 1 and text.endswith(suffix)
        text = text[:-len(suffix)]
    return text


def test_priority_review_keeps_administrative_ports_and_public_data_serious():
    assert SEVERITY_REVIEW["aws.claude_a.vpc.sg_no_world_ssh"]["recommended"] == "high"
    assert SEVERITY_REVIEW["aws.claude_a.vpc.sg_no_world_rdp"]["recommended"] == "high"
    assert SEVERITY_REVIEW["aws.c2b.elbv2.internet_facing_open_sg"]["recommended"] == "medium"
    assert SEVERITY_REVIEW["aws.gap.s3.no_public_write_acl_or_policy"]["recommended"] == "critical"
    assert SEVERITY_REVIEW["aws.claude_a.s3.restrict_public_read"]["recommended"] == "critical"
    assert SEVERITY_REVIEW["aws.c2b.cloudfront.custom_ssl_certificate"]["recommended"] == "info"
    assert SEVERITY_REVIEW["aws.c2b.dms.public_instance_open_sg"]["recommended"] == "high"
