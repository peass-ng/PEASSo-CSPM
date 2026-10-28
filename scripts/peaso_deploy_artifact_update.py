"""Private proposal for a distinct serial-29 artifact-update approval route.

Pure offline reviewer only. It does not plan, apply, publish, or call AWS. This
is deliberately outside frozen source 496eef8c pending coordinator review.
"""
from __future__ import annotations

from peaso import deployment
from collections import Counter
from copy import deepcopy
import base64
import hashlib
import io
import json
import re
import stat
import zipfile

from scripts import peaso_deploy_current_update as current
from scripts import peaso_deploy_successor_update as old_successor


ACCOUNT = deployment.value("account_id")
BACKEND = current.BACKEND
LINEAGE = "07a58930-bf9f-7350-17e9-5e4d275a308a"
SERIAL = 29
COUNT = 75
ADDRESS_SHA = "5dbfcee92b413b0da4a42cda161ff23022f84fd66c2a5c287c34ae3f3d9474b6"
BASELINE_RAW_SHA = "920f27350dff517c85ccefa7e04a51ab8e93d60060155a53ecda6fad83b04285"
BASELINE_CANONICAL_SHA = "abf950690c501e4a7dedd428ba6171c6e7a2313dd32dffab50189444a17c1514"
SOURCE_VERSION = "496eef8cca4155316263c73feb1d83b99c238e7d5dc5d36c6e3cf687f61b5930"
SOURCE_RELEASE_SHA = "394d03b29242ad309df155b79efee9e903714232becfd97ac22a9c0ee11f4af1"
SOURCE_ZIP_SHA = "9ef901874da33452d14e6991dbe9783e665716c678dbcb8f0d1683ad03033fa1"
SOURCE_API_SHA = "4e2f4a4c778cd6600a6a00f053d579298cb498f2deef86019b8038eee271c4d6"
SOURCE_FRONTEND_SHA = "23995811a3fe69916f6103bb1fbe8e0ff359a3d2b3ac748086f30cd289088646"
SOURCE_IMAGE = ((("DEPLOYMENT_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/hacktricks-cspm-worker"
                "@sha256:084d16c716c8d7a322fab8ad5ae24b9cabe93ed5fca2db30491056e5f28dca54").replace("DEPLOYMENT_ACCOUNT_ID", deployment.value("account_id"))))
TARGET_CHECK = ("resource", "aws_s3_object.customer_role_template")
SIX_ACTIONS = old_successor.UPDATE_ACTIONS
PARENT_POLICY = {"aws_iam_role.api", "aws_iam_role.workflow", "aws_s3_bucket.templates[0]"}
TAG_DRIFT = {
    'aws_ecs_task_definition.tasks["collector"]',
    'aws_ecs_task_definition.tasks["analyzer"]',
    'aws_s3_object.customer_role_template["04fbe795580c205cb86e6ad71a73c52935628bd43c5d5ee398b4333b2155748a"]',
    'aws_s3_object.customer_role_template["25b895c00a3fad47f390e4946c83f6e47487c8e52e8342cf136d1a1eb1c1ea17"]',
    'aws_s3_object.customer_role_template["9254e0c0c0a7519c7a0a0c128e9d147d799dba3ca9cf9ff76902fcb4cd5ab08f"]',
}
DRIFT_ALLOWLIST = PARENT_POLICY | TAG_DRIFT
# Measured source496: 1,299 members, 157,289,453 uncompressed bytes,
# 35,167,907-byte largest member, 18,331,641-byte archive. Adding the public
# compliance ledgers/pinned compiler inputs measured 1,450 members,
# 228,628,579 uncompressed bytes and a 27,217,714-byte archive.
# Current reviewed cohort: 1,613 source files plus release.json, 240,980,294 expanded bytes.
MAX_SOURCE_MEMBERS = 1866
MAX_SOURCE_MEMBER_BYTES = 40_000_000
MAX_SOURCE_UNCOMPRESSED_BYTES = 250_000_000
MAX_SOURCE_ARCHIVE_BYTES = 32_000_000
BASELINE_RUNTIME_MEMBERS = 751
# The reviewed source832 addition after source496. Legacy candidates carry
# either the baseline runtime set or the baseline plus these exact bytes.
APPROVED_RUNTIME_ADDITIONS = {
    "peaso/checks/aws_config_recording.py": "50800c1a5c30aa407d0791d4416cc473ea19c3d03f584a2a4a2cfa694d2eabec",
}
# The next reviewed successor includes all six of these source members.
# No partial set or extra runtime member is admitted.
APPROVED_SUCCESSOR_RUNTIME_ADDITIONS = {
    **APPROVED_RUNTIME_ADDITIONS,
    "peaso/checks/aws_backup_plan_frequency.py": "0f40ddcace19dded128369f32efad6d72e36a8a95590073beb8cada2d4cff08d",
    "peaso/checks/central_native_fixtures.py": "2b9665b5b12e164a76b0982bc055857be82cd72d09eafcb8588bc96ead0503f4",
    "peaso/checks/gcp_data_access.py": "ce997648d524475e848aff41353b99f3add7075eca451146a89a7998da9f51c5",
    "peaso/checks/k8s_namespace_policy_presence.py": "47f64b995e1f5ca9b6db72ff62a7a4594521448f2a1fbba174d453251698a2b2",
    "peaso/collectors/aws_policy.py": "a3003f6c3930bd5f23523cc6128192ee6a22891a47035df922e34498ada0429d",
    "peaso/gcp_data_access_policy.py": "03167a5cf56583a9ae4efb08aba2beb24fa0e62fcafded1b6f7f47181cb5d4c7",
}
# Exact next-batch runtime additions over the original 751-member source496 baseline.
# This is a complete path/hash set; missing, altered or extra members are rejected.
APPROVED_BATCH_RUNTIME_ADDITIONS = {
    "peaso/checks/aws_backup_plan_frequency.py": "0f40ddcace19dded128369f32efad6d72e36a8a95590073beb8cada2d4cff08d",
    "peaso/checks/aws_config_recording.py": "50800c1a5c30aa407d0791d4416cc473ea19c3d03f584a2a4a2cfa694d2eabec",
    "peaso/checks/batch_remaining_aws.py": "197ccf540f23e9373d8db281bf1544d2d2bba793be3738ff214e9a6038d813b2",
    "peaso/checks/batch_remaining_azure.py": "82e39d57beef687761098e206457e5e7f7e25a792fc9fcc8600d809f4737b136",
    "peaso/checks/batch_remaining_azure_vm_storage.py": "11f0353505ec70bb7cbc1f6f72add7ceb664fcbd01d05bd8018b2063dd09babb",
    "peaso/checks/batch_remaining_gcp.py": "4f93aebdb8c4fabb603cc122b7a390bc153abc6039035c4a0e780be708aed870",
    "peaso/checks/batch_remaining_k8s.py": "0f0c92c50a05e92bfd0357767066e4e481c03320c2f582ff10194d8cc25dd578",
    "peaso/checks/central_batch_fixtures.json": "ed8c38a1f719d740f99cc864a61400c7fc95575569aa560c59e15c1581261a4f",
    "peaso/checks/central_native_fixtures.py": "2b9665b5b12e164a76b0982bc055857be82cd72d09eafcb8588bc96ead0503f4",
    "peaso/checks/compliance_next_k8s.py": "d0184f0934601aaa4682c07d1f0dbfa1b40fa2e9090ce2ca53ca413471b96dfc",
    "peaso/checks/gcp_data_access.py": "ce997648d524475e848aff41353b99f3add7075eca451146a89a7998da9f51c5",
    "peaso/checks/k8s_namespace_policy_presence.py": "47f64b995e1f5ca9b6db72ff62a7a4594521448f2a1fbba174d453251698a2b2",
    "peaso/checks/wafv2_basic.py": "b300d867db2803793f56b23dbd2c51751435236428267e12e23c398c99316437",
    "peaso/collectors/aws_codebuild_redaction.py": "d3f487ca28fae5563b2cd5839f760dbd742e859388ab0646dc762d5c7826f18d",
    "peaso/collectors/aws_facts_v4_holds.py": "f1c230a3dce2c1178781997876edd76b7a17055c05ad624168cb01eabf591a01",
    "peaso/collectors/aws_policy.py": "a3003f6c3930bd5f23523cc6128192ee6a22891a47035df922e34498ada0429d",
    "peaso/collectors/batch_remaining_azure_vm_storage.py": "44bb52e7d7e9e7290cb302e439e1ada18b3dd278895125c857fd028dffa21053",
    "peaso/collectors/batch_remaining_k8s.py": "8c15aa07719cc9596edb3aa7128c99b8d301ef35269ab860ceeb238bec95bb3e",
    "peaso/collectors/gcp_facts_v4_holds.py": "f52b9df380e2e69de33cd39bd99f3fda30cac030a1a583c50660b8b9a083f39f",
    "peaso/gcp_data_access_policy.py": "03167a5cf56583a9ae4efb08aba2beb24fa0e62fcafded1b6f7f47181cb5d4c7",
    "peaso/privesc/catalog/aws/lightsail.yaml": "1645b857297793df9c1f6a69e236cbff5873b65055e4e4056360c693c809a279",
    "peaso/privesc/catalog/azure/app_configuration.yaml": "937a2bbc1a2b42d08ef7d183653e540f7320b672c59d9ed5068a191a3aaca89b",
    "peaso/privesc/catalog/azure/monitor.yaml": "a2cec1047c97588d0537a02e1f5ac06ed091188097b8427369fc8362f715cada",
    "peaso/privesc/catalog/azure/storage.yaml": "be4c268b9114175bbf079a4d9c70009392f9fab26afa47ea8100930255b19b15",
    "peaso/privesc/catalog/gcp/aiplatform.yaml": "d32d22ffb8909105cbc49f3fe0704df6ffb8e43494c7c908981d59dd31800c69",
    "peaso/privesc/catalog/gcp/bigtable.yaml": "436131e96ff896df4425319aee3952c6010909dab2b4256302a4367af8e230db",
    "peaso/privesc/catalog/gcp/dlp.yaml": "a4191890cd5bb94485588a7830567975f59ded4b2043f58331a4e6a60223187d",
    "peaso/privesc/catalog/gcp/parametermanager.yaml": "8273c65df5d117386103e3694b7074ab002487b851706897c63d44300f76acab",
    "peaso/privesc/catalog/gcp/secretmanager.yaml": "7ddb46238daeeba20663d30f5a2f07ab25b26cfd8838895787043a6b28c5b23e",
    "peaso/privesc/catalog_versions/legacy-0b3633-delta.json": "40640ad0e7179af395ec37f9456ef7b9d8340e8ab81e9edb7a460769edca258a",
    "peaso/privesc/versioned_catalog.py": "7208003138d9686636f0037c19b2bf2edee3af33910aa511c8ade3bb99ffc8f2",
    "peaso/rulepacks/remediation_compliance_batch_remaining_aws.json": "5a56f6461032af032d3714b48a0cefd876bee49a3db75c8a7e40a897ce9b0f05",
    "peaso/rulepacks/remediation_compliance_batch_remaining_azure.json": "21d698a751ccd45b4b603370e007850269660107ad1b739441c3374d92233d32",
    "peaso/rulepacks/remediation_compliance_batch_remaining_gcp.json": "bcbbcd828f5755524f709fd25150a666ffa8c7b8015da4f0f9571177a67812f6",
    "peaso/rulepacks/remediation_compliance_batch_remaining_k8s.json": "5485734fd0351e2dc8f6862b65472164e05df802e32d9c08d061826d1f1492ca"
}
# Exact ten-check successor roster; historical approved branches remain intact.
APPROVED_POST_DFAF_RUNTIME_ADDITIONS = {'peaso/checks/aws_backup_plan_frequency.py': '0f40ddcace19dded128369f32efad6d72e36a8a95590073beb8cada2d4cff08d', 'peaso/checks/aws_config_recording.py': '50800c1a5c30aa407d0791d4416cc473ea19c3d03f584a2a4a2cfa694d2eabec', 'peaso/checks/batch_remaining_aws.py': '197ccf540f23e9373d8db281bf1544d2d2bba793be3738ff214e9a6038d813b2', 'peaso/checks/batch_remaining_azure.py': '82e39d57beef687761098e206457e5e7f7e25a792fc9fcc8600d809f4737b136', 'peaso/checks/batch_remaining_azure_vm_storage.py': '11f0353505ec70bb7cbc1f6f72add7ceb664fcbd01d05bd8018b2063dd09babb', 'peaso/checks/batch_remaining_gcp.py': '4f93aebdb8c4fabb603cc122b7a390bc153abc6039035c4a0e780be708aed870', 'peaso/checks/batch_remaining_k8s.py': '0f0c92c50a05e92bfd0357767066e4e481c03320c2f582ff10194d8cc25dd578', 'peaso/checks/central_batch_fixtures.json': '8d7632ddfe521a4b0d5cdef363b579ebaafede96e815b3e559705b93ff4aef43', 'peaso/checks/central_native_fixtures.py': '2b9665b5b12e164a76b0982bc055857be82cd72d09eafcb8588bc96ead0503f4', 'peaso/checks/compliance_next_k8s.py': 'd0184f0934601aaa4682c07d1f0dbfa1b40fa2e9090ce2ca53ca413471b96dfc', 'peaso/checks/gcp_data_access.py': 'ce997648d524475e848aff41353b99f3add7075eca451146a89a7998da9f51c5', 'peaso/checks/k8s_namespace_policy_presence.py': '47f64b995e1f5ca9b6db72ff62a7a4594521448f2a1fbba174d453251698a2b2', 'peaso/checks/post_dfaf_aws.py': '301493a4bd3ee865d3d830807a9d6481ef5e3910b3e8ba99c26b57b487cd0fce', 'peaso/checks/post_dfaf_aws_specs.py': '4f2410348d731c2c76c3db79b0b2b0aebedebf874ce9044f9dccb612622d2476', 'peaso/checks/post_dfaf_azure.py': 'c00e5f758009f1929eb97f83a096706874b97fc6e2269dea8ccdab06c8e5640e', 'peaso/checks/wafv2_basic.py': 'b300d867db2803793f56b23dbd2c51751435236428267e12e23c398c99316437', 'peaso/collectors/aws_codebuild_redaction.py': 'd3f487ca28fae5563b2cd5839f760dbd742e859388ab0646dc762d5c7826f18d', 'peaso/collectors/aws_facts_v4_holds.py': 'f1c230a3dce2c1178781997876edd76b7a17055c05ad624168cb01eabf591a01', 'peaso/collectors/aws_policy.py': 'a3003f6c3930bd5f23523cc6128192ee6a22891a47035df922e34498ada0429d', 'peaso/collectors/batch_remaining_azure_vm_storage.py': '44bb52e7d7e9e7290cb302e439e1ada18b3dd278895125c857fd028dffa21053', 'peaso/collectors/batch_remaining_k8s.py': '8c15aa07719cc9596edb3aa7128c99b8d301ef35269ab860ceeb238bec95bb3e', 'peaso/collectors/gcp_facts_v4_holds.py': 'f52b9df380e2e69de33cd39bd99f3fda30cac030a1a583c50660b8b9a083f39f', 'peaso/gcp_data_access_policy.py': '03167a5cf56583a9ae4efb08aba2beb24fa0e62fcafded1b6f7f47181cb5d4c7', 'peaso/privesc/catalog/aws/lightsail.yaml': '1645b857297793df9c1f6a69e236cbff5873b65055e4e4056360c693c809a279', 'peaso/privesc/catalog/azure/app_configuration.yaml': '937a2bbc1a2b42d08ef7d183653e540f7320b672c59d9ed5068a191a3aaca89b', 'peaso/privesc/catalog/azure/monitor.yaml': 'a2cec1047c97588d0537a02e1f5ac06ed091188097b8427369fc8362f715cada', 'peaso/privesc/catalog/azure/storage.yaml': 'be4c268b9114175bbf079a4d9c70009392f9fab26afa47ea8100930255b19b15', 'peaso/privesc/catalog/gcp/aiplatform.yaml': 'd32d22ffb8909105cbc49f3fe0704df6ffb8e43494c7c908981d59dd31800c69', 'peaso/privesc/catalog/gcp/bigtable.yaml': '436131e96ff896df4425319aee3952c6010909dab2b4256302a4367af8e230db', 'peaso/privesc/catalog/gcp/dlp.yaml': 'a4191890cd5bb94485588a7830567975f59ded4b2043f58331a4e6a60223187d', 'peaso/privesc/catalog/gcp/parametermanager.yaml': '8273c65df5d117386103e3694b7074ab002487b851706897c63d44300f76acab', 'peaso/privesc/catalog/gcp/secretmanager.yaml': '7ddb46238daeeba20663d30f5a2f07ab25b26cfd8838895787043a6b28c5b23e', 'peaso/privesc/catalog_versions/legacy-0b3633-delta.json': '40640ad0e7179af395ec37f9456ef7b9d8340e8ab81e9edb7a460769edca258a', 'peaso/privesc/versioned_catalog.py': '7208003138d9686636f0037c19b2bf2edee3af33910aa511c8ade3bb99ffc8f2', 'peaso/rulepacks/remediation_compliance_batch_remaining_aws.json': '9779df0bb1e672607a68488870f1d0e1de5ace357c5478a296f5ca071fffdd2f', 'peaso/rulepacks/remediation_compliance_batch_remaining_azure.json': '0590b6972c32ec6b9137820eeed219534c02465cb883abf5116798662a0feb25', 'peaso/rulepacks/remediation_compliance_batch_remaining_gcp.json': 'bcbbcd828f5755524f709fd25150a666ffa8c7b8015da4f0f9571177a67812f6', 'peaso/rulepacks/remediation_compliance_batch_remaining_k8s.json': '5485734fd0351e2dc8f6862b65472164e05df802e32d9c08d061826d1f1492ca'}
# Exact grouped two-check successor over the accepted post-dfaf runtime.
APPROVED_NEXT20_RUNTIME_ADDITIONS = {
    **APPROVED_POST_DFAF_RUNTIME_ADDITIONS,
    'peaso/checks/central_batch_fixtures.json': '1e06f4c13cb403e65f35586a7a1e94c808b3e7fbda1d0ea2e8b30f9c6c3c87f0',
    'peaso/checks/next20_aws.py': '8b5bedb10366b2708e445bc0068f41a1e6aea0bf8fe7f20c81029dfce665e569',
    'peaso/rulepacks/remediation_compliance_batch_remaining_aws.json': 'bb6413d8df303852b03f0ee1c89d04ea54291b2cd3bf5b4af103f1c3661ab39b',
}
# Exact APIM and GCP audit successor runtime additions over the reviewed set.
APPROVED_APIM_GCP_RUNTIME_ADDITIONS = {
    **APPROVED_NEXT20_RUNTIME_ADDITIONS,
    'peaso/checks/azure_apim_native.py': 'af1e1903c167c813e1ab8e8a9c7fa2336dc6cb5f9d8757f7beaaf6f481744f6b',
    'peaso/checks/central_batch_fixtures.json': '50f89b8163fd5a023afe1af062d76f44a4627af5c37f6e4cd9ceede49a657b9f',
    'peaso/checks/gcp_audit_native.py': '8c2f5e8d0a76571c06a0e0ade0e83cd54f0814fe525fc9f293968224ba2edf8f',
    'peaso/collectors/azure_apim_native.py': 'f43150e470199e27637de0760fd288aed07362f69378290567a78e42d9eb7975',
    'peaso/collectors/gcp.py': '9325aad599a5929050c2add8f743882638741912811a5b54a3d41d703f76cb41',
    'peaso/collectors/gcp_audit_native.py': 'be7442b7feb98f7b54a288a559b276fd93d34d80de56919451e29169db48d49e',
    'peaso/rulepacks/remediation_compliance_batch_remaining_azure.json': 'dce077a19e235ba3a50d0046e415d567a7df61ff13c0c690e26771666039e710',
    'peaso/rulepacks/remediation_compliance_batch_remaining_gcp.json': '5d618ab15fa5cd624e2b2559ab9f308dabe5fb2fa255d33ff664386c5e97b71c',
    'peaso/server/validation.py': 'abbc9d0726cb040331e193f28b6f54574d5fa9ceae9d4503cefd156aa77199ca',
}
# Measured API ZIP: 4,429 members, 212,277,843 uncompressed bytes,
# 35,167,907-byte largest member, 46,320,531-byte archive.
MAX_API_MEMBERS = 4600
MAX_API_MEMBER_BYTES = 40_000_000
MAX_API_UNCOMPRESSED_BYTES = 240_000_000
MAX_API_ARCHIVE_BYTES = 55_000_000
RUNTIME_EXTRAS = {"bluepeass/__init__.py", "bluepeass/k8s.py", "bluepeass/k8s_risks.py",
                  "scripts/cloud_permission_risks.py"}


APPROVED_NEXT_GROUP_RUNTIME_ADDITIONS = {'peaso/checks/aws_backup_plan_frequency.py': '0f40ddcace19dded128369f32efad6d72e36a8a95590073beb8cada2d4cff08d', 'peaso/checks/aws_config_recording.py': '50800c1a5c30aa407d0791d4416cc473ea19c3d03f584a2a4a2cfa694d2eabec', 'peaso/checks/batch_remaining_aws.py': '197ccf540f23e9373d8db281bf1544d2d2bba793be3738ff214e9a6038d813b2', 'peaso/checks/batch_remaining_azure.py': '82e39d57beef687761098e206457e5e7f7e25a792fc9fcc8600d809f4737b136', 'peaso/checks/batch_remaining_azure_vm_storage.py': '11f0353505ec70bb7cbc1f6f72add7ceb664fcbd01d05bd8018b2063dd09babb', 'peaso/checks/batch_remaining_gcp.py': '4f93aebdb8c4fabb603cc122b7a390bc153abc6039035c4a0e780be708aed870', 'peaso/checks/batch_remaining_k8s.py': '0f0c92c50a05e92bfd0357767066e4e481c03320c2f582ff10194d8cc25dd578', 'peaso/checks/central_batch_fixtures.json': '1a226d4af6f26c7216c305d36109226bed11e28051c936cb86f66ffcb5dc734b', 'peaso/checks/central_native_fixtures.py': '2b9665b5b12e164a76b0982bc055857be82cd72d09eafcb8588bc96ead0503f4', 'peaso/checks/compliance_next_k8s.py': 'd0184f0934601aaa4682c07d1f0dbfa1b40fa2e9090ce2ca53ca413471b96dfc', 'peaso/checks/gcp_data_access.py': 'ce997648d524475e848aff41353b99f3add7075eca451146a89a7998da9f51c5', 'peaso/checks/k8s_namespace_policy_presence.py': '47f64b995e1f5ca9b6db72ff62a7a4594521448f2a1fbba174d453251698a2b2', 'peaso/checks/post_dfaf_aws.py': '301493a4bd3ee865d3d830807a9d6481ef5e3910b3e8ba99c26b57b487cd0fce', 'peaso/checks/post_dfaf_aws_specs.py': '4f2410348d731c2c76c3db79b0b2b0aebedebf874ce9044f9dccb612622d2476', 'peaso/checks/post_dfaf_azure.py': 'c00e5f758009f1929eb97f83a096706874b97fc6e2269dea8ccdab06c8e5640e', 'peaso/checks/wafv2_basic.py': 'b300d867db2803793f56b23dbd2c51751435236428267e12e23c398c99316437', 'peaso/collectors/aws_codebuild_redaction.py': 'd3f487ca28fae5563b2cd5839f760dbd742e859388ab0646dc762d5c7826f18d', 'peaso/collectors/aws_facts_v4_holds.py': 'f1c230a3dce2c1178781997876edd76b7a17055c05ad624168cb01eabf591a01', 'peaso/collectors/aws_policy.py': 'a3003f6c3930bd5f23523cc6128192ee6a22891a47035df922e34498ada0429d', 'peaso/collectors/batch_remaining_azure_vm_storage.py': '44bb52e7d7e9e7290cb302e439e1ada18b3dd278895125c857fd028dffa21053', 'peaso/collectors/batch_remaining_k8s.py': '8c15aa07719cc9596edb3aa7128c99b8d301ef35269ab860ceeb238bec95bb3e', 'peaso/collectors/gcp_facts_v4_holds.py': 'f52b9df380e2e69de33cd39bd99f3fda30cac030a1a583c50660b8b9a083f39f', 'peaso/gcp_data_access_policy.py': '03167a5cf56583a9ae4efb08aba2beb24fa0e62fcafded1b6f7f47181cb5d4c7', 'peaso/privesc/catalog/aws/lightsail.yaml': '1645b857297793df9c1f6a69e236cbff5873b65055e4e4056360c693c809a279', 'peaso/privesc/catalog/azure/app_configuration.yaml': '937a2bbc1a2b42d08ef7d183653e540f7320b672c59d9ed5068a191a3aaca89b', 'peaso/privesc/catalog/azure/monitor.yaml': 'a2cec1047c97588d0537a02e1f5ac06ed091188097b8427369fc8362f715cada', 'peaso/privesc/catalog/azure/storage.yaml': 'be4c268b9114175bbf079a4d9c70009392f9fab26afa47ea8100930255b19b15', 'peaso/privesc/catalog/gcp/aiplatform.yaml': 'd32d22ffb8909105cbc49f3fe0704df6ffb8e43494c7c908981d59dd31800c69', 'peaso/privesc/catalog/gcp/bigtable.yaml': '436131e96ff896df4425319aee3952c6010909dab2b4256302a4367af8e230db', 'peaso/privesc/catalog/gcp/dlp.yaml': 'a4191890cd5bb94485588a7830567975f59ded4b2043f58331a4e6a60223187d', 'peaso/privesc/catalog/gcp/parametermanager.yaml': '8273c65df5d117386103e3694b7074ab002487b851706897c63d44300f76acab', 'peaso/privesc/catalog/gcp/secretmanager.yaml': '7ddb46238daeeba20663d30f5a2f07ab25b26cfd8838895787043a6b28c5b23e', 'peaso/privesc/catalog_versions/legacy-0b3633-delta.json': '40640ad0e7179af395ec37f9456ef7b9d8340e8ab81e9edb7a460769edca258a', 'peaso/privesc/versioned_catalog.py': '7208003138d9686636f0037c19b2bf2edee3af33910aa511c8ade3bb99ffc8f2', 'peaso/rulepacks/remediation_compliance_batch_remaining_aws.json': 'ebe28d47a1880fa09acc7f42022a1e199ac9c27992049d2ca074670b41d6d490', 'peaso/rulepacks/remediation_compliance_batch_remaining_azure.json': 'a8f76c1a53926fa6cbbda666e80108b494d7933d77d9d39f6d1226f02937b91a', 'peaso/rulepacks/remediation_compliance_batch_remaining_gcp.json': '5d618ab15fa5cd624e2b2559ab9f308dabe5fb2fa255d33ff664386c5e97b71c', 'peaso/rulepacks/remediation_compliance_batch_remaining_k8s.json': '5485734fd0351e2dc8f6862b65472164e05df802e32d9c08d061826d1f1492ca', 'peaso/checks/next20_aws.py': '8b5bedb10366b2708e445bc0068f41a1e6aea0bf8fe7f20c81029dfce665e569', 'peaso/checks/azure_apim_native.py': 'af1e1903c167c813e1ab8e8a9c7fa2336dc6cb5f9d8757f7beaaf6f481744f6b', 'peaso/checks/gcp_audit_native.py': '8c2f5e8d0a76571c06a0e0ade0e83cd54f0814fe525fc9f293968224ba2edf8f', 'peaso/collectors/azure_apim_native.py': 'f43150e470199e27637de0760fd288aed07362f69378290567a78e42d9eb7975', 'peaso/collectors/gcp.py': '9325aad599a5929050c2add8f743882638741912811a5b54a3d41d703f76cb41', 'peaso/collectors/gcp_audit_native.py': 'be7442b7feb98f7b54a288a559b276fd93d34d80de56919451e29169db48d49e', 'peaso/server/validation.py': 'abbc9d0726cb040331e193f28b6f54574d5fa9ceae9d4503cefd156aa77199ca', 'peaso/reports.py': '79e990617633f028bb37b2cdd0630799bec573c10ce5e3beec640d49c970bd21', 'peaso/collectors/azure.py': 'f98a2f8f9181ddcf1a07592a525e8df8abaeab428d2115a07346b466b9bfbc5d', 'peaso/collectors/azure_appservice_identity_followup.py': 'd5e135f5973b2909974bfd2bf5cb43c03931e71590e63649da35850a75554aaf', 'peaso/collectors/aws.py': '90a237628b2a45012e07adff78d3c9e9e92c3d855fa5237d1b11fdd3945df7f4', 'peaso/collectors/aws_facts_compute_edge.py': '7457cb0db2aabf2a01a6ac18fed0a0a9cebf587f8bf86bdf863fe1b277379782', 'peaso/checks/remaining_aws_gcp_native.py': 'ded9f2aa60b562cc3db565a091434ad182e8ae8635d4b128549b827a39a6f5f9', 'peaso/checks/next_group_azure_fixtures.py': '274822bd1753bef38af173b6be01774abba8ab1bb6b0a0fe3d76638b2e0da249', 'peaso/checks/azure_appservice_identity_followup.py': 'ca7ffd2dccf77fd8e7b90d31c567cbb48b666300330555242582efe768347463', 'peaso/checks/__init__.py': 'caef27171667da9fd23216591ec2bb2e406a47e4ff2dcf47a45a490a0c6121c0', 'peaso/checks/next_group_aws_fixtures.py': '0076893df5c07f55cd2244d98afaa4516e56f5a1a7bb4f3c5bf7ee1874adb90a', 'peaso/checks/azure_easm_native.py': 'd75e42848fae6c53b0f9e29fdb5c568325bbf8f2e136a7dcc435c58b1036f94b', 'peaso/checks/azure_graph_credential_age.py': 'ba0b2f87162cbace267cb0d630f05655d59239b287d9e7ae6b4f8744cc30a7b4', 'peaso/checks/next_group_easm_fixtures.py': '3162d5c0deeb1122ddddb06a82793167366dc71f17983547365791854f0406a8', 'peaso/checks/next_group_appservice_fixtures.py': '1f461d725797b538f7e6550f7aa70217b029e6ec846a3a9e7ce5e6531057c3be', 'peaso/checks/azure_log_profile_retention.py': 'ba369f5809f8484310b89079ee0b4c3a5523f561ff03cd349488766cc86837ba'}

# Retain the historical admission branches; this exact successor binds the
# live collector repairs and deterministic report fixes independently.
APPROVED_LIVE_VALIDATION_RUNTIME_ADDITIONS = {
    **APPROVED_NEXT_GROUP_RUNTIME_ADDITIONS,
    "peaso/collectors/gcp.py": "70bdc6f7fae78bbecc703d5ef14014134b5e61e2a0ea07764a6fe0be919ed360",
    "peaso/collectors/azure.py": "c9e85901af5d95fabdeed5911f697d2aee1eca1a1b06b3a9b890614bd9774cb8",
    "peaso/engine.py": "8b0e0bfeec538469a0f4550307416b3a5b640b05a55e28680dcdf9d0dcd1a46a",
    "peaso/analysis/network.py": "4697a0bdcc4361aa34f599b73407b3d51921a34e07b175ff66152411e3b260f9",
    "peaso/analysis/internet_exposure.py": "f13b9b63903b49ebb99d61fcabd1b51c07994686a8ec8c33101b2d2b3980fbdc",
}

APPROVED_GCP_HISTORY_RUNTIME_ADDITIONS = {
    **APPROVED_LIVE_VALIDATION_RUNTIME_ADDITIONS,
    "peaso/collectors/gcp.py": "241dc6616ff3f7a06a858c907ceedfcad68aeb408e43c7dda89a6c41cf501c06",
    "peaso/collectors/gcp_compliance_wave.py": "49250bb20e6b692b7d43ba1bb69d979acd827f6df58789d729175d107fe9fe47",
    "peaso/collectors/gcp_history.py": "247084b652dc8ceefeb3f4f60a099c7e4dff124f4054c46d4714d61b1576dfda",
    "peaso/server/validation.py": "0523b71273b2186d2471d160551e47ad46407917a663a338bff2dbcf2ff86889",
}


APPROVED_PSC_RUNTIME_ADDITIONS = {
    **APPROVED_GCP_HISTORY_RUNTIME_ADDITIONS,
    "peaso/checks/__init__.py": "057dd4a8b7d82718089f4a28b0352f09b4431f5a1f90c757c6f2d8f5320734d3",
    "peaso/checks/gcp_psc_dns.py": "4d820199813173d9f32ab2b4a5b4547c449d7f88e69affe1064247cb2df1e599",
    "peaso/checks/gcp_psc_fixtures.json": "d452ed303ed02d23d05e1ef1efce880264002779bf3073dee79239a3764a6138",
    "peaso/gcp_psc_policy.py": "ceb9da0dca6e28d011e9f0d779fe519991bb78ec4e7df9bbba67494306eb0ff1",
    "peaso/collectors/gcp.py": "1f05830be1cd255bb7581e2a48ce935227ba18df84a6f4bf6d60a910fab8691b",
    "peaso/collectors/gcp_history.py": "21368065d8d1a46209e88d623bb848fe2e3dcb0e4e4c0e5b01f867b8ecf4e631",
    "peaso/server/validation.py": "6a89cf4e98a8a70b0fd3b7dbea1ca6065278dee59a3ae636daf499d8b327decb",
    "peaso/rulepacks/check_descriptions.json": "e58fff92f5cd9fd8ef2c646ee788265f71aff8d65e6e08861d4ecac7bcff6409",
    "peaso/rulepacks/catalog_summary.json": "0a4338745c9d0517721e90fc937238f757e63f97dac7dc1aeb868e799c1614ba",
    "peaso/rulepacks/runtime_metadata.json": "2a528fafc345323a393cbe20daf434c3a42feab67292406079d41cce9e0b70c3",
    "peaso/rulepacks/compliance_lookup.json": "fa5d9d0cf13d9c1f0f38244f2885af5fae70e40da56118ebd0410b1b0648b530",
    "peaso/rulepacks/compliance_requirements.json": "74c9961902b6af925911956c9ba383c468929ddd75fec49135ae01bb274dd1c4",
    "peaso/rulepacks/native_catalog.json": "887d428bf6ad5403ed3cdd516f0b0ec670a55e3983c5d7095ec5bf2c49bebf2f",
    "peaso/rulepacks/framework_catalog.json": "cffca9040e905045a0f783e20b62e9cba393833832106966895c815ba49db1ec",
}


APPROVED_TWO_HOUR_NATIVE_RUNTIME_ADDITIONS = {
    **APPROVED_PSC_RUNTIME_ADDITIONS,
    'peaso/checks/__init__.py': 'd5fd63069d4bc6d6d3ecfe339e91139ad4b435f0de44684f65b9473f33a9340b',
    'peaso/checks/aws_all_policies.json': '8e1cdcc44749b643d95e4ee223e386a4b4aba609d9e09a0577779cc34daa83bf',
    'peaso/checks/aws_all_policies.py': '46c12e7ef9f8ed1eac29709c720c0b703e71ee7d0ac15c2427c99346747ab9fe',
    'peaso/checks/aws_all_policies_fixtures.json': 'f93d3feb539b593561b3cf9878a0f151e5619ab29bb43984e9963e141eee9401',
    'peaso/checks/gcp_audit_rates.json': '5010787138c533e7af252d5cfc2aab641097fb6bc9607d6018a66aac943554d9',
    'peaso/checks/gcp_audit_rates.py': 'efb0da440e417b40efbcbf189b0fb62385be3b849136b04de08f61baff8e748c',
    'peaso/checks/gcp_audit_rates_fixtures.json': '2d2fd4319e86bb5f54d0f99b6c28ca0788504e46e822afdaed5d0dfe108a4354',
    'peaso/checks/native_storage_compute.json': 'e4891a7a99339126380eab0a9e66e855c4b1f7ee8558e79abe64a2471fac7c9d',
    'peaso/checks/native_storage_compute.py': '66bc80ff2d43d7d394defa1180199abf42fb0c40b56ff2696ce5f9733f1de318',
    'peaso/checks/native_storage_compute_fixtures.json': '815860e018a22d38bf666b17a981d28993bea720567d369e28e1d26b1339f274',
    'peaso/collectors/aws.py': 'bdae3a0eb065dc9b4745db86b6747120bf79047c4c5fd4990e3cbc5f7cc6f7ad',
    'peaso/collectors/aws_all_policies.py': '4be1797ead0658962fe64ddd17ac4437df49b3612e0d8746cf7315734e4a9886',
    'peaso/collectors/aws_facts_data_identity.py': '253132c2a4e51b7d4f4a4f722d115877a4e30d41982e907438a5b2bb4cb4f86b',
    'peaso/collectors/aws_privesc_facts.py': 'b0d6c5be4c068a7422c844f050c60d212931cdd87b6ce30fc1e2437aadcbf310',
    'peaso/collectors/azure.py': 'cb95f3578f40b9d3a45868f4b301588356a8efe700c6a8c65a25b82b2d958199',
    'peaso/collectors/azure_sql_inventory.py': '2bffcc5421ab573eb535cd3f36186e98db87defea014f7c7f7df5c55b586d65d',
    'peaso/collectors/gcp_audit_native.py': '02554f3aa9bf2a4d450455c75c6b7fac5ca2396e1afededd34db42a6ec4179e8',
    'peaso/engine.py': 'ce3d8e1566a1c48f275b1135cb5d02101bcfb60f9df8f52a58a7b523a339936b',
    'peaso/privesc/bounded_effects.json': '4ce1a0b29fbf026bbc26166915f87e5fb2c4e6396a8aa37ee91e56ca1840806d',
    'peaso/privesc/catalog/aws/bounded-effects-v5.yaml': 'd38ce968f6af36e9d5c72a098916978320ebf61653df6e6b2c1916de3fbaf80a',
    'peaso/privesc/catalog/aws/exact-principal-v5.yaml': 'b198454714e4e530682cea805f5e1db595c9eb7a8057f35b1f8d426f88c2a709',
    'peaso/privesc/catalog/azure/bounded-effects-v5.yaml': '1ca7a8398150cd05f2146e3466be8713481870cdcedfaf8813aad3e41b12a9f4',
    'peaso/privesc/catalog/gcp/bounded-effects-v5.yaml': '336a51ee7c3e5411d23c7e6fffd90849a28de2577ce2ccc02ff6e03877da5505',
    'peaso/privesc/catalog/gcp/exact-principal-v5.yaml': '345e1f41d7baf6f859b65eb6abdf8b6be5bf25781a9b25602ab1481bf1c7ec0b',
    'peaso/privesc/catalog_versions/principal-v4-manifest.json': '6008acf71acda21408c7039dddff2d7ccaeeaa3aecfc6f31ef5d2cdc5a4ea388',
    'peaso/privesc/effective_permissions/aws.py': '13f1caea607bf1801ae060434aa6977a370e08940096df5708864a87f1018357',
    'peaso/privesc/effective_permissions/bounded_evidence.py': '1cd1a44f2d955bb5dc877e404ab09294a3df9b67bb1ff9e867aec1cd0cf212af',
    'peaso/privesc/effective_permissions/exact_evidence.py': '966d87018abc0269ecb9d94cd7d7cd1c51798816440e5b8aeefd11f3a36a4f4a',
    'peaso/privesc/effective_permissions/gcp.py': 'fd9b0b2874eea988df33143a27311e686c9d61ab07af32dec059f495b43842a7',
    'peaso/privesc/effective_permissions/principal_evidence.py': '32839d9a782ab7d0a3ff09e31b99f49484024c7953930cb0187e576fd9c2e4e7',
    'peaso/privesc/exact_principal_tranche.json': 'c02921ad9a694b07415ffd5de0c97a0e8b0f34b73bbf40dc3b78e149e29b4af6',
    'peaso/privesc/privesc-technique.schema.json': '66870af6a15c42b9161e9c9f015afc3085baaf52e1c54eeb3a9a1289d4fb7934',
    'peaso/privesc/schema.py': 'ff810d99bd41f28140e8ecfc8703ac9e9775c12ea6deae86c7ffdbb44e123420',
    'peaso/privesc/versioned_catalog.py': 'c596a12076c502ac1027fdfe2b41b9ce2b6464077ae54feb63a9d6f7ea58a916',
    'peaso/rulepacks/catalog_summary.json': '1677e0d7e9d98794741b244ef0880880444409e0a50e0d0798a6065e3e7c175b',
    'peaso/rulepacks/check_descriptions.json': '35c0b0acc983a55a90b9fa28fdb871f19240fed9660808357e12df00791a1900',
    'peaso/rulepacks/compliance_lookup.json': '41dc9ce71e2cb64e3fad28c80d495b53c85af03d7c94c0d2f9ffa95a70eb0694',
    'peaso/rulepacks/compliance_requirements.json': '9488ad1b038ddb32ddf0f8a8671c88c7242ae8623473cc0a9390f49f43664673',
    'peaso/rulepacks/framework_catalog.json': '43962407bc8e143cf636317ee4c7323e36d6b6ce1657498287fad6c558d1fe11',
    'peaso/rulepacks/native_catalog.json': 'cd072d7a7979bebfa74ffb33e2e1422b94766dada038af56f0ea55b3169c7f54',
    'peaso/rulepacks/runtime_metadata.json': '1078d8fec808295b8af910288d5c55dee0aeab91fa7010fedec1d2f332625662',
    'peaso/server/app.py': '72a1536afbb8dd194c1b5d8e8dcf2604426ced4272354a1b004d098bd99e7ebb',
    'risk_rules/hacktricks-privesc-source.json': '082451e81fa450830ae5f6835e241dd412a6c30a8b2a0b1172cdbc89b2d71429',
}


# Exact V20 successor additions over the immutable source496 baseline.
# The separately verified canonical manifest replaces its redundant gzip copy.
APPROVED_V20_RUNTIME_ADDITIONS = {
    "peaso/analysis/aws_public_ingress.py": "f58f4f100215dd35da15ec177fbfa1b90145a6bf02fbd80afd759374544f06f0",
    "peaso/aws_budget_policy.py": "940a71e4627173e814381a148744a3840c81f60957f5bd2a6032fa4086ba4b69",
    "peaso/aws_waf_logging.py": "f97074cf8e7ecfb00ac1bac45947bdcd628affe294a0465283b1a5a35eb7c8b9",
    "peaso/azure_sw32_policy.py": "656c52580e63e50d926fa8d30172fa64401eb203b3f313ef5b036e3bf4b45812",
    "peaso/checks/aws_all_policies.json": "8e1cdcc44749b643d95e4ee223e386a4b4aba609d9e09a0577779cc34daa83bf",
    "peaso/checks/aws_all_policies.py": "46c12e7ef9f8ed1eac29709c720c0b703e71ee7d0ac15c2427c99346747ab9fe",
    "peaso/checks/aws_all_policies_fixtures.json": "f93d3feb539b593561b3cf9878a0f151e5619ab29bb43984e9963e141eee9401",
    "peaso/checks/aws_backup_plan_frequency.py": "0f40ddcace19dded128369f32efad6d72e36a8a95590073beb8cada2d4cff08d",
    "peaso/checks/aws_config_recording.py": "50800c1a5c30aa407d0791d4416cc473ea19c3d03f584a2a4a2cfa694d2eabec",
    "peaso/checks/azure_apim_diagnostics_native.py": "4221d0aa3092bff0bb5eeb11fdf3ecc58687f0899a52523fbfeed412bb4af55b",
    "peaso/checks/azure_apim_native.py": "af1e1903c167c813e1ab8e8a9c7fa2336dc6cb5f9d8757f7beaaf6f481744f6b",
    "peaso/checks/azure_appservice_identity_followup.py": "ca7ffd2dccf77fd8e7b90d31c567cbb48b666300330555242582efe768347463",
    "peaso/checks/azure_easm_native.py": "d75e42848fae6c53b0f9e29fdb5c568325bbf8f2e136a7dcc435c58b1036f94b",
    "peaso/checks/azure_graph_credential_age.py": "ba0b2f87162cbace267cb0d630f05655d59239b287d9e7ae6b4f8744cc30a7b4",
    "peaso/checks/azure_log_profile_retention.py": "ba369f5809f8484310b89079ee0b4c3a5523f561ff03cd349488766cc86837ba",
    "peaso/checks/batch_remaining_aws.py": "197ccf540f23e9373d8db281bf1544d2d2bba793be3738ff214e9a6038d813b2",
    "peaso/checks/batch_remaining_azure.py": "82e39d57beef687761098e206457e5e7f7e25a792fc9fcc8600d809f4737b136",
    "peaso/checks/batch_remaining_azure_vm_storage.py": "11f0353505ec70bb7cbc1f6f72add7ceb664fcbd01d05bd8018b2063dd09babb",
    "peaso/checks/batch_remaining_gcp.py": "4f93aebdb8c4fabb603cc122b7a390bc153abc6039035c4a0e780be708aed870",
    "peaso/checks/batch_remaining_k8s.py": "0f0c92c50a05e92bfd0357767066e4e481c03320c2f582ff10194d8cc25dd578",
    "peaso/checks/bulk_pending.json": "b51e99b8acfab245cfc6f04e99405f0fad78be3c082a61ac652a862b7bf7b7b8",
    "peaso/checks/bulk_pending.py": "41cd15965640293562f1808fd7cc31b85769a3e3a44aa3c5537d119dabd50a11",
    "peaso/checks/central_batch_fixtures.json": "1a226d4af6f26c7216c305d36109226bed11e28051c936cb86f66ffcb5dc734b",
    "peaso/checks/central_native_fixtures.py": "2b9665b5b12e164a76b0982bc055857be82cd72d09eafcb8588bc96ead0503f4",
    "peaso/checks/compliance_new_sw25_native_identity.py": "c347440d7e378900762fc5cf6253203c61325008f6320008919d68cb5c37c53e",
    "peaso/checks/compliance_next_k8s.py": "d0184f0934601aaa4682c07d1f0dbfa1b40fa2e9090ce2ca53ca413471b96dfc",
    "peaso/checks/gcp_audit_native.py": "8c2f5e8d0a76571c06a0e0ade0e83cd54f0814fe525fc9f293968224ba2edf8f",
    "peaso/checks/gcp_audit_rates.json": "5010787138c533e7af252d5cfc2aab641097fb6bc9607d6018a66aac943554d9",
    "peaso/checks/gcp_audit_rates.py": "efb0da440e417b40efbcbf189b0fb62385be3b849136b04de08f61baff8e748c",
    "peaso/checks/gcp_audit_rates_fixtures.json": "2d2fd4319e86bb5f54d0f99b6c28ca0788504e46e822afdaed5d0dfe108a4354",
    "peaso/checks/gcp_data_access.py": "ce997648d524475e848aff41353b99f3add7075eca451146a89a7998da9f51c5",
    "peaso/checks/gcp_psc_dns.py": "4d820199813173d9f32ab2b4a5b4547c449d7f88e69affe1064247cb2df1e599",
    "peaso/checks/gcp_psc_fixtures.json": "d452ed303ed02d23d05e1ef1efce880264002779bf3073dee79239a3764a6138",
    "peaso/checks/k8s_namespace_policy_presence.py": "47f64b995e1f5ca9b6db72ff62a7a4594521448f2a1fbba174d453251698a2b2",
    "peaso/checks/native_storage_compute.json": "e4891a7a99339126380eab0a9e66e855c4b1f7ee8558e79abe64a2471fac7c9d",
    "peaso/checks/native_storage_compute.py": "66bc80ff2d43d7d394defa1180199abf42fb0c40b56ff2696ce5f9733f1de318",
    "peaso/checks/native_storage_compute_fixtures.json": "815860e018a22d38bf666b17a981d28993bea720567d369e28e1d26b1339f274",
    "peaso/checks/next20_aws.py": "8b5bedb10366b2708e445bc0068f41a1e6aea0bf8fe7f20c81029dfce665e569",
    "peaso/checks/next_group_appservice_fixtures.py": "1f461d725797b538f7e6550f7aa70217b029e6ec846a3a9e7ce5e6531057c3be",
    "peaso/checks/next_group_aws_fixtures.py": "0076893df5c07f55cd2244d98afaa4516e56f5a1a7bb4f3c5bf7ee1874adb90a",
    "peaso/checks/next_group_azure_fixtures.py": "274822bd1753bef38af173b6be01774abba8ab1bb6b0a0fe3d76638b2e0da249",
    "peaso/checks/next_group_easm_fixtures.py": "3162d5c0deeb1122ddddb06a82793167366dc71f17983547365791854f0406a8",
    "peaso/checks/post_dfaf_aws.py": "301493a4bd3ee865d3d830807a9d6481ef5e3910b3e8ba99c26b57b487cd0fce",
    "peaso/checks/post_dfaf_aws_specs.py": "4f2410348d731c2c76c3db79b0b2b0aebedebf874ce9044f9dccb612622d2476",
    "peaso/checks/post_dfaf_azure.py": "c00e5f758009f1929eb97f83a096706874b97fc6e2269dea8ccdab06c8e5640e",
    "peaso/checks/remaining_aws_gcp_native.py": "ded9f2aa60b562cc3db565a091434ad182e8ae8635d4b128549b827a39a6f5f9",
    "peaso/checks/wafv2_basic.py": "b300d867db2803793f56b23dbd2c51751435236428267e12e23c398c99316437",
    "peaso/collectors/aws_all_policies.py": "4be1797ead0658962fe64ddd17ac4437df49b3612e0d8746cf7315734e4a9886",
    "peaso/collectors/aws_apigateway_native.py": "bf5c20ba91a679dcd303579b89ef6f9fd3b96e4664254716b5c98e4367e854a5",
    "peaso/collectors/aws_budget_stop_native.py": "8001bc5895828ec8fc38baeda5a9e5f863866a3d32889e7b1804a06338dbba44",
    "peaso/collectors/aws_bulk_inventory.py": "45aa2a3bce8581cf8bf1046e882eb701a03b61367378fdcee70d3b5ef415230d",
    "peaso/collectors/aws_cloudtrail_delivery_native.py": "bf7348354a77a39d2271f1b022d1620b0e7f7d3b68dc021cf06f86aceb369393",
    "peaso/collectors/aws_codebuild_redaction.py": "d3f487ca28fae5563b2cd5839f760dbd742e859388ab0646dc762d5c7826f18d",
    "peaso/collectors/aws_codecommit_review_native.py": "8700c0be3a48fe2d6a72ed29390d5938ce2b901ecfccfb829a94cc9618249e93",
    "peaso/collectors/aws_cost_policy.py": "1e53fa329bbaeba16b0548bbd6b912ebbadd4a22c1e1732c24665d68b36fc42d",
    "peaso/collectors/aws_ecr_artifacts_native.py": "3beaa9b23013e715902d29d76064c0bcf205c569b02b38f74d2c7ba0cd66e99c",
    "peaso/collectors/aws_facts_v4_holds.py": "1e2cec696c00e1b002111fa1c4e3d17f41585c115db0808e11162705e1cd9356",
    "peaso/collectors/aws_identity_center_native.py": "60592e3ff76ae393ed43d89f1554fb2da1f0daaf836b5e640c8760e8b0a66d3e",
    "peaso/collectors/aws_identity_metrics_native.py": "f96984d474dcb07f03ddc4a998d5c0ae32563677f0eaa2a02384bc79dafadfc0",
    "peaso/collectors/aws_kms_enclave_native.py": "589935d3ebd9bd13c1d58adf304daf78359374c8e78f88549f2db83c3f32d069",
    "peaso/collectors/aws_launch_configuration_redaction.py": "09f0a76060934ef47924c1cf747079ca0dba6a82e5803686155067516eb951b5",
    "peaso/collectors/aws_macie_coverage_native.py": "5650b5a3e15a654cda7d2e5dcd2974124c6a0a711e1798202bf11e4ca5e65a7b",
    "peaso/collectors/aws_operational_groups_native.py": "06108480e7c2f75ca30343ea5ca4fe3dc0a3fa92d8dee9cf2ccf8f47150f2456",
    "peaso/collectors/aws_organizations_native.py": "f331e1cd6fa1a496bcfffb0a3eeb93d72004028dec1bc72d63db731dd1feae5a",
    "peaso/collectors/aws_policy.py": "a3003f6c3930bd5f23523cc6128192ee6a22891a47035df922e34498ada0429d",
    "peaso/collectors/aws_priority_tags_native.py": "c1f67bb05912bb0e60303989dc722093d379e93d56796c48ca81dc40ddb353f1",
    "peaso/collectors/aws_public_ingress_native.py": "3dda8ed8ffdb9e3b650ffe50bc6da24d52f57e53c908357ef9bc4a2094309b7e",
    "peaso/collectors/aws_region_shield_native.py": "08f2a665106e9e66b799fa75946739b57c01076fed23b882f3f63651b652d471",
    "peaso/collectors/aws_resolver_firewall_native.py": "ca0970fa271384e2167db3cb2ed855cceda0dd834348671654597ec3d8b19a52",
    "peaso/collectors/aws_resource_policy_native.py": "b0c7b4081f965bab4ece4de503fac0de65038c6c98df010f877f745ce940998e",
    "peaso/collectors/aws_s3_backup_native.py": "48654c9bb7c4fcbb5ee52c8035cb0fd29d0d8a716b358e9d8399a4595aad3ffd",
    "peaso/collectors/aws_sagemaker_clarify_native.py": "f6695218f1c6f5dd060b7871b516d975fb54e1560aba5a413698b589aaa113af",
    "peaso/collectors/aws_ssm_inventory_events_native.py": "c495038efa6858ee77d75a1090fe357998076455da3c1c4bebc105fd9e00370a",
    "peaso/collectors/aws_transport_native.py": "ab038928f14c3136df4c9425856e57b2b199afa24085d739b4f8526a225e53e6",
    "peaso/collectors/aws_waf_inventory_native.py": "10bcdf16a32dc1edd69ef751dd2a1427dbeb5a1c10cf91fd605b97c6dd2ada20",
    "peaso/collectors/azure_access_reviews_native.py": "11647049e6d04b1e9985ec51f9e890c02b0e8da66f67391979628a60e772bd6f",
    "peaso/collectors/azure_apim_diagnostics_native.py": "d5fe9f4b821fa80c1bed677df063971d6ac61278d315b93eb24b4a7957f9bc2e",
    "peaso/collectors/azure_apim_native.py": "f43150e470199e27637de0760fd288aed07362f69378290567a78e42d9eb7975",
    "peaso/collectors/azure_appservice_identity_followup.py": "d5e135f5973b2909974bfd2bf5cb43c03931e71590e63649da35850a75554aaf",
    "peaso/collectors/azure_arm_metadata_native.py": "f244de81694d42e796544d520ab3d631faa58e115f9622ad61d039fe12c4fa50",
    "peaso/collectors/azure_assessment_criteria_native.py": "42ceb16728f8bde78874d38037c835085c1dba1770c3dab84c6b2a03cc268d1a",
    "peaso/collectors/azure_conditional_access_native.py": "9b69def3b75a31ab41eaeac2757b85fe9d3d4f505f948043cd8491cd0ebabe8a",
    "peaso/collectors/azure_database_native.py": "2b5c6850d33f9a74fc6bf46f92bab1330f1d4ae21e92a6461357cde837c3f683",
    "peaso/collectors/azure_defender_network_native.py": "ce70e05680d870ba145baed0701471783c721446a1781474f70c3b0bbb1985da",
    "peaso/collectors/azure_detection_telemetry.py": "d0c1e354f8c5fbfd8504667dd0268f3e685444e6aa1a5507abb336d16817758d",
    "peaso/collectors/azure_disclosure_native.py": "1038ca6d576f89c6d9bced0182239b140f4dbe51e7aafb60a1b569634f15426d",
    "peaso/collectors/azure_entra_diagnostics_native.py": "3ba791cd52c3e5b2fb78bcb12fced683402d552f8a8ff3bd13fec65fc941636f",
    "peaso/collectors/azure_frontdoor_native.py": "f020ec13c4a8ddd12c8e276f24538cb7c698f707b1f4eaebb52ce14e3305f675",
    "peaso/collectors/azure_function_limits_native.py": "cd1b13b2fd9d7983e1846fe651507a26422f4ab9cf7dd9866cdf9c50f28fc7e9",
    "peaso/collectors/azure_guest_configuration_native.py": "d534f80d292e158eba0caad3629b1d0fe54987c2cdbaf7e33a56a672f6159a54",
    "peaso/collectors/azure_guest_policy.py": "55f32bdb4d9e25f6603321fcb8a0877e07bce003ea7f2b02ea080401c2905c4d",
    "peaso/collectors/azure_guest_reports.py": "3b0b5a169a73bd97975b8968fed0b2e13b935ac8bc5f297ed791a128f8e74e4b",
    "peaso/collectors/azure_identity_intune_native.py": "02b0b6d133a2f0d30cb2e30a99d6d3d4feef78231eb61e680acd02987f0896fc",
    "peaso/collectors/azure_iot_policy_native.py": "5daa1c505286ba57c4f1ec016f54f5713b138d3b45cfd1c5fb542ee3ad893468",
    "peaso/collectors/azure_monitor_inventory_native.py": "81bd15cf090e296be7a299da4b7b9e42657c987bbed6afdeb82a0453a90e6127",
    "peaso/collectors/azure_resource_diagnostics_native.py": "36f73fc3665680b2489ab99c24dfee59b5f2afb236323952e7131dea481df0ed",
    "peaso/collectors/azure_resource_logging_policy.py": "2d7174efd2706acf66466e3216d95ec1b81d2af1cf5b1b54a8144246ca25d0ba",
    "peaso/collectors/azure_secret_versions_native.py": "53d8ad1f7599697fab83af4139644c93223f9cdbfc5355e587749e545149120c",
    "peaso/collectors/azure_sentinel_metadata_native.py": "3cc20e96f438c017261006a2e9d04f16cfc2d01224515a9477f73a7872e9896b",
    "peaso/collectors/azure_sql_inventory.py": "43a1549a843593c8e33812f5dfa9091a0e7ab534d895ea3e03e718cf08ec82ae",
    "peaso/collectors/azure_storage_backup_native.py": "249e5916a527ecd0d80378c1a4e769fc3511152f0887a85186bc1285aa473405",
    "peaso/collectors/azure_storage_recovery_metadata_native.py": "658807c10ba59c65ecc7a86bd0cae1d3079d785612b69b829908cc135cb81ca0",
    "peaso/collectors/azure_sw15_policy.py": "66a6ff162aa2727a33c3079cfd2709cbea883ce5bcc2f16407ef111743a5b82d",
    "peaso/collectors/batch_remaining_azure_vm_storage.py": "44bb52e7d7e9e7290cb302e439e1ada18b3dd278895125c857fd028dffa21053",
    "peaso/collectors/batch_remaining_k8s.py": "8c15aa07719cc9596edb3aa7128c99b8d301ef35269ab860ceeb238bec95bb3e",
    "peaso/collectors/bulk_evidence.json": "c1d173bead561f5777df8e703dd8a0939692202b8f2fe7427e8e6d72457a5744",
    "peaso/collectors/bulk_evidence.py": "fa0541d502c3feca30d8cea526600f2f8649d5cd456f2d3a8a4261c8f2a0469e",
    "peaso/collectors/gcp_audit_native.py": "02554f3aa9bf2a4d450455c75c6b7fac5ca2396e1afededd34db42a6ec4179e8",
    "peaso/collectors/gcp_facts_v4_holds.py": "f52b9df380e2e69de33cd39bd99f3fda30cac030a1a583c50660b8b9a083f39f",
    "peaso/collectors/gcp_history.py": "21368065d8d1a46209e88d623bb848fe2e3dcb0e4e4c0e5b01f867b8ecf4e631",
    "peaso/collectors/gcp_kms_effective_native.py": "7d2c1e81afebac5e99d47951c85c24aeb91e1795d3fe233c396d9bac6a30ae01",
    "peaso/collectors/gcp_native_evidence.py": "fdced136c30eca42529c967ba2a59f84068008ee98345a1a7abc2c974ca060e1",
    "peaso/collectors/gcp_os_patch_native.py": "e8d86dbc207104d2dbc59d2c0dd0a558f7d00e7edde5960d2750fa7803a85f58",
    "peaso/collectors/gcp_sbom_native.py": "e4fc4bc0c455146ed580d7ef3406424c8ddca2588ccf5cb7c723b922931902f8",
    "peaso/collectors/gcp_storage_acl_native.py": "9ef114ced31862ed48cc3defc7710623e130fcd6431051174fc44b6d19fa2033",
    "peaso/collectors/k8s_admission_file.py": "fc23c5692f1bc295394cf770312a58a8bb64dc532d2c2d9ad33cfeb8a440795f",
    "peaso/gcp_data_access_policy.py": "03167a5cf56583a9ae4efb08aba2beb24fa0e62fcafded1b6f7f47181cb5d4c7",
    "peaso/gcp_psc_policy.py": "ceb9da0dca6e28d011e9f0d779fe519991bb78ec4e7df9bbba67494306eb0ff1",
    "peaso/gcp_sbom_policy.py": "ef717b7f45ddb6d7abca981b6a871f60d9dde0f1eee442c64ddb342ca60be788",
    "peaso/privesc/azure_disclosure_effects.json": "6caf92a0ffdc59cffecb0c9d047d31bc7c49fe02dd0f19b11f3ec743a670f93e",
    "peaso/privesc/bounded_effects.json": "4ce1a0b29fbf026bbc26166915f87e5fb2c4e6396a8aa37ee91e56ca1840806d",
    "peaso/privesc/bulk_principal_tranche.json": "6cb1c21ba90b1ae08d0e5671efa373c8711d42cdb97d3f9055f84d3a239428a8",
    "peaso/privesc/catalog/aws/bounded-effects-v5.yaml": "d38ce968f6af36e9d5c72a098916978320ebf61653df6e6b2c1916de3fbaf80a",
    "peaso/privesc/catalog/aws/bulk-principal-v6.yaml": "e4e907a900127eec6feaa5bb9527ddb130d52c4895b94fd65acb6e8b0a29c779",
    "peaso/privesc/catalog/aws/exact-principal-v5.yaml": "b198454714e4e530682cea805f5e1db595c9eb7a8057f35b1f8d426f88c2a709",
    "peaso/privesc/catalog/aws/lightsail.yaml": "1645b857297793df9c1f6a69e236cbff5873b65055e4e4056360c693c809a279",
    "peaso/privesc/catalog/azure/app_configuration.yaml": "937a2bbc1a2b42d08ef7d183653e540f7320b672c59d9ed5068a191a3aaca89b",
    "peaso/privesc/catalog/azure/bounded-effects-v5.yaml": "1ca7a8398150cd05f2146e3466be8713481870cdcedfaf8813aad3e41b12a9f4",
    "peaso/privesc/catalog/azure/disclosure-effects-v7.yaml": "00175d020192d57529b305d80b2027dcea8df7b58aac26e0c60fd03196b79d3a",
    "peaso/privesc/catalog/azure/monitor.yaml": "a2cec1047c97588d0537a02e1f5ac06ed091188097b8427369fc8362f715cada",
    "peaso/privesc/catalog/azure/storage-local-v7.yaml": "39fc0f2734331d8d08d356614775095d8b7be97bf343aa240e110c12d2988f9f",
    "peaso/privesc/catalog/azure/storage.yaml": "be4c268b9114175bbf079a4d9c70009392f9fab26afa47ea8100930255b19b15",
    "peaso/privesc/catalog/gcp/aiplatform.yaml": "d32d22ffb8909105cbc49f3fe0704df6ffb8e43494c7c908981d59dd31800c69",
    "peaso/privesc/catalog/gcp/bigtable.yaml": "436131e96ff896df4425319aee3952c6010909dab2b4256302a4367af8e230db",
    "peaso/privesc/catalog/gcp/bounded-effects-v5.yaml": "336a51ee7c3e5411d23c7e6fffd90849a28de2577ce2ccc02ff6e03877da5505",
    "peaso/privesc/catalog/gcp/bulk-principal-v6.yaml": "1998a8787332908d955ab6e8769f315dac4afe80fb2e66b57dc34ad7a916cf25",
    "peaso/privesc/catalog/gcp/dlp.yaml": "a4191890cd5bb94485588a7830567975f59ded4b2043f58331a4e6a60223187d",
    "peaso/privesc/catalog/gcp/exact-principal-v5.yaml": "345e1f41d7baf6f859b65eb6abdf8b6be5bf25781a9b25602ab1481bf1c7ec0b",
    "peaso/privesc/catalog/gcp/parametermanager.yaml": "8273c65df5d117386103e3694b7074ab002487b851706897c63d44300f76acab",
    "peaso/privesc/catalog/gcp/secretmanager.yaml": "7ddb46238daeeba20663d30f5a2f07ab25b26cfd8838895787043a6b28c5b23e",
    "peaso/privesc/catalog/k8s/scoped-credential-v7.yaml": "7c4940f42a1754cd843688fcd903a522cd99ea98491c20a1ef5ed77dd75008a5",
    "peaso/privesc/catalog_versions/bounded-v5-manifest.json": "082451e81fa450830ae5f6835e241dd412a6c30a8b2a0b1172cdbc89b2d71429",
    "peaso/privesc/catalog_versions/bulk-principal-v6-manifest.json": "734401b202895e00ac1b6cb0f1534f77cde4d8e2ba912ca0ee974b1b8ec5035c",
    "peaso/privesc/catalog_versions/disclosure-v7-manifest.json": "91ffe7389d02568cdcdf74a6b08dafa5f665ea07c0c528988127ffc4d2a86c45",
    "peaso/privesc/catalog_versions/legacy-0b3633-delta.json": "40640ad0e7179af395ec37f9456ef7b9d8340e8ab81e9edb7a460769edca258a",
    "peaso/privesc/catalog_versions/principal-v4-manifest.json": "6008acf71acda21408c7039dddff2d7ccaeeaa3aecfc6f31ef5d2cdc5a4ea388",
    "peaso/privesc/effective_permissions/azure_disclosure_effects.py": "554dba11bab6ad0145960f8b594ae58ab165e00c0fbe3fb91c3a4bcfa6ef197f",
    "peaso/privesc/effective_permissions/bounded_evidence.py": "1cd1a44f2d955bb5dc877e404ab09294a3df9b67bb1ff9e867aec1cd0cf212af",
    "peaso/privesc/effective_permissions/credential_evidence.py": "a95078884cd2e1c91e3e729921254844237eaa0444b89bf0cd6afd88d9fcaef3",
    "peaso/privesc/effective_permissions/ec2_profile_association.py": "22f0c201cc7d2b37f26c26e307dca33ce55e5716c5f6bea64affc78aff78e039",
    "peaso/privesc/effective_permissions/principal_evidence.py": "2c4bd5e2e2fa33db271b963387787003a42e1c741dad27b22e7b37f23fc2f7e3",
    "peaso/privesc/effective_permissions/storage_local_identity.py": "7671720b0780e47c583e0877888235406c220e64b937d361edb555f3300df7d0",
    "peaso/privesc/exact_principal_tranche.json": "c02921ad9a694b07415ffd5de0c97a0e8b0f34b73bbf40dc3b78e149e29b4af6",
    "peaso/privesc/versioned_catalog.py": "fd6831825507de22b7155909b3bdc1f1e391244b85a180b7764e22f7974f6666",
    "peaso/rulepacks/remediation_compliance_batch_remaining_aws.json": "ebe28d47a1880fa09acc7f42022a1e199ac9c27992049d2ca074670b41d6d490",
    "peaso/rulepacks/remediation_compliance_batch_remaining_azure.json": "a8f76c1a53926fa6cbbda666e80108b494d7933d77d9d39f6d1226f02937b91a",
    "peaso/rulepacks/remediation_compliance_batch_remaining_gcp.json": "5d618ab15fa5cd624e2b2559ab9f308dabe5fb2fa255d33ff664386c5e97b71c",
    "peaso/rulepacks/remediation_compliance_batch_remaining_k8s.json": "5485734fd0351e2dc8f6862b65472164e05df802e32d9c08d061826d1f1492ca",
    "peaso/server/native_policy_validation.py": "2dcecfe126bbda97e47d8126bc5bfeb8cdff886756e4703b38894988f40e5559"
}
APPROVED_V20_RUNTIME_MEMBERS = 909
APPROVED_V20_RUNTIME_SHA256 = '1c98ed3c1c09c1a2cf4d2bc3d724f12e07378972b22e51965193441ec5477af8'


# Exact private V21 successor; all earlier admission maps remain immutable.
APPROVED_V21_RUNTIME_ADDITIONS = {
    "peaso/analysis/aws_public_ingress.py": "f58f4f100215dd35da15ec177fbfa1b90145a6bf02fbd80afd759374544f06f0",
    "peaso/aws_budget_policy.py": "940a71e4627173e814381a148744a3840c81f60957f5bd2a6032fa4086ba4b69",
    "peaso/aws_waf_logging.py": "f97074cf8e7ecfb00ac1bac45947bdcd628affe294a0465283b1a5a35eb7c8b9",
    "peaso/azure_sw32_policy.py": "656c52580e63e50d926fa8d30172fa64401eb203b3f313ef5b036e3bf4b45812",
    "peaso/checks/aws_all_policies.json": "8e1cdcc44749b643d95e4ee223e386a4b4aba609d9e09a0577779cc34daa83bf",
    "peaso/checks/aws_all_policies.py": "46c12e7ef9f8ed1eac29709c720c0b703e71ee7d0ac15c2427c99346747ab9fe",
    "peaso/checks/aws_all_policies_fixtures.json": "f93d3feb539b593561b3cf9878a0f151e5619ab29bb43984e9963e141eee9401",
    "peaso/checks/aws_backup_plan_frequency.py": "0f40ddcace19dded128369f32efad6d72e36a8a95590073beb8cada2d4cff08d",
    "peaso/checks/aws_config_recording.py": "50800c1a5c30aa407d0791d4416cc473ea19c3d03f584a2a4a2cfa694d2eabec",
    "peaso/checks/azure_apim_diagnostics_native.py": "4221d0aa3092bff0bb5eeb11fdf3ecc58687f0899a52523fbfeed412bb4af55b",
    "peaso/checks/azure_apim_native.py": "af1e1903c167c813e1ab8e8a9c7fa2336dc6cb5f9d8757f7beaaf6f481744f6b",
    "peaso/checks/azure_appservice_identity_followup.py": "ca7ffd2dccf77fd8e7b90d31c567cbb48b666300330555242582efe768347463",
    "peaso/checks/azure_easm_native.py": "d75e42848fae6c53b0f9e29fdb5c568325bbf8f2e136a7dcc435c58b1036f94b",
    "peaso/checks/azure_graph_credential_age.py": "ba0b2f87162cbace267cb0d630f05655d59239b287d9e7ae6b4f8744cc30a7b4",
    "peaso/checks/azure_log_profile_retention.py": "ba369f5809f8484310b89079ee0b4c3a5523f561ff03cd349488766cc86837ba",
    "peaso/checks/batch_remaining_aws.py": "197ccf540f23e9373d8db281bf1544d2d2bba793be3738ff214e9a6038d813b2",
    "peaso/checks/batch_remaining_azure.py": "82e39d57beef687761098e206457e5e7f7e25a792fc9fcc8600d809f4737b136",
    "peaso/checks/batch_remaining_azure_vm_storage.py": "11f0353505ec70bb7cbc1f6f72add7ceb664fcbd01d05bd8018b2063dd09babb",
    "peaso/checks/batch_remaining_gcp.py": "4f93aebdb8c4fabb603cc122b7a390bc153abc6039035c4a0e780be708aed870",
    "peaso/checks/batch_remaining_k8s.py": "0f0c92c50a05e92bfd0357767066e4e481c03320c2f582ff10194d8cc25dd578",
    "peaso/checks/bulk_pending.json": "b51e99b8acfab245cfc6f04e99405f0fad78be3c082a61ac652a862b7bf7b7b8",
    "peaso/checks/bulk_pending.py": "41cd15965640293562f1808fd7cc31b85769a3e3a44aa3c5537d119dabd50a11",
    "peaso/checks/central_batch_fixtures.json": "1a226d4af6f26c7216c305d36109226bed11e28051c936cb86f66ffcb5dc734b",
    "peaso/checks/central_native_fixtures.py": "2b9665b5b12e164a76b0982bc055857be82cd72d09eafcb8588bc96ead0503f4",
    "peaso/checks/compliance_new_sw25_native_identity.py": "c347440d7e378900762fc5cf6253203c61325008f6320008919d68cb5c37c53e",
    "peaso/checks/compliance_next_k8s.py": "d0184f0934601aaa4682c07d1f0dbfa1b40fa2e9090ce2ca53ca413471b96dfc",
    "peaso/checks/gcp_audit_native.py": "8c2f5e8d0a76571c06a0e0ade0e83cd54f0814fe525fc9f293968224ba2edf8f",
    "peaso/checks/gcp_audit_rates.json": "5010787138c533e7af252d5cfc2aab641097fb6bc9607d6018a66aac943554d9",
    "peaso/checks/gcp_audit_rates.py": "efb0da440e417b40efbcbf189b0fb62385be3b849136b04de08f61baff8e748c",
    "peaso/checks/gcp_audit_rates_fixtures.json": "2d2fd4319e86bb5f54d0f99b6c28ca0788504e46e822afdaed5d0dfe108a4354",
    "peaso/checks/gcp_data_access.py": "ce997648d524475e848aff41353b99f3add7075eca451146a89a7998da9f51c5",
    "peaso/checks/gcp_psc_dns.py": "4d820199813173d9f32ab2b4a5b4547c449d7f88e69affe1064247cb2df1e599",
    "peaso/checks/gcp_psc_fixtures.json": "d452ed303ed02d23d05e1ef1efce880264002779bf3073dee79239a3764a6138",
    "peaso/checks/k8s_namespace_policy_presence.py": "47f64b995e1f5ca9b6db72ff62a7a4594521448f2a1fbba174d453251698a2b2",
    "peaso/checks/native_storage_compute.json": "e4891a7a99339126380eab0a9e66e855c4b1f7ee8558e79abe64a2471fac7c9d",
    "peaso/checks/native_storage_compute.py": "66bc80ff2d43d7d394defa1180199abf42fb0c40b56ff2696ce5f9733f1de318",
    "peaso/checks/native_storage_compute_fixtures.json": "815860e018a22d38bf666b17a981d28993bea720567d369e28e1d26b1339f274",
    "peaso/checks/next20_aws.py": "8b5bedb10366b2708e445bc0068f41a1e6aea0bf8fe7f20c81029dfce665e569",
    "peaso/checks/next_group_appservice_fixtures.py": "1f461d725797b538f7e6550f7aa70217b029e6ec846a3a9e7ce5e6531057c3be",
    "peaso/checks/next_group_aws_fixtures.py": "0076893df5c07f55cd2244d98afaa4516e56f5a1a7bb4f3c5bf7ee1874adb90a",
    "peaso/checks/next_group_azure_fixtures.py": "274822bd1753bef38af173b6be01774abba8ab1bb6b0a0fe3d76638b2e0da249",
    "peaso/checks/next_group_easm_fixtures.py": "3162d5c0deeb1122ddddb06a82793167366dc71f17983547365791854f0406a8",
    "peaso/checks/post_dfaf_aws.py": "301493a4bd3ee865d3d830807a9d6481ef5e3910b3e8ba99c26b57b487cd0fce",
    "peaso/checks/post_dfaf_aws_specs.py": "4f2410348d731c2c76c3db79b0b2b0aebedebf874ce9044f9dccb612622d2476",
    "peaso/checks/post_dfaf_azure.py": "c00e5f758009f1929eb97f83a096706874b97fc6e2269dea8ccdab06c8e5640e",
    "peaso/checks/remaining_aws_gcp_native.py": "ded9f2aa60b562cc3db565a091434ad182e8ae8635d4b128549b827a39a6f5f9",
    "peaso/checks/wafv2_basic.py": "b300d867db2803793f56b23dbd2c51751435236428267e12e23c398c99316437",
    "peaso/collectors/aws_all_policies.py": "4be1797ead0658962fe64ddd17ac4437df49b3612e0d8746cf7315734e4a9886",
    "peaso/collectors/aws_apigateway_native.py": "bf5c20ba91a679dcd303579b89ef6f9fd3b96e4664254716b5c98e4367e854a5",
    "peaso/collectors/aws_budget_stop_native.py": "8001bc5895828ec8fc38baeda5a9e5f863866a3d32889e7b1804a06338dbba44",
    "peaso/collectors/aws_bulk_inventory.py": "45aa2a3bce8581cf8bf1046e882eb701a03b61367378fdcee70d3b5ef415230d",
    "peaso/collectors/aws_cloudtrail_delivery_native.py": "bf7348354a77a39d2271f1b022d1620b0e7f7d3b68dc021cf06f86aceb369393",
    "peaso/collectors/aws_codebuild_redaction.py": "d3f487ca28fae5563b2cd5839f760dbd742e859388ab0646dc762d5c7826f18d",
    "peaso/collectors/aws_codecommit_review_native.py": "8700c0be3a48fe2d6a72ed29390d5938ce2b901ecfccfb829a94cc9618249e93",
    "peaso/collectors/aws_controltower_native.py": "4cc022c9698532209a75fe280851e291964efb9244ff70ef607bdda685753999",
    "peaso/collectors/aws_cost_policy.py": "1e53fa329bbaeba16b0548bbd6b912ebbadd4a22c1e1732c24665d68b36fc42d",
    "peaso/collectors/aws_ecr_artifacts_native.py": "3beaa9b23013e715902d29d76064c0bcf205c569b02b38f74d2c7ba0cd66e99c",
    "peaso/collectors/aws_facts_v4_holds.py": "1e2cec696c00e1b002111fa1c4e3d17f41585c115db0808e11162705e1cd9356",
    "peaso/collectors/aws_identity_center_native.py": "60592e3ff76ae393ed43d89f1554fb2da1f0daaf836b5e640c8760e8b0a66d3e",
    "peaso/collectors/aws_identity_metrics_native.py": "f96984d474dcb07f03ddc4a998d5c0ae32563677f0eaa2a02384bc79dafadfc0",
    "peaso/collectors/aws_kms_enclave_native.py": "589935d3ebd9bd13c1d58adf304daf78359374c8e78f88549f2db83c3f32d069",
    "peaso/collectors/aws_launch_configuration_redaction.py": "09f0a76060934ef47924c1cf747079ca0dba6a82e5803686155067516eb951b5",
    "peaso/collectors/aws_macie_coverage_native.py": "5650b5a3e15a654cda7d2e5dcd2974124c6a0a711e1798202bf11e4ca5e65a7b",
    "peaso/collectors/aws_operational_groups_native.py": "06108480e7c2f75ca30343ea5ca4fe3dc0a3fa92d8dee9cf2ccf8f47150f2456",
    "peaso/collectors/aws_organizations_native.py": "f331e1cd6fa1a496bcfffb0a3eeb93d72004028dec1bc72d63db731dd1feae5a",
    "peaso/collectors/aws_policy.py": "a3003f6c3930bd5f23523cc6128192ee6a22891a47035df922e34498ada0429d",
    "peaso/collectors/aws_priority_tags_native.py": "c1f67bb05912bb0e60303989dc722093d379e93d56796c48ca81dc40ddb353f1",
    "peaso/collectors/aws_public_ingress_native.py": "3dda8ed8ffdb9e3b650ffe50bc6da24d52f57e53c908357ef9bc4a2094309b7e",
    "peaso/collectors/aws_region_shield_native.py": "08f2a665106e9e66b799fa75946739b57c01076fed23b882f3f63651b652d471",
    "peaso/collectors/aws_resolver_firewall_native.py": "ca0970fa271384e2167db3cb2ed855cceda0dd834348671654597ec3d8b19a52",
    "peaso/collectors/aws_resource_policy_native.py": "b0c7b4081f965bab4ece4de503fac0de65038c6c98df010f877f745ce940998e",
    "peaso/collectors/aws_s3_backup_native.py": "48654c9bb7c4fcbb5ee52c8035cb0fd29d0d8a716b358e9d8399a4595aad3ffd",
    "peaso/collectors/aws_sagemaker_clarify_native.py": "f6695218f1c6f5dd060b7871b516d975fb54e1560aba5a413698b589aaa113af",
    "peaso/collectors/aws_ssm_inventory_events_native.py": "c495038efa6858ee77d75a1090fe357998076455da3c1c4bebc105fd9e00370a",
    "peaso/collectors/aws_transport_native.py": "ab038928f14c3136df4c9425856e57b2b199afa24085d739b4f8526a225e53e6",
    "peaso/collectors/aws_waf_inventory_native.py": "10bcdf16a32dc1edd69ef751dd2a1427dbeb5a1c10cf91fd605b97c6dd2ada20",
    "peaso/collectors/azure_access_reviews_native.py": "11647049e6d04b1e9985ec51f9e890c02b0e8da66f67391979628a60e772bd6f",
    "peaso/collectors/azure_aks_workloads_native.py": "d96b6c68485b6d67e86dcbfa7380fc085f6920cf82c6f86edbcf2fa1a883c2f5",
    "peaso/collectors/azure_apim_diagnostics_native.py": "d5fe9f4b821fa80c1bed677df063971d6ac61278d315b93eb24b4a7957f9bc2e",
    "peaso/collectors/azure_apim_native.py": "f43150e470199e27637de0760fd288aed07362f69378290567a78e42d9eb7975",
    "peaso/collectors/azure_appservice_identity_followup.py": "d5e135f5973b2909974bfd2bf5cb43c03931e71590e63649da35850a75554aaf",
    "peaso/collectors/azure_arm_metadata_native.py": "f244de81694d42e796544d520ab3d631faa58e115f9622ad61d039fe12c4fa50",
    "peaso/collectors/azure_assessment_criteria_native.py": "42ceb16728f8bde78874d38037c835085c1dba1770c3dab84c6b2a03cc268d1a",
    "peaso/collectors/azure_conditional_access_native.py": "9b69def3b75a31ab41eaeac2757b85fe9d3d4f505f948043cd8491cd0ebabe8a",
    "peaso/collectors/azure_database_native.py": "2b5c6850d33f9a74fc6bf46f92bab1330f1d4ae21e92a6461357cde837c3f683",
    "peaso/collectors/azure_databricks_native.py": "3c6c56e700376316c7f711f7dc4981b4f02ec145bacf6553d9163326f7e64359",
    "peaso/collectors/azure_defender_network_native.py": "ce70e05680d870ba145baed0701471783c721446a1781474f70c3b0bbb1985da",
    "peaso/collectors/azure_detection_telemetry.py": "d0c1e354f8c5fbfd8504667dd0268f3e685444e6aa1a5507abb336d16817758d",
    "peaso/collectors/azure_disclosure_native.py": "1038ca6d576f89c6d9bced0182239b140f4dbe51e7aafb60a1b569634f15426d",
    "peaso/collectors/azure_entra_diagnostics_native.py": "3ba791cd52c3e5b2fb78bcb12fced683402d552f8a8ff3bd13fec65fc941636f",
    "peaso/collectors/azure_frontdoor_native.py": "f020ec13c4a8ddd12c8e276f24538cb7c698f707b1f4eaebb52ce14e3305f675",
    "peaso/collectors/azure_function_limits_native.py": "cd1b13b2fd9d7983e1846fe651507a26422f4ab9cf7dd9866cdf9c50f28fc7e9",
    "peaso/collectors/azure_guest_configuration_native.py": "d534f80d292e158eba0caad3629b1d0fe54987c2cdbaf7e33a56a672f6159a54",
    "peaso/collectors/azure_guest_policy.py": "55f32bdb4d9e25f6603321fcb8a0877e07bce003ea7f2b02ea080401c2905c4d",
    "peaso/collectors/azure_guest_reports.py": "3b0b5a169a73bd97975b8968fed0b2e13b935ac8bc5f297ed791a128f8e74e4b",
    "peaso/collectors/azure_identity_intune_native.py": "02b0b6d133a2f0d30cb2e30a99d6d3d4feef78231eb61e680acd02987f0896fc",
    "peaso/collectors/azure_iot_policy_native.py": "5daa1c505286ba57c4f1ec016f54f5713b138d3b45cfd1c5fb542ee3ad893468",
    "peaso/collectors/azure_monitor_inventory_native.py": "81bd15cf090e296be7a299da4b7b9e42657c987bbed6afdeb82a0453a90e6127",
    "peaso/collectors/azure_resource_diagnostics_native.py": "36f73fc3665680b2489ab99c24dfee59b5f2afb236323952e7131dea481df0ed",
    "peaso/collectors/azure_resource_logging_policy.py": "2d7174efd2706acf66466e3216d95ec1b81d2af1cf5b1b54a8144246ca25d0ba",
    "peaso/collectors/azure_secret_versions_native.py": "53d8ad1f7599697fab83af4139644c93223f9cdbfc5355e587749e545149120c",
    "peaso/collectors/azure_sentinel_metadata_native.py": "3cc20e96f438c017261006a2e9d04f16cfc2d01224515a9477f73a7872e9896b",
    "peaso/collectors/azure_sql_inventory.py": "43a1549a843593c8e33812f5dfa9091a0e7ab534d895ea3e03e718cf08ec82ae",
    "peaso/collectors/azure_storage_backup_native.py": "249e5916a527ecd0d80378c1a4e769fc3511152f0887a85186bc1285aa473405",
    "peaso/collectors/azure_storage_recovery_metadata_native.py": "658807c10ba59c65ecc7a86bd0cae1d3079d785612b69b829908cc135cb81ca0",
    "peaso/collectors/azure_sw15_policy.py": "66a6ff162aa2727a33c3079cfd2709cbea883ce5bcc2f16407ef111743a5b82d",
    "peaso/collectors/batch_remaining_azure_vm_storage.py": "44bb52e7d7e9e7290cb302e439e1ada18b3dd278895125c857fd028dffa21053",
    "peaso/collectors/batch_remaining_k8s.py": "8c15aa07719cc9596edb3aa7128c99b8d301ef35269ab860ceeb238bec95bb3e",
    "peaso/collectors/bulk_evidence.json": "c1d173bead561f5777df8e703dd8a0939692202b8f2fe7427e8e6d72457a5744",
    "peaso/collectors/bulk_evidence.py": "fb51c829ddc9ca2c83e7cb54de8e1ebc91c0530a8d7eb47d6083e5ff170e6e09",
    "peaso/collectors/gcp_audit_native.py": "02554f3aa9bf2a4d450455c75c6b7fac5ca2396e1afededd34db42a6ec4179e8",
    "peaso/collectors/gcp_facts_v4_holds.py": "f52b9df380e2e69de33cd39bd99f3fda30cac030a1a583c50660b8b9a083f39f",
    "peaso/collectors/gcp_history.py": "21368065d8d1a46209e88d623bb848fe2e3dcb0e4e4c0e5b01f867b8ecf4e631",
    "peaso/collectors/gcp_kms_effective_native.py": "7d2c1e81afebac5e99d47951c85c24aeb91e1795d3fe233c396d9bac6a30ae01",
    "peaso/collectors/gcp_native_evidence.py": "fdced136c30eca42529c967ba2a59f84068008ee98345a1a7abc2c974ca060e1",
    "peaso/collectors/gcp_os_patch_native.py": "e8d86dbc207104d2dbc59d2c0dd0a558f7d00e7edde5960d2750fa7803a85f58",
    "peaso/collectors/gcp_sbom_native.py": "e4fc4bc0c455146ed580d7ef3406424c8ddca2588ccf5cb7c723b922931902f8",
    "peaso/collectors/gcp_storage_acl_native.py": "9ef114ced31862ed48cc3defc7710623e130fcd6431051174fc44b6d19fa2033",
    "peaso/collectors/k8s_admission_file.py": "fc23c5692f1bc295394cf770312a58a8bb64dc532d2c2d9ad33cfeb8a440795f",
    "peaso/gcp_data_access_policy.py": "03167a5cf56583a9ae4efb08aba2beb24fa0e62fcafded1b6f7f47181cb5d4c7",
    "peaso/gcp_psc_policy.py": "ceb9da0dca6e28d011e9f0d779fe519991bb78ec4e7df9bbba67494306eb0ff1",
    "peaso/gcp_sbom_policy.py": "ef717b7f45ddb6d7abca981b6a871f60d9dde0f1eee442c64ddb342ca60be788",
    "peaso/privesc/azure_disclosure_effects.json": "6caf92a0ffdc59cffecb0c9d047d31bc7c49fe02dd0f19b11f3ec743a670f93e",
    "peaso/privesc/bounded_effects.json": "4ce1a0b29fbf026bbc26166915f87e5fb2c4e6396a8aa37ee91e56ca1840806d",
    "peaso/privesc/bulk_principal_tranche.json": "6cb1c21ba90b1ae08d0e5671efa373c8711d42cdb97d3f9055f84d3a239428a8",
    "peaso/privesc/catalog/aws/bounded-effects-v5.yaml": "d38ce968f6af36e9d5c72a098916978320ebf61653df6e6b2c1916de3fbaf80a",
    "peaso/privesc/catalog/aws/bulk-principal-v6.yaml": "e4e907a900127eec6feaa5bb9527ddb130d52c4895b94fd65acb6e8b0a29c779",
    "peaso/privesc/catalog/aws/exact-principal-v5.yaml": "b198454714e4e530682cea805f5e1db595c9eb7a8057f35b1f8d426f88c2a709",
    "peaso/privesc/catalog/aws/lightsail.yaml": "1645b857297793df9c1f6a69e236cbff5873b65055e4e4056360c693c809a279",
    "peaso/privesc/catalog/azure/app_configuration.yaml": "937a2bbc1a2b42d08ef7d183653e540f7320b672c59d9ed5068a191a3aaca89b",
    "peaso/privesc/catalog/azure/bounded-effects-v5.yaml": "1ca7a8398150cd05f2146e3466be8713481870cdcedfaf8813aad3e41b12a9f4",
    "peaso/privesc/catalog/azure/disclosure-effects-v7.yaml": "00175d020192d57529b305d80b2027dcea8df7b58aac26e0c60fd03196b79d3a",
    "peaso/privesc/catalog/azure/monitor.yaml": "a2cec1047c97588d0537a02e1f5ac06ed091188097b8427369fc8362f715cada",
    "peaso/privesc/catalog/azure/storage-local-v7.yaml": "39fc0f2734331d8d08d356614775095d8b7be97bf343aa240e110c12d2988f9f",
    "peaso/privesc/catalog/azure/storage.yaml": "be4c268b9114175bbf079a4d9c70009392f9fab26afa47ea8100930255b19b15",
    "peaso/privesc/catalog/gcp/aiplatform.yaml": "d32d22ffb8909105cbc49f3fe0704df6ffb8e43494c7c908981d59dd31800c69",
    "peaso/privesc/catalog/gcp/bigtable.yaml": "436131e96ff896df4425319aee3952c6010909dab2b4256302a4367af8e230db",
    "peaso/privesc/catalog/gcp/bounded-effects-v5.yaml": "336a51ee7c3e5411d23c7e6fffd90849a28de2577ce2ccc02ff6e03877da5505",
    "peaso/privesc/catalog/gcp/bulk-principal-v6.yaml": "1998a8787332908d955ab6e8769f315dac4afe80fb2e66b57dc34ad7a916cf25",
    "peaso/privesc/catalog/gcp/dlp.yaml": "a4191890cd5bb94485588a7830567975f59ded4b2043f58331a4e6a60223187d",
    "peaso/privesc/catalog/gcp/exact-principal-v5.yaml": "345e1f41d7baf6f859b65eb6abdf8b6be5bf25781a9b25602ab1481bf1c7ec0b",
    "peaso/privesc/catalog/gcp/parametermanager.yaml": "8273c65df5d117386103e3694b7074ab002487b851706897c63d44300f76acab",
    "peaso/privesc/catalog/gcp/secretmanager.yaml": "7ddb46238daeeba20663d30f5a2f07ab25b26cfd8838895787043a6b28c5b23e",
    "peaso/privesc/catalog/k8s/scoped-credential-v7.yaml": "7c4940f42a1754cd843688fcd903a522cd99ea98491c20a1ef5ed77dd75008a5",
    "peaso/privesc/catalog_versions/bounded-v5-manifest.json": "082451e81fa450830ae5f6835e241dd412a6c30a8b2a0b1172cdbc89b2d71429",
    "peaso/privesc/catalog_versions/bulk-principal-v6-manifest.json": "734401b202895e00ac1b6cb0f1534f77cde4d8e2ba912ca0ee974b1b8ec5035c",
    "peaso/privesc/catalog_versions/disclosure-v7-manifest.json": "91ffe7389d02568cdcdf74a6b08dafa5f665ea07c0c528988127ffc4d2a86c45",
    "peaso/privesc/catalog_versions/legacy-0b3633-delta.json": "40640ad0e7179af395ec37f9456ef7b9d8340e8ab81e9edb7a460769edca258a",
    "peaso/privesc/catalog_versions/principal-v4-manifest.json": "6008acf71acda21408c7039dddff2d7ccaeeaa3aecfc6f31ef5d2cdc5a4ea388",
    "peaso/privesc/effective_permissions/azure_disclosure_effects.py": "554dba11bab6ad0145960f8b594ae58ab165e00c0fbe3fb91c3a4bcfa6ef197f",
    "peaso/privesc/effective_permissions/bounded_evidence.py": "1cd1a44f2d955bb5dc877e404ab09294a3df9b67bb1ff9e867aec1cd0cf212af",
    "peaso/privesc/effective_permissions/credential_evidence.py": "a95078884cd2e1c91e3e729921254844237eaa0444b89bf0cd6afd88d9fcaef3",
    "peaso/privesc/effective_permissions/ec2_profile_association.py": "22f0c201cc7d2b37f26c26e307dca33ce55e5716c5f6bea64affc78aff78e039",
    "peaso/privesc/effective_permissions/principal_evidence.py": "2c4bd5e2e2fa33db271b963387787003a42e1c741dad27b22e7b37f23fc2f7e3",
    "peaso/privesc/effective_permissions/storage_local_identity.py": "7671720b0780e47c583e0877888235406c220e64b937d361edb555f3300df7d0",
    "peaso/privesc/exact_principal_tranche.json": "c02921ad9a694b07415ffd5de0c97a0e8b0f34b73bbf40dc3b78e149e29b4af6",
    "peaso/privesc/versioned_catalog.py": "fd6831825507de22b7155909b3bdc1f1e391244b85a180b7764e22f7974f6666",
    "peaso/rulepacks/remediation_compliance_batch_remaining_aws.json": "ebe28d47a1880fa09acc7f42022a1e199ac9c27992049d2ca074670b41d6d490",
    "peaso/rulepacks/remediation_compliance_batch_remaining_azure.json": "a8f76c1a53926fa6cbbda666e80108b494d7933d77d9d39f6d1226f02937b91a",
    "peaso/rulepacks/remediation_compliance_batch_remaining_gcp.json": "5d618ab15fa5cd624e2b2559ab9f308dabe5fb2fa255d33ff664386c5e97b71c",
    "peaso/rulepacks/remediation_compliance_batch_remaining_k8s.json": "5485734fd0351e2dc8f6862b65472164e05df802e32d9c08d061826d1f1492ca",
    "peaso/server/native_policy_validation.py": "42932637bdc8953d4f30b8dccb64ddc4f64c79f498623ca376bae62981a5c3d2"
}
APPROVED_V21_SOURCE_MEMBERS = 1814
APPROVED_V21_RUNTIME_MEMBERS = 912
APPROVED_V21_RUNTIME_SHA256 = '152c26b57e775a97c3664858014917e924721e8b8aeeab62c222b7e869bcd067'


# Exact additive V23 software successor; approved V20/44b6 bytes remain pinned.
APPROVED_V23_RUNTIME_ADDITIONS = {
    "peaso/analysis/aws_public_ingress.py": "f58f4f100215dd35da15ec177fbfa1b90145a6bf02fbd80afd759374544f06f0",
    "peaso/aws_budget_policy.py": "940a71e4627173e814381a148744a3840c81f60957f5bd2a6032fa4086ba4b69",
    "peaso/aws_waf_logging.py": "f97074cf8e7ecfb00ac1bac45947bdcd628affe294a0465283b1a5a35eb7c8b9",
    "peaso/azure_devops_git_policy.py": "4c195e73eebf742314c3eeafe0d1f95356d58e71e6c2339d8b1b8b8d418e28ed",
    "peaso/azure_sw32_policy.py": "9d9a545dbc9240e29a3389445dcb9f032fd2350db059e38d49a95f0d90d9e3b0",
    "peaso/checks/aws_all_policies.json": "8e1cdcc44749b643d95e4ee223e386a4b4aba609d9e09a0577779cc34daa83bf",
    "peaso/checks/aws_all_policies.py": "46c12e7ef9f8ed1eac29709c720c0b703e71ee7d0ac15c2427c99346747ab9fe",
    "peaso/checks/aws_all_policies_fixtures.json": "f93d3feb539b593561b3cf9878a0f151e5619ab29bb43984e9963e141eee9401",
    "peaso/checks/aws_backup_plan_frequency.py": "0f40ddcace19dded128369f32efad6d72e36a8a95590073beb8cada2d4cff08d",
    "peaso/checks/aws_config_recording.py": "50800c1a5c30aa407d0791d4416cc473ea19c3d03f584a2a4a2cfa694d2eabec",
    "peaso/checks/azure_apim_diagnostics_native.py": "4221d0aa3092bff0bb5eeb11fdf3ecc58687f0899a52523fbfeed412bb4af55b",
    "peaso/checks/azure_apim_native.py": "af1e1903c167c813e1ab8e8a9c7fa2336dc6cb5f9d8757f7beaaf6f481744f6b",
    "peaso/checks/azure_appservice_identity_followup.py": "ca7ffd2dccf77fd8e7b90d31c567cbb48b666300330555242582efe768347463",
    "peaso/checks/azure_easm_native.py": "d75e42848fae6c53b0f9e29fdb5c568325bbf8f2e136a7dcc435c58b1036f94b",
    "peaso/checks/azure_graph_credential_age.py": "ba0b2f87162cbace267cb0d630f05655d59239b287d9e7ae6b4f8744cc30a7b4",
    "peaso/checks/azure_log_profile_retention.py": "ba369f5809f8484310b89079ee0b4c3a5523f561ff03cd349488766cc86837ba",
    "peaso/checks/batch_remaining_aws.py": "197ccf540f23e9373d8db281bf1544d2d2bba793be3738ff214e9a6038d813b2",
    "peaso/checks/batch_remaining_azure.py": "82e39d57beef687761098e206457e5e7f7e25a792fc9fcc8600d809f4737b136",
    "peaso/checks/batch_remaining_azure_vm_storage.py": "11f0353505ec70bb7cbc1f6f72add7ceb664fcbd01d05bd8018b2063dd09babb",
    "peaso/checks/batch_remaining_gcp.py": "4f93aebdb8c4fabb603cc122b7a390bc153abc6039035c4a0e780be708aed870",
    "peaso/checks/batch_remaining_k8s.py": "0f0c92c50a05e92bfd0357767066e4e481c03320c2f582ff10194d8cc25dd578",
    "peaso/checks/bulk_pending.json": "066f67372969d2b87af77c01dc8a77767be4a4bb7ac4ac81be64ceb3fa49a7c1",
    "peaso/checks/bulk_pending.py": "41cd15965640293562f1808fd7cc31b85769a3e3a44aa3c5537d119dabd50a11",
    "peaso/checks/central_batch_fixtures.json": "1a226d4af6f26c7216c305d36109226bed11e28051c936cb86f66ffcb5dc734b",
    "peaso/checks/central_native_fixtures.py": "2b9665b5b12e164a76b0982bc055857be82cd72d09eafcb8588bc96ead0503f4",
    "peaso/checks/compliance_new_sw25_native_identity.py": "c347440d7e378900762fc5cf6253203c61325008f6320008919d68cb5c37c53e",
    "peaso/checks/compliance_next_k8s.py": "d0184f0934601aaa4682c07d1f0dbfa1b40fa2e9090ce2ca53ca413471b96dfc",
    "peaso/checks/gcp_audit_native.py": "8c2f5e8d0a76571c06a0e0ade0e83cd54f0814fe525fc9f293968224ba2edf8f",
    "peaso/checks/gcp_audit_rates.json": "5010787138c533e7af252d5cfc2aab641097fb6bc9607d6018a66aac943554d9",
    "peaso/checks/gcp_audit_rates.py": "efb0da440e417b40efbcbf189b0fb62385be3b849136b04de08f61baff8e748c",
    "peaso/checks/gcp_audit_rates_fixtures.json": "2d2fd4319e86bb5f54d0f99b6c28ca0788504e46e822afdaed5d0dfe108a4354",
    "peaso/checks/gcp_data_access.py": "ce997648d524475e848aff41353b99f3add7075eca451146a89a7998da9f51c5",
    "peaso/checks/gcp_psc_dns.py": "4d820199813173d9f32ab2b4a5b4547c449d7f88e69affe1064247cb2df1e599",
    "peaso/checks/gcp_psc_fixtures.json": "d452ed303ed02d23d05e1ef1efce880264002779bf3073dee79239a3764a6138",
    "peaso/checks/k8s_namespace_policy_presence.py": "47f64b995e1f5ca9b6db72ff62a7a4594521448f2a1fbba174d453251698a2b2",
    "peaso/checks/native_storage_compute.json": "e4891a7a99339126380eab0a9e66e855c4b1f7ee8558e79abe64a2471fac7c9d",
    "peaso/checks/native_storage_compute.py": "66bc80ff2d43d7d394defa1180199abf42fb0c40b56ff2696ce5f9733f1de318",
    "peaso/checks/native_storage_compute_fixtures.json": "815860e018a22d38bf666b17a981d28993bea720567d369e28e1d26b1339f274",
    "peaso/checks/next20_aws.py": "8b5bedb10366b2708e445bc0068f41a1e6aea0bf8fe7f20c81029dfce665e569",
    "peaso/checks/next_group_appservice_fixtures.py": "1f461d725797b538f7e6550f7aa70217b029e6ec846a3a9e7ce5e6531057c3be",
    "peaso/checks/next_group_aws_fixtures.py": "0076893df5c07f55cd2244d98afaa4516e56f5a1a7bb4f3c5bf7ee1874adb90a",
    "peaso/checks/next_group_azure_fixtures.py": "274822bd1753bef38af173b6be01774abba8ab1bb6b0a0fe3d76638b2e0da249",
    "peaso/checks/next_group_easm_fixtures.py": "3162d5c0deeb1122ddddb06a82793167366dc71f17983547365791854f0406a8",
    "peaso/checks/post_dfaf_aws.py": "301493a4bd3ee865d3d830807a9d6481ef5e3910b3e8ba99c26b57b487cd0fce",
    "peaso/checks/post_dfaf_aws_specs.py": "4f2410348d731c2c76c3db79b0b2b0aebedebf874ce9044f9dccb612622d2476",
    "peaso/checks/post_dfaf_azure.py": "c00e5f758009f1929eb97f83a096706874b97fc6e2269dea8ccdab06c8e5640e",
    "peaso/checks/remaining_aws_gcp_native.py": "ded9f2aa60b562cc3db565a091434ad182e8ae8635d4b128549b827a39a6f5f9",
    "peaso/checks/wafv2_basic.py": "b300d867db2803793f56b23dbd2c51751435236428267e12e23c398c99316437",
    "peaso/collectors/aws_all_policies.py": "4be1797ead0658962fe64ddd17ac4437df49b3612e0d8746cf7315734e4a9886",
    "peaso/collectors/aws_apigateway_native.py": "bf5c20ba91a679dcd303579b89ef6f9fd3b96e4664254716b5c98e4367e854a5",
    "peaso/collectors/aws_budget_stop_native.py": "8001bc5895828ec8fc38baeda5a9e5f863866a3d32889e7b1804a06338dbba44",
    "peaso/collectors/aws_bulk_inventory.py": "45aa2a3bce8581cf8bf1046e882eb701a03b61367378fdcee70d3b5ef415230d",
    "peaso/collectors/aws_cloudtrail_delivery_native.py": "bf7348354a77a39d2271f1b022d1620b0e7f7d3b68dc021cf06f86aceb369393",
    "peaso/collectors/aws_codebuild_redaction.py": "d3f487ca28fae5563b2cd5839f760dbd742e859388ab0646dc762d5c7826f18d",
    "peaso/collectors/aws_codecommit_review_native.py": "8700c0be3a48fe2d6a72ed29390d5938ce2b901ecfccfb829a94cc9618249e93",
    "peaso/collectors/aws_controltower_native.py": "4cc022c9698532209a75fe280851e291964efb9244ff70ef607bdda685753999",
    "peaso/collectors/aws_cost_policy.py": "1e53fa329bbaeba16b0548bbd6b912ebbadd4a22c1e1732c24665d68b36fc42d",
    "peaso/collectors/aws_ecr_artifacts_native.py": "3beaa9b23013e715902d29d76064c0bcf205c569b02b38f74d2c7ba0cd66e99c",
    "peaso/collectors/aws_facts_v4_holds.py": "1e2cec696c00e1b002111fa1c4e3d17f41585c115db0808e11162705e1cd9356",
    "peaso/collectors/aws_identity_center_native.py": "60592e3ff76ae393ed43d89f1554fb2da1f0daaf836b5e640c8760e8b0a66d3e",
    "peaso/collectors/aws_identity_metrics_native.py": "f96984d474dcb07f03ddc4a998d5c0ae32563677f0eaa2a02384bc79dafadfc0",
    "peaso/collectors/aws_kms_enclave_native.py": "589935d3ebd9bd13c1d58adf304daf78359374c8e78f88549f2db83c3f32d069",
    "peaso/collectors/aws_launch_configuration_redaction.py": "09f0a76060934ef47924c1cf747079ca0dba6a82e5803686155067516eb951b5",
    "peaso/collectors/aws_macie_coverage_native.py": "5650b5a3e15a654cda7d2e5dcd2974124c6a0a711e1798202bf11e4ca5e65a7b",
    "peaso/collectors/aws_operational_groups_native.py": "06108480e7c2f75ca30343ea5ca4fe3dc0a3fa92d8dee9cf2ccf8f47150f2456",
    "peaso/collectors/aws_organizations_native.py": "f331e1cd6fa1a496bcfffb0a3eeb93d72004028dec1bc72d63db731dd1feae5a",
    "peaso/collectors/aws_policy.py": "a3003f6c3930bd5f23523cc6128192ee6a22891a47035df922e34498ada0429d",
    "peaso/collectors/aws_priority_tags_native.py": "c1f67bb05912bb0e60303989dc722093d379e93d56796c48ca81dc40ddb353f1",
    "peaso/collectors/aws_public_ingress_native.py": "3dda8ed8ffdb9e3b650ffe50bc6da24d52f57e53c908357ef9bc4a2094309b7e",
    "peaso/collectors/aws_region_shield_native.py": "08f2a665106e9e66b799fa75946739b57c01076fed23b882f3f63651b652d471",
    "peaso/collectors/aws_resolver_firewall_native.py": "ca0970fa271384e2167db3cb2ed855cceda0dd834348671654597ec3d8b19a52",
    "peaso/collectors/aws_resource_policy_native.py": "b0c7b4081f965bab4ece4de503fac0de65038c6c98df010f877f745ce940998e",
    "peaso/collectors/aws_s3_backup_native.py": "48654c9bb7c4fcbb5ee52c8035cb0fd29d0d8a716b358e9d8399a4595aad3ffd",
    "peaso/collectors/aws_sagemaker_clarify_native.py": "f6695218f1c6f5dd060b7871b516d975fb54e1560aba5a413698b589aaa113af",
    "peaso/collectors/aws_ssm_inventory_events_native.py": "c495038efa6858ee77d75a1090fe357998076455da3c1c4bebc105fd9e00370a",
    "peaso/collectors/aws_transport_native.py": "ab038928f14c3136df4c9425856e57b2b199afa24085d739b4f8526a225e53e6",
    "peaso/collectors/aws_waf_inventory_native.py": "10bcdf16a32dc1edd69ef751dd2a1427dbeb5a1c10cf91fd605b97c6dd2ada20",
    "peaso/collectors/azure_access_reviews_native.py": "11647049e6d04b1e9985ec51f9e890c02b0e8da66f67391979628a60e772bd6f",
    "peaso/collectors/azure_aks_workloads_native.py": "d96b6c68485b6d67e86dcbfa7380fc085f6920cf82c6f86edbcf2fa1a883c2f5",
    "peaso/collectors/azure_apim_diagnostics_native.py": "d5fe9f4b821fa80c1bed677df063971d6ac61278d315b93eb24b4a7957f9bc2e",
    "peaso/collectors/azure_apim_native.py": "f43150e470199e27637de0760fd288aed07362f69378290567a78e42d9eb7975",
    "peaso/collectors/azure_appservice_identity_followup.py": "d5e135f5973b2909974bfd2bf5cb43c03931e71590e63649da35850a75554aaf",
    "peaso/collectors/azure_arm_metadata_native.py": "f244de81694d42e796544d520ab3d631faa58e115f9622ad61d039fe12c4fa50",
    "peaso/collectors/azure_assessment_criteria_native.py": "42ceb16728f8bde78874d38037c835085c1dba1770c3dab84c6b2a03cc268d1a",
    "peaso/collectors/azure_conditional_access_native.py": "9b69def3b75a31ab41eaeac2757b85fe9d3d4f505f948043cd8491cd0ebabe8a",
    "peaso/collectors/azure_database_native.py": "2b5c6850d33f9a74fc6bf46f92bab1330f1d4ae21e92a6461357cde837c3f683",
    "peaso/collectors/azure_databricks_native.py": "3c6c56e700376316c7f711f7dc4981b4f02ec145bacf6553d9163326f7e64359",
    "peaso/collectors/azure_defender_network_native.py": "ce70e05680d870ba145baed0701471783c721446a1781474f70c3b0bbb1985da",
    "peaso/collectors/azure_detection_telemetry.py": "d0c1e354f8c5fbfd8504667dd0268f3e685444e6aa1a5507abb336d16817758d",
    "peaso/collectors/azure_devops_git_native.py": "7b01f9f26acae14414d33b42095caad14adaf4644b3706fde2120e170b4c2c63",
    "peaso/collectors/azure_disclosure_native.py": "1038ca6d576f89c6d9bced0182239b140f4dbe51e7aafb60a1b569634f15426d",
    "peaso/collectors/azure_entra_diagnostics_native.py": "3ba791cd52c3e5b2fb78bcb12fced683402d552f8a8ff3bd13fec65fc941636f",
    "peaso/collectors/azure_frontdoor_native.py": "f020ec13c4a8ddd12c8e276f24538cb7c698f707b1f4eaebb52ce14e3305f675",
    "peaso/collectors/azure_function_limits_native.py": "cd1b13b2fd9d7983e1846fe651507a26422f4ab9cf7dd9866cdf9c50f28fc7e9",
    "peaso/collectors/azure_guest_configuration_native.py": "d534f80d292e158eba0caad3629b1d0fe54987c2cdbaf7e33a56a672f6159a54",
    "peaso/collectors/azure_guest_policy.py": "55f32bdb4d9e25f6603321fcb8a0877e07bce003ea7f2b02ea080401c2905c4d",
    "peaso/collectors/azure_guest_reports.py": "3b0b5a169a73bd97975b8968fed0b2e13b935ac8bc5f297ed791a128f8e74e4b",
    "peaso/collectors/azure_identity_intune_native.py": "02b0b6d133a2f0d30cb2e30a99d6d3d4feef78231eb61e680acd02987f0896fc",
    "peaso/collectors/azure_iot_policy_native.py": "5daa1c505286ba57c4f1ec016f54f5713b138d3b45cfd1c5fb542ee3ad893468",
    "peaso/collectors/azure_monitor_inventory_native.py": "81bd15cf090e296be7a299da4b7b9e42657c987bbed6afdeb82a0453a90e6127",
    "peaso/collectors/azure_resource_diagnostics_native.py": "36f73fc3665680b2489ab99c24dfee59b5f2afb236323952e7131dea481df0ed",
    "peaso/collectors/azure_resource_logging_policy.py": "2d7174efd2706acf66466e3216d95ec1b81d2af1cf5b1b54a8144246ca25d0ba",
    "peaso/collectors/azure_secret_versions_native.py": "53d8ad1f7599697fab83af4139644c93223f9cdbfc5355e587749e545149120c",
    "peaso/collectors/azure_sentinel_metadata_native.py": "3cc20e96f438c017261006a2e9d04f16cfc2d01224515a9477f73a7872e9896b",
    "peaso/collectors/azure_sql_inventory.py": "43a1549a843593c8e33812f5dfa9091a0e7ab534d895ea3e03e718cf08ec82ae",
    "peaso/collectors/azure_storage_backup_native.py": "249e5916a527ecd0d80378c1a4e769fc3511152f0887a85186bc1285aa473405",
    "peaso/collectors/azure_storage_recovery_metadata_native.py": "658807c10ba59c65ecc7a86bd0cae1d3079d785612b69b829908cc135cb81ca0",
    "peaso/collectors/azure_sw15_policy.py": "66a6ff162aa2727a33c3079cfd2709cbea883ce5bcc2f16407ef111743a5b82d",
    "peaso/collectors/batch_remaining_azure_vm_storage.py": "44bb52e7d7e9e7290cb302e439e1ada18b3dd278895125c857fd028dffa21053",
    "peaso/collectors/batch_remaining_k8s.py": "8c15aa07719cc9596edb3aa7128c99b8d301ef35269ab860ceeb238bec95bb3e",
    "peaso/collectors/bulk_evidence.json": "c1d173bead561f5777df8e703dd8a0939692202b8f2fe7427e8e6d72457a5744",
    "peaso/collectors/bulk_evidence.py": "fb51c829ddc9ca2c83e7cb54de8e1ebc91c0530a8d7eb47d6083e5ff170e6e09",
    "peaso/collectors/gcp_audit_native.py": "02554f3aa9bf2a4d450455c75c6b7fac5ca2396e1afededd34db42a6ec4179e8",
    "peaso/collectors/gcp_facts_v4_holds.py": "f52b9df380e2e69de33cd39bd99f3fda30cac030a1a583c50660b8b9a083f39f",
    "peaso/collectors/gcp_history.py": "21368065d8d1a46209e88d623bb848fe2e3dcb0e4e4c0e5b01f867b8ecf4e631",
    "peaso/collectors/gcp_kms_effective_native.py": "7d2c1e81afebac5e99d47951c85c24aeb91e1795d3fe233c396d9bac6a30ae01",
    "peaso/collectors/gcp_native_evidence.py": "fdced136c30eca42529c967ba2a59f84068008ee98345a1a7abc2c974ca060e1",
    "peaso/collectors/gcp_os_patch_native.py": "e8d86dbc207104d2dbc59d2c0dd0a558f7d00e7edde5960d2750fa7803a85f58",
    "peaso/collectors/gcp_sbom_native.py": "e4fc4bc0c455146ed580d7ef3406424c8ddca2588ccf5cb7c723b922931902f8",
    "peaso/collectors/gcp_storage_acl_native.py": "9ef114ced31862ed48cc3defc7710623e130fcd6431051174fc44b6d19fa2033",
    "peaso/collectors/k8s_admission_file.py": "fc23c5692f1bc295394cf770312a58a8bb64dc532d2c2d9ad33cfeb8a440795f",
    "peaso/gcp_data_access_policy.py": "03167a5cf56583a9ae4efb08aba2beb24fa0e62fcafded1b6f7f47181cb5d4c7",
    "peaso/gcp_psc_policy.py": "ceb9da0dca6e28d011e9f0d779fe519991bb78ec4e7df9bbba67494306eb0ff1",
    "peaso/gcp_sbom_policy.py": "ef717b7f45ddb6d7abca981b6a871f60d9dde0f1eee442c64ddb342ca60be788",
    "peaso/privesc/azure_disclosure_effects.json": "6caf92a0ffdc59cffecb0c9d047d31bc7c49fe02dd0f19b11f3ec743a670f93e",
    "peaso/privesc/bounded_effects.json": "4ce1a0b29fbf026bbc26166915f87e5fb2c4e6396a8aa37ee91e56ca1840806d",
    "peaso/privesc/bulk_principal_tranche.json": "6cb1c21ba90b1ae08d0e5671efa373c8711d42cdb97d3f9055f84d3a239428a8",
    "peaso/privesc/catalog/aws/bounded-effects-v5.yaml": "d38ce968f6af36e9d5c72a098916978320ebf61653df6e6b2c1916de3fbaf80a",
    "peaso/privesc/catalog/aws/bulk-principal-v6.yaml": "e4e907a900127eec6feaa5bb9527ddb130d52c4895b94fd65acb6e8b0a29c779",
    "peaso/privesc/catalog/aws/exact-principal-v5.yaml": "b198454714e4e530682cea805f5e1db595c9eb7a8057f35b1f8d426f88c2a709",
    "peaso/privesc/catalog/aws/lightsail.yaml": "1645b857297793df9c1f6a69e236cbff5873b65055e4e4056360c693c809a279",
    "peaso/privesc/catalog/azure/app_configuration.yaml": "937a2bbc1a2b42d08ef7d183653e540f7320b672c59d9ed5068a191a3aaca89b",
    "peaso/privesc/catalog/azure/bounded-effects-v5.yaml": "1ca7a8398150cd05f2146e3466be8713481870cdcedfaf8813aad3e41b12a9f4",
    "peaso/privesc/catalog/azure/disclosure-effects-v7.yaml": "00175d020192d57529b305d80b2027dcea8df7b58aac26e0c60fd03196b79d3a",
    "peaso/privesc/catalog/azure/monitor.yaml": "a2cec1047c97588d0537a02e1f5ac06ed091188097b8427369fc8362f715cada",
    "peaso/privesc/catalog/azure/storage-local-v7.yaml": "39fc0f2734331d8d08d356614775095d8b7be97bf343aa240e110c12d2988f9f",
    "peaso/privesc/catalog/azure/storage.yaml": "be4c268b9114175bbf079a4d9c70009392f9fab26afa47ea8100930255b19b15",
    "peaso/privesc/catalog/gcp/aiplatform.yaml": "d32d22ffb8909105cbc49f3fe0704df6ffb8e43494c7c908981d59dd31800c69",
    "peaso/privesc/catalog/gcp/bigtable.yaml": "436131e96ff896df4425319aee3952c6010909dab2b4256302a4367af8e230db",
    "peaso/privesc/catalog/gcp/bounded-effects-v5.yaml": "336a51ee7c3e5411d23c7e6fffd90849a28de2577ce2ccc02ff6e03877da5505",
    "peaso/privesc/catalog/gcp/bulk-principal-v6.yaml": "1998a8787332908d955ab6e8769f315dac4afe80fb2e66b57dc34ad7a916cf25",
    "peaso/privesc/catalog/gcp/dlp.yaml": "a4191890cd5bb94485588a7830567975f59ded4b2043f58331a4e6a60223187d",
    "peaso/privesc/catalog/gcp/exact-principal-v5.yaml": "345e1f41d7baf6f859b65eb6abdf8b6be5bf25781a9b25602ab1481bf1c7ec0b",
    "peaso/privesc/catalog/gcp/parametermanager.yaml": "8273c65df5d117386103e3694b7074ab002487b851706897c63d44300f76acab",
    "peaso/privesc/catalog/gcp/secretmanager.yaml": "7ddb46238daeeba20663d30f5a2f07ab25b26cfd8838895787043a6b28c5b23e",
    "peaso/privesc/catalog/k8s/scoped-credential-v7.yaml": "7c4940f42a1754cd843688fcd903a522cd99ea98491c20a1ef5ed77dd75008a5",
    "peaso/privesc/catalog_versions/bounded-v5-manifest.json": "082451e81fa450830ae5f6835e241dd412a6c30a8b2a0b1172cdbc89b2d71429",
    "peaso/privesc/catalog_versions/bulk-principal-v6-manifest.json": "734401b202895e00ac1b6cb0f1534f77cde4d8e2ba912ca0ee974b1b8ec5035c",
    "peaso/privesc/catalog_versions/disclosure-v7-manifest.json": "91ffe7389d02568cdcdf74a6b08dafa5f665ea07c0c528988127ffc4d2a86c45",
    "peaso/privesc/catalog_versions/legacy-0b3633-delta.json": "40640ad0e7179af395ec37f9456ef7b9d8340e8ab81e9edb7a460769edca258a",
    "peaso/privesc/catalog_versions/principal-v4-manifest.json": "6008acf71acda21408c7039dddff2d7ccaeeaa3aecfc6f31ef5d2cdc5a4ea388",
    "peaso/privesc/effective_permissions/azure_disclosure_effects.py": "554dba11bab6ad0145960f8b594ae58ab165e00c0fbe3fb91c3a4bcfa6ef197f",
    "peaso/privesc/effective_permissions/bounded_evidence.py": "1cd1a44f2d955bb5dc877e404ab09294a3df9b67bb1ff9e867aec1cd0cf212af",
    "peaso/privesc/effective_permissions/credential_evidence.py": "a95078884cd2e1c91e3e729921254844237eaa0444b89bf0cd6afd88d9fcaef3",
    "peaso/privesc/effective_permissions/ec2_profile_association.py": "22f0c201cc7d2b37f26c26e307dca33ce55e5716c5f6bea64affc78aff78e039",
    "peaso/privesc/effective_permissions/principal_evidence.py": "2c4bd5e2e2fa33db271b963387787003a42e1c741dad27b22e7b37f23fc2f7e3",
    "peaso/privesc/effective_permissions/storage_local_identity.py": "7671720b0780e47c583e0877888235406c220e64b937d361edb555f3300df7d0",
    "peaso/privesc/exact_principal_tranche.json": "c02921ad9a694b07415ffd5de0c97a0e8b0f34b73bbf40dc3b78e149e29b4af6",
    "peaso/privesc/versioned_catalog.py": "fd6831825507de22b7155909b3bdc1f1e391244b85a180b7764e22f7974f6666",
    "peaso/rulepacks/remediation_compliance_batch_remaining_aws.json": "ebe28d47a1880fa09acc7f42022a1e199ac9c27992049d2ca074670b41d6d490",
    "peaso/rulepacks/remediation_compliance_batch_remaining_azure.json": "a8f76c1a53926fa6cbbda666e80108b494d7933d77d9d39f6d1226f02937b91a",
    "peaso/rulepacks/remediation_compliance_batch_remaining_gcp.json": "5d618ab15fa5cd624e2b2559ab9f308dabe5fb2fa255d33ff664386c5e97b71c",
    "peaso/rulepacks/remediation_compliance_batch_remaining_k8s.json": "5485734fd0351e2dc8f6862b65472164e05df802e32d9c08d061826d1f1492ca",
    "peaso/server/native_policy_validation.py": "42932637bdc8953d4f30b8dccb64ddc4f64c79f498623ca376bae62981a5c3d2"
}
APPROVED_V23_SOURCE_MEMBERS = 1818
APPROVED_V23_RUNTIME_MEMBERS = 914
APPROVED_V23_RUNTIME_SHA256 = '50f36d431699fbb6e0e079908838209f5ef24a6686f36a9da40f3db0b2748f42'


# Exact additive V24 AKS successor; all prior maps remain literal.
APPROVED_V24_RUNTIME_ADDITIONS = {
    "peaso/analysis/aws_public_ingress.py": "f58f4f100215dd35da15ec177fbfa1b90145a6bf02fbd80afd759374544f06f0",
    "peaso/aws_budget_policy.py": "940a71e4627173e814381a148744a3840c81f60957f5bd2a6032fa4086ba4b69",
    "peaso/aws_waf_logging.py": "f97074cf8e7ecfb00ac1bac45947bdcd628affe294a0465283b1a5a35eb7c8b9",
    "peaso/azure_devops_git_policy.py": "4c195e73eebf742314c3eeafe0d1f95356d58e71e6c2339d8b1b8b8d418e28ed",
    "peaso/azure_sw32_policy.py": "9d9a545dbc9240e29a3389445dcb9f032fd2350db059e38d49a95f0d90d9e3b0",
    "peaso/checks/aws_all_policies.json": "8e1cdcc44749b643d95e4ee223e386a4b4aba609d9e09a0577779cc34daa83bf",
    "peaso/checks/aws_all_policies.py": "46c12e7ef9f8ed1eac29709c720c0b703e71ee7d0ac15c2427c99346747ab9fe",
    "peaso/checks/aws_all_policies_fixtures.json": "f93d3feb539b593561b3cf9878a0f151e5619ab29bb43984e9963e141eee9401",
    "peaso/checks/aws_backup_plan_frequency.py": "0f40ddcace19dded128369f32efad6d72e36a8a95590073beb8cada2d4cff08d",
    "peaso/checks/aws_config_recording.py": "50800c1a5c30aa407d0791d4416cc473ea19c3d03f584a2a4a2cfa694d2eabec",
    "peaso/checks/azure_apim_diagnostics_native.py": "4221d0aa3092bff0bb5eeb11fdf3ecc58687f0899a52523fbfeed412bb4af55b",
    "peaso/checks/azure_apim_native.py": "af1e1903c167c813e1ab8e8a9c7fa2336dc6cb5f9d8757f7beaaf6f481744f6b",
    "peaso/checks/azure_appservice_identity_followup.py": "ca7ffd2dccf77fd8e7b90d31c567cbb48b666300330555242582efe768347463",
    "peaso/checks/azure_easm_native.py": "d75e42848fae6c53b0f9e29fdb5c568325bbf8f2e136a7dcc435c58b1036f94b",
    "peaso/checks/azure_graph_credential_age.py": "ba0b2f87162cbace267cb0d630f05655d59239b287d9e7ae6b4f8744cc30a7b4",
    "peaso/checks/azure_log_profile_retention.py": "ba369f5809f8484310b89079ee0b4c3a5523f561ff03cd349488766cc86837ba",
    "peaso/checks/batch_remaining_aws.py": "197ccf540f23e9373d8db281bf1544d2d2bba793be3738ff214e9a6038d813b2",
    "peaso/checks/batch_remaining_azure.py": "82e39d57beef687761098e206457e5e7f7e25a792fc9fcc8600d809f4737b136",
    "peaso/checks/batch_remaining_azure_vm_storage.py": "11f0353505ec70bb7cbc1f6f72add7ceb664fcbd01d05bd8018b2063dd09babb",
    "peaso/checks/batch_remaining_gcp.py": "4f93aebdb8c4fabb603cc122b7a390bc153abc6039035c4a0e780be708aed870",
    "peaso/checks/batch_remaining_k8s.py": "0f0c92c50a05e92bfd0357767066e4e481c03320c2f582ff10194d8cc25dd578",
    "peaso/checks/bulk_pending.json": "af82bc70d181b3ad0e61bb4eab7c13a8f71898143be02ccd9224afd765ea0675",
    "peaso/checks/bulk_pending.py": "41cd15965640293562f1808fd7cc31b85769a3e3a44aa3c5537d119dabd50a11",
    "peaso/checks/central_batch_fixtures.json": "1a226d4af6f26c7216c305d36109226bed11e28051c936cb86f66ffcb5dc734b",
    "peaso/checks/central_native_fixtures.py": "2b9665b5b12e164a76b0982bc055857be82cd72d09eafcb8588bc96ead0503f4",
    "peaso/checks/compliance_new_sw25_native_identity.py": "c347440d7e378900762fc5cf6253203c61325008f6320008919d68cb5c37c53e",
    "peaso/checks/compliance_next_k8s.py": "d0184f0934601aaa4682c07d1f0dbfa1b40fa2e9090ce2ca53ca413471b96dfc",
    "peaso/checks/gcp_audit_native.py": "8c2f5e8d0a76571c06a0e0ade0e83cd54f0814fe525fc9f293968224ba2edf8f",
    "peaso/checks/gcp_audit_rates.json": "5010787138c533e7af252d5cfc2aab641097fb6bc9607d6018a66aac943554d9",
    "peaso/checks/gcp_audit_rates.py": "efb0da440e417b40efbcbf189b0fb62385be3b849136b04de08f61baff8e748c",
    "peaso/checks/gcp_audit_rates_fixtures.json": "2d2fd4319e86bb5f54d0f99b6c28ca0788504e46e822afdaed5d0dfe108a4354",
    "peaso/checks/gcp_data_access.py": "ce997648d524475e848aff41353b99f3add7075eca451146a89a7998da9f51c5",
    "peaso/checks/gcp_psc_dns.py": "4d820199813173d9f32ab2b4a5b4547c449d7f88e69affe1064247cb2df1e599",
    "peaso/checks/gcp_psc_fixtures.json": "d452ed303ed02d23d05e1ef1efce880264002779bf3073dee79239a3764a6138",
    "peaso/checks/k8s_namespace_policy_presence.py": "47f64b995e1f5ca9b6db72ff62a7a4594521448f2a1fbba174d453251698a2b2",
    "peaso/checks/native_storage_compute.json": "e4891a7a99339126380eab0a9e66e855c4b1f7ee8558e79abe64a2471fac7c9d",
    "peaso/checks/native_storage_compute.py": "66bc80ff2d43d7d394defa1180199abf42fb0c40b56ff2696ce5f9733f1de318",
    "peaso/checks/native_storage_compute_fixtures.json": "815860e018a22d38bf666b17a981d28993bea720567d369e28e1d26b1339f274",
    "peaso/checks/next20_aws.py": "8b5bedb10366b2708e445bc0068f41a1e6aea0bf8fe7f20c81029dfce665e569",
    "peaso/checks/next_group_appservice_fixtures.py": "1f461d725797b538f7e6550f7aa70217b029e6ec846a3a9e7ce5e6531057c3be",
    "peaso/checks/next_group_aws_fixtures.py": "0076893df5c07f55cd2244d98afaa4516e56f5a1a7bb4f3c5bf7ee1874adb90a",
    "peaso/checks/next_group_azure_fixtures.py": "274822bd1753bef38af173b6be01774abba8ab1bb6b0a0fe3d76638b2e0da249",
    "peaso/checks/next_group_easm_fixtures.py": "3162d5c0deeb1122ddddb06a82793167366dc71f17983547365791854f0406a8",
    "peaso/checks/post_dfaf_aws.py": "301493a4bd3ee865d3d830807a9d6481ef5e3910b3e8ba99c26b57b487cd0fce",
    "peaso/checks/post_dfaf_aws_specs.py": "4f2410348d731c2c76c3db79b0b2b0aebedebf874ce9044f9dccb612622d2476",
    "peaso/checks/post_dfaf_azure.py": "c00e5f758009f1929eb97f83a096706874b97fc6e2269dea8ccdab06c8e5640e",
    "peaso/checks/remaining_aws_gcp_native.py": "ded9f2aa60b562cc3db565a091434ad182e8ae8635d4b128549b827a39a6f5f9",
    "peaso/checks/wafv2_basic.py": "b300d867db2803793f56b23dbd2c51751435236428267e12e23c398c99316437",
    "peaso/collectors/aws_all_policies.py": "4be1797ead0658962fe64ddd17ac4437df49b3612e0d8746cf7315734e4a9886",
    "peaso/collectors/aws_apigateway_native.py": "bf5c20ba91a679dcd303579b89ef6f9fd3b96e4664254716b5c98e4367e854a5",
    "peaso/collectors/aws_budget_stop_native.py": "8001bc5895828ec8fc38baeda5a9e5f863866a3d32889e7b1804a06338dbba44",
    "peaso/collectors/aws_bulk_inventory.py": "45aa2a3bce8581cf8bf1046e882eb701a03b61367378fdcee70d3b5ef415230d",
    "peaso/collectors/aws_cloudtrail_delivery_native.py": "bf7348354a77a39d2271f1b022d1620b0e7f7d3b68dc021cf06f86aceb369393",
    "peaso/collectors/aws_codebuild_redaction.py": "d3f487ca28fae5563b2cd5839f760dbd742e859388ab0646dc762d5c7826f18d",
    "peaso/collectors/aws_codecommit_review_native.py": "8700c0be3a48fe2d6a72ed29390d5938ce2b901ecfccfb829a94cc9618249e93",
    "peaso/collectors/aws_controltower_native.py": "4cc022c9698532209a75fe280851e291964efb9244ff70ef607bdda685753999",
    "peaso/collectors/aws_cost_policy.py": "1e53fa329bbaeba16b0548bbd6b912ebbadd4a22c1e1732c24665d68b36fc42d",
    "peaso/collectors/aws_ecr_artifacts_native.py": "3beaa9b23013e715902d29d76064c0bcf205c569b02b38f74d2c7ba0cd66e99c",
    "peaso/collectors/aws_facts_v4_holds.py": "1e2cec696c00e1b002111fa1c4e3d17f41585c115db0808e11162705e1cd9356",
    "peaso/collectors/aws_identity_center_native.py": "60592e3ff76ae393ed43d89f1554fb2da1f0daaf836b5e640c8760e8b0a66d3e",
    "peaso/collectors/aws_identity_metrics_native.py": "f96984d474dcb07f03ddc4a998d5c0ae32563677f0eaa2a02384bc79dafadfc0",
    "peaso/collectors/aws_kms_enclave_native.py": "589935d3ebd9bd13c1d58adf304daf78359374c8e78f88549f2db83c3f32d069",
    "peaso/collectors/aws_launch_configuration_redaction.py": "09f0a76060934ef47924c1cf747079ca0dba6a82e5803686155067516eb951b5",
    "peaso/collectors/aws_macie_coverage_native.py": "5650b5a3e15a654cda7d2e5dcd2974124c6a0a711e1798202bf11e4ca5e65a7b",
    "peaso/collectors/aws_operational_groups_native.py": "06108480e7c2f75ca30343ea5ca4fe3dc0a3fa92d8dee9cf2ccf8f47150f2456",
    "peaso/collectors/aws_organizations_native.py": "f331e1cd6fa1a496bcfffb0a3eeb93d72004028dec1bc72d63db731dd1feae5a",
    "peaso/collectors/aws_policy.py": "a3003f6c3930bd5f23523cc6128192ee6a22891a47035df922e34498ada0429d",
    "peaso/collectors/aws_priority_tags_native.py": "c1f67bb05912bb0e60303989dc722093d379e93d56796c48ca81dc40ddb353f1",
    "peaso/collectors/aws_public_ingress_native.py": "3dda8ed8ffdb9e3b650ffe50bc6da24d52f57e53c908357ef9bc4a2094309b7e",
    "peaso/collectors/aws_region_shield_native.py": "08f2a665106e9e66b799fa75946739b57c01076fed23b882f3f63651b652d471",
    "peaso/collectors/aws_resolver_firewall_native.py": "ca0970fa271384e2167db3cb2ed855cceda0dd834348671654597ec3d8b19a52",
    "peaso/collectors/aws_resource_policy_native.py": "b0c7b4081f965bab4ece4de503fac0de65038c6c98df010f877f745ce940998e",
    "peaso/collectors/aws_s3_backup_native.py": "48654c9bb7c4fcbb5ee52c8035cb0fd29d0d8a716b358e9d8399a4595aad3ffd",
    "peaso/collectors/aws_sagemaker_clarify_native.py": "f6695218f1c6f5dd060b7871b516d975fb54e1560aba5a413698b589aaa113af",
    "peaso/collectors/aws_ssm_inventory_events_native.py": "c495038efa6858ee77d75a1090fe357998076455da3c1c4bebc105fd9e00370a",
    "peaso/collectors/aws_transport_native.py": "ab038928f14c3136df4c9425856e57b2b199afa24085d739b4f8526a225e53e6",
    "peaso/collectors/aws_waf_inventory_native.py": "10bcdf16a32dc1edd69ef751dd2a1427dbeb5a1c10cf91fd605b97c6dd2ada20",
    "peaso/collectors/azure_access_reviews_native.py": "11647049e6d04b1e9985ec51f9e890c02b0e8da66f67391979628a60e772bd6f",
    "peaso/collectors/azure_aks_workloads_native.py": "56464bdd18e5b747d39a3e47627aa500e85694b673b3cd833d324a8942b9493e",
    "peaso/collectors/azure_apim_diagnostics_native.py": "d5fe9f4b821fa80c1bed677df063971d6ac61278d315b93eb24b4a7957f9bc2e",
    "peaso/collectors/azure_apim_native.py": "f43150e470199e27637de0760fd288aed07362f69378290567a78e42d9eb7975",
    "peaso/collectors/azure_appservice_identity_followup.py": "d5e135f5973b2909974bfd2bf5cb43c03931e71590e63649da35850a75554aaf",
    "peaso/collectors/azure_arm_metadata_native.py": "f244de81694d42e796544d520ab3d631faa58e115f9622ad61d039fe12c4fa50",
    "peaso/collectors/azure_assessment_criteria_native.py": "42ceb16728f8bde78874d38037c835085c1dba1770c3dab84c6b2a03cc268d1a",
    "peaso/collectors/azure_conditional_access_native.py": "9b69def3b75a31ab41eaeac2757b85fe9d3d4f505f948043cd8491cd0ebabe8a",
    "peaso/collectors/azure_database_native.py": "2b5c6850d33f9a74fc6bf46f92bab1330f1d4ae21e92a6461357cde837c3f683",
    "peaso/collectors/azure_databricks_native.py": "3c6c56e700376316c7f711f7dc4981b4f02ec145bacf6553d9163326f7e64359",
    "peaso/collectors/azure_defender_network_native.py": "ce70e05680d870ba145baed0701471783c721446a1781474f70c3b0bbb1985da",
    "peaso/collectors/azure_detection_telemetry.py": "d0c1e354f8c5fbfd8504667dd0268f3e685444e6aa1a5507abb336d16817758d",
    "peaso/collectors/azure_devops_git_native.py": "7b01f9f26acae14414d33b42095caad14adaf4644b3706fde2120e170b4c2c63",
    "peaso/collectors/azure_disclosure_native.py": "1038ca6d576f89c6d9bced0182239b140f4dbe51e7aafb60a1b569634f15426d",
    "peaso/collectors/azure_entra_diagnostics_native.py": "3ba791cd52c3e5b2fb78bcb12fced683402d552f8a8ff3bd13fec65fc941636f",
    "peaso/collectors/azure_frontdoor_native.py": "f020ec13c4a8ddd12c8e276f24538cb7c698f707b1f4eaebb52ce14e3305f675",
    "peaso/collectors/azure_function_limits_native.py": "cd1b13b2fd9d7983e1846fe651507a26422f4ab9cf7dd9866cdf9c50f28fc7e9",
    "peaso/collectors/azure_guest_configuration_native.py": "d534f80d292e158eba0caad3629b1d0fe54987c2cdbaf7e33a56a672f6159a54",
    "peaso/collectors/azure_guest_policy.py": "55f32bdb4d9e25f6603321fcb8a0877e07bce003ea7f2b02ea080401c2905c4d",
    "peaso/collectors/azure_guest_reports.py": "3b0b5a169a73bd97975b8968fed0b2e13b935ac8bc5f297ed791a128f8e74e4b",
    "peaso/collectors/azure_identity_intune_native.py": "02b0b6d133a2f0d30cb2e30a99d6d3d4feef78231eb61e680acd02987f0896fc",
    "peaso/collectors/azure_iot_policy_native.py": "5daa1c505286ba57c4f1ec016f54f5713b138d3b45cfd1c5fb542ee3ad893468",
    "peaso/collectors/azure_monitor_inventory_native.py": "81bd15cf090e296be7a299da4b7b9e42657c987bbed6afdeb82a0453a90e6127",
    "peaso/collectors/azure_resource_diagnostics_native.py": "36f73fc3665680b2489ab99c24dfee59b5f2afb236323952e7131dea481df0ed",
    "peaso/collectors/azure_resource_logging_policy.py": "2d7174efd2706acf66466e3216d95ec1b81d2af1cf5b1b54a8144246ca25d0ba",
    "peaso/collectors/azure_secret_versions_native.py": "53d8ad1f7599697fab83af4139644c93223f9cdbfc5355e587749e545149120c",
    "peaso/collectors/azure_sentinel_metadata_native.py": "3cc20e96f438c017261006a2e9d04f16cfc2d01224515a9477f73a7872e9896b",
    "peaso/collectors/azure_sql_inventory.py": "43a1549a843593c8e33812f5dfa9091a0e7ab534d895ea3e03e718cf08ec82ae",
    "peaso/collectors/azure_storage_backup_native.py": "249e5916a527ecd0d80378c1a4e769fc3511152f0887a85186bc1285aa473405",
    "peaso/collectors/azure_storage_recovery_metadata_native.py": "658807c10ba59c65ecc7a86bd0cae1d3079d785612b69b829908cc135cb81ca0",
    "peaso/collectors/azure_sw15_policy.py": "66a6ff162aa2727a33c3079cfd2709cbea883ce5bcc2f16407ef111743a5b82d",
    "peaso/collectors/batch_remaining_azure_vm_storage.py": "44bb52e7d7e9e7290cb302e439e1ada18b3dd278895125c857fd028dffa21053",
    "peaso/collectors/batch_remaining_k8s.py": "8c15aa07719cc9596edb3aa7128c99b8d301ef35269ab860ceeb238bec95bb3e",
    "peaso/collectors/bulk_evidence.json": "c1d173bead561f5777df8e703dd8a0939692202b8f2fe7427e8e6d72457a5744",
    "peaso/collectors/bulk_evidence.py": "fb51c829ddc9ca2c83e7cb54de8e1ebc91c0530a8d7eb47d6083e5ff170e6e09",
    "peaso/collectors/gcp_audit_native.py": "02554f3aa9bf2a4d450455c75c6b7fac5ca2396e1afededd34db42a6ec4179e8",
    "peaso/collectors/gcp_facts_v4_holds.py": "f52b9df380e2e69de33cd39bd99f3fda30cac030a1a583c50660b8b9a083f39f",
    "peaso/collectors/gcp_history.py": "21368065d8d1a46209e88d623bb848fe2e3dcb0e4e4c0e5b01f867b8ecf4e631",
    "peaso/collectors/gcp_kms_effective_native.py": "7d2c1e81afebac5e99d47951c85c24aeb91e1795d3fe233c396d9bac6a30ae01",
    "peaso/collectors/gcp_native_evidence.py": "fdced136c30eca42529c967ba2a59f84068008ee98345a1a7abc2c974ca060e1",
    "peaso/collectors/gcp_os_patch_native.py": "e8d86dbc207104d2dbc59d2c0dd0a558f7d00e7edde5960d2750fa7803a85f58",
    "peaso/collectors/gcp_sbom_native.py": "e4fc4bc0c455146ed580d7ef3406424c8ddca2588ccf5cb7c723b922931902f8",
    "peaso/collectors/gcp_storage_acl_native.py": "9ef114ced31862ed48cc3defc7710623e130fcd6431051174fc44b6d19fa2033",
    "peaso/collectors/k8s_admission_file.py": "fc23c5692f1bc295394cf770312a58a8bb64dc532d2c2d9ad33cfeb8a440795f",
    "peaso/gcp_data_access_policy.py": "03167a5cf56583a9ae4efb08aba2beb24fa0e62fcafded1b6f7f47181cb5d4c7",
    "peaso/gcp_psc_policy.py": "ceb9da0dca6e28d011e9f0d779fe519991bb78ec4e7df9bbba67494306eb0ff1",
    "peaso/gcp_sbom_policy.py": "ef717b7f45ddb6d7abca981b6a871f60d9dde0f1eee442c64ddb342ca60be788",
    "peaso/privesc/azure_disclosure_effects.json": "6caf92a0ffdc59cffecb0c9d047d31bc7c49fe02dd0f19b11f3ec743a670f93e",
    "peaso/privesc/bounded_effects.json": "4ce1a0b29fbf026bbc26166915f87e5fb2c4e6396a8aa37ee91e56ca1840806d",
    "peaso/privesc/bulk_principal_tranche.json": "6cb1c21ba90b1ae08d0e5671efa373c8711d42cdb97d3f9055f84d3a239428a8",
    "peaso/privesc/catalog/aws/bounded-effects-v5.yaml": "d38ce968f6af36e9d5c72a098916978320ebf61653df6e6b2c1916de3fbaf80a",
    "peaso/privesc/catalog/aws/bulk-principal-v6.yaml": "e4e907a900127eec6feaa5bb9527ddb130d52c4895b94fd65acb6e8b0a29c779",
    "peaso/privesc/catalog/aws/exact-principal-v5.yaml": "b198454714e4e530682cea805f5e1db595c9eb7a8057f35b1f8d426f88c2a709",
    "peaso/privesc/catalog/aws/lightsail.yaml": "1645b857297793df9c1f6a69e236cbff5873b65055e4e4056360c693c809a279",
    "peaso/privesc/catalog/azure/app_configuration.yaml": "937a2bbc1a2b42d08ef7d183653e540f7320b672c59d9ed5068a191a3aaca89b",
    "peaso/privesc/catalog/azure/bounded-effects-v5.yaml": "1ca7a8398150cd05f2146e3466be8713481870cdcedfaf8813aad3e41b12a9f4",
    "peaso/privesc/catalog/azure/disclosure-effects-v7.yaml": "00175d020192d57529b305d80b2027dcea8df7b58aac26e0c60fd03196b79d3a",
    "peaso/privesc/catalog/azure/monitor.yaml": "a2cec1047c97588d0537a02e1f5ac06ed091188097b8427369fc8362f715cada",
    "peaso/privesc/catalog/azure/storage-local-v7.yaml": "39fc0f2734331d8d08d356614775095d8b7be97bf343aa240e110c12d2988f9f",
    "peaso/privesc/catalog/azure/storage.yaml": "be4c268b9114175bbf079a4d9c70009392f9fab26afa47ea8100930255b19b15",
    "peaso/privesc/catalog/gcp/aiplatform.yaml": "d32d22ffb8909105cbc49f3fe0704df6ffb8e43494c7c908981d59dd31800c69",
    "peaso/privesc/catalog/gcp/bigtable.yaml": "436131e96ff896df4425319aee3952c6010909dab2b4256302a4367af8e230db",
    "peaso/privesc/catalog/gcp/bounded-effects-v5.yaml": "336a51ee7c3e5411d23c7e6fffd90849a28de2577ce2ccc02ff6e03877da5505",
    "peaso/privesc/catalog/gcp/bulk-principal-v6.yaml": "1998a8787332908d955ab6e8769f315dac4afe80fb2e66b57dc34ad7a916cf25",
    "peaso/privesc/catalog/gcp/dlp.yaml": "a4191890cd5bb94485588a7830567975f59ded4b2043f58331a4e6a60223187d",
    "peaso/privesc/catalog/gcp/exact-principal-v5.yaml": "345e1f41d7baf6f859b65eb6abdf8b6be5bf25781a9b25602ab1481bf1c7ec0b",
    "peaso/privesc/catalog/gcp/parametermanager.yaml": "8273c65df5d117386103e3694b7074ab002487b851706897c63d44300f76acab",
    "peaso/privesc/catalog/gcp/secretmanager.yaml": "7ddb46238daeeba20663d30f5a2f07ab25b26cfd8838895787043a6b28c5b23e",
    "peaso/privesc/catalog/k8s/scoped-credential-v7.yaml": "7c4940f42a1754cd843688fcd903a522cd99ea98491c20a1ef5ed77dd75008a5",
    "peaso/privesc/catalog_versions/bounded-v5-manifest.json": "082451e81fa450830ae5f6835e241dd412a6c30a8b2a0b1172cdbc89b2d71429",
    "peaso/privesc/catalog_versions/bulk-principal-v6-manifest.json": "734401b202895e00ac1b6cb0f1534f77cde4d8e2ba912ca0ee974b1b8ec5035c",
    "peaso/privesc/catalog_versions/disclosure-v7-manifest.json": "91ffe7389d02568cdcdf74a6b08dafa5f665ea07c0c528988127ffc4d2a86c45",
    "peaso/privesc/catalog_versions/legacy-0b3633-delta.json": "40640ad0e7179af395ec37f9456ef7b9d8340e8ab81e9edb7a460769edca258a",
    "peaso/privesc/catalog_versions/principal-v4-manifest.json": "6008acf71acda21408c7039dddff2d7ccaeeaa3aecfc6f31ef5d2cdc5a4ea388",
    "peaso/privesc/effective_permissions/azure_disclosure_effects.py": "554dba11bab6ad0145960f8b594ae58ab165e00c0fbe3fb91c3a4bcfa6ef197f",
    "peaso/privesc/effective_permissions/bounded_evidence.py": "1cd1a44f2d955bb5dc877e404ab09294a3df9b67bb1ff9e867aec1cd0cf212af",
    "peaso/privesc/effective_permissions/credential_evidence.py": "a95078884cd2e1c91e3e729921254844237eaa0444b89bf0cd6afd88d9fcaef3",
    "peaso/privesc/effective_permissions/ec2_profile_association.py": "22f0c201cc7d2b37f26c26e307dca33ce55e5716c5f6bea64affc78aff78e039",
    "peaso/privesc/effective_permissions/principal_evidence.py": "2c4bd5e2e2fa33db271b963387787003a42e1c741dad27b22e7b37f23fc2f7e3",
    "peaso/privesc/effective_permissions/storage_local_identity.py": "7671720b0780e47c583e0877888235406c220e64b937d361edb555f3300df7d0",
    "peaso/privesc/exact_principal_tranche.json": "c02921ad9a694b07415ffd5de0c97a0e8b0f34b73bbf40dc3b78e149e29b4af6",
    "peaso/privesc/versioned_catalog.py": "fd6831825507de22b7155909b3bdc1f1e391244b85a180b7764e22f7974f6666",
    "peaso/rulepacks/remediation_compliance_batch_remaining_aws.json": "ebe28d47a1880fa09acc7f42022a1e199ac9c27992049d2ca074670b41d6d490",
    "peaso/rulepacks/remediation_compliance_batch_remaining_azure.json": "a8f76c1a53926fa6cbbda666e80108b494d7933d77d9d39f6d1226f02937b91a",
    "peaso/rulepacks/remediation_compliance_batch_remaining_gcp.json": "5d618ab15fa5cd624e2b2559ab9f308dabe5fb2fa255d33ff664386c5e97b71c",
    "peaso/rulepacks/remediation_compliance_batch_remaining_k8s.json": "5485734fd0351e2dc8f6862b65472164e05df802e32d9c08d061826d1f1492ca",
    "peaso/server/native_policy_validation.py": "42932637bdc8953d4f30b8dccb64ddc4f64c79f498623ca376bae62981a5c3d2"
}
APPROVED_V24_SOURCE_MEMBERS = 1819
APPROVED_V24_RUNTIME_MEMBERS = 914
APPROVED_V24_RUNTIME_SHA256 = '6255f2dd64945dc54e0ceef729fa0ac41efb5175cf93b61cf64e808b2b66a75b'


# Exact additive V25 compatibility successor; all prior maps remain literal.
APPROVED_V25_RUNTIME_ADDITIONS = {
    "peaso/analysis/aws_public_ingress.py": "f58f4f100215dd35da15ec177fbfa1b90145a6bf02fbd80afd759374544f06f0",
    "peaso/aws_budget_policy.py": "940a71e4627173e814381a148744a3840c81f60957f5bd2a6032fa4086ba4b69",
    "peaso/aws_waf_logging.py": "f97074cf8e7ecfb00ac1bac45947bdcd628affe294a0465283b1a5a35eb7c8b9",
    "peaso/azure_devops_git_policy.py": "4c195e73eebf742314c3eeafe0d1f95356d58e71e6c2339d8b1b8b8d418e28ed",
    "peaso/azure_sw32_policy.py": "9d9a545dbc9240e29a3389445dcb9f032fd2350db059e38d49a95f0d90d9e3b0",
    "peaso/checks/aws_all_policies.json": "8e1cdcc44749b643d95e4ee223e386a4b4aba609d9e09a0577779cc34daa83bf",
    "peaso/checks/aws_all_policies.py": "46c12e7ef9f8ed1eac29709c720c0b703e71ee7d0ac15c2427c99346747ab9fe",
    "peaso/checks/aws_all_policies_fixtures.json": "f93d3feb539b593561b3cf9878a0f151e5619ab29bb43984e9963e141eee9401",
    "peaso/checks/aws_backup_plan_frequency.py": "0f40ddcace19dded128369f32efad6d72e36a8a95590073beb8cada2d4cff08d",
    "peaso/checks/aws_config_recording.py": "50800c1a5c30aa407d0791d4416cc473ea19c3d03f584a2a4a2cfa694d2eabec",
    "peaso/checks/azure_apim_diagnostics_native.py": "4221d0aa3092bff0bb5eeb11fdf3ecc58687f0899a52523fbfeed412bb4af55b",
    "peaso/checks/azure_apim_native.py": "af1e1903c167c813e1ab8e8a9c7fa2336dc6cb5f9d8757f7beaaf6f481744f6b",
    "peaso/checks/azure_appservice_identity_followup.py": "ca7ffd2dccf77fd8e7b90d31c567cbb48b666300330555242582efe768347463",
    "peaso/checks/azure_easm_native.py": "d75e42848fae6c53b0f9e29fdb5c568325bbf8f2e136a7dcc435c58b1036f94b",
    "peaso/checks/azure_graph_credential_age.py": "ba0b2f87162cbace267cb0d630f05655d59239b287d9e7ae6b4f8744cc30a7b4",
    "peaso/checks/azure_log_profile_retention.py": "ba369f5809f8484310b89079ee0b4c3a5523f561ff03cd349488766cc86837ba",
    "peaso/checks/batch_remaining_aws.py": "197ccf540f23e9373d8db281bf1544d2d2bba793be3738ff214e9a6038d813b2",
    "peaso/checks/batch_remaining_azure.py": "82e39d57beef687761098e206457e5e7f7e25a792fc9fcc8600d809f4737b136",
    "peaso/checks/batch_remaining_azure_vm_storage.py": "11f0353505ec70bb7cbc1f6f72add7ceb664fcbd01d05bd8018b2063dd09babb",
    "peaso/checks/batch_remaining_gcp.py": "4f93aebdb8c4fabb603cc122b7a390bc153abc6039035c4a0e780be708aed870",
    "peaso/checks/batch_remaining_k8s.py": "0f0c92c50a05e92bfd0357767066e4e481c03320c2f582ff10194d8cc25dd578",
    "peaso/checks/bulk_pending.json": "5e7eaba9875443e33ffe6878a08238d69bda64d59ffceff78696200ae99637ee",
    "peaso/checks/bulk_pending.py": "41cd15965640293562f1808fd7cc31b85769a3e3a44aa3c5537d119dabd50a11",
    "peaso/checks/central_batch_fixtures.json": "1a226d4af6f26c7216c305d36109226bed11e28051c936cb86f66ffcb5dc734b",
    "peaso/checks/central_native_fixtures.py": "2b9665b5b12e164a76b0982bc055857be82cd72d09eafcb8588bc96ead0503f4",
    "peaso/checks/compliance_new_sw25_native_identity.py": "c347440d7e378900762fc5cf6253203c61325008f6320008919d68cb5c37c53e",
    "peaso/checks/compliance_next_k8s.py": "d0184f0934601aaa4682c07d1f0dbfa1b40fa2e9090ce2ca53ca413471b96dfc",
    "peaso/checks/gcp_audit_native.py": "8c2f5e8d0a76571c06a0e0ade0e83cd54f0814fe525fc9f293968224ba2edf8f",
    "peaso/checks/gcp_audit_rates.json": "5010787138c533e7af252d5cfc2aab641097fb6bc9607d6018a66aac943554d9",
    "peaso/checks/gcp_audit_rates.py": "efb0da440e417b40efbcbf189b0fb62385be3b849136b04de08f61baff8e748c",
    "peaso/checks/gcp_audit_rates_fixtures.json": "2d2fd4319e86bb5f54d0f99b6c28ca0788504e46e822afdaed5d0dfe108a4354",
    "peaso/checks/gcp_data_access.py": "ce997648d524475e848aff41353b99f3add7075eca451146a89a7998da9f51c5",
    "peaso/checks/gcp_psc_dns.py": "4d820199813173d9f32ab2b4a5b4547c449d7f88e69affe1064247cb2df1e599",
    "peaso/checks/gcp_psc_fixtures.json": "d452ed303ed02d23d05e1ef1efce880264002779bf3073dee79239a3764a6138",
    "peaso/checks/k8s_namespace_policy_presence.py": "47f64b995e1f5ca9b6db72ff62a7a4594521448f2a1fbba174d453251698a2b2",
    "peaso/checks/native_storage_compute.json": "e4891a7a99339126380eab0a9e66e855c4b1f7ee8558e79abe64a2471fac7c9d",
    "peaso/checks/native_storage_compute.py": "66bc80ff2d43d7d394defa1180199abf42fb0c40b56ff2696ce5f9733f1de318",
    "peaso/checks/native_storage_compute_fixtures.json": "815860e018a22d38bf666b17a981d28993bea720567d369e28e1d26b1339f274",
    "peaso/checks/next20_aws.py": "8b5bedb10366b2708e445bc0068f41a1e6aea0bf8fe7f20c81029dfce665e569",
    "peaso/checks/next_group_appservice_fixtures.py": "1f461d725797b538f7e6550f7aa70217b029e6ec846a3a9e7ce5e6531057c3be",
    "peaso/checks/next_group_aws_fixtures.py": "0076893df5c07f55cd2244d98afaa4516e56f5a1a7bb4f3c5bf7ee1874adb90a",
    "peaso/checks/next_group_azure_fixtures.py": "274822bd1753bef38af173b6be01774abba8ab1bb6b0a0fe3d76638b2e0da249",
    "peaso/checks/next_group_easm_fixtures.py": "3162d5c0deeb1122ddddb06a82793167366dc71f17983547365791854f0406a8",
    "peaso/checks/post_dfaf_aws.py": "301493a4bd3ee865d3d830807a9d6481ef5e3910b3e8ba99c26b57b487cd0fce",
    "peaso/checks/post_dfaf_aws_specs.py": "4f2410348d731c2c76c3db79b0b2b0aebedebf874ce9044f9dccb612622d2476",
    "peaso/checks/post_dfaf_azure.py": "c00e5f758009f1929eb97f83a096706874b97fc6e2269dea8ccdab06c8e5640e",
    "peaso/checks/remaining_aws_gcp_native.py": "ded9f2aa60b562cc3db565a091434ad182e8ae8635d4b128549b827a39a6f5f9",
    "peaso/checks/wafv2_basic.py": "b300d867db2803793f56b23dbd2c51751435236428267e12e23c398c99316437",
    "peaso/collectors/aws_all_policies.py": "4be1797ead0658962fe64ddd17ac4437df49b3612e0d8746cf7315734e4a9886",
    "peaso/collectors/aws_apigateway_native.py": "bf5c20ba91a679dcd303579b89ef6f9fd3b96e4664254716b5c98e4367e854a5",
    "peaso/collectors/aws_budget_stop_native.py": "8001bc5895828ec8fc38baeda5a9e5f863866a3d32889e7b1804a06338dbba44",
    "peaso/collectors/aws_bulk_inventory.py": "45aa2a3bce8581cf8bf1046e882eb701a03b61367378fdcee70d3b5ef415230d",
    "peaso/collectors/aws_cloudtrail_delivery_native.py": "bf7348354a77a39d2271f1b022d1620b0e7f7d3b68dc021cf06f86aceb369393",
    "peaso/collectors/aws_codebuild_redaction.py": "d3f487ca28fae5563b2cd5839f760dbd742e859388ab0646dc762d5c7826f18d",
    "peaso/collectors/aws_codecommit_review_native.py": "8700c0be3a48fe2d6a72ed29390d5938ce2b901ecfccfb829a94cc9618249e93",
    "peaso/collectors/aws_controltower_native.py": "4cc022c9698532209a75fe280851e291964efb9244ff70ef607bdda685753999",
    "peaso/collectors/aws_cost_policy.py": "1e53fa329bbaeba16b0548bbd6b912ebbadd4a22c1e1732c24665d68b36fc42d",
    "peaso/collectors/aws_ecr_artifacts_native.py": "3beaa9b23013e715902d29d76064c0bcf205c569b02b38f74d2c7ba0cd66e99c",
    "peaso/collectors/aws_facts_v4_holds.py": "1e2cec696c00e1b002111fa1c4e3d17f41585c115db0808e11162705e1cd9356",
    "peaso/collectors/aws_identity_center_native.py": "60592e3ff76ae393ed43d89f1554fb2da1f0daaf836b5e640c8760e8b0a66d3e",
    "peaso/collectors/aws_identity_metrics_native.py": "f96984d474dcb07f03ddc4a998d5c0ae32563677f0eaa2a02384bc79dafadfc0",
    "peaso/collectors/aws_kms_enclave_native.py": "589935d3ebd9bd13c1d58adf304daf78359374c8e78f88549f2db83c3f32d069",
    "peaso/collectors/aws_launch_configuration_redaction.py": "09f0a76060934ef47924c1cf747079ca0dba6a82e5803686155067516eb951b5",
    "peaso/collectors/aws_macie_coverage_native.py": "5650b5a3e15a654cda7d2e5dcd2974124c6a0a711e1798202bf11e4ca5e65a7b",
    "peaso/collectors/aws_operational_groups_native.py": "06108480e7c2f75ca30343ea5ca4fe3dc0a3fa92d8dee9cf2ccf8f47150f2456",
    "peaso/collectors/aws_organizations_native.py": "f331e1cd6fa1a496bcfffb0a3eeb93d72004028dec1bc72d63db731dd1feae5a",
    "peaso/collectors/aws_policy.py": "a3003f6c3930bd5f23523cc6128192ee6a22891a47035df922e34498ada0429d",
    "peaso/collectors/aws_priority_tags_native.py": "c1f67bb05912bb0e60303989dc722093d379e93d56796c48ca81dc40ddb353f1",
    "peaso/collectors/aws_public_ingress_native.py": "3dda8ed8ffdb9e3b650ffe50bc6da24d52f57e53c908357ef9bc4a2094309b7e",
    "peaso/collectors/aws_region_shield_native.py": "08f2a665106e9e66b799fa75946739b57c01076fed23b882f3f63651b652d471",
    "peaso/collectors/aws_resolver_firewall_native.py": "ca0970fa271384e2167db3cb2ed855cceda0dd834348671654597ec3d8b19a52",
    "peaso/collectors/aws_resource_policy_native.py": "b0c7b4081f965bab4ece4de503fac0de65038c6c98df010f877f745ce940998e",
    "peaso/collectors/aws_s3_backup_native.py": "48654c9bb7c4fcbb5ee52c8035cb0fd29d0d8a716b358e9d8399a4595aad3ffd",
    "peaso/collectors/aws_sagemaker_clarify_native.py": "f6695218f1c6f5dd060b7871b516d975fb54e1560aba5a413698b589aaa113af",
    "peaso/collectors/aws_ssm_inventory_events_native.py": "c495038efa6858ee77d75a1090fe357998076455da3c1c4bebc105fd9e00370a",
    "peaso/collectors/aws_transport_native.py": "ab038928f14c3136df4c9425856e57b2b199afa24085d739b4f8526a225e53e6",
    "peaso/collectors/aws_waf_inventory_native.py": "10bcdf16a32dc1edd69ef751dd2a1427dbeb5a1c10cf91fd605b97c6dd2ada20",
    "peaso/collectors/azure_access_reviews_native.py": "11647049e6d04b1e9985ec51f9e890c02b0e8da66f67391979628a60e772bd6f",
    "peaso/collectors/azure_aks_workloads_native.py": "d05435f71f90ba4c9861a2049d3e04d7465772bbdc519c14d4bba157d9e0a4b4",
    "peaso/collectors/azure_apim_diagnostics_native.py": "d5fe9f4b821fa80c1bed677df063971d6ac61278d315b93eb24b4a7957f9bc2e",
    "peaso/collectors/azure_apim_native.py": "f43150e470199e27637de0760fd288aed07362f69378290567a78e42d9eb7975",
    "peaso/collectors/azure_appservice_identity_followup.py": "d5e135f5973b2909974bfd2bf5cb43c03931e71590e63649da35850a75554aaf",
    "peaso/collectors/azure_arm_metadata_native.py": "f244de81694d42e796544d520ab3d631faa58e115f9622ad61d039fe12c4fa50",
    "peaso/collectors/azure_assessment_criteria_native.py": "42ceb16728f8bde78874d38037c835085c1dba1770c3dab84c6b2a03cc268d1a",
    "peaso/collectors/azure_conditional_access_native.py": "9b69def3b75a31ab41eaeac2757b85fe9d3d4f505f948043cd8491cd0ebabe8a",
    "peaso/collectors/azure_database_native.py": "2b5c6850d33f9a74fc6bf46f92bab1330f1d4ae21e92a6461357cde837c3f683",
    "peaso/collectors/azure_databricks_native.py": "3c6c56e700376316c7f711f7dc4981b4f02ec145bacf6553d9163326f7e64359",
    "peaso/collectors/azure_defender_network_native.py": "ce70e05680d870ba145baed0701471783c721446a1781474f70c3b0bbb1985da",
    "peaso/collectors/azure_detection_telemetry.py": "d0c1e354f8c5fbfd8504667dd0268f3e685444e6aa1a5507abb336d16817758d",
    "peaso/collectors/azure_devops_git_native.py": "7b01f9f26acae14414d33b42095caad14adaf4644b3706fde2120e170b4c2c63",
    "peaso/collectors/azure_disclosure_native.py": "1038ca6d576f89c6d9bced0182239b140f4dbe51e7aafb60a1b569634f15426d",
    "peaso/collectors/azure_entra_diagnostics_native.py": "3ba791cd52c3e5b2fb78bcb12fced683402d552f8a8ff3bd13fec65fc941636f",
    "peaso/collectors/azure_frontdoor_native.py": "f020ec13c4a8ddd12c8e276f24538cb7c698f707b1f4eaebb52ce14e3305f675",
    "peaso/collectors/azure_function_limits_native.py": "cd1b13b2fd9d7983e1846fe651507a26422f4ab9cf7dd9866cdf9c50f28fc7e9",
    "peaso/collectors/azure_guest_configuration_native.py": "d534f80d292e158eba0caad3629b1d0fe54987c2cdbaf7e33a56a672f6159a54",
    "peaso/collectors/azure_guest_policy.py": "55f32bdb4d9e25f6603321fcb8a0877e07bce003ea7f2b02ea080401c2905c4d",
    "peaso/collectors/azure_guest_reports.py": "3b0b5a169a73bd97975b8968fed0b2e13b935ac8bc5f297ed791a128f8e74e4b",
    "peaso/collectors/azure_identity_intune_native.py": "02b0b6d133a2f0d30cb2e30a99d6d3d4feef78231eb61e680acd02987f0896fc",
    "peaso/collectors/azure_iot_policy_native.py": "5daa1c505286ba57c4f1ec016f54f5713b138d3b45cfd1c5fb542ee3ad893468",
    "peaso/collectors/azure_monitor_inventory_native.py": "81bd15cf090e296be7a299da4b7b9e42657c987bbed6afdeb82a0453a90e6127",
    "peaso/collectors/azure_resource_diagnostics_native.py": "36f73fc3665680b2489ab99c24dfee59b5f2afb236323952e7131dea481df0ed",
    "peaso/collectors/azure_resource_logging_policy.py": "2d7174efd2706acf66466e3216d95ec1b81d2af1cf5b1b54a8144246ca25d0ba",
    "peaso/collectors/azure_secret_versions_native.py": "53d8ad1f7599697fab83af4139644c93223f9cdbfc5355e587749e545149120c",
    "peaso/collectors/azure_sentinel_metadata_native.py": "3cc20e96f438c017261006a2e9d04f16cfc2d01224515a9477f73a7872e9896b",
    "peaso/collectors/azure_sql_inventory.py": "43a1549a843593c8e33812f5dfa9091a0e7ab534d895ea3e03e718cf08ec82ae",
    "peaso/collectors/azure_storage_backup_native.py": "249e5916a527ecd0d80378c1a4e769fc3511152f0887a85186bc1285aa473405",
    "peaso/collectors/azure_storage_recovery_metadata_native.py": "658807c10ba59c65ecc7a86bd0cae1d3079d785612b69b829908cc135cb81ca0",
    "peaso/collectors/azure_sw15_policy.py": "66a6ff162aa2727a33c3079cfd2709cbea883ce5bcc2f16407ef111743a5b82d",
    "peaso/collectors/batch_remaining_azure_vm_storage.py": "44bb52e7d7e9e7290cb302e439e1ada18b3dd278895125c857fd028dffa21053",
    "peaso/collectors/batch_remaining_k8s.py": "8c15aa07719cc9596edb3aa7128c99b8d301ef35269ab860ceeb238bec95bb3e",
    "peaso/collectors/bulk_evidence.json": "c1d173bead561f5777df8e703dd8a0939692202b8f2fe7427e8e6d72457a5744",
    "peaso/collectors/bulk_evidence.py": "fb51c829ddc9ca2c83e7cb54de8e1ebc91c0530a8d7eb47d6083e5ff170e6e09",
    "peaso/collectors/gcp_audit_native.py": "02554f3aa9bf2a4d450455c75c6b7fac5ca2396e1afededd34db42a6ec4179e8",
    "peaso/collectors/gcp_facts_v4_holds.py": "f52b9df380e2e69de33cd39bd99f3fda30cac030a1a583c50660b8b9a083f39f",
    "peaso/collectors/gcp_history.py": "21368065d8d1a46209e88d623bb848fe2e3dcb0e4e4c0e5b01f867b8ecf4e631",
    "peaso/collectors/gcp_kms_effective_native.py": "7d2c1e81afebac5e99d47951c85c24aeb91e1795d3fe233c396d9bac6a30ae01",
    "peaso/collectors/gcp_native_evidence.py": "fdced136c30eca42529c967ba2a59f84068008ee98345a1a7abc2c974ca060e1",
    "peaso/collectors/gcp_os_patch_native.py": "e8d86dbc207104d2dbc59d2c0dd0a558f7d00e7edde5960d2750fa7803a85f58",
    "peaso/collectors/gcp_sbom_native.py": "e4fc4bc0c455146ed580d7ef3406424c8ddca2588ccf5cb7c723b922931902f8",
    "peaso/collectors/gcp_storage_acl_native.py": "9ef114ced31862ed48cc3defc7710623e130fcd6431051174fc44b6d19fa2033",
    "peaso/collectors/k8s_admission_file.py": "fc23c5692f1bc295394cf770312a58a8bb64dc532d2c2d9ad33cfeb8a440795f",
    "peaso/gcp_data_access_policy.py": "03167a5cf56583a9ae4efb08aba2beb24fa0e62fcafded1b6f7f47181cb5d4c7",
    "peaso/gcp_psc_policy.py": "ceb9da0dca6e28d011e9f0d779fe519991bb78ec4e7df9bbba67494306eb0ff1",
    "peaso/gcp_sbom_policy.py": "ef717b7f45ddb6d7abca981b6a871f60d9dde0f1eee442c64ddb342ca60be788",
    "peaso/privesc/azure_disclosure_effects.json": "6caf92a0ffdc59cffecb0c9d047d31bc7c49fe02dd0f19b11f3ec743a670f93e",
    "peaso/privesc/bounded_effects.json": "4ce1a0b29fbf026bbc26166915f87e5fb2c4e6396a8aa37ee91e56ca1840806d",
    "peaso/privesc/bulk_principal_tranche.json": "6cb1c21ba90b1ae08d0e5671efa373c8711d42cdb97d3f9055f84d3a239428a8",
    "peaso/privesc/catalog/aws/bounded-effects-v5.yaml": "d38ce968f6af36e9d5c72a098916978320ebf61653df6e6b2c1916de3fbaf80a",
    "peaso/privesc/catalog/aws/bulk-principal-v6.yaml": "e4e907a900127eec6feaa5bb9527ddb130d52c4895b94fd65acb6e8b0a29c779",
    "peaso/privesc/catalog/aws/exact-principal-v5.yaml": "b198454714e4e530682cea805f5e1db595c9eb7a8057f35b1f8d426f88c2a709",
    "peaso/privesc/catalog/aws/lightsail.yaml": "1645b857297793df9c1f6a69e236cbff5873b65055e4e4056360c693c809a279",
    "peaso/privesc/catalog/azure/app_configuration.yaml": "937a2bbc1a2b42d08ef7d183653e540f7320b672c59d9ed5068a191a3aaca89b",
    "peaso/privesc/catalog/azure/bounded-effects-v5.yaml": "1ca7a8398150cd05f2146e3466be8713481870cdcedfaf8813aad3e41b12a9f4",
    "peaso/privesc/catalog/azure/disclosure-effects-v7.yaml": "00175d020192d57529b305d80b2027dcea8df7b58aac26e0c60fd03196b79d3a",
    "peaso/privesc/catalog/azure/monitor.yaml": "a2cec1047c97588d0537a02e1f5ac06ed091188097b8427369fc8362f715cada",
    "peaso/privesc/catalog/azure/storage-local-v7.yaml": "39fc0f2734331d8d08d356614775095d8b7be97bf343aa240e110c12d2988f9f",
    "peaso/privesc/catalog/azure/storage.yaml": "be4c268b9114175bbf079a4d9c70009392f9fab26afa47ea8100930255b19b15",
    "peaso/privesc/catalog/gcp/aiplatform.yaml": "d32d22ffb8909105cbc49f3fe0704df6ffb8e43494c7c908981d59dd31800c69",
    "peaso/privesc/catalog/gcp/bigtable.yaml": "436131e96ff896df4425319aee3952c6010909dab2b4256302a4367af8e230db",
    "peaso/privesc/catalog/gcp/bounded-effects-v5.yaml": "336a51ee7c3e5411d23c7e6fffd90849a28de2577ce2ccc02ff6e03877da5505",
    "peaso/privesc/catalog/gcp/bulk-principal-v6.yaml": "1998a8787332908d955ab6e8769f315dac4afe80fb2e66b57dc34ad7a916cf25",
    "peaso/privesc/catalog/gcp/dlp.yaml": "a4191890cd5bb94485588a7830567975f59ded4b2043f58331a4e6a60223187d",
    "peaso/privesc/catalog/gcp/exact-principal-v5.yaml": "345e1f41d7baf6f859b65eb6abdf8b6be5bf25781a9b25602ab1481bf1c7ec0b",
    "peaso/privesc/catalog/gcp/parametermanager.yaml": "8273c65df5d117386103e3694b7074ab002487b851706897c63d44300f76acab",
    "peaso/privesc/catalog/gcp/secretmanager.yaml": "7ddb46238daeeba20663d30f5a2f07ab25b26cfd8838895787043a6b28c5b23e",
    "peaso/privesc/catalog/k8s/scoped-credential-v7.yaml": "7c4940f42a1754cd843688fcd903a522cd99ea98491c20a1ef5ed77dd75008a5",
    "peaso/privesc/catalog_versions/bounded-v5-manifest.json": "082451e81fa450830ae5f6835e241dd412a6c30a8b2a0b1172cdbc89b2d71429",
    "peaso/privesc/catalog_versions/bulk-principal-v6-manifest.json": "734401b202895e00ac1b6cb0f1534f77cde4d8e2ba912ca0ee974b1b8ec5035c",
    "peaso/privesc/catalog_versions/disclosure-v7-manifest.json": "91ffe7389d02568cdcdf74a6b08dafa5f665ea07c0c528988127ffc4d2a86c45",
    "peaso/privesc/catalog_versions/legacy-0b3633-delta.json": "40640ad0e7179af395ec37f9456ef7b9d8340e8ab81e9edb7a460769edca258a",
    "peaso/privesc/catalog_versions/principal-v4-manifest.json": "6008acf71acda21408c7039dddff2d7ccaeeaa3aecfc6f31ef5d2cdc5a4ea388",
    "peaso/privesc/effective_permissions/azure_disclosure_effects.py": "554dba11bab6ad0145960f8b594ae58ab165e00c0fbe3fb91c3a4bcfa6ef197f",
    "peaso/privesc/effective_permissions/bounded_evidence.py": "1cd1a44f2d955bb5dc877e404ab09294a3df9b67bb1ff9e867aec1cd0cf212af",
    "peaso/privesc/effective_permissions/credential_evidence.py": "a95078884cd2e1c91e3e729921254844237eaa0444b89bf0cd6afd88d9fcaef3",
    "peaso/privesc/effective_permissions/ec2_profile_association.py": "22f0c201cc7d2b37f26c26e307dca33ce55e5716c5f6bea64affc78aff78e039",
    "peaso/privesc/effective_permissions/principal_evidence.py": "2c4bd5e2e2fa33db271b963387787003a42e1c741dad27b22e7b37f23fc2f7e3",
    "peaso/privesc/effective_permissions/storage_local_identity.py": "7671720b0780e47c583e0877888235406c220e64b937d361edb555f3300df7d0",
    "peaso/privesc/exact_principal_tranche.json": "c02921ad9a694b07415ffd5de0c97a0e8b0f34b73bbf40dc3b78e149e29b4af6",
    "peaso/privesc/versioned_catalog.py": "fd6831825507de22b7155909b3bdc1f1e391244b85a180b7764e22f7974f6666",
    "peaso/rulepacks/remediation_compliance_batch_remaining_aws.json": "ebe28d47a1880fa09acc7f42022a1e199ac9c27992049d2ca074670b41d6d490",
    "peaso/rulepacks/remediation_compliance_batch_remaining_azure.json": "a8f76c1a53926fa6cbbda666e80108b494d7933d77d9d39f6d1226f02937b91a",
    "peaso/rulepacks/remediation_compliance_batch_remaining_gcp.json": "5d618ab15fa5cd624e2b2559ab9f308dabe5fb2fa255d33ff664386c5e97b71c",
    "peaso/rulepacks/remediation_compliance_batch_remaining_k8s.json": "5485734fd0351e2dc8f6862b65472164e05df802e32d9c08d061826d1f1492ca",
    "peaso/server/native_policy_validation.py": "42932637bdc8953d4f30b8dccb64ddc4f64c79f498623ca376bae62981a5c3d2"
}
APPROVED_V25_SOURCE_MEMBERS = 1821
APPROVED_V25_RUNTIME_MEMBERS = 914
APPROVED_V25_RUNTIME_SHA256 = '4009b0db942bdfd4e8cbfb302a03fdffa39e46be6ba86df5399ca1e205749034'


# Exact additive V26 APIM successor; preserve every prior literal.
APPROVED_V26_RUNTIME_ADDITIONS = {
    "peaso/analysis/aws_public_ingress.py": "f58f4f100215dd35da15ec177fbfa1b90145a6bf02fbd80afd759374544f06f0",
    "peaso/aws_budget_policy.py": "940a71e4627173e814381a148744a3840c81f60957f5bd2a6032fa4086ba4b69",
    "peaso/aws_waf_logging.py": "f97074cf8e7ecfb00ac1bac45947bdcd628affe294a0465283b1a5a35eb7c8b9",
    "peaso/azure_devops_git_policy.py": "4c195e73eebf742314c3eeafe0d1f95356d58e71e6c2339d8b1b8b8d418e28ed",
    "peaso/azure_sw32_policy.py": "9d9a545dbc9240e29a3389445dcb9f032fd2350db059e38d49a95f0d90d9e3b0",
    "peaso/checks/aws_all_policies.json": "8e1cdcc44749b643d95e4ee223e386a4b4aba609d9e09a0577779cc34daa83bf",
    "peaso/checks/aws_all_policies.py": "46c12e7ef9f8ed1eac29709c720c0b703e71ee7d0ac15c2427c99346747ab9fe",
    "peaso/checks/aws_all_policies_fixtures.json": "f93d3feb539b593561b3cf9878a0f151e5619ab29bb43984e9963e141eee9401",
    "peaso/checks/aws_backup_plan_frequency.py": "0f40ddcace19dded128369f32efad6d72e36a8a95590073beb8cada2d4cff08d",
    "peaso/checks/aws_config_recording.py": "50800c1a5c30aa407d0791d4416cc473ea19c3d03f584a2a4a2cfa694d2eabec",
    "peaso/checks/azure_apim_diagnostics_native.py": "4221d0aa3092bff0bb5eeb11fdf3ecc58687f0899a52523fbfeed412bb4af55b",
    "peaso/checks/azure_apim_native.py": "af1e1903c167c813e1ab8e8a9c7fa2336dc6cb5f9d8757f7beaaf6f481744f6b",
    "peaso/checks/azure_appservice_identity_followup.py": "ca7ffd2dccf77fd8e7b90d31c567cbb48b666300330555242582efe768347463",
    "peaso/checks/azure_easm_native.py": "d75e42848fae6c53b0f9e29fdb5c568325bbf8f2e136a7dcc435c58b1036f94b",
    "peaso/checks/azure_graph_credential_age.py": "ba0b2f87162cbace267cb0d630f05655d59239b287d9e7ae6b4f8744cc30a7b4",
    "peaso/checks/azure_log_profile_retention.py": "ba369f5809f8484310b89079ee0b4c3a5523f561ff03cd349488766cc86837ba",
    "peaso/checks/batch_remaining_aws.py": "197ccf540f23e9373d8db281bf1544d2d2bba793be3738ff214e9a6038d813b2",
    "peaso/checks/batch_remaining_azure.py": "82e39d57beef687761098e206457e5e7f7e25a792fc9fcc8600d809f4737b136",
    "peaso/checks/batch_remaining_azure_vm_storage.py": "11f0353505ec70bb7cbc1f6f72add7ceb664fcbd01d05bd8018b2063dd09babb",
    "peaso/checks/batch_remaining_gcp.py": "4f93aebdb8c4fabb603cc122b7a390bc153abc6039035c4a0e780be708aed870",
    "peaso/checks/batch_remaining_k8s.py": "0f0c92c50a05e92bfd0357767066e4e481c03320c2f582ff10194d8cc25dd578",
    "peaso/checks/bulk_pending.json": "5e7eaba9875443e33ffe6878a08238d69bda64d59ffceff78696200ae99637ee",
    "peaso/checks/bulk_pending.py": "41cd15965640293562f1808fd7cc31b85769a3e3a44aa3c5537d119dabd50a11",
    "peaso/checks/central_batch_fixtures.json": "1a226d4af6f26c7216c305d36109226bed11e28051c936cb86f66ffcb5dc734b",
    "peaso/checks/central_native_fixtures.py": "2b9665b5b12e164a76b0982bc055857be82cd72d09eafcb8588bc96ead0503f4",
    "peaso/checks/compliance_new_sw25_native_identity.py": "c347440d7e378900762fc5cf6253203c61325008f6320008919d68cb5c37c53e",
    "peaso/checks/compliance_next_k8s.py": "d0184f0934601aaa4682c07d1f0dbfa1b40fa2e9090ce2ca53ca413471b96dfc",
    "peaso/checks/gcp_audit_native.py": "8c2f5e8d0a76571c06a0e0ade0e83cd54f0814fe525fc9f293968224ba2edf8f",
    "peaso/checks/gcp_audit_rates.json": "5010787138c533e7af252d5cfc2aab641097fb6bc9607d6018a66aac943554d9",
    "peaso/checks/gcp_audit_rates.py": "efb0da440e417b40efbcbf189b0fb62385be3b849136b04de08f61baff8e748c",
    "peaso/checks/gcp_audit_rates_fixtures.json": "2d2fd4319e86bb5f54d0f99b6c28ca0788504e46e822afdaed5d0dfe108a4354",
    "peaso/checks/gcp_data_access.py": "ce997648d524475e848aff41353b99f3add7075eca451146a89a7998da9f51c5",
    "peaso/checks/gcp_psc_dns.py": "4d820199813173d9f32ab2b4a5b4547c449d7f88e69affe1064247cb2df1e599",
    "peaso/checks/gcp_psc_fixtures.json": "d452ed303ed02d23d05e1ef1efce880264002779bf3073dee79239a3764a6138",
    "peaso/checks/k8s_namespace_policy_presence.py": "47f64b995e1f5ca9b6db72ff62a7a4594521448f2a1fbba174d453251698a2b2",
    "peaso/checks/native_storage_compute.json": "e4891a7a99339126380eab0a9e66e855c4b1f7ee8558e79abe64a2471fac7c9d",
    "peaso/checks/native_storage_compute.py": "66bc80ff2d43d7d394defa1180199abf42fb0c40b56ff2696ce5f9733f1de318",
    "peaso/checks/native_storage_compute_fixtures.json": "815860e018a22d38bf666b17a981d28993bea720567d369e28e1d26b1339f274",
    "peaso/checks/next20_aws.py": "8b5bedb10366b2708e445bc0068f41a1e6aea0bf8fe7f20c81029dfce665e569",
    "peaso/checks/next_group_appservice_fixtures.py": "1f461d725797b538f7e6550f7aa70217b029e6ec846a3a9e7ce5e6531057c3be",
    "peaso/checks/next_group_aws_fixtures.py": "0076893df5c07f55cd2244d98afaa4516e56f5a1a7bb4f3c5bf7ee1874adb90a",
    "peaso/checks/next_group_azure_fixtures.py": "274822bd1753bef38af173b6be01774abba8ab1bb6b0a0fe3d76638b2e0da249",
    "peaso/checks/next_group_easm_fixtures.py": "3162d5c0deeb1122ddddb06a82793167366dc71f17983547365791854f0406a8",
    "peaso/checks/post_dfaf_aws.py": "301493a4bd3ee865d3d830807a9d6481ef5e3910b3e8ba99c26b57b487cd0fce",
    "peaso/checks/post_dfaf_aws_specs.py": "4f2410348d731c2c76c3db79b0b2b0aebedebf874ce9044f9dccb612622d2476",
    "peaso/checks/post_dfaf_azure.py": "c00e5f758009f1929eb97f83a096706874b97fc6e2269dea8ccdab06c8e5640e",
    "peaso/checks/remaining_aws_gcp_native.py": "ded9f2aa60b562cc3db565a091434ad182e8ae8635d4b128549b827a39a6f5f9",
    "peaso/checks/wafv2_basic.py": "b300d867db2803793f56b23dbd2c51751435236428267e12e23c398c99316437",
    "peaso/collectors/aws_all_policies.py": "4be1797ead0658962fe64ddd17ac4437df49b3612e0d8746cf7315734e4a9886",
    "peaso/collectors/aws_apigateway_native.py": "bf5c20ba91a679dcd303579b89ef6f9fd3b96e4664254716b5c98e4367e854a5",
    "peaso/collectors/aws_budget_stop_native.py": "8001bc5895828ec8fc38baeda5a9e5f863866a3d32889e7b1804a06338dbba44",
    "peaso/collectors/aws_bulk_inventory.py": "45aa2a3bce8581cf8bf1046e882eb701a03b61367378fdcee70d3b5ef415230d",
    "peaso/collectors/aws_cloudtrail_delivery_native.py": "bf7348354a77a39d2271f1b022d1620b0e7f7d3b68dc021cf06f86aceb369393",
    "peaso/collectors/aws_codebuild_redaction.py": "d3f487ca28fae5563b2cd5839f760dbd742e859388ab0646dc762d5c7826f18d",
    "peaso/collectors/aws_codecommit_review_native.py": "8700c0be3a48fe2d6a72ed29390d5938ce2b901ecfccfb829a94cc9618249e93",
    "peaso/collectors/aws_controltower_native.py": "4cc022c9698532209a75fe280851e291964efb9244ff70ef607bdda685753999",
    "peaso/collectors/aws_cost_policy.py": "1e53fa329bbaeba16b0548bbd6b912ebbadd4a22c1e1732c24665d68b36fc42d",
    "peaso/collectors/aws_ecr_artifacts_native.py": "3beaa9b23013e715902d29d76064c0bcf205c569b02b38f74d2c7ba0cd66e99c",
    "peaso/collectors/aws_facts_v4_holds.py": "1e2cec696c00e1b002111fa1c4e3d17f41585c115db0808e11162705e1cd9356",
    "peaso/collectors/aws_identity_center_native.py": "60592e3ff76ae393ed43d89f1554fb2da1f0daaf836b5e640c8760e8b0a66d3e",
    "peaso/collectors/aws_identity_metrics_native.py": "f96984d474dcb07f03ddc4a998d5c0ae32563677f0eaa2a02384bc79dafadfc0",
    "peaso/collectors/aws_kms_enclave_native.py": "589935d3ebd9bd13c1d58adf304daf78359374c8e78f88549f2db83c3f32d069",
    "peaso/collectors/aws_launch_configuration_redaction.py": "09f0a76060934ef47924c1cf747079ca0dba6a82e5803686155067516eb951b5",
    "peaso/collectors/aws_macie_coverage_native.py": "5650b5a3e15a654cda7d2e5dcd2974124c6a0a711e1798202bf11e4ca5e65a7b",
    "peaso/collectors/aws_operational_groups_native.py": "06108480e7c2f75ca30343ea5ca4fe3dc0a3fa92d8dee9cf2ccf8f47150f2456",
    "peaso/collectors/aws_organizations_native.py": "f331e1cd6fa1a496bcfffb0a3eeb93d72004028dec1bc72d63db731dd1feae5a",
    "peaso/collectors/aws_policy.py": "a3003f6c3930bd5f23523cc6128192ee6a22891a47035df922e34498ada0429d",
    "peaso/collectors/aws_priority_tags_native.py": "c1f67bb05912bb0e60303989dc722093d379e93d56796c48ca81dc40ddb353f1",
    "peaso/collectors/aws_public_ingress_native.py": "3dda8ed8ffdb9e3b650ffe50bc6da24d52f57e53c908357ef9bc4a2094309b7e",
    "peaso/collectors/aws_region_shield_native.py": "08f2a665106e9e66b799fa75946739b57c01076fed23b882f3f63651b652d471",
    "peaso/collectors/aws_resolver_firewall_native.py": "ca0970fa271384e2167db3cb2ed855cceda0dd834348671654597ec3d8b19a52",
    "peaso/collectors/aws_resource_policy_native.py": "b0c7b4081f965bab4ece4de503fac0de65038c6c98df010f877f745ce940998e",
    "peaso/collectors/aws_s3_backup_native.py": "48654c9bb7c4fcbb5ee52c8035cb0fd29d0d8a716b358e9d8399a4595aad3ffd",
    "peaso/collectors/aws_sagemaker_clarify_native.py": "f6695218f1c6f5dd060b7871b516d975fb54e1560aba5a413698b589aaa113af",
    "peaso/collectors/aws_ssm_inventory_events_native.py": "c495038efa6858ee77d75a1090fe357998076455da3c1c4bebc105fd9e00370a",
    "peaso/collectors/aws_transport_native.py": "ab038928f14c3136df4c9425856e57b2b199afa24085d739b4f8526a225e53e6",
    "peaso/collectors/aws_waf_inventory_native.py": "10bcdf16a32dc1edd69ef751dd2a1427dbeb5a1c10cf91fd605b97c6dd2ada20",
    "peaso/collectors/azure_access_reviews_native.py": "11647049e6d04b1e9985ec51f9e890c02b0e8da66f67391979628a60e772bd6f",
    "peaso/collectors/azure_aks_workloads_native.py": "d05435f71f90ba4c9861a2049d3e04d7465772bbdc519c14d4bba157d9e0a4b4",
    "peaso/collectors/azure_apim_diagnostics_native.py": "d5fe9f4b821fa80c1bed677df063971d6ac61278d315b93eb24b4a7957f9bc2e",
    "peaso/collectors/azure_apim_native.py": "02b20bffce3dc8efa0c74e027533ee438fb6261fcc0a2d0fdd56648b436c3d1d",
    "peaso/collectors/azure_apim_protocol_policy.py": "49c7572d6f0cad40853dc7be7f2867bd465fc2a656f4145680fb36f22cad011f",
    "peaso/collectors/azure_appservice_identity_followup.py": "d5e135f5973b2909974bfd2bf5cb43c03931e71590e63649da35850a75554aaf",
    "peaso/collectors/azure_arm_metadata_native.py": "f244de81694d42e796544d520ab3d631faa58e115f9622ad61d039fe12c4fa50",
    "peaso/collectors/azure_assessment_criteria_native.py": "42ceb16728f8bde78874d38037c835085c1dba1770c3dab84c6b2a03cc268d1a",
    "peaso/collectors/azure_conditional_access_native.py": "9b69def3b75a31ab41eaeac2757b85fe9d3d4f505f948043cd8491cd0ebabe8a",
    "peaso/collectors/azure_database_native.py": "2b5c6850d33f9a74fc6bf46f92bab1330f1d4ae21e92a6461357cde837c3f683",
    "peaso/collectors/azure_databricks_native.py": "3c6c56e700376316c7f711f7dc4981b4f02ec145bacf6553d9163326f7e64359",
    "peaso/collectors/azure_defender_network_native.py": "ce70e05680d870ba145baed0701471783c721446a1781474f70c3b0bbb1985da",
    "peaso/collectors/azure_detection_telemetry.py": "d0c1e354f8c5fbfd8504667dd0268f3e685444e6aa1a5507abb336d16817758d",
    "peaso/collectors/azure_devops_git_native.py": "7b01f9f26acae14414d33b42095caad14adaf4644b3706fde2120e170b4c2c63",
    "peaso/collectors/azure_disclosure_native.py": "1038ca6d576f89c6d9bced0182239b140f4dbe51e7aafb60a1b569634f15426d",
    "peaso/collectors/azure_entra_diagnostics_native.py": "3ba791cd52c3e5b2fb78bcb12fced683402d552f8a8ff3bd13fec65fc941636f",
    "peaso/collectors/azure_frontdoor_native.py": "f020ec13c4a8ddd12c8e276f24538cb7c698f707b1f4eaebb52ce14e3305f675",
    "peaso/collectors/azure_function_limits_native.py": "cd1b13b2fd9d7983e1846fe651507a26422f4ab9cf7dd9866cdf9c50f28fc7e9",
    "peaso/collectors/azure_guest_configuration_native.py": "d534f80d292e158eba0caad3629b1d0fe54987c2cdbaf7e33a56a672f6159a54",
    "peaso/collectors/azure_guest_policy.py": "55f32bdb4d9e25f6603321fcb8a0877e07bce003ea7f2b02ea080401c2905c4d",
    "peaso/collectors/azure_guest_reports.py": "3b0b5a169a73bd97975b8968fed0b2e13b935ac8bc5f297ed791a128f8e74e4b",
    "peaso/collectors/azure_identity_intune_native.py": "02b0b6d133a2f0d30cb2e30a99d6d3d4feef78231eb61e680acd02987f0896fc",
    "peaso/collectors/azure_iot_policy_native.py": "5daa1c505286ba57c4f1ec016f54f5713b138d3b45cfd1c5fb542ee3ad893468",
    "peaso/collectors/azure_monitor_inventory_native.py": "81bd15cf090e296be7a299da4b7b9e42657c987bbed6afdeb82a0453a90e6127",
    "peaso/collectors/azure_resource_diagnostics_native.py": "36f73fc3665680b2489ab99c24dfee59b5f2afb236323952e7131dea481df0ed",
    "peaso/collectors/azure_resource_logging_policy.py": "2d7174efd2706acf66466e3216d95ec1b81d2af1cf5b1b54a8144246ca25d0ba",
    "peaso/collectors/azure_secret_versions_native.py": "53d8ad1f7599697fab83af4139644c93223f9cdbfc5355e587749e545149120c",
    "peaso/collectors/azure_sentinel_metadata_native.py": "3cc20e96f438c017261006a2e9d04f16cfc2d01224515a9477f73a7872e9896b",
    "peaso/collectors/azure_sql_inventory.py": "43a1549a843593c8e33812f5dfa9091a0e7ab534d895ea3e03e718cf08ec82ae",
    "peaso/collectors/azure_storage_backup_native.py": "249e5916a527ecd0d80378c1a4e769fc3511152f0887a85186bc1285aa473405",
    "peaso/collectors/azure_storage_recovery_metadata_native.py": "658807c10ba59c65ecc7a86bd0cae1d3079d785612b69b829908cc135cb81ca0",
    "peaso/collectors/azure_sw15_policy.py": "66a6ff162aa2727a33c3079cfd2709cbea883ce5bcc2f16407ef111743a5b82d",
    "peaso/collectors/batch_remaining_azure_vm_storage.py": "44bb52e7d7e9e7290cb302e439e1ada18b3dd278895125c857fd028dffa21053",
    "peaso/collectors/batch_remaining_k8s.py": "8c15aa07719cc9596edb3aa7128c99b8d301ef35269ab860ceeb238bec95bb3e",
    "peaso/collectors/bulk_evidence.json": "c1d173bead561f5777df8e703dd8a0939692202b8f2fe7427e8e6d72457a5744",
    "peaso/collectors/bulk_evidence.py": "fb51c829ddc9ca2c83e7cb54de8e1ebc91c0530a8d7eb47d6083e5ff170e6e09",
    "peaso/collectors/gcp_audit_native.py": "02554f3aa9bf2a4d450455c75c6b7fac5ca2396e1afededd34db42a6ec4179e8",
    "peaso/collectors/gcp_facts_v4_holds.py": "f52b9df380e2e69de33cd39bd99f3fda30cac030a1a583c50660b8b9a083f39f",
    "peaso/collectors/gcp_history.py": "21368065d8d1a46209e88d623bb848fe2e3dcb0e4e4c0e5b01f867b8ecf4e631",
    "peaso/collectors/gcp_kms_effective_native.py": "7d2c1e81afebac5e99d47951c85c24aeb91e1795d3fe233c396d9bac6a30ae01",
    "peaso/collectors/gcp_native_evidence.py": "fdced136c30eca42529c967ba2a59f84068008ee98345a1a7abc2c974ca060e1",
    "peaso/collectors/gcp_os_patch_native.py": "e8d86dbc207104d2dbc59d2c0dd0a558f7d00e7edde5960d2750fa7803a85f58",
    "peaso/collectors/gcp_sbom_native.py": "e4fc4bc0c455146ed580d7ef3406424c8ddca2588ccf5cb7c723b922931902f8",
    "peaso/collectors/gcp_storage_acl_native.py": "9ef114ced31862ed48cc3defc7710623e130fcd6431051174fc44b6d19fa2033",
    "peaso/collectors/k8s_admission_file.py": "fc23c5692f1bc295394cf770312a58a8bb64dc532d2c2d9ad33cfeb8a440795f",
    "peaso/gcp_data_access_policy.py": "03167a5cf56583a9ae4efb08aba2beb24fa0e62fcafded1b6f7f47181cb5d4c7",
    "peaso/gcp_psc_policy.py": "ceb9da0dca6e28d011e9f0d779fe519991bb78ec4e7df9bbba67494306eb0ff1",
    "peaso/gcp_sbom_policy.py": "ef717b7f45ddb6d7abca981b6a871f60d9dde0f1eee442c64ddb342ca60be788",
    "peaso/privesc/azure_disclosure_effects.json": "6caf92a0ffdc59cffecb0c9d047d31bc7c49fe02dd0f19b11f3ec743a670f93e",
    "peaso/privesc/bounded_effects.json": "4ce1a0b29fbf026bbc26166915f87e5fb2c4e6396a8aa37ee91e56ca1840806d",
    "peaso/privesc/bulk_principal_tranche.json": "6cb1c21ba90b1ae08d0e5671efa373c8711d42cdb97d3f9055f84d3a239428a8",
    "peaso/privesc/catalog/aws/bounded-effects-v5.yaml": "d38ce968f6af36e9d5c72a098916978320ebf61653df6e6b2c1916de3fbaf80a",
    "peaso/privesc/catalog/aws/bulk-principal-v6.yaml": "e4e907a900127eec6feaa5bb9527ddb130d52c4895b94fd65acb6e8b0a29c779",
    "peaso/privesc/catalog/aws/exact-principal-v5.yaml": "b198454714e4e530682cea805f5e1db595c9eb7a8057f35b1f8d426f88c2a709",
    "peaso/privesc/catalog/aws/lightsail.yaml": "1645b857297793df9c1f6a69e236cbff5873b65055e4e4056360c693c809a279",
    "peaso/privesc/catalog/azure/app_configuration.yaml": "937a2bbc1a2b42d08ef7d183653e540f7320b672c59d9ed5068a191a3aaca89b",
    "peaso/privesc/catalog/azure/bounded-effects-v5.yaml": "1ca7a8398150cd05f2146e3466be8713481870cdcedfaf8813aad3e41b12a9f4",
    "peaso/privesc/catalog/azure/disclosure-effects-v7.yaml": "00175d020192d57529b305d80b2027dcea8df7b58aac26e0c60fd03196b79d3a",
    "peaso/privesc/catalog/azure/monitor.yaml": "a2cec1047c97588d0537a02e1f5ac06ed091188097b8427369fc8362f715cada",
    "peaso/privesc/catalog/azure/storage-local-v7.yaml": "39fc0f2734331d8d08d356614775095d8b7be97bf343aa240e110c12d2988f9f",
    "peaso/privesc/catalog/azure/storage.yaml": "be4c268b9114175bbf079a4d9c70009392f9fab26afa47ea8100930255b19b15",
    "peaso/privesc/catalog/gcp/aiplatform.yaml": "d32d22ffb8909105cbc49f3fe0704df6ffb8e43494c7c908981d59dd31800c69",
    "peaso/privesc/catalog/gcp/bigtable.yaml": "436131e96ff896df4425319aee3952c6010909dab2b4256302a4367af8e230db",
    "peaso/privesc/catalog/gcp/bounded-effects-v5.yaml": "336a51ee7c3e5411d23c7e6fffd90849a28de2577ce2ccc02ff6e03877da5505",
    "peaso/privesc/catalog/gcp/bulk-principal-v6.yaml": "1998a8787332908d955ab6e8769f315dac4afe80fb2e66b57dc34ad7a916cf25",
    "peaso/privesc/catalog/gcp/dlp.yaml": "a4191890cd5bb94485588a7830567975f59ded4b2043f58331a4e6a60223187d",
    "peaso/privesc/catalog/gcp/exact-principal-v5.yaml": "345e1f41d7baf6f859b65eb6abdf8b6be5bf25781a9b25602ab1481bf1c7ec0b",
    "peaso/privesc/catalog/gcp/parametermanager.yaml": "8273c65df5d117386103e3694b7074ab002487b851706897c63d44300f76acab",
    "peaso/privesc/catalog/gcp/secretmanager.yaml": "7ddb46238daeeba20663d30f5a2f07ab25b26cfd8838895787043a6b28c5b23e",
    "peaso/privesc/catalog/k8s/scoped-credential-v7.yaml": "7c4940f42a1754cd843688fcd903a522cd99ea98491c20a1ef5ed77dd75008a5",
    "peaso/privesc/catalog_versions/bounded-v5-manifest.json": "082451e81fa450830ae5f6835e241dd412a6c30a8b2a0b1172cdbc89b2d71429",
    "peaso/privesc/catalog_versions/bulk-principal-v6-manifest.json": "734401b202895e00ac1b6cb0f1534f77cde4d8e2ba912ca0ee974b1b8ec5035c",
    "peaso/privesc/catalog_versions/disclosure-v7-manifest.json": "91ffe7389d02568cdcdf74a6b08dafa5f665ea07c0c528988127ffc4d2a86c45",
    "peaso/privesc/catalog_versions/legacy-0b3633-delta.json": "40640ad0e7179af395ec37f9456ef7b9d8340e8ab81e9edb7a460769edca258a",
    "peaso/privesc/catalog_versions/principal-v4-manifest.json": "6008acf71acda21408c7039dddff2d7ccaeeaa3aecfc6f31ef5d2cdc5a4ea388",
    "peaso/privesc/effective_permissions/azure_disclosure_effects.py": "554dba11bab6ad0145960f8b594ae58ab165e00c0fbe3fb91c3a4bcfa6ef197f",
    "peaso/privesc/effective_permissions/bounded_evidence.py": "1cd1a44f2d955bb5dc877e404ab09294a3df9b67bb1ff9e867aec1cd0cf212af",
    "peaso/privesc/effective_permissions/credential_evidence.py": "a95078884cd2e1c91e3e729921254844237eaa0444b89bf0cd6afd88d9fcaef3",
    "peaso/privesc/effective_permissions/ec2_profile_association.py": "22f0c201cc7d2b37f26c26e307dca33ce55e5716c5f6bea64affc78aff78e039",
    "peaso/privesc/effective_permissions/principal_evidence.py": "2c4bd5e2e2fa33db271b963387787003a42e1c741dad27b22e7b37f23fc2f7e3",
    "peaso/privesc/effective_permissions/storage_local_identity.py": "7671720b0780e47c583e0877888235406c220e64b937d361edb555f3300df7d0",
    "peaso/privesc/exact_principal_tranche.json": "c02921ad9a694b07415ffd5de0c97a0e8b0f34b73bbf40dc3b78e149e29b4af6",
    "peaso/privesc/versioned_catalog.py": "fd6831825507de22b7155909b3bdc1f1e391244b85a180b7764e22f7974f6666",
    "peaso/rulepacks/remediation_compliance_batch_remaining_aws.json": "ebe28d47a1880fa09acc7f42022a1e199ac9c27992049d2ca074670b41d6d490",
    "peaso/rulepacks/remediation_compliance_batch_remaining_azure.json": "a8f76c1a53926fa6cbbda666e80108b494d7933d77d9d39f6d1226f02937b91a",
    "peaso/rulepacks/remediation_compliance_batch_remaining_gcp.json": "5d618ab15fa5cd624e2b2559ab9f308dabe5fb2fa255d33ff664386c5e97b71c",
    "peaso/rulepacks/remediation_compliance_batch_remaining_k8s.json": "5485734fd0351e2dc8f6862b65472164e05df802e32d9c08d061826d1f1492ca",
    "peaso/server/native_policy_validation.py": "a6f62b76f0b68820faa59b29277164b45f4ec04a43ff93c43873273613d7298e"
}
APPROVED_V26_SOURCE_MEMBERS = 1823
APPROVED_V26_RUNTIME_MEMBERS = 915
APPROVED_V26_RUNTIME_SHA256 = '2654e81c58131b48e7a6e3d8807c6045abe7560b0c8a93a72d9687934a9ba7bc'


# Exact additive V27 native metadata successor; preserve every prior literal.
APPROVED_V27_RUNTIME_ADDITIONS = {
    "peaso/analysis/aws_public_ingress.py": "f58f4f100215dd35da15ec177fbfa1b90145a6bf02fbd80afd759374544f06f0",
    "peaso/aws_budget_policy.py": "940a71e4627173e814381a148744a3840c81f60957f5bd2a6032fa4086ba4b69",
    "peaso/aws_waf_logging.py": "f97074cf8e7ecfb00ac1bac45947bdcd628affe294a0465283b1a5a35eb7c8b9",
    "peaso/azure_devops_git_policy.py": "4c195e73eebf742314c3eeafe0d1f95356d58e71e6c2339d8b1b8b8d418e28ed",
    "peaso/azure_sw32_policy.py": "9d9a545dbc9240e29a3389445dcb9f032fd2350db059e38d49a95f0d90d9e3b0",
    "peaso/checks/aws_all_policies.json": "8e1cdcc44749b643d95e4ee223e386a4b4aba609d9e09a0577779cc34daa83bf",
    "peaso/checks/aws_all_policies.py": "46c12e7ef9f8ed1eac29709c720c0b703e71ee7d0ac15c2427c99346747ab9fe",
    "peaso/checks/aws_all_policies_fixtures.json": "f93d3feb539b593561b3cf9878a0f151e5619ab29bb43984e9963e141eee9401",
    "peaso/checks/aws_backup_plan_frequency.py": "0f40ddcace19dded128369f32efad6d72e36a8a95590073beb8cada2d4cff08d",
    "peaso/checks/aws_config_recording.py": "50800c1a5c30aa407d0791d4416cc473ea19c3d03f584a2a4a2cfa694d2eabec",
    "peaso/checks/azure_apim_diagnostics_native.py": "4221d0aa3092bff0bb5eeb11fdf3ecc58687f0899a52523fbfeed412bb4af55b",
    "peaso/checks/azure_apim_native.py": "af1e1903c167c813e1ab8e8a9c7fa2336dc6cb5f9d8757f7beaaf6f481744f6b",
    "peaso/checks/azure_appservice_identity_followup.py": "ca7ffd2dccf77fd8e7b90d31c567cbb48b666300330555242582efe768347463",
    "peaso/checks/azure_easm_native.py": "d75e42848fae6c53b0f9e29fdb5c568325bbf8f2e136a7dcc435c58b1036f94b",
    "peaso/checks/azure_graph_credential_age.py": "ba0b2f87162cbace267cb0d630f05655d59239b287d9e7ae6b4f8744cc30a7b4",
    "peaso/checks/azure_log_profile_retention.py": "ba369f5809f8484310b89079ee0b4c3a5523f561ff03cd349488766cc86837ba",
    "peaso/checks/batch_remaining_aws.py": "197ccf540f23e9373d8db281bf1544d2d2bba793be3738ff214e9a6038d813b2",
    "peaso/checks/batch_remaining_azure.py": "82e39d57beef687761098e206457e5e7f7e25a792fc9fcc8600d809f4737b136",
    "peaso/checks/batch_remaining_azure_vm_storage.py": "11f0353505ec70bb7cbc1f6f72add7ceb664fcbd01d05bd8018b2063dd09babb",
    "peaso/checks/batch_remaining_gcp.py": "4f93aebdb8c4fabb603cc122b7a390bc153abc6039035c4a0e780be708aed870",
    "peaso/checks/batch_remaining_k8s.py": "0f0c92c50a05e92bfd0357767066e4e481c03320c2f582ff10194d8cc25dd578",
    "peaso/checks/bulk_pending.json": "2694ae6e9dd10a05027d34868ff269a08f0c85996948fb9a303e7aa44b86efda",
    "peaso/checks/bulk_pending.py": "41cd15965640293562f1808fd7cc31b85769a3e3a44aa3c5537d119dabd50a11",
    "peaso/checks/central_batch_fixtures.json": "1a226d4af6f26c7216c305d36109226bed11e28051c936cb86f66ffcb5dc734b",
    "peaso/checks/central_native_fixtures.py": "2b9665b5b12e164a76b0982bc055857be82cd72d09eafcb8588bc96ead0503f4",
    "peaso/checks/compliance_new_sw25_native_identity.py": "c347440d7e378900762fc5cf6253203c61325008f6320008919d68cb5c37c53e",
    "peaso/checks/compliance_next_k8s.py": "d0184f0934601aaa4682c07d1f0dbfa1b40fa2e9090ce2ca53ca413471b96dfc",
    "peaso/checks/gcp_audit_native.py": "8c2f5e8d0a76571c06a0e0ade0e83cd54f0814fe525fc9f293968224ba2edf8f",
    "peaso/checks/gcp_audit_rates.json": "5010787138c533e7af252d5cfc2aab641097fb6bc9607d6018a66aac943554d9",
    "peaso/checks/gcp_audit_rates.py": "efb0da440e417b40efbcbf189b0fb62385be3b849136b04de08f61baff8e748c",
    "peaso/checks/gcp_audit_rates_fixtures.json": "2d2fd4319e86bb5f54d0f99b6c28ca0788504e46e822afdaed5d0dfe108a4354",
    "peaso/checks/gcp_data_access.py": "ce997648d524475e848aff41353b99f3add7075eca451146a89a7998da9f51c5",
    "peaso/checks/gcp_psc_dns.py": "4d820199813173d9f32ab2b4a5b4547c449d7f88e69affe1064247cb2df1e599",
    "peaso/checks/gcp_psc_fixtures.json": "d452ed303ed02d23d05e1ef1efce880264002779bf3073dee79239a3764a6138",
    "peaso/checks/k8s_namespace_policy_presence.py": "47f64b995e1f5ca9b6db72ff62a7a4594521448f2a1fbba174d453251698a2b2",
    "peaso/checks/native_storage_compute.json": "e4891a7a99339126380eab0a9e66e855c4b1f7ee8558e79abe64a2471fac7c9d",
    "peaso/checks/native_storage_compute.py": "66bc80ff2d43d7d394defa1180199abf42fb0c40b56ff2696ce5f9733f1de318",
    "peaso/checks/native_storage_compute_fixtures.json": "815860e018a22d38bf666b17a981d28993bea720567d369e28e1d26b1339f274",
    "peaso/checks/next20_aws.py": "8b5bedb10366b2708e445bc0068f41a1e6aea0bf8fe7f20c81029dfce665e569",
    "peaso/checks/next_group_appservice_fixtures.py": "1f461d725797b538f7e6550f7aa70217b029e6ec846a3a9e7ce5e6531057c3be",
    "peaso/checks/next_group_aws_fixtures.py": "0076893df5c07f55cd2244d98afaa4516e56f5a1a7bb4f3c5bf7ee1874adb90a",
    "peaso/checks/next_group_azure_fixtures.py": "274822bd1753bef38af173b6be01774abba8ab1bb6b0a0fe3d76638b2e0da249",
    "peaso/checks/next_group_easm_fixtures.py": "3162d5c0deeb1122ddddb06a82793167366dc71f17983547365791854f0406a8",
    "peaso/checks/post_dfaf_aws.py": "301493a4bd3ee865d3d830807a9d6481ef5e3910b3e8ba99c26b57b487cd0fce",
    "peaso/checks/post_dfaf_aws_specs.py": "4f2410348d731c2c76c3db79b0b2b0aebedebf874ce9044f9dccb612622d2476",
    "peaso/checks/post_dfaf_azure.py": "c00e5f758009f1929eb97f83a096706874b97fc6e2269dea8ccdab06c8e5640e",
    "peaso/checks/remaining_aws_gcp_native.py": "ded9f2aa60b562cc3db565a091434ad182e8ae8635d4b128549b827a39a6f5f9",
    "peaso/checks/wafv2_basic.py": "b300d867db2803793f56b23dbd2c51751435236428267e12e23c398c99316437",
    "peaso/collectors/aws_all_policies.py": "4be1797ead0658962fe64ddd17ac4437df49b3612e0d8746cf7315734e4a9886",
    "peaso/collectors/aws_apigateway_native.py": "bf5c20ba91a679dcd303579b89ef6f9fd3b96e4664254716b5c98e4367e854a5",
    "peaso/collectors/aws_budget_stop_native.py": "8001bc5895828ec8fc38baeda5a9e5f863866a3d32889e7b1804a06338dbba44",
    "peaso/collectors/aws_bulk_inventory.py": "45aa2a3bce8581cf8bf1046e882eb701a03b61367378fdcee70d3b5ef415230d",
    "peaso/collectors/aws_cloudtrail_delivery_native.py": "bf7348354a77a39d2271f1b022d1620b0e7f7d3b68dc021cf06f86aceb369393",
    "peaso/collectors/aws_codebuild_redaction.py": "d3f487ca28fae5563b2cd5839f760dbd742e859388ab0646dc762d5c7826f18d",
    "peaso/collectors/aws_codecommit_review_native.py": "8700c0be3a48fe2d6a72ed29390d5938ce2b901ecfccfb829a94cc9618249e93",
    "peaso/collectors/aws_controltower_native.py": "4cc022c9698532209a75fe280851e291964efb9244ff70ef607bdda685753999",
    "peaso/collectors/aws_cost_policy.py": "1e53fa329bbaeba16b0548bbd6b912ebbadd4a22c1e1732c24665d68b36fc42d",
    "peaso/collectors/aws_ecr_artifacts_native.py": "3beaa9b23013e715902d29d76064c0bcf205c569b02b38f74d2c7ba0cd66e99c",
    "peaso/collectors/aws_facts_v4_holds.py": "1e2cec696c00e1b002111fa1c4e3d17f41585c115db0808e11162705e1cd9356",
    "peaso/collectors/aws_identity_center_native.py": "60592e3ff76ae393ed43d89f1554fb2da1f0daaf836b5e640c8760e8b0a66d3e",
    "peaso/collectors/aws_identity_metrics_native.py": "f96984d474dcb07f03ddc4a998d5c0ae32563677f0eaa2a02384bc79dafadfc0",
    "peaso/collectors/aws_kms_enclave_native.py": "589935d3ebd9bd13c1d58adf304daf78359374c8e78f88549f2db83c3f32d069",
    "peaso/collectors/aws_launch_configuration_redaction.py": "09f0a76060934ef47924c1cf747079ca0dba6a82e5803686155067516eb951b5",
    "peaso/collectors/aws_macie_coverage_native.py": "5650b5a3e15a654cda7d2e5dcd2974124c6a0a711e1798202bf11e4ca5e65a7b",
    "peaso/collectors/aws_operational_groups_native.py": "06108480e7c2f75ca30343ea5ca4fe3dc0a3fa92d8dee9cf2ccf8f47150f2456",
    "peaso/collectors/aws_organizations_native.py": "f331e1cd6fa1a496bcfffb0a3eeb93d72004028dec1bc72d63db731dd1feae5a",
    "peaso/collectors/aws_policy.py": "a3003f6c3930bd5f23523cc6128192ee6a22891a47035df922e34498ada0429d",
    "peaso/collectors/aws_priority_tags_native.py": "c1f67bb05912bb0e60303989dc722093d379e93d56796c48ca81dc40ddb353f1",
    "peaso/collectors/aws_public_ingress_native.py": "3dda8ed8ffdb9e3b650ffe50bc6da24d52f57e53c908357ef9bc4a2094309b7e",
    "peaso/collectors/aws_region_data_native.py": "e2440353ea5b31d50ce281e049dd4586e05710763c0b0b7ee8c737b79ae9f9e1",
    "peaso/collectors/aws_region_shield_native.py": "08f2a665106e9e66b799fa75946739b57c01076fed23b882f3f63651b652d471",
    "peaso/collectors/aws_resolver_firewall_native.py": "ca0970fa271384e2167db3cb2ed855cceda0dd834348671654597ec3d8b19a52",
    "peaso/collectors/aws_resource_policy_native.py": "b0c7b4081f965bab4ece4de503fac0de65038c6c98df010f877f745ce940998e",
    "peaso/collectors/aws_s3_backup_native.py": "48654c9bb7c4fcbb5ee52c8035cb0fd29d0d8a716b358e9d8399a4595aad3ffd",
    "peaso/collectors/aws_sagemaker_clarify_native.py": "f6695218f1c6f5dd060b7871b516d975fb54e1560aba5a413698b589aaa113af",
    "peaso/collectors/aws_ssm_inventory_events_native.py": "c495038efa6858ee77d75a1090fe357998076455da3c1c4bebc105fd9e00370a",
    "peaso/collectors/aws_transport_native.py": "ab038928f14c3136df4c9425856e57b2b199afa24085d739b4f8526a225e53e6",
    "peaso/collectors/aws_waf_inventory_native.py": "10bcdf16a32dc1edd69ef751dd2a1427dbeb5a1c10cf91fd605b97c6dd2ada20",
    "peaso/collectors/azure_access_reviews_native.py": "11647049e6d04b1e9985ec51f9e890c02b0e8da66f67391979628a60e772bd6f",
    "peaso/collectors/azure_aks_workloads_native.py": "d05435f71f90ba4c9861a2049d3e04d7465772bbdc519c14d4bba157d9e0a4b4",
    "peaso/collectors/azure_apim_diagnostics_native.py": "d5fe9f4b821fa80c1bed677df063971d6ac61278d315b93eb24b4a7957f9bc2e",
    "peaso/collectors/azure_apim_native.py": "02b20bffce3dc8efa0c74e027533ee438fb6261fcc0a2d0fdd56648b436c3d1d",
    "peaso/collectors/azure_apim_protocol_policy.py": "49c7572d6f0cad40853dc7be7f2867bd465fc2a656f4145680fb36f22cad011f",
    "peaso/collectors/azure_appservice_identity_followup.py": "d5e135f5973b2909974bfd2bf5cb43c03931e71590e63649da35850a75554aaf",
    "peaso/collectors/azure_arm_metadata_native.py": "f244de81694d42e796544d520ab3d631faa58e115f9622ad61d039fe12c4fa50",
    "peaso/collectors/azure_assessment_criteria_native.py": "42ceb16728f8bde78874d38037c835085c1dba1770c3dab84c6b2a03cc268d1a",
    "peaso/collectors/azure_conditional_access_native.py": "9b69def3b75a31ab41eaeac2757b85fe9d3d4f505f948043cd8491cd0ebabe8a",
    "peaso/collectors/azure_database_native.py": "2b5c6850d33f9a74fc6bf46f92bab1330f1d4ae21e92a6461357cde837c3f683",
    "peaso/collectors/azure_databricks_native.py": "3c6c56e700376316c7f711f7dc4981b4f02ec145bacf6553d9163326f7e64359",
    "peaso/collectors/azure_defender_network_native.py": "ce70e05680d870ba145baed0701471783c721446a1781474f70c3b0bbb1985da",
    "peaso/collectors/azure_detection_telemetry.py": "d0c1e354f8c5fbfd8504667dd0268f3e685444e6aa1a5507abb336d16817758d",
    "peaso/collectors/azure_devops_git_native.py": "7b01f9f26acae14414d33b42095caad14adaf4644b3706fde2120e170b4c2c63",
    "peaso/collectors/azure_devops_pipeline_native.py": "05a1993d4887bbd52824ba2a4df8fe0137f4a42f78a1607a9176d19cf5dbb2a5",
    "peaso/collectors/azure_disclosure_native.py": "1038ca6d576f89c6d9bced0182239b140f4dbe51e7aafb60a1b569634f15426d",
    "peaso/collectors/azure_entra_diagnostics_native.py": "3ba791cd52c3e5b2fb78bcb12fced683402d552f8a8ff3bd13fec65fc941636f",
    "peaso/collectors/azure_frontdoor_native.py": "f020ec13c4a8ddd12c8e276f24538cb7c698f707b1f4eaebb52ce14e3305f675",
    "peaso/collectors/azure_function_limits_native.py": "cd1b13b2fd9d7983e1846fe651507a26422f4ab9cf7dd9866cdf9c50f28fc7e9",
    "peaso/collectors/azure_guest_configuration_native.py": "d534f80d292e158eba0caad3629b1d0fe54987c2cdbaf7e33a56a672f6159a54",
    "peaso/collectors/azure_guest_policy.py": "55f32bdb4d9e25f6603321fcb8a0877e07bce003ea7f2b02ea080401c2905c4d",
    "peaso/collectors/azure_guest_reports.py": "3b0b5a169a73bd97975b8968fed0b2e13b935ac8bc5f297ed791a128f8e74e4b",
    "peaso/collectors/azure_identity_intune_native.py": "02b0b6d133a2f0d30cb2e30a99d6d3d4feef78231eb61e680acd02987f0896fc",
    "peaso/collectors/azure_iot_policy_native.py": "5daa1c505286ba57c4f1ec016f54f5713b138d3b45cfd1c5fb542ee3ad893468",
    "peaso/collectors/azure_monitor_inventory_native.py": "81bd15cf090e296be7a299da4b7b9e42657c987bbed6afdeb82a0453a90e6127",
    "peaso/collectors/azure_resource_diagnostics_native.py": "36f73fc3665680b2489ab99c24dfee59b5f2afb236323952e7131dea481df0ed",
    "peaso/collectors/azure_resource_logging_policy.py": "2d7174efd2706acf66466e3216d95ec1b81d2af1cf5b1b54a8144246ca25d0ba",
    "peaso/collectors/azure_secret_versions_native.py": "53d8ad1f7599697fab83af4139644c93223f9cdbfc5355e587749e545149120c",
    "peaso/collectors/azure_sentinel_metadata_native.py": "3cc20e96f438c017261006a2e9d04f16cfc2d01224515a9477f73a7872e9896b",
    "peaso/collectors/azure_sql_inventory.py": "43a1549a843593c8e33812f5dfa9091a0e7ab534d895ea3e03e718cf08ec82ae",
    "peaso/collectors/azure_storage_backup_native.py": "249e5916a527ecd0d80378c1a4e769fc3511152f0887a85186bc1285aa473405",
    "peaso/collectors/azure_storage_recovery_metadata_native.py": "658807c10ba59c65ecc7a86bd0cae1d3079d785612b69b829908cc135cb81ca0",
    "peaso/collectors/azure_sw15_policy.py": "66a6ff162aa2727a33c3079cfd2709cbea883ce5bcc2f16407ef111743a5b82d",
    "peaso/collectors/azure_vault_key_versions_native.py": "9f99c8f3327161412f6442c8531a566944a8fd2a4b32919da6cddf5bfdc0b932",
    "peaso/collectors/batch_remaining_azure_vm_storage.py": "44bb52e7d7e9e7290cb302e439e1ada18b3dd278895125c857fd028dffa21053",
    "peaso/collectors/batch_remaining_k8s.py": "8c15aa07719cc9596edb3aa7128c99b8d301ef35269ab860ceeb238bec95bb3e",
    "peaso/collectors/bulk_evidence.json": "c1d173bead561f5777df8e703dd8a0939692202b8f2fe7427e8e6d72457a5744",
    "peaso/collectors/bulk_evidence.py": "fb51c829ddc9ca2c83e7cb54de8e1ebc91c0530a8d7eb47d6083e5ff170e6e09",
    "peaso/collectors/gcp_audit_native.py": "02554f3aa9bf2a4d450455c75c6b7fac5ca2396e1afededd34db42a6ec4179e8",
    "peaso/collectors/gcp_facts_v4_holds.py": "f52b9df380e2e69de33cd39bd99f3fda30cac030a1a583c50660b8b9a083f39f",
    "peaso/collectors/gcp_history.py": "21368065d8d1a46209e88d623bb848fe2e3dcb0e4e4c0e5b01f867b8ecf4e631",
    "peaso/collectors/gcp_kms_effective_native.py": "7d2c1e81afebac5e99d47951c85c24aeb91e1795d3fe233c396d9bac6a30ae01",
    "peaso/collectors/gcp_native_evidence.py": "fdced136c30eca42529c967ba2a59f84068008ee98345a1a7abc2c974ca060e1",
    "peaso/collectors/gcp_os_patch_native.py": "e8d86dbc207104d2dbc59d2c0dd0a558f7d00e7edde5960d2750fa7803a85f58",
    "peaso/collectors/gcp_sbom_native.py": "e4fc4bc0c455146ed580d7ef3406424c8ddca2588ccf5cb7c723b922931902f8",
    "peaso/collectors/gcp_storage_acl_native.py": "9ef114ced31862ed48cc3defc7710623e130fcd6431051174fc44b6d19fa2033",
    "peaso/collectors/k8s_admission_file.py": "fc23c5692f1bc295394cf770312a58a8bb64dc532d2c2d9ad33cfeb8a440795f",
    "peaso/gcp_data_access_policy.py": "03167a5cf56583a9ae4efb08aba2beb24fa0e62fcafded1b6f7f47181cb5d4c7",
    "peaso/gcp_psc_policy.py": "ceb9da0dca6e28d011e9f0d779fe519991bb78ec4e7df9bbba67494306eb0ff1",
    "peaso/gcp_sbom_policy.py": "ef717b7f45ddb6d7abca981b6a871f60d9dde0f1eee442c64ddb342ca60be788",
    "peaso/privesc/azure_disclosure_effects.json": "6caf92a0ffdc59cffecb0c9d047d31bc7c49fe02dd0f19b11f3ec743a670f93e",
    "peaso/privesc/bounded_effects.json": "4ce1a0b29fbf026bbc26166915f87e5fb2c4e6396a8aa37ee91e56ca1840806d",
    "peaso/privesc/bulk_principal_tranche.json": "6cb1c21ba90b1ae08d0e5671efa373c8711d42cdb97d3f9055f84d3a239428a8",
    "peaso/privesc/catalog/aws/bounded-effects-v5.yaml": "d38ce968f6af36e9d5c72a098916978320ebf61653df6e6b2c1916de3fbaf80a",
    "peaso/privesc/catalog/aws/bulk-principal-v6.yaml": "e4e907a900127eec6feaa5bb9527ddb130d52c4895b94fd65acb6e8b0a29c779",
    "peaso/privesc/catalog/aws/exact-principal-v5.yaml": "b198454714e4e530682cea805f5e1db595c9eb7a8057f35b1f8d426f88c2a709",
    "peaso/privesc/catalog/aws/lightsail.yaml": "1645b857297793df9c1f6a69e236cbff5873b65055e4e4056360c693c809a279",
    "peaso/privesc/catalog/azure/app_configuration.yaml": "937a2bbc1a2b42d08ef7d183653e540f7320b672c59d9ed5068a191a3aaca89b",
    "peaso/privesc/catalog/azure/bounded-effects-v5.yaml": "1ca7a8398150cd05f2146e3466be8713481870cdcedfaf8813aad3e41b12a9f4",
    "peaso/privesc/catalog/azure/disclosure-effects-v7.yaml": "00175d020192d57529b305d80b2027dcea8df7b58aac26e0c60fd03196b79d3a",
    "peaso/privesc/catalog/azure/monitor.yaml": "a2cec1047c97588d0537a02e1f5ac06ed091188097b8427369fc8362f715cada",
    "peaso/privesc/catalog/azure/storage-local-v7.yaml": "39fc0f2734331d8d08d356614775095d8b7be97bf343aa240e110c12d2988f9f",
    "peaso/privesc/catalog/azure/storage.yaml": "be4c268b9114175bbf079a4d9c70009392f9fab26afa47ea8100930255b19b15",
    "peaso/privesc/catalog/gcp/aiplatform.yaml": "d32d22ffb8909105cbc49f3fe0704df6ffb8e43494c7c908981d59dd31800c69",
    "peaso/privesc/catalog/gcp/bigtable.yaml": "436131e96ff896df4425319aee3952c6010909dab2b4256302a4367af8e230db",
    "peaso/privesc/catalog/gcp/bounded-effects-v5.yaml": "336a51ee7c3e5411d23c7e6fffd90849a28de2577ce2ccc02ff6e03877da5505",
    "peaso/privesc/catalog/gcp/bulk-principal-v6.yaml": "1998a8787332908d955ab6e8769f315dac4afe80fb2e66b57dc34ad7a916cf25",
    "peaso/privesc/catalog/gcp/dlp.yaml": "a4191890cd5bb94485588a7830567975f59ded4b2043f58331a4e6a60223187d",
    "peaso/privesc/catalog/gcp/exact-principal-v5.yaml": "345e1f41d7baf6f859b65eb6abdf8b6be5bf25781a9b25602ab1481bf1c7ec0b",
    "peaso/privesc/catalog/gcp/parametermanager.yaml": "8273c65df5d117386103e3694b7074ab002487b851706897c63d44300f76acab",
    "peaso/privesc/catalog/gcp/secretmanager.yaml": "7ddb46238daeeba20663d30f5a2f07ab25b26cfd8838895787043a6b28c5b23e",
    "peaso/privesc/catalog/k8s/scoped-credential-v7.yaml": "7c4940f42a1754cd843688fcd903a522cd99ea98491c20a1ef5ed77dd75008a5",
    "peaso/privesc/catalog_versions/bounded-v5-manifest.json": "082451e81fa450830ae5f6835e241dd412a6c30a8b2a0b1172cdbc89b2d71429",
    "peaso/privesc/catalog_versions/bulk-principal-v6-manifest.json": "734401b202895e00ac1b6cb0f1534f77cde4d8e2ba912ca0ee974b1b8ec5035c",
    "peaso/privesc/catalog_versions/disclosure-v7-manifest.json": "91ffe7389d02568cdcdf74a6b08dafa5f665ea07c0c528988127ffc4d2a86c45",
    "peaso/privesc/catalog_versions/legacy-0b3633-delta.json": "40640ad0e7179af395ec37f9456ef7b9d8340e8ab81e9edb7a460769edca258a",
    "peaso/privesc/catalog_versions/principal-v4-manifest.json": "6008acf71acda21408c7039dddff2d7ccaeeaa3aecfc6f31ef5d2cdc5a4ea388",
    "peaso/privesc/effective_permissions/azure_disclosure_effects.py": "554dba11bab6ad0145960f8b594ae58ab165e00c0fbe3fb91c3a4bcfa6ef197f",
    "peaso/privesc/effective_permissions/bounded_evidence.py": "1cd1a44f2d955bb5dc877e404ab09294a3df9b67bb1ff9e867aec1cd0cf212af",
    "peaso/privesc/effective_permissions/credential_evidence.py": "a95078884cd2e1c91e3e729921254844237eaa0444b89bf0cd6afd88d9fcaef3",
    "peaso/privesc/effective_permissions/ec2_profile_association.py": "22f0c201cc7d2b37f26c26e307dca33ce55e5716c5f6bea64affc78aff78e039",
    "peaso/privesc/effective_permissions/principal_evidence.py": "2c4bd5e2e2fa33db271b963387787003a42e1c741dad27b22e7b37f23fc2f7e3",
    "peaso/privesc/effective_permissions/storage_local_identity.py": "7671720b0780e47c583e0877888235406c220e64b937d361edb555f3300df7d0",
    "peaso/privesc/exact_principal_tranche.json": "c02921ad9a694b07415ffd5de0c97a0e8b0f34b73bbf40dc3b78e149e29b4af6",
    "peaso/privesc/versioned_catalog.py": "fd6831825507de22b7155909b3bdc1f1e391244b85a180b7764e22f7974f6666",
    "peaso/rulepacks/remediation_compliance_batch_remaining_aws.json": "ebe28d47a1880fa09acc7f42022a1e199ac9c27992049d2ca074670b41d6d490",
    "peaso/rulepacks/remediation_compliance_batch_remaining_azure.json": "a8f76c1a53926fa6cbbda666e80108b494d7933d77d9d39f6d1226f02937b91a",
    "peaso/rulepacks/remediation_compliance_batch_remaining_gcp.json": "5d618ab15fa5cd624e2b2559ab9f308dabe5fb2fa255d33ff664386c5e97b71c",
    "peaso/rulepacks/remediation_compliance_batch_remaining_k8s.json": "5485734fd0351e2dc8f6862b65472164e05df802e32d9c08d061826d1f1492ca",
    "peaso/server/native_policy_validation.py": "a6f62b76f0b68820faa59b29277164b45f4ec04a43ff93c43873273613d7298e"
}
APPROVED_V27_SOURCE_MEMBERS = 1836
APPROVED_V27_RUNTIME_MEMBERS = 918
APPROVED_V27_RUNTIME_SHA256 = '7fe5a6d4d4b5be5812d1a5febe60fb2a1fc974b9a364d353c71b6172ddf3d772'


# Exact V28 group-display-name successor; preserve all historical literals.
APPROVED_V28_RUNTIME_ADDITIONS = {
    "peaso/analysis/aws_public_ingress.py": "f58f4f100215dd35da15ec177fbfa1b90145a6bf02fbd80afd759374544f06f0",
    "peaso/aws_budget_policy.py": "940a71e4627173e814381a148744a3840c81f60957f5bd2a6032fa4086ba4b69",
    "peaso/aws_waf_logging.py": "f97074cf8e7ecfb00ac1bac45947bdcd628affe294a0465283b1a5a35eb7c8b9",
    "peaso/azure_devops_git_policy.py": "4c195e73eebf742314c3eeafe0d1f95356d58e71e6c2339d8b1b8b8d418e28ed",
    "peaso/azure_sw32_policy.py": "9d9a545dbc9240e29a3389445dcb9f032fd2350db059e38d49a95f0d90d9e3b0",
    "peaso/checks/aws_all_policies.json": "8e1cdcc44749b643d95e4ee223e386a4b4aba609d9e09a0577779cc34daa83bf",
    "peaso/checks/aws_all_policies.py": "46c12e7ef9f8ed1eac29709c720c0b703e71ee7d0ac15c2427c99346747ab9fe",
    "peaso/checks/aws_all_policies_fixtures.json": "f93d3feb539b593561b3cf9878a0f151e5619ab29bb43984e9963e141eee9401",
    "peaso/checks/aws_backup_plan_frequency.py": "0f40ddcace19dded128369f32efad6d72e36a8a95590073beb8cada2d4cff08d",
    "peaso/checks/aws_config_recording.py": "50800c1a5c30aa407d0791d4416cc473ea19c3d03f584a2a4a2cfa694d2eabec",
    "peaso/checks/azure_apim_diagnostics_native.py": "4221d0aa3092bff0bb5eeb11fdf3ecc58687f0899a52523fbfeed412bb4af55b",
    "peaso/checks/azure_apim_native.py": "af1e1903c167c813e1ab8e8a9c7fa2336dc6cb5f9d8757f7beaaf6f481744f6b",
    "peaso/checks/azure_appservice_identity_followup.py": "ca7ffd2dccf77fd8e7b90d31c567cbb48b666300330555242582efe768347463",
    "peaso/checks/azure_easm_native.py": "d75e42848fae6c53b0f9e29fdb5c568325bbf8f2e136a7dcc435c58b1036f94b",
    "peaso/checks/azure_graph_credential_age.py": "ba0b2f87162cbace267cb0d630f05655d59239b287d9e7ae6b4f8744cc30a7b4",
    "peaso/checks/azure_log_profile_retention.py": "ba369f5809f8484310b89079ee0b4c3a5523f561ff03cd349488766cc86837ba",
    "peaso/checks/batch_remaining_aws.py": "197ccf540f23e9373d8db281bf1544d2d2bba793be3738ff214e9a6038d813b2",
    "peaso/checks/batch_remaining_azure.py": "82e39d57beef687761098e206457e5e7f7e25a792fc9fcc8600d809f4737b136",
    "peaso/checks/batch_remaining_azure_vm_storage.py": "11f0353505ec70bb7cbc1f6f72add7ceb664fcbd01d05bd8018b2063dd09babb",
    "peaso/checks/batch_remaining_gcp.py": "4f93aebdb8c4fabb603cc122b7a390bc153abc6039035c4a0e780be708aed870",
    "peaso/checks/batch_remaining_k8s.py": "0f0c92c50a05e92bfd0357767066e4e481c03320c2f582ff10194d8cc25dd578",
    "peaso/checks/bulk_pending.json": "2694ae6e9dd10a05027d34868ff269a08f0c85996948fb9a303e7aa44b86efda",
    "peaso/checks/bulk_pending.py": "41cd15965640293562f1808fd7cc31b85769a3e3a44aa3c5537d119dabd50a11",
    "peaso/checks/central_batch_fixtures.json": "1a226d4af6f26c7216c305d36109226bed11e28051c936cb86f66ffcb5dc734b",
    "peaso/checks/central_native_fixtures.py": "2b9665b5b12e164a76b0982bc055857be82cd72d09eafcb8588bc96ead0503f4",
    "peaso/checks/compliance_new_sw25_native_identity.py": "c347440d7e378900762fc5cf6253203c61325008f6320008919d68cb5c37c53e",
    "peaso/checks/compliance_next_k8s.py": "d0184f0934601aaa4682c07d1f0dbfa1b40fa2e9090ce2ca53ca413471b96dfc",
    "peaso/checks/gcp_audit_native.py": "8c2f5e8d0a76571c06a0e0ade0e83cd54f0814fe525fc9f293968224ba2edf8f",
    "peaso/checks/gcp_audit_rates.json": "5010787138c533e7af252d5cfc2aab641097fb6bc9607d6018a66aac943554d9",
    "peaso/checks/gcp_audit_rates.py": "efb0da440e417b40efbcbf189b0fb62385be3b849136b04de08f61baff8e748c",
    "peaso/checks/gcp_audit_rates_fixtures.json": "2d2fd4319e86bb5f54d0f99b6c28ca0788504e46e822afdaed5d0dfe108a4354",
    "peaso/checks/gcp_data_access.py": "ce997648d524475e848aff41353b99f3add7075eca451146a89a7998da9f51c5",
    "peaso/checks/gcp_psc_dns.py": "4d820199813173d9f32ab2b4a5b4547c449d7f88e69affe1064247cb2df1e599",
    "peaso/checks/gcp_psc_fixtures.json": "d452ed303ed02d23d05e1ef1efce880264002779bf3073dee79239a3764a6138",
    "peaso/checks/k8s_namespace_policy_presence.py": "47f64b995e1f5ca9b6db72ff62a7a4594521448f2a1fbba174d453251698a2b2",
    "peaso/checks/native_storage_compute.json": "e4891a7a99339126380eab0a9e66e855c4b1f7ee8558e79abe64a2471fac7c9d",
    "peaso/checks/native_storage_compute.py": "66bc80ff2d43d7d394defa1180199abf42fb0c40b56ff2696ce5f9733f1de318",
    "peaso/checks/native_storage_compute_fixtures.json": "815860e018a22d38bf666b17a981d28993bea720567d369e28e1d26b1339f274",
    "peaso/checks/next20_aws.py": "8b5bedb10366b2708e445bc0068f41a1e6aea0bf8fe7f20c81029dfce665e569",
    "peaso/checks/next_group_appservice_fixtures.py": "1f461d725797b538f7e6550f7aa70217b029e6ec846a3a9e7ce5e6531057c3be",
    "peaso/checks/next_group_aws_fixtures.py": "0076893df5c07f55cd2244d98afaa4516e56f5a1a7bb4f3c5bf7ee1874adb90a",
    "peaso/checks/next_group_azure_fixtures.py": "274822bd1753bef38af173b6be01774abba8ab1bb6b0a0fe3d76638b2e0da249",
    "peaso/checks/next_group_easm_fixtures.py": "3162d5c0deeb1122ddddb06a82793167366dc71f17983547365791854f0406a8",
    "peaso/checks/post_dfaf_aws.py": "301493a4bd3ee865d3d830807a9d6481ef5e3910b3e8ba99c26b57b487cd0fce",
    "peaso/checks/post_dfaf_aws_specs.py": "4f2410348d731c2c76c3db79b0b2b0aebedebf874ce9044f9dccb612622d2476",
    "peaso/checks/post_dfaf_azure.py": "c00e5f758009f1929eb97f83a096706874b97fc6e2269dea8ccdab06c8e5640e",
    "peaso/checks/remaining_aws_gcp_native.py": "ded9f2aa60b562cc3db565a091434ad182e8ae8635d4b128549b827a39a6f5f9",
    "peaso/checks/wafv2_basic.py": "b300d867db2803793f56b23dbd2c51751435236428267e12e23c398c99316437",
    "peaso/collectors/aws_all_policies.py": "4be1797ead0658962fe64ddd17ac4437df49b3612e0d8746cf7315734e4a9886",
    "peaso/collectors/aws_apigateway_native.py": "bf5c20ba91a679dcd303579b89ef6f9fd3b96e4664254716b5c98e4367e854a5",
    "peaso/collectors/aws_budget_stop_native.py": "8001bc5895828ec8fc38baeda5a9e5f863866a3d32889e7b1804a06338dbba44",
    "peaso/collectors/aws_bulk_inventory.py": "45aa2a3bce8581cf8bf1046e882eb701a03b61367378fdcee70d3b5ef415230d",
    "peaso/collectors/aws_cloudtrail_delivery_native.py": "bf7348354a77a39d2271f1b022d1620b0e7f7d3b68dc021cf06f86aceb369393",
    "peaso/collectors/aws_codebuild_redaction.py": "d3f487ca28fae5563b2cd5839f760dbd742e859388ab0646dc762d5c7826f18d",
    "peaso/collectors/aws_codecommit_review_native.py": "8700c0be3a48fe2d6a72ed29390d5938ce2b901ecfccfb829a94cc9618249e93",
    "peaso/collectors/aws_controltower_native.py": "4cc022c9698532209a75fe280851e291964efb9244ff70ef607bdda685753999",
    "peaso/collectors/aws_cost_policy.py": "1e53fa329bbaeba16b0548bbd6b912ebbadd4a22c1e1732c24665d68b36fc42d",
    "peaso/collectors/aws_ecr_artifacts_native.py": "3beaa9b23013e715902d29d76064c0bcf205c569b02b38f74d2c7ba0cd66e99c",
    "peaso/collectors/aws_facts_v4_holds.py": "1e2cec696c00e1b002111fa1c4e3d17f41585c115db0808e11162705e1cd9356",
    "peaso/collectors/aws_identity_center_native.py": "60592e3ff76ae393ed43d89f1554fb2da1f0daaf836b5e640c8760e8b0a66d3e",
    "peaso/collectors/aws_identity_metrics_native.py": "f96984d474dcb07f03ddc4a998d5c0ae32563677f0eaa2a02384bc79dafadfc0",
    "peaso/collectors/aws_kms_enclave_native.py": "589935d3ebd9bd13c1d58adf304daf78359374c8e78f88549f2db83c3f32d069",
    "peaso/collectors/aws_launch_configuration_redaction.py": "09f0a76060934ef47924c1cf747079ca0dba6a82e5803686155067516eb951b5",
    "peaso/collectors/aws_macie_coverage_native.py": "5650b5a3e15a654cda7d2e5dcd2974124c6a0a711e1798202bf11e4ca5e65a7b",
    "peaso/collectors/aws_operational_groups_native.py": "06108480e7c2f75ca30343ea5ca4fe3dc0a3fa92d8dee9cf2ccf8f47150f2456",
    "peaso/collectors/aws_organizations_native.py": "f331e1cd6fa1a496bcfffb0a3eeb93d72004028dec1bc72d63db731dd1feae5a",
    "peaso/collectors/aws_policy.py": "a3003f6c3930bd5f23523cc6128192ee6a22891a47035df922e34498ada0429d",
    "peaso/collectors/aws_priority_tags_native.py": "c1f67bb05912bb0e60303989dc722093d379e93d56796c48ca81dc40ddb353f1",
    "peaso/collectors/aws_public_ingress_native.py": "3dda8ed8ffdb9e3b650ffe50bc6da24d52f57e53c908357ef9bc4a2094309b7e",
    "peaso/collectors/aws_region_data_native.py": "e2440353ea5b31d50ce281e049dd4586e05710763c0b0b7ee8c737b79ae9f9e1",
    "peaso/collectors/aws_region_shield_native.py": "08f2a665106e9e66b799fa75946739b57c01076fed23b882f3f63651b652d471",
    "peaso/collectors/aws_resolver_firewall_native.py": "ca0970fa271384e2167db3cb2ed855cceda0dd834348671654597ec3d8b19a52",
    "peaso/collectors/aws_resource_policy_native.py": "b0c7b4081f965bab4ece4de503fac0de65038c6c98df010f877f745ce940998e",
    "peaso/collectors/aws_s3_backup_native.py": "48654c9bb7c4fcbb5ee52c8035cb0fd29d0d8a716b358e9d8399a4595aad3ffd",
    "peaso/collectors/aws_sagemaker_clarify_native.py": "f6695218f1c6f5dd060b7871b516d975fb54e1560aba5a413698b589aaa113af",
    "peaso/collectors/aws_ssm_inventory_events_native.py": "c495038efa6858ee77d75a1090fe357998076455da3c1c4bebc105fd9e00370a",
    "peaso/collectors/aws_transport_native.py": "ab038928f14c3136df4c9425856e57b2b199afa24085d739b4f8526a225e53e6",
    "peaso/collectors/aws_waf_inventory_native.py": "10bcdf16a32dc1edd69ef751dd2a1427dbeb5a1c10cf91fd605b97c6dd2ada20",
    "peaso/collectors/azure_access_reviews_native.py": "11647049e6d04b1e9985ec51f9e890c02b0e8da66f67391979628a60e772bd6f",
    "peaso/collectors/azure_aks_workloads_native.py": "d05435f71f90ba4c9861a2049d3e04d7465772bbdc519c14d4bba157d9e0a4b4",
    "peaso/collectors/azure_apim_diagnostics_native.py": "d5fe9f4b821fa80c1bed677df063971d6ac61278d315b93eb24b4a7957f9bc2e",
    "peaso/collectors/azure_apim_native.py": "02b20bffce3dc8efa0c74e027533ee438fb6261fcc0a2d0fdd56648b436c3d1d",
    "peaso/collectors/azure_apim_protocol_policy.py": "49c7572d6f0cad40853dc7be7f2867bd465fc2a656f4145680fb36f22cad011f",
    "peaso/collectors/azure_appservice_identity_followup.py": "d5e135f5973b2909974bfd2bf5cb43c03931e71590e63649da35850a75554aaf",
    "peaso/collectors/azure_arm_metadata_native.py": "f244de81694d42e796544d520ab3d631faa58e115f9622ad61d039fe12c4fa50",
    "peaso/collectors/azure_assessment_criteria_native.py": "42ceb16728f8bde78874d38037c835085c1dba1770c3dab84c6b2a03cc268d1a",
    "peaso/collectors/azure_conditional_access_native.py": "9b69def3b75a31ab41eaeac2757b85fe9d3d4f505f948043cd8491cd0ebabe8a",
    "peaso/collectors/azure_database_native.py": "2b5c6850d33f9a74fc6bf46f92bab1330f1d4ae21e92a6461357cde837c3f683",
    "peaso/collectors/azure_databricks_native.py": "3c6c56e700376316c7f711f7dc4981b4f02ec145bacf6553d9163326f7e64359",
    "peaso/collectors/azure_defender_network_native.py": "ce70e05680d870ba145baed0701471783c721446a1781474f70c3b0bbb1985da",
    "peaso/collectors/azure_detection_telemetry.py": "d0c1e354f8c5fbfd8504667dd0268f3e685444e6aa1a5507abb336d16817758d",
    "peaso/collectors/azure_devops_git_native.py": "7b01f9f26acae14414d33b42095caad14adaf4644b3706fde2120e170b4c2c63",
    "peaso/collectors/azure_devops_pipeline_native.py": "e1935267538ee628145317772fd10ed4fa120819a88ebc70f0bf3e22adad54f2",
    "peaso/collectors/azure_disclosure_native.py": "1038ca6d576f89c6d9bced0182239b140f4dbe51e7aafb60a1b569634f15426d",
    "peaso/collectors/azure_entra_diagnostics_native.py": "3ba791cd52c3e5b2fb78bcb12fced683402d552f8a8ff3bd13fec65fc941636f",
    "peaso/collectors/azure_frontdoor_native.py": "f020ec13c4a8ddd12c8e276f24538cb7c698f707b1f4eaebb52ce14e3305f675",
    "peaso/collectors/azure_function_limits_native.py": "cd1b13b2fd9d7983e1846fe651507a26422f4ab9cf7dd9866cdf9c50f28fc7e9",
    "peaso/collectors/azure_guest_configuration_native.py": "d534f80d292e158eba0caad3629b1d0fe54987c2cdbaf7e33a56a672f6159a54",
    "peaso/collectors/azure_guest_policy.py": "55f32bdb4d9e25f6603321fcb8a0877e07bce003ea7f2b02ea080401c2905c4d",
    "peaso/collectors/azure_guest_reports.py": "3b0b5a169a73bd97975b8968fed0b2e13b935ac8bc5f297ed791a128f8e74e4b",
    "peaso/collectors/azure_identity_intune_native.py": "02b0b6d133a2f0d30cb2e30a99d6d3d4feef78231eb61e680acd02987f0896fc",
    "peaso/collectors/azure_iot_policy_native.py": "5daa1c505286ba57c4f1ec016f54f5713b138d3b45cfd1c5fb542ee3ad893468",
    "peaso/collectors/azure_monitor_inventory_native.py": "81bd15cf090e296be7a299da4b7b9e42657c987bbed6afdeb82a0453a90e6127",
    "peaso/collectors/azure_resource_diagnostics_native.py": "36f73fc3665680b2489ab99c24dfee59b5f2afb236323952e7131dea481df0ed",
    "peaso/collectors/azure_resource_logging_policy.py": "2d7174efd2706acf66466e3216d95ec1b81d2af1cf5b1b54a8144246ca25d0ba",
    "peaso/collectors/azure_secret_versions_native.py": "53d8ad1f7599697fab83af4139644c93223f9cdbfc5355e587749e545149120c",
    "peaso/collectors/azure_sentinel_metadata_native.py": "3cc20e96f438c017261006a2e9d04f16cfc2d01224515a9477f73a7872e9896b",
    "peaso/collectors/azure_sql_inventory.py": "43a1549a843593c8e33812f5dfa9091a0e7ab534d895ea3e03e718cf08ec82ae",
    "peaso/collectors/azure_storage_backup_native.py": "249e5916a527ecd0d80378c1a4e769fc3511152f0887a85186bc1285aa473405",
    "peaso/collectors/azure_storage_recovery_metadata_native.py": "658807c10ba59c65ecc7a86bd0cae1d3079d785612b69b829908cc135cb81ca0",
    "peaso/collectors/azure_sw15_policy.py": "66a6ff162aa2727a33c3079cfd2709cbea883ce5bcc2f16407ef111743a5b82d",
    "peaso/collectors/azure_vault_key_versions_native.py": "9f99c8f3327161412f6442c8531a566944a8fd2a4b32919da6cddf5bfdc0b932",
    "peaso/collectors/batch_remaining_azure_vm_storage.py": "44bb52e7d7e9e7290cb302e439e1ada18b3dd278895125c857fd028dffa21053",
    "peaso/collectors/batch_remaining_k8s.py": "8c15aa07719cc9596edb3aa7128c99b8d301ef35269ab860ceeb238bec95bb3e",
    "peaso/collectors/bulk_evidence.json": "c1d173bead561f5777df8e703dd8a0939692202b8f2fe7427e8e6d72457a5744",
    "peaso/collectors/bulk_evidence.py": "fb51c829ddc9ca2c83e7cb54de8e1ebc91c0530a8d7eb47d6083e5ff170e6e09",
    "peaso/collectors/gcp_audit_native.py": "02554f3aa9bf2a4d450455c75c6b7fac5ca2396e1afededd34db42a6ec4179e8",
    "peaso/collectors/gcp_facts_v4_holds.py": "f52b9df380e2e69de33cd39bd99f3fda30cac030a1a583c50660b8b9a083f39f",
    "peaso/collectors/gcp_history.py": "21368065d8d1a46209e88d623bb848fe2e3dcb0e4e4c0e5b01f867b8ecf4e631",
    "peaso/collectors/gcp_kms_effective_native.py": "7d2c1e81afebac5e99d47951c85c24aeb91e1795d3fe233c396d9bac6a30ae01",
    "peaso/collectors/gcp_native_evidence.py": "fdced136c30eca42529c967ba2a59f84068008ee98345a1a7abc2c974ca060e1",
    "peaso/collectors/gcp_os_patch_native.py": "e8d86dbc207104d2dbc59d2c0dd0a558f7d00e7edde5960d2750fa7803a85f58",
    "peaso/collectors/gcp_sbom_native.py": "e4fc4bc0c455146ed580d7ef3406424c8ddca2588ccf5cb7c723b922931902f8",
    "peaso/collectors/gcp_storage_acl_native.py": "9ef114ced31862ed48cc3defc7710623e130fcd6431051174fc44b6d19fa2033",
    "peaso/collectors/k8s_admission_file.py": "fc23c5692f1bc295394cf770312a58a8bb64dc532d2c2d9ad33cfeb8a440795f",
    "peaso/gcp_data_access_policy.py": "03167a5cf56583a9ae4efb08aba2beb24fa0e62fcafded1b6f7f47181cb5d4c7",
    "peaso/gcp_psc_policy.py": "ceb9da0dca6e28d011e9f0d779fe519991bb78ec4e7df9bbba67494306eb0ff1",
    "peaso/gcp_sbom_policy.py": "ef717b7f45ddb6d7abca981b6a871f60d9dde0f1eee442c64ddb342ca60be788",
    "peaso/privesc/azure_disclosure_effects.json": "6caf92a0ffdc59cffecb0c9d047d31bc7c49fe02dd0f19b11f3ec743a670f93e",
    "peaso/privesc/bounded_effects.json": "4ce1a0b29fbf026bbc26166915f87e5fb2c4e6396a8aa37ee91e56ca1840806d",
    "peaso/privesc/bulk_principal_tranche.json": "6cb1c21ba90b1ae08d0e5671efa373c8711d42cdb97d3f9055f84d3a239428a8",
    "peaso/privesc/catalog/aws/bounded-effects-v5.yaml": "d38ce968f6af36e9d5c72a098916978320ebf61653df6e6b2c1916de3fbaf80a",
    "peaso/privesc/catalog/aws/bulk-principal-v6.yaml": "e4e907a900127eec6feaa5bb9527ddb130d52c4895b94fd65acb6e8b0a29c779",
    "peaso/privesc/catalog/aws/exact-principal-v5.yaml": "b198454714e4e530682cea805f5e1db595c9eb7a8057f35b1f8d426f88c2a709",
    "peaso/privesc/catalog/aws/lightsail.yaml": "1645b857297793df9c1f6a69e236cbff5873b65055e4e4056360c693c809a279",
    "peaso/privesc/catalog/azure/app_configuration.yaml": "937a2bbc1a2b42d08ef7d183653e540f7320b672c59d9ed5068a191a3aaca89b",
    "peaso/privesc/catalog/azure/bounded-effects-v5.yaml": "1ca7a8398150cd05f2146e3466be8713481870cdcedfaf8813aad3e41b12a9f4",
    "peaso/privesc/catalog/azure/disclosure-effects-v7.yaml": "00175d020192d57529b305d80b2027dcea8df7b58aac26e0c60fd03196b79d3a",
    "peaso/privesc/catalog/azure/monitor.yaml": "a2cec1047c97588d0537a02e1f5ac06ed091188097b8427369fc8362f715cada",
    "peaso/privesc/catalog/azure/storage-local-v7.yaml": "39fc0f2734331d8d08d356614775095d8b7be97bf343aa240e110c12d2988f9f",
    "peaso/privesc/catalog/azure/storage.yaml": "be4c268b9114175bbf079a4d9c70009392f9fab26afa47ea8100930255b19b15",
    "peaso/privesc/catalog/gcp/aiplatform.yaml": "d32d22ffb8909105cbc49f3fe0704df6ffb8e43494c7c908981d59dd31800c69",
    "peaso/privesc/catalog/gcp/bigtable.yaml": "436131e96ff896df4425319aee3952c6010909dab2b4256302a4367af8e230db",
    "peaso/privesc/catalog/gcp/bounded-effects-v5.yaml": "336a51ee7c3e5411d23c7e6fffd90849a28de2577ce2ccc02ff6e03877da5505",
    "peaso/privesc/catalog/gcp/bulk-principal-v6.yaml": "1998a8787332908d955ab6e8769f315dac4afe80fb2e66b57dc34ad7a916cf25",
    "peaso/privesc/catalog/gcp/dlp.yaml": "a4191890cd5bb94485588a7830567975f59ded4b2043f58331a4e6a60223187d",
    "peaso/privesc/catalog/gcp/exact-principal-v5.yaml": "345e1f41d7baf6f859b65eb6abdf8b6be5bf25781a9b25602ab1481bf1c7ec0b",
    "peaso/privesc/catalog/gcp/parametermanager.yaml": "8273c65df5d117386103e3694b7074ab002487b851706897c63d44300f76acab",
    "peaso/privesc/catalog/gcp/secretmanager.yaml": "7ddb46238daeeba20663d30f5a2f07ab25b26cfd8838895787043a6b28c5b23e",
    "peaso/privesc/catalog/k8s/scoped-credential-v7.yaml": "7c4940f42a1754cd843688fcd903a522cd99ea98491c20a1ef5ed77dd75008a5",
    "peaso/privesc/catalog_versions/bounded-v5-manifest.json": "082451e81fa450830ae5f6835e241dd412a6c30a8b2a0b1172cdbc89b2d71429",
    "peaso/privesc/catalog_versions/bulk-principal-v6-manifest.json": "734401b202895e00ac1b6cb0f1534f77cde4d8e2ba912ca0ee974b1b8ec5035c",
    "peaso/privesc/catalog_versions/disclosure-v7-manifest.json": "91ffe7389d02568cdcdf74a6b08dafa5f665ea07c0c528988127ffc4d2a86c45",
    "peaso/privesc/catalog_versions/legacy-0b3633-delta.json": "40640ad0e7179af395ec37f9456ef7b9d8340e8ab81e9edb7a460769edca258a",
    "peaso/privesc/catalog_versions/principal-v4-manifest.json": "6008acf71acda21408c7039dddff2d7ccaeeaa3aecfc6f31ef5d2cdc5a4ea388",
    "peaso/privesc/effective_permissions/azure_disclosure_effects.py": "554dba11bab6ad0145960f8b594ae58ab165e00c0fbe3fb91c3a4bcfa6ef197f",
    "peaso/privesc/effective_permissions/bounded_evidence.py": "1cd1a44f2d955bb5dc877e404ab09294a3df9b67bb1ff9e867aec1cd0cf212af",
    "peaso/privesc/effective_permissions/credential_evidence.py": "a95078884cd2e1c91e3e729921254844237eaa0444b89bf0cd6afd88d9fcaef3",
    "peaso/privesc/effective_permissions/ec2_profile_association.py": "22f0c201cc7d2b37f26c26e307dca33ce55e5716c5f6bea64affc78aff78e039",
    "peaso/privesc/effective_permissions/principal_evidence.py": "2c4bd5e2e2fa33db271b963387787003a42e1c741dad27b22e7b37f23fc2f7e3",
    "peaso/privesc/effective_permissions/storage_local_identity.py": "7671720b0780e47c583e0877888235406c220e64b937d361edb555f3300df7d0",
    "peaso/privesc/exact_principal_tranche.json": "c02921ad9a694b07415ffd5de0c97a0e8b0f34b73bbf40dc3b78e149e29b4af6",
    "peaso/privesc/versioned_catalog.py": "fd6831825507de22b7155909b3bdc1f1e391244b85a180b7764e22f7974f6666",
    "peaso/rulepacks/remediation_compliance_batch_remaining_aws.json": "ebe28d47a1880fa09acc7f42022a1e199ac9c27992049d2ca074670b41d6d490",
    "peaso/rulepacks/remediation_compliance_batch_remaining_azure.json": "a8f76c1a53926fa6cbbda666e80108b494d7933d77d9d39f6d1226f02937b91a",
    "peaso/rulepacks/remediation_compliance_batch_remaining_gcp.json": "5d618ab15fa5cd624e2b2559ab9f308dabe5fb2fa255d33ff664386c5e97b71c",
    "peaso/rulepacks/remediation_compliance_batch_remaining_k8s.json": "5485734fd0351e2dc8f6862b65472164e05df802e32d9c08d061826d1f1492ca",
    "peaso/server/native_policy_validation.py": "a6f62b76f0b68820faa59b29277164b45f4ec04a43ff93c43873273613d7298e"
}
APPROVED_V28_SOURCE_MEMBERS = 1836
APPROVED_V28_RUNTIME_MEMBERS = 918
APPROVED_V28_RUNTIME_SHA256 = '9d5c63b07850c22833710d52507a12e7a897cb44593fa6ffe35506cd269b9a10'


# Exact V29 TLS owner-policy + public DER successor; historical branches immutable.
APPROVED_V29_RUNTIME_ADDITIONS = {
    "peaso/analysis/aws_public_ingress.py": "f58f4f100215dd35da15ec177fbfa1b90145a6bf02fbd80afd759374544f06f0",
    "peaso/aws_budget_policy.py": "940a71e4627173e814381a148744a3840c81f60957f5bd2a6032fa4086ba4b69",
    "peaso/aws_waf_logging.py": "f97074cf8e7ecfb00ac1bac45947bdcd628affe294a0465283b1a5a35eb7c8b9",
    "peaso/azure_devops_git_policy.py": "4c195e73eebf742314c3eeafe0d1f95356d58e71e6c2339d8b1b8b8d418e28ed",
    "peaso/azure_sw32_policy.py": "9d9a545dbc9240e29a3389445dcb9f032fd2350db059e38d49a95f0d90d9e3b0",
    "peaso/azure_tls_owner_policy.py": "7d114ef4f04aafbe1af4e260aab1392712a15de9aca0609b6fc7653a739d0789",
    "peaso/checks/aws_all_policies.json": "8e1cdcc44749b643d95e4ee223e386a4b4aba609d9e09a0577779cc34daa83bf",
    "peaso/checks/aws_all_policies.py": "46c12e7ef9f8ed1eac29709c720c0b703e71ee7d0ac15c2427c99346747ab9fe",
    "peaso/checks/aws_all_policies_fixtures.json": "f93d3feb539b593561b3cf9878a0f151e5619ab29bb43984e9963e141eee9401",
    "peaso/checks/aws_backup_plan_frequency.py": "0f40ddcace19dded128369f32efad6d72e36a8a95590073beb8cada2d4cff08d",
    "peaso/checks/aws_config_recording.py": "50800c1a5c30aa407d0791d4416cc473ea19c3d03f584a2a4a2cfa694d2eabec",
    "peaso/checks/azure_apim_diagnostics_native.py": "4221d0aa3092bff0bb5eeb11fdf3ecc58687f0899a52523fbfeed412bb4af55b",
    "peaso/checks/azure_apim_native.py": "af1e1903c167c813e1ab8e8a9c7fa2336dc6cb5f9d8757f7beaaf6f481744f6b",
    "peaso/checks/azure_appservice_identity_followup.py": "ca7ffd2dccf77fd8e7b90d31c567cbb48b666300330555242582efe768347463",
    "peaso/checks/azure_easm_native.py": "d75e42848fae6c53b0f9e29fdb5c568325bbf8f2e136a7dcc435c58b1036f94b",
    "peaso/checks/azure_graph_credential_age.py": "ba0b2f87162cbace267cb0d630f05655d59239b287d9e7ae6b4f8744cc30a7b4",
    "peaso/checks/azure_log_profile_retention.py": "ba369f5809f8484310b89079ee0b4c3a5523f561ff03cd349488766cc86837ba",
    "peaso/checks/batch_remaining_aws.py": "197ccf540f23e9373d8db281bf1544d2d2bba793be3738ff214e9a6038d813b2",
    "peaso/checks/batch_remaining_azure.py": "82e39d57beef687761098e206457e5e7f7e25a792fc9fcc8600d809f4737b136",
    "peaso/checks/batch_remaining_azure_vm_storage.py": "11f0353505ec70bb7cbc1f6f72add7ceb664fcbd01d05bd8018b2063dd09babb",
    "peaso/checks/batch_remaining_gcp.py": "4f93aebdb8c4fabb603cc122b7a390bc153abc6039035c4a0e780be708aed870",
    "peaso/checks/batch_remaining_k8s.py": "0f0c92c50a05e92bfd0357767066e4e481c03320c2f582ff10194d8cc25dd578",
    "peaso/checks/bulk_pending.json": "2694ae6e9dd10a05027d34868ff269a08f0c85996948fb9a303e7aa44b86efda",
    "peaso/checks/bulk_pending.py": "41cd15965640293562f1808fd7cc31b85769a3e3a44aa3c5537d119dabd50a11",
    "peaso/checks/central_batch_fixtures.json": "1a226d4af6f26c7216c305d36109226bed11e28051c936cb86f66ffcb5dc734b",
    "peaso/checks/central_native_fixtures.py": "2b9665b5b12e164a76b0982bc055857be82cd72d09eafcb8588bc96ead0503f4",
    "peaso/checks/compliance_new_sw25_native_identity.py": "c347440d7e378900762fc5cf6253203c61325008f6320008919d68cb5c37c53e",
    "peaso/checks/compliance_next_k8s.py": "d0184f0934601aaa4682c07d1f0dbfa1b40fa2e9090ce2ca53ca413471b96dfc",
    "peaso/checks/gcp_audit_native.py": "8c2f5e8d0a76571c06a0e0ade0e83cd54f0814fe525fc9f293968224ba2edf8f",
    "peaso/checks/gcp_audit_rates.json": "5010787138c533e7af252d5cfc2aab641097fb6bc9607d6018a66aac943554d9",
    "peaso/checks/gcp_audit_rates.py": "efb0da440e417b40efbcbf189b0fb62385be3b849136b04de08f61baff8e748c",
    "peaso/checks/gcp_audit_rates_fixtures.json": "2d2fd4319e86bb5f54d0f99b6c28ca0788504e46e822afdaed5d0dfe108a4354",
    "peaso/checks/gcp_data_access.py": "ce997648d524475e848aff41353b99f3add7075eca451146a89a7998da9f51c5",
    "peaso/checks/gcp_psc_dns.py": "4d820199813173d9f32ab2b4a5b4547c449d7f88e69affe1064247cb2df1e599",
    "peaso/checks/gcp_psc_fixtures.json": "d452ed303ed02d23d05e1ef1efce880264002779bf3073dee79239a3764a6138",
    "peaso/checks/k8s_namespace_policy_presence.py": "47f64b995e1f5ca9b6db72ff62a7a4594521448f2a1fbba174d453251698a2b2",
    "peaso/checks/native_storage_compute.json": "e4891a7a99339126380eab0a9e66e855c4b1f7ee8558e79abe64a2471fac7c9d",
    "peaso/checks/native_storage_compute.py": "66bc80ff2d43d7d394defa1180199abf42fb0c40b56ff2696ce5f9733f1de318",
    "peaso/checks/native_storage_compute_fixtures.json": "815860e018a22d38bf666b17a981d28993bea720567d369e28e1d26b1339f274",
    "peaso/checks/next20_aws.py": "8b5bedb10366b2708e445bc0068f41a1e6aea0bf8fe7f20c81029dfce665e569",
    "peaso/checks/next_group_appservice_fixtures.py": "1f461d725797b538f7e6550f7aa70217b029e6ec846a3a9e7ce5e6531057c3be",
    "peaso/checks/next_group_aws_fixtures.py": "0076893df5c07f55cd2244d98afaa4516e56f5a1a7bb4f3c5bf7ee1874adb90a",
    "peaso/checks/next_group_azure_fixtures.py": "274822bd1753bef38af173b6be01774abba8ab1bb6b0a0fe3d76638b2e0da249",
    "peaso/checks/next_group_easm_fixtures.py": "3162d5c0deeb1122ddddb06a82793167366dc71f17983547365791854f0406a8",
    "peaso/checks/post_dfaf_aws.py": "301493a4bd3ee865d3d830807a9d6481ef5e3910b3e8ba99c26b57b487cd0fce",
    "peaso/checks/post_dfaf_aws_specs.py": "4f2410348d731c2c76c3db79b0b2b0aebedebf874ce9044f9dccb612622d2476",
    "peaso/checks/post_dfaf_azure.py": "c00e5f758009f1929eb97f83a096706874b97fc6e2269dea8ccdab06c8e5640e",
    "peaso/checks/remaining_aws_gcp_native.py": "ded9f2aa60b562cc3db565a091434ad182e8ae8635d4b128549b827a39a6f5f9",
    "peaso/checks/wafv2_basic.py": "b300d867db2803793f56b23dbd2c51751435236428267e12e23c398c99316437",
    "peaso/collectors/aws_all_policies.py": "4be1797ead0658962fe64ddd17ac4437df49b3612e0d8746cf7315734e4a9886",
    "peaso/collectors/aws_apigateway_native.py": "bf5c20ba91a679dcd303579b89ef6f9fd3b96e4664254716b5c98e4367e854a5",
    "peaso/collectors/aws_budget_stop_native.py": "8001bc5895828ec8fc38baeda5a9e5f863866a3d32889e7b1804a06338dbba44",
    "peaso/collectors/aws_bulk_inventory.py": "45aa2a3bce8581cf8bf1046e882eb701a03b61367378fdcee70d3b5ef415230d",
    "peaso/collectors/aws_cloudtrail_delivery_native.py": "bf7348354a77a39d2271f1b022d1620b0e7f7d3b68dc021cf06f86aceb369393",
    "peaso/collectors/aws_codebuild_redaction.py": "d3f487ca28fae5563b2cd5839f760dbd742e859388ab0646dc762d5c7826f18d",
    "peaso/collectors/aws_codecommit_review_native.py": "8700c0be3a48fe2d6a72ed29390d5938ce2b901ecfccfb829a94cc9618249e93",
    "peaso/collectors/aws_controltower_native.py": "4cc022c9698532209a75fe280851e291964efb9244ff70ef607bdda685753999",
    "peaso/collectors/aws_cost_policy.py": "1e53fa329bbaeba16b0548bbd6b912ebbadd4a22c1e1732c24665d68b36fc42d",
    "peaso/collectors/aws_ecr_artifacts_native.py": "3beaa9b23013e715902d29d76064c0bcf205c569b02b38f74d2c7ba0cd66e99c",
    "peaso/collectors/aws_facts_v4_holds.py": "1e2cec696c00e1b002111fa1c4e3d17f41585c115db0808e11162705e1cd9356",
    "peaso/collectors/aws_identity_center_native.py": "60592e3ff76ae393ed43d89f1554fb2da1f0daaf836b5e640c8760e8b0a66d3e",
    "peaso/collectors/aws_identity_metrics_native.py": "f96984d474dcb07f03ddc4a998d5c0ae32563677f0eaa2a02384bc79dafadfc0",
    "peaso/collectors/aws_kms_enclave_native.py": "589935d3ebd9bd13c1d58adf304daf78359374c8e78f88549f2db83c3f32d069",
    "peaso/collectors/aws_launch_configuration_redaction.py": "09f0a76060934ef47924c1cf747079ca0dba6a82e5803686155067516eb951b5",
    "peaso/collectors/aws_macie_coverage_native.py": "5650b5a3e15a654cda7d2e5dcd2974124c6a0a711e1798202bf11e4ca5e65a7b",
    "peaso/collectors/aws_operational_groups_native.py": "06108480e7c2f75ca30343ea5ca4fe3dc0a3fa92d8dee9cf2ccf8f47150f2456",
    "peaso/collectors/aws_organizations_native.py": "f331e1cd6fa1a496bcfffb0a3eeb93d72004028dec1bc72d63db731dd1feae5a",
    "peaso/collectors/aws_policy.py": "a3003f6c3930bd5f23523cc6128192ee6a22891a47035df922e34498ada0429d",
    "peaso/collectors/aws_priority_tags_native.py": "c1f67bb05912bb0e60303989dc722093d379e93d56796c48ca81dc40ddb353f1",
    "peaso/collectors/aws_public_ingress_native.py": "3dda8ed8ffdb9e3b650ffe50bc6da24d52f57e53c908357ef9bc4a2094309b7e",
    "peaso/collectors/aws_region_data_native.py": "e2440353ea5b31d50ce281e049dd4586e05710763c0b0b7ee8c737b79ae9f9e1",
    "peaso/collectors/aws_region_shield_native.py": "08f2a665106e9e66b799fa75946739b57c01076fed23b882f3f63651b652d471",
    "peaso/collectors/aws_resolver_firewall_native.py": "ca0970fa271384e2167db3cb2ed855cceda0dd834348671654597ec3d8b19a52",
    "peaso/collectors/aws_resource_policy_native.py": "b0c7b4081f965bab4ece4de503fac0de65038c6c98df010f877f745ce940998e",
    "peaso/collectors/aws_s3_backup_native.py": "48654c9bb7c4fcbb5ee52c8035cb0fd29d0d8a716b358e9d8399a4595aad3ffd",
    "peaso/collectors/aws_sagemaker_clarify_native.py": "f6695218f1c6f5dd060b7871b516d975fb54e1560aba5a413698b589aaa113af",
    "peaso/collectors/aws_ssm_inventory_events_native.py": "c495038efa6858ee77d75a1090fe357998076455da3c1c4bebc105fd9e00370a",
    "peaso/collectors/aws_transport_native.py": "ab038928f14c3136df4c9425856e57b2b199afa24085d739b4f8526a225e53e6",
    "peaso/collectors/aws_waf_inventory_native.py": "10bcdf16a32dc1edd69ef751dd2a1427dbeb5a1c10cf91fd605b97c6dd2ada20",
    "peaso/collectors/azure_access_reviews_native.py": "11647049e6d04b1e9985ec51f9e890c02b0e8da66f67391979628a60e772bd6f",
    "peaso/collectors/azure_aks_workloads_native.py": "d05435f71f90ba4c9861a2049d3e04d7465772bbdc519c14d4bba157d9e0a4b4",
    "peaso/collectors/azure_apim_diagnostics_native.py": "d5fe9f4b821fa80c1bed677df063971d6ac61278d315b93eb24b4a7957f9bc2e",
    "peaso/collectors/azure_apim_native.py": "02b20bffce3dc8efa0c74e027533ee438fb6261fcc0a2d0fdd56648b436c3d1d",
    "peaso/collectors/azure_apim_protocol_policy.py": "49c7572d6f0cad40853dc7be7f2867bd465fc2a656f4145680fb36f22cad011f",
    "peaso/collectors/azure_appservice_identity_followup.py": "d5e135f5973b2909974bfd2bf5cb43c03931e71590e63649da35850a75554aaf",
    "peaso/collectors/azure_arm_metadata_native.py": "f244de81694d42e796544d520ab3d631faa58e115f9622ad61d039fe12c4fa50",
    "peaso/collectors/azure_assessment_criteria_native.py": "42ceb16728f8bde78874d38037c835085c1dba1770c3dab84c6b2a03cc268d1a",
    "peaso/collectors/azure_certificate_issuance_native.py": "659b457f03bb4bf1d2a307a3aeaba6de3da2911e0796a4b3e7a1e8223a79e1f4",
    "peaso/collectors/azure_conditional_access_native.py": "9b69def3b75a31ab41eaeac2757b85fe9d3d4f505f948043cd8491cd0ebabe8a",
    "peaso/collectors/azure_database_native.py": "2b5c6850d33f9a74fc6bf46f92bab1330f1d4ae21e92a6461357cde837c3f683",
    "peaso/collectors/azure_databricks_native.py": "3c6c56e700376316c7f711f7dc4981b4f02ec145bacf6553d9163326f7e64359",
    "peaso/collectors/azure_defender_network_native.py": "ce70e05680d870ba145baed0701471783c721446a1781474f70c3b0bbb1985da",
    "peaso/collectors/azure_detection_telemetry.py": "d0c1e354f8c5fbfd8504667dd0268f3e685444e6aa1a5507abb336d16817758d",
    "peaso/collectors/azure_devops_git_native.py": "7b01f9f26acae14414d33b42095caad14adaf4644b3706fde2120e170b4c2c63",
    "peaso/collectors/azure_devops_pipeline_native.py": "e1935267538ee628145317772fd10ed4fa120819a88ebc70f0bf3e22adad54f2",
    "peaso/collectors/azure_disclosure_native.py": "1038ca6d576f89c6d9bced0182239b140f4dbe51e7aafb60a1b569634f15426d",
    "peaso/collectors/azure_entra_diagnostics_native.py": "3ba791cd52c3e5b2fb78bcb12fced683402d552f8a8ff3bd13fec65fc941636f",
    "peaso/collectors/azure_frontdoor_native.py": "f020ec13c4a8ddd12c8e276f24538cb7c698f707b1f4eaebb52ce14e3305f675",
    "peaso/collectors/azure_function_limits_native.py": "cd1b13b2fd9d7983e1846fe651507a26422f4ab9cf7dd9866cdf9c50f28fc7e9",
    "peaso/collectors/azure_guest_configuration_native.py": "d534f80d292e158eba0caad3629b1d0fe54987c2cdbaf7e33a56a672f6159a54",
    "peaso/collectors/azure_guest_policy.py": "55f32bdb4d9e25f6603321fcb8a0877e07bce003ea7f2b02ea080401c2905c4d",
    "peaso/collectors/azure_guest_reports.py": "3b0b5a169a73bd97975b8968fed0b2e13b935ac8bc5f297ed791a128f8e74e4b",
    "peaso/collectors/azure_identity_intune_native.py": "02b0b6d133a2f0d30cb2e30a99d6d3d4feef78231eb61e680acd02987f0896fc",
    "peaso/collectors/azure_iot_policy_native.py": "5daa1c505286ba57c4f1ec016f54f5713b138d3b45cfd1c5fb542ee3ad893468",
    "peaso/collectors/azure_monitor_inventory_native.py": "81bd15cf090e296be7a299da4b7b9e42657c987bbed6afdeb82a0453a90e6127",
    "peaso/collectors/azure_resource_diagnostics_native.py": "36f73fc3665680b2489ab99c24dfee59b5f2afb236323952e7131dea481df0ed",
    "peaso/collectors/azure_resource_logging_policy.py": "2d7174efd2706acf66466e3216d95ec1b81d2af1cf5b1b54a8144246ca25d0ba",
    "peaso/collectors/azure_secret_versions_native.py": "53d8ad1f7599697fab83af4139644c93223f9cdbfc5355e587749e545149120c",
    "peaso/collectors/azure_sentinel_metadata_native.py": "3cc20e96f438c017261006a2e9d04f16cfc2d01224515a9477f73a7872e9896b",
    "peaso/collectors/azure_sql_inventory.py": "43a1549a843593c8e33812f5dfa9091a0e7ab534d895ea3e03e718cf08ec82ae",
    "peaso/collectors/azure_storage_backup_native.py": "249e5916a527ecd0d80378c1a4e769fc3511152f0887a85186bc1285aa473405",
    "peaso/collectors/azure_storage_recovery_metadata_native.py": "658807c10ba59c65ecc7a86bd0cae1d3079d785612b69b829908cc135cb81ca0",
    "peaso/collectors/azure_sw15_policy.py": "66a6ff162aa2727a33c3079cfd2709cbea883ce5bcc2f16407ef111743a5b82d",
    "peaso/collectors/azure_vault_key_versions_native.py": "9f99c8f3327161412f6442c8531a566944a8fd2a4b32919da6cddf5bfdc0b932",
    "peaso/collectors/batch_remaining_azure_vm_storage.py": "44bb52e7d7e9e7290cb302e439e1ada18b3dd278895125c857fd028dffa21053",
    "peaso/collectors/batch_remaining_k8s.py": "8c15aa07719cc9596edb3aa7128c99b8d301ef35269ab860ceeb238bec95bb3e",
    "peaso/collectors/bulk_evidence.json": "c1d173bead561f5777df8e703dd8a0939692202b8f2fe7427e8e6d72457a5744",
    "peaso/collectors/bulk_evidence.py": "fb51c829ddc9ca2c83e7cb54de8e1ebc91c0530a8d7eb47d6083e5ff170e6e09",
    "peaso/collectors/gcp_audit_native.py": "02554f3aa9bf2a4d450455c75c6b7fac5ca2396e1afededd34db42a6ec4179e8",
    "peaso/collectors/gcp_facts_v4_holds.py": "f52b9df380e2e69de33cd39bd99f3fda30cac030a1a583c50660b8b9a083f39f",
    "peaso/collectors/gcp_history.py": "21368065d8d1a46209e88d623bb848fe2e3dcb0e4e4c0e5b01f867b8ecf4e631",
    "peaso/collectors/gcp_kms_effective_native.py": "7d2c1e81afebac5e99d47951c85c24aeb91e1795d3fe233c396d9bac6a30ae01",
    "peaso/collectors/gcp_native_evidence.py": "fdced136c30eca42529c967ba2a59f84068008ee98345a1a7abc2c974ca060e1",
    "peaso/collectors/gcp_os_patch_native.py": "e8d86dbc207104d2dbc59d2c0dd0a558f7d00e7edde5960d2750fa7803a85f58",
    "peaso/collectors/gcp_sbom_native.py": "e4fc4bc0c455146ed580d7ef3406424c8ddca2588ccf5cb7c723b922931902f8",
    "peaso/collectors/gcp_storage_acl_native.py": "9ef114ced31862ed48cc3defc7710623e130fcd6431051174fc44b6d19fa2033",
    "peaso/collectors/k8s_admission_file.py": "fc23c5692f1bc295394cf770312a58a8bb64dc532d2c2d9ad33cfeb8a440795f",
    "peaso/gcp_data_access_policy.py": "03167a5cf56583a9ae4efb08aba2beb24fa0e62fcafded1b6f7f47181cb5d4c7",
    "peaso/gcp_psc_policy.py": "ceb9da0dca6e28d011e9f0d779fe519991bb78ec4e7df9bbba67494306eb0ff1",
    "peaso/gcp_sbom_policy.py": "ef717b7f45ddb6d7abca981b6a871f60d9dde0f1eee442c64ddb342ca60be788",
    "peaso/privesc/azure_disclosure_effects.json": "6caf92a0ffdc59cffecb0c9d047d31bc7c49fe02dd0f19b11f3ec743a670f93e",
    "peaso/privesc/bounded_effects.json": "4ce1a0b29fbf026bbc26166915f87e5fb2c4e6396a8aa37ee91e56ca1840806d",
    "peaso/privesc/bulk_principal_tranche.json": "6cb1c21ba90b1ae08d0e5671efa373c8711d42cdb97d3f9055f84d3a239428a8",
    "peaso/privesc/catalog/aws/bounded-effects-v5.yaml": "d38ce968f6af36e9d5c72a098916978320ebf61653df6e6b2c1916de3fbaf80a",
    "peaso/privesc/catalog/aws/bulk-principal-v6.yaml": "e4e907a900127eec6feaa5bb9527ddb130d52c4895b94fd65acb6e8b0a29c779",
    "peaso/privesc/catalog/aws/exact-principal-v5.yaml": "b198454714e4e530682cea805f5e1db595c9eb7a8057f35b1f8d426f88c2a709",
    "peaso/privesc/catalog/aws/lightsail.yaml": "1645b857297793df9c1f6a69e236cbff5873b65055e4e4056360c693c809a279",
    "peaso/privesc/catalog/azure/app_configuration.yaml": "937a2bbc1a2b42d08ef7d183653e540f7320b672c59d9ed5068a191a3aaca89b",
    "peaso/privesc/catalog/azure/bounded-effects-v5.yaml": "1ca7a8398150cd05f2146e3466be8713481870cdcedfaf8813aad3e41b12a9f4",
    "peaso/privesc/catalog/azure/disclosure-effects-v7.yaml": "00175d020192d57529b305d80b2027dcea8df7b58aac26e0c60fd03196b79d3a",
    "peaso/privesc/catalog/azure/monitor.yaml": "a2cec1047c97588d0537a02e1f5ac06ed091188097b8427369fc8362f715cada",
    "peaso/privesc/catalog/azure/storage-local-v7.yaml": "39fc0f2734331d8d08d356614775095d8b7be97bf343aa240e110c12d2988f9f",
    "peaso/privesc/catalog/azure/storage.yaml": "be4c268b9114175bbf079a4d9c70009392f9fab26afa47ea8100930255b19b15",
    "peaso/privesc/catalog/gcp/aiplatform.yaml": "d32d22ffb8909105cbc49f3fe0704df6ffb8e43494c7c908981d59dd31800c69",
    "peaso/privesc/catalog/gcp/bigtable.yaml": "436131e96ff896df4425319aee3952c6010909dab2b4256302a4367af8e230db",
    "peaso/privesc/catalog/gcp/bounded-effects-v5.yaml": "336a51ee7c3e5411d23c7e6fffd90849a28de2577ce2ccc02ff6e03877da5505",
    "peaso/privesc/catalog/gcp/bulk-principal-v6.yaml": "1998a8787332908d955ab6e8769f315dac4afe80fb2e66b57dc34ad7a916cf25",
    "peaso/privesc/catalog/gcp/dlp.yaml": "a4191890cd5bb94485588a7830567975f59ded4b2043f58331a4e6a60223187d",
    "peaso/privesc/catalog/gcp/exact-principal-v5.yaml": "345e1f41d7baf6f859b65eb6abdf8b6be5bf25781a9b25602ab1481bf1c7ec0b",
    "peaso/privesc/catalog/gcp/parametermanager.yaml": "8273c65df5d117386103e3694b7074ab002487b851706897c63d44300f76acab",
    "peaso/privesc/catalog/gcp/secretmanager.yaml": "7ddb46238daeeba20663d30f5a2f07ab25b26cfd8838895787043a6b28c5b23e",
    "peaso/privesc/catalog/k8s/scoped-credential-v7.yaml": "7c4940f42a1754cd843688fcd903a522cd99ea98491c20a1ef5ed77dd75008a5",
    "peaso/privesc/catalog_versions/bounded-v5-manifest.json": "082451e81fa450830ae5f6835e241dd412a6c30a8b2a0b1172cdbc89b2d71429",
    "peaso/privesc/catalog_versions/bulk-principal-v6-manifest.json": "734401b202895e00ac1b6cb0f1534f77cde4d8e2ba912ca0ee974b1b8ec5035c",
    "peaso/privesc/catalog_versions/disclosure-v7-manifest.json": "91ffe7389d02568cdcdf74a6b08dafa5f665ea07c0c528988127ffc4d2a86c45",
    "peaso/privesc/catalog_versions/legacy-0b3633-delta.json": "40640ad0e7179af395ec37f9456ef7b9d8340e8ab81e9edb7a460769edca258a",
    "peaso/privesc/catalog_versions/principal-v4-manifest.json": "6008acf71acda21408c7039dddff2d7ccaeeaa3aecfc6f31ef5d2cdc5a4ea388",
    "peaso/privesc/effective_permissions/azure_disclosure_effects.py": "554dba11bab6ad0145960f8b594ae58ab165e00c0fbe3fb91c3a4bcfa6ef197f",
    "peaso/privesc/effective_permissions/bounded_evidence.py": "1cd1a44f2d955bb5dc877e404ab09294a3df9b67bb1ff9e867aec1cd0cf212af",
    "peaso/privesc/effective_permissions/credential_evidence.py": "a95078884cd2e1c91e3e729921254844237eaa0444b89bf0cd6afd88d9fcaef3",
    "peaso/privesc/effective_permissions/ec2_profile_association.py": "22f0c201cc7d2b37f26c26e307dca33ce55e5716c5f6bea64affc78aff78e039",
    "peaso/privesc/effective_permissions/principal_evidence.py": "2c4bd5e2e2fa33db271b963387787003a42e1c741dad27b22e7b37f23fc2f7e3",
    "peaso/privesc/effective_permissions/storage_local_identity.py": "7671720b0780e47c583e0877888235406c220e64b937d361edb555f3300df7d0",
    "peaso/privesc/exact_principal_tranche.json": "c02921ad9a694b07415ffd5de0c97a0e8b0f34b73bbf40dc3b78e149e29b4af6",
    "peaso/privesc/versioned_catalog.py": "fd6831825507de22b7155909b3bdc1f1e391244b85a180b7764e22f7974f6666",
    "peaso/rulepacks/remediation_compliance_batch_remaining_aws.json": "ebe28d47a1880fa09acc7f42022a1e199ac9c27992049d2ca074670b41d6d490",
    "peaso/rulepacks/remediation_compliance_batch_remaining_azure.json": "a8f76c1a53926fa6cbbda666e80108b494d7933d77d9d39f6d1226f02937b91a",
    "peaso/rulepacks/remediation_compliance_batch_remaining_gcp.json": "5d618ab15fa5cd624e2b2559ab9f308dabe5fb2fa255d33ff664386c5e97b71c",
    "peaso/rulepacks/remediation_compliance_batch_remaining_k8s.json": "5485734fd0351e2dc8f6862b65472164e05df802e32d9c08d061826d1f1492ca",
    "peaso/server/native_policy_validation.py": "a6f62b76f0b68820faa59b29277164b45f4ec04a43ff93c43873273613d7298e"
}
APPROVED_V29_SOURCE_MEMBERS = 1843
APPROVED_V29_RUNTIME_MEMBERS = 920
APPROVED_V29_RUNTIME_SHA256 = 'af5d1e4d3d3fea117113e7c01b7f3ebf7b2997c98a95a2da7745901bab320175'


# Exact V30 Lightsail plus mandatory provider read-only successor; historical branches immutable.
APPROVED_V30_RUNTIME_ADDITIONS = {
    "peaso/analysis/aws_public_ingress.py": "f58f4f100215dd35da15ec177fbfa1b90145a6bf02fbd80afd759374544f06f0",
    "peaso/aws_budget_policy.py": "940a71e4627173e814381a148744a3840c81f60957f5bd2a6032fa4086ba4b69",
    "peaso/aws_lightsail_owner_policy.py": "643e73ec15ea77fcd99d27d7098540cac8a1b854393574ee379d7737af9b8996",
    "peaso/aws_waf_logging.py": "f97074cf8e7ecfb00ac1bac45947bdcd628affe294a0465283b1a5a35eb7c8b9",
    "peaso/azure_devops_git_policy.py": "4c195e73eebf742314c3eeafe0d1f95356d58e71e6c2339d8b1b8b8d418e28ed",
    "peaso/azure_sw32_policy.py": "9d9a545dbc9240e29a3389445dcb9f032fd2350db059e38d49a95f0d90d9e3b0",
    "peaso/azure_tls_owner_policy.py": "7d114ef4f04aafbe1af4e260aab1392712a15de9aca0609b6fc7653a739d0789",
    "peaso/checks/aws_all_policies.json": "8e1cdcc44749b643d95e4ee223e386a4b4aba609d9e09a0577779cc34daa83bf",
    "peaso/checks/aws_all_policies.py": "46c12e7ef9f8ed1eac29709c720c0b703e71ee7d0ac15c2427c99346747ab9fe",
    "peaso/checks/aws_all_policies_fixtures.json": "f93d3feb539b593561b3cf9878a0f151e5619ab29bb43984e9963e141eee9401",
    "peaso/checks/aws_backup_plan_frequency.py": "0f40ddcace19dded128369f32efad6d72e36a8a95590073beb8cada2d4cff08d",
    "peaso/checks/aws_config_recording.py": "50800c1a5c30aa407d0791d4416cc473ea19c3d03f584a2a4a2cfa694d2eabec",
    "peaso/checks/azure_apim_diagnostics_native.py": "4221d0aa3092bff0bb5eeb11fdf3ecc58687f0899a52523fbfeed412bb4af55b",
    "peaso/checks/azure_apim_native.py": "af1e1903c167c813e1ab8e8a9c7fa2336dc6cb5f9d8757f7beaaf6f481744f6b",
    "peaso/checks/azure_appservice_identity_followup.py": "ca7ffd2dccf77fd8e7b90d31c567cbb48b666300330555242582efe768347463",
    "peaso/checks/azure_easm_native.py": "d75e42848fae6c53b0f9e29fdb5c568325bbf8f2e136a7dcc435c58b1036f94b",
    "peaso/checks/azure_graph_credential_age.py": "ba0b2f87162cbace267cb0d630f05655d59239b287d9e7ae6b4f8744cc30a7b4",
    "peaso/checks/azure_log_profile_retention.py": "ba369f5809f8484310b89079ee0b4c3a5523f561ff03cd349488766cc86837ba",
    "peaso/checks/batch_remaining_aws.py": "197ccf540f23e9373d8db281bf1544d2d2bba793be3738ff214e9a6038d813b2",
    "peaso/checks/batch_remaining_azure.py": "82e39d57beef687761098e206457e5e7f7e25a792fc9fcc8600d809f4737b136",
    "peaso/checks/batch_remaining_azure_vm_storage.py": "11f0353505ec70bb7cbc1f6f72add7ceb664fcbd01d05bd8018b2063dd09babb",
    "peaso/checks/batch_remaining_gcp.py": "4f93aebdb8c4fabb603cc122b7a390bc153abc6039035c4a0e780be708aed870",
    "peaso/checks/batch_remaining_k8s.py": "0f0c92c50a05e92bfd0357767066e4e481c03320c2f582ff10194d8cc25dd578",
    "peaso/checks/bulk_pending.json": "2694ae6e9dd10a05027d34868ff269a08f0c85996948fb9a303e7aa44b86efda",
    "peaso/checks/bulk_pending.py": "41cd15965640293562f1808fd7cc31b85769a3e3a44aa3c5537d119dabd50a11",
    "peaso/checks/central_batch_fixtures.json": "1a226d4af6f26c7216c305d36109226bed11e28051c936cb86f66ffcb5dc734b",
    "peaso/checks/central_native_fixtures.py": "2b9665b5b12e164a76b0982bc055857be82cd72d09eafcb8588bc96ead0503f4",
    "peaso/checks/compliance_new_sw25_native_identity.py": "c347440d7e378900762fc5cf6253203c61325008f6320008919d68cb5c37c53e",
    "peaso/checks/compliance_next_k8s.py": "d0184f0934601aaa4682c07d1f0dbfa1b40fa2e9090ce2ca53ca413471b96dfc",
    "peaso/checks/gcp_audit_native.py": "8c2f5e8d0a76571c06a0e0ade0e83cd54f0814fe525fc9f293968224ba2edf8f",
    "peaso/checks/gcp_audit_rates.json": "5010787138c533e7af252d5cfc2aab641097fb6bc9607d6018a66aac943554d9",
    "peaso/checks/gcp_audit_rates.py": "efb0da440e417b40efbcbf189b0fb62385be3b849136b04de08f61baff8e748c",
    "peaso/checks/gcp_audit_rates_fixtures.json": "2d2fd4319e86bb5f54d0f99b6c28ca0788504e46e822afdaed5d0dfe108a4354",
    "peaso/checks/gcp_data_access.py": "ce997648d524475e848aff41353b99f3add7075eca451146a89a7998da9f51c5",
    "peaso/checks/gcp_psc_dns.py": "4d820199813173d9f32ab2b4a5b4547c449d7f88e69affe1064247cb2df1e599",
    "peaso/checks/gcp_psc_fixtures.json": "d452ed303ed02d23d05e1ef1efce880264002779bf3073dee79239a3764a6138",
    "peaso/checks/k8s_namespace_policy_presence.py": "47f64b995e1f5ca9b6db72ff62a7a4594521448f2a1fbba174d453251698a2b2",
    "peaso/checks/native_storage_compute.json": "e4891a7a99339126380eab0a9e66e855c4b1f7ee8558e79abe64a2471fac7c9d",
    "peaso/checks/native_storage_compute.py": "66bc80ff2d43d7d394defa1180199abf42fb0c40b56ff2696ce5f9733f1de318",
    "peaso/checks/native_storage_compute_fixtures.json": "815860e018a22d38bf666b17a981d28993bea720567d369e28e1d26b1339f274",
    "peaso/checks/next20_aws.py": "8b5bedb10366b2708e445bc0068f41a1e6aea0bf8fe7f20c81029dfce665e569",
    "peaso/checks/next_group_appservice_fixtures.py": "1f461d725797b538f7e6550f7aa70217b029e6ec846a3a9e7ce5e6531057c3be",
    "peaso/checks/next_group_aws_fixtures.py": "0076893df5c07f55cd2244d98afaa4516e56f5a1a7bb4f3c5bf7ee1874adb90a",
    "peaso/checks/next_group_azure_fixtures.py": "274822bd1753bef38af173b6be01774abba8ab1bb6b0a0fe3d76638b2e0da249",
    "peaso/checks/next_group_easm_fixtures.py": "3162d5c0deeb1122ddddb06a82793167366dc71f17983547365791854f0406a8",
    "peaso/checks/post_dfaf_aws.py": "301493a4bd3ee865d3d830807a9d6481ef5e3910b3e8ba99c26b57b487cd0fce",
    "peaso/checks/post_dfaf_aws_specs.py": "4f2410348d731c2c76c3db79b0b2b0aebedebf874ce9044f9dccb612622d2476",
    "peaso/checks/post_dfaf_azure.py": "c00e5f758009f1929eb97f83a096706874b97fc6e2269dea8ccdab06c8e5640e",
    "peaso/checks/remaining_aws_gcp_native.py": "ded9f2aa60b562cc3db565a091434ad182e8ae8635d4b128549b827a39a6f5f9",
    "peaso/checks/wafv2_basic.py": "b300d867db2803793f56b23dbd2c51751435236428267e12e23c398c99316437",
    "peaso/collectors/aws_all_policies.py": "4be1797ead0658962fe64ddd17ac4437df49b3612e0d8746cf7315734e4a9886",
    "peaso/collectors/aws_apigateway_native.py": "bf5c20ba91a679dcd303579b89ef6f9fd3b96e4664254716b5c98e4367e854a5",
    "peaso/collectors/aws_budget_stop_native.py": "8001bc5895828ec8fc38baeda5a9e5f863866a3d32889e7b1804a06338dbba44",
    "peaso/collectors/aws_bulk_inventory.py": "45aa2a3bce8581cf8bf1046e882eb701a03b61367378fdcee70d3b5ef415230d",
    "peaso/collectors/aws_cloudtrail_delivery_native.py": "bf7348354a77a39d2271f1b022d1620b0e7f7d3b68dc021cf06f86aceb369393",
    "peaso/collectors/aws_codebuild_redaction.py": "d3f487ca28fae5563b2cd5839f760dbd742e859388ab0646dc762d5c7826f18d",
    "peaso/collectors/aws_codecommit_review_native.py": "8700c0be3a48fe2d6a72ed29390d5938ce2b901ecfccfb829a94cc9618249e93",
    "peaso/collectors/aws_controltower_native.py": "4cc022c9698532209a75fe280851e291964efb9244ff70ef607bdda685753999",
    "peaso/collectors/aws_cost_policy.py": "1e53fa329bbaeba16b0548bbd6b912ebbadd4a22c1e1732c24665d68b36fc42d",
    "peaso/collectors/aws_ecr_artifacts_native.py": "3beaa9b23013e715902d29d76064c0bcf205c569b02b38f74d2c7ba0cd66e99c",
    "peaso/collectors/aws_facts_v4_holds.py": "1e2cec696c00e1b002111fa1c4e3d17f41585c115db0808e11162705e1cd9356",
    "peaso/collectors/aws_identity_center_native.py": "60592e3ff76ae393ed43d89f1554fb2da1f0daaf836b5e640c8760e8b0a66d3e",
    "peaso/collectors/aws_identity_metrics_native.py": "f96984d474dcb07f03ddc4a998d5c0ae32563677f0eaa2a02384bc79dafadfc0",
    "peaso/collectors/aws_kms_enclave_native.py": "589935d3ebd9bd13c1d58adf304daf78359374c8e78f88549f2db83c3f32d069",
    "peaso/collectors/aws_launch_configuration_redaction.py": "09f0a76060934ef47924c1cf747079ca0dba6a82e5803686155067516eb951b5",
    "peaso/collectors/aws_lightsail_iam_native.py": "6d7c9f00c7a9da7e4c3f8da9e19de2c2d168664b32fa09c9753f3df2fb3d5047",
    "peaso/collectors/aws_macie_coverage_native.py": "5650b5a3e15a654cda7d2e5dcd2974124c6a0a711e1798202bf11e4ca5e65a7b",
    "peaso/collectors/aws_operational_groups_native.py": "06108480e7c2f75ca30343ea5ca4fe3dc0a3fa92d8dee9cf2ccf8f47150f2456",
    "peaso/collectors/aws_organizations_native.py": "f331e1cd6fa1a496bcfffb0a3eeb93d72004028dec1bc72d63db731dd1feae5a",
    "peaso/collectors/aws_policy.py": "a3003f6c3930bd5f23523cc6128192ee6a22891a47035df922e34498ada0429d",
    "peaso/collectors/aws_priority_tags_native.py": "c1f67bb05912bb0e60303989dc722093d379e93d56796c48ca81dc40ddb353f1",
    "peaso/collectors/aws_public_ingress_native.py": "3dda8ed8ffdb9e3b650ffe50bc6da24d52f57e53c908357ef9bc4a2094309b7e",
    "peaso/collectors/aws_region_data_native.py": "e2440353ea5b31d50ce281e049dd4586e05710763c0b0b7ee8c737b79ae9f9e1",
    "peaso/collectors/aws_region_shield_native.py": "08f2a665106e9e66b799fa75946739b57c01076fed23b882f3f63651b652d471",
    "peaso/collectors/aws_resolver_firewall_native.py": "ca0970fa271384e2167db3cb2ed855cceda0dd834348671654597ec3d8b19a52",
    "peaso/collectors/aws_resource_policy_native.py": "b0c7b4081f965bab4ece4de503fac0de65038c6c98df010f877f745ce940998e",
    "peaso/collectors/aws_s3_backup_native.py": "48654c9bb7c4fcbb5ee52c8035cb0fd29d0d8a716b358e9d8399a4595aad3ffd",
    "peaso/collectors/aws_sagemaker_clarify_native.py": "f6695218f1c6f5dd060b7871b516d975fb54e1560aba5a413698b589aaa113af",
    "peaso/collectors/aws_ssm_inventory_events_native.py": "c495038efa6858ee77d75a1090fe357998076455da3c1c4bebc105fd9e00370a",
    "peaso/collectors/aws_transport_native.py": "ab038928f14c3136df4c9425856e57b2b199afa24085d739b4f8526a225e53e6",
    "peaso/collectors/aws_waf_inventory_native.py": "10bcdf16a32dc1edd69ef751dd2a1427dbeb5a1c10cf91fd605b97c6dd2ada20",
    "peaso/collectors/azure_access_reviews_native.py": "11647049e6d04b1e9985ec51f9e890c02b0e8da66f67391979628a60e772bd6f",
    "peaso/collectors/azure_aks_admitted_limits_native.py": "11975f3845f600c6179ccc4305b03fb67a465d8f385d20b7ee3ef20a29aa20c2",
    "peaso/collectors/azure_aks_workloads_native.py": "46ff291ae4b4ad820b6aa4a2205929a6ac2f42fccc2eafad70b8f875a2252e11",
    "peaso/collectors/azure_apim_diagnostics_native.py": "d5fe9f4b821fa80c1bed677df063971d6ac61278d315b93eb24b4a7957f9bc2e",
    "peaso/collectors/azure_apim_native.py": "02b20bffce3dc8efa0c74e027533ee438fb6261fcc0a2d0fdd56648b436c3d1d",
    "peaso/collectors/azure_apim_protocol_policy.py": "49c7572d6f0cad40853dc7be7f2867bd465fc2a656f4145680fb36f22cad011f",
    "peaso/collectors/azure_appservice_identity_followup.py": "d5e135f5973b2909974bfd2bf5cb43c03931e71590e63649da35850a75554aaf",
    "peaso/collectors/azure_arm_metadata_native.py": "f244de81694d42e796544d520ab3d631faa58e115f9622ad61d039fe12c4fa50",
    "peaso/collectors/azure_assessment_criteria_native.py": "42ceb16728f8bde78874d38037c835085c1dba1770c3dab84c6b2a03cc268d1a",
    "peaso/collectors/azure_certificate_issuance_native.py": "659b457f03bb4bf1d2a307a3aeaba6de3da2911e0796a4b3e7a1e8223a79e1f4",
    "peaso/collectors/azure_conditional_access_native.py": "9b69def3b75a31ab41eaeac2757b85fe9d3d4f505f948043cd8491cd0ebabe8a",
    "peaso/collectors/azure_database_native.py": "2b5c6850d33f9a74fc6bf46f92bab1330f1d4ae21e92a6461357cde837c3f683",
    "peaso/collectors/azure_databricks_native.py": "3c6c56e700376316c7f711f7dc4981b4f02ec145bacf6553d9163326f7e64359",
    "peaso/collectors/azure_defender_network_native.py": "ce70e05680d870ba145baed0701471783c721446a1781474f70c3b0bbb1985da",
    "peaso/collectors/azure_detection_telemetry.py": "d0c1e354f8c5fbfd8504667dd0268f3e685444e6aa1a5507abb336d16817758d",
    "peaso/collectors/azure_devops_git_native.py": "7b01f9f26acae14414d33b42095caad14adaf4644b3706fde2120e170b4c2c63",
    "peaso/collectors/azure_devops_pipeline_native.py": "e1935267538ee628145317772fd10ed4fa120819a88ebc70f0bf3e22adad54f2",
    "peaso/collectors/azure_disclosure_native.py": "1038ca6d576f89c6d9bced0182239b140f4dbe51e7aafb60a1b569634f15426d",
    "peaso/collectors/azure_entra_diagnostics_native.py": "3ba791cd52c3e5b2fb78bcb12fced683402d552f8a8ff3bd13fec65fc941636f",
    "peaso/collectors/azure_frontdoor_native.py": "f020ec13c4a8ddd12c8e276f24538cb7c698f707b1f4eaebb52ce14e3305f675",
    "peaso/collectors/azure_function_limits_native.py": "cd1b13b2fd9d7983e1846fe651507a26422f4ab9cf7dd9866cdf9c50f28fc7e9",
    "peaso/collectors/azure_guest_configuration_native.py": "d534f80d292e158eba0caad3629b1d0fe54987c2cdbaf7e33a56a672f6159a54",
    "peaso/collectors/azure_guest_policy.py": "55f32bdb4d9e25f6603321fcb8a0877e07bce003ea7f2b02ea080401c2905c4d",
    "peaso/collectors/azure_guest_reports.py": "3b0b5a169a73bd97975b8968fed0b2e13b935ac8bc5f297ed791a128f8e74e4b",
    "peaso/collectors/azure_identity_intune_native.py": "02b0b6d133a2f0d30cb2e30a99d6d3d4feef78231eb61e680acd02987f0896fc",
    "peaso/collectors/azure_iot_policy_native.py": "5daa1c505286ba57c4f1ec016f54f5713b138d3b45cfd1c5fb542ee3ad893468",
    "peaso/collectors/azure_monitor_inventory_native.py": "81bd15cf090e296be7a299da4b7b9e42657c987bbed6afdeb82a0453a90e6127",
    "peaso/collectors/azure_resource_diagnostics_native.py": "36f73fc3665680b2489ab99c24dfee59b5f2afb236323952e7131dea481df0ed",
    "peaso/collectors/azure_resource_logging_policy.py": "2d7174efd2706acf66466e3216d95ec1b81d2af1cf5b1b54a8144246ca25d0ba",
    "peaso/collectors/azure_secret_versions_native.py": "53d8ad1f7599697fab83af4139644c93223f9cdbfc5355e587749e545149120c",
    "peaso/collectors/azure_sentinel_metadata_native.py": "3cc20e96f438c017261006a2e9d04f16cfc2d01224515a9477f73a7872e9896b",
    "peaso/collectors/azure_sql_inventory.py": "43a1549a843593c8e33812f5dfa9091a0e7ab534d895ea3e03e718cf08ec82ae",
    "peaso/collectors/azure_storage_backup_native.py": "249e5916a527ecd0d80378c1a4e769fc3511152f0887a85186bc1285aa473405",
    "peaso/collectors/azure_storage_recovery_metadata_native.py": "658807c10ba59c65ecc7a86bd0cae1d3079d785612b69b829908cc135cb81ca0",
    "peaso/collectors/azure_sw15_policy.py": "66a6ff162aa2727a33c3079cfd2709cbea883ce5bcc2f16407ef111743a5b82d",
    "peaso/collectors/azure_vault_key_versions_native.py": "9f99c8f3327161412f6442c8531a566944a8fd2a4b32919da6cddf5bfdc0b932",
    "peaso/collectors/batch_remaining_azure_vm_storage.py": "44bb52e7d7e9e7290cb302e439e1ada18b3dd278895125c857fd028dffa21053",
    "peaso/collectors/batch_remaining_k8s.py": "8c15aa07719cc9596edb3aa7128c99b8d301ef35269ab860ceeb238bec95bb3e",
    "peaso/collectors/bulk_evidence.json": "c1d173bead561f5777df8e703dd8a0939692202b8f2fe7427e8e6d72457a5744",
    "peaso/collectors/bulk_evidence.py": "fb51c829ddc9ca2c83e7cb54de8e1ebc91c0530a8d7eb47d6083e5ff170e6e09",
    "peaso/collectors/gcp_audit_native.py": "02554f3aa9bf2a4d450455c75c6b7fac5ca2396e1afededd34db42a6ec4179e8",
    "peaso/collectors/gcp_facts_v4_holds.py": "f52b9df380e2e69de33cd39bd99f3fda30cac030a1a583c50660b8b9a083f39f",
    "peaso/collectors/gcp_history.py": "21368065d8d1a46209e88d623bb848fe2e3dcb0e4e4c0e5b01f867b8ecf4e631",
    "peaso/collectors/gcp_kms_effective_native.py": "7d2c1e81afebac5e99d47951c85c24aeb91e1795d3fe233c396d9bac6a30ae01",
    "peaso/collectors/gcp_native_evidence.py": "fdced136c30eca42529c967ba2a59f84068008ee98345a1a7abc2c974ca060e1",
    "peaso/collectors/gcp_os_patch_native.py": "e8d86dbc207104d2dbc59d2c0dd0a558f7d00e7edde5960d2750fa7803a85f58",
    "peaso/collectors/gcp_sbom_native.py": "e4fc4bc0c455146ed580d7ef3406424c8ddca2588ccf5cb7c723b922931902f8",
    "peaso/collectors/gcp_storage_acl_native.py": "9ef114ced31862ed48cc3defc7710623e130fcd6431051174fc44b6d19fa2033",
    "peaso/collectors/k8s_admission_file.py": "fc23c5692f1bc295394cf770312a58a8bb64dc532d2c2d9ad33cfeb8a440795f",
    "peaso/gcp_data_access_policy.py": "03167a5cf56583a9ae4efb08aba2beb24fa0e62fcafded1b6f7f47181cb5d4c7",
    "peaso/gcp_psc_policy.py": "ceb9da0dca6e28d011e9f0d779fe519991bb78ec4e7df9bbba67494306eb0ff1",
    "peaso/gcp_sbom_policy.py": "ef717b7f45ddb6d7abca981b6a871f60d9dde0f1eee442c64ddb342ca60be788",
    "peaso/privesc/azure_disclosure_effects.json": "6caf92a0ffdc59cffecb0c9d047d31bc7c49fe02dd0f19b11f3ec743a670f93e",
    "peaso/privesc/bounded_effects.json": "4ce1a0b29fbf026bbc26166915f87e5fb2c4e6396a8aa37ee91e56ca1840806d",
    "peaso/privesc/bulk_principal_tranche.json": "6cb1c21ba90b1ae08d0e5671efa373c8711d42cdb97d3f9055f84d3a239428a8",
    "peaso/privesc/catalog/aws/bounded-effects-v5.yaml": "d38ce968f6af36e9d5c72a098916978320ebf61653df6e6b2c1916de3fbaf80a",
    "peaso/privesc/catalog/aws/bulk-principal-v6.yaml": "e4e907a900127eec6feaa5bb9527ddb130d52c4895b94fd65acb6e8b0a29c779",
    "peaso/privesc/catalog/aws/exact-principal-v5.yaml": "b198454714e4e530682cea805f5e1db595c9eb7a8057f35b1f8d426f88c2a709",
    "peaso/privesc/catalog/aws/lightsail.yaml": "1645b857297793df9c1f6a69e236cbff5873b65055e4e4056360c693c809a279",
    "peaso/privesc/catalog/azure/app_configuration.yaml": "937a2bbc1a2b42d08ef7d183653e540f7320b672c59d9ed5068a191a3aaca89b",
    "peaso/privesc/catalog/azure/bounded-effects-v5.yaml": "1ca7a8398150cd05f2146e3466be8713481870cdcedfaf8813aad3e41b12a9f4",
    "peaso/privesc/catalog/azure/disclosure-effects-v7.yaml": "00175d020192d57529b305d80b2027dcea8df7b58aac26e0c60fd03196b79d3a",
    "peaso/privesc/catalog/azure/monitor.yaml": "a2cec1047c97588d0537a02e1f5ac06ed091188097b8427369fc8362f715cada",
    "peaso/privesc/catalog/azure/storage-local-v7.yaml": "39fc0f2734331d8d08d356614775095d8b7be97bf343aa240e110c12d2988f9f",
    "peaso/privesc/catalog/azure/storage.yaml": "be4c268b9114175bbf079a4d9c70009392f9fab26afa47ea8100930255b19b15",
    "peaso/privesc/catalog/gcp/aiplatform.yaml": "d32d22ffb8909105cbc49f3fe0704df6ffb8e43494c7c908981d59dd31800c69",
    "peaso/privesc/catalog/gcp/bigtable.yaml": "436131e96ff896df4425319aee3952c6010909dab2b4256302a4367af8e230db",
    "peaso/privesc/catalog/gcp/bounded-effects-v5.yaml": "336a51ee7c3e5411d23c7e6fffd90849a28de2577ce2ccc02ff6e03877da5505",
    "peaso/privesc/catalog/gcp/bulk-principal-v6.yaml": "1998a8787332908d955ab6e8769f315dac4afe80fb2e66b57dc34ad7a916cf25",
    "peaso/privesc/catalog/gcp/dlp.yaml": "a4191890cd5bb94485588a7830567975f59ded4b2043f58331a4e6a60223187d",
    "peaso/privesc/catalog/gcp/exact-principal-v5.yaml": "345e1f41d7baf6f859b65eb6abdf8b6be5bf25781a9b25602ab1481bf1c7ec0b",
    "peaso/privesc/catalog/gcp/parametermanager.yaml": "8273c65df5d117386103e3694b7074ab002487b851706897c63d44300f76acab",
    "peaso/privesc/catalog/gcp/secretmanager.yaml": "7ddb46238daeeba20663d30f5a2f07ab25b26cfd8838895787043a6b28c5b23e",
    "peaso/privesc/catalog/k8s/scoped-credential-v7.yaml": "7c4940f42a1754cd843688fcd903a522cd99ea98491c20a1ef5ed77dd75008a5",
    "peaso/privesc/catalog_versions/bounded-v5-manifest.json": "082451e81fa450830ae5f6835e241dd412a6c30a8b2a0b1172cdbc89b2d71429",
    "peaso/privesc/catalog_versions/bulk-principal-v6-manifest.json": "734401b202895e00ac1b6cb0f1534f77cde4d8e2ba912ca0ee974b1b8ec5035c",
    "peaso/privesc/catalog_versions/disclosure-v7-manifest.json": "91ffe7389d02568cdcdf74a6b08dafa5f665ea07c0c528988127ffc4d2a86c45",
    "peaso/privesc/catalog_versions/legacy-0b3633-delta.json": "40640ad0e7179af395ec37f9456ef7b9d8340e8ab81e9edb7a460769edca258a",
    "peaso/privesc/catalog_versions/principal-v4-manifest.json": "6008acf71acda21408c7039dddff2d7ccaeeaa3aecfc6f31ef5d2cdc5a4ea388",
    "peaso/privesc/effective_permissions/azure_disclosure_effects.py": "554dba11bab6ad0145960f8b594ae58ab165e00c0fbe3fb91c3a4bcfa6ef197f",
    "peaso/privesc/effective_permissions/bounded_evidence.py": "1cd1a44f2d955bb5dc877e404ab09294a3df9b67bb1ff9e867aec1cd0cf212af",
    "peaso/privesc/effective_permissions/credential_evidence.py": "a95078884cd2e1c91e3e729921254844237eaa0444b89bf0cd6afd88d9fcaef3",
    "peaso/privesc/effective_permissions/ec2_profile_association.py": "22f0c201cc7d2b37f26c26e307dca33ce55e5716c5f6bea64affc78aff78e039",
    "peaso/privesc/effective_permissions/principal_evidence.py": "2c4bd5e2e2fa33db271b963387787003a42e1c741dad27b22e7b37f23fc2f7e3",
    "peaso/privesc/effective_permissions/storage_local_identity.py": "7671720b0780e47c583e0877888235406c220e64b937d361edb555f3300df7d0",
    "peaso/privesc/exact_principal_tranche.json": "c02921ad9a694b07415ffd5de0c97a0e8b0f34b73bbf40dc3b78e149e29b4af6",
    "peaso/privesc/versioned_catalog.py": "fd6831825507de22b7155909b3bdc1f1e391244b85a180b7764e22f7974f6666",
    "peaso/rulepacks/remediation_compliance_batch_remaining_aws.json": "ebe28d47a1880fa09acc7f42022a1e199ac9c27992049d2ca074670b41d6d490",
    "peaso/rulepacks/remediation_compliance_batch_remaining_azure.json": "a8f76c1a53926fa6cbbda666e80108b494d7933d77d9d39f6d1226f02937b91a",
    "peaso/rulepacks/remediation_compliance_batch_remaining_gcp.json": "5d618ab15fa5cd624e2b2559ab9f308dabe5fb2fa255d33ff664386c5e97b71c",
    "peaso/rulepacks/remediation_compliance_batch_remaining_k8s.json": "5485734fd0351e2dc8f6862b65472164e05df802e32d9c08d061826d1f1492ca",
    "peaso/server/native_policy_validation.py": "a6f62b76f0b68820faa59b29277164b45f4ec04a43ff93c43873273613d7298e"
}
APPROVED_V30_SOURCE_MEMBERS = 1856
APPROVED_V30_RUNTIME_MEMBERS = 923
APPROVED_V30_RUNTIME_SHA256 = '8286e370af64bc3f0eab7c7f77a9c033cf01a5b75f4dc327b457d4da13794900'


# Exact V31 public-edge configuration and API packaging successor; historical branches immutable.
APPROVED_V31_RUNTIME_ADDITIONS = {
    "peaso/analysis/aws_public_ingress.py": "f58f4f100215dd35da15ec177fbfa1b90145a6bf02fbd80afd759374544f06f0",
    "peaso/aws_budget_policy.py": "940a71e4627173e814381a148744a3840c81f60957f5bd2a6032fa4086ba4b69",
    "peaso/aws_lightsail_owner_policy.py": "643e73ec15ea77fcd99d27d7098540cac8a1b854393574ee379d7737af9b8996",
    "peaso/aws_waf_logging.py": "f97074cf8e7ecfb00ac1bac45947bdcd628affe294a0465283b1a5a35eb7c8b9",
    "peaso/azure_devops_git_policy.py": "4c195e73eebf742314c3eeafe0d1f95356d58e71e6c2339d8b1b8b8d418e28ed",
    "peaso/azure_sw32_policy.py": "9d9a545dbc9240e29a3389445dcb9f032fd2350db059e38d49a95f0d90d9e3b0",
    "peaso/azure_tls_owner_policy.py": "7d114ef4f04aafbe1af4e260aab1392712a15de9aca0609b6fc7653a739d0789",
    "peaso/checks/aws_all_policies.json": "8e1cdcc44749b643d95e4ee223e386a4b4aba609d9e09a0577779cc34daa83bf",
    "peaso/checks/aws_all_policies.py": "46c12e7ef9f8ed1eac29709c720c0b703e71ee7d0ac15c2427c99346747ab9fe",
    "peaso/checks/aws_all_policies_fixtures.json": "f93d3feb539b593561b3cf9878a0f151e5619ab29bb43984e9963e141eee9401",
    "peaso/checks/aws_backup_plan_frequency.py": "0f40ddcace19dded128369f32efad6d72e36a8a95590073beb8cada2d4cff08d",
    "peaso/checks/aws_config_recording.py": "50800c1a5c30aa407d0791d4416cc473ea19c3d03f584a2a4a2cfa694d2eabec",
    "peaso/checks/azure_apim_diagnostics_native.py": "4221d0aa3092bff0bb5eeb11fdf3ecc58687f0899a52523fbfeed412bb4af55b",
    "peaso/checks/azure_apim_native.py": "af1e1903c167c813e1ab8e8a9c7fa2336dc6cb5f9d8757f7beaaf6f481744f6b",
    "peaso/checks/azure_appservice_identity_followup.py": "ca7ffd2dccf77fd8e7b90d31c567cbb48b666300330555242582efe768347463",
    "peaso/checks/azure_easm_native.py": "d75e42848fae6c53b0f9e29fdb5c568325bbf8f2e136a7dcc435c58b1036f94b",
    "peaso/checks/azure_graph_credential_age.py": "ba0b2f87162cbace267cb0d630f05655d59239b287d9e7ae6b4f8744cc30a7b4",
    "peaso/checks/azure_log_profile_retention.py": "ba369f5809f8484310b89079ee0b4c3a5523f561ff03cd349488766cc86837ba",
    "peaso/checks/batch_remaining_aws.py": "197ccf540f23e9373d8db281bf1544d2d2bba793be3738ff214e9a6038d813b2",
    "peaso/checks/batch_remaining_azure.py": "82e39d57beef687761098e206457e5e7f7e25a792fc9fcc8600d809f4737b136",
    "peaso/checks/batch_remaining_azure_vm_storage.py": "11f0353505ec70bb7cbc1f6f72add7ceb664fcbd01d05bd8018b2063dd09babb",
    "peaso/checks/batch_remaining_gcp.py": "4f93aebdb8c4fabb603cc122b7a390bc153abc6039035c4a0e780be708aed870",
    "peaso/checks/batch_remaining_k8s.py": "0f0c92c50a05e92bfd0357767066e4e481c03320c2f582ff10194d8cc25dd578",
    "peaso/checks/bulk_pending.json": "85fbd32ae05004c43b554fc2b909c1127e76baa152bb675959b05d0890da9931",
    "peaso/checks/bulk_pending.py": "41cd15965640293562f1808fd7cc31b85769a3e3a44aa3c5537d119dabd50a11",
    "peaso/checks/central_batch_fixtures.json": "1a226d4af6f26c7216c305d36109226bed11e28051c936cb86f66ffcb5dc734b",
    "peaso/checks/central_native_fixtures.py": "2b9665b5b12e164a76b0982bc055857be82cd72d09eafcb8588bc96ead0503f4",
    "peaso/checks/compliance_new_sw25_native_identity.py": "c347440d7e378900762fc5cf6253203c61325008f6320008919d68cb5c37c53e",
    "peaso/checks/compliance_next_k8s.py": "d0184f0934601aaa4682c07d1f0dbfa1b40fa2e9090ce2ca53ca413471b96dfc",
    "peaso/checks/gcp_audit_native.py": "8c2f5e8d0a76571c06a0e0ade0e83cd54f0814fe525fc9f293968224ba2edf8f",
    "peaso/checks/gcp_audit_rates.json": "5010787138c533e7af252d5cfc2aab641097fb6bc9607d6018a66aac943554d9",
    "peaso/checks/gcp_audit_rates.py": "efb0da440e417b40efbcbf189b0fb62385be3b849136b04de08f61baff8e748c",
    "peaso/checks/gcp_audit_rates_fixtures.json": "2d2fd4319e86bb5f54d0f99b6c28ca0788504e46e822afdaed5d0dfe108a4354",
    "peaso/checks/gcp_data_access.py": "ce997648d524475e848aff41353b99f3add7075eca451146a89a7998da9f51c5",
    "peaso/checks/gcp_psc_dns.py": "4d820199813173d9f32ab2b4a5b4547c449d7f88e69affe1064247cb2df1e599",
    "peaso/checks/gcp_psc_fixtures.json": "d452ed303ed02d23d05e1ef1efce880264002779bf3073dee79239a3764a6138",
    "peaso/checks/k8s_namespace_policy_presence.py": "47f64b995e1f5ca9b6db72ff62a7a4594521448f2a1fbba174d453251698a2b2",
    "peaso/checks/native_storage_compute.json": "e4891a7a99339126380eab0a9e66e855c4b1f7ee8558e79abe64a2471fac7c9d",
    "peaso/checks/native_storage_compute.py": "66bc80ff2d43d7d394defa1180199abf42fb0c40b56ff2696ce5f9733f1de318",
    "peaso/checks/native_storage_compute_fixtures.json": "815860e018a22d38bf666b17a981d28993bea720567d369e28e1d26b1339f274",
    "peaso/checks/next20_aws.py": "8b5bedb10366b2708e445bc0068f41a1e6aea0bf8fe7f20c81029dfce665e569",
    "peaso/checks/next_group_appservice_fixtures.py": "1f461d725797b538f7e6550f7aa70217b029e6ec846a3a9e7ce5e6531057c3be",
    "peaso/checks/next_group_aws_fixtures.py": "0076893df5c07f55cd2244d98afaa4516e56f5a1a7bb4f3c5bf7ee1874adb90a",
    "peaso/checks/next_group_azure_fixtures.py": "274822bd1753bef38af173b6be01774abba8ab1bb6b0a0fe3d76638b2e0da249",
    "peaso/checks/next_group_easm_fixtures.py": "3162d5c0deeb1122ddddb06a82793167366dc71f17983547365791854f0406a8",
    "peaso/checks/post_dfaf_aws.py": "301493a4bd3ee865d3d830807a9d6481ef5e3910b3e8ba99c26b57b487cd0fce",
    "peaso/checks/post_dfaf_aws_specs.py": "4f2410348d731c2c76c3db79b0b2b0aebedebf874ce9044f9dccb612622d2476",
    "peaso/checks/post_dfaf_azure.py": "c00e5f758009f1929eb97f83a096706874b97fc6e2269dea8ccdab06c8e5640e",
    "peaso/checks/remaining_aws_gcp_native.py": "ded9f2aa60b562cc3db565a091434ad182e8ae8635d4b128549b827a39a6f5f9",
    "peaso/checks/wafv2_basic.py": "b300d867db2803793f56b23dbd2c51751435236428267e12e23c398c99316437",
    "peaso/collectors/aws_all_policies.py": "4be1797ead0658962fe64ddd17ac4437df49b3612e0d8746cf7315734e4a9886",
    "peaso/collectors/aws_apigateway_native.py": "bf5c20ba91a679dcd303579b89ef6f9fd3b96e4664254716b5c98e4367e854a5",
    "peaso/collectors/aws_budget_stop_native.py": "8001bc5895828ec8fc38baeda5a9e5f863866a3d32889e7b1804a06338dbba44",
    "peaso/collectors/aws_bulk_inventory.py": "45aa2a3bce8581cf8bf1046e882eb701a03b61367378fdcee70d3b5ef415230d",
    "peaso/collectors/aws_cloudtrail_delivery_native.py": "bf7348354a77a39d2271f1b022d1620b0e7f7d3b68dc021cf06f86aceb369393",
    "peaso/collectors/aws_codebuild_redaction.py": "d3f487ca28fae5563b2cd5839f760dbd742e859388ab0646dc762d5c7826f18d",
    "peaso/collectors/aws_codecommit_review_native.py": "8700c0be3a48fe2d6a72ed29390d5938ce2b901ecfccfb829a94cc9618249e93",
    "peaso/collectors/aws_controltower_native.py": "4cc022c9698532209a75fe280851e291964efb9244ff70ef607bdda685753999",
    "peaso/collectors/aws_cost_policy.py": "1e53fa329bbaeba16b0548bbd6b912ebbadd4a22c1e1732c24665d68b36fc42d",
    "peaso/collectors/aws_ecr_artifacts_native.py": "3beaa9b23013e715902d29d76064c0bcf205c569b02b38f74d2c7ba0cd66e99c",
    "peaso/collectors/aws_facts_v4_holds.py": "1e2cec696c00e1b002111fa1c4e3d17f41585c115db0808e11162705e1cd9356",
    "peaso/collectors/aws_identity_center_native.py": "60592e3ff76ae393ed43d89f1554fb2da1f0daaf836b5e640c8760e8b0a66d3e",
    "peaso/collectors/aws_identity_metrics_native.py": "f96984d474dcb07f03ddc4a998d5c0ae32563677f0eaa2a02384bc79dafadfc0",
    "peaso/collectors/aws_kms_enclave_native.py": "589935d3ebd9bd13c1d58adf304daf78359374c8e78f88549f2db83c3f32d069",
    "peaso/collectors/aws_launch_configuration_redaction.py": "09f0a76060934ef47924c1cf747079ca0dba6a82e5803686155067516eb951b5",
    "peaso/collectors/aws_lightsail_iam_native.py": "6d7c9f00c7a9da7e4c3f8da9e19de2c2d168664b32fa09c9753f3df2fb3d5047",
    "peaso/collectors/aws_macie_coverage_native.py": "5650b5a3e15a654cda7d2e5dcd2974124c6a0a711e1798202bf11e4ca5e65a7b",
    "peaso/collectors/aws_operational_groups_native.py": "06108480e7c2f75ca30343ea5ca4fe3dc0a3fa92d8dee9cf2ccf8f47150f2456",
    "peaso/collectors/aws_organizations_native.py": "f331e1cd6fa1a496bcfffb0a3eeb93d72004028dec1bc72d63db731dd1feae5a",
    "peaso/collectors/aws_policy.py": "a3003f6c3930bd5f23523cc6128192ee6a22891a47035df922e34498ada0429d",
    "peaso/collectors/aws_priority_tags_native.py": "c1f67bb05912bb0e60303989dc722093d379e93d56796c48ca81dc40ddb353f1",
    "peaso/collectors/aws_public_ingress_native.py": "3dda8ed8ffdb9e3b650ffe50bc6da24d52f57e53c908357ef9bc4a2094309b7e",
    "peaso/collectors/aws_region_data_native.py": "e2440353ea5b31d50ce281e049dd4586e05710763c0b0b7ee8c737b79ae9f9e1",
    "peaso/collectors/aws_region_shield_native.py": "08f2a665106e9e66b799fa75946739b57c01076fed23b882f3f63651b652d471",
    "peaso/collectors/aws_resolver_firewall_native.py": "ca0970fa271384e2167db3cb2ed855cceda0dd834348671654597ec3d8b19a52",
    "peaso/collectors/aws_resource_policy_native.py": "b0c7b4081f965bab4ece4de503fac0de65038c6c98df010f877f745ce940998e",
    "peaso/collectors/aws_s3_backup_native.py": "48654c9bb7c4fcbb5ee52c8035cb0fd29d0d8a716b358e9d8399a4595aad3ffd",
    "peaso/collectors/aws_sagemaker_clarify_native.py": "f6695218f1c6f5dd060b7871b516d975fb54e1560aba5a413698b589aaa113af",
    "peaso/collectors/aws_ssm_inventory_events_native.py": "c495038efa6858ee77d75a1090fe357998076455da3c1c4bebc105fd9e00370a",
    "peaso/collectors/aws_transport_native.py": "ab038928f14c3136df4c9425856e57b2b199afa24085d739b4f8526a225e53e6",
    "peaso/collectors/aws_waf_inventory_native.py": "10bcdf16a32dc1edd69ef751dd2a1427dbeb5a1c10cf91fd605b97c6dd2ada20",
    "peaso/collectors/azure_access_reviews_native.py": "11647049e6d04b1e9985ec51f9e890c02b0e8da66f67391979628a60e772bd6f",
    "peaso/collectors/azure_aks_admitted_limits_native.py": "11975f3845f600c6179ccc4305b03fb67a465d8f385d20b7ee3ef20a29aa20c2",
    "peaso/collectors/azure_aks_workloads_native.py": "46ff291ae4b4ad820b6aa4a2205929a6ac2f42fccc2eafad70b8f875a2252e11",
    "peaso/collectors/azure_apim_diagnostics_native.py": "d5fe9f4b821fa80c1bed677df063971d6ac61278d315b93eb24b4a7957f9bc2e",
    "peaso/collectors/azure_apim_native.py": "02b20bffce3dc8efa0c74e027533ee438fb6261fcc0a2d0fdd56648b436c3d1d",
    "peaso/collectors/azure_apim_protocol_policy.py": "49c7572d6f0cad40853dc7be7f2867bd465fc2a656f4145680fb36f22cad011f",
    "peaso/collectors/azure_appservice_identity_followup.py": "d5e135f5973b2909974bfd2bf5cb43c03931e71590e63649da35850a75554aaf",
    "peaso/collectors/azure_arm_metadata_native.py": "f244de81694d42e796544d520ab3d631faa58e115f9622ad61d039fe12c4fa50",
    "peaso/collectors/azure_assessment_criteria_native.py": "42ceb16728f8bde78874d38037c835085c1dba1770c3dab84c6b2a03cc268d1a",
    "peaso/collectors/azure_certificate_issuance_native.py": "659b457f03bb4bf1d2a307a3aeaba6de3da2911e0796a4b3e7a1e8223a79e1f4",
    "peaso/collectors/azure_conditional_access_native.py": "9b69def3b75a31ab41eaeac2757b85fe9d3d4f505f948043cd8491cd0ebabe8a",
    "peaso/collectors/azure_database_native.py": "2b5c6850d33f9a74fc6bf46f92bab1330f1d4ae21e92a6461357cde837c3f683",
    "peaso/collectors/azure_databricks_native.py": "3c6c56e700376316c7f711f7dc4981b4f02ec145bacf6553d9163326f7e64359",
    "peaso/collectors/azure_defender_network_native.py": "ce70e05680d870ba145baed0701471783c721446a1781474f70c3b0bbb1985da",
    "peaso/collectors/azure_detection_telemetry.py": "d0c1e354f8c5fbfd8504667dd0268f3e685444e6aa1a5507abb336d16817758d",
    "peaso/collectors/azure_devops_git_native.py": "7b01f9f26acae14414d33b42095caad14adaf4644b3706fde2120e170b4c2c63",
    "peaso/collectors/azure_devops_pipeline_native.py": "e1935267538ee628145317772fd10ed4fa120819a88ebc70f0bf3e22adad54f2",
    "peaso/collectors/azure_disclosure_native.py": "1038ca6d576f89c6d9bced0182239b140f4dbe51e7aafb60a1b569634f15426d",
    "peaso/collectors/azure_entra_diagnostics_native.py": "3ba791cd52c3e5b2fb78bcb12fced683402d552f8a8ff3bd13fec65fc941636f",
    "peaso/collectors/azure_frontdoor_native.py": "f020ec13c4a8ddd12c8e276f24538cb7c698f707b1f4eaebb52ce14e3305f675",
    "peaso/collectors/azure_function_limits_native.py": "cd1b13b2fd9d7983e1846fe651507a26422f4ab9cf7dd9866cdf9c50f28fc7e9",
    "peaso/collectors/azure_guest_configuration_native.py": "d534f80d292e158eba0caad3629b1d0fe54987c2cdbaf7e33a56a672f6159a54",
    "peaso/collectors/azure_guest_policy.py": "55f32bdb4d9e25f6603321fcb8a0877e07bce003ea7f2b02ea080401c2905c4d",
    "peaso/collectors/azure_guest_reports.py": "3b0b5a169a73bd97975b8968fed0b2e13b935ac8bc5f297ed791a128f8e74e4b",
    "peaso/collectors/azure_identity_intune_native.py": "02b0b6d133a2f0d30cb2e30a99d6d3d4feef78231eb61e680acd02987f0896fc",
    "peaso/collectors/azure_iot_policy_native.py": "5daa1c505286ba57c4f1ec016f54f5713b138d3b45cfd1c5fb542ee3ad893468",
    "peaso/collectors/azure_monitor_inventory_native.py": "81bd15cf090e296be7a299da4b7b9e42657c987bbed6afdeb82a0453a90e6127",
    "peaso/collectors/azure_nsg_ingress_native.py": "cde389f77bcb84a407b7e85b20420d7c8fdfc623bc2dcdbdd620816142b35f03",
    "peaso/collectors/azure_public_edge_native.py": "a03b38c782d3ddda800d891babf114036b65faf5f0e29c38ef2410d392547dda",
    "peaso/collectors/azure_resource_diagnostics_native.py": "36f73fc3665680b2489ab99c24dfee59b5f2afb236323952e7131dea481df0ed",
    "peaso/collectors/azure_resource_logging_policy.py": "2d7174efd2706acf66466e3216d95ec1b81d2af1cf5b1b54a8144246ca25d0ba",
    "peaso/collectors/azure_secret_versions_native.py": "53d8ad1f7599697fab83af4139644c93223f9cdbfc5355e587749e545149120c",
    "peaso/collectors/azure_sentinel_metadata_native.py": "3cc20e96f438c017261006a2e9d04f16cfc2d01224515a9477f73a7872e9896b",
    "peaso/collectors/azure_sql_inventory.py": "43a1549a843593c8e33812f5dfa9091a0e7ab534d895ea3e03e718cf08ec82ae",
    "peaso/collectors/azure_storage_backup_native.py": "249e5916a527ecd0d80378c1a4e769fc3511152f0887a85186bc1285aa473405",
    "peaso/collectors/azure_storage_recovery_metadata_native.py": "658807c10ba59c65ecc7a86bd0cae1d3079d785612b69b829908cc135cb81ca0",
    "peaso/collectors/azure_sw15_policy.py": "66a6ff162aa2727a33c3079cfd2709cbea883ce5bcc2f16407ef111743a5b82d",
    "peaso/collectors/azure_vault_key_versions_native.py": "9f99c8f3327161412f6442c8531a566944a8fd2a4b32919da6cddf5bfdc0b932",
    "peaso/collectors/batch_remaining_azure_vm_storage.py": "44bb52e7d7e9e7290cb302e439e1ada18b3dd278895125c857fd028dffa21053",
    "peaso/collectors/batch_remaining_k8s.py": "8c15aa07719cc9596edb3aa7128c99b8d301ef35269ab860ceeb238bec95bb3e",
    "peaso/collectors/bulk_evidence.json": "c1d173bead561f5777df8e703dd8a0939692202b8f2fe7427e8e6d72457a5744",
    "peaso/collectors/bulk_evidence.py": "fb51c829ddc9ca2c83e7cb54de8e1ebc91c0530a8d7eb47d6083e5ff170e6e09",
    "peaso/collectors/gcp_audit_native.py": "02554f3aa9bf2a4d450455c75c6b7fac5ca2396e1afededd34db42a6ec4179e8",
    "peaso/collectors/gcp_facts_v4_holds.py": "f52b9df380e2e69de33cd39bd99f3fda30cac030a1a583c50660b8b9a083f39f",
    "peaso/collectors/gcp_history.py": "21368065d8d1a46209e88d623bb848fe2e3dcb0e4e4c0e5b01f867b8ecf4e631",
    "peaso/collectors/gcp_kms_effective_native.py": "7d2c1e81afebac5e99d47951c85c24aeb91e1795d3fe233c396d9bac6a30ae01",
    "peaso/collectors/gcp_native_evidence.py": "fdced136c30eca42529c967ba2a59f84068008ee98345a1a7abc2c974ca060e1",
    "peaso/collectors/gcp_os_patch_native.py": "e8d86dbc207104d2dbc59d2c0dd0a558f7d00e7edde5960d2750fa7803a85f58",
    "peaso/collectors/gcp_sbom_native.py": "e4fc4bc0c455146ed580d7ef3406424c8ddca2588ccf5cb7c723b922931902f8",
    "peaso/collectors/gcp_storage_acl_native.py": "9ef114ced31862ed48cc3defc7710623e130fcd6431051174fc44b6d19fa2033",
    "peaso/collectors/k8s_admission_file.py": "fc23c5692f1bc295394cf770312a58a8bb64dc532d2c2d9ad33cfeb8a440795f",
    "peaso/gcp_data_access_policy.py": "03167a5cf56583a9ae4efb08aba2beb24fa0e62fcafded1b6f7f47181cb5d4c7",
    "peaso/gcp_psc_policy.py": "ceb9da0dca6e28d011e9f0d779fe519991bb78ec4e7df9bbba67494306eb0ff1",
    "peaso/gcp_sbom_policy.py": "ef717b7f45ddb6d7abca981b6a871f60d9dde0f1eee442c64ddb342ca60be788",
    "peaso/privesc/azure_disclosure_effects.json": "6caf92a0ffdc59cffecb0c9d047d31bc7c49fe02dd0f19b11f3ec743a670f93e",
    "peaso/privesc/bounded_effects.json": "4ce1a0b29fbf026bbc26166915f87e5fb2c4e6396a8aa37ee91e56ca1840806d",
    "peaso/privesc/bulk_principal_tranche.json": "6cb1c21ba90b1ae08d0e5671efa373c8711d42cdb97d3f9055f84d3a239428a8",
    "peaso/privesc/catalog/aws/bounded-effects-v5.yaml": "d38ce968f6af36e9d5c72a098916978320ebf61653df6e6b2c1916de3fbaf80a",
    "peaso/privesc/catalog/aws/bulk-principal-v6.yaml": "e4e907a900127eec6feaa5bb9527ddb130d52c4895b94fd65acb6e8b0a29c779",
    "peaso/privesc/catalog/aws/exact-principal-v5.yaml": "b198454714e4e530682cea805f5e1db595c9eb7a8057f35b1f8d426f88c2a709",
    "peaso/privesc/catalog/aws/lightsail.yaml": "1645b857297793df9c1f6a69e236cbff5873b65055e4e4056360c693c809a279",
    "peaso/privesc/catalog/azure/app_configuration.yaml": "937a2bbc1a2b42d08ef7d183653e540f7320b672c59d9ed5068a191a3aaca89b",
    "peaso/privesc/catalog/azure/bounded-effects-v5.yaml": "1ca7a8398150cd05f2146e3466be8713481870cdcedfaf8813aad3e41b12a9f4",
    "peaso/privesc/catalog/azure/disclosure-effects-v7.yaml": "00175d020192d57529b305d80b2027dcea8df7b58aac26e0c60fd03196b79d3a",
    "peaso/privesc/catalog/azure/monitor.yaml": "a2cec1047c97588d0537a02e1f5ac06ed091188097b8427369fc8362f715cada",
    "peaso/privesc/catalog/azure/storage-local-v7.yaml": "39fc0f2734331d8d08d356614775095d8b7be97bf343aa240e110c12d2988f9f",
    "peaso/privesc/catalog/azure/storage.yaml": "be4c268b9114175bbf079a4d9c70009392f9fab26afa47ea8100930255b19b15",
    "peaso/privesc/catalog/gcp/aiplatform.yaml": "d32d22ffb8909105cbc49f3fe0704df6ffb8e43494c7c908981d59dd31800c69",
    "peaso/privesc/catalog/gcp/bigtable.yaml": "436131e96ff896df4425319aee3952c6010909dab2b4256302a4367af8e230db",
    "peaso/privesc/catalog/gcp/bounded-effects-v5.yaml": "336a51ee7c3e5411d23c7e6fffd90849a28de2577ce2ccc02ff6e03877da5505",
    "peaso/privesc/catalog/gcp/bulk-principal-v6.yaml": "1998a8787332908d955ab6e8769f315dac4afe80fb2e66b57dc34ad7a916cf25",
    "peaso/privesc/catalog/gcp/dlp.yaml": "a4191890cd5bb94485588a7830567975f59ded4b2043f58331a4e6a60223187d",
    "peaso/privesc/catalog/gcp/exact-principal-v5.yaml": "345e1f41d7baf6f859b65eb6abdf8b6be5bf25781a9b25602ab1481bf1c7ec0b",
    "peaso/privesc/catalog/gcp/parametermanager.yaml": "8273c65df5d117386103e3694b7074ab002487b851706897c63d44300f76acab",
    "peaso/privesc/catalog/gcp/secretmanager.yaml": "7ddb46238daeeba20663d30f5a2f07ab25b26cfd8838895787043a6b28c5b23e",
    "peaso/privesc/catalog/k8s/scoped-credential-v7.yaml": "7c4940f42a1754cd843688fcd903a522cd99ea98491c20a1ef5ed77dd75008a5",
    "peaso/privesc/catalog_versions/bounded-v5-manifest.json": "082451e81fa450830ae5f6835e241dd412a6c30a8b2a0b1172cdbc89b2d71429",
    "peaso/privesc/catalog_versions/bulk-principal-v6-manifest.json": "734401b202895e00ac1b6cb0f1534f77cde4d8e2ba912ca0ee974b1b8ec5035c",
    "peaso/privesc/catalog_versions/disclosure-v7-manifest.json": "91ffe7389d02568cdcdf74a6b08dafa5f665ea07c0c528988127ffc4d2a86c45",
    "peaso/privesc/catalog_versions/legacy-0b3633-delta.json": "40640ad0e7179af395ec37f9456ef7b9d8340e8ab81e9edb7a460769edca258a",
    "peaso/privesc/catalog_versions/principal-v4-manifest.json": "6008acf71acda21408c7039dddff2d7ccaeeaa3aecfc6f31ef5d2cdc5a4ea388",
    "peaso/privesc/effective_permissions/azure_disclosure_effects.py": "554dba11bab6ad0145960f8b594ae58ab165e00c0fbe3fb91c3a4bcfa6ef197f",
    "peaso/privesc/effective_permissions/bounded_evidence.py": "1cd1a44f2d955bb5dc877e404ab09294a3df9b67bb1ff9e867aec1cd0cf212af",
    "peaso/privesc/effective_permissions/credential_evidence.py": "a95078884cd2e1c91e3e729921254844237eaa0444b89bf0cd6afd88d9fcaef3",
    "peaso/privesc/effective_permissions/ec2_profile_association.py": "22f0c201cc7d2b37f26c26e307dca33ce55e5716c5f6bea64affc78aff78e039",
    "peaso/privesc/effective_permissions/principal_evidence.py": "2c4bd5e2e2fa33db271b963387787003a42e1c741dad27b22e7b37f23fc2f7e3",
    "peaso/privesc/effective_permissions/storage_local_identity.py": "7671720b0780e47c583e0877888235406c220e64b937d361edb555f3300df7d0",
    "peaso/privesc/exact_principal_tranche.json": "c02921ad9a694b07415ffd5de0c97a0e8b0f34b73bbf40dc3b78e149e29b4af6",
    "peaso/privesc/versioned_catalog.py": "fd6831825507de22b7155909b3bdc1f1e391244b85a180b7764e22f7974f6666",
    "peaso/rulepacks/remediation_compliance_batch_remaining_aws.json": "ebe28d47a1880fa09acc7f42022a1e199ac9c27992049d2ca074670b41d6d490",
    "peaso/rulepacks/remediation_compliance_batch_remaining_azure.json": "a8f76c1a53926fa6cbbda666e80108b494d7933d77d9d39f6d1226f02937b91a",
    "peaso/rulepacks/remediation_compliance_batch_remaining_gcp.json": "5d618ab15fa5cd624e2b2559ab9f308dabe5fb2fa255d33ff664386c5e97b71c",
    "peaso/rulepacks/remediation_compliance_batch_remaining_k8s.json": "5485734fd0351e2dc8f6862b65472164e05df802e32d9c08d061826d1f1492ca",
    "peaso/server/native_policy_validation.py": "a6f62b76f0b68820faa59b29277164b45f4ec04a43ff93c43873273613d7298e"
}
APPROVED_V31_SOURCE_MEMBERS = 1866
APPROVED_V31_RUNTIME_MEMBERS = 925
APPROVED_V31_RUNTIME_SHA256 = '4a70f78d1d023276ab9dab29d71c20657ea0b54c260953d5aa1b64418edb1612'


def approved_runtime_additions(value):
    # Keep every legacy exact branch and add only the reviewed full next-batch set.
    return value in ({}, APPROVED_RUNTIME_ADDITIONS,
                     APPROVED_SUCCESSOR_RUNTIME_ADDITIONS,
                     APPROVED_BATCH_RUNTIME_ADDITIONS,
                     APPROVED_POST_DFAF_RUNTIME_ADDITIONS,
                     APPROVED_NEXT20_RUNTIME_ADDITIONS,
                     APPROVED_APIM_GCP_RUNTIME_ADDITIONS,
                     APPROVED_NEXT_GROUP_RUNTIME_ADDITIONS,
                     APPROVED_LIVE_VALIDATION_RUNTIME_ADDITIONS,
                     APPROVED_GCP_HISTORY_RUNTIME_ADDITIONS,
                     APPROVED_PSC_RUNTIME_ADDITIONS,
                     APPROVED_TWO_HOUR_NATIVE_RUNTIME_ADDITIONS,
                     APPROVED_V20_RUNTIME_ADDITIONS,
                     APPROVED_V21_RUNTIME_ADDITIONS,
                     APPROVED_V23_RUNTIME_ADDITIONS,
                     APPROVED_V24_RUNTIME_ADDITIONS,
                     APPROVED_V25_RUNTIME_ADDITIONS,
                     APPROVED_V26_RUNTIME_ADDITIONS,
                     APPROVED_V27_RUNTIME_ADDITIONS,
                     APPROVED_V28_RUNTIME_ADDITIONS,
                     APPROVED_V29_RUNTIME_ADDITIONS,
                     APPROVED_V30_RUNTIME_ADDITIONS,
                     APPROVED_V31_RUNTIME_ADDITIONS)



def approved_v20_runtime(runtime):
    """Admit only the reviewed complete 909-member path/hash mapping."""
    return (isinstance(runtime, dict) and len(runtime) == APPROVED_V20_RUNTIME_MEMBERS
            and sha(canonical(runtime)) == APPROVED_V20_RUNTIME_SHA256)


def approved_v20_baseline_omission(files, baseline_files):
    """Only this exact successor omits the byte-equivalent canonical gzip copy."""
    duplicate = "peaso/rulepacks/upstream_manifest.json.gz"
    plain = "peaso/rulepacks/upstream_manifest.json"
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(("peaso/", "risk_rules/")) or name in RUNTIME_EXTRAS}
    return (len(files) == 1807 and approved_v20_runtime(runtime)
            and set(baseline_files) - set(files) == {duplicate}
            and files.get(plain) == baseline_files.get(plain)
            and files.get(plain) == "45bfebef85bb831e55b4aaf8037aabff7e257a39caef2625e44b161a34b09091"
            and baseline_files.get(duplicate) == "b4e2c0c4c8e5bdff53b68dc210dc677f4d79de1a77d6ad002990a2f53f34e627")


def approved_v21_runtime(runtime):
    """Bind every runtime path and byte, including modified baseline members."""
    return (isinstance(runtime, dict) and len(runtime) == APPROVED_V21_RUNTIME_MEMBERS
            and sha(canonical(runtime)) == APPROVED_V21_RUNTIME_SHA256)


def approved_v21_baseline_omission(files, baseline_files):
    """Only the exact reviewed successor inherits the same one-gzip omission."""
    duplicate = "peaso/rulepacks/upstream_manifest.json.gz"
    plain = "peaso/rulepacks/upstream_manifest.json"
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(("peaso/", "risk_rules/")) or name in RUNTIME_EXTRAS}
    return (len(files) == APPROVED_V21_SOURCE_MEMBERS and approved_v21_runtime(runtime)
            and set(baseline_files) - set(files) == {duplicate}
            and files.get(plain) == baseline_files.get(plain)
            and files.get(plain) == "45bfebef85bb831e55b4aaf8037aabff7e257a39caef2625e44b161a34b09091"
            and baseline_files.get(duplicate) == "b4e2c0c4c8e5bdff53b68dc210dc677f4d79de1a77d6ad002990a2f53f34e627")


def approved_v23_runtime(runtime):
    """Bind all914 paths and bytes, including every modified baseline member."""
    return (isinstance(runtime, dict) and len(runtime) == APPROVED_V23_RUNTIME_MEMBERS
            and sha(canonical(runtime)) == APPROVED_V23_RUNTIME_SHA256)


def approved_v23_baseline_omission(files, baseline_files):
    """Inherit only the exact canonical byte-identical gzip exception."""
    duplicate = "peaso/rulepacks/upstream_manifest.json.gz"
    plain = "peaso/rulepacks/upstream_manifest.json"
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(("peaso/", "risk_rules/")) or name in RUNTIME_EXTRAS}
    return (len(files) == APPROVED_V23_SOURCE_MEMBERS and approved_v23_runtime(runtime)
            and set(baseline_files) - set(files) == {duplicate}
            and files.get(plain) == baseline_files.get(plain)
            and files.get(plain) == "45bfebef85bb831e55b4aaf8037aabff7e257a39caef2625e44b161a34b09091"
            and baseline_files.get(duplicate) == "b4e2c0c4c8e5bdff53b68dc210dc677f4d79de1a77d6ad002990a2f53f34e627")


def approved_v24_runtime(runtime):
    """Bind all914 paths and bytes, including every modified baseline member."""
    return (isinstance(runtime, dict) and len(runtime) == APPROVED_V24_RUNTIME_MEMBERS
            and sha(canonical(runtime)) == APPROVED_V24_RUNTIME_SHA256)

def approved_v24_baseline_omission(files, baseline_files):
    """Inherit only the exact canonical byte-identical gzip exception."""
    duplicate = "peaso/rulepacks/upstream_manifest.json.gz"
    plain = "peaso/rulepacks/upstream_manifest.json"
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(("peaso/", "risk_rules/")) or name in RUNTIME_EXTRAS}
    return (len(files) == APPROVED_V24_SOURCE_MEMBERS and approved_v24_runtime(runtime)
            and set(baseline_files) - set(files) == {duplicate}
            and files.get(plain) == baseline_files.get(plain)
            and files.get(plain) == "45bfebef85bb831e55b4aaf8037aabff7e257a39caef2625e44b161a34b09091"
            and baseline_files.get(duplicate) == "b4e2c0c4c8e5bdff53b68dc210dc677f4d79de1a77d6ad002990a2f53f34e627")


def approved_v25_runtime(runtime):
    """Bind all914 paths and bytes, including every modified baseline member."""
    return (isinstance(runtime, dict) and len(runtime) == APPROVED_V25_RUNTIME_MEMBERS
            and sha(canonical(runtime)) == APPROVED_V25_RUNTIME_SHA256)

def approved_v25_baseline_omission(files, baseline_files):
    """Inherit only the exact canonical byte-identical gzip exception."""
    duplicate = "peaso/rulepacks/upstream_manifest.json.gz"
    plain = "peaso/rulepacks/upstream_manifest.json"
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(("peaso/", "risk_rules/")) or name in RUNTIME_EXTRAS}
    return (len(files) == APPROVED_V25_SOURCE_MEMBERS and approved_v25_runtime(runtime)
            and set(baseline_files) - set(files) == {duplicate}
            and files.get(plain) == baseline_files.get(plain)
            and files.get(plain) == "45bfebef85bb831e55b4aaf8037aabff7e257a39caef2625e44b161a34b09091"
            and baseline_files.get(duplicate) == "b4e2c0c4c8e5bdff53b68dc210dc677f4d79de1a77d6ad002990a2f53f34e627")


def approved_v26_runtime(runtime):
    """Bind all915 paths and bytes, including every modified baseline member."""
    return (isinstance(runtime, dict) and len(runtime) == APPROVED_V26_RUNTIME_MEMBERS
            and sha(canonical(runtime)) == APPROVED_V26_RUNTIME_SHA256)

def approved_v26_baseline_omission(files, baseline_files):
    """Inherit only the exact canonical byte-identical gzip exception."""
    duplicate = "peaso/rulepacks/upstream_manifest.json.gz"
    plain = "peaso/rulepacks/upstream_manifest.json"
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(("peaso/", "risk_rules/")) or name in RUNTIME_EXTRAS}
    return (len(files) == APPROVED_V26_SOURCE_MEMBERS and approved_v26_runtime(runtime)
            and set(baseline_files) - set(files) == {duplicate}
            and files.get(plain) == baseline_files.get(plain)
            and files.get(plain) == "45bfebef85bb831e55b4aaf8037aabff7e257a39caef2625e44b161a34b09091"
            and baseline_files.get(duplicate) == "b4e2c0c4c8e5bdff53b68dc210dc677f4d79de1a77d6ad002990a2f53f34e627")


def approved_v27_runtime(runtime):
    """Bind all918 paths and bytes, including every modified baseline member."""
    return (isinstance(runtime, dict) and len(runtime) == APPROVED_V27_RUNTIME_MEMBERS
            and sha(canonical(runtime)) == APPROVED_V27_RUNTIME_SHA256)

def approved_v27_baseline_omission(files, baseline_files):
    """Inherit only the exact canonical byte-identical gzip exception."""
    duplicate = "peaso/rulepacks/upstream_manifest.json.gz"
    plain = "peaso/rulepacks/upstream_manifest.json"
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(("peaso/", "risk_rules/")) or name in RUNTIME_EXTRAS}
    return (len(files) == APPROVED_V27_SOURCE_MEMBERS and approved_v27_runtime(runtime)
            and set(baseline_files) - set(files) == {duplicate}
            and files.get(plain) == baseline_files.get(plain)
            and files.get(plain) == "45bfebef85bb831e55b4aaf8037aabff7e257a39caef2625e44b161a34b09091"
            and baseline_files.get(duplicate) == "b4e2c0c4c8e5bdff53b68dc210dc677f4d79de1a77d6ad002990a2f53f34e627")


def approved_v28_runtime(runtime):
    """Bind all918 paths and bytes, including every modified baseline member."""
    return (isinstance(runtime, dict) and len(runtime) == APPROVED_V28_RUNTIME_MEMBERS
            and sha(canonical(runtime)) == APPROVED_V28_RUNTIME_SHA256)

def approved_v28_baseline_omission(files, baseline_files):
    """Inherit only the exact canonical byte-identical gzip exception."""
    duplicate = "peaso/rulepacks/upstream_manifest.json.gz"
    plain = "peaso/rulepacks/upstream_manifest.json"
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(("peaso/", "risk_rules/")) or name in RUNTIME_EXTRAS}
    return (len(files) == APPROVED_V28_SOURCE_MEMBERS and approved_v28_runtime(runtime)
            and set(baseline_files) - set(files) == {duplicate}
            and files.get(plain) == baseline_files.get(plain)
            and files.get(plain) == "45bfebef85bb831e55b4aaf8037aabff7e257a39caef2625e44b161a34b09091"
            and baseline_files.get(duplicate) == "b4e2c0c4c8e5bdff53b68dc210dc677f4d79de1a77d6ad002990a2f53f34e627")


def approved_v29_runtime(runtime):
    """Bind all920 paths and bytes, including every modified baseline member."""
    return (isinstance(runtime, dict) and len(runtime) == APPROVED_V29_RUNTIME_MEMBERS
            and sha(canonical(runtime)) == APPROVED_V29_RUNTIME_SHA256)

def approved_v29_baseline_omission(files, baseline_files):
    """Inherit only the exact canonical byte-identical gzip exception."""
    duplicate = "peaso/rulepacks/upstream_manifest.json.gz"
    plain = "peaso/rulepacks/upstream_manifest.json"
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(("peaso/", "risk_rules/")) or name in RUNTIME_EXTRAS}
    return (len(files) == APPROVED_V29_SOURCE_MEMBERS and approved_v29_runtime(runtime)
            and set(baseline_files) - set(files) == {duplicate}
            and files.get(plain) == baseline_files.get(plain)
            and files.get(plain) == "45bfebef85bb831e55b4aaf8037aabff7e257a39caef2625e44b161a34b09091"
            and baseline_files.get(duplicate) == "b4e2c0c4c8e5bdff53b68dc210dc677f4d79de1a77d6ad002990a2f53f34e627")


def approved_v30_runtime(runtime):
    """Bind all923 paths and bytes, including every modified baseline member."""
    return (isinstance(runtime, dict) and len(runtime) == APPROVED_V30_RUNTIME_MEMBERS
            and sha(canonical(runtime)) == APPROVED_V30_RUNTIME_SHA256)

def approved_v30_baseline_omission(files, baseline_files):
    """Inherit only the exact canonical byte-identical gzip exception."""
    duplicate = "peaso/rulepacks/upstream_manifest.json.gz"
    plain = "peaso/rulepacks/upstream_manifest.json"
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(("peaso/", "risk_rules/")) or name in RUNTIME_EXTRAS}
    return (len(files) == APPROVED_V30_SOURCE_MEMBERS and approved_v30_runtime(runtime)
            and set(baseline_files) - set(files) == {duplicate}
            and files.get(plain) == baseline_files.get(plain)
            and files.get(plain) == "45bfebef85bb831e55b4aaf8037aabff7e257a39caef2625e44b161a34b09091"
            and baseline_files.get(duplicate) == "b4e2c0c4c8e5bdff53b68dc210dc677f4d79de1a77d6ad002990a2f53f34e627")


def approved_v31_runtime(runtime):
    """Bind all925 paths and bytes, including every modified baseline member."""
    return (isinstance(runtime, dict) and len(runtime) == APPROVED_V31_RUNTIME_MEMBERS
            and sha(canonical(runtime)) == APPROVED_V31_RUNTIME_SHA256)

def approved_v31_baseline_omission(files, baseline_files):
    """Inherit only the exact canonical byte-identical gzip exception."""
    duplicate = "peaso/rulepacks/upstream_manifest.json.gz"
    plain = "peaso/rulepacks/upstream_manifest.json"
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(("peaso/", "risk_rules/")) or name in RUNTIME_EXTRAS}
    return (len(files) == APPROVED_V31_SOURCE_MEMBERS and approved_v31_runtime(runtime)
            and set(baseline_files) - set(files) == {duplicate}
            and files.get(plain) == baseline_files.get(plain)
            and files.get(plain) == "45bfebef85bb831e55b4aaf8037aabff7e257a39caef2625e44b161a34b09091"
            and baseline_files.get(duplicate) == "b4e2c0c4c8e5bdff53b68dc210dc677f4d79de1a77d6ad002990a2f53f34e627")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(value: bytes):
    return hashlib.sha256(value).hexdigest()


def _check_rows(state):
    rows = state.get("check_results")
    if not isinstance(rows, list) or len(rows) != 7 or any(not isinstance(row, dict) for row in rows):
        raise RuntimeError("Baseline validation inventory differs")
    ids = [(row.get("object_kind"), row.get("config_addr")) for row in rows]
    if len(set(ids)) != 7 or ids.count(TARGET_CHECK) != 1:
        raise RuntimeError("Baseline validation identities differ")
    target = rows[ids.index(TARGET_CHECK)]
    objects = target.get("objects")
    if (set(target) != {"object_kind", "config_addr", "objects", "status"} or
            target["status"] != "pass" or not isinstance(objects, list) or len(objects) != 5 or
            any(not isinstance(obj, dict) or set(obj) != {"object_addr", "status"} or
                not isinstance(obj["object_addr"], str) or not obj["object_addr"] or
                obj["status"] != "pass" for obj in objects) or
            len({obj["object_addr"] for obj in objects}) != 5):
        raise RuntimeError("Baseline target validation differs")
    return rows, dict(zip(ids, rows)), objects


def exact_baseline(raw: bytes):
    if sha(raw) != BASELINE_RAW_SHA:
        raise RuntimeError("Serial-29 S3 state bytes changed")
    state = json.loads(raw)
    if (sha(canonical(state)) != BASELINE_CANONICAL_SHA or
            state.get("lineage") != LINEAGE or state.get("serial") != SERIAL):
        raise RuntimeError("Serial-29 state identity changed")
    resources = managed(state)
    _check_rows(state)
    return state, resources


def managed(state):
    if state.get("lineage") != LINEAGE or state.get("serial") != SERIAL:
        raise RuntimeError("Serial-29 state epoch differs")
    resources = {}
    for block in state.get("resources", []):
        if block.get("mode") != "managed":
            continue
        if block.get("module") or not isinstance(block.get("instances"), list):
            raise RuntimeError("Managed state module or instances differ")
        for instance in block["instances"]:
            address = f'{block.get("type")}.{block.get("name")}'
            if "index_key" in instance:
                address += "[" + json.dumps(instance["index_key"], separators=(",", ":")) + "]"
            values = instance.get("attributes")
            if (address in resources or instance.get("deposed") or instance.get("status") == "tainted" or
                    not isinstance(values, dict)):
                raise RuntimeError("Managed state identity or values differ")
            if address == "random_bytes.credential_key":
                if values.get("length") != 32 or not isinstance(values.get("hex"), str) or len(values["hex"]) != 64:
                    raise RuntimeError("State credential identity differs")
            elif not isinstance(values.get("id"), str) or not values["id"]:
                raise RuntimeError("Managed state ID differs")
            resources[address] = values
    address_bytes = ("\n".join(sorted(resources)) + "\n").encode()
    if len(resources) != COUNT or sha(address_bytes) != ADDRESS_SHA:
        raise RuntimeError("Managed state address inventory differs")
    return resources


def state_pull_matches(pulled, baseline):
    """Allow only full-value permutation of one proven five-object validation row."""
    try:
        if not isinstance(pulled, dict) or not isinstance(baseline, dict):
            return False
        if sha(canonical(baseline)) != BASELINE_CANONICAL_SHA or set(pulled) != set(baseline):
            return False
        if any(pulled[key] != baseline[key] for key in baseline if key != "check_results"):
            return False
        _, prior, first = _check_rows(baseline)
        _, observed, second = _check_rows(pulled)
        if set(prior) != set(observed):
            return False
        if any(prior[key] != observed[key] for key in prior if key != TARGET_CHECK):
            return False
        if {key: value for key, value in prior[TARGET_CHECK].items() if key != "objects"} != {
                key: value for key, value in observed[TARGET_CHECK].items() if key != "objects"}:
            return False
        if Counter(canonical(obj) for obj in first) != Counter(canonical(obj) for obj in second):
            return False
        left, right = deepcopy(pulled), deepcopy(baseline)
        for state in (left, right):
            target = next(row for row in state["check_results"]
                          if (row.get("object_kind"), row.get("config_addr")) == TARGET_CHECK)
            target["objects"].sort(key=canonical)
        # Existing comparator still enforces every other complete state value.
        from scripts import peaso_deploy as deploy
        return deploy.recovery_live_state_matches(left, right)
    except (KeyError, TypeError, ValueError, RuntimeError):
        return False


def reviewed_drift(rows, raw_resources, approved):
    if not isinstance(rows, list) or not isinstance(approved, dict):
        raise RuntimeError("Refresh drift or approval malformed")
    by_address = {row.get("address"): row for row in rows if isinstance(row, dict)}
    if len(by_address) != len(rows) or set(by_address) != set(approved) or not set(by_address) <= DRIFT_ALLOWLIST:
        raise RuntimeError("Refresh has unapproved or duplicate drift")
    refreshed = dict(raw_resources)
    for address, row in by_address.items():
        change = row.get("change")
        if (row.get("mode") != "managed" or row.get("module_address") or
                not isinstance(change, dict) or change.get("actions") != ["update"] or
                change.get("before") != raw_resources[address] or
                not isinstance(change.get("after"), dict) or current.unknown(change.get("after_unknown") or {})):
            raise RuntimeError("Refresh drift identity or values differ")
        before, after = change["before"], change["after"]
        observed = {"before_sha256": sha(canonical(before)), "after_sha256": sha(canonical(after)),
                    "change_sha256": sha(canonical(change))}
        if approved[address] != observed:
            raise RuntimeError("Refresh drift differs from per-row approval")
        field = "inline_policy" if address.startswith("aws_iam_role.") else (
            "policy" if address == "aws_s3_bucket.templates[0]" else "tags")
        if current.changed_fields(change) != [field]:
            raise RuntimeError("Refresh drift changed unrelated fields")
        if field == "tags":
            if before.get("tags") is not None or after.get("tags") != {}:
                raise RuntimeError("Provider tag drift is not nil to empty")
        else:
            child_address = {"aws_iam_role.api": "aws_iam_role_policy.api",
                             "aws_iam_role.workflow": "aws_iam_role_policy.workflow",
                             "aws_s3_bucket.templates[0]": "aws_s3_bucket_policy.templates[0]"}[address]
            child = raw_resources[child_address]
            policy = after.get("policy") if field == "policy" else (after.get("inline_policy") or [{}])[0].get("policy")
            if current.json_document(policy, "parent policy") != current.json_document(child.get("policy"), "owned child"):
                raise RuntimeError("Parent policy differs from owned child")
            if field == "inline_policy":
                old, new = before.get(field), after.get(field)
                if (not isinstance(old, list) or not isinstance(new, list) or len(old) != 1 or len(new) != 1 or
                        old[0].get("name") != new[0].get("name") or new[0].get("name") != child.get("name")):
                    raise RuntimeError("Parent policy identity differs")
            if address == "aws_iam_role.api":
                current.check_api_policy({"policy": before["inline_policy"][0]["policy"]},
                                         {"policy": after["inline_policy"][0]["policy"]})
            elif address == "aws_iam_role.workflow":
                if not current.task_refs_equal(before["inline_policy"][0]["policy"],
                                               after["inline_policy"][0]["policy"]):
                    raise RuntimeError("Workflow parent policy differs beyond task revisions")
            else:
                current.check_template_policy({"policy": before["policy"]},
                                              {"policy": after["policy"]}, raw_resources)
        refreshed[address] = after
    return refreshed


def review_plan(data, contract, state, refresh):
    """Review only a complete saved six-address artifact update for epoch 29."""
    expected = {"schema", "account", "backend", "state", "refresh", "plan", "baseline_release",
                "candidate_release", "approved_drift", "approved_changes"}
    if (not isinstance(contract, dict) or set(contract) != expected or
            contract["schema"] != "peaso-artifact-update-epoch29-v1" or
            contract["account"] != ACCOUNT or contract["backend"] != BACKEND):
        raise RuntimeError("Artifact update contract scope or fields differ")
    source = {"source_version": SOURCE_VERSION, "release_json_sha256": SOURCE_RELEASE_SHA,
              "source_zip_sha256": SOURCE_ZIP_SHA, "api_zip_sha256": SOURCE_API_SHA,
              "frontend_manifest_sha256": SOURCE_FRONTEND_SHA, "worker_image": SOURCE_IMAGE}
    if contract["baseline_release"] != source:
        raise RuntimeError("Artifact update baseline source differs")
    required_release = set(source)
    candidate = contract["candidate_release"]
    if (not isinstance(candidate, dict) or set(candidate) != required_release or
            candidate["source_version"] == SOURCE_VERSION or
            any(not isinstance(candidate[key], str) or not re.fullmatch(r"[a-f0-9]{64}", candidate[key])
                for key in required_release - {"worker_image"}) or
            not isinstance(candidate["worker_image"], str) or not re.fullmatch(
                rf"{ACCOUNT}\.dkr\.ecr\.us-east-1\.amazonaws\.com/hacktricks-cspm-worker@sha256:[a-f0-9]{{64}}",
                candidate["worker_image"])):
        raise RuntimeError("Artifact update candidate release fields differ")
    if (not isinstance(contract["plan"], dict) or set(contract["plan"]) != {"sha256", "json_sha256"} or
            not isinstance(contract["refresh"], dict) or set(contract["refresh"]) != {"json_sha256"} or
            any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value)
                for value in [*contract["plan"].values(), *contract["refresh"].values()])):
        raise RuntimeError("Artifact update plan/refresh hash approval differs")
    if (contract["state"] != {"sha256": BASELINE_RAW_SHA, "canonical_sha256": BASELINE_CANONICAL_SHA,
                              "lineage": LINEAGE, "serial": SERIAL, "managed_address_sha256": ADDRESS_SHA,
                              "managed_count": COUNT}):
        raise RuntimeError("Artifact update baseline state differs")
    if (data.get("errored") is not False or data.get("applyable") is not True or
            data.get("complete") is not True or data.get("terraform_version") != "1.14.3" or
            refresh.get("errored") is not False or refresh.get("terraform_version") != "1.14.3"):
        raise RuntimeError("Artifact update plan or refresh incomplete")
    raw = managed(state)
    _check_rows(state)
    if data.get("resource_drift") != refresh.get("resource_drift"):
        raise RuntimeError("Saved plan drift differs from reviewed refresh")
    resources = reviewed_drift(refresh["resource_drift"], raw, contract["approved_drift"])
    prior_root = data.get("prior_state", {}).get("values", {}).get("root_module", {})
    prior = prior_root.get("resources")
    if prior_root.get("child_modules") or not isinstance(prior, list) or len(prior) != COUNT + 7:
        raise RuntimeError("Artifact update prior inventory differs")
    current.check_prior_data_sources(state, [row for row in prior if row.get("mode") == "data"])
    prior_managed = [row for row in prior if row.get("mode") == "managed"]
    by_prior = {row.get("address"): row for row in prior_managed}
    if len(by_prior) != COUNT or set(by_prior) != set(resources) or any(
            row.get("values") != resources[address] for address, row in by_prior.items()):
        raise RuntimeError("Artifact update prior values differ from refresh")
    for address, row in by_prior.items():
        base = f'{row.get("type")}.{row.get("name")}'
        indexed = base + "[" + json.dumps(row["index"], separators=(",", ":")) + "]" if "index" in row else base
        provider = ("registry.terraform.io/hashicorp/random" if row.get("type") == "random_bytes"
                    else "registry.terraform.io/hashicorp/aws")
        if (address != indexed or row.get("provider_name") != provider or
                type(row.get("schema_version")) is not int):
            raise RuntimeError("Artifact update prior resource identity differs")
    rows = data.get("resource_changes")
    if (not isinstance(rows, list) or len(rows) != COUNT or any(
            not isinstance(row, dict) or row.get("mode") != "managed" or row.get("module_address") for row in rows)):
        raise RuntimeError("Artifact update managed plan inventory differs")
    changes = {row.get("address"): row for row in rows}
    if len(changes) != COUNT or set(changes) != set(resources):
        raise RuntimeError("Artifact update changed addresses differ")
    approvals = contract["approved_changes"]
    if not isinstance(approvals, dict) or set(approvals) != set(SIX_ACTIONS):
        raise RuntimeError("Artifact update must approve exactly six actions")
    for address, row in changes.items():
        prior_row = by_prior[address]
        for key in ("mode", "type", "name", "index", "provider_name"):
            if row.get(key) != prior_row.get(key):
                raise RuntimeError("Artifact update resource identity differs")
        change = row.get("change")
        if not isinstance(change, dict):
            raise RuntimeError("Artifact update change malformed")
        if address not in SIX_ACTIONS:
            if (change.get("actions") != ["no-op"] or change.get("before") != resources[address] or
                    change.get("after") != resources[address] or current.unknown(change.get("after_unknown") or {})):
                raise RuntimeError("Artifact update unrelated row is not exact no-op")
            continue
        old_successor.check_change(row, resources)
        expected_approval = {"actions": change["actions"], "changed_fields": current.changed_fields(change),
                             "change_sha256": sha(canonical(change))}
        if approvals[address] != expected_approval:
            raise RuntimeError("Artifact update action differs from exact approval")
    check_candidate_bodies(changes, candidate)
    return {"resources": resources, "drift_rows": refresh["resource_drift"],
            "approved_changes": approvals, "state": state}


def check_candidate_bodies(changes, candidate):
    version = candidate["source_version"]
    source_url = f"https://cspm.hacktricks.wiki/source/peaso-source-{version}.zip"
    api_hash = base64.b64encode(bytes.fromhex(candidate["api_zip_sha256"])).decode()
    for address in ("aws_lambda_function.api", "aws_lambda_function.scheduler"):
        after = changes[address]["change"]["after"]
        env = (after.get("environment") or [{}])[0].get("variables")
        if (after.get("source_code_hash") != api_hash or
                not isinstance(after.get("filename"), str) or
                not after["filename"].endswith("/infra/aws/build/api.zip") or
                not isinstance(env, dict) or env.get("PEASO_SOURCE_VERSION") != version or
                env.get("PEASO_SOURCE_URL") != source_url):
            raise RuntimeError("Artifact update Lambda body differs from candidate API/source")
    for address in ('aws_ecs_task_definition.tasks["collector"]',
                    'aws_ecs_task_definition.tasks["analyzer"]'):
        try:
            containers = json.loads(changes[address]["change"]["after"]["container_definitions"])
            container = containers[0]
            env = {item["name"]: item["value"] for item in container["environment"]}
        except (KeyError, IndexError, TypeError, ValueError):
            raise RuntimeError("Artifact update task body is malformed") from None
        if (len(containers) != 1 or len(env) != len(container["environment"]) or
                container.get("image") != candidate["worker_image"] or
                env.get("PEASO_SOURCE_VERSION") != version):
            raise RuntimeError("Artifact update task body differs from candidate worker/source")


def review_bytes(*, contract_raw: bytes, state_raw: bytes, baseline_release_raw: bytes,
                 refresh_raw: bytes,
                 plan_raw: bytes, plan_binary: bytes, candidate_release_raw: bytes,
                 candidate_source_zip: bytes, candidate_api_zip: bytes,
                 candidate_frontend_manifest: bytes):
    """Bind a later reviewed contract to complete supplied offline evidence bytes."""
    contract = json.loads(contract_raw)
    if not isinstance(contract, dict):
        raise RuntimeError("Artifact update contract is not an object")
    state, _ = exact_baseline(state_raw)
    if sha(baseline_release_raw) != SOURCE_RELEASE_SHA:
        raise RuntimeError("Artifact update baseline release bytes differ")
    baseline_release = json.loads(baseline_release_raw)
    if (not isinstance(baseline_release, dict) or baseline_release.get("source_version") != SOURCE_VERSION or
            not isinstance(baseline_release.get("files"), dict) or len(baseline_release["files"]) != 1299):
        raise RuntimeError("Artifact update baseline source manifest differs")
    if (sha(refresh_raw) != (contract.get("refresh") or {}).get("json_sha256") or
            sha(plan_raw) != (contract.get("plan") or {}).get("json_sha256") or
            sha(plan_binary) != (contract.get("plan") or {}).get("sha256") or
            sha(candidate_release_raw) != (contract.get("candidate_release") or {}).get("release_json_sha256") or
            sha(candidate_source_zip) != (contract.get("candidate_release") or {}).get("source_zip_sha256") or
            sha(candidate_api_zip) != (contract.get("candidate_release") or {}).get("api_zip_sha256") or
            sha(candidate_frontend_manifest) != (contract.get("candidate_release") or {}).get("frontend_manifest_sha256")):
        raise RuntimeError("Artifact update evidence bytes differ from approval")
    release = json.loads(candidate_release_raw)
    if (not isinstance(release, dict) or
            release.get("source_version") != contract["candidate_release"]["source_version"] or
            release.get("source_version") != sha(canonical(release.get("files"))) or
            release.get("source_url") != f'https://cspm.hacktricks.wiki/source/peaso-source-{release["source_version"]}.zip' or
            release.get("license") != "AGPL-3.0" or
            not isinstance(release.get("files"), dict) or len(release["files"]) < 1299 or
            any(not isinstance(name, str) or not isinstance(value, str) or
                not re.fullmatch(r"[a-f0-9]{64}", value) for name, value in release["files"].items())):
        raise RuntimeError("Artifact update candidate source manifest differs")
    if any(name.startswith("/") or ".." in name.split("/") or name.endswith("/")
           for name in release["files"]):
        raise RuntimeError("Artifact update source member path differs")
    v20_successor = approved_v20_baseline_omission(release["files"], baseline_release["files"])
    v21_successor = approved_v21_baseline_omission(release["files"], baseline_release["files"])
    v23_successor = approved_v23_baseline_omission(release["files"], baseline_release["files"])
    v24_successor = approved_v24_baseline_omission(release["files"], baseline_release["files"])
    v25_successor = approved_v25_baseline_omission(release["files"], baseline_release["files"])
    v26_successor = approved_v26_baseline_omission(release["files"], baseline_release["files"])
    v27_successor = approved_v27_baseline_omission(release["files"], baseline_release["files"])
    v28_successor = approved_v28_baseline_omission(release["files"], baseline_release["files"])
    v29_successor = approved_v29_baseline_omission(release["files"], baseline_release["files"])
    v30_successor = approved_v30_baseline_omission(release["files"], baseline_release["files"])
    v31_successor = approved_v31_baseline_omission(release["files"], baseline_release["files"])
    if not set(baseline_release["files"]) <= set(release["files"]) and not (v20_successor or v21_successor or v23_successor or v24_successor or v25_successor or v26_successor or v27_successor or v28_successor or v29_successor or v30_successor or v31_successor):
        raise RuntimeError("Artifact update omitted a baseline source member")
    if len(candidate_source_zip) > MAX_SOURCE_ARCHIVE_BYTES:
        raise RuntimeError("Artifact update source ZIP exceeds measured archive budget")
    with zipfile.ZipFile(io.BytesIO(candidate_source_zip)) as archive:
        members = archive.infolist()
        names = [member.filename for member in members]
        if (len(names) > MAX_SOURCE_MEMBERS + 1 or len(names) != len(set(names)) or
                set(names) != set(release["files"]) | {"release.json"} or
                any(member.file_size > MAX_SOURCE_MEMBER_BYTES for member in members) or
                sum(member.file_size for member in members) > MAX_SOURCE_UNCOMPRESSED_BYTES):
            raise RuntimeError("Artifact update source ZIP inventory differs")
        if any(member.is_dir() or member.flag_bits & 1 or
               stat.S_IFMT(member.external_attr >> 16) not in (0, stat.S_IFREG) or
               member.compress_type != zipfile.ZIP_DEFLATED for member in members):
            raise RuntimeError("Artifact update source ZIP contains unsafe member metadata")
        if json.loads(archive.read("release.json")) != release:
            raise RuntimeError("Artifact update source ZIP manifest differs")
        for name, expected in release["files"].items():
            info = archive.getinfo(name)
            if info.file_size > MAX_SOURCE_MEMBER_BYTES or sha(archive.read(name)) != expected:
                raise RuntimeError("Artifact update source ZIP member differs")
    if len(candidate_api_zip) > MAX_API_ARCHIVE_BYTES:
        raise RuntimeError("Artifact update API ZIP exceeds measured archive budget")
    runtime = {name: expected for name, expected in release["files"].items()
               if name.startswith(("peaso/", "risk_rules/")) or name in RUNTIME_EXTRAS}
    baseline_runtime = {name for name in baseline_release["files"]
                        if name.startswith(("peaso/", "risk_rules/")) or name in RUNTIME_EXTRAS}
    added_runtime = {name: runtime[name] for name in set(runtime) - baseline_runtime}
    if (len(baseline_runtime) != BASELINE_RUNTIME_MEMBERS or
            (not baseline_runtime <= set(runtime) and not (v20_successor or v21_successor or v23_successor or v24_successor or v25_successor or v26_successor or v27_successor or v28_successor or v29_successor or v30_successor or v31_successor)) or
            not approved_runtime_additions(added_runtime) or
            (added_runtime == APPROVED_V20_RUNTIME_ADDITIONS and not v20_successor) or
            (added_runtime == APPROVED_V21_RUNTIME_ADDITIONS and not v21_successor) or
            (added_runtime == APPROVED_V23_RUNTIME_ADDITIONS and not v23_successor) or
            (added_runtime == APPROVED_V24_RUNTIME_ADDITIONS and not v24_successor) or
            (added_runtime == APPROVED_V25_RUNTIME_ADDITIONS and not v25_successor) or
            (added_runtime == APPROVED_V26_RUNTIME_ADDITIONS and not v26_successor) or
            (added_runtime == APPROVED_V27_RUNTIME_ADDITIONS and not v27_successor) or
            (added_runtime == APPROVED_V28_RUNTIME_ADDITIONS and not v28_successor) or
            (added_runtime == APPROVED_V29_RUNTIME_ADDITIONS and not v29_successor) or
            (added_runtime == APPROVED_V30_RUNTIME_ADDITIONS and not v30_successor) or
            (added_runtime == APPROVED_V31_RUNTIME_ADDITIONS and not v31_successor)):
        raise RuntimeError("Artifact update required runtime inventory differs")
    with zipfile.ZipFile(io.BytesIO(candidate_api_zip)) as archive:
        members = archive.infolist()
        names = [member.filename for member in members]
        if (len(names) > MAX_API_MEMBERS or len(names) != len(set(names)) or
                "peaso_release.json" not in names or not set(runtime) <= set(names) or
                any(name.startswith("/") or ".." in name.split("/") or name.endswith("/") for name in names) or
                any(member.file_size > MAX_API_MEMBER_BYTES or member.is_dir() or member.flag_bits & 1 or
                    stat.S_IFMT(member.external_attr >> 16) != stat.S_IFREG or
                    member.compress_type != zipfile.ZIP_DEFLATED for member in members) or
                sum(member.file_size for member in members) > MAX_API_UNCOMPRESSED_BYTES):
            raise RuntimeError("Artifact update API ZIP inventory or metadata differs")
        if archive.read("peaso_release.json") != candidate_release_raw:
            raise RuntimeError("Artifact update API ZIP embedded release differs")
        for name, expected in runtime.items():
            if sha(archive.read(name)) != expected:
                raise RuntimeError("Artifact update API ZIP runtime member differs")
    frontend = json.loads(candidate_frontend_manifest)
    if (not isinstance(frontend, dict) or frontend.get("source_version") != release["source_version"] or
            not isinstance(frontend.get("files"), dict) or not frontend["files"]):
        raise RuntimeError("Artifact update frontend manifest differs")
    return review_plan(json.loads(plan_raw), contract, state, json.loads(refresh_raw))


def load_context(plan, raw_json, data, contract_path, approved_sha256, infra, build):
    """Proposed product loader: exact private evidence and complete frozen source."""
    from pathlib import Path

    raw_contract = current.private_artifact(Path(contract_path), approved_sha256)
    outer = json.loads(raw_contract)
    if (not isinstance(outer, dict) or set(outer) != {"schema", "review", "evidence"} or
            outer["schema"] != "peaso-artifact-update-evidence-v1" or
            not isinstance(outer["review"], dict) or not isinstance(outer["evidence"], dict) or
            set(outer["evidence"]) != {"state_path", "refresh_path", "plan_json_path",
                                        "baseline_release_path"}):
        raise RuntimeError("Artifact update private evidence envelope differs")
    review = outer["review"]
    evidence = outer["evidence"]
    for key, value in evidence.items():
        if not isinstance(value, str) or not Path(value).is_absolute():
            raise RuntimeError("Artifact update private evidence path differs: " + key)
    state_raw = current.private_artifact(Path(evidence["state_path"]), review["state"]["sha256"])
    refresh_raw = current.private_artifact(Path(evidence["refresh_path"]), review["refresh"]["json_sha256"])
    plan_json = current.private_artifact(Path(evidence["plan_json_path"]), review["plan"]["json_sha256"])
    baseline_release = current.private_artifact(Path(evidence["baseline_release_path"]), SOURCE_RELEASE_SHA)
    if plan_json != raw_json or json.loads(plan_json) != data:
        raise RuntimeError("Artifact update saved plan JSON differs from private capture")
    release_path = Path(build) / "release.json"
    if release_path.is_symlink() or not release_path.is_file():
        raise RuntimeError("Artifact update release manifest is missing or a symlink")
    release_raw = release_path.read_bytes()
    candidate_version = review["candidate_release"]["source_version"]
    source_zip = Path(build) / f"peaso-source-{candidate_version}.zip"
    api_zip = Path(build) / "api.zip"
    frontend_manifest = Path(build) / "frontend-build.json"
    if any(path.is_symlink() or not path.is_file() for path in
           (Path(plan), release_path, source_zip, api_zip, frontend_manifest)):
        raise RuntimeError("Artifact update saved plan or build member is missing or a symlink")
    context = review_bytes(
        contract_raw=canonical(review), state_raw=state_raw,
        baseline_release_raw=baseline_release, refresh_raw=refresh_raw,
        plan_raw=raw_json, plan_binary=Path(plan).read_bytes(),
        candidate_release_raw=release_raw, candidate_source_zip=source_zip.read_bytes(),
        candidate_api_zip=api_zip.read_bytes(),
        candidate_frontend_manifest=frontend_manifest.read_bytes())
    release = json.loads(release_raw)
    root = Path(infra).parent.parent
    snapshot = Path(build) / "source-snapshot"
    if json.loads((snapshot / "release.json").read_bytes()) != release:
        raise RuntimeError("Artifact update frozen snapshot manifest differs")
    for name, expected in release["files"].items():
        for base in (root, snapshot):
            path = base / name
            if (not path.is_file() or path.is_symlink() or
                    not path.resolve().is_relative_to(base.resolve()) or
                    sha(path.read_bytes()) != expected):
                raise RuntimeError("Artifact update root/snapshot source differs: " + name)
    variables = json.loads((Path(infra) / "deployment.auto.tfvars.json").read_bytes())
    if (variables.get("source_version") != candidate_version or
            variables.get("worker_image") != review["candidate_release"]["worker_image"] or
            Path(variables.get("api_zip", "")) != api_zip.resolve()):
        raise RuntimeError("Artifact update deployment variable identity differs")
    context.update({"contract_path": str(contract_path), "contract_sha256": approved_sha256,
                    "state_sha256": review["state"]["sha256"], "lineage": LINEAGE,
                    "serial": SERIAL, "release": review["candidate_release"]})
    if (sha(current.private_artifact(Path(contract_path), approved_sha256)) != approved_sha256 or
            sha(Path(plan).read_bytes()) != review["plan"]["sha256"]):
        raise RuntimeError("Artifact update approval or saved plan changed during review")
    return context


check_resolved_documents = old_successor.check_resolved_documents


def check_publish_target(output):
    """Reject a different S3/CloudFront target before any publication write."""
    if (not isinstance(output, dict) or
            (output.get("frontend_bucket") or {}).get("value") !=
            (("hacktricks-cspm-frontend-DEPLOYMENT_ACCOUNT_ID").replace("DEPLOYMENT_ACCOUNT_ID", deployment.value("account_id"))) or
            (output.get("cloudfront_distribution_id") or {}).get("value") !=
            "E24KDR2EDPKSBS"):
        raise RuntimeError("Artifact update publication target differs from epoch-29 state")
