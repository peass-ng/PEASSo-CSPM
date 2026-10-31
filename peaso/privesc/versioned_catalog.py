"""Exact binding for the additive principal-target v4 catalog and legacy cards."""
from __future__ import annotations

from functools import lru_cache
import base64
import hashlib
import io
import json
import struct
import tarfile
import zipfile
import zlib
from pathlib import Path

import yaml

from .schema import CATALOG_DIR, CatalogError, load_catalog

BINDING_SCHEMA = "privesc-catalog-binding-v1"
LEGACY_MANIFEST = "fe767aecd3beee553441ec6e586fa5aa6a946345b7beca43397e4c4c7c6bb481"
LEGACY_REVISION = "0b3633117413069d93b713d2a98a9e16b1d189f3"
LEGACY_DELTA_SHA256 = "40640ad0e7179af395ec37f9456ef7b9d8340e8ab81e9edb7a460769edca258a"
V4_MANIFEST = "6008acf71acda21408c7039dddff2d7ccaeeaa3aecfc6f31ef5d2cdc5a4ea388"
V4_REVISION = "4913b6d88ced9972f72ccdd708d21641725a6fb5"
V4_EFFECTIVE_TREE = "413792ea4aec86e48c352ffab2c0bea9e82795bc234251342737ec0276b748d2"
LEGACY_DELTA = Path(__file__).resolve().parent / "catalog_versions/legacy-0b3633-delta.json"
BOUNDED_MANIFEST = "734401b202895e00ac1b6cb0f1534f77cde4d8e2ba912ca0ee974b1b8ec5035c"
BOUNDED_TREE = "1a54bad4102d18f89c78f45c915964554a62f994c1bffa693844cac5e119cca8"
REVIEWED_685_PREVIOUS_MANIFEST = 'faee1d9f348246d4c69330c03a371fb83fde135413e9c3b204cae7b34e0c97f4'
REVIEWED_685_PREVIOUS_TREE = '2e30181ac85c7af8d49d093a3abfb19dc1113304f473540c8344d90004690e79'
REVIEWED_685_PREVIOUS_ARCHIVE_SHA256 = '0ace179747b298d9f294ecbfc5d3d54b0e23d06b7921b8a71750f895b270d881'
REVIEWED_685_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-reviewed-685-863-source-manifest.json'
REVIEWED_685_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-reviewed-685-863-catalog.tar.gz'
REVIEWED_691_PREVIOUS_MANIFEST = '16e83c81081977912ae81f40981ba0a6ed5ad4cb939ecf3801ef5bd4302e8917'
REVIEWED_691_PREVIOUS_TREE = 'bd33c3dc1d491a0daf045d73f7cfcc335b8341456bc47681fe20550d18a63a4c'
REVIEWED_691_PREVIOUS_ARCHIVE_SHA256 = 'fc6ee9346dbec5e670118b5f87efb624424ff03a84f2c0d798ab56bb00139577'
REVIEWED_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-reviewed-691-source-manifest.json'
REVIEWED_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-reviewed-691-catalog.tar.gz'
BEANSTALK_685_PREVIOUS_MANIFEST = 'd0f411c0fd932267614209ecaf763d5ea34c22c6f6c5762df8f7b265a002d2e0'
BEANSTALK_685_PREVIOUS_TREE = 'c5424a883127f80c21168352067bae2635be2d586d77a645cb288c8c1bb997b7'
BEANSTALK_685_PREVIOUS_ARCHIVE_SHA256 = '3e23d5a8d7fa79367b5ab623ab29451ee68a3c69de02a5a005762fdf0d4ce900'
BEANSTALK_685_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-reviewed-685-99a-source-manifest.json'
BEANSTALK_685_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-reviewed-685-99a-catalog.tar.gz'
CLOUD_SOURCE_685_PREVIOUS_MANIFEST = '35c76659d735fe959a5cb8da1cfa68908dfc6dbdaff8ab9364a32f452fad1db2'
CLOUD_SOURCE_685_PREVIOUS_TREE = 'edb0d25e9e4c812549fd13dca1ccc0567087c6922cd21f1863ba69a8b629be2a'
CLOUD_SOURCE_685_PREVIOUS_ARCHIVE_SHA256 = '025882d07a8da5c3911c35ae77a5db58c807f758028d3ff768bd92c5678b42fb'
CLOUD_SOURCE_685_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-reviewed-685-before-cloud-source-source-manifest.json'
CLOUD_SOURCE_685_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-reviewed-685-before-cloud-source-catalog.tar.gz'
LINEAGE_685_PREVIOUS_MANIFEST = 'e7ca75dc3b85d5048b145e51921b58edf60079deb3a908a9b218595aac3c3e63'
LINEAGE_685_PREVIOUS_TREE = '1000c7cbea096c46e7d25992fb6c504fa0cddf92d462249c5a84c51d547bcee4'
LINEAGE_685_PREVIOUS_ARCHIVE_SHA256 = '2adbea7b6bf681d68e4d3251dd1e21bd09384339206dfdf7955fd6725f4c0b5b'
LINEAGE_685_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-reviewed-685-before-lineage-resolution-source-manifest.json'
LINEAGE_685_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-reviewed-685-before-lineage-resolution-catalog.tar.gz'
APIM_ANCHOR_685_PREVIOUS_MANIFEST = 'a51552d630e44fc5daafae3cbe3e70b3bacc5c81864b1c57885db1f877fd8382'
APIM_ANCHOR_685_PREVIOUS_TREE = 'b5b50df92c4dc30ee8cfc212e6a08fc1f15e4d55a31d92a0879851d61cbdfcc8'
APIM_ANCHOR_685_PREVIOUS_ARCHIVE_SHA256 = '471a7864be4b6dbdfb430e917ec9c1320433b36fa7552cf1ecd1b2574b3eaa79'
APIM_ANCHOR_685_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-reviewed-685-before-apim-anchor-source-manifest.json'
APIM_ANCHOR_685_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-reviewed-685-before-apim-anchor-catalog.tar.gz'
MWAA_TOKEN_REASON_685_PREVIOUS_MANIFEST = '8fb197160ed8f236c554cbb1630256fba47963e0755654fb4f6f017df06d1bc5'
MWAA_TOKEN_REASON_685_PREVIOUS_TREE = '21b9159c4f9de06ef56637214c241da7ef1285e4a72491b1fda6a5a2b094b632'
MWAA_TOKEN_REASON_685_PREVIOUS_ARCHIVE_SHA256 = 'cac08e430052f9b1dda76b9fdc94277ceff6851ca5fc9bd4903145e23707d752'
MWAA_TOKEN_REASON_685_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-reviewed-685-before-mwaa-token-reason-source-manifest.json'
MWAA_TOKEN_REASON_685_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-reviewed-685-before-mwaa-token-reason-catalog.tar.gz'
ECS_REGISTER_685_PREVIOUS_MANIFEST = '497f5f774ae1a7fb53e40f023deff4fd9a995e992cdca540babcbd7d78cc89dd'
ECS_REGISTER_685_PREVIOUS_TREE = '13485c5d9bf71a7cbf4f30cbce0bd56ec854f4cf20196e4ea48040cabb51339c'
ECS_REGISTER_685_PREVIOUS_ARCHIVE_SHA256 = '82f2b532e144331aa0cf950d72ef9d21ab58ce038dcc35ca469071c572f14526'
ECS_REGISTER_685_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-reviewed-685-before-ecs-register-source-manifest.json'
ECS_REGISTER_685_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-reviewed-685-before-ecs-register-catalog.tar.gz'
APPSTREAM_RESOURCE_700_PREVIOUS_MANIFEST = '9c3c20a056723d3a6628f52361c658ed63fa7a6553a799c7d215546b5bc3cd97'
APPSTREAM_RESOURCE_700_PREVIOUS_TREE = 'e2aebb783f31913ad6eb37a511a57cb7a4ec2754cb4c0a33a15e52849aa21833'
APPSTREAM_RESOURCE_700_PREVIOUS_ARCHIVE_SHA256 = '9088e3d467efc69f56e5db4bab566ca26eeb78b40475457c5bd6ff51585c0aa3'
APPSTREAM_RESOURCE_700_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-700-before-appstream-resource-requires-source-manifest.json'
APPSTREAM_RESOURCE_700_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-700-before-appstream-resource-requires-catalog.tar.gz'
SOURCE_REPIN_700_PREVIOUS_MANIFEST = '6e1cd8ac3d631a42a569eeafccf0f5c396e57bfe5946454c77fe213791c3d456'
SOURCE_REPIN_700_PREVIOUS_TREE = '6f29f2951ed59e62d23921036697e09fbf35d5e9e84c977e150449779f1b2aff'
SOURCE_REPIN_700_PREVIOUS_ARCHIVE_SHA256 = 'a239ffcca6bb2e0ac67e170672d56c16e31f06c5407f8466724643791a31ac2c'
SOURCE_REPIN_700_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-700-before-ht-source-repin-source-manifest.json'
SOURCE_REPIN_700_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-700-before-ht-source-repin-catalog.tar.gz'
FINAL_AWS_AUDIT_691_PREVIOUS_MANIFEST = '16e83c81081977912ae81f40981ba0a6ed5ad4cb939ecf3801ef5bd4302e8917'
FINAL_AWS_AUDIT_691_PREVIOUS_TREE = 'bd33c3dc1d491a0daf045d73f7cfcc335b8341456bc47681fe20550d18a63a4c'
FINAL_AWS_AUDIT_691_PREVIOUS_ARCHIVE_SHA256 = 'ecc7ba16e01e8cfbe8b6fb4d9259411e190c2aa98b22bac709de40c071305df6'
FINAL_AWS_AUDIT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-before-final-aws-audit-source-manifest.json'
FINAL_AWS_AUDIT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-before-final-aws-audit-catalog.tar.gz'
FINAL_TWO_ROLE_EFFECTS_691_PREVIOUS_MANIFEST = 'd7f6015a720aa97b48e7407e9e64619a73152ee3d42e866d08a240fa1a65773a'
FINAL_TWO_ROLE_EFFECTS_691_PREVIOUS_TREE = 'a75ba19025307cc03b0e6e26c91a347b0e305944b5b06cad04d48ff9f29c1205'
FINAL_TWO_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256 = '54841a5e8b4f8f163dd726df317b1172ea06811930add95f5abc97c84e785950'
FINAL_TWO_ROLE_EFFECTS_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-final-two-role-effects-source-manifest.json'
FINAL_TWO_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-final-two-role-effects-catalog.tar.gz'
JIT_WORKSPACES_ROLE_EFFECTS_691_PREVIOUS_MANIFEST = '0636ad23bd482cd74de8d137059f35e9e35afafd03f96a0ff2bf0b355c05376e'
JIT_WORKSPACES_ROLE_EFFECTS_691_PREVIOUS_TREE = '25bbdfaee3a2d52119ba1b362ef8ceedd996975cd0e420dd4f40a6c0850ec1fb'
JIT_WORKSPACES_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256 = 'da22d375c778991dacc7963ee37a423199c3888997efaa62770f0f546d760a1c'
JIT_WORKSPACES_ROLE_EFFECTS_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-jit-workspaces-role-effects-source-manifest.json'
JIT_WORKSPACES_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-jit-workspaces-role-effects-catalog.tar.gz'
SERVICECATALOG_ROLE_EFFECTS_691_PREVIOUS_MANIFEST = '9b0bc8606abbebc421d3101090dc8293f27ac2c20c642398aba42e2413a075d3'
SERVICECATALOG_ROLE_EFFECTS_691_PREVIOUS_TREE = '7dd57d2fd79d4024414fe1929ea1d1afa5dcf64d483536f7cd01d9756d3e7301'
SERVICECATALOG_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256 = 'dfb88f423b64d439602d7e6598d5369919467712cea3a2e555711bef8bf3a4c1'
SERVICECATALOG_ROLE_EFFECTS_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-servicecatalog-role-effects-source-manifest.json'
SERVICECATALOG_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-servicecatalog-role-effects-catalog.tar.gz'
MWAA_ROLE_EFFECTS_691_PREVIOUS_MANIFEST = 'c1585b66113b1da29e29dc214fd1a6caff8c3aace230e97e48c1e74ad0657cc9'
MWAA_ROLE_EFFECTS_691_PREVIOUS_TREE = '637e2fbeb83b920d9dba26d8674378ebb71322263ff0cdc1088f5bd4f641e3a4'
MWAA_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256 = '5868f66593505a359d2f2b4f07d040e3ecc031e0fcd1fcb2516162c73ea16745'
MWAA_ROLE_EFFECTS_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-mwaa-role-effects-source-manifest.json'
MWAA_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-mwaa-role-effects-catalog.tar.gz'
MIGRATIONHUB_ROLE_EFFECTS_691_PREVIOUS_MANIFEST = '4259b27bdd6b54410a048045d78549cc966d0f620444a492340c2265d9173db1'
MIGRATIONHUB_ROLE_EFFECTS_691_PREVIOUS_TREE = '3a42fb1524dba200926da33d2bd6290da18ea581fddbd4ed51e84163a8f178bf'
MIGRATIONHUB_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256 = '1d816c7dfc4f5b8a9becf3e064526a59b67466d7c2a4f579ced776c95e98970b'
MIGRATIONHUB_ROLE_EFFECTS_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-migrationhub-role-effects-source-manifest.json'
MIGRATIONHUB_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-migrationhub-role-effects-catalog.tar.gz'
M2_ROLE_EFFECT_691_PREVIOUS_MANIFEST = '683947c2a982ef489e52b2ad6225e55d6c3f63148f3328b66bcb385b97d0259d'
M2_ROLE_EFFECT_691_PREVIOUS_TREE = 'e69a1d5c138e55b58987221c79213ffe918a888d46ea24b66f5a580fd5e09710'
M2_ROLE_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '3fc7680fd06dde5d9eee9316461dd87c73988285a891ef9ae2e47a95790c56eb'
M2_ROLE_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-m2-role-effect-source-manifest.json'
M2_ROLE_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-m2-role-effect-catalog.tar.gz'
LAMBDA_WRAPPER_ROLE_SWAP_691_PREVIOUS_MANIFEST = '808fe54818de6c7bfe57f4303059147ddf01d94b9c884478a7acdfad1af39fe4'
LAMBDA_WRAPPER_ROLE_SWAP_691_PREVIOUS_TREE = 'aa07d8e55e0f8253f8dd47c13fed1edecac0224385afe389979d14c2b07713a5'
LAMBDA_WRAPPER_ROLE_SWAP_691_PREVIOUS_ARCHIVE_SHA256 = '4d3ee8693b6307da31337274f7fd6faf63e09244ffbd38e2f7a893bba2c16f42'
LAMBDA_WRAPPER_ROLE_SWAP_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-lambda-wrapper-role-swap-source-manifest.json'
LAMBDA_WRAPPER_ROLE_SWAP_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-lambda-wrapper-role-swap-catalog.tar.gz'
LAMBDA_EXISTING_SQS_MAPPING_691_PREVIOUS_MANIFEST = 'a1bacd4e6a087020468af4a5c9803af1b2e944e18a1c1f261d15367239d54693'
LAMBDA_EXISTING_SQS_MAPPING_691_PREVIOUS_TREE = 'cc655253fcb6f4c9dacc6b5cebdc87f13b9e22c99c1fac1c0b1625e382a6a3da'
LAMBDA_EXISTING_SQS_MAPPING_691_PREVIOUS_ARCHIVE_SHA256 = '581d0b93b0da72a5bdaccae41a82e47b029ca4c91825a608a003540f2ade7a97'
LAMBDA_EXISTING_SQS_MAPPING_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-lambda-existing-sqs-mapping-source-manifest.json'
LAMBDA_EXISTING_SQS_MAPPING_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-lambda-existing-sqs-mapping-catalog.tar.gz'
LAMBDA_DYNAMODB_STREAM_691_PREVIOUS_MANIFEST = '149ee4df2c24032d7e5c358b6ba3cf3994145f7d4e8eb03cacd3b8b54cdb3a47'
LAMBDA_DYNAMODB_STREAM_691_PREVIOUS_TREE = 'a90eb3081cafb41e12628d21f90c4ecf69602d0cecbb77f4acc4d0cfa8acdf6a'
LAMBDA_DYNAMODB_STREAM_691_PREVIOUS_ARCHIVE_SHA256 = 'e2791f17d01e68a583b37389b9d77b42bae250e95e7f3278bbcbc26b9d26c577'
LAMBDA_DYNAMODB_STREAM_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-lambda-dynamodb-stream-source-manifest.json'
LAMBDA_DYNAMODB_STREAM_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-lambda-dynamodb-stream-catalog.tar.gz'
LAMBDA_EVENTBRIDGE_SCHEDULE_691_PREVIOUS_MANIFEST = 'ad8db405084d457ad28724cf1b345c66b703596796286964271f5be71ffb79e7'
LAMBDA_EVENTBRIDGE_SCHEDULE_691_PREVIOUS_TREE = '5852676e6afd26c332c9a430f614f904440d09404f18a7950ba8e07e22e0abbf'
LAMBDA_EVENTBRIDGE_SCHEDULE_691_PREVIOUS_ARCHIVE_SHA256 = 'f1ade8cffdc69d1dbb092c89b3cf3aad521d6c7fe4b170de95c6d515349f69ba'
LAMBDA_EVENTBRIDGE_SCHEDULE_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-lambda-eventbridge-schedule-source-manifest.json'
LAMBDA_EVENTBRIDGE_SCHEDULE_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-lambda-eventbridge-schedule-catalog.tar.gz'
LAMBDA_MICROVM_CONNECTOR_691_PREVIOUS_MANIFEST = 'a9d71685bba8421057da4c1ea836e485815dda5867a89f9ef0944b9ff9ab1a8d'
LAMBDA_MICROVM_CONNECTOR_691_PREVIOUS_TREE = 'f8c33b8a70df457a93235d4b6f6dcefa5dbaded1da39c6da24b1a1e0ee57db97'
LAMBDA_MICROVM_CONNECTOR_691_PREVIOUS_ARCHIVE_SHA256 = '279a7539f6f53c562e892b5bd33230f7a0d7960a13af5d266f6cca8879c1c8a2'
LAMBDA_MICROVM_CONNECTOR_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-lambda-microvm-connector-source-manifest.json'
LAMBDA_MICROVM_CONNECTOR_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-lambda-microvm-connector-catalog.tar.gz'
KAFKACONNECT_PLUGIN_EFFECT_691_PREVIOUS_MANIFEST = 'b61d767b8374dc6915d52c78553c77fdd0703889925d4ee049133225270f0e10'
KAFKACONNECT_PLUGIN_EFFECT_691_PREVIOUS_TREE = 'c73799a33fd35d03a87222f42fcccd1e26e00ae5db05f829a1daeb7b894cda3b'
KAFKACONNECT_PLUGIN_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = 'b9538a2d459c33dcc43a278d6f95277ed9e1ae03e492c1b8204a60372c8cec65'
KAFKACONNECT_PLUGIN_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-kafkaconnect-plugin-effect-source-manifest.json'
KAFKACONNECT_PLUGIN_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-kafkaconnect-plugin-effect-catalog.tar.gz'
IOT_EXISTING_ALIAS_EFFECT_691_PREVIOUS_MANIFEST = '8309b1b11fed2eefcadd32a92532f6d6d95c421cf822b854f4fe53643fc4f454'
IOT_EXISTING_ALIAS_EFFECT_691_PREVIOUS_TREE = '75efe868ebe1e293ef7cc572e88e66a1db3a7ccbf8628816561a8bb04bb3d0fc'
IOT_EXISTING_ALIAS_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = 'c87c3d421d540861d16e93adce4343b1f01b97ab168c063f55125a6b326b61ec'
IOT_EXISTING_ALIAS_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-iot-existing-alias-effect-source-manifest.json'
IOT_EXISTING_ALIAS_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-iot-existing-alias-effect-catalog.tar.gz'
GLUE_EXTERNAL_SCRIPT_EFFECT_691_PREVIOUS_MANIFEST = '9225c65918dd67e038c1753eae411ccccf2cf31b83d72548f1e621424cd13438'
GLUE_EXTERNAL_SCRIPT_EFFECT_691_PREVIOUS_TREE = '6fe49fa21c83ca15cd3c32f803bdd58c080df5d6807f9bdafd97e36ec70f216e'
GLUE_EXTERNAL_SCRIPT_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = 'ce75fe4c08846ae89e59c8f6bdf28dcb3cfabd41349427db308c66385d4b54d2'
GLUE_EXTERNAL_SCRIPT_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-glue-external-script-effect-source-manifest.json'
GLUE_EXTERNAL_SCRIPT_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-glue-external-script-effect-catalog.tar.gz'
GAMELIFTSTREAMS_SESSION_EFFECT_691_PREVIOUS_MANIFEST = '8ffa2192b4873d378c61865ef16459a70529aed1a2a081164500143060a0bc1b'
GAMELIFTSTREAMS_SESSION_EFFECT_691_PREVIOUS_TREE = '55c05ebddf380fd4153ed664b0c9ec81cafc06e6e9c6fb06596927cae216ba93'
GAMELIFTSTREAMS_SESSION_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '73abab86f21dec872666d59d2a053b452ee85bed4aebf76463fbe71571d73663'
GAMELIFTSTREAMS_SESSION_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-gameliftstreams-session-effect-source-manifest.json'
GAMELIFTSTREAMS_SESSION_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-gameliftstreams-session-effect-catalog.tar.gz'
EVENTS_SUBSCRIBER_EFFECT_691_PREVIOUS_MANIFEST = '119bc1a1db78a8410c732e79e5de8a840acb37ee9bc67417861c775d08989694'
EVENTS_SUBSCRIBER_EFFECT_691_PREVIOUS_TREE = '8d048c0beb291b34ff95f6262ea81ff2d7e5dfd2d28043fdea202cff0d04ca19'
EVENTS_SUBSCRIBER_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = 'dae4f0d10a2b59b65c4f450d15506bda677fa5e296d4e72cd1cf66228126dcad'
EVENTS_SUBSCRIBER_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-events-subscriber-effect-source-manifest.json'
EVENTS_SUBSCRIBER_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-events-subscriber-effect-catalog.tar.gz'
EMR_RUNJOBFLOW_ROLE_691_PREVIOUS_MANIFEST = '03fe4a7c76d7f415eb02e4b7597803718685d72560d38d955dfd8b651c2a6f34'
EMR_RUNJOBFLOW_ROLE_691_PREVIOUS_TREE = '71ef44da2a7265ca85d8210ff8034b72555f8977f631b70b8f3c6f006b3b4cb0'
EMR_RUNJOBFLOW_ROLE_691_PREVIOUS_ARCHIVE_SHA256 = '81e865b66decc19f1c3ec93478de41e49d2c8f93b2b94c7793df5c9efe47bc76'
EMR_RUNJOBFLOW_ROLE_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-emr-runjobflow-role-source-manifest.json'
EMR_RUNJOBFLOW_ROLE_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-emr-runjobflow-role-catalog.tar.gz'
EMR_CLUSTER_ENDPOINT_EFFECT_691_PREVIOUS_MANIFEST = '6e7ba4573077b689e468fbc25d3f5c799ca1f36fe0869e596e27b0492c9e0f58'
EMR_CLUSTER_ENDPOINT_EFFECT_691_PREVIOUS_TREE = 'dba82afc352bd94f6be1623cd330a7f8a0848f68cc3ea2a6124e611f34cdd340'
EMR_CLUSTER_ENDPOINT_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = 'e8f4adc66af1c55bc150f22d18040b3d0225f466e6fe89ac1e1a06dc64cb0345'
EMR_CLUSTER_ENDPOINT_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-emr-cluster-endpoint-effect-source-manifest.json'
EMR_CLUSTER_ENDPOINT_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-emr-cluster-endpoint-effect-catalog.tar.gz'
EMR_SERVERLESS_EFFECT_691_PREVIOUS_MANIFEST = '4524ddab468afa92d40f3607c9e351f6de93921f7dbede6bcd3b39e75adb57e6'
EMR_SERVERLESS_EFFECT_691_PREVIOUS_TREE = 'c879aa77f94a1e60e77aa2b938a0a52eac8ed2e6ea147e8172889bfb9d8db11d'
EMR_SERVERLESS_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '609c179eb2b7b6efefa78e13fe2e218db0b79640a6260df02d74a025ab17d60a'
EMR_SERVERLESS_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-emr-serverless-effect-source-manifest.json'
EMR_SERVERLESS_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-emr-serverless-effect-catalog.tar.gz'
EMR_CONTAINERS_EFFECTS_691_PREVIOUS_MANIFEST = 'df9cab26ec4f109424285231e07076043c13875b9a6b6611c83b834e71f93ed3'
EMR_CONTAINERS_EFFECTS_691_PREVIOUS_TREE = '44bce2b96b4a4f869e0f39b08bcd0754d010694c00fa8384e76de0e5c9184e4d'
EMR_CONTAINERS_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256 = 'aedfc889749778101554d7b3e4062761fb70d733d1ce3eae0e82396b505d1240'
EMR_CONTAINERS_EFFECTS_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-emr-containers-effects-source-manifest.json'
EMR_CONTAINERS_EFFECTS_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-emr-containers-effects-catalog.tar.gz'
BEANSTALK_ROLE_691_PREVIOUS_MANIFEST = '40bd46c6969f7799700385844c6006874aa91a225b1e79f2784ee2e330186505'
BEANSTALK_ROLE_691_PREVIOUS_TREE = 'bcd70ac750a6fecb96abb85391a9d016b93a4caffe8ec7975ebf82a7d7cae547'
BEANSTALK_ROLE_691_PREVIOUS_ARCHIVE_SHA256 = '3036e9041c72b3fac60c45d08ad9c9486e54708f0cbc5352f3f713260c5b404a'
BEANSTALK_ROLE_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-beanstalk-role-source-manifest.json'
BEANSTALK_ROLE_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-beanstalk-role-catalog.tar.gz'
SPOT_REQUEST_ROLE_691_PREVIOUS_MANIFEST = '445fb7835e3303586a551a219e83d73e4c77e77a7270e75cc3e27eb46d2ec174'
SPOT_REQUEST_ROLE_691_PREVIOUS_TREE = '48eefdfcc9f687f06c590d522f137fb569a2b53e15bc9c39fae8320f4961ffa5'
SPOT_REQUEST_ROLE_691_PREVIOUS_ARCHIVE_SHA256 = '07ea04daa17cf96d3b7543b8ed1493ec0a975d0cb4f0e6bd66cd015fc9dd13ba'
SPOT_REQUEST_ROLE_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ec2-spot-request-role-source-manifest.json'
SPOT_REQUEST_ROLE_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ec2-spot-request-role-catalog.tar.gz'
RUNINSTANCES_ROLE_691_PREVIOUS_MANIFEST = 'f70e1f998ef4136cf6b8bdb9664a9d6b593dac8de60edfc3fd79a8cc91d56de6'
RUNINSTANCES_ROLE_691_PREVIOUS_TREE = '521364463ac882acedcd99116c7b0161dab13b7c75511893c5985f858a1511c8'
RUNINSTANCES_ROLE_691_PREVIOUS_ARCHIVE_SHA256 = 'd6ac1e8b8af545842b042dba0b69f6c3397566fb0f6c82b86d20f26321aac23c'
RUNINSTANCES_ROLE_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ec2-runinstances-role-source-manifest.json'
RUNINSTANCES_ROLE_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ec2-runinstances-role-catalog.tar.gz'
SPOT_FLEET_ROLE_EXECUTION_691_PREVIOUS_MANIFEST = '100d1cde6bb9d2f4b9f2013d2ac2018000b1ec8bc225cbff9d96f69f57b40ef3'
SPOT_FLEET_ROLE_EXECUTION_691_PREVIOUS_TREE = 'a24cf4db7290f5cfae30526b5bcdb53afcc1a2462504bb4f050fa63dfa93a3fc'
SPOT_FLEET_ROLE_EXECUTION_691_PREVIOUS_ARCHIVE_SHA256 = 'b64b65881beb5b7a33f6024d184edecfa43c58bd289cebed4cd9ad9ba9e5a6f9'
SPOT_FLEET_ROLE_EXECUTION_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-spot-fleet-role-execution-source-manifest.json'
SPOT_FLEET_ROLE_EXECUTION_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-spot-fleet-role-execution-catalog.tar.gz'
ASG_ROLE_EXECUTION_691_PREVIOUS_MANIFEST = '08bc5b6f6e16d0d09dba37da2b9b6ffbe3f4a59c36ffd74c2f32727239fab044'
ASG_ROLE_EXECUTION_691_PREVIOUS_TREE = '1ea8b62f3b72d69c8a7d500d3c6d14aafc1bed55ab13503dccbf1916f2f1f7df'
ASG_ROLE_EXECUTION_691_PREVIOUS_ARCHIVE_SHA256 = 'e924d01c79467da195ec0e3db381c9775705bcaeb21e86f978ac246538cf2787'
ASG_ROLE_EXECUTION_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-asg-role-execution-source-manifest.json'
ASG_ROLE_EXECUTION_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-asg-role-execution-catalog.tar.gz'
DEVICEFARM_EXISTING_SPEC_691_PREVIOUS_MANIFEST = '05f715c7b2a667e518cc751fcc0f57d49f75188c9fc2a47a0a086245c5ac5351'
DEVICEFARM_EXISTING_SPEC_691_PREVIOUS_TREE = 'c09df9838459cc86a9dd91e3469ffd59666e67c7820e2053b67019eeeb10ab43'
DEVICEFARM_EXISTING_SPEC_691_PREVIOUS_ARCHIVE_SHA256 = 'ac65bc08a85e454b0118949e703c701e810deb5855bdc424f2fc49bf76bbedf1'
DEVICEFARM_EXISTING_SPEC_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-devicefarm-existing-spec-source-manifest.json'
DEVICEFARM_EXISTING_SPEC_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-devicefarm-existing-spec-catalog.tar.gz'
DEADLINE_FLEET_WORKER_691_PREVIOUS_MANIFEST = '751d050355a10ab0e8fa2799aaffdded09f5a43a3b9237b8673b2600bc84f7b1'
DEADLINE_FLEET_WORKER_691_PREVIOUS_TREE = 'd3fa923b195c8699d70a49f1a2f84e05cdcd997f9db5664dc7638017f2a9534a'
DEADLINE_FLEET_WORKER_691_PREVIOUS_ARCHIVE_SHA256 = 'a356613ea594108da6cee5ba6390bc1904aba625cb84d7fca7806a8c245d87a1'
DEADLINE_FLEET_WORKER_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-deadline-fleet-worker-source-manifest.json'
DEADLINE_FLEET_WORKER_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-deadline-fleet-worker-catalog.tar.gz'
DEADLINE_QUEUE_ROLE_691_PREVIOUS_MANIFEST = '43040a7f54bad49f6323c791ef2f94b007d8d5ffa33331c68092ff81a0f62bd4'
DEADLINE_QUEUE_ROLE_691_PREVIOUS_TREE = 'df00a649303f1e86707741333135fd61e1d3c592c6ad02adf79131a0eb81e922'
DEADLINE_QUEUE_ROLE_691_PREVIOUS_ARCHIVE_SHA256 = '7f727b5dcae4caa7b64f3d854d478fd2d3d464d49b5ae2133f4bf434e55b6a90'
DEADLINE_QUEUE_ROLE_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-deadline-queue-role-source-manifest.json'
DEADLINE_QUEUE_ROLE_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-deadline-queue-role-catalog.tar.gz'
DATAPIPELINE_EC2_EFFECT_691_PREVIOUS_MANIFEST = '0682a00e35dbb252b0fffed851879d5a9c4162bba7369aa1a7a47a949cca3b6d'
DATAPIPELINE_EC2_EFFECT_691_PREVIOUS_TREE = '28ecc1e2b08572b83fa7e7bf0484f5edf070a71614da7412306487a1235bc4fd'
DATAPIPELINE_EC2_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '0b4a56d69bec29359a5281762ffa27b197f5774089642a6015ce041df2b5b11a'
DATAPIPELINE_EC2_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-datapipeline-ec2-effect-source-manifest.json'
DATAPIPELINE_EC2_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-datapipeline-ec2-effect-catalog.tar.gz'
CONFIG_REMEDIATION_EFFECT_691_PREVIOUS_MANIFEST = '1d8f99c9d913646252bd474a3ad92a5699338db47202f780b03b932ddddb203f'
CONFIG_REMEDIATION_EFFECT_691_PREVIOUS_TREE = 'dc5df1ad639d304f62a52178dfd3596f1640290805b616824fd6ac387fe0ca6d'
CONFIG_REMEDIATION_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '6f15518842e3b14986dfeac205ab16012778f4880f2563259e935dc747f564e3'
CONFIG_REMEDIATION_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-config-remediation-effect-source-manifest.json'
CONFIG_REMEDIATION_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-config-remediation-effect-catalog.tar.gz'
CODEPIPELINE_EXISTING_EFFECT_691_PREVIOUS_MANIFEST = 'ae5e96ad4586978f3311a6130e70bb4141ceb02038c8650a919ef0e7ffef70cf'
CODEPIPELINE_EXISTING_EFFECT_691_PREVIOUS_TREE = '59ac76acff80f53a07977091f089941b18dae89259d37e6aa59586de400fa6f8'
CODEPIPELINE_EXISTING_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = 'd62060b85e3e73515b8d6fb4e3121a0e6ae489f942cc62ae756caf4010194618'
CODEPIPELINE_EXISTING_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-codepipeline-existing-effect-source-manifest.json'
CODEPIPELINE_EXISTING_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-codepipeline-existing-effect-catalog.tar.gz'
CODEBUILD_DEBUG_EFFECT_691_PREVIOUS_MANIFEST = '106a947e61441c3cffdd19e5fbd946aa1612b20c5a58096322610efd68ccbe2e'
CODEBUILD_DEBUG_EFFECT_691_PREVIOUS_TREE = '5eca6d1452fea5baa32d1c28f8729148de4612852709e1084e7aca46d1d32d5b'
CODEBUILD_DEBUG_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '014d557f0c7c2178245ba8820efec5f591e95cf824e143652c5f337c8f012697'
CODEBUILD_DEBUG_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-codebuild-debug-effect-source-manifest.json'
CODEBUILD_DEBUG_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-codebuild-debug-effect-catalog.tar.gz'
SSM_EXISTING_AUTOMATION_EFFECT_691_PREVIOUS_MANIFEST = 'f8336a45e947eda18a1580f331e11db183c05a2a522019ce4d162a5704ba21f5'
SSM_EXISTING_AUTOMATION_EFFECT_691_PREVIOUS_TREE = 'a57ad15997ffacee374dac42b8325cc9fcd9f99526f8e1b200112aff39be686e'
SSM_EXISTING_AUTOMATION_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '80e41e97555f5fd223021751998030aae48bfacc7fad6ae1bb7c9e789cf2d20f'
SSM_EXISTING_AUTOMATION_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ssm-existing-automation-effect-source-manifest.json'
SSM_EXISTING_AUTOMATION_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ssm-existing-automation-effect-catalog.tar.gz'
BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_MANIFEST = '51ad72ee8e05dacaca2b532cd851d8527a00930bb7475d5e2154ea1b6059158d'
BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_TREE = 'a3334fa6d17032c44e0f37cd1d83b1aadfdc4247fe836ca616a66494911714d1'
BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '2c5161a4c90c79611b2a2c1694527376fd5cf2f5b28733c69c03910f59cb008b'
BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-bedrock-actiongroup-effect-source-manifest.json'
BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-bedrock-actiongroup-effect-catalog.tar.gz'
AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_MANIFEST = '8ce864b0fe471254abb80bfeb68cdb5146692eda4be282494a3c5fb771a6c9be'
AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_TREE = '739e8413a050127100d094cca16689ded67edc500866d7924b23c8b234cd1628'
AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '721afb18982a26ee59e145e703e744bf022a3170439f62dd09070348b7ed0e7e'
AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-harness-effect-source-manifest.json'
AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-harness-effect-catalog.tar.gz'
AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_MANIFEST = '49ef0c95f71e891a4604037d0197d90fe455c829fedcbd54c0e800c4351a7db0'
AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_TREE = '7a122fab5b7a1ae53982a2bdf557863210f5d6188366aa006a9628724a3faa64'
AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256 = 'cfb29edb1ebb14ea22f727b7b3f949bc2beebb9f6583cc6bbabe1cb246f8ca0d'
AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-runtime-effects-source-manifest.json'
AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-runtime-effects-catalog.tar.gz'
AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_MANIFEST = '5b905aecc542a60efecc97e6403d740ef7c9f770bdfe4ae93b2f2a0e42bd6a86'
AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_TREE = '8a8eaeb5628ea6111417f2f73d6e2243b1ff59edf9a87e623a99a7dd3f71676f'
AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256 = 'b133c40b7d937de0592a2b4b3293f9e1b2e014269171e4f37004b2980fbb183d'
AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-amplify-role-effects-source-manifest.json'
AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-amplify-role-effects-catalog.tar.gz'
CFN_STACKSET_EFFECTS_691_PREVIOUS_MANIFEST = 'f3bfba9621bff59733dc98b0fe121aa5bb3c68c719ad2e7068f37a9e66ce56c0'
CFN_STACKSET_EFFECTS_691_PREVIOUS_TREE = 'b025978c4283bb3280a2ddefc075e89d9309d12526b05ed870d8a077494c75b9'
CFN_STACKSET_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256 = 'bbed62b8b77c872a0a594ff51de1fad951633972b9040b23ab6bbe2921df1d3c'
CFN_STACKSET_EFFECTS_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-cfn-stackset-effects-source-manifest.json'
CFN_STACKSET_EFFECTS_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-cfn-stackset-effects-catalog.tar.gz'
CFN_EXTENSION_EFFECT_691_PREVIOUS_MANIFEST = 'd9a85c3da367de77a3dcf10ef968edbd918119346efab80e8f94bec62c9e7b91'
CFN_EXTENSION_EFFECT_691_PREVIOUS_TREE = '558fe51a5c9922b03131ec96f4c917ab73d54b179c87c033b948ae3d0c3e35b4'
CFN_EXTENSION_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '57db9b70702d20b6e459f818a2c46c75f6c874168142923c9266d30f8e447dc3'
CFN_EXTENSION_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-cfn-extension-effect-source-manifest.json'
CFN_EXTENSION_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-cfn-extension-effect-catalog.tar.gz'
CFN_TEMPLATE_EFFECT_691_PREVIOUS_MANIFEST = 'f3ed89fd4e4884b3e526ddbcf04fd202b3c56be995f97bf46cc9d4fd35bdae95'
CFN_TEMPLATE_EFFECT_691_PREVIOUS_TREE = 'd8a6d6eecd5a1549e40e7b5844b0d7a73c5c83d84c9b5eff5460bda963ed0f8b'
CFN_TEMPLATE_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '2f3a3ff201aceaa530fc66f593a279bc3a4cb228e0b9f5149b4a7e457e07f99d'
CFN_TEMPLATE_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-cfn-template-effect-source-manifest.json'
CFN_TEMPLATE_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-cfn-template-effect-catalog.tar.gz'
TESTSTATE_ROLE_EFFECT_691_PREVIOUS_MANIFEST = 'f0586639b1ad4837cac0dc5b12806d0ced42bb2fb0c4aa1328e3f2afb7e88fb7'
TESTSTATE_ROLE_EFFECT_691_PREVIOUS_TREE = '363415fa117bdacb6974de883392d7a6a1da3b54eb4f06bc8ace64714003671a'
TESTSTATE_ROLE_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '3b17dbdb69bf3ab6a2f8ec64211e94a6109bda3d8d8d0396fbd5f8c38f9b6c10'
TESTSTATE_ROLE_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-teststate-role-effect-source-manifest.json'
TESTSTATE_ROLE_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-teststate-role-effect-catalog.tar.gz'
SFN_ROLE_EFFECT_691_PREVIOUS_MANIFEST = '530170809258602823f876081bb4c85b2817c0d62f5161344652189ea0924c43'
SFN_ROLE_EFFECT_691_PREVIOUS_TREE = '16825d2b867b660efb9d3e7f47bc47542f9ca5b0e97d9a8b631e60f5123d5644'
SFN_ROLE_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '21d3cef33b6297fee68ae4674b6b9f8aeadcc5a32531328cd95103c545307a67'
SFN_ROLE_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sfn-role-effect-source-manifest.json'
SFN_ROLE_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sfn-role-effect-catalog.tar.gz'
INSTANCE_CONNECT_WITNESS_691_PREVIOUS_MANIFEST = 'f868300f0dd2c8c4cec0e77aa8bb2e9a23b44c8fa740d6c9566134bdd589cbd1'
INSTANCE_CONNECT_WITNESS_691_PREVIOUS_TREE = '7fa8d5aee2d834b447c4044e7c3de29dff646646b053e60dff16ab1da95cee2b'
INSTANCE_CONNECT_WITNESS_691_PREVIOUS_ARCHIVE_SHA256 = '1e8854b793889ad9ba630f8a3b66eed206809d6888269ebd793c5c50cc59c18c'
INSTANCE_CONNECT_WITNESS_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-instance-connect-witness-source-manifest.json'
INSTANCE_CONNECT_WITNESS_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-instance-connect-witness-catalog.tar.gz'
ECS_TASKSET_691_PREVIOUS_MANIFEST = 'f1a9881cb26ee82add04203c590a097dfcbbda3d28e494f6e88bd2cb9340aec3'
ECS_TASKSET_691_PREVIOUS_TREE = 'fcf5b88f42934843baf95fe1d0c5d4cea59014de4f4965964c358d6ea915996d'
ECS_TASKSET_691_PREVIOUS_ARCHIVE_SHA256 = 'd9e3f7d8b25b396c1db7fa6f194f379a6e414a9817df6c20bda14d84f2c05cce'
ECS_TASKSET_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-taskset-source-manifest.json'
ECS_TASKSET_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-taskset-catalog.tar.gz'
ECS_NODE_ESCAPE_691_PREVIOUS_MANIFEST = '5561563fabef7927c2763f40b5a04ba3ceb544cdf47674fe0b7f898f96c40583'
ECS_NODE_ESCAPE_691_PREVIOUS_TREE = '5550788c8db2fc527af237a77d9477597038ed825c171c95dd162a71c24d2800'
ECS_NODE_ESCAPE_691_PREVIOUS_ARCHIVE_SHA256 = '9cf128317951805677d171707eca8641c6147dcd2428fe9488e9e1a51eed3c7d'
ECS_NODE_ESCAPE_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-node-escape-source-manifest.json'
ECS_NODE_ESCAPE_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-node-escape-catalog.tar.gz'
ECS_SERVICE_691_PREVIOUS_MANIFEST = 'f677bda213c14acfb265232020ac1f40299d9a578b1c245b8cc4997afdcd669f'
ECS_SERVICE_691_PREVIOUS_TREE = '1d5715aa0b5bab28f619adf3bf28f5843d7b320bfea0b1cfa3cc7869d1f09ed9'
ECS_SERVICE_691_PREVIOUS_ARCHIVE_SHA256 = 'ace7f8bf08f5b4cc6246f0f6447617370b64a2ec98fbe668892be308c9556b9a'
ECS_SERVICE_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-service-source-manifest.json'
ECS_SERVICE_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-service-catalog.tar.gz'
ECS_START_TASK_691_PREVIOUS_MANIFEST = 'cc82aa1ec6b773f74eae2c9cd1151117fa5b4429d49db99e21361a6340af04c5'
ECS_START_TASK_691_PREVIOUS_TREE = '0ff0d0acb3b498cfe7ff075c67997faf7ff9c90530f30636106a228c221d6a57'
ECS_START_TASK_691_PREVIOUS_ARCHIVE_SHA256 = '655e6b485b22bf6acb720b6f06440d8d9e7228d1a2a9f5c811210f60309561d0'
ECS_START_TASK_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-start-task-source-manifest.json'
ECS_START_TASK_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-start-task-catalog.tar.gz'
ECS_NEW_TASK_691_PREVIOUS_MANIFEST = 'eaa7ebf65018ebf1050dd6e0da0f0fe5faeba1cb8860e58d767ff5514f1b26a0'
ECS_NEW_TASK_691_PREVIOUS_TREE = '14c112c88b85e8b2b7931b3bc1188be670c78101f832b5af82d623b57976f35e'
ECS_NEW_TASK_691_PREVIOUS_ARCHIVE_SHA256 = '5df7bb9d79c556cfb7434981f7e9c25385d3cd37d7f70a309c3521021350e528'
ECS_NEW_TASK_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-new-task-source-manifest.json'
ECS_NEW_TASK_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-new-task-catalog.tar.gz'
ORGANIZATIONS_RCP_691_REVISIONLESS_MANIFEST = '7d528406be7793c99131834f3b4747dbf14fec5ac0515d813c60949670c1baba'
ORGANIZATIONS_RCP_691_REVISIONLESS_TREE = 'e2aebb783f31913ad6eb37a511a57cb7a4ec2754cb4c0a33a15e52849aa21833'
ORGANIZATIONS_RCP_691_PREVIOUS_MANIFEST = 'fb78323d003a13e56cb130b11cbc5b5236bd91c31a67f0cc81c5aae05eaac45e'
ORGANIZATIONS_RCP_691_PREVIOUS_TREE = 'e79cf10386508df546b33f8383e78907948571eaf6479b2047a8a45683b65ae8'
ORGANIZATIONS_RCP_691_PREVIOUS_ARCHIVE_SHA256 = '511107dedd9565230d7b23cd67856f2d4c658e2429460796cf8b9fb097c38c6f'
ORGANIZATIONS_RCP_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-organizations-rcp-source-manifest.json'
ORGANIZATIONS_RCP_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-organizations-rcp-catalog.tar.gz'
LAMBDA_SIGNER_691_PREVIOUS_MANIFEST = '8307e36f62dcbb54c919323e0d64ada6c22eea1d9eb24fd0226206b11614c08b'
LAMBDA_SIGNER_691_PREVIOUS_TREE = 'd3922e48ac9141556673d0efc1abd97ba6098dd5da25ae2adb4e205a5ae40a9c'
LAMBDA_SIGNER_691_PREVIOUS_ARCHIVE_SHA256 = 'b0a1b2f8cdbba10a915270d3d1f92fb20652f986c856ee3da267f0fdcbc5b2bf'
LAMBDA_SIGNER_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-lambda-signer-source-manifest.json'
LAMBDA_SIGNER_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-lambda-signer-catalog.tar.gz'
BEDROCK_ACTIONGROUP_691_PREVIOUS_MANIFEST = '3fdcb007a021b3ef361042ab08f872b94b4fbd9f8a9dd75cb559121ab151b548'
BEDROCK_ACTIONGROUP_691_PREVIOUS_TREE = '6afe893eae9983f5ade792d4843859d17345e976d42059c20956006f05239b28'
BEDROCK_ACTIONGROUP_691_PREVIOUS_ARCHIVE_SHA256 = 'e6b9c6578202c95cd66f6c884bd8ba2ca15fc3211361937dad140e6e06807347'
BEDROCK_ACTIONGROUP_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-bedrock-actiongroup-source-manifest.json'
BEDROCK_ACTIONGROUP_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-bedrock-actiongroup-catalog.tar.gz'
QUICKSIGHT_IAM_USER_691_PREVIOUS_MANIFEST = '19bf9a8082fa3a377c618ad7913031984c5e26a284eb97973db4e2a3ad247b6c'
QUICKSIGHT_IAM_USER_691_PREVIOUS_TREE = 'aae59f4e332677bf53b6a818be971322e6b3dd6abaa235d656d0e4ad091dc7cc'
QUICKSIGHT_IAM_USER_691_PREVIOUS_ARCHIVE_SHA256 = '0442c1a94aa226ca060762d87057a63472b0c1dfb84238698708276f4645a2c6'
QUICKSIGHT_IAM_USER_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-quicksight-iam-user-source-manifest.json'
QUICKSIGHT_IAM_USER_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-quicksight-iam-user-catalog.tar.gz'
KAFKACONNECT_GUARD_691_PREVIOUS_MANIFEST = 'ca9cdc54975419f2a34f0f63b21f786020a29cc1805bfd10e7e7c708206b6724'
KAFKACONNECT_GUARD_691_PREVIOUS_TREE = 'dbea3e2c627b7f6eba5419a35136c0e64a494a515dda2a908cbd3ae322d712ec'
KAFKACONNECT_GUARD_691_PREVIOUS_ARCHIVE_SHA256 = '47f2d1ddebce44c6a0ec35227fb2755a0354ed15c69f64d1dc742e7613fff409'
KAFKACONNECT_GUARD_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-kafkaconnect-guard-source-manifest.json'
KAFKACONNECT_GUARD_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-kafkaconnect-guard-catalog.tar.gz'
BRAKET_SCRIPT_691_PREVIOUS_MANIFEST = '0ce8c76fdce5d95d95e0356a00a4b0d74c83dda2978ad01e6a1f6b2aeabbd0ef'
BRAKET_SCRIPT_691_PREVIOUS_TREE = 'e9066dcaa6f9922dc2c052b40b91890b080050196a18a91813569b424fa6c648'
BRAKET_SCRIPT_691_PREVIOUS_ARCHIVE_SHA256 = '116de18203795165e7fadd8e3b9a3aadfd2a6ab7b24ceb6f5abee22a0709bd7e'
BRAKET_SCRIPT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-braket-script-source-manifest.json'
BRAKET_SCRIPT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-braket-script-catalog.tar.gz'
SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_MANIFEST = '392a4be387c23be959eb5f576754139a927dd25d1792a8d449c3ee60d5773200'
SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_TREE = 'f3583c06bde667bfd76875c5e26d419c48da172f627a7102764c28a8e814d3a7'
SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_ARCHIVE_SHA256 = '052a888ebaa2aa10575e91231642ea5e62018490f0691ab3486e172c664185ed'
SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-domain-default-source-manifest.json'
SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-domain-default-catalog.tar.gz'
SAGEMAKER_ROLE_SWAP_691_PREVIOUS_MANIFEST = '56ae535cd55189ad085897b4827810fc54b0a22a1ea3257ae9f8f2b64febb640'
SAGEMAKER_ROLE_SWAP_691_PREVIOUS_TREE = 'c5d892bce674772fd331fd1dade9179dd2585862ac6a59307b67d9d80b676dc5'
SAGEMAKER_ROLE_SWAP_691_PREVIOUS_ARCHIVE_SHA256 = 'fe2e845edbdc735fd8004f0ac1a711a4bcf22c109fae5800bd4674e2fa55ac14'
SAGEMAKER_ROLE_SWAP_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-role-swap-source-manifest.json'
SAGEMAKER_ROLE_SWAP_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-role-swap-catalog.tar.gz'
SAGEMAKER_NEW_PROFILE_691_PREVIOUS_MANIFEST = '4dcaaedf17e9a32f4be83a2bdf2b89449d0e26f50e2ceebcdcd660654a076b58'
SAGEMAKER_NEW_PROFILE_691_PREVIOUS_TREE = '3be383bad95b339d945719d0f945077b49ed3cba1e7e836ccb256d520bd44def'
SAGEMAKER_NEW_PROFILE_691_PREVIOUS_ARCHIVE_SHA256 = 'c8f9b66155d2048e71eba4afadddbc8a59b50b3781efb5ebd2031c93d9bb51c6'
SAGEMAKER_NEW_PROFILE_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-new-profile-source-manifest.json'
SAGEMAKER_NEW_PROFILE_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-new-profile-catalog.tar.gz'
SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_MANIFEST = '0f335824eeb4cc48a61e8933dafb44e642ad6d6ae14a6b505cd69a2adb718add'
SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_TREE = '3aff7843f0fa840ec3972b1e45135ab115bbc7a9d42e7c9d5942dfe10d5acdd5'
SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_ARCHIVE_SHA256 = '8e18ccbe4fe86756a95178897dfa68c67becf4198378b0efca0af924212b49b9'
SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-studio-profile-source-manifest.json'
SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-studio-profile-catalog.tar.gz'
SAGEMAKER_HPO_691_PREVIOUS_MANIFEST = '89035f1582caf6c7432d96e9588c9fefb12672f0c7803bf18237c5de6333a07e'
SAGEMAKER_HPO_691_PREVIOUS_TREE = 'd1da99310af26bc3bf72599cb916b73ecfd5f2bdf7e2c49985686b9ee02b038e'
SAGEMAKER_HPO_691_PREVIOUS_ARCHIVE_SHA256 = 'c2ad00104eb25ae4b053915e9fa50a1ce6a71bbf135fad2f6593c31d88701855'
SAGEMAKER_HPO_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-hpo-source-manifest.json'
SAGEMAKER_HPO_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-hpo-catalog.tar.gz'
SAGEMAKER_TRAINING_691_PREVIOUS_MANIFEST = 'fa4f4499c5cb0a1ea4dc496168823bf43793442796e3dc05f9ea9fed9a2cdec0'
SAGEMAKER_TRAINING_691_PREVIOUS_TREE = '231f6c0a3e59f7657ef024e97092eecba2806d7d1be6ba77827cd121b4df1cba'
SAGEMAKER_TRAINING_691_PREVIOUS_ARCHIVE_SHA256 = '504045ad4a28c0f86e68f4c633af9ee23e4d3e69415b8f06b507a400aab3f8fa'
SAGEMAKER_TRAINING_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-training-source-manifest.json'
SAGEMAKER_TRAINING_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-training-catalog.tar.gz'
SAGEMAKER_PROCESSING_691_PREVIOUS_MANIFEST = '0a7b194cdaceb8c90e1595914f39a8d40aef3b30c56364ccf6473d3263b7068e'
SAGEMAKER_PROCESSING_691_PREVIOUS_TREE = 'de0d1a5f2bdc6f27fb016007c6f7d3963a6b40b7c7be3c1bebadf979468f76a3'
SAGEMAKER_PROCESSING_691_PREVIOUS_ARCHIVE_SHA256 = 'be0662361f363634bb51f05a1b2f80b3dfad55f93ea25050e857b0c2412ef2e4'
SAGEMAKER_PROCESSING_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-processing-source-manifest.json'
SAGEMAKER_PROCESSING_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-processing-catalog.tar.gz'
SAGEMAKER_JOBS_691_PREVIOUS_MANIFEST = '47fdcba8d133a306b9317f2bcad6c7a77e96d12a65123d2f486dfd0700f68c04'
SAGEMAKER_JOBS_691_PREVIOUS_TREE = '848f9d1792a34ea8c00efad0bf1937b21ed2b9f93a15aee1829b245e1fc79304'
SAGEMAKER_JOBS_691_PREVIOUS_ARCHIVE_SHA256 = '7cbfcb11a726a8475fae954481fea6db84b47309ab7c46d8a9cc54b288216833'
SAGEMAKER_JOBS_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-jobs-source-manifest.json'
SAGEMAKER_JOBS_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-jobs-catalog.tar.gz'
AGENTCORE_HARNESS_691_PREVIOUS_MANIFEST = '81627b08898b863af35f59a5332f7621f8aa8d06cd375b7f9753e733da3e2395'
AGENTCORE_HARNESS_691_PREVIOUS_TREE = 'ea1e585646eaea4c98b43fca034d006cae9fd40f03cf288f98862b5649aea6cf'
AGENTCORE_HARNESS_691_PREVIOUS_ARCHIVE_SHA256 = '2adc4f6ac05da00f15b583d67f1b352398b2fb2a434d2308e46d57a468ae88c0'
AGENTCORE_HARNESS_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-harness-source-manifest.json'
AGENTCORE_HARNESS_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-harness-catalog.tar.gz'
AGENTCORE_CREATE_691_PREVIOUS_MANIFEST = 'f92c37efdda62e967b9d9ade6e8e54177d6aee388adccadab7f56ac285dc4962'
AGENTCORE_CREATE_691_PREVIOUS_TREE = 'e236cb6644af345fccdbb4fc360ecba35cc1da5eadaf416dd64ef1d17d718399'
AGENTCORE_CREATE_691_PREVIOUS_ARCHIVE_SHA256 = 'b97efb36f1a85326abd19a80d0276460962daac558e9ed37e155a1362abca530'
AGENTCORE_CREATE_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-create-source-manifest.json'
AGENTCORE_CREATE_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-create-catalog.tar.gz'
AGENTCORE_RUNTIME_691_PREVIOUS_MANIFEST = 'ac9b5fef566fed0d17edec1e7c59851693e7f046791eb17372eb3ea6e4917f08'
AGENTCORE_RUNTIME_691_PREVIOUS_TREE = 'b24b77793e75ed4604d2ef9e9a4ac80f1f5285c0cdc38d1f66952537ca4a416f'
AGENTCORE_RUNTIME_691_PREVIOUS_ARCHIVE_SHA256 = '7e06d00f5871dadeca62ce7826945ebebcfc9e30b6037e7729150553a6e47d96'
AGENTCORE_RUNTIME_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-runtime-source-manifest.json'
AGENTCORE_RUNTIME_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-runtime-catalog.tar.gz'
AGENTCORE_EXISTING_690_PREVIOUS_MANIFEST = 'a7a84dd20d61b4083c7be91e42c54f93bf4d4f7cb1e87a1521a18127979d5e5e'
AGENTCORE_EXISTING_690_PREVIOUS_TREE = '5c64f696e91db857c524df563419f870dc80beb12573d16d269a7cf365894786'
AGENTCORE_EXISTING_690_PREVIOUS_ARCHIVE_SHA256 = '08c960e9e96e2e20f96c58a707438e0d2f5b4472fddbe86cf0481675a1e373f2'
AGENTCORE_EXISTING_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-agentcore-existing-source-manifest.json'
AGENTCORE_EXISTING_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-agentcore-existing-catalog.tar.gz'
AGENTCORE_BOUNDS_690_PREVIOUS_MANIFEST = '6460f3bdd25bb05f15a3a33b2b23c57781b28fce63fe44a7d3a7bcf51f9aa495'
AGENTCORE_BOUNDS_690_PREVIOUS_TREE = '3e4ea09bcfbec4ae862853d6893a9a280e68508586151afe84c674d45d2bb629'
AGENTCORE_BOUNDS_690_PREVIOUS_ARCHIVE_SHA256 = '1a1ac60d7cf7943142fa79efdef01e976eb04dd971d5597e2e53a7f334cc162d'
AGENTCORE_BOUNDS_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-agentcore-bounds-source-manifest.json'
AGENTCORE_BOUNDS_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-agentcore-bounds-catalog.tar.gz'
STS_FEDERATION_690_PREVIOUS_MANIFEST = '01fd53c0626d86f93074ff5bf9df156a9669fbfdcde49e4fdf62e98651800177'
STS_FEDERATION_690_PREVIOUS_TREE = '6f53ecb88d28c8d85b5662af8bab7d057593105d4a6d00a16f04e6c35ca3cae9'
STS_FEDERATION_690_PREVIOUS_ARCHIVE_SHA256 = '733288886fe9cc1ffb823613cb4e35701bcb25d9ddb9664d12546985fd1c0e3e'
STS_FEDERATION_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-sts-federation-source-manifest.json'
STS_FEDERATION_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-sts-federation-catalog.tar.gz'
AMPLIFY_ROLE_690_PREVIOUS_MANIFEST = 'd7b5b4a730dd083dd61bd5cf7e7811347b93e00a884282b0c83574fea0f4596f'
AMPLIFY_ROLE_690_PREVIOUS_TREE = 'aac314c56a9ec863567616f8046c0e007ffc5febd7305b4710c0758ad545160f'
AMPLIFY_ROLE_690_PREVIOUS_ARCHIVE_SHA256 = '027497fb9af5db2481b84160433349234e2b3396fa88e4847678cd301cd43e65'
AMPLIFY_ROLE_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-amplify-role-source-manifest.json'
AMPLIFY_ROLE_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-amplify-role-catalog.tar.gz'
EMR_RUNTIME_689_PREVIOUS_MANIFEST = '91c90190da87604f641fc64670f698cfdf4fb8d68b7ecd8a17176bcf2025866f'
EMR_RUNTIME_689_PREVIOUS_TREE = '3b779fee9682b4b10ed7e72be534371528d23007f35ab6a041785e5ca66ed02f'
EMR_RUNTIME_689_PREVIOUS_ARCHIVE_SHA256 = '172462e09fd16c782ebc5ec20eca46a26f21c6aa9be51c2a94dd1cb1ce972262'
EMR_RUNTIME_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-emr-runtime-source-manifest.json'
EMR_RUNTIME_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-emr-runtime-catalog.tar.gz'
ELASTICBEANSTALK_EFFECT_689_PREVIOUS_MANIFEST = '093fc183e5cd8f1b97afd29330d06e8aa5c4ce6bcd4a9a01236ab3ff6ac3c936'
ELASTICBEANSTALK_EFFECT_689_PREVIOUS_TREE = 'f4a38f3b6628abbb56b900b6a740aa7406be26a95512bce16b42845778b87663'
ELASTICBEANSTALK_EFFECT_689_PREVIOUS_ARCHIVE_SHA256 = '649bcd860061403ebd63f4b342133179fcdf45db124a19ad212c7284f375da1a'
ELASTICBEANSTALK_EFFECT_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-elasticbeanstalk-effect-source-manifest.json'
ELASTICBEANSTALK_EFFECT_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-elasticbeanstalk-effect-catalog.tar.gz'
CONFIG_REMEDIATION_689_PREVIOUS_MANIFEST = '7ce57468896503c2d0d674e3588357872b5e9d9e4a182f78471d1b66988f3b47'
CONFIG_REMEDIATION_689_PREVIOUS_TREE = '3847c9b4ef67600aebfcbfaf0d1866faeaea1f4e27a69fc140680906d434fb17'
CONFIG_REMEDIATION_689_PREVIOUS_ARCHIVE_SHA256 = 'b56e63f84f09b3cc3623950ba2f665f7ef460d166c32669986d5178d2b3bf330'
CONFIG_REMEDIATION_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-config-remediation-source-manifest.json'
CONFIG_REMEDIATION_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-config-remediation-catalog.tar.gz'
SERVICECATALOG_EFFECT_689_PREVIOUS_MANIFEST = '29b74a9633cc0900893ce77dabd373fa53efd6f4b1f58739cc9b2544f9b53d28'
SERVICECATALOG_EFFECT_689_PREVIOUS_TREE = '1311ff4ef2de5f6e0fca5c8fccb108d3ce258d2c0077c8c193c4db9a00b21785'
SERVICECATALOG_EFFECT_689_PREVIOUS_ARCHIVE_SHA256 = '12af6717d5601a0e0ffa7765a15648f7c3c0fe3c0e1cef7f9c9f32a7e6ce4344'
SERVICECATALOG_EFFECT_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-servicecatalog-effect-source-manifest.json'
SERVICECATALOG_EFFECT_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-servicecatalog-effect-catalog.tar.gz'
ORG_ACCESS_ROLE_689_PREVIOUS_MANIFEST = '40ed3dbdcf05791488c34fe3c3bae1677f84229e8e1b3d3fd1bc69abe33879c2'
ORG_ACCESS_ROLE_689_PREVIOUS_TREE = '02e8ad7362978074692d08fb861a88b70d24cc0513cf77b275a4395d812131c3'
ORG_ACCESS_ROLE_689_PREVIOUS_ARCHIVE_SHA256 = '39af0a2ceb978416e25473fdc08a9175fc84d3e6c0b33ffe8073f46b0bbbba0e'
ORG_ACCESS_ROLE_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-org-access-role-source-manifest.json'
ORG_ACCESS_ROLE_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-org-access-role-catalog.tar.gz'
STEPFUNCTIONS_PASSROLE_689_PREVIOUS_MANIFEST = '357bbbdbb165311268aa808065b43553f1a301bcd8c1ea08caf3ec58a78ee1e9'
STEPFUNCTIONS_PASSROLE_689_PREVIOUS_TREE = '2f3970ff928e4ff224581aea739d26fa1d532205db450300151702f17daadea4'
STEPFUNCTIONS_PASSROLE_689_PREVIOUS_ARCHIVE_SHA256 = '876a304860924d592979155806ef45dc1b24e160f32386bbfce5f5fe543f4d0e'
STEPFUNCTIONS_PASSROLE_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-stepfunctions-passrole-source-manifest.json'
STEPFUNCTIONS_PASSROLE_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-stepfunctions-passrole-catalog.tar.gz'
GAMELIFT_COVERAGE_689_PREVIOUS_MANIFEST = '0c28d0a2c692ed51aecc805fff445975b885d68f3d26f5c4dd6e9d062cbddbf0'
GAMELIFT_COVERAGE_689_PREVIOUS_TREE = 'a0535402ab3eb2c234cad79a425ebdecabf7eb307f55ac85f7edc3c7dbb6b7b9'
GAMELIFT_COVERAGE_689_PREVIOUS_ARCHIVE_SHA256 = '063f2bd25164aed56d660ba54411f719a90d25a930f9e9a1cbb0eff0876d4b15'
GAMELIFT_COVERAGE_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-gamelift-coverage-source-manifest.json'
GAMELIFT_COVERAGE_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-gamelift-coverage-catalog.tar.gz'
COGNITO_IDP_SECRET_689_PREVIOUS_MANIFEST = '87b1606cb1fc9b04eb7a94aba9c211b94f30470f07c6c8f4f2682c5456291812'
COGNITO_IDP_SECRET_689_PREVIOUS_TREE = '0c36966d4b7286cacbdcd71835074acfa161ed6512dc6ff181a5b236157fbb24'
COGNITO_IDP_SECRET_689_PREVIOUS_ARCHIVE_SHA256 = 'f7a0b692161b10307885b0f0d238cabd25470227c52148668c2ef2088b522416'
COGNITO_IDP_SECRET_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-cognito-idp-secret-source-manifest.json'
COGNITO_IDP_SECRET_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-cognito-idp-secret-catalog.tar.gz'
EC2_RUNINSTANCES_689_PREVIOUS_MANIFEST = '198ea2384323076842402c5a41a0609d68bce7796a3ee358e989bc7b2c9b55fc'
EC2_RUNINSTANCES_689_PREVIOUS_TREE = '63df04c3d07b852e079e91acc80ccd8f37ad134eef035981976aa76df12dd559'
EC2_RUNINSTANCES_689_PREVIOUS_ARCHIVE_SHA256 = '9eac9d43af09b43bb63c3ed8e4337f038b4a6ac665e1d81be42d51a1e4a53df6'
EC2_RUNINSTANCES_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-ec2-runinstances-source-manifest.json'
EC2_RUNINSTANCES_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-ec2-runinstances-catalog.tar.gz'
STALE_COVERAGE_689_PREVIOUS_MANIFEST = '2c3da3d187ff9dfa1f5b3ce05a8cb3f90bfa71a877d4a448fe667c894248cd62'
STALE_COVERAGE_689_PREVIOUS_TREE = '74d2b6e516ce9f2d5b6fa13b1a220697c5800d9330c160ac0fdb89b19ea47038'
STALE_COVERAGE_689_PREVIOUS_ARCHIVE_SHA256 = '6dc4fe0177bce9eee480ef65740a1c05c308ca122fb516f1015d687fd532cbfd'
STALE_COVERAGE_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-stale-coverage-source-manifest.json'
STALE_COVERAGE_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-stale-coverage-catalog.tar.gz'
FINSPACE_SUNSET_690_PREVIOUS_MANIFEST = '2d85f83a0367d243011a00f1b176bfea9f96464a6518b99db1db8acb592271ca'
FINSPACE_SUNSET_690_PREVIOUS_TREE = '7e8ac01d407a05d8d6babf57eb02b43f3cd28d8906147594dc5e87d81c472992'
FINSPACE_SUNSET_690_PREVIOUS_ARCHIVE_SHA256 = '1b8753caaeb7141ee06ccd62d550bb6dce8223d6d92bb61a7c2d41b4b3f80fdf'
FINSPACE_SUNSET_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-finspace-sunset-source-manifest.json'
FINSPACE_SUNSET_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-finspace-sunset-catalog.tar.gz'
SPOT_REQUEST_690_PREVIOUS_MANIFEST = 'caa32ddb832aae734f3b96f0a9de124802995b23c9f375e72dfde64e5d8ba196'
SPOT_REQUEST_690_PREVIOUS_TREE = '9c1b10cde6cbc0fb180b7b6908bf1d9dc1979942fd253647903d00eb3d9b700e'
SPOT_REQUEST_690_PREVIOUS_ARCHIVE_SHA256 = 'e384f312ff4e88b7a0667b8b2333910febeefb2d84583938d6a557beb3bf2089'
SPOT_REQUEST_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-spot-request-source-manifest.json'
SPOT_REQUEST_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-spot-request-catalog.tar.gz'
TESTSTATE_690_PREVIOUS_MANIFEST = '020ac318f044f346654731db54ce11b7647a88ca45cbfc23dcfaa174578d0e2c'
TESTSTATE_690_PREVIOUS_TREE = '4ec8e1868e9713ce4055f9d0112c183345dcfaff8dfcb491a72e4d1de856aba7'
TESTSTATE_690_PREVIOUS_ARCHIVE_SHA256 = 'c5a0ee00075c139c0a568d67e1968c74613dbe0f63940494398610c4b692ae20'
TESTSTATE_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-stepfunctions-teststate-source-manifest.json'
TESTSTATE_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-stepfunctions-teststate-catalog.tar.gz'
INSTANCE_CONNECT_690_PREVIOUS_MANIFEST = '57ec5bf9b335c1369f895d8a73d1baa9c633a6f62d47ac7be47d6e598af8bbab'
INSTANCE_CONNECT_690_PREVIOUS_TREE = 'a2fd5dd18c65ea4b80090995c12f87977470457653fd344878d97efa98f11882'
INSTANCE_CONNECT_690_PREVIOUS_ARCHIVE_SHA256 = '6a8a10d0142bce84df55b010fa3a03c53771d220c779221b3d3e84c415b8498c'
INSTANCE_CONNECT_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-instance-connect-source-manifest.json'
INSTANCE_CONNECT_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-instance-connect-catalog.tar.gz'
BRAKET_690_PREVIOUS_MANIFEST = 'f618292a0fd784dfd2d63a979494e31e42ca75873fa2c0ba65518ee6380137c4'
BRAKET_690_PREVIOUS_TREE = '39ad82f667cf13b21cfa83c7af9824bdd0196642e7aee919acdd24ae9d038384'
BRAKET_690_PREVIOUS_ARCHIVE_SHA256 = '41d294d768a69bf55352a12c857f2fa787fe8ec7408ad639cff6cea19e6e1908'
BRAKET_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-braket-device-job-source-manifest.json'
BRAKET_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-braket-device-job-catalog.tar.gz'
CLOUDCONTROL_690_PREVIOUS_MANIFEST = '7f88162ac1519995d3ca2b4f7e4fb20ba8cf094139f3bf11be1a7f87c9964cc0'
CLOUDCONTROL_690_PREVIOUS_TREE = '11bf8b5fe6ca71220bcd892902cefe6661f8e7d858ca541fd57c25637e5e4393'
CLOUDCONTROL_690_PREVIOUS_ARCHIVE_SHA256 = 'e656656a19d2cb82a4e7edd223f6348f621980784a6fefcdbde81a092daa2623'
CLOUDCONTROL_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-cloudcontrol-global-source-manifest.json'
CLOUDCONTROL_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-cloudcontrol-global-catalog.tar.gz'
MWAA_SLR_690_PREVIOUS_MANIFEST = '38eb22ca895b154e26c7fb4e57efac2fd1d7c7f2b93cb15e953fd0dd5494a677'
MWAA_SLR_690_PREVIOUS_TREE = '6a2558eb2f3c33449bbb8a2e81c55caac59394978869706c447f65ebaad8c71f'
MWAA_SLR_690_PREVIOUS_ARCHIVE_SHA256 = '3618eb55592ef3d104fa4d5568b4745a874f4303513a8b26f62aa56ec0b666e3'
MWAA_SLR_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-mwaa-slr-source-manifest.json'
MWAA_SLR_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-mwaa-slr-catalog.tar.gz'
GLUE_SCRIPT_690_PREVIOUS_MANIFEST = '5688e8828d5da6bfe50dc0e7d7ecf57c205ff51a15b0dbfd7c3605e86cf20244'
GLUE_SCRIPT_690_PREVIOUS_TREE = 'e677064371a06be1699166d93a1c4014479584387281b0ada9bf814cce339ab1'
GLUE_SCRIPT_690_PREVIOUS_ARCHIVE_SHA256 = '926f48081c890a43935b2186f49fa4e5696cb421c14e7375e0ccf662471dd337'
GLUE_SCRIPT_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-glue-script-binding-source-manifest.json'
GLUE_SCRIPT_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-glue-script-binding-catalog.tar.gz'
GLUE_690_PREVIOUS_MANIFEST = 'd9aabeaf2ad628290897d7bdd71a3f340c64285fd16c05bba78e419d80b67c1f'
GLUE_690_PREVIOUS_TREE = '41a2882ae0c929b50fc12407a7caefd76ed21644950a1a8131a79da8420bb3db'
GLUE_690_PREVIOUS_ARCHIVE_SHA256 = 'b799ec4aa3d3cc9cf35e738616586696d168b919f972afeec5d1f39151d40fb2'
GLUE_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-glue-dev-endpoint-source-manifest.json'
GLUE_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-glue-dev-endpoint-catalog.tar.gz'
DEVICEFARM_690_PREVIOUS_MANIFEST = 'd7605097dbcd5220cad0aecd2bbf4b2b08b839a442fed67644ba9161782556fd'
DEVICEFARM_690_PREVIOUS_TREE = 'a5b712f658ccaed3b962839c3e7e634652db05f5f297def720002f3e65a72ea7'
DEVICEFARM_690_PREVIOUS_ARCHIVE_SHA256 = '7c0c2fdc3890e3c1c460e4084fe175bfe80f8aeec408096a7ffa89a2e1531d3a'
DEVICEFARM_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-devicefarm-source-manifest.json'
DEVICEFARM_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-devicefarm-catalog.tar.gz'
IOT_EXISTING_689_PREVIOUS_MANIFEST = 'e8f57144d46d8135eb9f474e143f418263d00d2f38f1cc4a9b4130a42577e85f'
IOT_EXISTING_689_PREVIOUS_TREE = '642f2ed5b4dd647f616650e8ea182f2b666b56239843d5561ad8475e32296ed8'
IOT_EXISTING_689_PREVIOUS_ARCHIVE_SHA256 = '33a68002171d9530e7cef98c1dac0c2be6f7404ae66906579655efef81bcc7f6'
IOT_EXISTING_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-iot-existing-alias-source-manifest.json'
IOT_EXISTING_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-iot-existing-alias-catalog.tar.gz'
GAMELIFT_SHELL_689_PREVIOUS_MANIFEST = '96af62443eb91ef5f191e53431a1c454d6c01a9227990296b975859304061e38'
GAMELIFT_SHELL_689_PREVIOUS_TREE = 'ea0f81124392a2b3c1497fcbd84f5f10e29b0f7233faa98b9e3f55040d46b787'
GAMELIFT_SHELL_689_PREVIOUS_ARCHIVE_SHA256 = '7c203f81019b1c73ec8cccf185aa122c3f092aef57dcf987fdb586eb4b243100'
GAMELIFT_SHELL_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-gamelift-shell-source-manifest.json'
GAMELIFT_SHELL_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-gamelift-shell-catalog.tar.gz'
GAMELIFT_SHARED_688_PREVIOUS_MANIFEST = '4f7aad5ed3fac85e64cf6a48b1c3dedd8d437716841b4c0542de5ffce7ff416b'
GAMELIFT_SHARED_688_PREVIOUS_TREE = '2932696952ff3d375e67011d9d390f44a47bda268dd3715f4a18e96e784ebaf9'
GAMELIFT_SHARED_688_PREVIOUS_ARCHIVE_SHA256 = '46371c73bf402bdadddc8a2d3e7890bf0d15bd0536488e982ba050f30cda150e'
GAMELIFT_SHARED_688_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-688-quicksight-source-manifest.json'
GAMELIFT_SHARED_688_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-688-quicksight-catalog.tar.gz'
SCHEDULER_UPDATE_687_PREVIOUS_MANIFEST = '2bbb1711fccc2d4de32e9f80f30a44b5fa90eea3c40233da917217222897790f'
SCHEDULER_UPDATE_687_PREVIOUS_TREE = '7ecbbce66663c7cafab4d2ff70b75e56fb4048d854f0a0b039fcb321e1b1c2bb'
SCHEDULER_UPDATE_687_PREVIOUS_ARCHIVE_SHA256 = '1aeb24e40c36b96d529d620dd60a6e51307a7556935c599e14a8443c4a455b14'
SCHEDULER_UPDATE_687_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-687-scheduler-update-source-manifest.json'
SCHEDULER_UPDATE_687_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-687-scheduler-update-catalog.tar.gz'
SCHEDULER_CREATE_686_PREVIOUS_MANIFEST = 'e1ba0fb3b429fc2bb9ce6dc1c9d307969d3b70cd3b62d3823f4e5fe3711aa976'
SCHEDULER_CREATE_686_PREVIOUS_TREE = '853549b616c06803bba97771b9d14d1cbca9459f1d750fc9f40a0df83ecf0bc3'
SCHEDULER_CREATE_686_PREVIOUS_ARCHIVE_SHA256 = 'd1e84bdcc4d0c54dbaffbddaaab4db987a46a979f80c05d4ed924a65655d203a'
SCHEDULER_CREATE_686_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-686-scheduler-create-source-manifest.json'
SCHEDULER_CREATE_686_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-686-scheduler-create-catalog.tar.gz'
DEADLINE_DEPENDENCIES_686_PREVIOUS_MANIFEST = '296e1b6e6d8359d486cbba8d9a250fc4b2f430bd0d06b98ff31fdf3243fdd360'
DEADLINE_DEPENDENCIES_686_PREVIOUS_TREE = '3d231c0ab1f30796668b2d12e2de29e9a5357ae4f8e810462e4843814ab1c199'
DEADLINE_DEPENDENCIES_686_PREVIOUS_ARCHIVE_SHA256 = '2b152b5e753a25243ff73a2ba2a7f22b6c5848224fe42c14ed5ea2dac69cc32f'
DEADLINE_DEPENDENCIES_686_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-686-deadline-worker-dependencies-source-manifest.json'
DEADLINE_DEPENDENCIES_686_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-686-deadline-worker-dependencies-catalog.tar.gz'
DEADLINE_NEW_WORKER_685_PREVIOUS_MANIFEST = 'e616da28305d487c70d65f238bfe725e0a69e8eaadba108249b28cdca0bd03a9'
DEADLINE_NEW_WORKER_685_PREVIOUS_TREE = '65314cd326eca8023b58b7ecaf1d143ffe1167cbe6c3025858484cc2a8dbd245'
DEADLINE_NEW_WORKER_685_PREVIOUS_ARCHIVE_SHA256 = 'a4a528b725a6d2a8d8c50a5dfab19b76f945ec115dfa2bf679398d1778cbf539'
DEADLINE_NEW_WORKER_685_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-685-deadline-new-worker-source-manifest.json'
DEADLINE_NEW_WORKER_685_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-685-deadline-new-worker-catalog.tar.gz'
DEADLINE_WORKER_684_PREVIOUS_MANIFEST = '8f1a9abe937cc74f499cc1dc6316544a37f37967cd4f4c254f80ad269fb4e60d'
DEADLINE_WORKER_684_PREVIOUS_TREE = 'd9bcd120bf3d79acde0e2520e0056a3d77b30988d5201be874e3ccc930293a8b'
DEADLINE_WORKER_684_PREVIOUS_ARCHIVE_SHA256 = '1ed684664f996a36a05b8c88aea17e55133e6df60af8b54b0d7e8d5ebd8684f3'
DEADLINE_WORKER_684_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-684-deadline-existing-worker-source-manifest.json'
DEADLINE_WORKER_684_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-684-deadline-existing-worker-catalog.tar.gz'
DEADLINE_FLEET_684_PREVIOUS_MANIFEST = 'af62253634cee8f664d4fe5d7e25133734a363cd8c917f6e74bdadc3ecb71732'
DEADLINE_FLEET_684_PREVIOUS_TREE = 'ca26d6b56ae3848b61da6ba96ab413616223877caa5973be1f00e4b0d2f3c95b'
DEADLINE_FLEET_684_PREVIOUS_ARCHIVE_SHA256 = 'e3ce247d4403235280743256dc19d890f4c8dad6d96199cc6c3bf7cc551b6d88'
DEADLINE_FLEET_684_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-684-deadline-fleet-scope-source-manifest.json'
DEADLINE_FLEET_684_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-684-deadline-fleet-scope-catalog.tar.gz'
DEADLINE_QUEUE_683_PREVIOUS_MANIFEST = '51881e49473f48dac6fa4b1a724dcdf2bd08fe6d6ae9b7d1833c127999298365'
DEADLINE_QUEUE_683_PREVIOUS_TREE = '73524d94236f143acfa52452e22c28e37111f997ec8ed841fa218846ce4a88fd'
DEADLINE_QUEUE_683_PREVIOUS_ARCHIVE_SHA256 = '83134ca0fb63e6b30aa52f8d3776be8fbfcef56a61e6376c5d78d7549881a68e'
DEADLINE_QUEUE_683_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-683-deadline-queue-source-manifest.json'
DEADLINE_QUEUE_683_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-683-deadline-queue-catalog.tar.gz'
CLOUDFRONT_CREATE_683_PREVIOUS_MANIFEST = '473c03db5521c972b4eabbd478955243825d55055a834b336786f4415f1a235e'
CLOUDFRONT_CREATE_683_PREVIOUS_TREE = '9b57effb04904ecbeb32ce792ed3668b4ea1fb645b8ca6790ec73a572a4475c3'
CLOUDFRONT_CREATE_683_PREVIOUS_ARCHIVE_SHA256 = '12100524ae96a118b67541532819b3ccf0a40d1144a95bdda89dcf8fc30711a0'
CLOUDFRONT_CREATE_683_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-683-cloudfront-create-source-manifest.json'
CLOUDFRONT_CREATE_683_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-683-cloudfront-create-catalog.tar.gz'
COGNITO_GUEST_EXISTING_683_PREVIOUS_MANIFEST = '70f2970c1744af66851bbe87dfa372a18aa908c89f5f61d7072b8313918f64c6'
COGNITO_GUEST_EXISTING_683_PREVIOUS_TREE = '781cd6f1481e00cc34086fbcaa4f2bd6147beaad623762725fda6c1ddc2445da'
COGNITO_GUEST_EXISTING_683_PREVIOUS_ARCHIVE_SHA256 = 'c6d1b8bcd9f2587a4d309f96debd1ad0be92f772abbc2057582ade5bd82979ae'
COGNITO_GUEST_EXISTING_683_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-683-cognito-guest-existing-source-manifest.json'
COGNITO_GUEST_EXISTING_683_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-683-cognito-guest-existing-catalog.tar.gz'
COGNITO_GUEST_682_PREVIOUS_MANIFEST = '070ffca432c04525fd59598b50b38e3dace8e7f1f9eaad60f8851fc4ee68fe1e'
COGNITO_GUEST_682_PREVIOUS_TREE = '86de91111e926806ad603078a88e1becd5ffc53f50b7323bb9fa0e5ccfa2114b'
COGNITO_GUEST_682_PREVIOUS_ARCHIVE_SHA256 = '12f90b298900206937bc7c01fbfc2962d495fcb2b2c3975e5f6c45a060c3b82c'
COGNITO_GUEST_682_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-682-cognito-guest-classic-source-manifest.json'
COGNITO_GUEST_682_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-682-cognito-guest-classic-catalog.tar.gz'
SAGEMAKER_ATTACH_682_PREVIOUS_MANIFEST = '1e3da74d7edbd1490aeafccfa650e7e01a7a71163d5aa959b8e6f9244949ebd9'
SAGEMAKER_ATTACH_682_PREVIOUS_TREE = 'dd09ade57ea0a886c7a37963c60b1f7badfbbb6bbf65bd9abf3f737dfe7c3a07'
SAGEMAKER_ATTACH_682_PREVIOUS_ARCHIVE_SHA256 = 'd1dd9259a4cbd1383a916e80235d74be26929f604fe8dbc3caf579aeeee02d25'
SAGEMAKER_ATTACH_682_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-682-sagemaker-attach-source-manifest.json'
SAGEMAKER_ATTACH_682_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-682-sagemaker-attach-catalog.tar.gz'
GAMELIFT_GROUP_682_PREVIOUS_MANIFEST = '028d895b523eb128696dbcdc0f866bb180c2f3c733f44337fa52fbd64a1b4e15'
GAMELIFT_GROUP_682_PREVIOUS_TREE = '39e933196b904e1af7b4fe2b10544317de91a5c2e0e6ea07df268e5bc0e7ca4e'
GAMELIFT_GROUP_682_PREVIOUS_ARCHIVE_SHA256 = '9176b3e00232b0d76d6c7a3e3ac956b3242c4164b9f3fe9ee8306e0173c52c8a'
GAMELIFT_GROUP_682_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-682-gamelift-group-source-manifest.json'
GAMELIFT_GROUP_682_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-682-gamelift-group-catalog.tar.gz'
SAGEMAKER_LCC_677_PREVIOUS_MANIFEST = '22ecf1eb87abe05bdab76bcdc3756f63a042c225ca55f7e7f0402fa2f77f2a81'
SAGEMAKER_LCC_677_PREVIOUS_TREE = 'a969be051deaead368da7bfc18836720adc16ba39dff047971d52b84233218e6'
SAGEMAKER_LCC_677_PREVIOUS_ARCHIVE_SHA256 = '666314d8973313ff2aa50fae1c87911f2fbb4805bcfd157102ef5b93456ae4f2'
SAGEMAKER_LCC_677_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-677-sagemaker-lcc-source-manifest.json'
SAGEMAKER_LCC_677_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-677-sagemaker-lcc-catalog.tar.gz'
SAGEMAKER_LCC_PREVIOUS_MANIFEST = 'd50f94c14b997e98e7109eb5a38831243eb164498ff5872c680288caf0b44f5d'
SAGEMAKER_LCC_PREVIOUS_TREE = '84537823c63b438f9e41d7e7b115a3ef46dd6c85383b99122d1b6ed6a1aef508'
SAGEMAKER_LCC_PREVIOUS_ENTRY_COUNT = 676
SAGEMAKER_LCC_PREVIOUS_EXCLUDED_COUNT = 3723
SAGEMAKER_LCC_PREVIOUS_ARCHIVE_SHA256 = 'acbb2f78a8f4fd489218e0dad20b2774f84cf91afe40babb8ab4d40fd9f68793'
SAGEMAKER_LCC_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-676-sagemaker-lcc-source-manifest.json'
SAGEMAKER_LCC_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-676-sagemaker-lcc-catalog.tar.gz'
SSM_HYBRID_PREVIOUS_MANIFEST = '767604c8fd7bb41e51177886371eb3c33f31d698a21586bc5b230364271d9d18'
SSM_HYBRID_PREVIOUS_TREE = '5677fb5e5aced10aaed8cf84e51d42f7813f7d213f72e89e3956558616d5cb71'
SSM_HYBRID_PREVIOUS_ENTRY_COUNT = 674
SSM_HYBRID_PREVIOUS_EXCLUDED_COUNT = 3723
SSM_HYBRID_PREVIOUS_ARCHIVE_SHA256 = '103d422dedb73776703f8d33e3c7278b0c01c6b35160e2ac23d1818173421a9b'
SSM_HYBRID_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-674-ssm-hybrid-source-manifest.json'
SSM_HYBRID_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-674-ssm-hybrid-catalog.tar.gz'
MWAA_DAG_PREVIOUS_MANIFEST = 'ead398e038dec38299179fe6dcadbaaa1125bafa85617e8ba738320d46d99e0c'
MWAA_DAG_PREVIOUS_TREE = '68e7b2982721974b183936f2fe6612b1cae983ddf2088010f3167bd6a7c540a6'
MWAA_DAG_PREVIOUS_ENTRY_COUNT = 673
MWAA_DAG_PREVIOUS_EXCLUDED_COUNT = 3723
MWAA_DAG_PREVIOUS_ARCHIVE_SHA256 = '5fde181a76164521079837f7ec4ba12ed9d83b2147bd0f56c4529fde3251e8a8'
MWAA_DAG_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-673-mwaa-dag-source-manifest.json'
MWAA_DAG_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-673-mwaa-dag-catalog.tar.gz'
IMAGEBUILDER_PREVIOUS_MANIFEST = '806df7e9e167327f94546f21aef691ead74b27aac1807278ac0500ab031ce5dd'
IMAGEBUILDER_PREVIOUS_TREE = '25f7f17354a44d519da70a2b0b7dc9ee8bc7cc7190325fc457d96978cc07881b'
IMAGEBUILDER_PREVIOUS_ENTRY_COUNT = 673
IMAGEBUILDER_PREVIOUS_EXCLUDED_COUNT = 3723
IMAGEBUILDER_PREVIOUS_ARCHIVE_SHA256 = '33ba00ab6f5240658907c8a2c04c8fb45dcf9d7df261214fe01f4de783b7dd26'
IMAGEBUILDER_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-673-imagebuilder-source-manifest.json'
IMAGEBUILDER_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-673-imagebuilder-catalog.tar.gz'
GLUE_SCRIPT_PREVIOUS_MANIFEST = '78c82d0bffa7d95e75fcd66c798cd7b3d5423f328b632731f62c61cd5c02db5e'
GLUE_SCRIPT_PREVIOUS_TREE = '05938ad2b8b18f72f55be44a2b420eab322e0e744198e9e14f4b40a61e4b52e6'
GLUE_SCRIPT_PREVIOUS_ENTRY_COUNT = 672
GLUE_SCRIPT_PREVIOUS_EXCLUDED_COUNT = 3723
GLUE_SCRIPT_PREVIOUS_ARCHIVE_SHA256 = 'eb58c2e2349910946a399264ebc60a80e7ada3ee2b5d5e2d53a4cd41f72d5afb'
GLUE_SCRIPT_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-672-glue-script-source-manifest.json'
GLUE_SCRIPT_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-672-glue-script-catalog.tar.gz'
ECSCAPE_PREVIOUS_MANIFEST = '9c316dfc3f48451080f3d92579fb9428bdd4963cdd2a6a6eb4ab76eaeb8f1dc3'
ECSCAPE_PREVIOUS_TREE = '6fef6e9cbdd398932c52f43f98d2f4323fe81c0506ec3f6bfd30cb51594138dc'
ECSCAPE_PREVIOUS_ENTRY_COUNT = 672
ECSCAPE_PREVIOUS_EXCLUDED_COUNT = 3723
ECSCAPE_PREVIOUS_ARCHIVE_SHA256 = '9edc25d69c607dc5f7e97ed768aa7b3a21296ce488a95a0cd6d61e84d24bdb91'
ECSCAPE_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-672-ecscape-source-manifest.json'
ECSCAPE_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-672-ecscape-catalog.tar.gz'
ENABLE_CLASSIC_PREVIOUS_MANIFEST = '563a6cdc997965f2bb4c277293a077d4d54756bb3c4d2bd6079abf9ed3ec6e3b'
ENABLE_CLASSIC_PREVIOUS_TREE = '034912fcdf1fee642a14d2d8269778b7ba1a51d5adb48db547e88da4005da425'
ENABLE_CLASSIC_PREVIOUS_ENTRY_COUNT = 671
ENABLE_CLASSIC_PREVIOUS_EXCLUDED_COUNT = 3723
ENABLE_CLASSIC_PREVIOUS_ARCHIVE_SHA256 = '066a64c76b33ca6b9222526e0f880198001baa200315faa918db52747d02bbbf'
ENABLE_CLASSIC_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-671-cognito-enable-classic-source-manifest.json'
ENABLE_CLASSIC_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-671-cognito-enable-classic-catalog.tar.gz'
SETROLES_PREVIOUS_MANIFEST = '9101d6942f7cb64270b0593849623d3bc2f591a961ca48a60158bb59abf620d0'
SETROLES_PREVIOUS_TREE = '8cf68cd6be9d5ead8210d5333ee813a2829ce086cf141a4a3d601b657609fd81'
SETROLES_PREVIOUS_ENTRY_COUNT = 670
SETROLES_PREVIOUS_EXCLUDED_COUNT = 3723
SETROLES_PREVIOUS_ARCHIVE_SHA256 = '6c599495006c19b0781150323151f959cea481b4e813a065897248d78fd7928f'
SETROLES_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-670-cognito-setroles-source-manifest.json'
SETROLES_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-670-cognito-setroles-catalog.tar.gz'
CLASSIC_PREVIOUS_MANIFEST = '9f9d526ff17571b7fd3c8610e9ca5c01aa9ea22f6654065659a1bcfd718a49d2'
CLASSIC_PREVIOUS_TREE = '9f077698a417165440cbd9bd9404cc007ad793c6bc5c09347191cd173c5611a5'
CLASSIC_PREVIOUS_ENTRY_COUNT = 669
CLASSIC_PREVIOUS_EXCLUDED_COUNT = 3723
CLASSIC_PREVIOUS_ARCHIVE_SHA256 = 'f868234cb65a87d552da35768276aab8cf3d2de0f85bb583d60d5adf895e8096'
CLASSIC_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-669-cognito-classic-source-manifest.json'
CLASSIC_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-669-cognito-classic-catalog.tar.gz'
COGNITO_PREVIOUS_MANIFEST = 'fa98e52c3a7b0778d45750885e62c1f08a0b08c68b2a2fe405d407ca24bf8d83'
COGNITO_PREVIOUS_TREE = '92585138ea667380fdd66d6cf2c03c46f080034aa8904975fc0ec82feda14a9d'
COGNITO_PREVIOUS_ENTRY_COUNT = 668
COGNITO_PREVIOUS_EXCLUDED_COUNT = 3724
COGNITO_PREVIOUS_ARCHIVE_SHA256 = '57bd1634f4787a387d9711fc2d09119ed2f956a6ed5d85e235f22cab03d94a0d'
COGNITO_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-668-cognito-source-manifest.json'
COGNITO_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-668-cognito-catalog.tar.gz'
GAMELIFT_CURRENT_MANIFEST = '37a6cc93d703b54c1bbf58e346ab0c855bbec910dee9611ee77511928699e7fe'
GAMELIFT_CURRENT_TREE = '4e029c42de100f8d63ace40173ce4b9e894a5f12bb42f470831a8745b4950399'
GAMELIFT_CURRENT_ENTRY_COUNT = 667
GAMELIFT_CURRENT_EXCLUDED_COUNT = 3725
GAMELIFT_CURRENT_ARCHIVE_SHA256 = 'f16d34175f0dca5d92d316fc2f5d4eaf6506a11fdb0a92dfdcf31e828b32d0af'
GAMELIFT_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-667-gamelift-source-manifest.json'
GAMELIFT_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-667-gamelift-catalog.tar.gz'
IOT_V2_CURRENT_MANIFEST = 'b34c5215e969f886c4b286c3d33afd62f3364d5b58dce96a8393d8ef79465090'
IOT_V2_CURRENT_TREE = '98e3a4ac18955dec5670e267f03b8f942bfadf01d5cb483d94a928e4229b4428'
IOT_V2_CURRENT_ENTRY_COUNT = 667
IOT_V2_CURRENT_EXCLUDED_COUNT = 3725
IOT_V2_CURRENT_ARCHIVE_SHA256 = '8c52a13e77b13013342d9f70acbc2e8b3cd6a339d15d421ab86090f23455605f'
IOT_V2_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-667-iot-v2-source-manifest.json'
IOT_V2_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-667-iot-v2-catalog.tar.gz'
IOT_V1_CURRENT_MANIFEST = 'd0b9a70385686e426173bb33f5ceced688eef8b145863f06bd656e9872e6087b'
IOT_V1_CURRENT_TREE = 'ec6fd3f2a2f745ccb28bbac553ca280604f43607754da2364f0602c78ffed964'
IOT_V1_CURRENT_ENTRY_COUNT = 667
IOT_V1_CURRENT_EXCLUDED_COUNT = 3725
IOT_V1_CURRENT_ARCHIVE_SHA256 = '0927784c95eb72590096dd56fae5b290c7866feb13ba29893b590f332767aafd'
IOT_V1_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-667-iot-v1-source-manifest.json'
IOT_V1_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-667-iot-v1-catalog.tar.gz'
IOT_CURRENT_MANIFEST = 'c154e1c71f1351f02f99477babae646760c491ca1039b8ba51a9508076a9cc08'
IOT_CURRENT_TREE = 'b68a44ccadaf04a9efccf624d4cf7ce2c3c5e9c4b099357dec05b66f59b46efa'
IOT_CURRENT_ENTRY_COUNT = 667
IOT_CURRENT_EXCLUDED_COUNT = 3725
IOT_CURRENT_ARCHIVE_SHA256 = '9cfa0520e58d5ddee3f45161e934e5b849ab82881c06bf2962325611452925a8'
IOT_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-667-source-manifest.json'
IOT_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-667-catalog.tar.gz'
APPRUNNER_CURRENT_MANIFEST = '6fbd47a393f3377664859a479c46ca53192305096c5cf8366a249854c406f654'
APPRUNNER_CURRENT_TREE = '3043d253ecdb229018b0d0a71326a136d1f8d7af669933a22a65d9affc84a7d4'
APPRUNNER_CURRENT_ENTRY_COUNT = 666
APPRUNNER_CURRENT_EXCLUDED_COUNT = 3725
APPRUNNER_CURRENT_ARCHIVE_SHA256 = 'd42fd391ed8bdddc61960c0613af6ce598847c78c560c6aa352b18dda6d405e8'
APPRUNNER_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-666-source-manifest.json'
APPRUNNER_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-666-catalog.tar.gz'
BATCH_CURRENT_MANIFEST = 'a295871d623b8091fe0d3c1536293784ec93ec12db1914ae3707134e7840e6a2'
BATCH_CURRENT_TREE = '79a6945cd533dc781d668c234a59029476948af84d2b4af7198a8c1b10543cd9'
BATCH_CURRENT_ENTRY_COUNT = 665
BATCH_CURRENT_EXCLUDED_COUNT = 3726
BATCH_CURRENT_ARCHIVE_SHA256 = 'bc49a17111242283be708b591eeb95c53f9be60a23f8ff23952ad0476dfc835e'
BATCH_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-665-source-manifest.json'
BATCH_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-665-catalog.tar.gz'
ATHENA_CURRENT_MANIFEST = '9376370a8e63fefb6853e4e07ff750eb91d6aa66450e2eea3e9346930a1092f1'
ATHENA_CURRENT_TREE = '6aed4798e9eb1ba63eea1a1b4cace68122b1c13f0cd64e52d849951191f51343'
ATHENA_CURRENT_ENTRY_COUNT = 664
ATHENA_CURRENT_EXCLUDED_COUNT = 3727
ATHENA_CURRENT_ARCHIVE_SHA256 = '996bfe08a042b7000758250688faca0a1f8dfc4ba0bb43923977547ec2758baa'
ATHENA_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-664-source-manifest.json'
ATHENA_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-664-catalog.tar.gz'
RECENT_CURRENT_MANIFEST = '206b1895056780d15c6707bb434e46a25df4d53bf6c284e8bbb6d7d567a46806'
RECENT_CURRENT_TREE = 'd3dbaf40848dd14c4c2d199c8f7ec81126724f8311e23f9579282c02026c4f2f'
RECENT_CURRENT_ENTRY_COUNT = 661
RECENT_CURRENT_EXCLUDED_COUNT = 3730
RECENT_CURRENT_ARCHIVE_SHA256 = '96e4a5344ab18a45a41ddc1be280d816afe4356a675f9d11ae5871e64b5df484'
RECENT_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-661-source-manifest.json'
RECENT_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-661-catalog.tar.gz'
INTERMEDIATE_CURRENT_MANIFEST = 'eada56c3fbbbf06891601ef0711e3b2d2f216cdf8981e5e87e9501f7702ef868'
INTERMEDIATE_CURRENT_TREE = '9cace7c01a6cc13e22b369c99298cc0a4f6df6226aa13a7b63cfb6a4d1ad29e9'
INTERMEDIATE_CURRENT_ENTRY_COUNT = 660
INTERMEDIATE_CURRENT_EXCLUDED_COUNT = 3731
INTERMEDIATE_CURRENT_ARCHIVE_SHA256 = '24ef5805dc374d0b9163abe241dd86bf5edfb05e9e8746241bfab253e19634dd'
INTERMEDIATE_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-660-source-manifest.json'
INTERMEDIATE_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-660-catalog.tar.gz'
PREVIOUS_CURRENT_MANIFEST = '6d994be99fd3fd696c05dd0a352c0cb348da2dc62648e7caf99f03a113162f18'
PREVIOUS_CURRENT_TREE = '163c469428477120a0b2ff7aa9af4f0dfc82fb8dcf339165ddbae4d32f00914d'
PREVIOUS_CURRENT_ENTRY_COUNT = 633
PREVIOUS_CURRENT_EXCLUDED_COUNT = 3515
PREVIOUS_CURRENT_ARCHIVE_SHA256 = 'fad4c89765aa466f27831b6992a7e79059c28a118ee3707496a0e944b6335826'
PREVIOUS_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-633-source-manifest.json'
PREVIOUS_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-633-catalog.tar.gz'
PRIOR_CURRENT_MANIFEST = "eb459bc440cdad814f3acde244a36fa7f546119a351d5ce720ef0cd2281835bf"
PRIOR_DISCLOSURE_MANIFEST = "91ffe7389d02568cdcdf74a6b08dafa5f665ea07c0c528988127ffc4d2a86c45"
PRIOR_DISCLOSURE_TREE = "5091464bedcb10bb87301695ca733276dc67b865e544c408ccf72a5408176f0f"
PRIOR_DISCLOSURE_HISTORY = Path(__file__).resolve().parent / "catalog_versions/disclosure-v7-manifest.json"
PRIOR_CURRENT_TREE = "99207e6469fc5e5b3daf21324e6860599b116ffcf7d30600643bd229b0f11494"
CURRENT_HISTORY = Path(__file__).resolve().parent / "catalog_versions/bulk-principal-v6-manifest.json"
PRIOR_CATALOG_ARCHIVE = Path(__file__).resolve().parent / "catalog_versions/prior-disclosure-catalog-20261016.tar.gz"
PRIOR_CATALOG_ARCHIVE_SHA256 = "498459a1979833e9e1a09b64bbeb859beb004980ad7baa81818621e5c810c030"
RUNTIME_HISTORY_PACK = Path(__file__).resolve().parent / "catalog_versions/runtime-history-v1.zip"
RUNTIME_HISTORY_SHA256 = "7a922b6538ae372df99776b81b3932e375cabff9d54fd0e83b9727adcf02c4e2"
PRIOR_SOURCE_MANIFEST = Path(__file__).resolve().parent / "catalog_versions/prior-disclosure-source-manifest.json"
PRIOR_BOUNDED_MANIFEST = "082451e81fa450830ae5f6835e241dd412a6c30a8b2a0b1172cdbc89b2d71429"
PRIOR_BOUNDED_TREE = "695e38b0bc93df9ba031828ffefbabe8e10b60741580554a5f36b8f37aa05414"
BOUNDED_HISTORY = Path(__file__).resolve().parent / "catalog_versions/bounded-v5-manifest.json"
V4_HISTORY = Path(__file__).resolve().parent / "catalog_versions/principal-v4-manifest.json"


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _paths(catalog_dir=None, manifest_path=None, history_path=None):
    catalog_dir = Path(catalog_dir or CATALOG_DIR)
    manifest_path = Path(manifest_path or catalog_dir.parents[2] / "risk_rules/hacktricks-privesc-source.json")
    history_path = Path(history_path or LEGACY_DELTA)
    return catalog_dir, manifest_path, history_path


@lru_cache(maxsize=4)
def _current_tree(catalog_dir):
    """Content address of the live catalog: per-file sha256 and the effective tree digest."""
    root = Path(catalog_dir)
    actual = {str(path.relative_to(root)): _sha(path) for path in root.rglob("*.yaml")}
    tree = ''.join(f'{name} {actual[name]}\n' for name in sorted(actual))
    return actual, hashlib.sha256(tree.encode()).hexdigest()


@lru_cache(maxsize=4)
def _manifest_sha(manifest_path):
    try:
        return _sha(Path(manifest_path))
    except OSError:
        return None


@lru_cache(maxsize=4)
def _current_entries(catalog_dir):
    actual, _ = _current_tree(catalog_dir)
    from . import loaded_catalog_for
    loaded = loaded_catalog_for(catalog_dir, actual)
    if loaded is None:
        loaded = load_catalog(Path(catalog_dir), strict=True)
    elif loaded["errors"]:  # same failure the strict load raises for these bytes
        raise CatalogError("; ".join(loaded["errors"][:20]))
    return {entry["id"]: entry for entry in loaded["entries"]}


def _binding_for(catalog_dir, manifest_path):
    return {"schema": BINDING_SCHEMA, "manifest_sha256": _manifest_sha(str(manifest_path)),
            "effective_tree_sha256": _current_tree(str(catalog_dir))[1], "source_revision": V4_REVISION}


def __getattr__(name):
    # The current catalog identity is derived from the live catalog, never pinned.
    if name in ("CURRENT_MANIFEST", "CURRENT_TREE"):
        binding = current_binding()
        return binding["manifest_sha256" if name == "CURRENT_MANIFEST" else "effective_tree_sha256"]
    raise AttributeError(name)


@lru_cache(maxsize=1)
def _verified_lineage_685_previous():
    """Keep the exact reviewed catalog before exclusion source lineage resolution."""
    return _verified_archived_current(
        LINEAGE_685_PREVIOUS_MANIFEST_PATH, LINEAGE_685_PREVIOUS_ARCHIVE,
        LINEAGE_685_PREVIOUS_MANIFEST, LINEAGE_685_PREVIOUS_ARCHIVE_SHA256,
        LINEAGE_685_PREVIOUS_TREE, 685, 3777)


@lru_cache(maxsize=1)
def _verified_mwaa_token_reason_685_previous():
    """Keep stored report bindings from before the MWAA exclusion clarification exact."""
    return _verified_archived_current(
        MWAA_TOKEN_REASON_685_PREVIOUS_MANIFEST_PATH, MWAA_TOKEN_REASON_685_PREVIOUS_ARCHIVE,
        MWAA_TOKEN_REASON_685_PREVIOUS_MANIFEST, MWAA_TOKEN_REASON_685_PREVIOUS_ARCHIVE_SHA256,
        MWAA_TOKEN_REASON_685_PREVIOUS_TREE, 685, 3777)


@lru_cache(maxsize=1)
def _verified_beanstalk_685_previous():
    return _verified_archived_current(
        BEANSTALK_685_PREVIOUS_MANIFEST_PATH, BEANSTALK_685_PREVIOUS_ARCHIVE,
        BEANSTALK_685_PREVIOUS_MANIFEST, BEANSTALK_685_PREVIOUS_ARCHIVE_SHA256,
        BEANSTALK_685_PREVIOUS_TREE, 685, 3777)


@lru_cache(maxsize=1)
def _verified_cloud_source_685_previous():
    """Retain the exact current catalog before the Cloud source update."""
    return _verified_archived_current(
        CLOUD_SOURCE_685_PREVIOUS_MANIFEST_PATH, CLOUD_SOURCE_685_PREVIOUS_ARCHIVE,
        CLOUD_SOURCE_685_PREVIOUS_MANIFEST, CLOUD_SOURCE_685_PREVIOUS_ARCHIVE_SHA256,
        CLOUD_SOURCE_685_PREVIOUS_TREE, 685, 3777)


@lru_cache(maxsize=1)
def _verified_ecs_register_685_previous():
    """Retain the exact catalog before ECS registration required a matching revision."""
    return _verified_archived_current(
        ECS_REGISTER_685_PREVIOUS_MANIFEST_PATH, ECS_REGISTER_685_PREVIOUS_ARCHIVE,
        ECS_REGISTER_685_PREVIOUS_MANIFEST, ECS_REGISTER_685_PREVIOUS_ARCHIVE_SHA256,
        ECS_REGISTER_685_PREVIOUS_TREE, 685, 3777)


@lru_cache(maxsize=1)
def _verified_reviewed_685_previous():
    """Keep the exact preceding 685-entry catalog for stored report bindings."""
    return _verified_archived_current(
        REVIEWED_685_PREVIOUS_MANIFEST_PATH, REVIEWED_685_PREVIOUS_ARCHIVE,
        REVIEWED_685_PREVIOUS_MANIFEST, REVIEWED_685_PREVIOUS_ARCHIVE_SHA256,
        REVIEWED_685_PREVIOUS_TREE, 685, 3777)


@lru_cache(maxsize=1)
def _verified_reviewed_691_previous():
    """Keep the exact prior 691-entry catalog for existing report bindings."""
    return _verified_archived_current(
        REVIEWED_691_PREVIOUS_MANIFEST_PATH, REVIEWED_691_PREVIOUS_ARCHIVE,
        REVIEWED_691_PREVIOUS_MANIFEST, REVIEWED_691_PREVIOUS_ARCHIVE_SHA256,
        REVIEWED_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_previous_current():
    """Keep the exact 633-entry catalog used by already stored report cards."""
    return _verified_archived_current(
        PREVIOUS_CURRENT_MANIFEST_PATH, PREVIOUS_CURRENT_ARCHIVE,
        PREVIOUS_CURRENT_MANIFEST, PREVIOUS_CURRENT_ARCHIVE_SHA256,
        PREVIOUS_CURRENT_TREE, PREVIOUS_CURRENT_ENTRY_COUNT, PREVIOUS_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_gamelift_group_682_previous():
    """Keep the exact 682-entry catalog before the active-group condition."""
    return _verified_archived_current(
        GAMELIFT_GROUP_682_PREVIOUS_MANIFEST_PATH, GAMELIFT_GROUP_682_PREVIOUS_ARCHIVE,
        GAMELIFT_GROUP_682_PREVIOUS_MANIFEST, GAMELIFT_GROUP_682_PREVIOUS_ARCHIVE_SHA256,
        GAMELIFT_GROUP_682_PREVIOUS_TREE, 682, 3723)


@lru_cache(maxsize=1)
def _verified_cognito_guest_682_previous():
    """Keep the exact catalog before the Cognito guest Basic-flow route."""
    return _verified_archived_current(
        COGNITO_GUEST_682_PREVIOUS_MANIFEST_PATH, COGNITO_GUEST_682_PREVIOUS_ARCHIVE,
        COGNITO_GUEST_682_PREVIOUS_MANIFEST, COGNITO_GUEST_682_PREVIOUS_ARCHIVE_SHA256,
        COGNITO_GUEST_682_PREVIOUS_TREE, 682, 3723)


@lru_cache(maxsize=1)
def _verified_scheduler_update_687_previous():
    """Keep the exact 687-entry catalog before QuickSight self-promotion."""
    return _verified_archived_current(
        SCHEDULER_UPDATE_687_PREVIOUS_MANIFEST_PATH, SCHEDULER_UPDATE_687_PREVIOUS_ARCHIVE,
        SCHEDULER_UPDATE_687_PREVIOUS_MANIFEST, SCHEDULER_UPDATE_687_PREVIOUS_ARCHIVE_SHA256,
        SCHEDULER_UPDATE_687_PREVIOUS_TREE, 687, 3723)


@lru_cache(maxsize=1)
def _verified_gamelift_shared_688_previous():
    """Keep the exact 688-entry catalog before the GameLift shell route."""
    return _verified_archived_current(
        GAMELIFT_SHARED_688_PREVIOUS_MANIFEST_PATH, GAMELIFT_SHARED_688_PREVIOUS_ARCHIVE,
        GAMELIFT_SHARED_688_PREVIOUS_MANIFEST, GAMELIFT_SHARED_688_PREVIOUS_ARCHIVE_SHA256,
        GAMELIFT_SHARED_688_PREVIOUS_TREE, 688, 3723)


@lru_cache(maxsize=1)
def _verified_cloudcontrol_690_previous():
    """Keep the exact catalog before Cloud Control's global action correction."""
    return _verified_archived_current(
        CLOUDCONTROL_690_PREVIOUS_MANIFEST_PATH, CLOUDCONTROL_690_PREVIOUS_ARCHIVE,
        CLOUDCONTROL_690_PREVIOUS_MANIFEST, CLOUDCONTROL_690_PREVIOUS_ARCHIVE_SHA256,
        CLOUDCONTROL_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_braket_690_previous():
    """Keep the exact catalog before Braket's device and job resource correction."""
    return _verified_archived_current(
        BRAKET_690_PREVIOUS_MANIFEST_PATH, BRAKET_690_PREVIOUS_ARCHIVE,
        BRAKET_690_PREVIOUS_MANIFEST, BRAKET_690_PREVIOUS_ARCHIVE_SHA256,
        BRAKET_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_instance_connect_690_previous():
    """Keep the exact catalog before host access became unresolved."""
    return _verified_archived_current(
        INSTANCE_CONNECT_690_PREVIOUS_MANIFEST_PATH, INSTANCE_CONNECT_690_PREVIOUS_ARCHIVE,
        INSTANCE_CONNECT_690_PREVIOUS_MANIFEST, INSTANCE_CONNECT_690_PREVIOUS_ARCHIVE_SHA256,
        INSTANCE_CONNECT_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_teststate_690_previous():
    """Keep the exact catalog before TestState role reach became unresolved."""
    return _verified_archived_current(
        TESTSTATE_690_PREVIOUS_MANIFEST_PATH, TESTSTATE_690_PREVIOUS_ARCHIVE,
        TESTSTATE_690_PREVIOUS_MANIFEST, TESTSTATE_690_PREVIOUS_ARCHIVE_SHA256,
        TESTSTATE_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_appstream_resource_700_previous():
    """Keep reports bound to the 700-entry catalog before AppStream resource requirements."""
    return _verified_archived_current(
        APPSTREAM_RESOURCE_700_PREVIOUS_MANIFEST_PATH,
        APPSTREAM_RESOURCE_700_PREVIOUS_ARCHIVE,
        APPSTREAM_RESOURCE_700_PREVIOUS_MANIFEST,
        APPSTREAM_RESOURCE_700_PREVIOUS_ARCHIVE_SHA256,
        APPSTREAM_RESOURCE_700_PREVIOUS_TREE, 700, 3734)


@lru_cache(maxsize=1)
def _verified_source_repin_700_previous():
    """Keep reports bound to the 700-entry catalog before source anchor repinning."""
    return _verified_archived_current(
        SOURCE_REPIN_700_PREVIOUS_MANIFEST_PATH,
        SOURCE_REPIN_700_PREVIOUS_ARCHIVE,
        SOURCE_REPIN_700_PREVIOUS_MANIFEST,
        SOURCE_REPIN_700_PREVIOUS_ARCHIVE_SHA256,
        SOURCE_REPIN_700_PREVIOUS_TREE, 700, 3734)


@lru_cache(maxsize=1)
def _verified_final_aws_audit_691_previous():
    """Keep reports bound to the catalog before the final AWS route review."""
    return _verified_archived_current(
        FINAL_AWS_AUDIT_691_PREVIOUS_MANIFEST_PATH,
        FINAL_AWS_AUDIT_691_PREVIOUS_ARCHIVE,
        FINAL_AWS_AUDIT_691_PREVIOUS_MANIFEST,
        FINAL_AWS_AUDIT_691_PREVIOUS_ARCHIVE_SHA256,
        FINAL_AWS_AUDIT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_final_two_role_effects_691_previous():
    """Keep the exact catalog before HyperPod and Organizations proof binding."""
    return _verified_archived_current(
        FINAL_TWO_ROLE_EFFECTS_691_PREVIOUS_MANIFEST_PATH,
        FINAL_TWO_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE,
        FINAL_TWO_ROLE_EFFECTS_691_PREVIOUS_MANIFEST,
        FINAL_TWO_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256,
        FINAL_TWO_ROLE_EFFECTS_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_jit_workspaces_role_effects_691_previous():
    """Keep the exact catalog before JIT and WorkSpaces role-effect binding."""
    return _verified_archived_current(
        JIT_WORKSPACES_ROLE_EFFECTS_691_PREVIOUS_MANIFEST_PATH,
        JIT_WORKSPACES_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE,
        JIT_WORKSPACES_ROLE_EFFECTS_691_PREVIOUS_MANIFEST,
        JIT_WORKSPACES_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256,
        JIT_WORKSPACES_ROLE_EFFECTS_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_servicecatalog_role_effects_691_previous():
    """Keep the exact catalog before Service Catalog role-effect binding."""
    return _verified_archived_current(
        SERVICECATALOG_ROLE_EFFECTS_691_PREVIOUS_MANIFEST_PATH,
        SERVICECATALOG_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE,
        SERVICECATALOG_ROLE_EFFECTS_691_PREVIOUS_MANIFEST,
        SERVICECATALOG_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256,
        SERVICECATALOG_ROLE_EFFECTS_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_mwaa_role_effects_691_previous():
    """Keep the exact catalog before MWAA execution-role proof binding."""
    return _verified_archived_current(
        MWAA_ROLE_EFFECTS_691_PREVIOUS_MANIFEST_PATH,
        MWAA_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE,
        MWAA_ROLE_EFFECTS_691_PREVIOUS_MANIFEST,
        MWAA_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256,
        MWAA_ROLE_EFFECTS_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_migrationhub_role_effects_691_previous():
    """Keep the exact catalog before Migration Hub role-effect binding."""
    return _verified_archived_current(
        MIGRATIONHUB_ROLE_EFFECTS_691_PREVIOUS_MANIFEST_PATH,
        MIGRATIONHUB_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE,
        MIGRATIONHUB_ROLE_EFFECTS_691_PREVIOUS_MANIFEST,
        MIGRATIONHUB_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256,
        MIGRATIONHUB_ROLE_EFFECTS_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_m2_role_effect_691_previous():
    """Keep the exact catalog before M2 execution-role proof binding."""
    return _verified_archived_current(
        M2_ROLE_EFFECT_691_PREVIOUS_MANIFEST_PATH,
        M2_ROLE_EFFECT_691_PREVIOUS_ARCHIVE,
        M2_ROLE_EFFECT_691_PREVIOUS_MANIFEST,
        M2_ROLE_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        M2_ROLE_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_lambda_wrapper_role_swap_691_previous():
    """Keep the exact catalog before the Lambda wrapper-layer role-swap route."""
    return _verified_archived_current(
        LAMBDA_WRAPPER_ROLE_SWAP_691_PREVIOUS_MANIFEST_PATH,
        LAMBDA_WRAPPER_ROLE_SWAP_691_PREVIOUS_ARCHIVE,
        LAMBDA_WRAPPER_ROLE_SWAP_691_PREVIOUS_MANIFEST,
        LAMBDA_WRAPPER_ROLE_SWAP_691_PREVIOUS_ARCHIVE_SHA256,
        LAMBDA_WRAPPER_ROLE_SWAP_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_lambda_existing_sqs_mapping_691_previous():
    """Keep the exact catalog before existing SQS mapping binding."""
    return _verified_archived_current(
        LAMBDA_EXISTING_SQS_MAPPING_691_PREVIOUS_MANIFEST_PATH,
        LAMBDA_EXISTING_SQS_MAPPING_691_PREVIOUS_ARCHIVE,
        LAMBDA_EXISTING_SQS_MAPPING_691_PREVIOUS_MANIFEST,
        LAMBDA_EXISTING_SQS_MAPPING_691_PREVIOUS_ARCHIVE_SHA256,
        LAMBDA_EXISTING_SQS_MAPPING_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_lambda_dynamodb_stream_691_previous():
    """Keep the exact catalog before DynamoDB stream role binding."""
    return _verified_archived_current(
        LAMBDA_DYNAMODB_STREAM_691_PREVIOUS_MANIFEST_PATH,
        LAMBDA_DYNAMODB_STREAM_691_PREVIOUS_ARCHIVE,
        LAMBDA_DYNAMODB_STREAM_691_PREVIOUS_MANIFEST,
        LAMBDA_DYNAMODB_STREAM_691_PREVIOUS_ARCHIVE_SHA256,
        LAMBDA_DYNAMODB_STREAM_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_lambda_eventbridge_schedule_691_previous():
    """Keep the exact catalog before EventBridge schedule and target binding."""
    return _verified_archived_current(
        LAMBDA_EVENTBRIDGE_SCHEDULE_691_PREVIOUS_MANIFEST_PATH,
        LAMBDA_EVENTBRIDGE_SCHEDULE_691_PREVIOUS_ARCHIVE,
        LAMBDA_EVENTBRIDGE_SCHEDULE_691_PREVIOUS_MANIFEST,
        LAMBDA_EVENTBRIDGE_SCHEDULE_691_PREVIOUS_ARCHIVE_SHA256,
        LAMBDA_EVENTBRIDGE_SCHEDULE_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_lambda_microvm_connector_691_previous():
    """Keep the exact catalog before Lambda MicroVM connector authorization correction."""
    return _verified_archived_current(
        LAMBDA_MICROVM_CONNECTOR_691_PREVIOUS_MANIFEST_PATH,
        LAMBDA_MICROVM_CONNECTOR_691_PREVIOUS_ARCHIVE,
        LAMBDA_MICROVM_CONNECTOR_691_PREVIOUS_MANIFEST,
        LAMBDA_MICROVM_CONNECTOR_691_PREVIOUS_ARCHIVE_SHA256,
        LAMBDA_MICROVM_CONNECTOR_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_kafkaconnect_plugin_effect_691_previous():
    """Keep the exact catalog before MSK Connect plugin role-effect binding."""
    return _verified_archived_current(
        KAFKACONNECT_PLUGIN_EFFECT_691_PREVIOUS_MANIFEST_PATH,
        KAFKACONNECT_PLUGIN_EFFECT_691_PREVIOUS_ARCHIVE,
        KAFKACONNECT_PLUGIN_EFFECT_691_PREVIOUS_MANIFEST,
        KAFKACONNECT_PLUGIN_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        KAFKACONNECT_PLUGIN_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_iot_existing_alias_effect_691_previous():
    """Keep the exact catalog before IoT existing-alias evidence binding."""
    return _verified_archived_current(
        IOT_EXISTING_ALIAS_EFFECT_691_PREVIOUS_MANIFEST_PATH,
        IOT_EXISTING_ALIAS_EFFECT_691_PREVIOUS_ARCHIVE,
        IOT_EXISTING_ALIAS_EFFECT_691_PREVIOUS_MANIFEST,
        IOT_EXISTING_ALIAS_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        IOT_EXISTING_ALIAS_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_glue_external_script_effect_691_previous():
    """Keep the exact catalog before Glue external script binding."""
    return _verified_archived_current(
        GLUE_EXTERNAL_SCRIPT_EFFECT_691_PREVIOUS_MANIFEST_PATH,
        GLUE_EXTERNAL_SCRIPT_EFFECT_691_PREVIOUS_ARCHIVE,
        GLUE_EXTERNAL_SCRIPT_EFFECT_691_PREVIOUS_MANIFEST,
        GLUE_EXTERNAL_SCRIPT_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        GLUE_EXTERNAL_SCRIPT_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_gameliftstreams_session_effect_691_previous():
    """Keep the exact catalog before GameLift Streams role session binding."""
    return _verified_archived_current(
        GAMELIFTSTREAMS_SESSION_EFFECT_691_PREVIOUS_MANIFEST_PATH,
        GAMELIFTSTREAMS_SESSION_EFFECT_691_PREVIOUS_ARCHIVE,
        GAMELIFTSTREAMS_SESSION_EFFECT_691_PREVIOUS_MANIFEST,
        GAMELIFTSTREAMS_SESSION_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        GAMELIFTSTREAMS_SESSION_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_events_subscriber_effect_691_previous():
    """Keep the exact catalog before EventBridge subscriber effect binding."""
    return _verified_archived_current(
        EVENTS_SUBSCRIBER_EFFECT_691_PREVIOUS_MANIFEST_PATH,
        EVENTS_SUBSCRIBER_EFFECT_691_PREVIOUS_ARCHIVE,
        EVENTS_SUBSCRIBER_EFFECT_691_PREVIOUS_MANIFEST,
        EVENTS_SUBSCRIBER_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        EVENTS_SUBSCRIBER_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_emr_runjobflow_role_691_previous():
    """Keep the exact catalog before the EMR cluster launch role binding."""
    return _verified_archived_current(
        EMR_RUNJOBFLOW_ROLE_691_PREVIOUS_MANIFEST_PATH,
        EMR_RUNJOBFLOW_ROLE_691_PREVIOUS_ARCHIVE,
        EMR_RUNJOBFLOW_ROLE_691_PREVIOUS_MANIFEST,
        EMR_RUNJOBFLOW_ROLE_691_PREVIOUS_ARCHIVE_SHA256,
        EMR_RUNJOBFLOW_ROLE_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_emr_cluster_endpoint_effect_691_previous():
    """Keep the exact catalog before EMR endpoint role-effect binding."""
    return _verified_archived_current(
        EMR_CLUSTER_ENDPOINT_EFFECT_691_PREVIOUS_MANIFEST_PATH,
        EMR_CLUSTER_ENDPOINT_EFFECT_691_PREVIOUS_ARCHIVE,
        EMR_CLUSTER_ENDPOINT_EFFECT_691_PREVIOUS_MANIFEST,
        EMR_CLUSTER_ENDPOINT_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        EMR_CLUSTER_ENDPOINT_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_emr_serverless_effect_691_previous():
    """Keep the exact catalog before EMR Serverless job-effect binding."""
    return _verified_archived_current(
        EMR_SERVERLESS_EFFECT_691_PREVIOUS_MANIFEST_PATH,
        EMR_SERVERLESS_EFFECT_691_PREVIOUS_ARCHIVE,
        EMR_SERVERLESS_EFFECT_691_PREVIOUS_MANIFEST,
        EMR_SERVERLESS_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        EMR_SERVERLESS_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_emr_containers_effects_691_previous():
    """Keep the exact catalog before EMR on EKS runtime-effect binding."""
    return _verified_archived_current(
        EMR_CONTAINERS_EFFECTS_691_PREVIOUS_MANIFEST_PATH,
        EMR_CONTAINERS_EFFECTS_691_PREVIOUS_ARCHIVE,
        EMR_CONTAINERS_EFFECTS_691_PREVIOUS_MANIFEST,
        EMR_CONTAINERS_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256,
        EMR_CONTAINERS_EFFECTS_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_beanstalk_role_691_previous():
    """Keep the exact catalog before the Beanstalk environment role binding."""
    return _verified_archived_current(
        BEANSTALK_ROLE_691_PREVIOUS_MANIFEST_PATH,
        BEANSTALK_ROLE_691_PREVIOUS_ARCHIVE,
        BEANSTALK_ROLE_691_PREVIOUS_MANIFEST,
        BEANSTALK_ROLE_691_PREVIOUS_ARCHIVE_SHA256,
        BEANSTALK_ROLE_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_spot_request_role_691_previous():
    """Keep the exact catalog before the Spot request role binding."""
    return _verified_archived_current(
        SPOT_REQUEST_ROLE_691_PREVIOUS_MANIFEST_PATH,
        SPOT_REQUEST_ROLE_691_PREVIOUS_ARCHIVE,
        SPOT_REQUEST_ROLE_691_PREVIOUS_MANIFEST,
        SPOT_REQUEST_ROLE_691_PREVIOUS_ARCHIVE_SHA256,
        SPOT_REQUEST_ROLE_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_runinstances_role_691_previous():
    """Keep the exact catalog before the EC2 RunInstances role binding."""
    return _verified_archived_current(
        RUNINSTANCES_ROLE_691_PREVIOUS_MANIFEST_PATH,
        RUNINSTANCES_ROLE_691_PREVIOUS_ARCHIVE,
        RUNINSTANCES_ROLE_691_PREVIOUS_MANIFEST,
        RUNINSTANCES_ROLE_691_PREVIOUS_ARCHIVE_SHA256,
        RUNINSTANCES_ROLE_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_spot_fleet_role_execution_691_previous():
    """Keep the exact catalog before the Spot Fleet execution binding."""
    return _verified_archived_current(
        SPOT_FLEET_ROLE_EXECUTION_691_PREVIOUS_MANIFEST_PATH,
        SPOT_FLEET_ROLE_EXECUTION_691_PREVIOUS_ARCHIVE,
        SPOT_FLEET_ROLE_EXECUTION_691_PREVIOUS_MANIFEST,
        SPOT_FLEET_ROLE_EXECUTION_691_PREVIOUS_ARCHIVE_SHA256,
        SPOT_FLEET_ROLE_EXECUTION_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_asg_role_execution_691_previous():
    """Keep the exact catalog before Auto Scaling launch-role execution binding."""
    return _verified_archived_current(
        ASG_ROLE_EXECUTION_691_PREVIOUS_MANIFEST_PATH,
        ASG_ROLE_EXECUTION_691_PREVIOUS_ARCHIVE,
        ASG_ROLE_EXECUTION_691_PREVIOUS_MANIFEST,
        ASG_ROLE_EXECUTION_691_PREVIOUS_ARCHIVE_SHA256,
        ASG_ROLE_EXECUTION_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_devicefarm_existing_spec_691_previous():
    """Keep the exact catalog before the Device Farm existing-spec role binding."""
    return _verified_archived_current(
        DEVICEFARM_EXISTING_SPEC_691_PREVIOUS_MANIFEST_PATH,
        DEVICEFARM_EXISTING_SPEC_691_PREVIOUS_ARCHIVE,
        DEVICEFARM_EXISTING_SPEC_691_PREVIOUS_MANIFEST,
        DEVICEFARM_EXISTING_SPEC_691_PREVIOUS_ARCHIVE_SHA256,
        DEVICEFARM_EXISTING_SPEC_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_deadline_fleet_worker_691_previous():
    """Keep the exact catalog before the Deadline worker authority correction."""
    return _verified_archived_current(
        DEADLINE_FLEET_WORKER_691_PREVIOUS_MANIFEST_PATH,
        DEADLINE_FLEET_WORKER_691_PREVIOUS_ARCHIVE,
        DEADLINE_FLEET_WORKER_691_PREVIOUS_MANIFEST,
        DEADLINE_FLEET_WORKER_691_PREVIOUS_ARCHIVE_SHA256,
        DEADLINE_FLEET_WORKER_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_deadline_queue_role_691_previous():
    """Keep the exact catalog before the Deadline queue role update binding."""
    return _verified_archived_current(
        DEADLINE_QUEUE_ROLE_691_PREVIOUS_MANIFEST_PATH,
        DEADLINE_QUEUE_ROLE_691_PREVIOUS_ARCHIVE,
        DEADLINE_QUEUE_ROLE_691_PREVIOUS_MANIFEST,
        DEADLINE_QUEUE_ROLE_691_PREVIOUS_ARCHIVE_SHA256,
        DEADLINE_QUEUE_ROLE_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_datapipeline_ec2_effect_691_previous():
    """Keep the exact catalog before Data Pipeline required EC2 role execution evidence."""
    return _verified_archived_current(
        DATAPIPELINE_EC2_EFFECT_691_PREVIOUS_MANIFEST_PATH,
        DATAPIPELINE_EC2_EFFECT_691_PREVIOUS_ARCHIVE,
        DATAPIPELINE_EC2_EFFECT_691_PREVIOUS_MANIFEST,
        DATAPIPELINE_EC2_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        DATAPIPELINE_EC2_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_config_remediation_effect_691_previous():
    """Keep the exact catalog before Config remediation accepted existing documents."""
    return _verified_archived_current(
        CONFIG_REMEDIATION_EFFECT_691_PREVIOUS_MANIFEST_PATH,
        CONFIG_REMEDIATION_EFFECT_691_PREVIOUS_ARCHIVE,
        CONFIG_REMEDIATION_EFFECT_691_PREVIOUS_MANIFEST,
        CONFIG_REMEDIATION_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        CONFIG_REMEDIATION_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_codepipeline_existing_effect_691_previous():
    """Keep the exact catalog before an existing pipeline required artifact delivery evidence."""
    return _verified_archived_current(
        CODEPIPELINE_EXISTING_EFFECT_691_PREVIOUS_MANIFEST_PATH,
        CODEPIPELINE_EXISTING_EFFECT_691_PREVIOUS_ARCHIVE,
        CODEPIPELINE_EXISTING_EFFECT_691_PREVIOUS_MANIFEST,
        CODEPIPELINE_EXISTING_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        CODEPIPELINE_EXISTING_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_codebuild_debug_effect_691_previous():
    """Keep the exact catalog before CodeBuild debug required a live role effect."""
    return _verified_archived_current(
        CODEBUILD_DEBUG_EFFECT_691_PREVIOUS_MANIFEST_PATH,
        CODEBUILD_DEBUG_EFFECT_691_PREVIOUS_ARCHIVE,
        CODEBUILD_DEBUG_EFFECT_691_PREVIOUS_MANIFEST,
        CODEBUILD_DEBUG_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        CODEBUILD_DEBUG_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_ssm_existing_automation_effect_691_previous():
    """Keep the exact catalog before existing Automation required a role effect witness."""
    return _verified_archived_current(
        SSM_EXISTING_AUTOMATION_EFFECT_691_PREVIOUS_MANIFEST_PATH,
        SSM_EXISTING_AUTOMATION_EFFECT_691_PREVIOUS_ARCHIVE,
        SSM_EXISTING_AUTOMATION_EFFECT_691_PREVIOUS_MANIFEST,
        SSM_EXISTING_AUTOMATION_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        SSM_EXISTING_AUTOMATION_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_bedrock_actiongroup_effect_691_previous():
    """Keep the exact catalog before Bedrock action groups required observed execution."""
    return _verified_archived_current(
        BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_MANIFEST_PATH,
        BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_ARCHIVE,
        BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_MANIFEST,
        BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_agentcore_harness_effect_691_previous():
    """Keep the exact catalog before AgentCore harness commands required evidence."""
    return _verified_archived_current(
        AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_MANIFEST_PATH, AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_ARCHIVE,
        AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_MANIFEST, AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_agentcore_runtime_effects_691_previous():
    """Keep the exact catalog before AgentCore runtime effects required evidence."""
    return _verified_archived_current(
        AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_MANIFEST_PATH, AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_ARCHIVE,
        AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_MANIFEST, AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256,
        AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_amplify_role_effects_691_previous():
    """Keep the exact catalog before Amplify role effects required observed operations."""
    return _verified_archived_current(
        AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_MANIFEST_PATH, AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE,
        AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_MANIFEST, AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256,
        AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_cfn_stackset_effects_691_previous():
    """Keep the exact catalog before StackSet effects required reviewed evidence."""
    return _verified_archived_current(
        CFN_STACKSET_EFFECTS_691_PREVIOUS_MANIFEST_PATH, CFN_STACKSET_EFFECTS_691_PREVIOUS_ARCHIVE,
        CFN_STACKSET_EFFECTS_691_PREVIOUS_MANIFEST, CFN_STACKSET_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256,
        CFN_STACKSET_EFFECTS_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_cfn_extension_effect_691_previous():
    """Keep the exact catalog before private extension handler effects were witnessed."""
    return _verified_archived_current(
        CFN_EXTENSION_EFFECT_691_PREVIOUS_MANIFEST_PATH, CFN_EXTENSION_EFFECT_691_PREVIOUS_ARCHIVE,
        CFN_EXTENSION_EFFECT_691_PREVIOUS_MANIFEST, CFN_EXTENSION_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        CFN_EXTENSION_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_cfn_template_effect_691_previous():
    """Keep the exact catalog before CloudFormation required witnessed role effects."""
    return _verified_archived_current(
        CFN_TEMPLATE_EFFECT_691_PREVIOUS_MANIFEST_PATH, CFN_TEMPLATE_EFFECT_691_PREVIOUS_ARCHIVE,
        CFN_TEMPLATE_EFFECT_691_PREVIOUS_MANIFEST, CFN_TEMPLATE_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        CFN_TEMPLATE_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_teststate_role_effect_691_previous():
    """Keep the exact catalog before TestState accepted a reviewed role operation."""
    return _verified_archived_current(
        TESTSTATE_ROLE_EFFECT_691_PREVIOUS_MANIFEST_PATH, TESTSTATE_ROLE_EFFECT_691_PREVIOUS_ARCHIVE,
        TESTSTATE_ROLE_EFFECT_691_PREVIOUS_MANIFEST, TESTSTATE_ROLE_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        TESTSTATE_ROLE_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_sfn_role_effect_691_previous():
    """Keep the exact catalog before Step Functions role effects required reviewed execution."""
    return _verified_archived_current(
        SFN_ROLE_EFFECT_691_PREVIOUS_MANIFEST_PATH, SFN_ROLE_EFFECT_691_PREVIOUS_ARCHIVE,
        SFN_ROLE_EFFECT_691_PREVIOUS_MANIFEST, SFN_ROLE_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        SFN_ROLE_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_instance_connect_witness_691_previous():
    """Keep the exact catalog before Instance Connect accepted a bounded host witness."""
    return _verified_archived_current(
        INSTANCE_CONNECT_WITNESS_691_PREVIOUS_MANIFEST_PATH,
        INSTANCE_CONNECT_WITNESS_691_PREVIOUS_ARCHIVE,
        INSTANCE_CONNECT_WITNESS_691_PREVIOUS_MANIFEST,
        INSTANCE_CONNECT_WITNESS_691_PREVIOUS_ARCHIVE_SHA256,
        INSTANCE_CONNECT_WITNESS_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_ecs_taskset_691_previous():
    """Keep the exact catalog before task-set escalation was bound to one service."""
    return _verified_archived_current(
        ECS_TASKSET_691_PREVIOUS_MANIFEST_PATH, ECS_TASKSET_691_PREVIOUS_ARCHIVE,
        ECS_TASKSET_691_PREVIOUS_MANIFEST, ECS_TASKSET_691_PREVIOUS_ARCHIVE_SHA256,
        ECS_TASKSET_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_ecs_node_escape_691_previous():
    """Keep the exact catalog before privileged task escape was bound to one host."""
    return _verified_archived_current(
        ECS_NODE_ESCAPE_691_PREVIOUS_MANIFEST_PATH, ECS_NODE_ESCAPE_691_PREVIOUS_ARCHIVE,
        ECS_NODE_ESCAPE_691_PREVIOUS_MANIFEST, ECS_NODE_ESCAPE_691_PREVIOUS_ARCHIVE_SHA256,
        ECS_NODE_ESCAPE_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_ecs_service_691_previous():
    """Keep the exact catalog before ECS service deployment was bound to a concrete cluster."""
    return _verified_archived_current(
        ECS_SERVICE_691_PREVIOUS_MANIFEST_PATH, ECS_SERVICE_691_PREVIOUS_ARCHIVE,
        ECS_SERVICE_691_PREVIOUS_MANIFEST, ECS_SERVICE_691_PREVIOUS_ARCHIVE_SHA256,
        ECS_SERVICE_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_ecs_start_task_691_previous():
    """Keep the exact catalog before ECS StartTask was bound to a connected host."""
    return _verified_archived_current(
        ECS_START_TASK_691_PREVIOUS_MANIFEST_PATH, ECS_START_TASK_691_PREVIOUS_ARCHIVE,
        ECS_START_TASK_691_PREVIOUS_MANIFEST, ECS_START_TASK_691_PREVIOUS_ARCHIVE_SHA256,
        ECS_START_TASK_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_ecs_new_task_691_previous():
    """Keep the exact catalog before the new ECS task launch was bound to a live cluster."""
    return _verified_archived_current(
        ECS_NEW_TASK_691_PREVIOUS_MANIFEST_PATH, ECS_NEW_TASK_691_PREVIOUS_ARCHIVE,
        ECS_NEW_TASK_691_PREVIOUS_MANIFEST, ECS_NEW_TASK_691_PREVIOUS_ARCHIVE_SHA256,
        ECS_NEW_TASK_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_organizations_rcp_691_previous():
    """Keep the exact catalog before the Organizations root SCP and target RCP wording."""
    return _verified_archived_current(
        ORGANIZATIONS_RCP_691_PREVIOUS_MANIFEST_PATH,
        ORGANIZATIONS_RCP_691_PREVIOUS_ARCHIVE,
        ORGANIZATIONS_RCP_691_PREVIOUS_MANIFEST,
        ORGANIZATIONS_RCP_691_PREVIOUS_ARCHIVE_SHA256,
        ORGANIZATIONS_RCP_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_lambda_signer_691_previous():
    """Keep the exact catalog before signing-profile and artifact join requirements."""
    return _verified_archived_current(
        LAMBDA_SIGNER_691_PREVIOUS_MANIFEST_PATH,
        LAMBDA_SIGNER_691_PREVIOUS_ARCHIVE,
        LAMBDA_SIGNER_691_PREVIOUS_MANIFEST,
        LAMBDA_SIGNER_691_PREVIOUS_ARCHIVE_SHA256,
        LAMBDA_SIGNER_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_bedrock_actiongroup_691_previous():
    """Keep the exact catalog before guarding unverified Bedrock action-group execution."""
    return _verified_archived_current(
        BEDROCK_ACTIONGROUP_691_PREVIOUS_MANIFEST_PATH,
        BEDROCK_ACTIONGROUP_691_PREVIOUS_ARCHIVE,
        BEDROCK_ACTIONGROUP_691_PREVIOUS_MANIFEST,
        BEDROCK_ACTIONGROUP_691_PREVIOUS_ARCHIVE_SHA256,
        BEDROCK_ACTIONGROUP_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_quicksight_iam_user_691_previous():
    """Keep the exact catalog before IAM-user registration documentation and role-session exclusion."""
    return _verified_archived_current(
        QUICKSIGHT_IAM_USER_691_PREVIOUS_MANIFEST_PATH,
        QUICKSIGHT_IAM_USER_691_PREVIOUS_ARCHIVE,
        QUICKSIGHT_IAM_USER_691_PREVIOUS_MANIFEST,
        QUICKSIGHT_IAM_USER_691_PREVIOUS_ARCHIVE_SHA256,
        QUICKSIGHT_IAM_USER_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_kafkaconnect_guard_691_previous():
    """Keep the exact catalog before the MSK Connect execution guard."""
    return _verified_archived_current(
        KAFKACONNECT_GUARD_691_PREVIOUS_MANIFEST_PATH,
        KAFKACONNECT_GUARD_691_PREVIOUS_ARCHIVE,
        KAFKACONNECT_GUARD_691_PREVIOUS_MANIFEST,
        KAFKACONNECT_GUARD_691_PREVIOUS_ARCHIVE_SHA256,
        KAFKACONNECT_GUARD_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_braket_script_691_previous():
    """Keep the exact catalog before Braket device, code and output joins."""
    return _verified_archived_current(
        BRAKET_SCRIPT_691_PREVIOUS_MANIFEST_PATH, BRAKET_SCRIPT_691_PREVIOUS_ARCHIVE,
        BRAKET_SCRIPT_691_PREVIOUS_MANIFEST, BRAKET_SCRIPT_691_PREVIOUS_ARCHIVE_SHA256,
        BRAKET_SCRIPT_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_sagemaker_domain_default_691_previous():
    """Keep the exact catalog before the Studio domain-default route."""
    return _verified_archived_current(
        SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_MANIFEST_PATH,
        SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_ARCHIVE,
        SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_MANIFEST,
        SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_sagemaker_role_swap_691_previous():
    """Keep the exact catalog before the Studio profile role-swap route."""
    return _verified_archived_current(
        SAGEMAKER_ROLE_SWAP_691_PREVIOUS_MANIFEST_PATH,
        SAGEMAKER_ROLE_SWAP_691_PREVIOUS_ARCHIVE,
        SAGEMAKER_ROLE_SWAP_691_PREVIOUS_MANIFEST,
        SAGEMAKER_ROLE_SWAP_691_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_ROLE_SWAP_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_sagemaker_new_profile_691_previous():
    """Keep the exact catalog before the Studio new-profile app route."""
    return _verified_archived_current(
        SAGEMAKER_NEW_PROFILE_691_PREVIOUS_MANIFEST_PATH,
        SAGEMAKER_NEW_PROFILE_691_PREVIOUS_ARCHIVE,
        SAGEMAKER_NEW_PROFILE_691_PREVIOUS_MANIFEST,
        SAGEMAKER_NEW_PROFILE_691_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_NEW_PROFILE_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_sagemaker_studio_profile_691_previous():
    """Keep the exact catalog before the Studio profile lifecycle route."""
    return _verified_archived_current(
        SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_MANIFEST_PATH,
        SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_ARCHIVE,
        SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_MANIFEST,
        SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_sagemaker_hpo_691_previous():
    """Keep the exact catalog before the HPO script-mode role route."""
    return _verified_archived_current(
        SAGEMAKER_HPO_691_PREVIOUS_MANIFEST_PATH, SAGEMAKER_HPO_691_PREVIOUS_ARCHIVE,
        SAGEMAKER_HPO_691_PREVIOUS_MANIFEST, SAGEMAKER_HPO_691_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_HPO_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_sagemaker_training_691_previous():
    """Keep the exact catalog before the Training job inline-entrypoint route."""
    return _verified_archived_current(
        SAGEMAKER_TRAINING_691_PREVIOUS_MANIFEST_PATH, SAGEMAKER_TRAINING_691_PREVIOUS_ARCHIVE,
        SAGEMAKER_TRAINING_691_PREVIOUS_MANIFEST, SAGEMAKER_TRAINING_691_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_TRAINING_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_sagemaker_processing_691_previous():
    """Keep the exact catalog before the Processing job inline-entrypoint route."""
    return _verified_archived_current(
        SAGEMAKER_PROCESSING_691_PREVIOUS_MANIFEST_PATH, SAGEMAKER_PROCESSING_691_PREVIOUS_ARCHIVE,
        SAGEMAKER_PROCESSING_691_PREVIOUS_MANIFEST, SAGEMAKER_PROCESSING_691_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_PROCESSING_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_sagemaker_jobs_691_previous():
    """Keep the exact catalog before SageMaker job and PassRole scoping."""
    return _verified_archived_current(
        SAGEMAKER_JOBS_691_PREVIOUS_MANIFEST_PATH, SAGEMAKER_JOBS_691_PREVIOUS_ARCHIVE,
        SAGEMAKER_JOBS_691_PREVIOUS_MANIFEST, SAGEMAKER_JOBS_691_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_JOBS_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_agentcore_harness_691_previous():
    """Keep the exact catalog before the harness composite-operation correction."""
    return _verified_archived_current(
        AGENTCORE_HARNESS_691_PREVIOUS_MANIFEST_PATH, AGENTCORE_HARNESS_691_PREVIOUS_ARCHIVE,
        AGENTCORE_HARNESS_691_PREVIOUS_MANIFEST, AGENTCORE_HARNESS_691_PREVIOUS_ARCHIVE_SHA256,
        AGENTCORE_HARNESS_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_agentcore_create_691_previous():
    """Keep the exact catalog before generated AgentCore Runtime scope binding."""
    return _verified_archived_current(
        AGENTCORE_CREATE_691_PREVIOUS_MANIFEST_PATH, AGENTCORE_CREATE_691_PREVIOUS_ARCHIVE,
        AGENTCORE_CREATE_691_PREVIOUS_MANIFEST, AGENTCORE_CREATE_691_PREVIOUS_ARCHIVE_SHA256,
        AGENTCORE_CREATE_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_agentcore_runtime_691_previous():
    """Keep the exact catalog before the AgentCore runtime/endpoint join."""
    return _verified_archived_current(
        AGENTCORE_RUNTIME_691_PREVIOUS_MANIFEST_PATH, AGENTCORE_RUNTIME_691_PREVIOUS_ARCHIVE,
        AGENTCORE_RUNTIME_691_PREVIOUS_MANIFEST, AGENTCORE_RUNTIME_691_PREVIOUS_ARCHIVE_SHA256,
        AGENTCORE_RUNTIME_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_agentcore_existing_690_previous():
    """Keep the exact catalog before the existing Code Interpreter route."""
    return _verified_archived_current(
        AGENTCORE_EXISTING_690_PREVIOUS_MANIFEST_PATH, AGENTCORE_EXISTING_690_PREVIOUS_ARCHIVE,
        AGENTCORE_EXISTING_690_PREVIOUS_MANIFEST, AGENTCORE_EXISTING_690_PREVIOUS_ARCHIVE_SHA256,
        AGENTCORE_EXISTING_690_PREVIOUS_TREE, 690, 3736)


@lru_cache(maxsize=1)
def _verified_agentcore_bounds_690_previous():
    """Keep the exact catalog before AgentCore browser and gateway bounds."""
    return _verified_archived_current(
        AGENTCORE_BOUNDS_690_PREVIOUS_MANIFEST_PATH, AGENTCORE_BOUNDS_690_PREVIOUS_ARCHIVE,
        AGENTCORE_BOUNDS_690_PREVIOUS_MANIFEST, AGENTCORE_BOUNDS_690_PREVIOUS_ARCHIVE_SHA256,
        AGENTCORE_BOUNDS_690_PREVIOUS_TREE, 690, 3734)


@lru_cache(maxsize=1)
def _verified_sts_federation_690_previous():
    """Keep the exact catalog before SAML and web-identity candidates were tracked."""
    return _verified_archived_current(
        STS_FEDERATION_690_PREVIOUS_MANIFEST_PATH, STS_FEDERATION_690_PREVIOUS_ARCHIVE,
        STS_FEDERATION_690_PREVIOUS_MANIFEST, STS_FEDERATION_690_PREVIOUS_ARCHIVE_SHA256,
        STS_FEDERATION_690_PREVIOUS_TREE, 690, 3732)


@lru_cache(maxsize=1)
def _verified_amplify_role_690_previous():
    """Keep the exact catalog before Amplify app and branch gating."""
    return _verified_archived_current(
        AMPLIFY_ROLE_690_PREVIOUS_MANIFEST_PATH, AMPLIFY_ROLE_690_PREVIOUS_ARCHIVE,
        AMPLIFY_ROLE_690_PREVIOUS_MANIFEST, AMPLIFY_ROLE_690_PREVIOUS_ARCHIVE_SHA256,
        AMPLIFY_ROLE_690_PREVIOUS_TREE, 690, 3732)


@lru_cache(maxsize=1)
def _verified_emr_runtime_689_previous():
    """Keep the exact catalog before EMR runtime-role routes were corrected."""
    return _verified_archived_current(
        EMR_RUNTIME_689_PREVIOUS_MANIFEST_PATH, EMR_RUNTIME_689_PREVIOUS_ARCHIVE,
        EMR_RUNTIME_689_PREVIOUS_MANIFEST, EMR_RUNTIME_689_PREVIOUS_ARCHIVE_SHA256,
        EMR_RUNTIME_689_PREVIOUS_TREE, 689, 3730)


@lru_cache(maxsize=1)
def _verified_elasticbeanstalk_effect_689_previous():
    """Keep the exact catalog before Elastic Beanstalk runtime gating."""
    return _verified_archived_current(
        ELASTICBEANSTALK_EFFECT_689_PREVIOUS_MANIFEST_PATH, ELASTICBEANSTALK_EFFECT_689_PREVIOUS_ARCHIVE,
        ELASTICBEANSTALK_EFFECT_689_PREVIOUS_MANIFEST, ELASTICBEANSTALK_EFFECT_689_PREVIOUS_ARCHIVE_SHA256,
        ELASTICBEANSTALK_EFFECT_689_PREVIOUS_TREE, 689, 3730)


@lru_cache(maxsize=1)
def _verified_config_remediation_689_previous():
    """Keep the exact catalog before Config remediation runtime gating."""
    return _verified_archived_current(
        CONFIG_REMEDIATION_689_PREVIOUS_MANIFEST_PATH, CONFIG_REMEDIATION_689_PREVIOUS_ARCHIVE,
        CONFIG_REMEDIATION_689_PREVIOUS_MANIFEST, CONFIG_REMEDIATION_689_PREVIOUS_ARCHIVE_SHA256,
        CONFIG_REMEDIATION_689_PREVIOUS_TREE, 689, 3729)


@lru_cache(maxsize=1)
def _verified_servicecatalog_effect_689_previous():
    """Keep the exact catalog before Service Catalog artifact-effect gating."""
    return _verified_archived_current(
        SERVICECATALOG_EFFECT_689_PREVIOUS_MANIFEST_PATH, SERVICECATALOG_EFFECT_689_PREVIOUS_ARCHIVE,
        SERVICECATALOG_EFFECT_689_PREVIOUS_MANIFEST, SERVICECATALOG_EFFECT_689_PREVIOUS_ARCHIVE_SHA256,
        SERVICECATALOG_EFFECT_689_PREVIOUS_TREE, 689, 3729)


@lru_cache(maxsize=1)
def _verified_org_access_role_689_previous():
    """Keep the exact catalog before generated Organizations access-role gating."""
    return _verified_archived_current(
        ORG_ACCESS_ROLE_689_PREVIOUS_MANIFEST_PATH, ORG_ACCESS_ROLE_689_PREVIOUS_ARCHIVE,
        ORG_ACCESS_ROLE_689_PREVIOUS_MANIFEST, ORG_ACCESS_ROLE_689_PREVIOUS_ARCHIVE_SHA256,
        ORG_ACCESS_ROLE_689_PREVIOUS_TREE, 689, 3726)


@lru_cache(maxsize=1)
def _verified_stepfunctions_passrole_689_previous():
    """Keep the exact catalog before Step Functions PassRole service binding."""
    return _verified_archived_current(
        STEPFUNCTIONS_PASSROLE_689_PREVIOUS_MANIFEST_PATH, STEPFUNCTIONS_PASSROLE_689_PREVIOUS_ARCHIVE,
        STEPFUNCTIONS_PASSROLE_689_PREVIOUS_MANIFEST, STEPFUNCTIONS_PASSROLE_689_PREVIOUS_ARCHIVE_SHA256,
        STEPFUNCTIONS_PASSROLE_689_PREVIOUS_TREE, 689, 3726)


@lru_cache(maxsize=1)
def _verified_gamelift_coverage_689_previous():
    """Keep the exact catalog before GameLift fleet-variant exclusions."""
    return _verified_archived_current(
        GAMELIFT_COVERAGE_689_PREVIOUS_MANIFEST_PATH, GAMELIFT_COVERAGE_689_PREVIOUS_ARCHIVE,
        GAMELIFT_COVERAGE_689_PREVIOUS_MANIFEST, GAMELIFT_COVERAGE_689_PREVIOUS_ARCHIVE_SHA256,
        GAMELIFT_COVERAGE_689_PREVIOUS_TREE, 689, 3724)


@lru_cache(maxsize=1)
def _verified_cognito_idp_secret_689_previous():
    """Keep the exact catalog before Cognito client-secret scope correction."""
    return _verified_archived_current(
        COGNITO_IDP_SECRET_689_PREVIOUS_MANIFEST_PATH, COGNITO_IDP_SECRET_689_PREVIOUS_ARCHIVE,
        COGNITO_IDP_SECRET_689_PREVIOUS_MANIFEST, COGNITO_IDP_SECRET_689_PREVIOUS_ARCHIVE_SHA256,
        COGNITO_IDP_SECRET_689_PREVIOUS_TREE, 689, 3724)


@lru_cache(maxsize=1)
def _verified_ec2_runinstances_689_previous():
    """Keep the exact catalog before EC2 launch reach became unresolved."""
    return _verified_archived_current(
        EC2_RUNINSTANCES_689_PREVIOUS_MANIFEST_PATH, EC2_RUNINSTANCES_689_PREVIOUS_ARCHIVE,
        EC2_RUNINSTANCES_689_PREVIOUS_MANIFEST, EC2_RUNINSTANCES_689_PREVIOUS_ARCHIVE_SHA256,
        EC2_RUNINSTANCES_689_PREVIOUS_TREE, 689, 3724)


@lru_cache(maxsize=1)
def _verified_stale_coverage_689_previous():
    """Keep the exact catalog before stale coverage text was corrected."""
    return _verified_archived_current(
        STALE_COVERAGE_689_PREVIOUS_MANIFEST_PATH, STALE_COVERAGE_689_PREVIOUS_ARCHIVE,
        STALE_COVERAGE_689_PREVIOUS_MANIFEST, STALE_COVERAGE_689_PREVIOUS_ARCHIVE_SHA256,
        STALE_COVERAGE_689_PREVIOUS_TREE, 689, 3724)


@lru_cache(maxsize=1)
def _verified_finspace_sunset_690_previous():
    """Keep the exact catalog before Amazon FinSpace became unavailable."""
    return _verified_archived_current(
        FINSPACE_SUNSET_690_PREVIOUS_MANIFEST_PATH, FINSPACE_SUNSET_690_PREVIOUS_ARCHIVE,
        FINSPACE_SUNSET_690_PREVIOUS_MANIFEST, FINSPACE_SUNSET_690_PREVIOUS_ARCHIVE_SHA256,
        FINSPACE_SUNSET_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_spot_request_690_previous():
    """Keep the exact catalog before scoped Spot grants became unresolved."""
    return _verified_archived_current(
        SPOT_REQUEST_690_PREVIOUS_MANIFEST_PATH, SPOT_REQUEST_690_PREVIOUS_ARCHIVE,
        SPOT_REQUEST_690_PREVIOUS_MANIFEST, SPOT_REQUEST_690_PREVIOUS_ARCHIVE_SHA256,
        SPOT_REQUEST_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_mwaa_slr_690_previous():
    """Keep the exact catalog before MWAA service-linked role scope correction."""
    return _verified_archived_current(
        MWAA_SLR_690_PREVIOUS_MANIFEST_PATH, MWAA_SLR_690_PREVIOUS_ARCHIVE,
        MWAA_SLR_690_PREVIOUS_MANIFEST, MWAA_SLR_690_PREVIOUS_ARCHIVE_SHA256,
        MWAA_SLR_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_glue_script_690_previous():
    """Keep the exact catalog before the Glue script-object binding was documented."""
    return _verified_archived_current(
        GLUE_SCRIPT_690_PREVIOUS_MANIFEST_PATH, GLUE_SCRIPT_690_PREVIOUS_ARCHIVE,
        GLUE_SCRIPT_690_PREVIOUS_MANIFEST, GLUE_SCRIPT_690_PREVIOUS_ARCHIVE_SHA256,
        GLUE_SCRIPT_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_glue_690_previous():
    """Keep the exact catalog before the Glue endpoint route was narrowed."""
    return _verified_archived_current(
        GLUE_690_PREVIOUS_MANIFEST_PATH, GLUE_690_PREVIOUS_ARCHIVE,
        GLUE_690_PREVIOUS_MANIFEST, GLUE_690_PREVIOUS_ARCHIVE_SHA256,
        GLUE_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_devicefarm_690_previous():
    """Keep the exact catalog before the Device Farm route was narrowed."""
    return _verified_archived_current(
        DEVICEFARM_690_PREVIOUS_MANIFEST_PATH, DEVICEFARM_690_PREVIOUS_ARCHIVE,
        DEVICEFARM_690_PREVIOUS_MANIFEST, DEVICEFARM_690_PREVIOUS_ARCHIVE_SHA256,
        DEVICEFARM_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_gamelift_shell_689_previous():
    """Keep the exact 689-entry catalog before the controlled-build join."""
    return _verified_archived_current(
        GAMELIFT_SHELL_689_PREVIOUS_MANIFEST_PATH, GAMELIFT_SHELL_689_PREVIOUS_ARCHIVE,
        GAMELIFT_SHELL_689_PREVIOUS_MANIFEST, GAMELIFT_SHELL_689_PREVIOUS_ARCHIVE_SHA256,
        GAMELIFT_SHELL_689_PREVIOUS_TREE, 689, 3723)


@lru_cache(maxsize=1)
def _verified_iot_existing_689_previous():
    """Keep the exact 689-entry catalog before existing IoT alias repointing."""
    return _verified_archived_current(
        IOT_EXISTING_689_PREVIOUS_MANIFEST_PATH, IOT_EXISTING_689_PREVIOUS_ARCHIVE,
        IOT_EXISTING_689_PREVIOUS_MANIFEST, IOT_EXISTING_689_PREVIOUS_ARCHIVE_SHA256,
        IOT_EXISTING_689_PREVIOUS_TREE, 689, 3723)


@lru_cache(maxsize=1)
def _verified_scheduler_create_686_previous():
    """Keep the exact catalog before the existing-schedule update route."""
    return _verified_archived_current(
        SCHEDULER_CREATE_686_PREVIOUS_MANIFEST_PATH, SCHEDULER_CREATE_686_PREVIOUS_ARCHIVE,
        SCHEDULER_CREATE_686_PREVIOUS_MANIFEST, SCHEDULER_CREATE_686_PREVIOUS_ARCHIVE_SHA256,
        SCHEDULER_CREATE_686_PREVIOUS_TREE, 686, 3723)


@lru_cache(maxsize=1)
def _verified_deadline_dependencies_686_previous():
    """Keep the exact catalog before worker creation dependencies were documented."""
    return _verified_archived_current(
        DEADLINE_DEPENDENCIES_686_PREVIOUS_MANIFEST_PATH, DEADLINE_DEPENDENCIES_686_PREVIOUS_ARCHIVE,
        DEADLINE_DEPENDENCIES_686_PREVIOUS_MANIFEST, DEADLINE_DEPENDENCIES_686_PREVIOUS_ARCHIVE_SHA256,
        DEADLINE_DEPENDENCIES_686_PREVIOUS_TREE, 686, 3723)


@lru_cache(maxsize=1)
def _verified_deadline_new_worker_685_previous():
    """Keep the exact catalog before the new worker route on an existing fleet."""
    return _verified_archived_current(
        DEADLINE_NEW_WORKER_685_PREVIOUS_MANIFEST_PATH, DEADLINE_NEW_WORKER_685_PREVIOUS_ARCHIVE,
        DEADLINE_NEW_WORKER_685_PREVIOUS_MANIFEST, DEADLINE_NEW_WORKER_685_PREVIOUS_ARCHIVE_SHA256,
        DEADLINE_NEW_WORKER_685_PREVIOUS_TREE, 685, 3723)


@lru_cache(maxsize=1)
def _verified_deadline_worker_684_previous():
    """Keep the exact catalog before the existing Deadline worker role route."""
    return _verified_archived_current(
        DEADLINE_WORKER_684_PREVIOUS_MANIFEST_PATH, DEADLINE_WORKER_684_PREVIOUS_ARCHIVE,
        DEADLINE_WORKER_684_PREVIOUS_MANIFEST, DEADLINE_WORKER_684_PREVIOUS_ARCHIVE_SHA256,
        DEADLINE_WORKER_684_PREVIOUS_TREE, 684, 3723)


@lru_cache(maxsize=1)
def _verified_deadline_fleet_684_previous():
    """Keep the exact catalog before the Deadline fleet worker scope correction."""
    return _verified_archived_current(
        DEADLINE_FLEET_684_PREVIOUS_MANIFEST_PATH, DEADLINE_FLEET_684_PREVIOUS_ARCHIVE,
        DEADLINE_FLEET_684_PREVIOUS_MANIFEST, DEADLINE_FLEET_684_PREVIOUS_ARCHIVE_SHA256,
        DEADLINE_FLEET_684_PREVIOUS_TREE, 684, 3723)


@lru_cache(maxsize=1)
def _verified_deadline_queue_683_previous():
    """Keep the exact catalog before the existing Deadline queue role route."""
    return _verified_archived_current(
        DEADLINE_QUEUE_683_PREVIOUS_MANIFEST_PATH, DEADLINE_QUEUE_683_PREVIOUS_ARCHIVE,
        DEADLINE_QUEUE_683_PREVIOUS_MANIFEST, DEADLINE_QUEUE_683_PREVIOUS_ARCHIVE_SHA256,
        DEADLINE_QUEUE_683_PREVIOUS_TREE, 683, 3723)


@lru_cache(maxsize=1)
def _verified_cloudfront_create_683_previous():
    """Keep the exact catalog before the CloudFront creation path was added."""
    return _verified_archived_current(
        CLOUDFRONT_CREATE_683_PREVIOUS_MANIFEST_PATH, CLOUDFRONT_CREATE_683_PREVIOUS_ARCHIVE,
        CLOUDFRONT_CREATE_683_PREVIOUS_MANIFEST, CLOUDFRONT_CREATE_683_PREVIOUS_ARCHIVE_SHA256,
        CLOUDFRONT_CREATE_683_PREVIOUS_TREE, 683, 3723)


@lru_cache(maxsize=1)
def _verified_cognito_guest_existing_683_previous():
    """Keep the exact catalog before already-public pools were excluded."""
    return _verified_archived_current(
        COGNITO_GUEST_EXISTING_683_PREVIOUS_MANIFEST_PATH, COGNITO_GUEST_EXISTING_683_PREVIOUS_ARCHIVE,
        COGNITO_GUEST_EXISTING_683_PREVIOUS_MANIFEST, COGNITO_GUEST_EXISTING_683_PREVIOUS_ARCHIVE_SHA256,
        COGNITO_GUEST_EXISTING_683_PREVIOUS_TREE, 683, 3723)


@lru_cache(maxsize=1)
def _verified_sagemaker_attach_682_previous():
    """Keep the exact catalog before the notebook attachment condition."""
    return _verified_archived_current(
        SAGEMAKER_ATTACH_682_PREVIOUS_MANIFEST_PATH, SAGEMAKER_ATTACH_682_PREVIOUS_ARCHIVE,
        SAGEMAKER_ATTACH_682_PREVIOUS_MANIFEST, SAGEMAKER_ATTACH_682_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_ATTACH_682_PREVIOUS_TREE, 682, 3723)


@lru_cache(maxsize=1)
def _verified_sagemaker_lcc_677_previous():
    """Keep the exact 677-entry catalog used before the next audit batch."""
    return _verified_archived_current(
        SAGEMAKER_LCC_677_PREVIOUS_MANIFEST_PATH, SAGEMAKER_LCC_677_PREVIOUS_ARCHIVE,
        SAGEMAKER_LCC_677_PREVIOUS_MANIFEST, SAGEMAKER_LCC_677_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_LCC_677_PREVIOUS_TREE, 677, 3722)


@lru_cache(maxsize=1)
def _verified_sagemaker_lcc_previous():
    """Keep the exact catalog used before the attached notebook lifecycle route."""
    return _verified_archived_current(
        SAGEMAKER_LCC_PREVIOUS_MANIFEST_PATH, SAGEMAKER_LCC_PREVIOUS_ARCHIVE,
        SAGEMAKER_LCC_PREVIOUS_MANIFEST, SAGEMAKER_LCC_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_LCC_PREVIOUS_TREE, SAGEMAKER_LCC_PREVIOUS_ENTRY_COUNT,
        SAGEMAKER_LCC_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_mwaa_dag_previous():
    """Keep the exact catalog used before the MWAA DAG-object route."""
    return _verified_archived_current(
        MWAA_DAG_PREVIOUS_MANIFEST_PATH, MWAA_DAG_PREVIOUS_ARCHIVE,
        MWAA_DAG_PREVIOUS_MANIFEST, MWAA_DAG_PREVIOUS_ARCHIVE_SHA256,
        MWAA_DAG_PREVIOUS_TREE, MWAA_DAG_PREVIOUS_ENTRY_COUNT,
        MWAA_DAG_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_ssm_hybrid_previous():
    """Keep the exact catalog used before the hybrid-node shell routes."""
    return _verified_archived_current(
        SSM_HYBRID_PREVIOUS_MANIFEST_PATH, SSM_HYBRID_PREVIOUS_ARCHIVE,
        SSM_HYBRID_PREVIOUS_MANIFEST, SSM_HYBRID_PREVIOUS_ARCHIVE_SHA256,
        SSM_HYBRID_PREVIOUS_TREE, SSM_HYBRID_PREVIOUS_ENTRY_COUNT,
        SSM_HYBRID_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_cognito_previous():
    """Keep the exact 668-entry catalog used before the developer-token route."""
    return _verified_archived_current(
        COGNITO_PREVIOUS_MANIFEST_PATH, COGNITO_PREVIOUS_ARCHIVE,
        COGNITO_PREVIOUS_MANIFEST, COGNITO_PREVIOUS_ARCHIVE_SHA256,
        COGNITO_PREVIOUS_TREE, COGNITO_PREVIOUS_ENTRY_COUNT, COGNITO_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_classic_previous():
    """Keep the exact 669-entry catalog used before the Basic-flow route."""
    return _verified_archived_current(
        CLASSIC_PREVIOUS_MANIFEST_PATH, CLASSIC_PREVIOUS_ARCHIVE,
        CLASSIC_PREVIOUS_MANIFEST, CLASSIC_PREVIOUS_ARCHIVE_SHA256,
        CLASSIC_PREVIOUS_TREE, CLASSIC_PREVIOUS_ENTRY_COUNT, CLASSIC_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_setroles_previous():
    """Keep the exact 670-entry catalog used before the pool-role mutation route."""
    return _verified_archived_current(
        SETROLES_PREVIOUS_MANIFEST_PATH, SETROLES_PREVIOUS_ARCHIVE,
        SETROLES_PREVIOUS_MANIFEST, SETROLES_PREVIOUS_ARCHIVE_SHA256,
        SETROLES_PREVIOUS_TREE, SETROLES_PREVIOUS_ENTRY_COUNT, SETROLES_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_enable_classic_previous():
    """Keep the exact 671-entry catalog used before the flow-enablement route."""
    return _verified_archived_current(
        ENABLE_CLASSIC_PREVIOUS_MANIFEST_PATH, ENABLE_CLASSIC_PREVIOUS_ARCHIVE,
        ENABLE_CLASSIC_PREVIOUS_MANIFEST, ENABLE_CLASSIC_PREVIOUS_ARCHIVE_SHA256,
        ENABLE_CLASSIC_PREVIOUS_TREE, ENABLE_CLASSIC_PREVIOUS_ENTRY_COUNT, ENABLE_CLASSIC_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_ecscape_previous():
    """Keep the exact catalog used before ECScape execution roles were included."""
    return _verified_archived_current(
        ECSCAPE_PREVIOUS_MANIFEST_PATH, ECSCAPE_PREVIOUS_ARCHIVE,
        ECSCAPE_PREVIOUS_MANIFEST, ECSCAPE_PREVIOUS_ARCHIVE_SHA256,
        ECSCAPE_PREVIOUS_TREE, ECSCAPE_PREVIOUS_ENTRY_COUNT, ECSCAPE_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_glue_script_previous():
    """Keep the exact catalog used before the Glue script-object route was added."""
    return _verified_archived_current(
        GLUE_SCRIPT_PREVIOUS_MANIFEST_PATH, GLUE_SCRIPT_PREVIOUS_ARCHIVE,
        GLUE_SCRIPT_PREVIOUS_MANIFEST, GLUE_SCRIPT_PREVIOUS_ARCHIVE_SHA256,
        GLUE_SCRIPT_PREVIOUS_TREE, GLUE_SCRIPT_PREVIOUS_ENTRY_COUNT,
        GLUE_SCRIPT_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_imagebuilder_previous():
    """Keep the exact catalog used before the Image Builder pipeline binding repair."""
    return _verified_archived_current(
        IMAGEBUILDER_PREVIOUS_MANIFEST_PATH, IMAGEBUILDER_PREVIOUS_ARCHIVE,
        IMAGEBUILDER_PREVIOUS_MANIFEST, IMAGEBUILDER_PREVIOUS_ARCHIVE_SHA256,
        IMAGEBUILDER_PREVIOUS_TREE, IMAGEBUILDER_PREVIOUS_ENTRY_COUNT,
        IMAGEBUILDER_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_gamelift_current():
    """Keep the exact catalog used before the GameLift admin-shell route."""
    return _verified_archived_current(
        GAMELIFT_CURRENT_MANIFEST_PATH, GAMELIFT_CURRENT_ARCHIVE,
        GAMELIFT_CURRENT_MANIFEST, GAMELIFT_CURRENT_ARCHIVE_SHA256,
        GAMELIFT_CURRENT_TREE, GAMELIFT_CURRENT_ENTRY_COUNT, GAMELIFT_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_iot_current():
    """Keep the exact 667-entry catalog used before the IoT route correction."""
    return _verified_archived_current(
        IOT_CURRENT_MANIFEST_PATH, IOT_CURRENT_ARCHIVE,
        IOT_CURRENT_MANIFEST, IOT_CURRENT_ARCHIVE_SHA256,
        IOT_CURRENT_TREE, IOT_CURRENT_ENTRY_COUNT, IOT_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_iot_v1_current():
    """Keep the exact IoT catalog before the self-registered certificate variant."""
    return _verified_archived_current(
        IOT_V1_CURRENT_MANIFEST_PATH, IOT_V1_CURRENT_ARCHIVE,
        IOT_V1_CURRENT_MANIFEST, IOT_V1_CURRENT_ARCHIVE_SHA256,
        IOT_V1_CURRENT_TREE, IOT_V1_CURRENT_ENTRY_COUNT, IOT_V1_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_iot_v2_current():
    """Keep the exact IoT catalog before regional setup was joined."""
    return _verified_archived_current(
        IOT_V2_CURRENT_MANIFEST_PATH, IOT_V2_CURRENT_ARCHIVE,
        IOT_V2_CURRENT_MANIFEST, IOT_V2_CURRENT_ARCHIVE_SHA256,
        IOT_V2_CURRENT_TREE, IOT_V2_CURRENT_ENTRY_COUNT, IOT_V2_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_intermediate_current():
    """Keep the exact 660-entry catalog used before the next AWS recovery."""
    return _verified_archived_current(
        INTERMEDIATE_CURRENT_MANIFEST_PATH, INTERMEDIATE_CURRENT_ARCHIVE,
        INTERMEDIATE_CURRENT_MANIFEST, INTERMEDIATE_CURRENT_ARCHIVE_SHA256,
        INTERMEDIATE_CURRENT_TREE, INTERMEDIATE_CURRENT_ENTRY_COUNT, INTERMEDIATE_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_recent_current():
    """Keep the exact 661-entry catalog used before Athena sessions were restored."""
    return _verified_archived_current(
        RECENT_CURRENT_MANIFEST_PATH, RECENT_CURRENT_ARCHIVE,
        RECENT_CURRENT_MANIFEST, RECENT_CURRENT_ARCHIVE_SHA256,
        RECENT_CURRENT_TREE, RECENT_CURRENT_ENTRY_COUNT, RECENT_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_athena_current():
    """Keep the exact 664-entry catalog used before the Batch restoration."""
    return _verified_archived_current(
        ATHENA_CURRENT_MANIFEST_PATH, ATHENA_CURRENT_ARCHIVE,
        ATHENA_CURRENT_MANIFEST, ATHENA_CURRENT_ARCHIVE_SHA256,
        ATHENA_CURRENT_TREE, ATHENA_CURRENT_ENTRY_COUNT, ATHENA_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_batch_current():
    """Keep the exact 665-entry catalog used before App Runner restoration."""
    return _verified_archived_current(
        BATCH_CURRENT_MANIFEST_PATH, BATCH_CURRENT_ARCHIVE,
        BATCH_CURRENT_MANIFEST, BATCH_CURRENT_ARCHIVE_SHA256,
        BATCH_CURRENT_TREE, BATCH_CURRENT_ENTRY_COUNT, BATCH_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_apprunner_current():
    """Keep the exact 666-entry catalog used before the AppSync addition."""
    return _verified_archived_current(
        APPRUNNER_CURRENT_MANIFEST_PATH, APPRUNNER_CURRENT_ARCHIVE,
        APPRUNNER_CURRENT_MANIFEST, APPRUNNER_CURRENT_ARCHIVE_SHA256,
        APPRUNNER_CURRENT_TREE, APPRUNNER_CURRENT_ENTRY_COUNT, APPRUNNER_CURRENT_EXCLUDED_COUNT)


def _history_json_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("archived_history_duplicate_index_key")
        result[key] = value
    return result


def _history_original_pair(manifest_path, archive_path, manifest_digest, archive_digest):
    """Prefer exact originals; recover either missing file from the pinned pack."""
    if manifest_path.exists() and archive_path.exists():
        manifest = manifest_path.read_bytes()
        archived = archive_path.read_bytes()
    else:
        if (manifest_path.parent.resolve() != RUNTIME_HISTORY_PACK.parent.resolve()
                or archive_path.parent.resolve() != RUNTIME_HISTORY_PACK.parent.resolve()
                or manifest_path.name != manifest_path.as_posix().rsplit('/', 1)[-1]
                or archive_path.name != archive_path.as_posix().rsplit('/', 1)[-1]):
            raise ValueError("archived_history_location_mismatch")
        packed = RUNTIME_HISTORY_PACK.read_bytes()
        if hashlib.sha256(packed).hexdigest() != RUNTIME_HISTORY_SHA256:
            raise ValueError("archived_history_pack_changed")
        with zipfile.ZipFile(io.BytesIO(packed)) as container:
            names = container.namelist()
            if len(names) != len(set(names)) or set(names) != {
                    'index.json', 'blocks.bin', 'references.bin', 'manifests.bin'}:
                raise ValueError("archived_history_pack_members_mismatch")
            index = json.loads(container.read('index.json'), object_pairs_hook=_history_json_unique)
            if (type(index) is not dict or set(index) != {'schema', 'block_sha256', 'versions'}
                    or index['schema'] != 'privesc-exact-history-v1'
                    or type(index['block_sha256']) is not list
                    or type(index['versions']) is not dict or len(index['versions']) != 137):
                raise ValueError("archived_history_pack_index_mismatch")
            for archive_name, version in index['versions'].items():
                if (type(archive_name) is not str or '/' in archive_name or '\\' in archive_name
                        or not archive_name.endswith('.tar.gz') or type(version) is not dict
                        or type(version.get('manifest_name')) is not str
                        or '/' in version['manifest_name'] or '\\' in version['manifest_name']
                        or not version['manifest_name'].endswith('.json')):
                    raise ValueError("archived_history_pack_index_mismatch")
            blocks = container.read('blocks.bin')
            refs = container.read('references.bin')
            manifests = container.read('manifests.bin')
        hashes = index['block_sha256']
        if (len(blocks) != 512 * len(hashes) or len(hashes) > 65536
                or any(type(digest) is not str or len(digest) != 64
                       or hashlib.sha256(blocks[i*512:(i+1)*512]).hexdigest() != digest
                       for i, digest in enumerate(hashes))):
            raise ValueError("archived_history_block_mismatch")
        row = index['versions'].get(archive_path.name)
        if (type(row) is not dict or set(row) != {'archive_sha256', 'manifest_name',
                'manifest_sha256', 'header', 'trailer', 'tar_size', 'reference_offset',
                'reference_count', 'manifest_offset', 'manifest_size'}
                or row['archive_sha256'] != archive_digest
                or row['manifest_name'] != manifest_path.name
                or row['manifest_sha256'] != manifest_digest):
            raise ValueError("archived_history_identity_mismatch")
        offset, count = row['reference_offset'], row['reference_count']
        moffset, msize = row['manifest_offset'], row['manifest_size']
        if (type(offset) is not int or type(count) is not int or count < 1
                or offset < 0 or offset + count * 2 > len(refs)
                or type(moffset) is not int or type(msize) is not int
                or moffset < 0 or msize < 1 or moffset + msize > len(manifests)
                or row['tar_size'] != count * 512):
            raise ValueError("archived_history_offset_mismatch")
        recovered_manifest = manifests[moffset:moffset+msize]
        ids = struct.unpack_from('<' + 'H' * count, refs, offset)
        if any(i >= len(hashes) for i in ids):
            raise ValueError("archived_history_reference_mismatch")
        raw_tar = b''.join(blocks[i*512:(i+1)*512] for i in ids)
        header = base64.b64decode(row['header'], validate=True)
        trailer = base64.b64decode(row['trailer'], validate=True)
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        recovered_archive = header + compressor.compress(raw_tar) + compressor.flush() + trailer
        manifest = manifest_path.read_bytes() if manifest_path.exists() else recovered_manifest
        archived = archive_path.read_bytes() if archive_path.exists() else recovered_archive
    if (hashlib.sha256(manifest).hexdigest() != manifest_digest
            or hashlib.sha256(archived).hexdigest() != archive_digest):
        raise ValueError("archived_current_changed")
    return manifest, archived


def _verified_archived_current(manifest_path, archive_path, manifest_digest, archive_digest,
                               tree_digest, entry_count, excluded_count):
    from .schema import SAFE_YAML_LOADER
    manifest, archived = _history_original_pair(
        manifest_path, archive_path, manifest_digest, archive_digest)
    wanted = json.loads(manifest)["sha256"]
    actual, entries, excluded = {}, {}, 0
    with tarfile.open(fileobj=io.BytesIO(archived), mode="r:gz") as archive:
        for member in archive:
            if not member.isfile() or not member.name.startswith("catalog/"):
                raise ValueError("archived_current_path_mismatch")
            name = member.name.removeprefix("catalog/")
            if name not in wanted or name in actual:
                raise ValueError("archived_current_path_mismatch")
            payload = archive.extractfile(member).read()
            actual[name] = hashlib.sha256(payload).hexdigest()
            rows = yaml.load(payload, Loader=SAFE_YAML_LOADER) or []
            if name.rsplit("/", 1)[-1].startswith("_excluded"):
                excluded += len(rows)
            else:
                for row in rows:
                    item = dict(row, _file=name)
                    if item["id"] in entries:
                        raise ValueError("archived_current_duplicate_id")
                    entries[item["id"]] = item
    tree = ''.join(f'{name} {actual[name]}\n' for name in sorted(actual))
    if (actual != wanted or hashlib.sha256(tree.encode()).hexdigest() != tree_digest or
            len(entries) != entry_count or excluded != excluded_count):
        raise ValueError("archived_current_mismatch")
    return entries


@lru_cache(maxsize=1)
def _verified_prior():
    """Read the exact previous catalog so old report bindings keep their meanings."""
    from .schema import SAFE_YAML_LOADER
    manifest, archived = _history_original_pair(PRIOR_SOURCE_MANIFEST, PRIOR_CATALOG_ARCHIVE,
                                                PRIOR_CURRENT_MANIFEST, PRIOR_CATALOG_ARCHIVE_SHA256)
    wanted = json.loads(manifest)["sha256"]
    actual, entries, excluded = {}, {}, 0
    with tarfile.open(fileobj=io.BytesIO(archived), mode="r:gz") as archive:
        for member in archive:
            if not member.isfile():
                continue
            name = member.name.removeprefix("catalog/")
            if name == member.name or name not in wanted:
                raise ValueError("prior_catalog_archive_path_mismatch")
            payload = archive.extractfile(member).read()
            actual[name] = hashlib.sha256(payload).hexdigest()
            rows = yaml.load(payload, Loader=SAFE_YAML_LOADER) or []
            if name.rsplit("/", 1)[-1].startswith("_excluded"):
                excluded += len(rows)
            else:
                for row in rows:
                    item = dict(row, _file=name)
                    if item["id"] in entries:
                        raise ValueError("prior_catalog_duplicate_id")
                    entries[item["id"]] = item
    if actual != wanted or len(entries) != 1234 or excluded != 2847:
        raise ValueError("prior_catalog_archive_mismatch")
    return entries, actual


def _principal_v4(entries, catalog_hashes):
    """Old cards retain their exact 244-file catalog and original 1,052 meanings."""
    if _sha(V4_HISTORY) != V4_MANIFEST:
        raise ValueError("principal_v4_history_mismatch")
    pins = json.loads(V4_HISTORY.read_text())["sha256"]
    if len(pins) != 244 or any(catalog_hashes.get(name) != digest for name, digest in pins.items()):
        raise ValueError("principal_v4_history_files_mismatch")
    retained = {ident: entry for ident, entry in entries.items()
                if str(entry.get("_file", "")) in pins}
    if len(retained) != 1052:
        raise ValueError("principal_v4_history_count_mismatch")
    return retained


@lru_cache(maxsize=4)
def _verified_history(history_path):
    if _sha(Path(history_path)) != LEGACY_DELTA_SHA256:
        raise ValueError("legacy_delta_sha_mismatch")
    history = json.loads(Path(history_path).read_text())
    if (history.get("schema") != "legacy-source0b-catalog-delta-v1" or
            history.get("baseline_manifest_sha256") != LEGACY_MANIFEST or
            history.get("baseline_revision") != LEGACY_REVISION or
            len(history.get("legacy_ids", [])) != 1004 or
            len(history.get("changed_shared_ids", [])) != 75 or
            len(history.get("retired_ids", [])) != 28 or
            len(history.get("old_entries", {})) != 103 or history.get("retired_aliases") != {}):
        raise ValueError("legacy_delta_mismatch")
    return history


@lru_cache(maxsize=1)
def _verified_apim_anchor_685_previous():
    """Keep the exact catalog before the APIM SSO source anchor correction."""
    return _verified_archived_current(
        APIM_ANCHOR_685_PREVIOUS_MANIFEST_PATH, APIM_ANCHOR_685_PREVIOUS_ARCHIVE,
        APIM_ANCHOR_685_PREVIOUS_MANIFEST, APIM_ANCHOR_685_PREVIOUS_ARCHIVE_SHA256,
        APIM_ANCHOR_685_PREVIOUS_TREE, 685, 3777)


def current_binding(*, catalog_dir=None, manifest_path=None):
    catalog_dir, manifest_path, _ = _paths(catalog_dir, manifest_path)
    _current_entries(str(catalog_dir))
    return _binding_for(catalog_dir, manifest_path)


def _matches_current(binding, catalog_dir, manifest_path):
    try:
        current = _binding_for(catalog_dir, manifest_path)
    except OSError:
        return False
    return all(binding.get(key) == current[key]
               for key in ("manifest_sha256", "effective_tree_sha256", "source_revision"))


def lookup_entries(technique_ids, binding=None, *, tenant_id=None, catalog_dir=None,
                   manifest_path=None, history_path=None):
    """Return original entries plus lookup state; never reinterpret graph edges.

    Missing bindings use source0b labels as an explicitly uncertain legacy
    fallback. Unknown or contradictory bindings return no descriptions.
    """
    catalog_dir, manifest_path, history_path = _paths(catalog_dir, manifest_path, history_path)
    ids = tuple(dict.fromkeys(technique_ids))
    if binding is None:
        version, status = "legacy", "legacy_unversioned_fallback"
    elif not isinstance(binding, dict) or binding.get("schema") != BINDING_SCHEMA:
        return {}, "invalid_catalog_binding"
    elif tenant_id is not None and binding.get("tenant_id") != tenant_id:
        return {}, "tenant_binding_mismatch"
    elif _matches_current(binding, catalog_dir, manifest_path):
        version, status = "current", "exact_strict_privesc"
    elif (binding.get("manifest_sha256") == APIM_ANCHOR_685_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == APIM_ANCHOR_685_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "apim_anchor_685_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == LINEAGE_685_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == LINEAGE_685_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "lineage_685_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == MWAA_TOKEN_REASON_685_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == MWAA_TOKEN_REASON_685_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "mwaa_token_reason_685_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == BEANSTALK_685_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == BEANSTALK_685_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "beanstalk_685_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == CLOUD_SOURCE_685_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == CLOUD_SOURCE_685_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cloud_source_685_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ECS_REGISTER_685_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ECS_REGISTER_685_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "ecs_register_685_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == REVIEWED_685_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == REVIEWED_685_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "reviewed_685_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == REVIEWED_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == REVIEWED_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "reviewed_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == APPSTREAM_RESOURCE_700_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == APPSTREAM_RESOURCE_700_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "appstream_resource_700_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SOURCE_REPIN_700_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SOURCE_REPIN_700_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "source_repin_700_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == FINAL_TWO_ROLE_EFFECTS_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == FINAL_TWO_ROLE_EFFECTS_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "final_two_role_effects_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == JIT_WORKSPACES_ROLE_EFFECTS_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == JIT_WORKSPACES_ROLE_EFFECTS_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "jit_workspaces_role_effects_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SERVICECATALOG_ROLE_EFFECTS_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SERVICECATALOG_ROLE_EFFECTS_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "servicecatalog_role_effects_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == MWAA_ROLE_EFFECTS_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == MWAA_ROLE_EFFECTS_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "mwaa_role_effects_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == MIGRATIONHUB_ROLE_EFFECTS_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == MIGRATIONHUB_ROLE_EFFECTS_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "migrationhub_role_effects_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == M2_ROLE_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == M2_ROLE_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "m2_role_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == LAMBDA_WRAPPER_ROLE_SWAP_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == LAMBDA_WRAPPER_ROLE_SWAP_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "lambda_wrapper_role_swap_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == LAMBDA_EXISTING_SQS_MAPPING_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == LAMBDA_EXISTING_SQS_MAPPING_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "lambda_existing_sqs_mapping_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == LAMBDA_DYNAMODB_STREAM_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == LAMBDA_DYNAMODB_STREAM_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "lambda_dynamodb_stream_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == LAMBDA_EVENTBRIDGE_SCHEDULE_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == LAMBDA_EVENTBRIDGE_SCHEDULE_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "lambda_eventbridge_schedule_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == LAMBDA_MICROVM_CONNECTOR_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == LAMBDA_MICROVM_CONNECTOR_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "lambda_microvm_connector_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == KAFKACONNECT_PLUGIN_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == KAFKACONNECT_PLUGIN_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "kafkaconnect_plugin_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == IOT_EXISTING_ALIAS_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == IOT_EXISTING_ALIAS_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "iot_existing_alias_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == GLUE_EXTERNAL_SCRIPT_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == GLUE_EXTERNAL_SCRIPT_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "glue_external_script_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == GAMELIFTSTREAMS_SESSION_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == GAMELIFTSTREAMS_SESSION_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "gameliftstreams_session_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == EVENTS_SUBSCRIBER_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == EVENTS_SUBSCRIBER_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "events_subscriber_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == EMR_RUNJOBFLOW_ROLE_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == EMR_RUNJOBFLOW_ROLE_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "emr_runjobflow_role_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == EMR_CLUSTER_ENDPOINT_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == EMR_CLUSTER_ENDPOINT_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "emr_cluster_endpoint_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == EMR_SERVERLESS_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == EMR_SERVERLESS_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "emr_serverless_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == EMR_CONTAINERS_EFFECTS_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == EMR_CONTAINERS_EFFECTS_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "emr_containers_effects_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == BEANSTALK_ROLE_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == BEANSTALK_ROLE_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "beanstalk_role_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SPOT_REQUEST_ROLE_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SPOT_REQUEST_ROLE_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "spot_request_role_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == RUNINSTANCES_ROLE_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == RUNINSTANCES_ROLE_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "runinstances_role_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SPOT_FLEET_ROLE_EXECUTION_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SPOT_FLEET_ROLE_EXECUTION_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "spot_fleet_role_execution_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ASG_ROLE_EXECUTION_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ASG_ROLE_EXECUTION_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "asg_role_execution_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == DEVICEFARM_EXISTING_SPEC_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == DEVICEFARM_EXISTING_SPEC_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "devicefarm_existing_spec_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == DEADLINE_FLEET_WORKER_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == DEADLINE_FLEET_WORKER_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "deadline_fleet_worker_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == DEADLINE_QUEUE_ROLE_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == DEADLINE_QUEUE_ROLE_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "deadline_queue_role_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == DATAPIPELINE_EC2_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == DATAPIPELINE_EC2_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "datapipeline_ec2_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == CONFIG_REMEDIATION_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == CONFIG_REMEDIATION_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "config_remediation_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == CODEPIPELINE_EXISTING_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == CODEPIPELINE_EXISTING_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "codepipeline_existing_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == CODEBUILD_DEBUG_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == CODEBUILD_DEBUG_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "codebuild_debug_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SSM_EXISTING_AUTOMATION_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SSM_EXISTING_AUTOMATION_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "ssm_existing_automation_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "bedrock_actiongroup_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "agentcore_harness_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "agentcore_runtime_effects_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "amplify_role_effects_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == CFN_STACKSET_EFFECTS_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == CFN_STACKSET_EFFECTS_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cfn_stackset_effects_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == CFN_EXTENSION_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == CFN_EXTENSION_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cfn_extension_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == CFN_TEMPLATE_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == CFN_TEMPLATE_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cfn_template_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == TESTSTATE_ROLE_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == TESTSTATE_ROLE_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "teststate_role_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SFN_ROLE_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SFN_ROLE_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sfn_role_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == INSTANCE_CONNECT_WITNESS_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == INSTANCE_CONNECT_WITNESS_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "instance_connect_witness_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ECS_TASKSET_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ECS_TASKSET_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "ecs_taskset_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ECS_NODE_ESCAPE_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ECS_NODE_ESCAPE_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "ecs_node_escape_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ECS_SERVICE_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ECS_SERVICE_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "ecs_service_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ECS_START_TASK_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ECS_START_TASK_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "ecs_start_task_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ECS_NEW_TASK_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ECS_NEW_TASK_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "ecs_new_task_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ORGANIZATIONS_RCP_691_REVISIONLESS_MANIFEST and
          binding.get("effective_tree_sha256") == ORGANIZATIONS_RCP_691_REVISIONLESS_TREE and
          binding.get("source_revision") == V4_REVISION):
        # The source commit became known after the YAML was committed; this
        # binding keeps that original tree after the current catalog advances.
        version, status = "appstream_resource_700_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ORGANIZATIONS_RCP_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ORGANIZATIONS_RCP_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "organizations_rcp_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == LAMBDA_SIGNER_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == LAMBDA_SIGNER_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "lambda_signer_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == BEDROCK_ACTIONGROUP_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == BEDROCK_ACTIONGROUP_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "bedrock_actiongroup_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == QUICKSIGHT_IAM_USER_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == QUICKSIGHT_IAM_USER_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "quicksight_iam_user_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == KAFKACONNECT_GUARD_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == KAFKACONNECT_GUARD_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "kafkaconnect_guard_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == BRAKET_SCRIPT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == BRAKET_SCRIPT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "braket_script_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_domain_default_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_ROLE_SWAP_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_ROLE_SWAP_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_role_swap_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_NEW_PROFILE_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_NEW_PROFILE_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_new_profile_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_studio_profile_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_HPO_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_HPO_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_hpo_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_TRAINING_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_TRAINING_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_training_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_PROCESSING_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_PROCESSING_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_processing_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_JOBS_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_JOBS_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_jobs_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == AGENTCORE_HARNESS_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == AGENTCORE_HARNESS_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "agentcore_harness_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == AGENTCORE_CREATE_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == AGENTCORE_CREATE_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "agentcore_create_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == AGENTCORE_RUNTIME_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == AGENTCORE_RUNTIME_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "agentcore_runtime_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == AGENTCORE_EXISTING_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == AGENTCORE_EXISTING_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "agentcore_existing_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == AGENTCORE_BOUNDS_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == AGENTCORE_BOUNDS_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "agentcore_bounds_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == STS_FEDERATION_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == STS_FEDERATION_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sts_federation_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == AMPLIFY_ROLE_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == AMPLIFY_ROLE_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "amplify_role_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == EMR_RUNTIME_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == EMR_RUNTIME_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "emr_runtime_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ELASTICBEANSTALK_EFFECT_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ELASTICBEANSTALK_EFFECT_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "elasticbeanstalk_effect_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == CONFIG_REMEDIATION_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == CONFIG_REMEDIATION_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "config_remediation_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SERVICECATALOG_EFFECT_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SERVICECATALOG_EFFECT_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "servicecatalog_effect_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ORG_ACCESS_ROLE_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ORG_ACCESS_ROLE_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "org_access_role_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == STEPFUNCTIONS_PASSROLE_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == STEPFUNCTIONS_PASSROLE_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "stepfunctions_passrole_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == GAMELIFT_COVERAGE_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == GAMELIFT_COVERAGE_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "gamelift_coverage_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == COGNITO_IDP_SECRET_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == COGNITO_IDP_SECRET_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cognito_idp_secret_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == EC2_RUNINSTANCES_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == EC2_RUNINSTANCES_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "ec2_runinstances_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == STALE_COVERAGE_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == STALE_COVERAGE_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "stale_coverage_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == FINSPACE_SUNSET_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == FINSPACE_SUNSET_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "finspace_sunset_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SPOT_REQUEST_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SPOT_REQUEST_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "spot_request_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == TESTSTATE_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == TESTSTATE_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "teststate_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == INSTANCE_CONNECT_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == INSTANCE_CONNECT_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "instance_connect_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == BRAKET_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == BRAKET_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "braket_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == CLOUDCONTROL_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == CLOUDCONTROL_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cloudcontrol_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == MWAA_SLR_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == MWAA_SLR_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "mwaa_slr_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == GLUE_SCRIPT_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == GLUE_SCRIPT_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "glue_script_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == GLUE_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == GLUE_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "glue_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == DEVICEFARM_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == DEVICEFARM_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "devicefarm_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == IOT_EXISTING_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == IOT_EXISTING_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "iot_existing_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == GAMELIFT_SHELL_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == GAMELIFT_SHELL_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "gamelift_shell_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == GAMELIFT_SHARED_688_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == GAMELIFT_SHARED_688_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "gamelift_shared_688_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SCHEDULER_UPDATE_687_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SCHEDULER_UPDATE_687_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "scheduler_update_687_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SCHEDULER_CREATE_686_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SCHEDULER_CREATE_686_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "scheduler_create_686_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == DEADLINE_DEPENDENCIES_686_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == DEADLINE_DEPENDENCIES_686_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "deadline_dependencies_686_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == DEADLINE_NEW_WORKER_685_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == DEADLINE_NEW_WORKER_685_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "deadline_new_worker_685_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == DEADLINE_WORKER_684_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == DEADLINE_WORKER_684_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "deadline_worker_684_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == DEADLINE_FLEET_684_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == DEADLINE_FLEET_684_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "deadline_fleet_684_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == DEADLINE_QUEUE_683_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == DEADLINE_QUEUE_683_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "deadline_queue_683_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == CLOUDFRONT_CREATE_683_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == CLOUDFRONT_CREATE_683_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cloudfront_create_683_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_ATTACH_682_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_ATTACH_682_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_attach_682_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == COGNITO_GUEST_682_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == COGNITO_GUEST_682_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cognito_guest_682_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == COGNITO_GUEST_EXISTING_683_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == COGNITO_GUEST_EXISTING_683_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cognito_guest_existing_683_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == GAMELIFT_GROUP_682_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == GAMELIFT_GROUP_682_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "gamelift_group_682_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_LCC_677_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_LCC_677_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_lcc_677_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_LCC_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_LCC_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_lcc_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SSM_HYBRID_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SSM_HYBRID_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "ssm_hybrid_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == MWAA_DAG_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == MWAA_DAG_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "mwaa_dag_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == IMAGEBUILDER_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == IMAGEBUILDER_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "imagebuilder_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == GLUE_SCRIPT_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == GLUE_SCRIPT_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "glue_script_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ECSCAPE_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ECSCAPE_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "ecscape_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ENABLE_CLASSIC_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ENABLE_CLASSIC_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "enable_classic_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SETROLES_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SETROLES_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "setroles_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == CLASSIC_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == CLASSIC_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "classic_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == COGNITO_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == COGNITO_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cognito_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == PREVIOUS_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == PREVIOUS_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "previous_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == GAMELIFT_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == GAMELIFT_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "gamelift_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == IOT_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == IOT_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "iot_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == IOT_V1_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == IOT_V1_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "iot_v1_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == IOT_V2_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == IOT_V2_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "iot_v2_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == BATCH_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == BATCH_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "batch_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == APPRUNNER_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == APPRUNNER_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "apprunner_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == INTERMEDIATE_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == INTERMEDIATE_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "intermediate_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == RECENT_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == RECENT_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "recent_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ATHENA_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == ATHENA_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "athena_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == PRIOR_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == PRIOR_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "prior_current", "exact_bounded_v5"
    elif (binding.get("manifest_sha256") == PRIOR_DISCLOSURE_MANIFEST and
          binding.get("effective_tree_sha256") == PRIOR_DISCLOSURE_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "prior_disclosure", "exact_bounded_v5"
    elif (binding.get("manifest_sha256") == BOUNDED_MANIFEST and
          binding.get("effective_tree_sha256") == BOUNDED_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "bounded", "exact_bounded_v5"
    elif (binding.get("manifest_sha256") == PRIOR_BOUNDED_MANIFEST and
          binding.get("effective_tree_sha256") == PRIOR_BOUNDED_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "prior_bounded", "exact_bounded_v5"
    elif (binding.get("manifest_sha256") == V4_MANIFEST and
          binding.get("effective_tree_sha256") == V4_EFFECTIVE_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "v4", "exact_additive_v4"
    elif (binding.get("manifest_sha256") == LEGACY_MANIFEST and
          binding.get("source_revision") == LEGACY_REVISION):
        version, status = "legacy", "exact_legacy"
    else:
        return {}, "unknown_catalog_manifest"
    try:
        if version == "current":
            current = _current_entries(str(catalog_dir))
            return {ident: current[ident] for ident in ids if ident in current}, status
        if version == "apim_anchor_685_previous":
            previous = _verified_apim_anchor_685_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "lineage_685_previous":
            previous = _verified_lineage_685_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "mwaa_token_reason_685_previous":
            previous = _verified_mwaa_token_reason_685_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "beanstalk_685_previous":
            previous = _verified_beanstalk_685_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cloud_source_685_previous":
            previous = _verified_cloud_source_685_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "ecs_register_685_previous":
            previous = _verified_ecs_register_685_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "reviewed_685_previous":
            previous = _verified_reviewed_685_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "reviewed_691_previous":
            previous = _verified_reviewed_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "appstream_resource_700_previous":
            previous = _verified_appstream_resource_700_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "source_repin_700_previous":
            previous = _verified_source_repin_700_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "final_two_role_effects_691_previous":
            previous = _verified_final_two_role_effects_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "jit_workspaces_role_effects_691_previous":
            previous = _verified_jit_workspaces_role_effects_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "servicecatalog_role_effects_691_previous":
            previous = _verified_servicecatalog_role_effects_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "mwaa_role_effects_691_previous":
            previous = _verified_mwaa_role_effects_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "migrationhub_role_effects_691_previous":
            previous = _verified_migrationhub_role_effects_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "m2_role_effect_691_previous":
            previous = _verified_m2_role_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "lambda_wrapper_role_swap_691_previous":
            previous = _verified_lambda_wrapper_role_swap_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "lambda_existing_sqs_mapping_691_previous":
            previous = _verified_lambda_existing_sqs_mapping_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "lambda_dynamodb_stream_691_previous":
            previous = _verified_lambda_dynamodb_stream_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "lambda_eventbridge_schedule_691_previous":
            previous = _verified_lambda_eventbridge_schedule_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "lambda_microvm_connector_691_previous":
            previous = _verified_lambda_microvm_connector_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "kafkaconnect_plugin_effect_691_previous":
            previous = _verified_kafkaconnect_plugin_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "iot_existing_alias_effect_691_previous":
            previous = _verified_iot_existing_alias_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "glue_external_script_effect_691_previous":
            previous = _verified_glue_external_script_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "gameliftstreams_session_effect_691_previous":
            previous = _verified_gameliftstreams_session_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "events_subscriber_effect_691_previous":
            previous = _verified_events_subscriber_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "emr_runjobflow_role_691_previous":
            previous = _verified_emr_runjobflow_role_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "emr_cluster_endpoint_effect_691_previous":
            previous = _verified_emr_cluster_endpoint_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "emr_serverless_effect_691_previous":
            previous = _verified_emr_serverless_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "emr_containers_effects_691_previous":
            previous = _verified_emr_containers_effects_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "beanstalk_role_691_previous":
            previous = _verified_beanstalk_role_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "spot_request_role_691_previous":
            previous = _verified_spot_request_role_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "runinstances_role_691_previous":
            previous = _verified_runinstances_role_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "spot_fleet_role_execution_691_previous":
            previous = _verified_spot_fleet_role_execution_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "asg_role_execution_691_previous":
            previous = _verified_asg_role_execution_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "devicefarm_existing_spec_691_previous":
            previous = _verified_devicefarm_existing_spec_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "deadline_fleet_worker_691_previous":
            previous = _verified_deadline_fleet_worker_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "deadline_queue_role_691_previous":
            previous = _verified_deadline_queue_role_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "datapipeline_ec2_effect_691_previous":
            previous = _verified_datapipeline_ec2_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        elif version == "config_remediation_effect_691_previous":
            previous = _verified_config_remediation_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        elif version == "codepipeline_existing_effect_691_previous":
            previous = _verified_codepipeline_existing_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        elif version == "codebuild_debug_effect_691_previous":
            previous = _verified_codebuild_debug_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        elif version == "ssm_existing_automation_effect_691_previous":
            previous = _verified_ssm_existing_automation_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        elif version == "bedrock_actiongroup_effect_691_previous":
            previous = _verified_bedrock_actiongroup_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        elif version == "agentcore_harness_effect_691_previous":
            previous = _verified_agentcore_harness_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "agentcore_runtime_effects_691_previous":
            previous = _verified_agentcore_runtime_effects_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "amplify_role_effects_691_previous":
            previous = _verified_amplify_role_effects_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cfn_stackset_effects_691_previous":
            previous = _verified_cfn_stackset_effects_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cfn_extension_effect_691_previous":
            previous = _verified_cfn_extension_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cfn_template_effect_691_previous":
            previous = _verified_cfn_template_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "teststate_role_effect_691_previous":
            previous = _verified_teststate_role_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sfn_role_effect_691_previous":
            previous = _verified_sfn_role_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "instance_connect_witness_691_previous":
            previous = _verified_instance_connect_witness_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "ecs_taskset_691_previous":
            previous = _verified_ecs_taskset_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "ecs_node_escape_691_previous":
            previous = _verified_ecs_node_escape_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "ecs_service_691_previous":
            previous = _verified_ecs_service_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "ecs_start_task_691_previous":
            previous = _verified_ecs_start_task_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "ecs_new_task_691_previous":
            previous = _verified_ecs_new_task_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "organizations_rcp_691_previous":
            previous = _verified_organizations_rcp_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "lambda_signer_691_previous":
            previous = _verified_lambda_signer_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "bedrock_actiongroup_691_previous":
            previous = _verified_bedrock_actiongroup_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "quicksight_iam_user_691_previous":
            previous = _verified_quicksight_iam_user_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "kafkaconnect_guard_691_previous":
            previous = _verified_kafkaconnect_guard_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "braket_script_691_previous":
            previous = _verified_braket_script_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_domain_default_691_previous":
            previous = _verified_sagemaker_domain_default_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_role_swap_691_previous":
            previous = _verified_sagemaker_role_swap_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_new_profile_691_previous":
            previous = _verified_sagemaker_new_profile_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_studio_profile_691_previous":
            previous = _verified_sagemaker_studio_profile_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_hpo_691_previous":
            previous = _verified_sagemaker_hpo_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_training_691_previous":
            previous = _verified_sagemaker_training_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_processing_691_previous":
            previous = _verified_sagemaker_processing_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_jobs_691_previous":
            previous = _verified_sagemaker_jobs_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "agentcore_harness_691_previous":
            previous = _verified_agentcore_harness_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "agentcore_create_691_previous":
            previous = _verified_agentcore_create_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "agentcore_runtime_691_previous":
            previous = _verified_agentcore_runtime_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "agentcore_existing_690_previous":
            previous = _verified_agentcore_existing_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "agentcore_bounds_690_previous":
            previous = _verified_agentcore_bounds_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sts_federation_690_previous":
            previous = _verified_sts_federation_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "amplify_role_690_previous":
            previous = _verified_amplify_role_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "emr_runtime_689_previous":
            previous = _verified_emr_runtime_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "elasticbeanstalk_effect_689_previous":
            previous = _verified_elasticbeanstalk_effect_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "config_remediation_689_previous":
            previous = _verified_config_remediation_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "servicecatalog_effect_689_previous":
            previous = _verified_servicecatalog_effect_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "org_access_role_689_previous":
            previous = _verified_org_access_role_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "stepfunctions_passrole_689_previous":
            previous = _verified_stepfunctions_passrole_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "gamelift_coverage_689_previous":
            previous = _verified_gamelift_coverage_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cognito_idp_secret_689_previous":
            previous = _verified_cognito_idp_secret_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "ec2_runinstances_689_previous":
            previous = _verified_ec2_runinstances_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "stale_coverage_689_previous":
            previous = _verified_stale_coverage_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "finspace_sunset_690_previous":
            previous = _verified_finspace_sunset_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "spot_request_690_previous":
            previous = _verified_spot_request_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "teststate_690_previous":
            previous = _verified_teststate_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "instance_connect_690_previous":
            previous = _verified_instance_connect_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "braket_690_previous":
            previous = _verified_braket_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cloudcontrol_690_previous":
            previous = _verified_cloudcontrol_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "mwaa_slr_690_previous":
            previous = _verified_mwaa_slr_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "glue_script_690_previous":
            previous = _verified_glue_script_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "glue_690_previous":
            previous = _verified_glue_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "devicefarm_690_previous":
            previous = _verified_devicefarm_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "iot_existing_689_previous":
            previous = _verified_iot_existing_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "gamelift_shell_689_previous":
            previous = _verified_gamelift_shell_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "gamelift_shared_688_previous":
            previous = _verified_gamelift_shared_688_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "scheduler_update_687_previous":
            previous = _verified_scheduler_update_687_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "scheduler_create_686_previous":
            previous = _verified_scheduler_create_686_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "deadline_dependencies_686_previous":
            previous = _verified_deadline_dependencies_686_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "deadline_new_worker_685_previous":
            previous = _verified_deadline_new_worker_685_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "deadline_worker_684_previous":
            previous = _verified_deadline_worker_684_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "deadline_fleet_684_previous":
            previous = _verified_deadline_fleet_684_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "deadline_queue_683_previous":
            previous = _verified_deadline_queue_683_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cloudfront_create_683_previous":
            previous = _verified_cloudfront_create_683_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_attach_682_previous":
            previous = _verified_sagemaker_attach_682_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cognito_guest_682_previous":
            previous = _verified_cognito_guest_682_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cognito_guest_existing_683_previous":
            previous = _verified_cognito_guest_existing_683_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "gamelift_group_682_previous":
            previous = _verified_gamelift_group_682_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_lcc_677_previous":
            previous = _verified_sagemaker_lcc_677_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_lcc_previous":
            previous = _verified_sagemaker_lcc_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "ssm_hybrid_previous":
            previous = _verified_ssm_hybrid_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "mwaa_dag_previous":
            previous = _verified_mwaa_dag_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "imagebuilder_previous":
            previous = _verified_imagebuilder_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "glue_script_previous":
            previous = _verified_glue_script_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "ecscape_previous":
            previous = _verified_ecscape_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "enable_classic_previous":
            previous = _verified_enable_classic_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "setroles_previous":
            previous = _verified_setroles_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "classic_previous":
            previous = _verified_classic_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cognito_previous":
            previous = _verified_cognito_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "previous_current":
            previous = _verified_previous_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "gamelift_current":
            previous = _verified_gamelift_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "iot_current":
            previous = _verified_iot_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "iot_v1_current":
            previous = _verified_iot_v1_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "iot_v2_current":
            previous = _verified_iot_v2_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "batch_current":
            previous = _verified_batch_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "apprunner_current":
            previous = _verified_apprunner_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "intermediate_current":
            previous = _verified_intermediate_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "recent_current":
            previous = _verified_recent_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "athena_current":
            previous = _verified_athena_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        v4, prior_hashes = _verified_prior()
        if version == "prior_current":
            return {ident: v4[ident] for ident in ids if ident in v4}, status
        if version == "prior_disclosure":
            if _sha(PRIOR_DISCLOSURE_HISTORY) != PRIOR_DISCLOSURE_MANIFEST:
                raise ValueError("disclosure_history_changed")
            pins = json.loads(PRIOR_DISCLOSURE_HISTORY.read_text())["sha256"]
            if len(pins) != 253 or any(prior_hashes.get(name) != digest for name, digest in pins.items()):
                raise ValueError("disclosure_history_files_changed")
            retained = {key: value for key, value in v4.items() if str(value.get("_file", "")) in pins}
            if len(retained) != 1227:
                raise ValueError("disclosure_history_count_changed")
            return {key: retained[key] for key in ids if key in retained}, status
        if version == "bounded":
            if _sha(CURRENT_HISTORY) != BOUNDED_MANIFEST:
                raise ValueError("bulk_principal_history_changed")
            pins = json.loads(CURRENT_HISTORY.read_text())["sha256"]
            if len(pins) != 251 or any(prior_hashes.get(name) != digest for name, digest in pins.items()):
                raise ValueError("bulk_principal_history_files_changed")
            retained = {key: value for key, value in v4.items() if str(value.get("_file", "")) in pins}
            if len(retained) != 1224:
                raise ValueError("bulk_principal_history_count_changed")
            return {key: retained[key] for key in ids if key in retained}, status
        if version == "prior_bounded":
            if _sha(BOUNDED_HISTORY) != PRIOR_BOUNDED_MANIFEST: raise ValueError("bounded_history_changed")
            pins = json.loads(BOUNDED_HISTORY.read_text())["sha256"]
            if len(pins) != 249 or any(prior_hashes.get(name) != digest for name, digest in pins.items()): raise ValueError("bounded_history_files_changed")
            retained = {k:v for k,v in v4.items() if str(v.get("_file", "")) in pins}
            if len(retained) != 1126: raise ValueError("bounded_history_count_changed")
            return {k:retained[k] for k in ids if k in retained}, status
        if version == "v4":
            original = _principal_v4(v4, prior_hashes)
            return {ident: original[ident] for ident in ids if ident in original}, status
        history = _verified_history(str(history_path))
        allowed, old = set(history["legacy_ids"]), history["old_entries"]
        return {ident: old.get(ident, v4.get(ident)) for ident in ids if ident in allowed and
                (ident in old or ident in v4)}, status
    except (OSError, ValueError, KeyError, CatalogError):
        return {}, "catalog_unavailable"


def card_technique_ids(card, principal_id):
    """Select IDs only from edges bound to the requested card principal."""
    ids = set()
    aggregates = set(card.get("member_of_aggregates") or [])
    for edge in card.get("outgoing") or []:
        if edge.get("source") == principal_id:
            ids.update(edge.get("techniques") or [])
    for edge in card.get("incoming") or []:
        target = edge.get("target")
        if target == principal_id or (target in aggregates and edge.get("via_aggregate") == target):
            ids.update(edge.get("techniques") or [])
    return sorted(ident for ident in ids if isinstance(ident, str))
