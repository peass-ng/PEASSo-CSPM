"""Real combined imports and exact, atomic, isolated admission tamper checks.

No source reader is virtualized. Each mutation runs against real bytes in a
bounded hardlink clone; atomic replacement never writes through shared inodes.
"""
from contextlib import contextmanager
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
from tests.shared_admission_epoch_compatibility_20261020 import active_shared, _reverse
from tests.retained_upstream_manifest_20261020 import ORIGINAL as RETAINED_UPSTREAM_PATH, original_bytes as retained_upstream_bytes
from tests.retired_privesc_catalog_20261022 import ARCHIVE as RETIRED_CATALOG_ARCHIVE, REMOVED as RETIRED_CATALOG_PATH, original_bytes as retired_catalog_bytes
from tests.reviewed_current_successors_20261026 import extend as extend_reviewed_successors


ROOT = Path(__file__).resolve().parents[1]
BASE = "5c59608087204eff7216bb3798a4521d7f3442d5"
BASELINE = "tests/fixtures/provider_combined_bridge_baseline_20261020.json.gz"
BASELINE_SHA256 = "82799a2e0c366c80f3ec4d0626837fdf37ec0b38fc426d0ede565301df4c54a6"
GENERATED_CATALOGS = frozenset({
    "peaso/rulepacks/catalog_summary.json", "peaso/rulepacks/native_catalog.json",
})
# Release owner may pin the final reviewed network correction here. Retain its
# original baseline hash as before_sha256; after_sha256/after_size bind all new
# bytes. This explicit file allowlist cannot admit unrelated package changes.
REVIEWED_CURRENT_CHANGES = {'peaso/ai/access.py': {'after_sha256': 'ab7d0ff1b8997775e9fe2d5ec781ac1b8b69a591b29666c97c266bcfe38437e7',
                        'after_size': 9263,
                        'before_sha256': '19139ffeb3205e860c32dc393d95f7471f4dddf911d6fd0936ab05bb615a187e'},
 'peaso/ai/agents/priorities.yaml': {'after_sha256': '82e77a4090dec82b866eee6df225684f4c60ae22c6c829990bb915d8ca229dbc',
                                     'after_size': 10777,
                                     'before_sha256': '950de2a095ee25219fe6770fc8913bcf5f4f6f17320a68adad4722924605916a'},
 'peaso/ai/auth.py': {'after_sha256': '417d70fe80bf510b3482c679f9b547272be77379546b3183fe771fd42bc613cf',
                      'after_size': 18371,
                      'before_sha256': '4698a34f11d32f5d61dfa62ed2abd82dbf7f484d7c88af3903ea59a0038ee9d9'},
 'peaso/ai/codex_relay_cli.py': {'after_sha256': 'a1e8c519b624ab30d131f1a4a070deb2eea8e780584a41b405f6212592539fb9',
                                 'after_size': 1571,
                                 'before_sha256': 'eb21e350afa98e319676e12b5b60dbe9b9ef516fbc203970267798a66e5d6aee'},
 'peaso/ai/contracts.py': {'after_sha256': '59edf654ad40e0f7afa06514eefd4d3635840083bfc47d7b2b76ebe656dd9052',
                           'after_size': 8414,
                           'before_sha256': '34b025dcb642d07f1c7a586437cdda006d4a34cb75f6de219f6511610a685df2'},
 'peaso/ai/fargate.py': {'after_sha256': '9b39ddbb3844744c81fff421ed643c912ab61339071700c69e01af8ad7ccb176',
                         'after_size': 9071,
                         'before_sha256': 'f619a772d49642fb32453f6b9c18038e7573ba0370671f7e43581fe507cf76c5'},
 'peaso/ai/model_relay.py': {'after_sha256': '38b983c2a628e0b8d67aff0c58cdc3dabf5569262386c3124edfbd26b760cb6a',
                             'after_size': 12638,
                             'before_sha256': 'c8ffb7196454a6b1214fe9a47deb014b3d1679a59855494a0069125ab4bf9c4a'},
 'peaso/ai/network.py': {'after_sha256': 'f8da3a90c6fbc0e2c2bb8fa40f2007bf45abdfa149b37c92d8b7b693f5ebd6fd',
                         'after_size': 14438,
                         'before_sha256': 'c7e43d252261d26b2ee9d6fa2a3cee79a344dd052bee2f959a98b2a624d8d024'},
 'peaso/ai/pipeline.py': {'after_sha256': '82dfc50293019b8a49930b3be27039ee47fb8ee4151bbe13d5f2332a8f0f61e5',
                          'after_size': 29455,
                          'before_sha256': 'cff1e0a4e346c407ddef53a3e3b984b9eed0ff965acb9fb54329bcdb6751aa56'},
 'peaso/ai/recommendations.schema.json': {'after_sha256': '816d9c36f3671973b9e8ca13f790732b28c8ac296c107582e517d581f2d9026b',
                                          'after_size': 1734,
                                          'before_sha256': '0006dee24add1dc64094eec8d8f93e3fe597a58a63cedabed70f0f0f99cd1d70'},
 'peaso/ai/runner.py': {'after_sha256': '34283810a05c9f06cb4046a98fc8b2689c0e85c2beb019caa9e658132c4b0197',
                        'after_size': 6065,
                        'before_sha256': 'd789f8a65af278d089bd9eaf18dc88d2dfa348b67f4f2d486a6b51f0aae9b997'},
 'peaso/ai/task_runtime.py': {'after_sha256': '85d5cd47ca3a586fc623dbd008ac1279784ebcd43d57fe0e696f4748012cea91',
                              'after_size': 7439,
                              'before_sha256': '1a8fd2234bcd145f08683449c0748fdf2a7741fb01b1e412799f85991366c02f'},
 'peaso/analysis/__init__.py': {'after_sha256': '37c4ddb5026c4d3762378c1444fc3865f9d44b476b7c17ba9bf0bcd88b78af05',
                                'after_size': 16279,
                                'before_sha256': 'ddb92b18186d677c4297b40069b4b7e039d61e154aeb290b70b47e91922e2e73'},
 'peaso/analysis/common.py': {'after_sha256': '43f5f66f4ab5d99ea96fe122108ff04e2e8fe857c964bf755cdfe6d5772054d9',
                              'after_size': 13921,
                              'before_sha256': '3895ba27f4a153bfa6ed88dfef7d3628dfa1ec4786e4d319d29a0ca42981a656'},
 'peaso/analysis/iam.py': {'after_sha256': '851da1533afa9ec352964c65c26a08ae38d731bf9c4342e522564195fe350750',
                           'after_size': 39438,
                           'before_sha256': 'e78c5f41644b8ed2bd3adcc0cfb1346fa9a20f80c30fd63d067b94643745faa2'},
 'peaso/analysis/internet_exposure.py': {'after_sha256': '6a1f29125b24d13d70babf871261f2f024ebbd65ec093c6a6c453e83c48e76d9',
                                         'after_size': 101654,
                                         'before_sha256': 'cc1a94d3b134813fed743a7a8867c3f289c8a27e34b2bacce87a324918348d8a'},
 'peaso/attack_detection/aws_apigateway_controls_next.py': {'after_sha256': '7630d9b580fe82027f7ad6c18fbc56d00bc31431e8d02b03f09a7d8f782f11d1',
                                                            'after_size': 8082,
                                                            'before_sha256': '889f18f39ecb7d2420e73ed649766b6b116c7ec8de4cceb5938e90a2a101d095'},
 'peaso/attack_detection/aws_apigateway_rest_next.py': {'after_sha256': '5ee85a40ba8adf61767eda6d0a51fa17955659bc73906c2c9b13f6a2b7ae1fbf',
                                                        'after_size': 14584,
                                                        'before_sha256': '18ab31e8b5b5e1307edb587f7a053c07f1729988414a7eb75998381f2aa11892'},
 'peaso/attack_detection/aws_kinesis_video_controls_next.py': {'after_sha256': 'bd468a871700f24b6ef3dd967bfc64cb507e28b7da7649f9d2ac2ac4286ff549',
                                                               'after_size': 5861,
                                                               'before_sha256': '51cb1690457da6ec9cb370cf3c4c015504a382acaada0d15426e2ec127e5725b'},
 'peaso/attack_detection/github_source.py': {'after_sha256': '1b931cdbf42e01913d13e6104bb6895290a707076f7316d5348abd3bea687c2d',
                                             'after_size': 8693,
                                             'before_sha256': '2cb605b7076ad23a0429afb5a16287b60ea147a7ef256a32af62fa25b82f14fe'},
 'peaso/attack_detection/history_worker_s3.py': {'after_sha256': 'c1829aa087a0f16676463048dd317cad741bd409c4e68518440971f764935cf1',
                                                 'after_size': 7141,
                                                 'before_sha256': '1a030e1322364378f001e4187162824a8a833d1e516243c4b02f3ed42e96be96'},
 'peaso/attack_detection/rules.py': {'after_sha256': '8990b15a19913968b5cf14076a56ed14266a303316aa0f6993994efbbc095c7a',
                                     'after_size': 95186,
                                     'before_sha256': 'c65b53b8f01ecfca2e4dbfc15d31f72f5915002c7a4b137aefb6c6cdbccf00a9'},
 'peaso/check_services.json': {'after_sha256': '7a927e4511750cd215da9dd7474fde6e030f77b72589f1d81f8814f750f52831',
                               'after_size': 29085,
                               'before_sha256': '1a9c0705c8c95e5d100ef951d0f0689fa6685021a0f39a7159c6c38e95cd4458'},
 'peaso/check_services.py': {'after_sha256': '012ddc04cf1d43b1c7e8140a882a3d4c8747a972be0d1effa9327f9e038d6827',
                             'after_size': 7058,
                             'before_sha256': '1f051f70a4150f7e27e09d002c6154d7dab0b4fcbfce1a8e1e995bfaa4975222'},
 'peaso/checks/aws_a_cloudwatch.py': {'after_sha256': '7cae38304bca4ec34d34d7604f44af5f07c084a49987c204e63988276c5b67f9',
                                      'after_size': 6306,
                                      'before_sha256': '7a1676c0684b5a13873664dee3ede626c05dc890c0af23009e09365dc1fdd05e'},
 'peaso/checks/aws_a_s3.py': {'after_sha256': 'ff02961210c23380ae79b3ea983e7734f5205ef49acb0a3e00bbb5f7eea3916d',
                              'after_size': 2526,
                              'before_sha256': 'c52c29a395fa7a92d05679850b5ac69cdc44e84a59a70080f7d864cb4f4bba2c'},
 'peaso/checks/aws_b_redshift.py': {'after_sha256': '7c91cb15971019ca364f2e4f42e91f85ff7d6ec0563a08d2def2096a575313b1',
                                    'after_size': 3731,
                                    'before_sha256': 'a41b0e842a4b78831243bf3979ea0afdfd4c294eb37fcdc94f79b1e0ea792db4'},
 'peaso/checks/aws_bulk_clarity_reviewed.py': {'after_sha256': 'ef68d3aa110be7e5abd42f0f0bc9f2b859e332743c0048eb03035cdb7262fb55',
                                               'after_size': 204834,
                                               'before_sha256': 'af2d8d2bea36aec498658b5c559d489153f49a99fcd338ea44e961bd26ee8e18'},
 'peaso/checks/aws_compute_storage_clarity_reviewed.py': {'after_sha256': '6e960216a22a00ab7096c62a260c8d0cb64388ed2dc9b1753a986c55380f2c2b',
                                                          'after_size': 304457,
                                                          'before_sha256': '6cadd7cc05d873ed44e2c0a4848aea8c93adee16e12051274007785bca57807d'},
 'peaso/checks/aws_database_clarity_reviewed.py': {'after_sha256': '8863773e66615e1bfee1e3f63267726986abfcacdad0fe761c44d80f21177991',
                                                   'after_size': 122547,
                                                   'before_sha256': '51d749640427e40b41fbc91408e9a21b27dc581a013c77a32699eccbd2f6975c'},
 'peaso/checks/aws_evidence_explanations.py': {'after_sha256': '0ac49910f70e2b536b887f7212d128a66b0fc36d0e6fbc08c3e693acc02e197d',
                                               'after_size': 20495,
                                               'before_sha256': '553ab10e9d41bde6cfb4bbbdb6f096260369c48bc687dc5d5b67f8fc766daad6'},
 'peaso/checks/aws_final_clarity_reviewed.py': {'after_sha256': 'a5dabbd95b6f2c313aec83a5343d4724ed8c872fe3e4c1a567ab75b1bf03f12b',
                                                'after_size': 85560,
                                                'before_sha256': '1fac121f5b486fc4c063b94e9fa9f7850ac856ab42aff4b71573966d5336852e'},
 'peaso/checks/aws_finding_clarity_reviewed.py': {'after_sha256': '61c480f4d44dc4e1e79ae10ba234b31192e93ab606a9b94295d97739d0a65eae',
                                                  'after_size': 2150915,
                                                  'before_sha256': '6b20d911d7060a34d3e24dfb3716454a3a34b78bd4d36aa7a56b96351a9dc1a2'},
 'peaso/checks/aws_pass_observed_evidence.py': {'after_sha256': '29826790ff3e17a388f3a14245c203b6af69bef28e7482084eb8ea6ffa94fe88',
                                                'after_size': 131674,
                                                'before_sha256': 'daa9578a78e63c98ac2e81ebb6c32ec9b9cb6445344e296c1904226a6b44e1bb'},
 'peaso/checks/aws_remaining_clarity_reviewed.py': {'after_sha256': '3278304ee70acd4f9a05fb77cec3dacbc084b3c1c3772d646bd0a923219fb960',
                                                    'after_size': 377167,
                                                    'before_sha256': '795e494658b989eecbd141fdcad1ce99e97dc81d9a18f06424c3068600d69775'},
 'peaso/checks/aws_selected_configuration_secret_review_20261020.py': {'after_sha256': '633e8ef1e4f7d2fe1f49a07e57b3e37c62096e464cbd7f4dd7ebf113131c1ab3',
                                                                       'after_size': 8460,
                                                                       'before_sha256': '819cb82c47a3eefca9e4e7c6a3d14a6624f4e0e836e2b50638384533cb9d6b65'},
 'peaso/checks/azure_acr_image_secret_review_20261020.py': {'after_sha256': '35cedadfac4e25d2ae11c43ce9ec82647270bc5fd85ea9571ddad5d31626e1ac',
                                                            'after_size': 28509,
                                                            'before_sha256': '11821a6a2d2366602d993d79c58844d6f0c14b1a766ffd19c43894bef8f2dd39'},
 'peaso/checks/azure_databricks_notebook_secret_review_20261020.py': {'after_sha256': '0c33f325736990b88d2dd6c1a17d484f935186a6a82000cf54230f41d09c4e77',
                                                                      'after_size': 10023,
                                                                      'before_sha256': 'ffba8f894df00f9d6d014a19a2fc03158e84363610266abbf171d4c878e2f7ec'},
 'peaso/checks/azure_finding_clarity_reviewed.py': {'after_sha256': '7534a2168774d272d1108c6f87c691880af7586d66d0822e067d37423b717675',
                                                    'after_size': 2633484,
                                                    'before_sha256': '747074079138e16c5c795a779a85bb59d8263981f7a3c88547be6a8df95a070d'},
 'peaso/checks/azure_ml_selected_asset_secret_review_20261020.py': {'after_sha256': '35a8d3768fb07ceff272135df5476b51c34f93d519853e640a478e5c76a9d3d7',
                                                                    'after_size': 10234,
                                                                    'before_sha256': '4c66fc194c7c94537581f240ee6999ee87e6677c6deeb5e65b510c4eddf6f472'},
 'peaso/checks/azure_ml_selected_job_secret_review_20261020.py': {'after_sha256': 'beaa1363271f57d117031e7a7af2357be6b3abbb8ba3c4d305a94a8764b42a1d',
                                                                  'after_size': 8658,
                                                                  'before_sha256': '20536cbdc302fdbee0565304aca63314e9ada62c769e17e383b3c3dc00798bd1'},
 'peaso/checks/catalog.py': {'after_sha256': '963984d3bc5b4f3d3df16a4d601a7c2839f9da50c1b5067faca7001c3625e4d9',
                             'after_size': 36508,
                             'before_sha256': 'c24821bee09ad54f650825c43886bd69e9c7b3143b75f380fef370857fac4568'},
 'peaso/checks/claude2_aws_b_compute.py': {'after_sha256': '8b061001de6711d59ac584c15f09a703fa2f41b8455838bba714d862634db4ed',
                                           'after_size': 84453,
                                           'before_sha256': '4c4059e8eaec5777274a9affdd3d64608d9c78970b117d6b2fa8383b72e69a4e'},
 'peaso/checks/claude2_aws_b_data.py': {'after_sha256': 'cce4938d49ca2d51394fb19b380eb50e97d007938822ac3595dd359178d7e102',
                                        'after_size': 83060,
                                        'before_sha256': '5916d6a78cffd92a3aaacf9d1498df334170f43e760752ca28f470f5c19689b8'},
 'peaso/checks/claude_aws_a_common.py': {'after_sha256': '42218f329b77e55cd56c2f46de0a82ab260c849ca1ae1e89ac95a54e201a87d8',
                                         'after_size': 38141,
                                         'before_sha256': 'a6cfb97daa2a3a7f8d72c68e15039691ee28ea42fc01d12c770f9f9343a93696'},
 'peaso/checks/claude_aws_a_iam.py': {'after_sha256': '5a1f81ead33c02f957be1d1ee2461afaa7a07b2cb62ec8997dcbc377f3c5c687',
                                      'after_size': 72515,
                                      'before_sha256': '671b51dad0a630377080f1f74a41eb6b0afa481fae9bd29c4c7da5c6d9dc8eaf'},
 'peaso/checks/claude_aws_b_messaging.py': {'after_sha256': '3c01e5e55f6bb580757ad65dd8239f0edd21943b3539f1d2ae4d4c9168fb4084',
                                            'after_size': 42262,
                                            'before_sha256': '48c8fd57ba42ed480b33f9dc6b2dcefe2fdbf18d53aaad4f987fdc2807dd687c'},
 'peaso/checks/claude_azure_data.py': {'after_sha256': 'e8fd6583fe2d61fd07a2001a3d91c1a7983998e0e76b33add898f8a097af377b',
                                       'after_size': 76299,
                                       'before_sha256': 'd4013488f1536f9be4425a690d3cb87ef73ae35c08e02b356d1ff1324c00d472'},
 'peaso/checks/claude_azure_identity.py': {'after_sha256': '1888c282670451c0aebce38b9597019ffccac20bfbeaad181b3ffe33ac2c3ab8',
                                           'after_size': 89515,
                                           'before_sha256': '0279457a6e88216e84bc36188362def0480e86013cc790fdb8d143ca751d5acf'},
 'peaso/checks/claude_azure_network.py': {'after_sha256': 'e7a0cddf4c9adc96efe9ae665575c0f1187fb065bf9393ca4e5bff514faf760c',
                                          'after_size': 72202,
                                          'before_sha256': '5cafa8d926a058366a0a1e2119735a061d267ca284b2cf46906cce8d138e254b'},
 'peaso/checks/claude_gcp_k8s_compute.py': {'after_sha256': '071adbccfe52668da08440632d9f5d3ef4b74781a8ba8570442b02a7fdc69952',
                                            'after_size': 41579,
                                            'before_sha256': '0c6d1b300fa08f86a63146bea7d6424668b1b5e70a36e1fde8f3ba4ee4638c36'},
 'peaso/checks/claude_gcp_k8s_iam.py': {'after_sha256': 'e5080847e9facfe4c70b2cb38089dc6b830b1fb74d55700ff23d359225a78a2e',
                                        'after_size': 83259,
                                        'before_sha256': '528b295b1648d1587a5c9bb42bedf82e59185a6124b632ccc9cc5c0dc2470d1a'},
 'peaso/checks/compliance_new_k8s.py': {'after_sha256': '57a80c6ba1df451ee3775530e714ded65a4abd755f6130fdad3ce86c3f83be18',
                                        'after_size': 22704,
                                        'before_sha256': '35fd7fabf444064d68efff6b70ed773e6b30ae1c8c9776bcab5affc1f8468c8b'},
 'peaso/checks/exposure_endpoints.py': {'after_sha256': 'b6339bd946d38e1fe2058a966cef24a270e579fcf04e38f0d640e082785c3d44',
                                        'after_size': 6577,
                                        'before_sha256': 'fcb83aabf932385e03b9ae39279b986d5956bb07d42c074ceeb9a8de9128cb10'},
 'peaso/checks/finding_types.json': {'after_sha256': '533306fc7e6c2eb6db6cbadf33857e1d3d04bcdaf4270cb09ee142772ea3fe4a',
                                     'after_size': 289232,
                                     'before_sha256': 'cfd4550d48fea23c8b0a8ee91efb51de7d0db3dea516475eccc32bb10a9dd2a0'},
 'peaso/checks/gcp_artifact_file_secret_review_20261019.py': {'after_sha256': '83b18b9e43d88c7fa4271defd6cb9d1111e320814e7e4d8f191f010fba7ba0b2',
                                                              'after_size': 7137,
                                                              'before_sha256': '0fe7d4fcbcd953d913e2ffa1df5b08573f01c8527ff333d351ddd3e037b36e54'},
 'peaso/checks/gcp_cloudbuild_log_secret_review_20261019.py': {'after_sha256': 'ea79ddaf6041bee7fbfc75504af71d6def2698d23b82c2b7d77dba4b48eec792',
                                                               'after_size': 19150,
                                                               'before_sha256': 'd1f3618df951b59b8ebc73424acb7b1fed9795121f21054571061a4173c01967'},
 'peaso/checks/gcp_composer_source_secret_review_20261019.py': {'after_sha256': '4d792063c7dfde93400aa5ca89c5637f978fbca645aae51aaba7e06ae7aa12b7',
                                                                'after_size': 10867,
                                                                'before_sha256': 'd176034b246ff2f901e767f52d3c02832ec192766f361e552852d579dd567027'},
 'peaso/checks/gcp_dataproc_referenced_source_descriptions_20261020.json': {'after_sha256': '401356d5dd33b4509f662cca19d9d2cb64b45567c68c65d4a7c304ba3d669e03',
                                                                            'after_size': 2526,
                                                                            'before_sha256': '46409c8fab9f8b24bddf5eda9f4418031b79482a9da4f9b7ea878951b72442c3'},
 'peaso/checks/gcp_dataproc_referenced_source_secret_review_20261020.py': {'after_sha256': 'b0896e0082f39de705a4a8648d9cb8236c8b4f34e3c59c3c852f485e714d138c',
                                                                           'after_size': 8619,
                                                                           'before_sha256': '49ca4dda3b2abc80d8e59c75eecb3b432ea930ffa396494082ea9cfd7382423d'},
 'peaso/checks/gcp_image_secret_review_20261019.py': {'after_sha256': '0c0e9e68f1a7a39457822e3f7a20195f21c1f61948efa5c4e6b3fa926872263b',
                                                      'after_size': 11222,
                                                      'before_sha256': '83fe957437bdb4a8142361bc4329af903dede65cb2e0242d2c35cda5211c79fd'},
 'peaso/checks/gcp_remaining_clarity_reviewed.py': {'after_sha256': '75bbf4b4656f9c1ab2f7788f19caf6d96035e3114a57d8a1ed1e4e8db1c6f454',
                                                    'after_size': 761146,
                                                    'before_sha256': '12a3e9449ce2495485533f19b512dc2454605a1abd2eaaa0fbe6b0f788fa8820'},
 'peaso/checks/gcp_scalar_clarity_reviewed.py': {'after_sha256': '9c329178ade3a675237bd1d362267ce95e41fc9de32f5deef97bbba7b4ad8246',
                                                 'after_size': 22139,
                                                 'before_sha256': '7286bbb8882867de213b1fee23d9834a0e85c67324bc033787d12642ae510b42'},
 'peaso/checks/gcp_selected_archive_secret_review_20261019.py': {'after_sha256': 'cde1fe3ec267ef201f7b9fbe432dd2266b36164b3ee6e20fa55d589f77388cfb',
                                                                 'after_size': 7805,
                                                                 'before_sha256': 'd7636cee350ce0aa0c9fc32f3a71ef141f960050abb0757af082772a4f315a6a'},
 'peaso/checks/gcp_sourcerepo_secret_review_20261019.py': {'after_sha256': '1edae1338a7f2a7f8b13e5939b4e33ad01c79c7fe3d80f634c69f5243d2664ac',
                                                           'after_size': 12892,
                                                           'before_sha256': 'f397ee93b511f396bb49fb467e05a88e23a741e492a22dcb93d9f8d99aded5d0'},
 'peaso/checks/gcp_task_routine_secret_review_20261020.py': {'after_sha256': '7deb55ddf182adade8f6f0e2beb52a019ed30e62908698de5758fef7b99fa63b',
                                                             'after_size': 10779,
                                                             'before_sha256': '18a4701d7e40fb18bc75291f80383a376713aa4a3fc3c4703b7c7f5c275aeeb1'},
 'peaso/checks/hacktricks_scope.json': {'after_sha256': '6f72dba0f23c0c93d8e5ea9227714705f8b22fb83ba3e30c0622cc03b90f915c',
                                        'after_size': 542379,
                                        'before_sha256': 'd5badbc9699697ebb59fec66f9f320560182d8265105b7135c42e755ab497292'},
 'peaso/checks/hacktricks_scope.py': {'after_sha256': 'b0bf0b60e2b246de12b5ab646e6ac889eb82e007e05e7caa4b5fd3206ec6fcf2',
                                      'after_size': 1589,
                                      'before_sha256': '8c208ef4d137cc7a6409b2c4cdabcdb6d1818ec88b4f09d5e75e89e7aa1bb95f'},
 'peaso/checks/k8s_literal_current_metadata_20261020.py': {'after_sha256': 'bd0a73d17b87d869cb8905e0a72c0a6eb37f34bdd3e8872c9ce19275ac06203c',
                                                           'after_size': 4684,
                                                           'before_sha256': 'b57a0c7e050d31f00f3225bcdc5597212751698ac6b37058c640adebbea04983'},
 'peaso/checks/k8s_literal_secret_review_20261020.py': {'after_sha256': '1454c3c67f49e8b3094ec3274cb058e29d3f7797b89a11be7974a9d06d2a25c1',
                                                        'after_size': 8172,
                                                        'before_sha256': 'dd05e8f47d961d9a1a0a71d2289f302adb8497ce9599a2194df8c3eda49eab88'},
 'peaso/checks/k8s_ports_components.py': {'after_sha256': '0b717883a125ed880899da71f58053d6b59756c8f18f0b5ea5b9f4d44fd5538e',
                                          'after_size': 23504,
                                          'before_sha256': '460178158b6797d2683b840b57c3d69e2a64ad6288118a6c6cad3d6c36786aeb'},
 'peaso/checks/k8s_ports_workloads.py': {'after_sha256': '0a0ab554c6f00eaf2967fb860bd644c96e8ac4730002a1a937175b7b5dca2ad5',
                                         'after_size': 18905,
                                         'before_sha256': 'd7690b5488231e5e56570cc3a203774facdf3123511a34822b911f3e7551d951'},
 'peaso/checks/k8s_selected_metadata_secret_admission_20261020.py': {'after_sha256': 'cd56b5746144b5d1a67ea380ca0871ea871a159003a3b4fdcc7af456851250f9',
                                                                     'after_size': 10633,
                                                                     'before_sha256': '93d277e39340ba828501021fa9311500411998bbb840fb85d5f147f871100540'},
 'peaso/checks/k8s_selected_metadata_secret_review_20261020.py': {'after_sha256': 'b42079e18301c9087fc18533cc81414134e1215677dd47c915e3d721820a15f8',
                                                                  'after_size': 3603,
                                                                  'before_sha256': '5ace4ac736493509b0bc1d573f61ac30dbdb9d22fc1a6e98ecad524ac57c030f'},
 'peaso/checks/k8s_workload_clarity_reviewed.py': {'after_sha256': '4faad1de0c73c2fd38f87f0f384a111047373281aba51182e3c298e585c03fb5',
                                                   'after_size': 1546661,
                                                   'before_sha256': '03cb86e0f0b2aff3919c7acd99f96fdf0605405201fdd7952e0009df3d74e344'},
 'peaso/checks/reviewed_release_priorities_20261020.json': {'after_sha256': 'c07d3e87a06bf4f1772c9b9933c708697aed94e35a7f23179ac40c0dd215bc42',
                                                            'after_size': 87235,
                                                            'before_sha256': 'e032c43d73c74976398d8279d9122c6a49bd39ff948d742564f1d312e6c5a71c'},
 'peaso/checks/selected_configuration_content_observed_20261020.py': {'after_sha256': '557b419a76bd8e3b77618e1a0dbe94c396549c67b6480b3578a8e0b82b01ae5c',
                                                                      'after_size': 8914,
                                                                      'before_sha256': '4f9d5a582c2b574e33e5cd99da3a026b768d36b2cd05f25b656f9e7323ab0e0b'},
 'peaso/cli.py': {'after_sha256': '63ed1756d72cffb2f4c37a67cca334690dd0a0c8f9402fff47152c30804e724b',
                  'after_size': 13646,
                  'before_sha256': '64abe6b8c5128ffb41e92811766d8e6b263e683172ce754875958745cbe6a312'},
 'peaso/collectors/aws.py': {'after_sha256': '09b7a016fce9b9dc7c1cdd2a847309d86b512c61bbcc99df404f61faee361814',
                             'after_size': 207522,
                             'before_sha256': '6895fefeb9374e42df4f39234de826615f4660ed7d830027b6b91621dedd3255'},
 'peaso/collectors/aws_access_analyzer_lifecycle.py': {'after_sha256': '05ef0cc1157de1cd226da2e48d71dd63be1e6bea2cb759b7bc9c273acdf8e427',
                                                       'after_size': 9357,
                                                       'before_sha256': '23788052bbe56fc609e1a61f567995f237884520a15daf1cb50879a26a218a5e'},
 'peaso/collectors/aws_additional_secret_indicators.py': {'after_sha256': '505ebd8f6d11b43979110094840701fe75170e368a7387d08e35dec022785035',
                                                          'after_size': 17383,
                                                          'before_sha256': 'e2cfc9bcd839b1a7a803580b549b3d02d8a67757274551a0afc4130e5d184787'},
 'peaso/collectors/aws_b_services.py': {'after_sha256': '59c138a826795d03a12d427e84307db040a514326079300cd3cede104dd1896e',
                                        'after_size': 29951,
                                        'before_sha256': '8d78a921cd7af6c50ceb198f608c7135a50e23bce290975f38bd0681fd98c1ba'},
 'peaso/collectors/aws_code_log_content_indicators.py': {'after_sha256': '9a93faa6ea79503a43d80da060b9623b27b05ee22b7a5cda5b2037b63d02f8f4',
                                                         'after_size': 21182,
                                                         'before_sha256': '06fd10cdc45542e15e31d4e735256fa62b3733c805dc5eb1865b7e3923013355'},
 'peaso/collectors/aws_codebuild_buildspec_runtime_20261020.py': {'after_sha256': '70e9d13e572bc77bae366e7bbcadee51c5a2e32dcba9c87043385c7013a9081d',
                                                                  'after_size': 11526,
                                                                  'before_sha256': '50be001febf5a568b2b2ffbe7c295edafeb3f34a5e395a4bf29a6bc94f58b01f'},
 'peaso/collectors/aws_codebuild_buildspec_source_20261020.py': {'after_sha256': '13cec858770033e4383f91180c4b20246c8c0f82bdbf1ffaf7c9eee0eb7ab042',
                                                                 'after_size': 14859,
                                                                 'before_sha256': '4890d8a97cd86cdcee0df334956531432ae26ec2f6a1758f1ecb858e7f778bce'},
 'peaso/collectors/aws_codebuild_redaction.py': {'after_sha256': 'c3a87db6c298863ece41dd5c18403d520773e3b1c4454c0b0274574fba194441',
                                                 'after_size': 11158,
                                                 'before_sha256': '0e4f5bbfb0f974c4044af89d44f719b3d558b9aa7406d302032e6f757e54a4b7'},
 'peaso/collectors/aws_configuration_payload_secret_indicators.py': {'after_sha256': '242735153eecd312bfdc4d71fb48f94384942f4a95d42b2a918310367b925518',
                                                                     'after_size': 17836,
                                                                     'before_sha256': 'eef6d7241cc5f09f9560c427fa9f336a636d1996130f0eb5b05d17377883fdc9'},
 'peaso/collectors/aws_configuration_secret_indicators.py': {'after_sha256': '5970679996f93e13ad9d277fcc63556bcbe55d52371c617bb6844200057dbd05',
                                                             'after_size': 9109,
                                                             'before_sha256': 'cbeb631ac665dea0c221a3ad370d21000b8c458a33072b4f0d5c855bedbc147c'},
 'peaso/collectors/aws_ecr_artifacts_native.py': {'after_sha256': '55864daaa50a9dd87e319483a3d2239c242e6b0f156ca2b5c2f86977be3a38d3',
                                                  'after_size': 16549,
                                                  'before_sha256': '3beaa9b23013e715902d29d76064c0bcf205c569b02b38f74d2c7ba0cd66e99c'},
 'peaso/collectors/aws_facts_cb_ca.py': {'after_sha256': '5a8e27d97a617d7ca0755555d68e5e086da401dfc442ae2ef15c856990def78f',
                                         'after_size': 86932,
                                         'before_sha256': '16d584b51f90483a303edeee7a8e17729f2ce62a6aa0a5d7a15099667fd98e6a'},
 'peaso/collectors/aws_facts_compute_edge.py': {'after_sha256': '33132a9fd900a55e6e7a259abcbb9af7b9a978a3ceb1cc589d78c4e754de2671',
                                                'after_size': 39113,
                                                'before_sha256': 'e90c50cd3b1f4f1b5f21c41b684b4677e4167e02a16741a4c07d1f634a1f466a'},
 'peaso/collectors/aws_facts_data_identity.py': {'after_sha256': '76f2a8304c841ce5392ba7422dc82c7d66bbe9db15de3b28224f6238409ff0d4',
                                                 'after_size': 50700,
                                                 'before_sha256': 'c572ad513010d71a283dbd5f73c64787a46619960b191f5abac5c7ae89318cd0'},
 'peaso/collectors/aws_facts_ext.py': {'after_sha256': 'd6cf438da42ea1eb43628d2e31856691fda8dba1c6052b9e2cd36649fe49cb0f',
                                       'after_size': 48391,
                                       'before_sha256': '3e04007b730f56be31c7ab217b1713d05f6fbab0a7ecf512b09b107ad040f8db'},
 'peaso/collectors/aws_facts_v4_holds.py': {'after_sha256': 'f798458bf33646afc06863b6c545ebd3c55310cbf8dbae01dbaa3a3a1993b522',
                                            'after_size': 15958,
                                            'before_sha256': '1e2cec696c00e1b002111fa1c4e3d17f41585c115db0808e11162705e1cd9356'},
 'peaso/collectors/aws_lambda_environment_secret_indicators.py': {'after_sha256': '52fbb1b2ba632e43fc40ff00ebc159271febfb2ec3a6d7785a8f9b354e54bd08',
                                                                  'after_size': 12667,
                                                                  'before_sha256': '2fce27977e83ba4f9abc6baa6ac78d4ff5e0e4a2b8b27d52d333a0458e67f289'},
 'peaso/collectors/aws_network_catalog.py': {'after_sha256': 'd1650f4b35a1eae64fe5d0105163934e4a5f3403d6cbbb433c7c2a01f0ad15b7',
                                             'after_size': 24007,
                                             'before_sha256': '50d1b6a8e9157e5ad4423081b8e8a16921105577da7ed68ec6f7f758d1a71ac1'},
 'peaso/collectors/aws_network_inventory.py': {'after_sha256': '148fd46c7fa885e648ba787d9adb3745d36663074aa8ba80a1db229f7922c6c9',
                                               'after_size': 17701,
                                               'before_sha256': 'bcdee5a0fc9c9c6b2a107cab6ff5251d2f77ebb4d9f3d88145d0b5c4c4e54b1f'},
 'peaso/collectors/aws_package_content_indicators.py': {'after_sha256': '03a62985743638498b5c7c4b8ecdb2e3622ad1209c254b474e1e435b1b4c9dd3',
                                                        'after_size': 45951,
                                                        'before_sha256': 'ce459d4b5ed0ae991591f09f61b462f7841f0977d5935579e561409c0117e7e6'},
 'peaso/collectors/aws_s3_selected_source_secret_indicators.py': {'after_sha256': '9afd1a1f64ebba13a1e2477a50071e999f6633fffe58870b13f157e22ad8ca8b',
                                                                  'after_size': 33151,
                                                                  'before_sha256': 'b040a3b23746561fe913b1bd985669a0820fdde72b12fd864c5f6b5b894e3053'},
 'peaso/collectors/aws_selected_configuration_secret_indicators.py': {'after_sha256': '8d258c01c306b2e4cc78d58e4e5fd4e7b15a40abc7e2fdf32837e79625377ba6',
                                                                      'after_size': 47342,
                                                                      'before_sha256': 'c7a87afb1fc02740979a34efa2a03141d4e0daddbfdda1e45c604507c31c450f'},
 'peaso/collectors/aws_user_data_secret_indicators.py': {'after_sha256': '28eeada41f9d1b10d31ccd469e1eec85d38c53def87fd520b2556bd598ee5161',
                                                         'after_size': 2201,
                                                         'before_sha256': '077b5d258d6728c0b712935d34899c0feb27e3d11f758a81e793a6a240016205'},
 'peaso/collectors/aws_workload_command_runtime_20261020.py': {'after_sha256': 'de543276807257ff814980b78e523be21de02cecab7f9b31b2cb7dfb0940b09d',
                                                               'after_size': 6824,
                                                               'before_sha256': '9dc132a81388ee3b228b8b1de0820aefe9bfb741be37ea4c082920254e5c96b5'},
 'peaso/collectors/aws_workload_command_source_20261020.py': {'after_sha256': 'a5aa7cba18e0acc377a505abed400d82d835eb9bf7650460d0623fea0b1d6778',
                                                              'after_size': 22948,
                                                              'before_sha256': 'c5c5c24b7fbd4b696903d38b6e84a02ad3ebfa35616e6378a67afb97b8ae757e'},
 'peaso/collectors/azure.py': {'after_sha256': '3b43aa8afe041fffc1c465a4fe3c1e58f39e73dfb23497d335083b53afb8c473',
                               'after_size': 246867,
                               'before_sha256': '22aa297159aeec7ab4a0645877bf69de4c8c8c645098ffe1d0dd05a56f0f8aac'},
 'peaso/collectors/azure_acr_image_secret_indicators.py': {'after_sha256': '528640e64c665a79e9b045ecc028e5eccfae9ddd1f28e237ff73ae390ab54c9a',
                                                           'after_size': 20407,
                                                           'before_sha256': '8e9c55f0fcee045b9c283554e7e5908f8ef1aff5225bfd3eb6a4e037b1a0995d'},
 'peaso/collectors/azure_apim_operation_window_20261020.py': {'after_sha256': '2a0e52c4b2d9a42fc88e71309077272ad6dd0aee6534ed0ec37398a058f1d5b4',
                                                              'after_size': 15182,
                                                              'before_sha256': '91bec2bbb602d4b21875d30cb4fe350ab11a809010eab93570ecd053657fab85'},
 'peaso/collectors/azure_app_settings_secret_indicators.py': {'after_sha256': '9e5b349da018641ddf6f7835560eea29ab35f13b28e1b5884d00a9e65d576ada',
                                                              'after_size': 13959,
                                                              'before_sha256': 'f7fed346ff359f463e72cff63f4de9e1971e2aeef2223ed8b338c91c7520248b'},
 'peaso/collectors/azure_databricks_notebook_secret_indicators.py': {'after_sha256': '2c341ba97b78cb309fb5612b0c01ac6c45b2b8039d948268f919e43376e8510a',
                                                                     'after_size': 27273,
                                                                     'before_sha256': '6eed83bf1d6b6e8055dabb1c0cee052f1b7c636121c742e74b8727bc23b4b222'},
 'peaso/collectors/azure_devops_git_native.py': {'after_sha256': 'aa627a331825c3466c692ab79d46944d8f57c182ac4f7e5bc610ef5388157d9a',
                                                 'after_size': 10671,
                                                 'before_sha256': '7b01f9f26acae14414d33b42095caad14adaf4644b3706fde2120e170b4c2c63'},
 'peaso/collectors/azure_devops_selected_content_secret_indicators.py': {'after_sha256': '03035c9d97862a0788c2b9fd3fb23236e099ebe8f2d178ae67bb010fa7717039',
                                                                         'after_size': 19250,
                                                                         'before_sha256': '3def2355bfad985b1543022cc14443677dd6ed37928a4d1109eeffb741fb5434'},
 'peaso/collectors/azure_function_package_integration_20261020.py': {'after_sha256': '9eb8c15ad1052795777ae95960f7c65a8062d5555e2456a9c34a9f2aa6d1e58c',
                                                                     'after_size': 12770,
                                                                     'before_sha256': '678fc74f19156541992b9ce3536cf642253842b34583e6408005a4e38858c0e0'},
 'peaso/collectors/azure_function_package_source_20261020.py': {'after_sha256': '6761247a25ad29e8b2fa102ac7475d095ebde70398dfbe89c6db0b56cdd2395c',
                                                                'after_size': 19622,
                                                                'before_sha256': 'f8dca90c993a417d5717c80ac6fdee069d66d5839039e0269e831ddfd2663303'},
 'peaso/collectors/azure_function_settings_declarations_20261020.py': {'after_sha256': 'b237e407b2a286d16507e442ab763d9c97376036f51a8b842e19fb762a3e1a77',
                                                                       'after_size': 20385,
                                                                       'before_sha256': 'fba106883b1fce7b517dfea87f60f6e84509da0378caddd126ef625b01c46863'},
 'peaso/collectors/azure_ml_selected_asset_secret_indicators.py': {'after_sha256': 'f98e15e23276ceb840159cc98b314f27bdeebe737c15a8d3ede74f685eee6ef1',
                                                                   'after_size': 21608,
                                                                   'before_sha256': 'e5d98f9692035b60342526497ca70076a06cdafd3dbf8bfc0aa706ea70f2486f'},
 'peaso/collectors/azure_ml_selected_job_secret_indicators.py': {'after_sha256': '25c0c9fcea3ee28a25b55a7d22588fbdbca009324c90f65c26945c57eacf7ba4',
                                                                 'after_size': 11971,
                                                                 'before_sha256': 'a0644628612d680fea88a9dcedca7541f1560278fc5d4ea116710739035143c3'},
 'peaso/collectors/azure_selected_configuration_secret_indicators.py': {'after_sha256': 'd118e7faa46d63114f369f13fdf26f2bc0e5c2a5d8d13e504fd19ea8c181645b',
                                                                        'after_size': 22090,
                                                                        'before_sha256': '570bf399805ef12cd647007d43ea450f1138244d58c4326972842c42281d7604'},
 'peaso/collectors/azure_selected_declaration_secret_indicators.py': {'after_sha256': '361844ed7f69dfa530d539e3e661d40cdb7e3f96a08aa1704b36f9b76d75ed18',
                                                                      'after_size': 22710,
                                                                      'before_sha256': '31b9a452cc530f4ceee89b1ca5b6892217eeea82d1699b9c86126e3fd9bdc6f2'},
 'peaso/collectors/azure_selected_log_sample_secret_indicators.py': {'after_sha256': '9734c02af422eabb3f1308cdc046713b05a3071d3d29eae3cdc1944d647d695e',
                                                                     'after_size': 17799,
                                                                     'before_sha256': 'fd07ef51f86ef4ed6889c62c532de732f69f7c76e568c08db6d39271094718f8'},
 'peaso/collectors/azure_selected_secret_integration_20261020.py': {'after_sha256': '7609b76c8b3e43e18c444b7d53815306b83a3e0c62b21ca44a19ffa895fbb7a1',
                                                                    'after_size': 2784,
                                                                    'before_sha256': '0046da76a6a83b45abfe53041472ed21b60c298130aeb7154a7da1cc0b13344c'},
 'peaso/collectors/azure_selected_storage_secret_indicators.py': {'after_sha256': '4a090b1f8fe9da69de7e4aef9d467e01d421cc00febc0fc20ea978e1f1f00b63',
                                                                  'after_size': 23672,
                                                                  'before_sha256': '59db1280c49909db57368b7e4e61e846f5f2c8ee1b323c6b2204f2110646beda'},
 'peaso/collectors/gcp.py': {'after_sha256': '2f770fc9ef7ed9ae773318c78185fdf7830bac66d52b4d99c29bfb373f651235',
                             'after_size': 268594,
                             'before_sha256': 'f7554a0e905d712242bfd2826866517bbc410b1a4aa9e3ef195c75c07df37e96'},
 'peaso/collectors/gcp_additional_literal_secret_indicators.py': {'after_sha256': 'bd38dd89cbbbd0238f700e074954eef741a18b4605d8511297ba73df1aa0fef9',
                                                                  'after_size': 28804,
                                                                  'before_sha256': '0bfb934509a3ae9cd00f826371bbc1d7a7999d755d62a2234f1da650cc9ca492'},
 'peaso/collectors/gcp_appengine_source_secret_indicators.py': {'after_sha256': '2dada521edbcf79f1bc3c007faab7dec39ca3265ac805e6a18f186ae8cae363e',
                                                                'after_size': 14228,
                                                                'before_sha256': '5f0dc6ceb82d853f10f4af47858504ae09b266e50800f49ecf8724238385ad61'},
 'peaso/collectors/gcp_artifact_file_secret_indicators.py': {'after_sha256': '13f050c19bca65f164cece4c3f12e4745181e815bcc12c93f94f09815328a897',
                                                             'after_size': 16769,
                                                             'before_sha256': '30606f70908536e1fd5a710ccd5f62d0fb953fa1eeac474341c7f38c01db2e5b'},
 'peaso/collectors/gcp_batch_referenced_source_20261020.py': {'after_sha256': 'f21abd85d0484b63210b3a595ce00f2f7a4b0e463437ac626b174e1bb0c104c8',
                                                              'after_size': 20423,
                                                              'before_sha256': 'c0bb32c6b0f8aaa0975ec3ed28875b2618ab8c2a674e16b41173e21ba4082921'},
 'peaso/collectors/gcp_cloudbuild_log_secret_indicators.py': {'after_sha256': 'b4f2e30ad5141d7fe55be30aba6f85234ab91ee9ae6aa2a95c505b565ead13e3',
                                                              'after_size': 15599,
                                                              'before_sha256': 'd3b9e2f4a76079808f7c3b6b47daeaf215b46df1abb28669224e0eeb848f7568'},
 'peaso/collectors/gcp_cloudrun_content_sources.py': {'after_sha256': 'e77571cf6d7df16cc605c2812a555140c978a108b008214fffcd465ab6461e51',
                                                      'after_size': 12895,
                                                      'before_sha256': '9eba14a11e18f0910bbebff72b8a482d2a676f399d46795f6a7fe8b318d69699'},
 'peaso/collectors/gcp_cloudrun_v2_job_declared_images_20261020.py': {'after_sha256': 'f38f6d25dd081129e3dca5fac87d9caa47c08c5ac7c4bd0c9cc9f5d1fa0045bb',
                                                                      'after_size': 20913,
                                                                      'before_sha256': '91e6118e969286fd577eea11c65f5f2129e4711604c45414f601fbeb71ed0f51'},
 'peaso/collectors/gcp_composer_source_secret_indicators.py': {'after_sha256': '1155223c7360cddb7c7276ffe0213c1e8c145daafe28b58ba44d9b41f23ad9a8',
                                                               'after_size': 16488,
                                                               'before_sha256': 'fbe60d18f2ec81fd014ed8b1650daf194f49166324c01e0d5d9ab09c4f062257'},
 'peaso/collectors/gcp_configuration_secret_indicators.py': {'after_sha256': 'f26a95b868a297a6450632ab20fadef51e9731079e6c9c9f005048df27d06b6e',
                                                             'after_size': 16968,
                                                             'before_sha256': '8c573da30b8bf20c1dfa88d450e44caf0935aa68f831fef941ef58f832901549'},
 'peaso/collectors/gcp_dataflow_referenced_source_20261020.py': {'after_sha256': 'e9b4d073084291fdbfad7b84752a69ed0bb62c0bb46e2b2df9b9ca8d46860cbe',
                                                                 'after_size': 21186,
                                                                 'before_sha256': 'c638e6ad782b475e9d6bc2ee93aed1bc57da67281bbb53ffa364935f84c6ad59'},
 'peaso/collectors/gcp_dataform_secret_indicators.py': {'after_sha256': '05f69411648c3b5c43440259247da31501c3baaf533fd37318045cd645e15415',
                                                        'after_size': 18424,
                                                        'before_sha256': 'ca02f4a3025442421b25433a7930f157cb9ffd01295c8a07b8dce1d8a9428a70'},
 'peaso/collectors/gcp_dataproc_referenced_source_secret_indicators.py': {'after_sha256': 'bc67ceb68d3e1c08b6d4a6e49710347e98e7ee363c23fe9ff37c984ce24de5aa',
                                                                          'after_size': 29773,
                                                                          'before_sha256': '75f3bb777dd00bb154f24de0f459994fefbced29262c91ec17967618f54801f0'},
 'peaso/collectors/gcp_function_secret_indicators.py': {'after_sha256': '3f0fd85858c2c29d76740539a3aef5c7d022e4b52b19398581b8d535fd7be7fe',
                                                        'after_size': 9357,
                                                        'before_sha256': 'f0107e484b39ca361710b0c838c07eb861fe8701239f79e91b41230a211b58c3'},
 'peaso/collectors/gcp_function_secret_pairs_20261020.py': {'after_sha256': '31237ce04804acc4a82923b5a0e4fb0a02d2246cb8a03ef15a364e576df31c9c',
                                                            'after_size': 9769,
                                                            'before_sha256': 'e6f344088f0fbbbb50ff782852495cc9c23a874448e9b732543027e01e068598'},
 'peaso/collectors/gcp_gke_literal_secret_indicators.py': {'after_sha256': 'd1fb79749be2e5731ff14f99285e600756772275ce3f2e47e9924af92795399b',
                                                           'after_size': 31424,
                                                           'before_sha256': '9939b98e6393d33fc105d9f1f6ece556f697d19a69f6064149fcbbc0b52a3def'},
 'peaso/collectors/gcp_image_secret_indicators.py': {'after_sha256': '79a71aff4057819868db2d87b1608f07b29474aaf7c967f2a1f0f93207f250d1',
                                                     'after_size': 23150,
                                                     'before_sha256': '7891365e7a5ecd82734dd385d1ed64b56b11e1283e07dc2f3b9e16cbee2e104e'},
 'peaso/collectors/gcp_job_literal_secret_indicators.py': {'after_sha256': 'b0c3dbd8efbd003c03d3b4b67b87e74601b17698ee38303fa1eee1312c52c961',
                                                           'after_size': 28633,
                                                           'before_sha256': 'afe4305155c2350cab0faa3f00d8a2a1431de0d23f890fe3780075abd77c8055'},
 'peaso/collectors/gcp_log_secret_indicators.py': {'after_sha256': '742707093416635c370b49b5f4d4ceb7aa6ead869a7d3748e1ee3698a4ab8268',
                                                   'after_size': 16108,
                                                   'before_sha256': '7600114140eef746787981f73b18b47910c0d82797662050f2a6944306b7b161'},
 'peaso/collectors/gcp_network_catalog.py': {'after_sha256': 'c98251b502ef4bee29bc78d1e45675fb5c1e8d70cc689a37bb2133950f97a301',
                                             'after_size': 23319,
                                             'before_sha256': 'ee993a57728ce4e41a183d19942de76a9907f2532ade9cd1cafd2d303630682f'},
 'peaso/collectors/gcp_notebook_airflow_secret_indicators.py': {'after_sha256': '8317f2883f819d07d88b05a5714e119a241c3f0a2200a9d54e47ba24d8f28684',
                                                                'after_size': 12331,
                                                                'before_sha256': '70d808587cca4847f5979f7ed9eb6452b6f332c6996d68157c7af00cf3278118'},
 'peaso/collectors/gcp_selected_archive_secret_indicators.py': {'after_sha256': '686b2922de3447d6fe91a76071e56f9d57df169253ab45b24124df2cd1aa5675',
                                                                'after_size': 11881,
                                                                'before_sha256': '5da0da030a5d7be256956f7126f5a8b5aaed8c552b49185a8d6ed7d4e1badd23'},
 'peaso/collectors/gcp_selected_object_secret_indicators.py': {'after_sha256': '9d9aa19b15499e3eb9c69add0610e014b9be8f1e4997403cdc6ad70818260339',
                                                               'after_size': 15166,
                                                               'before_sha256': 'fb9d1c2837660501bd87ab9642519f4caadfc395eee3193d1ccefd1bb2517959'},
 'peaso/collectors/gcp_selected_task_routine_secret_indicators.py': {'after_sha256': 'a8f794d8b1cedcdc8d45e11d4c6f4bc7ca62c649e753d4abe5342e99d77e1ec6',
                                                                     'after_size': 16107,
                                                                     'before_sha256': 'b424bf05b428b54914baad891b272151351284c630b62c72d3ae1c826ccf8530'},
 'peaso/collectors/gcp_sourcerepo_secret_indicators.py': {'after_sha256': 'b885ce15301a12cfcbb9dcb9fdc9b22358af706f961c4c3c69110ac543af3dde',
                                                          'after_size': 16156,
                                                          'before_sha256': '34f0c7eaf42626d7da2bbeac98ce912e792000aa28e42bea91c6fbc3f0591069'},
 'peaso/collectors/gcp_workbench_referenced_source_20261020.py': {'after_sha256': '0362bb137ea6b0dfb1d5479e67e83b4478f10fa31d35bc41f22086806c5c76aa',
                                                                  'after_size': 24683,
                                                                  'before_sha256': '3c8a3b4dcaf51c6f1544dd1d4465d8a60c00ec1d605a3d808e7590b0ce219b73'},
 'peaso/collectors/k8s.py': {'after_sha256': 'c24dd7b7e8c8686e7586bafef776268a3700f72dcc898271fc3ed295fcfd6a56',
                             'after_size': 128319,
                             'before_sha256': '86eca83f116bc8fe4a2b28d5ced1ae6612507c5cc3f53968fe6ec28df14a15f1'},
 'peaso/collectors/k8s_literal_secret_indicators.py': {'after_sha256': '81a720ec705b5ab461c93ca8db6df00314d74fbd797cdf48e9305553c0f2fc3b',
                                                       'after_size': 22303,
                                                       'before_sha256': '1ee91c6b52cf142d30ef58f55dd11f8e1688d129791c869a1a6783e7a80aa47b'},
 'peaso/collectors/k8s_selected_log_sample_secret_indicators.py': {'after_sha256': 'c9c3923d34f35347097d1d7a9c4cc83d8755a0b3c7d7b7dfb059684c9cebd7e3',
                                                                   'after_size': 25274,
                                                                   'before_sha256': '0fe2d51cb83f4126994f1bfaf1eff50c96469c3b1e285c44d78825f48328e9c0'},
 'peaso/engine.py': {'after_sha256': 'a50d361a883b7f2ea21026ce8413cfe4741481ed21fe5cb812b2acd8125a5c12',
                     'after_size': 158245,
                     'before_sha256': '8e00227aa81c91869e025f7f4c18426e6a2383c3eff05ae7d904fd63c34bfe5b'},
 'peaso/finding_groups.py': {'after_sha256': '988d84b1d701b8e22163fa77c58302e7f1761f388578666887160111eb494be0',
                             'after_size': 12332,
                             'before_sha256': '3bf8ee3254dc5cecbd36b72619c8d8698c0d4f625f6de7fe9e32692feb7e9ac7'},
 'peaso/finding_observation.py': {'after_sha256': '2232b4bc5c705ed8afdec0dadfc6ad1b1b28517938325450f318ee3851231254',
                                  'after_size': 4596,
                                  'before_sha256': '5bbf65a0174ebdf613daafa280050ac37f22d36dd256842843234fdbd00e281c'},
 'peaso/finding_types.py': {'after_sha256': '2103ac2bfe7a1f1feaa852e2547db064a6184f1ea764a75dd9c6dcc98619f299',
                            'after_size': 1957,
                            'before_sha256': 'c8f13d627a6a1420b871b7cb2e5fd0684505788caaca7cef65c72c93e784111f'},
 'peaso/least_privilege.py': {'after_sha256': '75056a22a267881fb7be27250f3fb300ca347ae0c683d59d9048495c042ff43f',
                              'after_size': 11154,
                              'before_sha256': '61e9aaf18953054eeee37e130f515a12d9f180cd06dc25f723345aaeb0b0ddf1'},
 'peaso/principal_exposure.py': {'after_sha256': 'b4e98f78fe7d2541f52d2884fb1021a68a4326e8abe876c94b91bc1ad34806ab',
                                 'after_size': 51683,
                                 'before_sha256': '1b6d987e8918a07393e571b1da82b1e4ecf1539d15436f30e8f00201f0382dff'},
 'peaso/principal_exposure_requirements.py': {'after_sha256': '90674590dc003621529435b6638735b122c66f30f8c472aad932ee1011f26481',
                                              'after_size': 1279,
                                              'before_sha256': 'e86fc86a22244876e4a70d455791727a702c40b2995a10d5ab5542187730e9f5'},
 'peaso/privesc/catalog/aws/_excluded_eks_strict_reaudit_20261016.yaml': {'after_sha256': '4ce99488d31b8b83672f031214b0818614cf4a3c4843758e180c277efc929091',
                                                                          'after_size': 3385,
                                                                          'before_sha256': '06d5eb0cabde1c3556addc88c6facfa9b8ed6c08b595636db4f1830fa066272a'},
 'peaso/privesc/catalog/aws/_excluded_uncollected_host_join_strict_reaudit_20261016.yaml': {'after_sha256': '457059a7cbeb8cce340faa541cf93442299fdb73cefd4daf87d593101453bda8',
                                                                                            'after_size': 11032,
                                                                                            'before_sha256': 'a534c8cdbaac2d98dbe5eea05d3bfa9e6a4d950bd747dc9574c486580c47c36d'},
 'peaso/privesc/catalog/aws/_excluded_uncollected_service_join_final_reaudit_20261016.yaml': {'after_sha256': '829d841560dd6f1e74bdd5647a623867667a16e376932515682d0f59f0026441',
                                                                                              'after_size': 6167,
                                                                                              'before_sha256': 'edd158a156a51180f5b61ca2ce8dea819ad1cff6ba1245a26b090d30fbb6f204'},
 'peaso/privesc/catalog/aws/amplify.yaml': {'after_sha256': 'bbe4822db2eb820ca7630b3c51089dcc57ac14e1d49d67db459df74a3ddc6db4',
                                            'after_size': 6437,
                                            'before_sha256': '104d9a155b91ec8b26fab0cff38f1b78f2963a39802966f0c5555ba9f6b8d201'},
 'peaso/privesc/catalog/aws/apprunner.yaml': {'after_sha256': 'c8e2ee1bd260c18c9e43d76ce66db19b656cb05edd4224cfbaca6399fda48daa',
                                              'after_size': 5672,
                                              'before_sha256': '5844af33c334fcaa692981a6cf18d164dde8c9e7f4a0ef8d2e9b0573e1ad5862'},
 'peaso/privesc/catalog/aws/appstream.yaml': {'after_sha256': 'c7b23d0b9444ec822e9400f8e205de333626f6f678ae182ff919e38d4cdb97e1',
                                              'after_size': 14216,
                                              'before_sha256': '481b4638ebe455be735cb1184107e304de5c877301cd88dd19632a066edff1ef'},
 'peaso/privesc/catalog/aws/athena.yaml': {'after_sha256': '69da7d26e8b021827ccac4ec03f3a0d58830382da27cc617d9796eac508f96ed',
                                           'after_size': 3359,
                                           'before_sha256': '283b74faaa7a0da3f7d069a87059d5d3f21c9813e4333cb02d9ca9a041e8587f'},
 'peaso/privesc/catalog/aws/batch.yaml': {'after_sha256': '81c04052566721d10c461c82e7bb7ae73648f80d0eefde76f4a127b54e6adfd2',
                                          'after_size': 3330,
                                          'before_sha256': 'e872c7aaa0c9589436b9579f38ebad620f677a63dd636821dfb31efe47116d2a'},
 'peaso/privesc/catalog/aws/bedrock.yaml': {'after_sha256': '2e947c953c2378a4d2ebbea1da20718196b4b8c92021ea6664be29cc1809812c',
                                            'after_size': 10951,
                                            'before_sha256': 'b8d3daec804e3e4445b873161ebf5ec824d0275ddfd17b13edbda8b5002a9aaf'},
 'peaso/privesc/catalog/aws/braket.yaml': {'after_sha256': '9333867fce2500440bcb2fb7a387317701850fc8f69c71abbb1fab4a1134f5f0',
                                           'after_size': 2105,
                                           'before_sha256': '4ec781aad950913b1014cb7cb4d17f9e0beedbb36810be6b8ea2f8a772231d14'},
 'peaso/privesc/catalog/aws/cloudcontrol.yaml': {'after_sha256': '6b7bb1860a99ca666e176e41812beda4d41be70178a7df1c245ace50b7efb6b0',
                                                 'after_size': 2857,
                                                 'before_sha256': '9025efb72f877c06451648ee52a63f61ef4dd5ac96cc19c2a643f4f8eb0dff85'},
 'peaso/privesc/catalog/aws/cloudformation.yaml': {'after_sha256': 'ad4816740a10c606b7cbbfc9c6582759e5a9269669aba008ede3eb8a141bb717',
                                                   'after_size': 18299,
                                                   'before_sha256': '625f1cd4f7376585e9e7174401eab7bf39388d5db62fce179e7841b8e2218a81'},
 'peaso/privesc/catalog/aws/cloudfront.yaml': {'after_sha256': 'a18feca425a11c7f754426824365f681a666a043e0f4d397ba2fcb4716fc9a61',
                                               'after_size': 3475,
                                               'before_sha256': 'aa3a86edb32653508d0ce7d9960115b30cc4db4f51ea7958234691a0b670405c'},
 'peaso/privesc/catalog/aws/codebuild.yaml': {'after_sha256': '60f2efd19ffd3aa47904a5b8b5da5496cfb52477915cba647261e7ce78929e73',
                                              'after_size': 15486,
                                              'before_sha256': '4595acf1c920f0b35e7e19c1b421d18e3917c24afb3664032e7179cef5452689'},
 'peaso/privesc/catalog/aws/codepipeline.yaml': {'after_sha256': 'ad9fe5c3eaf2794ecbea601a1773af86e39372bf1e706df53b499325fff6e30e',
                                                 'after_size': 7668,
                                                 'before_sha256': '4c413cbda23022762569dd8dac2fd30b4a47d9b518162d5878751b5aebfaf0d5'},
 'peaso/privesc/catalog/aws/config.yaml': {'after_sha256': '05dcdb743e5c10cb67aafada8e0fd02d3cb90565c52ee478bfdff7b995a4eecd',
                                           'after_size': 3142,
                                           'before_sha256': '909c84ea777f23a9e7d5df11562a5c7199eb9fa998e61be6912421cd7047efc1'},
 'peaso/privesc/catalog/aws/datapipeline.yaml': {'after_sha256': 'd0cd911056af980f78e338ed57841e1db5e9caadab2ad655f1e006e10eff6276',
                                                 'after_size': 2540,
                                                 'before_sha256': '623bf29c4f4ec1127fb6fe5729055d7a5d47759fb429111220d3e136dc4df1d7'},
 'peaso/privesc/catalog/aws/deadline.yaml': {'after_sha256': '5eac90672eb7ff7b5481043dd786cdb31cf8174537b9f458841b387c225f7e68',
                                             'after_size': 4660,
                                             'before_sha256': 'af5268fefbc4c7d7a481b176278b1026005fea1980deba1d06a1f7f0c60f17f3'},
 'peaso/privesc/catalog/aws/devicefarm.yaml': {'after_sha256': 'ce61d9df6a834b6327a1e43c30adf5bcf67b9b2f61875905f83d5117241f2fc6',
                                               'after_size': 2334,
                                               'before_sha256': '700ff232a8ff7ea321a2bfd342f42ba2edada0700be549bf622f1dc15d150e9b'},
 'peaso/privesc/catalog/aws/ec2.yaml': {'after_sha256': '367ea2f0063fc8d487645531b4c7a4d48ead8fd0fddcc75dba4918365f3e748b',
                                        'after_size': 16765,
                                        'before_sha256': '4e487b00eef310ad676796fa32ea9cf492445304267050ec4db7d5bbc6381d01'},
 'peaso/privesc/catalog/aws/ecs.yaml': {'after_sha256': 'ea07876be3159eea7e56cdb772e39179ed6474b36c123b6bf05ecbc08556436c',
                                        'after_size': 12259,
                                        'before_sha256': '20e3b4e1c6c1cec0ff5bb6eadc701d3514f7e7520bdf662046c763438c6888a7'},
 'peaso/privesc/catalog/aws/eks.yaml': {'after_sha256': '29a2b105513036aef128f86b3fe65ce170ff8cfeeb1c51a5ccd87197023f1d24',
                                        'after_size': 8979,
                                        'before_sha256': '5d5b1de3bac627d90cd3f85b9a9b6fd98116abb98257ab35fb80eff018681c5e'},
 'peaso/privesc/catalog/aws/elasticbeanstalk.yaml': {'after_sha256': 'ee6506397e43cbb4a26295cc105c04c2396dbf34db2748d85e5f9fb71f1e33aa',
                                                     'after_size': 3785,
                                                     'before_sha256': 'f9d4bc7fc67d99d0380c2bbd75efeb600239e17ec82c63cefd9fe6cc3c7993eb'},
 'peaso/privesc/catalog/aws/emr.yaml': {'after_sha256': '661844631116a7cd6c33a545208eadb9f04ee6925bda60f9bba65e69b90eea36',
                                        'after_size': 6674,
                                        'before_sha256': 'a06ae910a846151468598dbbedda912c63a84544fb5e208ddbe03f80e7dd83a9'},
 'peaso/privesc/catalog/aws/emrserverless.yaml': {'after_sha256': 'f9d00c56fcab511b428a6fd2633de60d6c4a57ee1c9de5c152741662e5f4b8e6',
                                                  'after_size': 8917,
                                                  'before_sha256': '9370eedf754e792ac2e81ce45e6f0d7c236ee8ad35b94fedeacf48d0996c76c9'},
 'peaso/privesc/catalog/aws/events.yaml': {'after_sha256': '9f314caa754dae44b2f6c25acb6f8901f8521fa864f3a36f4013b3608c579b40',
                                           'after_size': 2941,
                                           'before_sha256': '200c7cba5b70b62fc6859866ae483c028e789ff0c1e63308adc3b39f64ee9082'},
 'peaso/privesc/catalog/aws/exact-principal-v5.yaml': {'after_sha256': '32b590c868500a3998bb367abb22ed7e498fb24c5cb1f6147fa5da533ce11ec7',
                                                       'after_size': 10909,
                                                       'before_sha256': '892b101a0c3a90e933a497f3c7c9dfa92b0c7121dfac0e1ccfb84298af5eedc2'},
 'peaso/privesc/catalog/aws/flink.yaml': {'after_sha256': '1d1ba1cf4df640ce13a75b7eb4ffcb5ff7ab73e1b055826ac394becaaf7adf83',
                                          'after_size': 2706,
                                          'before_sha256': '8ae0a66cc9f82cf4eac115111600873c5e0db22eba5ef78dec81477a2220cb66'},
 'peaso/privesc/catalog/aws/gameliftstreams.yaml': {'after_sha256': 'fba6c01fb72a83df35baf9dcdf3c2c71907a70040bc2c9b8333824f8d63f23aa',
                                                    'after_size': 2691,
                                                    'before_sha256': 'b466b32d4f8646c9e1b06157ec9bbd168335f75739c4f6619830f37ab48baff9'},
 'peaso/privesc/catalog/aws/glue.yaml': {'after_sha256': '6be60e2bc010228b3a73bafc349ff0aa68282a2c52f320ab2260e38f2fcfd790',
                                         'after_size': 14054,
                                         'before_sha256': '66b9f991fecd0545422012fcd5f1659fa3bfc6413e86499553b8ef856c9616f5'},
 'peaso/privesc/catalog/aws/grafana.yaml': {'after_sha256': '4b5279e48474294e5b8b551faf7e501d8b263d8bb12bac55347dcf3d5ff6be91',
                                            'after_size': 5443,
                                            'before_sha256': 'e6a0c5b7de7fd11454fc2caf5144006d4f580cedd8635935463630d3e071507c'},
 'peaso/privesc/catalog/aws/iam.yaml': {'after_sha256': '36eb2b2ae0ef9fb00fd709a8a52a107abd3d0a905dca9fdbd5d2edabc46e4a51',
                                        'after_size': 39643,
                                        'before_sha256': 'eb275cf2b6e4aaed9177b072335c73f313bb0368a9b62fafa567828b2723e9f2'},
 'peaso/privesc/catalog/aws/lambda.yaml': {'after_sha256': '039331cbe0720153418d8d07836f21bd8fefb6a268eee8456d2bb3f7d3493a5a',
                                           'after_size': 30393,
                                           'before_sha256': '9bf180664f272ba62403a626d51841e71572f4474055052e1db9e2ad76195789'},
 'peaso/privesc/catalog/aws/m2.yaml': {'after_sha256': '5f6af5d896a364a5a5eb0999e42ae1d9733b9bc03fa8e500b44535c03a207461',
                                       'after_size': 3194,
                                       'before_sha256': '6a6847ab2d1c161f76c78b00faf216433e082c4457eb0818648ef3c3000746d5'},
 'peaso/privesc/catalog/aws/migrationhub.yaml': {'after_sha256': '7645ecdfd54f2d9b116c6cb34910c167b0759d497b8a43c619cfac865d0c639a',
                                                 'after_size': 5888,
                                                 'before_sha256': '712053ec0c45f24041d13600045aba376a7df5183ed3551a5a4fe7d6f0ef6dd8'},
 'peaso/privesc/catalog/aws/mldataaccess.yaml': {'after_sha256': '38317ed82e186cfd3117ae5cb54657a10ac60e8dc643d3a041979f972ac41753',
                                                 'after_size': 5455,
                                                 'before_sha256': '8df2a2fd109ce9ad83bc4b6e539730ecfaaca81630a5900ffe52b87fcfd0a8c3'},
 'peaso/privesc/catalog/aws/mwaa.yaml': {'after_sha256': 'eb33d3f7077e8604d8de7e6c14721751faeb01be4185f5923c1b9c15401138c3',
                                         'after_size': 5694,
                                         'before_sha256': 'a926130b8c1f08d7971a489901525a17e2f6a578fd6ba6c471b5cec18bdba85d'},
 'peaso/privesc/catalog/aws/organizations.yaml': {'after_sha256': '7b61bdd9d5bbc8be72d973a8a4783e75e6a41060a86b52846bddc8ecf5bd66f6',
                                                  'after_size': 5114,
                                                  'before_sha256': 'ec2804ef1e1b47753e6e7cac21ede40e807a0c34f717d89086378fd09a03d6df'},
 'peaso/privesc/catalog/aws/quicksight.yaml': {'after_sha256': 'a4104ddd00a4d93fbc5cfad8a253e96942b222a7816f9fc0f47e5b92c51a4ae4',
                                               'after_size': 2213,
                                               'before_sha256': '7dbfb747cc17c7d9b55a2125452ac666970082d8b4dfc518236d52d2cd2158b9'},
 'peaso/privesc/catalog/aws/s3.yaml': {'after_sha256': '5690dda8cf38b0252c4ae9d526848dc0dbae572e22729613c02519a28af43aad',
                                       'after_size': 4810,
                                       'before_sha256': 'ec5a5e120877c664989a33ed97ce6c8d2e88c9ce6c62d6d41d067f3387b22c14'},
 'peaso/privesc/catalog/aws/sagemaker.yaml': {'after_sha256': '3bdad3c0f9ffa7103f3ae42306c660250a4584c29710d481187d7f67cdd4b680',
                                              'after_size': 22498,
                                              'before_sha256': '12dd17309895bd1fafd48432af18b681e269ad806546dca9a7653d73b330f3cc'},
 'peaso/privesc/catalog/aws/scheduler.yaml': {'after_sha256': '95ef350bb76a1f87bc085d706a7958404fb34b6cd6a7ae39950dcd4dc0ee2cd0',
                                              'after_size': 2385,
                                              'before_sha256': '7fcdf75c29efc950d194b912be846ee5335220a096e4dabc1d8a98098ae68fe2'},
 'peaso/privesc/catalog/aws/scoped_grants.yaml': {'after_sha256': '5d823300caabe6038c338bdfdfed4436f2b020ffac1211a3b9743e078260890f',
                                                  'after_size': 7094,
                                                  'before_sha256': 'eb81246e23447f8c20dc5de0e64282d4a45601dd20271375e8f809db20279e56'},
 'peaso/privesc/catalog/aws/ssm-incidents.yaml': {'after_sha256': '0b67e3ed49dc935b1f3ed45b2948d571637394e93aacf87ca238438a8833c0b6',
                                                  'after_size': 2896,
                                                  'before_sha256': '9d2a602967ddee33f54151157719c6c1ed592ae412a2f8e3c5944ca7c930ec48'},
 'peaso/privesc/catalog/aws/ssm.yaml': {'after_sha256': '2b625fe0b4b667f4b0cd908c867b74b37387849ff4ef558595c8c2d92dc2097a',
                                        'after_size': 17724,
                                        'before_sha256': '7799825bf03727fe3e1c4e23b69b83aaf8a2e2323a2ca192f338a3f8dd86ac39'},
 'peaso/privesc/catalog/aws/stepfunctions.yaml': {'after_sha256': 'a74fee8d582598961779dc431605aa3d2a3469c09d87181af5e053f33ccf539f',
                                                  'after_size': 6209,
                                                  'before_sha256': '4bad2f2b1afe3933fd9d078a71b7a77956c44519f8ea4b9d3bcdd3c790c2c68c'},
 'peaso/privesc/catalog/aws/sts.yaml': {'after_sha256': '8339400182a52d2b380606f2f5bdb30a15e3afaf6c31e00adafc5d71da8c2d4d',
                                        'after_size': 7493,
                                        'before_sha256': '45b1f557495d7643d8d5dd231a7d1f783b2feaef356ede2b65db1723083e0f29'},
 'peaso/privesc/catalog/aws/workspaces.yaml': {'after_sha256': '642764b9709968f6e6c76a353ac50dab32bd6586509a47be090787d0230d65bd',
                                               'after_size': 2620,
                                               'before_sha256': 'b2d5f632513fd02af700a503b06a03837b2cedbf8e6e7a5e8ba01c664201992c'},
 'peaso/privesc/catalog/gcp/bigtable.yaml': {'after_sha256': '6a43ae3dbf6b1e6f5f63c9f3ac6110aa4078f90c3ef1621af0d2d3f61993df63',
                                             'after_size': 3000,
                                             'before_sha256': 'd17f19c394c7b3ee05712494d17f9510ff64775c52262a65fb460ce026c69f43'},
 'peaso/privesc/effective_permissions/aws.py': {'after_sha256': '41821b785fb17e9c73e793773c108288644ed980372be2c7c30b3bb0801ee787',
                                                'after_size': 572606,
                                                'before_sha256': 'c57baf34dd7970404bdcdb294bfcc9e348f74ba1de3c9efffe175a95e2d079ec'},
 'peaso/privesc/effective_permissions/aws_conditions.py': {'after_sha256': '050705908b1b5f7fad124dba2c379fee04e140dc38ca37c94dd6f314e1dd26b3',
                                                           'after_size': 12592,
                                                           'before_sha256': 'ffdba563d22c4e16f5d193fca38e0f1ccbfa449d4c843602d031d98f8cb2c005'},
 'peaso/privesc/effective_permissions/aws_s3_access_grants.py': {'after_sha256': 'a3b1847e504e61f36a5860fc9d1c691215acb952716c2b756b5d1a0ee6c075d0',
                                                                 'after_size': 4473,
                                                                 'before_sha256': '6469c7f431a2279060556601f351750a4ebf1b4e9c178bc7b7742cca30b2e318'},
 'peaso/privesc/effective_permissions/aws_s3_self_grant.py': {'after_sha256': 'b4ab4792bc79db2ed6c8b9ae1af215ac3b33145a1ca73ef00cdaaf69b976090c',
                                                              'after_size': 3140,
                                                              'before_sha256': '41ffb3bcb53defb421e99a89df1c09b45a79a054e65860b1af34771ed388bf22'},
 'peaso/privesc/effective_permissions/aws_scoped_grants.py': {'after_sha256': '86d7d5f6c10384f8389f39d50991da72f625af764caeb307d4e27d73ae6948c4',
                                                              'after_size': 5637,
                                                              'before_sha256': '23d2cb6bf3cea7637943b8c8d1f45bbd8891d444141a88bb04de47f61cc5571f'},
 'peaso/privesc/effective_permissions/ec2_profile_association.py': {'after_sha256': '4f83e51e0525a1d2d51dea5cd8fd9f94ededa16baf8fef8aa501fd8ac64dd2f0',
                                                                    'after_size': 11814,
                                                                    'before_sha256': 'ab05a45f4c8e82998c1831a4de5c55cff903098496d29a3f72c80ce80161b9c5'},
 'peaso/privesc/evaluator.py': {'after_sha256': 'e11d43b4b0caa223d399f3457651ef12d00cb24a6bbf60681b3bac3f50c9ab6f',
                                'after_size': 68507,
                                'before_sha256': '5aa866af5b51518db04449324ba3ab7d75316700992391f3e4f3fe498a4305ee'},
 'peaso/privesc/finding_explanation.json': {'after_sha256': 'bf3f0dc9adf604363d8bb960598efdaced8c5c4aec42eec7e31e4ffb661bc476',
                                            'after_size': 185102,
                                            'before_sha256': '79f51cab12b8d815fde729be09adc39d3b4664899f1b6d6c7eefe8a1cc98ae68'},
 'peaso/privesc/finding_explanation.py': {'after_sha256': '3d0a530d20ecfb3468fd87bae99438d8f8e6e802c39e55a55cc36363884d8206',
                                          'after_size': 6261,
                                          'before_sha256': '6b42ec83d0e09fb182ac238870c31c0eaa92008408c671fcb1c7a418dde4d13a'},
 'peaso/privesc/graph.py': {'after_sha256': 'da53f3c50900cd52afe003b4817e5a559199d5a58f1816bb1bae3f112abf3ebf',
                            'after_size': 28950,
                            'before_sha256': 'd84af484a1c7765127da3cf7ce3179ba331f79b792f56a23eb7250c2c0cb5714'},
 'peaso/privesc/privesc-technique.schema.json': {'after_sha256': '621811cc0244541a67b99289d0b3ef10ad8bb716bebd1fe2af1848c108f0bcd1',
                                                 'after_size': 162666,
                                                 'before_sha256': '87813e47589caaf97f0d11cb3e55123a3b229676136f179d2ed045771a65e1da'},
 'peaso/privesc/schema.py': {'after_sha256': 'c2d6746620d3ad3a523a8f2f70e706417045d184c63fea1d2f5029bd3a68ff07',
                             'after_size': 216925,
                             'before_sha256': '6de9324c85af2bd58d1e2feab6cf255b4b2c2f17704668371c8cc4fcad2de674'},
 'peaso/privesc/versioned_catalog.py': {'after_sha256': '33582b7e45c7cc0857c4bc3c8e3d70d4988914be8a53dc5d10992f7e26a81131',
                                        'after_size': 16206,
                                        'before_sha256': 'b14f581917d7c626600cf9ebb0eecfec69f2055787efaa143bda0faff7683b36'},
 'peaso/progress.py': {'after_sha256': '795477ca9c1c79f0cbecb67bd9ac0e3327c7984e4bdae105c5fe649a163974da',
                       'after_size': 6829,
                       'before_sha256': 'a9cb5e9b1b9c77eb583450d8045e8636c2f089c958af0350bbeb51d4d9889188'},
 'peaso/rulepacks/check_descriptions.json': {'after_sha256': 'ddc30745b6a31dac8c655a117f72a044369503889e9182b6259fafa30190cb5d',
                                             'after_size': 4465829,
                                             'before_sha256': 'e9efda68fd352ec174d406b66d17525a8df3d0e217427cb0cca063b9e232d096'},
 'peaso/rulepacks/compliance_lookup.json': {'after_sha256': '009658dae818966ca496bcae1b7699b59bf1fc3ff932b96e85450f67f3a7fb5f',
                                            'after_size': 3590365,
                                            'before_sha256': '75d3b6a1a454577bc82e1e71bd4ac5394f5365f38547af5e6b3d4d22b92b7f63'},
 'peaso/rulepacks/compliance_requirements.json': {'after_sha256': 'eb1acafd1c23183a8b689d068f9a6eae55115204d906381350d8ea124e280867',
                                                  'after_size': 20270522,
                                                  'before_sha256': '7824cdc5e17d3900892d0f066576b8b6bc726adb6d754b6fcfdf50961be1f363'},
 'peaso/rulepacks/framework_catalog.json': {'after_sha256': 'b78a33d15c88450bc4bba68fa30611d6c7d0bb02bba89dc96acca389a0443001',
                                            'after_size': 940022,
                                            'before_sha256': '20b7add1167c5e0d12964cb2f3e1f021e0fdb3180e3c03677f0beba61d7f144f'},
 'peaso/rulepacks/remediation_aws_families_reviewed.json': {'after_sha256': '2bc00a89cbafef9555941ee3d2edbca4a8112bfb95f24ff5210509a3e7583e4c',
                                                            'after_size': 1563338,
                                                            'before_sha256': '6577458b6149df569672f777594f3c267a6a572bff2b63d88db0d9d60e545fda'},
 'peaso/rulepacks/remediation_aws_reviewed.json': {'after_sha256': '44b7a839e07512625ee5597315c5d3f5b3a51ed0fd094e3988bd0a355c72049b',
                                                   'after_size': 1745331,
                                                   'before_sha256': 'b19eef2e094da960355bfa3d1a78a2f4618742aa7d1eda18c4e0da1fe857fa8c'},
 'peaso/rulepacks/remediation_azure_reviewed.json': {'after_sha256': '79125774225588425ac791bcfe24ea1fc29d91edd69dd05c9e086f50cd4c0d7c',
                                                     'after_size': 381373,
                                                     'before_sha256': '07a2e7b7fe86d2203e9fe990a063874c08aa118a3084e8850136aadf36f40fa7'},
 'peaso/rulepacks/remediation_compliance_batch_remaining_aws.json': {'after_sha256': '70acf720532286acc5f7f8fdfee14928dce45237a2e4b344edd5650c0e9dac2a',
                                                                     'after_size': 53374,
                                                                     'before_sha256': 'ebe28d47a1880fa09acc7f42022a1e199ac9c27992049d2ca074670b41d6d490'},
 'peaso/rulepacks/remediation_compliance_batch_remaining_azure.json': {'after_sha256': 'f14498d67d8abf30da78d5209bb6a0ecd003a0aa3a21bc69d7d23511705e6cc0',
                                                                       'after_size': 42909,
                                                                       'before_sha256': 'a8f76c1a53926fa6cbbda666e80108b494d7933d77d9d39f6d1226f02937b91a'},
 'peaso/rulepacks/remediation_compliance_batch_remaining_k8s.json': {'after_sha256': '10c964fa627bea08572001bcf8ecf298095c0c0a84ffce0e75c4f366b4444cfb',
                                                                     'after_size': 73974,
                                                                     'before_sha256': '5485734fd0351e2dc8f6862b65472164e05df802e32d9c08d061826d1f1492ca'},
 'peaso/rulepacks/remediation_compliance_new_azure.json': {'after_sha256': '895b06ddfe288462798d3f0641072570677994fc894f2fd8c34c0bd0a8e46887',
                                                           'after_size': 9020,
                                                           'before_sha256': 'ac2130282b35c03d408d4af20b8a05d34642d401746b25e2aa5d7fef1d2d1c53'},
 'peaso/rulepacks/remediation_compliance_new_k8s.json': {'after_sha256': '5f1ed90f96a88a9679b5d1da3726faac8d8d222707f58d88c9f5229783f1ac7a',
                                                         'after_size': 25902,
                                                         'before_sha256': '2edc3719ee1883f91b482eb5c89f31702b4286ed5066a20ad0adb018a516314e'},
 'peaso/rulepacks/remediation_curated.json': {'after_sha256': 'b00eac2c6c2bae62a3d926ed42fd93fc219a31bc293bfc44594d736cd98634d7',
                                              'after_size': 204445,
                                              'before_sha256': 'b425e641bb9b46c42c78d17821f37a9789031d6aa4cc2c52bd90ecd4a996f34b'},
 'peaso/rulepacks/remediation_details.json': {'after_sha256': '5c8749627b4f20e61274a6cae2cc19ddd44fc4d7528940b43237f99874bd3c25',
                                              'after_size': 1753119,
                                              'before_sha256': '9bd958901b844eda3d4a21d088ee952bbd4f76c46d904f9880b88fec34638dca'},
 'peaso/rulepacks/remediation_native_azure_review_20261020.json': {'after_sha256': 'e26592e05250ea4eb78113dc48059412274ab6a62eca0d4dd3cc9d7e4e3d5582',
                                                                   'after_size': 28050,
                                                                   'before_sha256': '8cb77c6ff3c9e529e66b2728b1ea01fc3f20f9a4358f34532d8144bbd52946ac'},
 'peaso/rulepacks/runtime_metadata.json': {'after_sha256': 'f3127e56f1a77ea1c0b627ba607b4356a9144e548adfc3a2e190fea66d610cce',
                                           'after_size': 18535771,
                                           'before_sha256': 'a792979ad0ecac951ad23acc765b93a9414a023bc1a2aeba63988e65a366d3c7'},
 'peaso/secret_scanning.py': {'after_sha256': 'a1c7163c021ac85b945f3b4289a5fa45f4e641bc22e302c51c9014ec7531c322',
                              'after_size': 17399,
                              'before_sha256': '72aaf391e3b168d9b8f7a10603a5763c04137b5e7807fef320b4fc22fa1a9d19'},
 'peaso/server/access_check.py': {'after_sha256': 'f8a7c0866a42ac0426312ac6159be7b393c70a4975e618e6dcccdda99a2debad',
                                  'after_size': 38504,
                                  'before_sha256': 'e8909a1f9fcaae4f2c85e61a3858a96712e6903d2c297c80944c7f22497bd975'},
 'peaso/server/app.py': {'after_sha256': '11e23b0edc2e64b9ff32f3ad89102a461ab23fe01d7ae074edd98362765b7d6a',
                         'after_size': 135216,
                         'before_sha256': '5f2b3dc9bb6f54c56502b22263973c6d1c6f0932af703317d46008dd11732707'},
 'peaso/server/attack_logs.py': {'after_sha256': 'bd9d35207edd00a7fd3d1630afd2d7e43064db6e03cd4c6f1b4ec510703e1315',
                                 'after_size': 12105,
                                 'before_sha256': 'ba14e74bfe4e71e4f79a8661d3a4bc3de25d467873f8e7ee2c937f4f9df10142'},
 'peaso/server/aws_access_requirements.py': {'after_sha256': '5440560f68b7a31551a6ba634bd2897fb8a80ac87c7822039fe1e2731dddba79',
                                             'after_size': 5244,
                                             'before_sha256': '49145075d9ed2d5956d4a332a0caadca7cfd480c84473bbe36701b4e6d82ed44'},
 'peaso/server/azure_attack_logs.py': {'after_sha256': 'a754eeb25080ca6bdb021b717a3b854d9431da92dc45959cc2220e661d09eb6f',
                                       'after_size': 11025,
                                       'before_sha256': '4e843c88d126594dde63dce52c08c680eb08131661d678f6884552d5dec82557'},
 'peaso/server/entra_attack_logs.py': {'after_sha256': 'b6805b72b0ffd1b3843d6348b58321fed66ab15bcffc8d2bdc91533015e3b141',
                                       'after_size': 8670,
                                       'before_sha256': '2f4298a69bd2b5d6dace6f5eeb7d0b0c636626b2ece1e1f1d5a871620cf659c9'},
 'peaso/server/gcp_attack_logs.py': {'after_sha256': '751720b7a679d3d7abdfa77814dbe0052cc77e99a0d148f2073175ea4a082063',
                                     'after_size': 8813,
                                     'before_sha256': '2d1e92105d2082b2dba5abc0f6033797b0bf94aea54857e66fa699c8026fe122'},
 'peaso/server/models.py': {'after_sha256': 'a7d2c1b37ee8c7511da3f43ab5125a8c3b7130cdce9b02055e14463897d865f1',
                            'after_size': 8475,
                            'before_sha256': '7029f52ca0d16370eaf58ad6fb4666d1767a914f196acecafd3cea3088591933'},
 'peaso/server/scheduler_handler.py': {'after_sha256': '1228e2ef457a4e79263e0d4daa3c2aed8773c78b2f277c59e3fba963b019922f',
                                       'after_size': 788,
                                       'before_sha256': '72d709a61e762af1740be41e63bcde54fd30328d86cb7b3017e3e6729fb676a3'},
 'peaso/server/validation.py': {'after_sha256': '5120dfd68b9b15a62d81281f779dcb71aa4b59db314d0dbc5c00b5f073348d9d',
                                'after_size': 70336,
                                'before_sha256': '71060735cab0da2e358c89bbd00963e63fa7166ede9089bc9f111a860e1b794d'},
 'peaso/snapshot.py': {'after_sha256': 'f373beecd5374bc8383389163f5b596fd8c72c5a7e7835d2c739c98b71f7c027',
                       'after_size': 9404,
                       'before_sha256': '6dcf7d4953c1b1b17e8669cb5f44960a4340ea8d6e9f93fb356d4df52d570919'},
 'peaso/storage/artifacts.py': {'after_sha256': 'a31b81222e4abbdd9f7e2427f78854bda8692af18033ff1bd6c2b4d237b645f6',
                                'after_size': 8946,
                                'before_sha256': 'de542a6dde456cf0975aa8bd61240933cbdefd2b83a600e3fe9a963c100c549e'},
 'peaso/storage/dynamodb.py': {'after_sha256': '15ecb32f222eeb7f06928662b2d6e53c51fe8fd8542e1830a9aba5be07172c67',
                               'after_size': 68903,
                               'before_sha256': '9f74a16cae0e890e0cfadb6811e8f8c3936ebd6e2460ceca0cfedf96164c34fe'},
 'peaso/storage/reports.py': {'after_sha256': '403efea11af4263462370d33a14fa5d02c6083573bf98e9601ff7f3c1ca1c156',
                              'after_size': 11855,
                              'before_sha256': '2416214b3021e55883fdf8ba1108f90a98f81f1192899b9806e43001eeb4e166'},
 'peaso/storage/runtime.py': {'after_sha256': '22a5e7e68bc1fbac13732ec413248154c8582e1d733a5ca86737aeef59435b69',
                              'after_size': 2492,
                              'before_sha256': '4a52941e15925e48296da78e3a8386a58a60de5bfb0ad0119d66a397886a2214'},
 'peaso/storage/sqlite.py': {'after_sha256': '60eb5e815baf6320e942c9c21adf8ed2da710df375e2135106170943fe16a783',
                             'after_size': 51452,
                             'before_sha256': '40b0e77c3b6ce103881eb3e867a9a2f45ddfab99fc17ba5e6c76cc6bfd916144'},
 'peaso/worker.py': {'after_sha256': '9d9e43a534fccfc7617bee6ffc3e4839069e6982bf11554620d2699d279cd612',
                     'after_size': 34048,
                     'before_sha256': '9c1e6d558aad8804996fef249ad3836d39498a23121436aab69cbe0a52384bb0'}}
REVIEWABLE_CURRENT_PATHS = frozenset(['peaso/ai/access.py',
 'peaso/ai/agents/priorities.yaml',
 'peaso/ai/auth.py',
 'peaso/ai/codex_relay_cli.py',
 'peaso/ai/contracts.py',
 'peaso/ai/fargate.py',
 'peaso/ai/model_relay.py',
 'peaso/ai/network.py',
 'peaso/ai/pipeline.py',
 'peaso/ai/recommendations.schema.json',
 'peaso/ai/runner.py',
 'peaso/ai/task_runtime.py',
 'peaso/analysis/__init__.py',
 'peaso/analysis/common.py',
 'peaso/analysis/iam.py',
 'peaso/analysis/internet_exposure.py',
 'peaso/attack_detection/aws_apigateway_controls_next.py',
 'peaso/attack_detection/aws_apigateway_rest_next.py',
 'peaso/attack_detection/aws_kinesis_video_controls_next.py',
 'peaso/attack_detection/github_source.py',
 'peaso/attack_detection/history_worker_s3.py',
 'peaso/attack_detection/rules.py',
 'peaso/check_services.json',
 'peaso/check_services.py',
 'peaso/checks/aws_a_cloudwatch.py',
 'peaso/checks/aws_a_s3.py',
 'peaso/checks/aws_b_redshift.py',
 'peaso/checks/aws_bulk_clarity_reviewed.py',
 'peaso/checks/aws_compute_storage_clarity_reviewed.py',
 'peaso/checks/aws_database_clarity_reviewed.py',
 'peaso/checks/aws_evidence_explanations.py',
 'peaso/checks/aws_final_clarity_reviewed.py',
 'peaso/checks/aws_finding_clarity_reviewed.py',
 'peaso/checks/aws_pass_observed_evidence.py',
 'peaso/checks/aws_remaining_clarity_reviewed.py',
 'peaso/checks/aws_selected_configuration_secret_review_20261020.py',
 'peaso/checks/azure_acr_image_secret_review_20261020.py',
 'peaso/checks/azure_databricks_notebook_secret_review_20261020.py',
 'peaso/checks/azure_finding_clarity_reviewed.py',
 'peaso/checks/azure_ml_selected_asset_secret_review_20261020.py',
 'peaso/checks/azure_ml_selected_job_secret_review_20261020.py',
 'peaso/checks/catalog.py',
 'peaso/checks/claude2_aws_b_compute.py',
 'peaso/checks/claude2_aws_b_data.py',
 'peaso/checks/claude_aws_a_common.py',
 'peaso/checks/claude_aws_a_iam.py',
 'peaso/checks/claude_aws_b_messaging.py',
 'peaso/checks/claude_azure_data.py',
 'peaso/checks/claude_azure_identity.py',
 'peaso/checks/claude_azure_network.py',
 'peaso/checks/claude_gcp_k8s_compute.py',
 'peaso/checks/claude_gcp_k8s_iam.py',
 'peaso/checks/compliance_new_k8s.py',
 'peaso/checks/exposure_endpoints.py',
 'peaso/checks/finding_types.json',
 'peaso/checks/gcp_artifact_file_secret_review_20261019.py',
 'peaso/checks/gcp_cloudbuild_log_secret_review_20261019.py',
 'peaso/checks/gcp_composer_source_secret_review_20261019.py',
 'peaso/checks/gcp_dataproc_referenced_source_descriptions_20261020.json',
 'peaso/checks/gcp_dataproc_referenced_source_secret_review_20261020.py',
 'peaso/checks/gcp_image_secret_review_20261019.py',
 'peaso/checks/gcp_remaining_clarity_reviewed.py',
 'peaso/checks/gcp_scalar_clarity_reviewed.py',
 'peaso/checks/gcp_selected_archive_secret_review_20261019.py',
 'peaso/checks/gcp_sourcerepo_secret_review_20261019.py',
 'peaso/checks/gcp_task_routine_secret_review_20261020.py',
 'peaso/checks/hacktricks_scope.json',
 'peaso/checks/hacktricks_scope.py',
 'peaso/checks/k8s_literal_current_metadata_20261020.py',
 'peaso/checks/k8s_literal_secret_review_20261020.py',
 'peaso/checks/k8s_ports_components.py',
 'peaso/checks/k8s_ports_workloads.py',
 'peaso/checks/k8s_selected_metadata_secret_admission_20261020.py',
 'peaso/checks/k8s_selected_metadata_secret_review_20261020.py',
 'peaso/checks/k8s_workload_clarity_reviewed.py',
 'peaso/checks/reviewed_release_priorities_20261020.json',
 'peaso/checks/selected_configuration_content_observed_20261020.py',
 'peaso/cli.py',
 'peaso/collectors/aws.py',
 'peaso/collectors/aws_access_analyzer_lifecycle.py',
 'peaso/collectors/aws_additional_secret_indicators.py',
 'peaso/collectors/aws_b_services.py',
 'peaso/collectors/aws_code_log_content_indicators.py',
 'peaso/collectors/aws_codebuild_buildspec_runtime_20261020.py',
 'peaso/collectors/aws_codebuild_buildspec_source_20261020.py',
 'peaso/collectors/aws_codebuild_redaction.py',
 'peaso/collectors/aws_configuration_payload_secret_indicators.py',
 'peaso/collectors/aws_configuration_secret_indicators.py',
 'peaso/collectors/aws_ecr_artifacts_native.py',
 'peaso/collectors/aws_facts_cb_ca.py',
 'peaso/collectors/aws_facts_compute_edge.py',
 'peaso/collectors/aws_facts_data_identity.py',
 'peaso/collectors/aws_facts_ext.py',
 'peaso/collectors/aws_facts_v4_holds.py',
 'peaso/collectors/aws_lambda_environment_secret_indicators.py',
 'peaso/collectors/aws_network_catalog.py',
 'peaso/collectors/aws_network_inventory.py',
 'peaso/collectors/aws_package_content_indicators.py',
 'peaso/collectors/aws_s3_selected_source_secret_indicators.py',
 'peaso/collectors/aws_selected_configuration_secret_indicators.py',
 'peaso/collectors/aws_user_data_secret_indicators.py',
 'peaso/collectors/aws_workload_command_runtime_20261020.py',
 'peaso/collectors/aws_workload_command_source_20261020.py',
 'peaso/collectors/azure.py',
 'peaso/collectors/azure_acr_image_secret_indicators.py',
 'peaso/collectors/azure_apim_operation_window_20261020.py',
 'peaso/collectors/azure_app_settings_secret_indicators.py',
 'peaso/collectors/azure_databricks_notebook_secret_indicators.py',
 'peaso/collectors/azure_devops_git_native.py',
 'peaso/collectors/azure_devops_selected_content_secret_indicators.py',
 'peaso/collectors/azure_function_package_integration_20261020.py',
 'peaso/collectors/azure_function_package_source_20261020.py',
 'peaso/collectors/azure_function_settings_declarations_20261020.py',
 'peaso/collectors/azure_ml_selected_asset_secret_indicators.py',
 'peaso/collectors/azure_ml_selected_job_secret_indicators.py',
 'peaso/collectors/azure_selected_configuration_secret_indicators.py',
 'peaso/collectors/azure_selected_declaration_secret_indicators.py',
 'peaso/collectors/azure_selected_log_sample_secret_indicators.py',
 'peaso/collectors/azure_selected_secret_integration_20261020.py',
 'peaso/collectors/azure_selected_storage_secret_indicators.py',
 'peaso/collectors/gcp.py',
 'peaso/collectors/gcp_additional_literal_secret_indicators.py',
 'peaso/collectors/gcp_appengine_source_secret_indicators.py',
 'peaso/collectors/gcp_artifact_file_secret_indicators.py',
 'peaso/collectors/gcp_batch_referenced_source_20261020.py',
 'peaso/collectors/gcp_cloudbuild_log_secret_indicators.py',
 'peaso/collectors/gcp_cloudrun_content_sources.py',
 'peaso/collectors/gcp_cloudrun_v2_job_declared_images_20261020.py',
 'peaso/collectors/gcp_composer_source_secret_indicators.py',
 'peaso/collectors/gcp_configuration_secret_indicators.py',
 'peaso/collectors/gcp_dataflow_referenced_source_20261020.py',
 'peaso/collectors/gcp_dataform_secret_indicators.py',
 'peaso/collectors/gcp_dataproc_referenced_source_secret_indicators.py',
 'peaso/collectors/gcp_function_secret_indicators.py',
 'peaso/collectors/gcp_function_secret_pairs_20261020.py',
 'peaso/collectors/gcp_gke_literal_secret_indicators.py',
 'peaso/collectors/gcp_image_secret_indicators.py',
 'peaso/collectors/gcp_job_literal_secret_indicators.py',
 'peaso/collectors/gcp_log_secret_indicators.py',
 'peaso/collectors/gcp_network_catalog.py',
 'peaso/collectors/gcp_notebook_airflow_secret_indicators.py',
 'peaso/collectors/gcp_selected_archive_secret_indicators.py',
 'peaso/collectors/gcp_selected_object_secret_indicators.py',
 'peaso/collectors/gcp_selected_task_routine_secret_indicators.py',
 'peaso/collectors/gcp_sourcerepo_secret_indicators.py',
 'peaso/collectors/gcp_workbench_referenced_source_20261020.py',
 'peaso/collectors/k8s.py',
 'peaso/collectors/k8s_literal_secret_indicators.py',
 'peaso/collectors/k8s_selected_log_sample_secret_indicators.py',
 'peaso/engine.py',
 'peaso/finding_groups.py',
 'peaso/finding_observation.py',
 'peaso/finding_types.py',
 'peaso/least_privilege.py',
 'peaso/principal_exposure.py',
 'peaso/principal_exposure_requirements.py',
 'peaso/privesc/catalog/aws/_excluded_eks_strict_reaudit_20261016.yaml',
 'peaso/privesc/catalog/aws/_excluded_uncollected_host_join_strict_reaudit_20261016.yaml',
 'peaso/privesc/catalog/aws/_excluded_uncollected_service_join_final_reaudit_20261016.yaml',
 'peaso/privesc/catalog/aws/amplify.yaml',
 'peaso/privesc/catalog/aws/apprunner.yaml',
 'peaso/privesc/catalog/aws/appstream.yaml',
 'peaso/privesc/catalog/aws/athena.yaml',
 'peaso/privesc/catalog/aws/batch.yaml',
 'peaso/privesc/catalog/aws/bedrock.yaml',
 'peaso/privesc/catalog/aws/braket.yaml',
 'peaso/privesc/catalog/aws/cloudcontrol.yaml',
 'peaso/privesc/catalog/aws/cloudformation.yaml',
 'peaso/privesc/catalog/aws/cloudfront.yaml',
 'peaso/privesc/catalog/aws/codebuild.yaml',
 'peaso/privesc/catalog/aws/codepipeline.yaml',
 'peaso/privesc/catalog/aws/config.yaml',
 'peaso/privesc/catalog/aws/datapipeline.yaml',
 'peaso/privesc/catalog/aws/deadline.yaml',
 'peaso/privesc/catalog/aws/devicefarm.yaml',
 'peaso/privesc/catalog/aws/ec2.yaml',
 'peaso/privesc/catalog/aws/ecs.yaml',
 'peaso/privesc/catalog/aws/eks.yaml',
 'peaso/privesc/catalog/aws/elasticbeanstalk.yaml',
 'peaso/privesc/catalog/aws/emr.yaml',
 'peaso/privesc/catalog/aws/emrserverless.yaml',
 'peaso/privesc/catalog/aws/events.yaml',
 'peaso/privesc/catalog/aws/exact-principal-v5.yaml',
 'peaso/privesc/catalog/aws/flink.yaml',
 'peaso/privesc/catalog/aws/gameliftstreams.yaml',
 'peaso/privesc/catalog/aws/glue.yaml',
 'peaso/privesc/catalog/aws/grafana.yaml',
 'peaso/privesc/catalog/aws/iam.yaml',
 'peaso/privesc/catalog/aws/lambda.yaml',
 'peaso/privesc/catalog/aws/m2.yaml',
 'peaso/privesc/catalog/aws/migrationhub.yaml',
 'peaso/privesc/catalog/aws/mldataaccess.yaml',
 'peaso/privesc/catalog/aws/mwaa.yaml',
 'peaso/privesc/catalog/aws/organizations.yaml',
 'peaso/privesc/catalog/aws/quicksight.yaml',
 'peaso/privesc/catalog/aws/s3.yaml',
 'peaso/privesc/catalog/aws/sagemaker.yaml',
 'peaso/privesc/catalog/aws/scheduler.yaml',
 'peaso/privesc/catalog/aws/scoped_grants.yaml',
 'peaso/privesc/catalog/aws/ssm-incidents.yaml',
 'peaso/privesc/catalog/aws/ssm.yaml',
 'peaso/privesc/catalog/aws/stepfunctions.yaml',
 'peaso/privesc/catalog/aws/sts.yaml',
 'peaso/privesc/catalog/aws/workspaces.yaml',
 'peaso/privesc/catalog/gcp/bigtable.yaml',
 'peaso/privesc/effective_permissions/aws.py',
 'peaso/privesc/effective_permissions/aws_conditions.py',
 'peaso/privesc/effective_permissions/aws_s3_access_grants.py',
 'peaso/privesc/effective_permissions/aws_s3_self_grant.py',
 'peaso/privesc/effective_permissions/aws_scoped_grants.py',
 'peaso/privesc/effective_permissions/ec2_profile_association.py',
 'peaso/privesc/evaluator.py',
 'peaso/privesc/finding_explanation.json',
 'peaso/privesc/finding_explanation.py',
 'peaso/privesc/graph.py',
 'peaso/privesc/privesc-technique.schema.json',
 'peaso/privesc/schema.py',
 'peaso/privesc/versioned_catalog.py',
 'peaso/progress.py',
 'peaso/rulepacks/check_descriptions.json',
 'peaso/rulepacks/compliance_lookup.json',
 'peaso/rulepacks/compliance_requirements.json',
 'peaso/rulepacks/framework_catalog.json',
 'peaso/rulepacks/remediation_aws_families_reviewed.json',
 'peaso/rulepacks/remediation_aws_reviewed.json',
 'peaso/rulepacks/remediation_azure_reviewed.json',
 'peaso/rulepacks/remediation_compliance_batch_remaining_aws.json',
 'peaso/rulepacks/remediation_compliance_batch_remaining_azure.json',
 'peaso/rulepacks/remediation_compliance_batch_remaining_k8s.json',
 'peaso/rulepacks/remediation_compliance_new_azure.json',
 'peaso/rulepacks/remediation_compliance_new_k8s.json',
 'peaso/rulepacks/remediation_curated.json',
 'peaso/rulepacks/remediation_details.json',
 'peaso/rulepacks/remediation_native_azure_review_20261020.json',
 'peaso/rulepacks/runtime_metadata.json',
 'peaso/secret_scanning.py',
 'peaso/server/access_check.py',
 'peaso/server/app.py',
 'peaso/server/attack_logs.py',
 'peaso/server/aws_access_requirements.py',
 'peaso/server/azure_attack_logs.py',
 'peaso/server/entra_attack_logs.py',
 'peaso/server/gcp_attack_logs.py',
 'peaso/server/models.py',
 'peaso/server/scheduler_handler.py',
 'peaso/server/validation.py',
 'peaso/snapshot.py',
 'peaso/storage/artifacts.py',
 'peaso/storage/dynamodb.py',
 'peaso/storage/reports.py',
 'peaso/storage/runtime.py',
 'peaso/storage/sqlite.py',
 'peaso/worker.py'])
REVIEWABLE_CURRENT_PATHS = extend_reviewed_successors('provider_combined_source_bridge_20261020', REVIEWED_CURRENT_CHANGES, REVIEWABLE_CURRENT_PATHS)
INITIALIZER_ADDITION = (
    b"from . import native_admission_cpu_shared_successor_20261020 as _deployed_ai_shared_source\n"
    b"_historical_aws_workload_command_shared_successor_20261020 = aws_workload_command_shared_successor_20261020\n"
    b"aws_workload_command_shared_successor_20261020 = _deployed_ai_shared_source\n"
)
HELPER = "peaso/checks/native_admission_cpu_shared_successor_20261020.py"
RECEIPT = HELPER.removesuffix(".py") + ".json"
BRIDGE_IMPORT = "from tests.shared_admission_epoch_compatibility_20261020 import active_shared\nbridge = active_shared()\n"
NATIVE_IDS = {
    "aws.review.workload.selected_command_literal_secret_indicators",
    "gcp.review.cloudrun_job.declared_image_secret_indicators",
}



def _pinned_proof(name, expected):
    raw = (ROOT / 'peaso/checks' / (name + '.json')).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected, 'Source-proof receipt changed: ' + name
    return json.loads(raw)


def cpu_receipt():
    """The unchanged canonical CPU proof remains independently testable."""
    return _pinned_proof('native_admission_cpu_shared_successor_20261020',
                         '93a723d84bf4a11cc69f22e0ae924c20c1f1da96c5f6f7f77f148f27b35a0374')


def cpu_epoch_bytes(relative, raw):
    """Two finite signed layers, followed by the original CPU source assertions."""
    if relative not in {'peaso/checks/__init__.py', 'peaso/collectors/aws.py', 'peaso/collectors/aws_facts_swc.py', 'peaso/collectors/azure.py', 'peaso/engine.py'}:
        return raw
    from peaso.checks import private_secret_shared_source_successor_20261021 as current
    if relative == 'peaso/checks/__init__.py':
        if hashlib.sha256(raw).hexdigest() == current._private_receipt()['initializer_after_sha256']:
            raw = current._initialization_predecessor(raw)
        from tests.gcp_positive_conservation_epoch_20261020 import metadata_initializer_bytes
        raw = metadata_initializer_bytes(raw)
    else:
        raw = current._private_before(relative, raw, ROOT)
    layers = (
        ('azure_metadata_only_shared_successor_20261020',
         '4dfa99f4f0903bc99037f8a9e9d860f84ce0c0ce686a8e891f8277c054bdafa7',
         'metadata_only_epoch_file_deltas'),
        ('collector_noop_authorization_shared_successor_20261020',
         '5709994cbe4aa84b8546c21807952dd8873bbca0c6bd354b99459090dccc7be1',
         'native_epoch_file_deltas'))
    for name, expected, section in layers:
        proof = _pinned_proof(name, expected)
        if relative in proof[section]:
            row = proof[section][relative]
            if hashlib.sha256(raw).hexdigest() == row['current_sha256']:
                raw = _reverse(raw.decode(), row).encode()
    expected = cpu_receipt()['integration_file_deltas'][relative]['current_sha256']
    assert hashlib.sha256(raw).hexdigest() == expected, relative
    return raw

# A cold, bytecode-free import attests the whole source closure (about 20 CPU
# seconds); leave headroom for shared or loaded runners.
SUBPROCESS_TIMEOUT = 300


def run(code, root=ROOT):
    # Each subprocess runs the "once" attestation policy: every verifier runs
    # its complete proof on first use, so changed bytes are refused at import.
    # Repeating every nested proof (conftest's "always") costs minutes per cold
    # import; tests of live rebinding after import turn it on explicitly.
    environment = {key: value for key, value in os.environ.items() if key != "PEASO_SOURCE_ATTESTATION"}
    environment.update(PEASO_SOURCE_ATTESTATION="once", PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(root),
                       AWS_EC2_METADATA_DISABLED="true", AWS_CONFIG_FILE="/nonexistent/bridge-proof",
                       AWS_SHARED_CREDENTIALS_FILE="/nonexistent/bridge-proof")
    return subprocess.run([sys.executable, "-B", "-c", code], cwd=root, env=environment,
                          capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)


def green(result):
    assert result.returncode == 0, result.stderr[-9000:]
    return json.loads(result.stdout)


def rejected(result):
    assert result.returncode != 0, "Tampered real source unexpectedly admitted: " + result.stdout
    # Refusal must be an admission/identity failure, not a missing clone input.
    assert "RuntimeError:" in result.stderr or "AdmissionError:" in result.stderr, result.stderr[-9000:]
    assert "FileNotFoundError" not in result.stderr and "ModuleNotFoundError" not in result.stderr, result.stderr[-9000:]


@pytest.fixture(scope="module")
def isolated(tmp_path_factory):
    target = tmp_path_factory.mktemp("provider-bridge-hardlinks")
    paths = (subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
             if (ROOT / ".git").exists() else
             [str(path.relative_to(ROOT)) for directory in ("peaso", "tests", "docs", "scripts", "risk_rules", "bluepeass")
              for path in (ROOT / directory).rglob("*") if path.is_file()
              and "__pycache__" not in path.parts and path.suffix != ".pyc"])
    allowed = {"peaso", "tests", "docs", "scripts", "risk_rules", "bluepeass"}
    paths = [p for p in paths if p and p.split("/", 1)[0] in allowed]
    # Git does not list the separately admitted current overlay. Copy its
    # exact receipt-attested source closure alongside the historical package.
    current = _pinned_proof('azure_metadata_only_shared_successor_20261020',
                            '4dfa99f4f0903bc99037f8a9e9d860f84ce0c0ce686a8e891f8277c054bdafa7')
    closure = set(current['sources']) | {row['path'] for row in current['functions'].values()}
    closure |= {'peaso/checks/azure_metadata_only_shared_successor_20261020.json',
                'peaso/checks/collector_noop_authorization_shared_successor_20261020.json',
                'tests/shared_admission_epoch_compatibility_20261020.py'}
    for name in tuple(closure):
        companion = name.removesuffix('.py') + '.json'
        if name.startswith('peaso/checks/') and name.endswith('.py') and (ROOT / companion).exists():
            closure.add(companion)
    paths = sorted(set(paths) | closure | {HELPER, RECEIPT, BASELINE, "peaso/checks/aws_deployed_ai_shared_successor_20261020.py", "peaso/checks/aws_deployed_ai_shared_successor_20261020.json"})
    assert len(paths) < 12000
    assert sum((ROOT / p).stat().st_size for p in paths) < 2 * 1024 * 1024 * 1024
    for name in paths:
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.link(ROOT / name, destination)
    # Confirm this is the real cloned package, with a successful cold import
    # before any negative proof can be attributed to tampering.
    result = green(run("from pathlib import Path\nfrom peaso.engine import get_catalog\nimport peaso,json\n"
                       "catalog=get_catalog()\nprint(json.dumps({'root':str(Path(peaso.__file__).resolve().parent.parent), 'count':len(catalog['checks'])}))", target))
    assert Path(result["root"]) == target and result["count"] > 1000
    try:
        yield target
    finally:
        shutil.rmtree(target)


@contextmanager
def atomic_change(root, name, changed):
    path = root / name
    before = path.read_bytes()
    source_before = (ROOT / name).read_bytes()
    temporary = path.with_name(path.name + ".bridge-test-atomic")
    try:
        temporary.write_bytes(changed)
        os.replace(temporary, path)
        assert (ROOT / name).read_bytes() == source_before
        yield
    finally:
        temporary.write_bytes(before)
        os.replace(temporary, path)
        assert (ROOT / name).read_bytes() == source_before


def test_catalog_native_registrations_and_deployed_ai_corrections_import_for_real():
    value = green(run("""
import importlib, inspect, json
from peaso.engine import get_catalog
catalog=get_catalog()
from peaso import checks
from peaso.checks import native_admission_cpu_shared_successor_20261020 as canonical_cpu
from tests.shared_admission_epoch_compatibility_20261020 import active_shared
bridge = active_shared()
assert bridge.accepted_native is canonical_cpu
from peaso.checks import aws_ai_recheck_corrections_20261020 as ai
from peaso.checks import aws_workload_command_runtime_consumer_20261020 as command
from peaso.checks import gcp_cloudrun_job_image_secret_review_20261020 as job
from peaso.collectors import aws
registered={c.id:c for c in checks.CHECKS}
assert inspect.unwrap(registered[command.runtime.CHECK].evaluate) is command.evaluate
assert inspect.unwrap(registered[job.CHECK_ID].evaluate) is job.evaluate
for cid in ai.IDS:
    assert registered[cid].evaluate.__code__.co_filename.endswith('aws_ai_recheck_corrections_20261020.py'), cid
canonical=importlib.import_module('peaso.checks.aws_workload_command_shared_successor_20261020')
assert bridge.historical is canonical
assert checks.aws_workload_command_shared_successor_20261020 is bridge
for qualified, fn in bridge._HISTORICAL_FUNCTIONS.items():
    assert getattr(canonical, qualified.split(':')[1]) is fn
bridge.reviewed_inputs(); bridge.s3_reviewed_inputs()
assert 'peaso.collectors.aws_ai_recheck_facts_20261020' in aws.EXTENSION_MODULES
print(json.dumps({'ids':[c['id'] for c in catalog['checks']], 'historical_functions':len(bridge._HISTORICAL_FUNCTIONS)}))
"""))
    assert NATIVE_IDS <= set(value["ids"]) and value["historical_functions"] > 5


def pinned_baseline(raw=None):
    """Retain the complete base package manifest without Git object availability."""
    raw = (ROOT / BASELINE).read_bytes() if raw is None else raw
    assert hashlib.sha256(raw).hexdigest() == BASELINE_SHA256, "Historical baseline fixture changed"
    value = json.loads(gzip.decompress(raw))
    assert value["schema"] == 1 and value["base_commit"] == BASE
    assert len(value["files"]) == 1818
    initializer = value["initializer"].encode()
    row = value["files"]["peaso/checks/__init__.py"]
    assert len(initializer) == row["size"] and hashlib.sha256(initializer).hexdigest() == row["sha256"]
    assert GENERATED_CATALOGS <= value["files"].keys()
    return value


def verify_historical_bytes(root=ROOT, baseline=None):
    baseline = pinned_baseline() if baseline is None else baseline
    assert REVIEWED_CURRENT_CHANGES.keys() <= REVIEWABLE_CURRENT_PATHS
    for name, change in REVIEWED_CURRENT_CHANGES.items():
        assert change.keys() == {"before_sha256", "after_sha256", "after_size"}, name
        assert change["before_sha256"] == baseline["files"][name]["sha256"], name
        assert change["after_sha256"] != change["before_sha256"], name
        assert len(change["after_sha256"]) == 64 and all(c in "0123456789abcdef" for c in change["after_sha256"]), name
        assert type(change["after_size"]) is int and change["after_size"] > 0, name
    for name, row in baseline["files"].items():
        if name in GENERATED_CATALOGS or name == "peaso/checks/__init__.py":
            continue
        raw=(retired_catalog_bytes(root, name) if name==RETIRED_CATALOG_PATH else retained_upstream_bytes(root) if name==RETAINED_UPSTREAM_PATH else (root/name).read_bytes())
        if name in REVIEWED_CURRENT_CHANGES:
            change = REVIEWED_CURRENT_CHANGES[name]
            assert len(raw) == change["after_size"] and hashlib.sha256(raw).hexdigest() == change["after_sha256"], name
            continue
        assert len(raw) == row["size"] and hashlib.sha256(raw).hexdigest() == row["sha256"], name
    # Only the exact three-line alias may differ from the pinned initializer.
    initializer = cpu_epoch_bytes("peaso/checks/__init__.py", (root / "peaso/checks/__init__.py").read_bytes())
    assert initializer.count(INITIALIZER_ADDITION) == 1
    assert initializer.replace(INITIALIZER_ADDITION, b"", 1) == baseline["initializer"].encode()


def verify_generated_catalogs(root=ROOT):
    # Render from the real registry in a cold subprocess. Comparing hashes of
    # complete payloads is exact byte verification, not a JSON subset check.
    value = green(run("""
import hashlib,json
from scripts.peaso_compliance_materialize import ROOT,render_documents
outputs=render_documents()
print(json.dumps({str(path.relative_to(ROOT)):hashlib.sha256(raw).hexdigest()
                  for path,raw in outputs.items()}))
""", root))
    assert GENERATED_CATALOGS <= value.keys()
    for name in GENERATED_CATALOGS:
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == value[name], name


def test_every_historical_package_byte_is_unchanged_against_combined_base(monkeypatch):
    # A shallow checkout need not contain BASE. No baseline Git commands may run.
    def forbidden_git(*args, **kwargs):
        raise AssertionError("Conservation must not require Git history")
    monkeypatch.setattr(subprocess, "check_output", forbidden_git)
    verify_historical_bytes()
    verify_generated_catalogs()


def test_portable_baseline_cannot_be_replaced():
    raw = (ROOT / BASELINE).read_bytes()
    with pytest.raises(AssertionError, match="Historical baseline fixture changed"):
        pinned_baseline(raw + b" ")


@pytest.mark.parametrize("name", [
    "peaso/checks/aws_workload_command_shared_successor_20261020.py",
    "peaso/checks/aws_workload_command_runtime_admission_20261020.json",
    "peaso/checks/__init__.py", "peaso/rulepacks/runtime_metadata.json",
])
def test_portable_conservation_rejects_historical_changes(isolated, name):
    with atomic_change(isolated, name, (isolated / name).read_bytes() + b"\n "):
        # The initializer is first reversed through its reviewed epochs, which refuse unknown bytes.
        with pytest.raises((AssertionError, RuntimeError)):
            verify_historical_bytes(isolated)


@pytest.fixture(scope="module")
def historical_tree(tmp_path_factory):
    target = tmp_path_factory.mktemp("provider-historical-bytes")
    # The retired catalog file stays absent; its exact bytes come from the archive.
    names = [name for name in pinned_baseline()["files"] if name != RETIRED_CATALOG_PATH]
    for name in names + [RETIRED_CATALOG_ARCHIVE]:
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.link(ROOT / name, destination)
    try:
        yield target
    finally:
        shutil.rmtree(target)


def test_exact_reviewed_app_successor_keeps_original_hash_and_rejects_other_bytes(historical_tree, monkeypatch):
    isolated = historical_tree
    name = "peaso/ai/network.py"
    before = (isolated / name).read_bytes()
    original_digest = pinned_baseline()["files"][name]["sha256"]
    after = before + b"\n# Exact synthetic reviewed app correction witness.\n"
    row = {"before_sha256": original_digest,
           "after_sha256": hashlib.sha256(after).hexdigest(), "after_size": len(after)}
    monkeypatch.setitem(REVIEWED_CURRENT_CHANGES, name, row)
    with atomic_change(isolated, name, after):
        verify_historical_bytes(isolated)
    with atomic_change(isolated, name, after + b" "):
        with pytest.raises(AssertionError, match=name):
            verify_historical_bytes(isolated)
    monkeypatch.setitem(row, "before_sha256", "0" * 64)
    with pytest.raises(AssertionError, match=name):
        verify_historical_bytes(isolated)


def test_reviewed_app_map_cannot_exempt_historical_guards(historical_tree, monkeypatch):
    isolated = historical_tree
    monkeypatch.setitem(REVIEWED_CURRENT_CHANGES, HELPER, {})
    with pytest.raises(AssertionError):
        verify_historical_bytes(isolated)


@pytest.mark.parametrize("name", sorted(GENERATED_CATALOGS))
def test_generated_catalog_exceptions_require_exact_materialization(isolated, name):
    with atomic_change(isolated, name, (isolated / name).read_bytes() + b"\n "):
        # Semantically identical JSON still cannot bypass exact materialization.
        with pytest.raises(AssertionError, match=name):
            verify_generated_catalogs(isolated)


def test_exact_additions_and_replacements_reconstruct_the_whole_historical_epoch():
    active_shared().reviewed_delta(ROOT)
    receipt = cpu_receipt()
    assert set(receipt["integration_file_deltas"]) == {
        "peaso/checks/__init__.py", "peaso/collectors/aws.py", "peaso/engine.py", "peaso/collectors/aws_facts_swc.py", "peaso/collectors/azure.py"}
    for name, row in receipt["integration_file_deltas"].items():
        current = cpu_epoch_bytes(name, (ROOT / name).read_bytes()).decode()
        assert hashlib.sha256(current.encode()).hexdigest() == row["current_sha256"]
        for before, after in row.get("exact_replacements", []):
            assert current.count(after) == 1
            current = current.replace(after, before, 1)
        for addition in row["exact_additions"]:
            assert current.count(addition) == 1
            current = current.replace(addition, "", 1)
        assert hashlib.sha256(current.encode()).hexdigest() == row["predecessor_sha256"]
    swc = receipt["integration_file_deltas"]["peaso/collectors/aws_facts_swc.py"]
    assert swc["exact_replacements"] == [[
        '    item["Targets"] = _list(read, ["Id", "Arn"])\n',
        '    item["Targets"] = _list(read, ["Id", "Arn", "DeadLetterConfig"])\n']]


@pytest.mark.parametrize("name", [
    "peaso/collectors/aws.py", "peaso/engine.py", "peaso/collectors/aws_facts_swc.py",
    "peaso/collectors/gcp.py", "peaso/checks/aws_ai_recheck_corrections_20261020.py",
    "peaso/checks/aws_workload_command_shared_successor_20261020.py",
    "peaso/checks/aws_workload_command_runtime_admission_20261020.json",
    "peaso/collectors/azure.py",
    "peaso/checks/aws_deployed_ai_shared_successor_20261020.py",
    "peaso/checks/aws_deployed_ai_shared_successor_20261020.json", HELPER, RECEIPT,
])
def test_real_unrelated_edits_and_historical_or_bridge_tamper_are_rejected(isolated, name):
    before = (isolated / name).read_bytes()
    # JSON whitespace is semantic no-op but must still violate byte attestation.
    changed = before + (b"\n " if name.endswith(".json") else b"\n# unrelated source edit\n")
    with atomic_change(isolated, name, changed):
        result = run(BRIDGE_IMPORT + "bridge.reviewed_delta()", isolated)
        admission = "peaso.private_secret_source_epoch_20261021.AdmissionError: "
        # The reviewed GCP transport and the content-cohort self-proof now refuse these first.
        earlier = {
            # Whichever reviewed GCP proof runs first refuses the edited collector.
            "peaso/collectors/gcp.py": (admission + "reviewed transport source changed",
                                        admission + "reviewed GCP current source changed",
                                        admission + "finite successor current source changed"),
            "peaso/checks/aws_ai_recheck_corrections_20261020.py":
                "RuntimeError: Content cohort source changed: peaso/checks/aws_ai_recheck_corrections_20261020.py",
            "peaso/checks/aws_workload_command_shared_successor_20261020.py": admission + "unreviewed predecessor request",
            "peaso/checks/aws_workload_command_runtime_admission_20261020.json": admission + "unreviewed predecessor request",
            "peaso/checks/aws_deployed_ai_shared_successor_20261020.py": admission + "unreviewed predecessor request",
            "peaso/checks/aws_deployed_ai_shared_successor_20261020.json": admission + "unreviewed predecessor request",
            "peaso/checks/native_admission_cpu_shared_successor_20261020.py": admission + "unreviewed predecessor request",
        }
        if name in earlier:
            assert result.returncode != 0, "Tampered real source unexpectedly admitted: " + result.stdout
            expected = earlier[name] if isinstance(earlier[name], tuple) else (earlier[name],)
            assert result.stderr.rstrip().endswith(expected), result.stderr[-9000:]
            assert "FileNotFoundError" not in result.stderr and "ModuleNotFoundError" not in result.stderr
        else:
            rejected(result)


@pytest.mark.parametrize("name,before,after", [
    ("peaso/collectors/aws.py", "'ebs_optimization_facts_requested', 'sqs_dead_letter_sources_requested'", "'ebs_optimization_facts_requested', 'changed_dead_letter_sources_requested'"),
    ("peaso/engine.py", "['_ebs_optimization_facts_requested']", "['_wrong_optimization_facts_requested']"),
    ("peaso/collectors/aws.py", 'EXTENSION_MODULES += ("peaso.collectors.aws_ai_recheck_facts_20261020",)\n', ""),
    ("peaso/collectors/aws_facts_swc.py", '["Id", "Arn", "DeadLetterConfig"]', '["Id", "Arn"]'),
])
def test_missing_or_changed_deployed_flags_extensions_and_replacements_fail(isolated, name, before, after):
    value = (isolated / name).read_text()
    assert value.count(before) == 1
    with atomic_change(isolated, name, value.replace(before, after, 1).encode()):
        rejected(run(BRIDGE_IMPORT + "bridge.reviewed_inputs()", isolated))


@pytest.mark.parametrize("owner,name,mode", [
    ("peaso.collectors.aws", "collect", "identity"),
    ("peaso.collectors.aws", "collect", "code"),
    ("peaso.collectors.aws", "_safe", "identity"),
    ("peaso.collectors.aws", "_safe", "code"),
    ("peaso.checks.aws_workload_command_shared_successor_20261020", "reviewed_delta", "identity"),
    ("peaso.checks.native_admission_cpu_shared_successor_20261020", "reviewed_delta", "code"),
])
def test_executing_callable_identity_and_code_replacements_fail(owner, name, mode):
    # The positive import is real. Only the negative attempt changes runtime
    # state, in its own subprocess, with no source readers mocked or replaced.
    script = BRIDGE_IMPORT + f"""
import importlib
from peaso import source_attestation_mode
# Re-prove after the replacement, as tests and the image build do.
source_attestation_mode.ALWAYS = True
owner=importlib.import_module({owner!r})
function=getattr(owner,{name!r})
if {mode!r} == 'identity':
    setattr(owner,{name!r},lambda *args,**kwargs: None)
else:
    # Use real file-backed code so 3.12 inspect reaches the admission guard.
    function.__code__=bridge._reverse.__code__
bridge.reviewed_inputs()
"""
    rejected(run(script))


def test_bridge_alias_must_precede_first_shared_installer(isolated):
    name = "peaso/checks/__init__.py"
    value = (isolated / name).read_text()
    # The current epoch rebinds the canonical bridge name to its positive shared source.
    alias = "aws_workload_command_shared_successor_20261020 = _positive_shared_source"
    first = "aws_workload_command_shared_successor_20261020.install_s3()"
    assert value.count(alias) == 1 and value.index(alias) < value.index(first)
    changed = value.replace(alias, "# delayed bridge alias", 1).replace(first, first + "\n" + alias, 1)
    with atomic_change(isolated, name, changed.encode()):
        rejected(run("from peaso.engine import get_catalog\nget_catalog()", isolated))


@pytest.mark.parametrize('relative', [
    'peaso/checks/__init__.py', 'peaso/collectors/azure.py'])
def test_finite_cpu_epoch_reversals_reject_unknown_current_source_bytes(relative):
    from peaso.private_secret_source_epoch_20261021 import AdmissionError
    raw = (ROOT / relative).read_bytes()
    cpu_epoch_bytes(relative, raw)
    with pytest.raises((AssertionError, RuntimeError, AdmissionError)):
        cpu_epoch_bytes(relative, raw + b'\n# unreviewed source proof bytes\n')
