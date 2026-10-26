"""Exact test-only successors for admitted GCP source and prose boundaries.

Historical review rows and captures stay unchanged. The capability fingerprint
is an in-process mutation guard, never a portable admission or JSON exporter.
"""
from copy import deepcopy
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FUNCTION_ID = 'gcp.review.function.literal_environment_secret_indicators'
JOB_ID = 'gcp.review.cloudrun_job.declared_image_secret_indicators'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def cases_fingerprint(value):
    """Hash exact known object fields and graph links, independent of addresses."""
    from peaso.azure_function_package_index_20261020 import _Admitted, _Assertions
    known = {_Admitted: 'native_owner_admission', _Assertions: 'supplied_assertions'}
    seen = {}
    def encode(member):
        kind = type(member)
        if kind in (str, int, bool, float, type(None)):
            return [kind.__name__, member]
        if kind not in (dict, list, tuple) and kind not in known:
            raise TypeError('Unreviewed fixture object: ' + kind.__module__ + '.' + kind.__qualname__)
        if id(member) in seen:
            return ['reference', seen[id(member)]]
        reference = seen[id(member)] = len(seen)
        if kind is dict:
            if any(type(key) is not str for key in member):
                raise TypeError('Unreviewed fixture mapping key')
            return ['dict', reference, [[key, encode(member[key])] for key in sorted(member)]]
        if kind in (list, tuple):
            return [kind.__name__, reference, [encode(part) for part in member]]
        return [known[kind], reference, [[name, encode(getattr(member, name))]
                for name in ('snapshot', 'expected', 'scope')]]
    encoded = encode(value)
    return hashlib.sha256(json.dumps(encoded, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def checked_json(path, expected):
    raw = (ROOT / path).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected, path
    return json.loads(gzip.decompress(raw) if path.endswith('.gz') else raw)


def checked(path):
    return checked_json(path, PINNED_FILES[path])


def current_extension_reviews(historical):
    """Retain36 old owners, prove one exact replacement, add nine admissions."""
    assert len(historical) == 36
    assert not historical.keys() & ADDED_EXTENSION_REVIEWS.keys()
    old = historical[FUNCTION_ID]
    archive = checked('peaso/checks/gcp_function_secret_paired_predecessors_20261020.json.gz')
    assert digest(archive['legacy_cases'][FUNCTION_ID]) == old['fixture_sha256']
    source = bytes.fromhex(archive['files'][old['source']]['hex'])
    assert hashlib.sha256(source).hexdigest() == old['source_sha256']
    assert (ROOT / old['source']).read_bytes() == source
    erratum = checked('docs/check-review/gcp-function-current-ledger-erratum-20261020.json')
    assert erratum['historical_predicate'] == {
        'path': old['source'],
        'qualname': old['reviewed_binding']['module'] + '.' + old['reviewed_binding']['source_qualname'],
        'body_sha256': old['reviewed_binding']['predicate_source_sha256']}
    current = CURRENT_FUNCTION_REVIEW
    assert erratum['predicate'] == {
        'path': current['source'],
        'qualname': current['reviewed_binding']['module'] + '.' + current['reviewed_binding']['source_qualname'],
        'body_sha256': current['reviewed_binding']['predicate_source_sha256'],
        'file_sha256': current['source_sha256']}
    current_cases = checked('peaso/checks/gcp_function_secret_partial_page_cases_20261020.json')
    page = checked('peaso/checks/gcp_function_secret_page_admission_20261020.json')
    assert page['check_id'] == FUNCTION_ID
    assert page['cases'] == 'peaso/checks/gcp_function_secret_partial_page_cases_20261020.json'
    assert page['sources'][page['cases']]['sha256'] == PINNED_FILES[page['cases']]
    assert digest(current_cases[FUNCTION_ID]) == current['fixture_sha256']
    assert old['admission_sha256'] == current['admission_sha256']
    assert old['copy_catalog_sha256'] == current['copy_catalog_sha256']
    result = deepcopy(historical)
    result[FUNCTION_ID] = deepcopy(current)
    result.update(deepcopy(ADDED_EXTENSION_REVIEWS))
    for cid, row in ADDED_EXTENSION_REVIEWS.items():
        reference = OWNER_RUNTIME_RECEIPTS[cid]
        native = checked_json(reference['path'], reference['sha256'])
        binding = row['reviewed_binding']
        qualified = binding['module'] + ':' + binding['source_qualname']
        if cid == JOB_ID:
            assert native['check']['id'] == cid
            assert native['check']['predicate'] == qualified
            assert native['source_sha256'][row['source']] == row['source_sha256']
        elif qualified in native.get('runtime_functions', {}):
            function = native['runtime_functions'][qualified]
            assert function['path'] == row['source']
            assert function['sha256'] == binding['predicate_source_sha256']
        elif qualified in native.get('functions', {}):
            function = native['functions'][qualified]
            assert function['path'] == row['source']
            assert function['body_sha256'] == binding['predicate_source_sha256']
        else:
            function, = [record for record in native['checks'] if record['id'] == cid]
            assert function['evaluate'] == qualified
            assert function['predicate_sha256'] == binding['predicate_source_sha256']
        if 'fixture' in native:
            assert native['fixture'] in row['fixture_sources']
    return result


def historical_admission_row(cid, row):
    """Reverse only the four accepted CCC associations on the two old IDs."""
    if cid not in WORKBENCH_CCC_ADDITIONS:
        return row
    row = deepcopy(row)
    additions = [r for r in row['requirements'] if r['framework_id'] == 'ccc_gcp']
    assert len(additions) == 2
    assert digest(additions) == WORKBENCH_CCC_ADDITIONS[cid]
    row['requirements'] = [r for r in row['requirements'] if r['framework_id'] != 'ccc_gcp']
    return row


def extension_cases(cid, cases):
    if cid != JOB_ID:
        return cases[cid]
    receipt = checked('docs/gcp-review/recheck-20261020/gcp_cloudrun_job_image_runtime_20261020_receipt.json')
    result = {}
    for witness in receipt['native_runtime_witnesses']:
        finding, snapshot = witness['finding'], witness['snapshot']
        collection, = snapshot['collections']
        assert finding['check_id'] == cid
        branch = finding['status'].lower()
        assert branch in ('pass', 'fail') and branch not in result
        result[branch] = deepcopy(collection['items'][0])
        result[branch + '_index'] = {'context': {'provider': 'gcp', 'scope': collection['scope'],
            'metadata': deepcopy(snapshot['metadata'])}, 'collections': {collection['type']: [deepcopy(collection)]}}
    result.update(unknown={}, unknown_index={})
    return result


def current_golden_rows(historical):
    """Preserve every row; seven exact prose errata and one source-pair delta."""
    assert digest(historical) == digest(checked('tests/fixtures/gcp-natural-evidence-golden.json'))
    for path in ('peaso/checks/gcp_natural_evidence.py', 'peaso/checks/gcp_evidence_explanations.json'):
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == PINNED_FILES[path]
    historical_source = gzip.decompress((ROOT / 'tests/fixtures/gcp_evidence_explanations_predecessor_b775.py.gz').read_bytes())
    assert hashlib.sha256(historical_source).hexdigest() == PINNED_FILES['peaso/checks/gcp_evidence_explanations.py']
    assert hashlib.sha256((ROOT / 'peaso/checks/gcp_evidence_explanations.py').read_bytes()).hexdigest() == 'a67e98105d1a17c608252d621a329cf86716878e992389b3377276670361d841'
    assert hashlib.sha256((ROOT / 'peaso/checks/gcp_evidence_explanations_current_20261023.json').read_bytes()).hexdigest() == 'd0cfac399589ee9597ea4fd404560ea3cc30155ceb20f888ca37b3f66467cc63'
    result = deepcopy(historical)
    seen = set()
    for row in result:
        cid, branch = row['finding']['check_id'], row['case']
        key = cid + '|' + branch
        if key in GOLDEN_PROSE_SUCCESSORS:
            successor = GOLDEN_PROSE_SUCCESSORS[key]
            assert digest(row) == successor['historical_row_sha256']
            row['expected'] = successor['expected']
            seen.add(key)
        if cid == FUNCTION_ID and branch == 'fail':
            # The old synthetic fingerprint remains pinned in the golden;
            # current paired native cases supply both runtime/build locations.
            before = row['finding']['evidence']['secret_leaks']
            assert before == [{'fingerprint': 'a' * 64,
                'detectors': [{'engine': 'kingfisher', 'rule': 'synthetic'}],
                'locations': [{'path': 'serviceConfig.environmentVariables', 'line': 1}]}]
            cases = checked('peaso/checks/gcp_function_secret_partial_page_cases_20261020.json')
            row['finding']['evidence']['secret_leaks'] = deepcopy(cases[cid]['fail']['FunctionSecretIndicators']['leaks'])
    assert seen == GOLDEN_PROSE_SUCCESSORS.keys()
    return result


def current_missing_observation(cid, catalog):
    if cid != JOB_ID:
        return catalog[cid]['missing_observation']
    path = 'peaso/checks/gcp_cloudrun_job_image_observed_20261020.py'
    assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == PINNED_FILES[path]
    return ('Evidence for the selected Cloud Run Job’s declared image is incomplete or unbound. '
            'Secret absence and the executed image were not established; credentials were not validated.')


PINNED_FILES = json.loads(r'''
{
  "docs/check-review/gcp-function-current-ledger-erratum-20261020.json": "a0e89befb7eb83f29b37c23f5409e52c0e1e6a10e786314fa50364bae660967a",
  "docs/compliance-ledgers/native-extensions/gcp-batch-referenced-source-20261020.json": "53808fbafe6709eccb594951e5151d5a132298600ff18ae060e9ba44927ed233",
  "docs/compliance-ledgers/native-extensions/gcp-dataflow-referenced-source-20261020.json": "3602c9ef9ef8ba2a1cdcfee853587a2f67f1a08ec0f1d56b33425754a553eb70",
  "docs/compliance-ledgers/native-extensions/gcp-dataproc-referenced-source-20261020.json": "084b861b7cad7ca872d96a87a0b70431a0ebed2033cfa9ff0f5fe71102df9bce",
  "docs/compliance-ledgers/native-extensions/gcp-workbench-head3-20261020.json": "f39bb9be12da90641f7c554cc03c91259d60b426184b417eeee5e3a3a4a26661",
  "docs/compliance-ledgers/native-extensions/gcp-workbench-referenced-source-20261020.json": "7ee9ab010077c71a27fadf08c231d715073eb8df1800739a09aa54042adb2845",
  "docs/compliance-ledgers/native-extensions/workload-content-20261020.json": "990f38aa7472ec959a524ed52b5652075bbba0d1a0f4c5894747b5a1a9abf9ff",
  "docs/gcp-review/recheck-20261020/bigquery-historical-native-closure.json": "aa4f777196baec8e451cce94d2d6f8baa958185ef6702a4a6b9fa298b576ad2c",
  "docs/gcp-review/recheck-20261020/compute-second-fixes.json": "cff94ec444905393e950ebfb2dee93a0a36fa503cd81881e917267b6923ebbd7",
  "docs/gcp-review/recheck-20261020/final-services-predicate-successors.json": "2ec7f70a441788f5049543caa045b4e5748e3855393990b3cae8acbfa582e8dd",
  "docs/gcp-review/recheck-20261020/gcp_cloudrun_job_image_runtime_20261020_receipt.json": "dc63589448228096c334e087e84dd299cc49ac18a53941660a7a3ba8686eb8bc",
  "peaso/checks/gcp_cloudrun_job_image_observed_20261020.py": "f6180e6efe4ff213f13f328470b4ec898be5ca3f589b11502c634d264897572d",
  "peaso/checks/gcp_cloudrun_job_image_secret_review_20261020.py": "6411b11c8d7926311ebd88da98890b42b56e0a63b936bf7568792c42c4cd3a22",
  "peaso/checks/gcp_dataflow_batch_source_runtime_cases_20261020.json": "3eaffaf2bc5124c9662acab4a09d39b0a5243ee29a3fb0b1fe47708b586d96a7",
  "peaso/checks/gcp_dataflow_batch_source_runtime_consumer_20261020.py": "c06098ba7318daf6519e0647e7f9e0acd49496790d1ee22f2f8a3f16d1136489",
  "peaso/checks/gcp_dataproc_referenced_source_secret_review_20261020.py": "49ca4dda3b2abc80d8e59c75eecb3b432ea930ffa396494082ea9cfd7382423d",
  "peaso/checks/gcp_dataproc_source_runtime_cases_20261020.json": "ea6f724d024a80c76d50616bfe8be848088eced477b3b83b0b505768e2626bd5",
  "peaso/checks/gcp_evidence_explanations.json": "91d201e8a8c094c538dbc759d4fad695cb16c3cae41ae582925af03a79d14cfc",
  "peaso/checks/gcp_evidence_explanations.py": "ef658069466a230b16d450122b9203f57df8c039028a26981cfe055b76822313",
  "peaso/checks/gcp_function_secret_page_admission_20261020.json": "a9cf3dd72f0745e2c61cb9ace44afdbaa9dc06ba0e02a7a3ffd4c253d2d95b23",
  "peaso/checks/gcp_function_secret_paired_predecessors_20261020.json.gz": "aa4d52a469ec2ef9525488aa1b9dfb2b67be07d69179e9e5772d7f90f36892e2",
  "peaso/checks/gcp_function_secret_partial_page_cases_20261020.json": "d21c09b9e550934994c26efd3cda3738918308189254f2c9a1252d487f9bb9e7",
  "peaso/checks/gcp_natural_evidence.py": "16ee1b2e9fb5b90d859c01778f83c5e3d95674e4b4fa92e72f49d527eb514ab8",
  "peaso/checks/gcp_task_routine_secret_review_20261020.py": "18a4701d7e40fb18bc75291f80383a376713aa4a3fc3c4703b7c7f5c275aeeb1",
  "peaso/checks/gcp_task_routine_secret_review_20261020_fixtures.json.gz": "567fc1842443b68cc2311415d8420961cdd09441e18b68f4ad31a3399b85ae5a",
  "peaso/checks/gcp_workbench_head3_admission_20261020.py": "c974c7adbba841fa2b17a54e02fb677fe859f08eda0885c292b5be33da4b3a7d",
  "peaso/checks/gcp_workbench_head3_admission_cases_20261020.json": "8552db02f92dd14f23e0095dc21fb49d02667f27d09b7d68dd49b19c37edd17f",
  "peaso/checks/gcp_workbench_source_runtime_cases_20261020.json": "07a5d9705d018212894baf3b4d2254fa7d025ca151d14cb8776fcdfbae55dd0f",
  "peaso/checks/gcp_workbench_source_runtime_consumer_20261020.py": "c72dacd26ccba160b22a919d5d4885984f69bf3aebc5c2e08539cf7ddf751ad7",
  "tests/fixtures/gcp-cloudrun-job-image-observed-20261020.json": "51a9df2046d65f5f2c21067726b1ce19967e6080fee3508b9fe159bc06a0f1ec",
  "tests/fixtures/gcp-natural-evidence-golden.json": "2f9352c93dc0fabfea12914468ce2bc1f1b066c98da2410005a36dbff97a00c8"
}
''')


ADDED_EXTENSION_REVIEWS = json.loads(r'''
{
  "gcp.review.batch.selected_mounted_script_source_secret_indicators": {
    "admission_path": "docs/compliance-ledgers/native-extensions/gcp-batch-referenced-source-20261020.json",
    "admission_sha256": "a5006eb109ffb557ad13a19163a2974e6ad496534b20c75660b227ca5ff33e7b",
    "copy_catalog_sha256": "25e9dc3f7b68e8a827cd18b48ff1f4440f2846c13af9ce69642c4c1bb1a58a7b",
    "fixture_sha256": "b12e59c3d469cbd7ae89c829a41ee1848c0ef16a85216cd451a57705c5f3bf93",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_dataflow_batch_source_runtime_cases_20261020.json",
        "sha256": "3eaffaf2bc5124c9662acab4a09d39b0a5243ee29a3fb0b1fe47708b586d96a7"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "batch_selected_mounted_script_source",
      "module": "peaso.checks.gcp_dataflow_batch_source_runtime_consumer_20261020",
      "predicate_bindings": {},
      "predicate_qualname": "batch_source",
      "predicate_source_sha256": "c61f78ddb45d98a492862e475dd78915ac5832700dc617c98ad22d90a7cc6e2f",
      "source_qualname": "batch_source"
    },
    "source": "peaso/checks/gcp_dataflow_batch_source_runtime_consumer_20261020.py",
    "source_sha256": "c06098ba7318daf6519e0647e7f9e0acd49496790d1ee22f2f8a3f16d1136489"
  },
  "gcp.review.cloudrun_job.declared_image_secret_indicators": {
    "admission_path": "docs/compliance-ledgers/native-extensions/workload-content-20261020.json",
    "admission_sha256": "ae7a93c779418b5001d2752eefb896564aed39366e809bf6bd7382ac3800d14c",
    "copy_catalog_sha256": "5ff00e5776102217e044deb6799f8feb727ec711da99e51721022f520ac6a050",
    "fixture_sha256": "2b0c14f9d0fbad7182602775e03e80afec445479bb035b3f5f8b823b6d508b34",
    "fixture_sources": [
      {
        "path": "docs/gcp-review/recheck-20261020/gcp_cloudrun_job_image_runtime_20261020_receipt.json",
        "sha256": "dc63589448228096c334e087e84dd299cc49ac18a53941660a7a3ba8686eb8bc"
      },
      {
        "path": "tests/fixtures/gcp-cloudrun-job-image-observed-20261020.json",
        "sha256": "51a9df2046d65f5f2c21067726b1ce19967e6080fee3508b9fe159bc06a0f1ec"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "cloudrun_job_declared_image",
      "module": "peaso.checks.gcp_cloudrun_job_image_secret_review_20261020",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "predicate_source_sha256": "762b8f49bfca1c935537f8c8f624d964ccd78173aada34c2c7cc4908b3491f32",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_cloudrun_job_image_secret_review_20261020.py",
    "source_sha256": "6411b11c8d7926311ebd88da98890b42b56e0a63b936bf7568792c42c4cd3a22"
  },
  "gcp.review.dataflow.selected_package_referenced_source_secret_indicators": {
    "admission_path": "docs/compliance-ledgers/native-extensions/gcp-dataflow-referenced-source-20261020.json",
    "admission_sha256": "ce64873bb465e9d40ee19e3dfd74362f4aa923857eef48ebac4e6249d876e1c6",
    "copy_catalog_sha256": "091759813a181ef4c9ddadd0c0da504963cbcf312ad45fb90fc537d447920d35",
    "fixture_sha256": "0463afb2cdccd59e38810596a219317235d48f9d21f1ccda90a8ec571c37b269",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_dataflow_batch_source_runtime_cases_20261020.json",
        "sha256": "3eaffaf2bc5124c9662acab4a09d39b0a5243ee29a3fb0b1fe47708b586d96a7"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "dataflow_selected_package_source",
      "module": "peaso.checks.gcp_dataflow_batch_source_runtime_consumer_20261020",
      "predicate_bindings": {},
      "predicate_qualname": "dataflow_source",
      "predicate_source_sha256": "d5d608d2cbc74efcc9346ab226fb4f2f67f11050240f60c0eb39fc8b611b4edf",
      "source_qualname": "dataflow_source"
    },
    "source": "peaso/checks/gcp_dataflow_batch_source_runtime_consumer_20261020.py",
    "source_sha256": "c06098ba7318daf6519e0647e7f9e0acd49496790d1ee22f2f8a3f16d1136489"
  },
  "gcp.review.dataproc.selected_initialization_referenced_source_secret_indicators": {
    "admission_path": "docs/compliance-ledgers/native-extensions/gcp-dataproc-referenced-source-20261020.json",
    "admission_sha256": "9e907f55187170cd2dc9866f2c5070eb059a4063eaa557402c80344741fba913",
    "copy_catalog_sha256": "f1f295d44f59bd272161a2982aa11d3fe7ad9bfdc6fa50635a2ee1d72846f4be",
    "fixture_sha256": "8fa1850f48751a91173cb724cffc6019f37da07b3d07a68290e19fa524bdc9fd",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_dataproc_source_runtime_cases_20261020.json",
        "sha256": "ea6f724d024a80c76d50616bfe8be848088eced477b3b83b0b505768e2626bd5"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "dataproc_selected_initialization_source",
      "module": "peaso.checks.gcp_dataproc_referenced_source_secret_review_20261020",
      "predicate_bindings": {},
      "predicate_qualname": "initialization_source",
      "predicate_source_sha256": "1892e940ffbf22eb6225f001e076f7b7cb9e8cc50849a2a5f3917030d7de0b85",
      "source_qualname": "initialization_source"
    },
    "source": "peaso/checks/gcp_dataproc_referenced_source_secret_review_20261020.py",
    "source_sha256": "49ca4dda3b2abc80d8e59c75eecb3b432ea930ffa396494082ea9cfd7382423d"
  },
  "gcp.review.dataproc.selected_job_referenced_source_secret_indicators": {
    "admission_path": "docs/compliance-ledgers/native-extensions/gcp-dataproc-referenced-source-20261020.json",
    "admission_sha256": "5028735259f9d4ba14c77834ea3a039f32611a80a69ca2f153429485b7b036ef",
    "copy_catalog_sha256": "f1f295d44f59bd272161a2982aa11d3fe7ad9bfdc6fa50635a2ee1d72846f4be",
    "fixture_sha256": "3b468b64b074e353eb932524a8ccf441b2fc9d32db4735c5e672dd1cf70a465a",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_dataproc_source_runtime_cases_20261020.json",
        "sha256": "ea6f724d024a80c76d50616bfe8be848088eced477b3b83b0b505768e2626bd5"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "dataproc_selected_job_source",
      "module": "peaso.checks.gcp_dataproc_referenced_source_secret_review_20261020",
      "predicate_bindings": {},
      "predicate_qualname": "job_source",
      "predicate_source_sha256": "fe9e41d0218cbf6e86de887465ac5e6ab7630ee6ef6daa8e3468238380eb850a",
      "source_qualname": "job_source"
    },
    "source": "peaso/checks/gcp_dataproc_referenced_source_secret_review_20261020.py",
    "source_sha256": "49ca4dda3b2abc80d8e59c75eecb3b432ea930ffa396494082ea9cfd7382423d"
  },
  "gcp.review.workbench.auto_upgrade_schedule_declared": {
    "admission_path": "docs/compliance-ledgers/native-extensions/gcp-workbench-head3-20261020.json",
    "admission_sha256": "d5fcef4c8e22fa0147371959d7cc6811284daafe29df3d1eb98956a5359aed4c",
    "copy_catalog_sha256": "c20cfbb7c03bcda8e37c36e249c388dc2405a5b63bf59bc3143fac2b4b19ac0d",
    "fixture_sha256": "e8409707eda48777130afa1ef08b067e3009535def0e1bf7e573645e27ee1bb7",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_workbench_head3_admission_cases_20261020.json",
        "sha256": "8552db02f92dd14f23e0095dc21fb49d02667f27d09b7d68dd49b19c37edd17f"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "workbench_instance",
      "module": "peaso.checks.gcp_workbench_head3_admission_20261020",
      "predicate_bindings": {},
      "predicate_qualname": "auto_upgrade_schedule_declared",
      "predicate_source_sha256": "5d45c3d0a93909291b433855598398879ca3b21c91235ed5b78c4363093e79a4",
      "source_qualname": "auto_upgrade_schedule_declared"
    },
    "source": "peaso/checks/gcp_workbench_head3_admission_20261020.py",
    "source_sha256": "c974c7adbba841fa2b17a54e02fb677fe859f08eda0885c292b5be33da4b3a7d"
  },
  "gcp.review.workbench.file_download_disabled": {
    "admission_path": "docs/compliance-ledgers/native-extensions/gcp-workbench-head3-20261020.json",
    "admission_sha256": "dff75a0adebdde258b307fa030bef26f8377d873410f13c69c8bae465f5e3c65",
    "copy_catalog_sha256": "9bbfa1c52c0b0304623d77fb56d74d2d29d470d3ada392efd92acaf4436a1589",
    "fixture_sha256": "51ebde6162a51d6f8879c28842e0a1bdb8f005b7406b56d2140c13f465aab4f9",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_workbench_head3_admission_cases_20261020.json",
        "sha256": "8552db02f92dd14f23e0095dc21fb49d02667f27d09b7d68dd49b19c37edd17f"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "workbench_instance",
      "module": "peaso.checks.gcp_workbench_head3_admission_20261020",
      "predicate_bindings": {},
      "predicate_qualname": "file_download_disabled",
      "predicate_source_sha256": "ac2c7002518abb2fd5aa58d056b450c57e618455c66818fd40ed9e270637194d",
      "source_qualname": "file_download_disabled"
    },
    "source": "peaso/checks/gcp_workbench_head3_admission_20261020.py",
    "source_sha256": "c974c7adbba841fa2b17a54e02fb677fe859f08eda0885c292b5be33da4b3a7d"
  },
  "gcp.review.workbench.selected_referenced_source_secret_indicators_20261020": {
    "admission_path": "docs/compliance-ledgers/native-extensions/gcp-workbench-referenced-source-20261020.json",
    "admission_sha256": "c4cce6f19fff27c060dbbe03fc7b5abbefd47230d5a765aac052210ea30ca422",
    "copy_catalog_sha256": "564c6692b33b374adda24630725401669ee1d351014c09203992e09870e72515",
    "fixture_sha256": "b64453fa58e28b4b18f3410190b98f6cb7dce762b6f061e03a34d3a2ec7cfd72",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_workbench_source_runtime_cases_20261020.json",
        "sha256": "07a5d9705d018212894baf3b4d2254fa7d025ca151d14cb8776fcdfbae55dd0f"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "workbench_selected_referenced_source_20261020",
      "module": "peaso.checks.gcp_workbench_source_runtime_consumer_20261020",
      "predicate_bindings": {},
      "predicate_qualname": "referenced_source",
      "predicate_source_sha256": "4ec558290b75c52482c002e347f61da6b61effa0246cb63a3b118d8a75c4ca7c",
      "source_qualname": "referenced_source"
    },
    "source": "peaso/checks/gcp_workbench_source_runtime_consumer_20261020.py",
    "source_sha256": "c72dacd26ccba160b22a919d5d4885984f69bf3aebc5c2e08539cf7ddf751ad7"
  },
  "gcp.review.workbench.terminal_access_disabled": {
    "admission_path": "docs/compliance-ledgers/native-extensions/gcp-workbench-head3-20261020.json",
    "admission_sha256": "135273c6cb842cb1b746275b40d8be1c4364f80d9e8a8d64dcd46f439e0b8c9f",
    "copy_catalog_sha256": "72a745ff6ea95765669d1e5acbb1ee6aa317e8bcd315dac7d7b581bc1e863877",
    "fixture_sha256": "62c5f174227836a973ab8fab78df52ce1874a9b401cfecae64851a776c314a9b",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_workbench_head3_admission_cases_20261020.json",
        "sha256": "8552db02f92dd14f23e0095dc21fb49d02667f27d09b7d68dd49b19c37edd17f"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "workbench_instance",
      "module": "peaso.checks.gcp_workbench_head3_admission_20261020",
      "predicate_bindings": {},
      "predicate_qualname": "terminal_access_disabled",
      "predicate_source_sha256": "48326cbfeda5f2c4d042a124f29f4aa701820b174fae6193a0f9ad78ae40546c",
      "source_qualname": "terminal_access_disabled"
    },
    "source": "peaso/checks/gcp_workbench_head3_admission_20261020.py",
    "source_sha256": "c974c7adbba841fa2b17a54e02fb677fe859f08eda0885c292b5be33da4b3a7d"
  }
}
''')


CURRENT_FUNCTION_REVIEW = json.loads(r'''
{
  "admission_path": "docs/compliance-ledgers/native-extensions/gcp-20261019.json",
  "admission_sha256": "6dedaec790abdcb45bc8f86e3752a0b83eeceacdcc88926e0d599ea4fd7e3737",
  "copy_catalog_sha256": "373d825d5cfea29c036d3efa2bcf471b51fd97ab0c516a6c2a93cacd99a819fa",
  "fixture_sha256": "ea226ce089842ed66c1562d22fb0bf443a9112a2d68dcc04a19f365c2360d02d",
  "fixture_sources": [
    {
      "path": "peaso/checks/gcp_function_secret_partial_page_cases_20261020.json",
      "sha256": "d21c09b9e550934994c26efd3cda3738918308189254f2c9a1252d487f9bb9e7"
    }
  ],
  "reviewed_binding": {
    "closure": {},
    "kind": "function",
    "module": "peaso.checks.gcp_function_secret_partial_page_20261020",
    "predicate_bindings": {},
    "predicate_qualname": "evaluate",
    "predicate_source_sha256": "98efa2eb6559047701bae612ebe9297d56a547cb4bf5630c9931a62748ca2a42",
    "source_qualname": "evaluate"
  },
  "source": "peaso/checks/gcp_function_secret_partial_page_20261020.py",
  "source_sha256": "56a16e3da541ed741109f02c7324fa54d8c7f95704eb342cc140a7d8b8454093"
}
''')


CURRENT_NATIVE_EXAMPLES = json.loads(r'''
{
  "gcp.review.batch.selected_mounted_script_source_secret_indicators": [
    {
      "branch": "pass",
      "evidence_sha256": "1402c6bf488e7b1d534d97d20259327a885f7461a9916fd01f6c31b005d736ca",
      "expected": "Both offline detectors found no supported secret in the selected Batch mounted script source. Only captured current referenced source is covered; previously executed bytes were not established.",
      "status": "PASS"
    },
    {
      "branch": "fail",
      "evidence_sha256": "5b9652da6ee0628bcac28e17a0032e2b55f88ef23d4985515a1297376accea8b",
      "expected": "A likely secret was detected in the selected Batch mounted script source. Its value is hidden and was not validated. Only captured current referenced source is covered; previously executed bytes were not established.",
      "status": "FAIL"
    },
    {
      "branch": "unknown",
      "evidence_sha256": "2995a5e18ae50180f81c9ed6c493c385ab3decc922ce29e5f1ea1ba7ba27571f",
      "expected": "The selected Batch mounted script source could not be completely read, identity-bound and scanned. Only captured current referenced source is covered; previously executed bytes were not established.",
      "status": "UNKNOWN"
    }
  ],
  "gcp.review.bigquery.selected_routine_secret_indicators": [
    {
      "branch": "pass",
      "evidence_sha256": "8c8cf56e64c556752eb8f5286c322b056b18be39e3191c0fd91ca699cefb2f4b",
      "expected": "Both offline detectors found no supported secret in the selected routine definition. Only selected content observed during this read was inspected; unselected resources, history and credential validity were not checked.",
      "status": "PASS"
    },
    {
      "branch": "fail",
      "evidence_sha256": "698507a6f56fffcc4dd4f086eea838004ec4a8b893960243a9b869b4a7172e15",
      "expected": "A likely secret was detected in the selected routine definition. Only selected content observed during this read was inspected; unselected resources, history and credential validity were not checked.",
      "status": "FAIL"
    },
    {
      "branch": "unknown",
      "evidence_sha256": "5acd47f3ace5dec74b9b7906114a9b4077b21f40ac62520e84b2f5df912f2697",
      "expected": "Selected supported content could not be completely read and scanned with both offline detectors. Only selected content observed during this read was inspected; unselected resources, history and credential validity were not checked.",
      "status": "UNKNOWN"
    }
  ],
  "gcp.review.cloudrun_job.declared_image_secret_indicators": [
    {
      "branch": "pass",
      "evidence_sha256": "ccce608a17fb5e336ac3d8adb6ce53cc2122d1285c4d6de4f4580f078b24061d",
      "expected": "Both offline detectors found no supported secret in the immutable image declared by the selected Cloud Run Job container. Credentials and the executed image were not verified.",
      "status": "PASS"
    },
    {
      "branch": "fail",
      "evidence_sha256": "47258001ea85da4ffb4e7d330c5eb69cf470bec956a0359d94b9c4949ef806c0",
      "expected": "A likely secret was detected in the immutable image declared by the selected Cloud Run Job container. Its value is hidden; credentials and the executed image were not verified.",
      "status": "FAIL"
    },
    {
      "branch": "unknown",
      "evidence_sha256": "b2d6b008a93a420ac7bfca69a1e36d5c34535e512491773029f5103bdf862aeb",
      "expected": "Evidence for the selected Cloud Run Job’s declared image is incomplete or unbound. Secret absence and the executed image were not established; credentials were not validated.",
      "status": "UNKNOWN"
    }
  ],
  "gcp.review.cloudtasks.selected_payload_secret_indicators": [
    {
      "branch": "pass",
      "evidence_sha256": "0d3736176d7540c5c20b8868d8c649354111d49552f719eef2ae80ee585556b7",
      "expected": "Both offline detectors found no supported secret in the selected task body and headers. Only selected content observed during this read was inspected; unselected resources, history and credential validity were not checked.",
      "status": "PASS"
    },
    {
      "branch": "fail",
      "evidence_sha256": "0c816efd9a19b6ac969b84d4793888ad3291f8aac1d5cc1f1f67620e23b9e4f3",
      "expected": "A likely secret was detected in the selected task body and headers. Only selected content observed during this read was inspected; unselected resources, history and credential validity were not checked.",
      "status": "FAIL"
    },
    {
      "branch": "unknown",
      "evidence_sha256": "525a119297e70bdd8ad52ca126350b27c637e40028b012a40f2dc57cab79f136",
      "expected": "Selected supported content could not be completely read and scanned with both offline detectors. Only selected content observed during this read was inspected; unselected resources, history and credential validity were not checked.",
      "status": "UNKNOWN"
    }
  ],
  "gcp.review.dataflow.selected_package_referenced_source_secret_indicators": [
    {
      "branch": "pass",
      "evidence_sha256": "e9579f244236188b82ff62e2b27385ddc55686440375e63d594d5353d70fc8e3",
      "expected": "Both offline detectors found no supported secret in the selected Dataflow package source. Only captured current referenced source is covered; previously executed bytes were not established.",
      "status": "PASS"
    },
    {
      "branch": "fail",
      "evidence_sha256": "8b7ad5e592baa7b8c43b550b1cad06dc83e6174e04acaee0f827e100c1853efe",
      "expected": "A likely secret was detected in the selected Dataflow package source. Its value is hidden and was not validated. Only captured current referenced source is covered; previously executed bytes were not established.",
      "status": "FAIL"
    },
    {
      "branch": "unknown",
      "evidence_sha256": "af8a571e44b3c2a57cf69bd6fa7aecdc043671399fb954f5b2674ad346be77ea",
      "expected": "The selected Dataflow package source could not be completely read, identity-bound and scanned. Only captured current referenced source is covered; previously executed bytes were not established.",
      "status": "UNKNOWN"
    }
  ],
  "gcp.review.dataproc.selected_initialization_referenced_source_secret_indicators": [
    {
      "branch": "pass",
      "evidence_sha256": "92549acfcee722a44aecbddcfe892b32f140f71c6e42714d40cf675172cbff60",
      "expected": "Both offline detectors found no supported secret in the selected Dataproc referenced source. Only the captured referenced source is covered; original executed bytes were not established.",
      "status": "PASS"
    },
    {
      "branch": "fail",
      "evidence_sha256": "880057546ca25ccc8b1d84fb32484ca10241e5e73cefa3167808e00764edcceb",
      "expected": "A likely secret was detected in the selected Dataproc referenced source. Its value is hidden and was not validated. Only the captured referenced source is covered; original executed bytes were not established.",
      "status": "FAIL"
    },
    {
      "branch": "unknown",
      "evidence_sha256": "e8534e87096b03a7521d5a20de92d2d661d61354465bf15d8d411f8fd4c7687f",
      "expected": "The selected Dataproc referenced source could not be completely read and scanned. Only the captured referenced source is covered; original executed bytes were not established.",
      "status": "UNKNOWN"
    }
  ],
  "gcp.review.dataproc.selected_job_referenced_source_secret_indicators": [
    {
      "branch": "pass",
      "evidence_sha256": "92549acfcee722a44aecbddcfe892b32f140f71c6e42714d40cf675172cbff60",
      "expected": "Both offline detectors found no supported secret in the selected Dataproc referenced source. Only the captured referenced source is covered; original executed bytes were not established.",
      "status": "PASS"
    },
    {
      "branch": "fail",
      "evidence_sha256": "be37491ae306defaa8844ed08b14fdf00edc8eaf5b271b40c76bb4f14f3a7254",
      "expected": "A likely secret was detected in the selected Dataproc referenced source. Its value is hidden and was not validated. Only the captured referenced source is covered; original executed bytes were not established.",
      "status": "FAIL"
    },
    {
      "branch": "unknown",
      "evidence_sha256": "e8534e87096b03a7521d5a20de92d2d661d61354465bf15d8d411f8fd4c7687f",
      "expected": "The selected Dataproc referenced source could not be completely read and scanned. Only the captured referenced source is covered; original executed bytes were not established.",
      "status": "UNKNOWN"
    }
  ],
  "gcp.review.function.literal_environment_secret_indicators": [
    {
      "branch": "pass",
      "evidence_sha256": "618d1c5a4e2f8d8d08e75cedbddea6c9bbf02c6462487db7e1bde03c674949e5",
      "expected": "Both offline detectors finished without finding a supported secret in the returned runtime and build environment values. Values remain hidden and credential validity is not tested.",
      "status": "PASS"
    },
    {
      "branch": "fail",
      "evidence_sha256": "98a13257472237504d7686746caba780ec6368a83472bd81a9dae190e974f373",
      "expected": "A likely secret was detected in the function’s literal environment values. Values remain hidden and credential validity is not tested.",
      "status": "FAIL"
    },
    {
      "branch": "unknown",
      "evidence_sha256": "b2f8755471c27ab9d9a0f6002384e2a082fab61fd9abe013dad312002ae0fea9",
      "expected": "The selected literal environment values could not be completely scanned. Values remain hidden and credential validity is not tested.",
      "status": "UNKNOWN"
    }
  ],
  "gcp.review.workbench.auto_upgrade_schedule_declared": [
    {
      "branch": "pass",
      "evidence_sha256": "8be227a93013298d4a672a75bba06115743cee1081ffd11b6e77ba79f3e7861f",
      "expected": "An automatic upgrade schedule is configured for this Workbench instance. Upgrade execution and patch status were not established.",
      "status": "PASS"
    },
    {
      "branch": "fail",
      "evidence_sha256": "3c4333cec20a0c2b573f2c87a0d58fbde31fa4f5b9b066b457efbfb03c4ecbce",
      "expected": "This Workbench instance has no automatic upgrade schedule configured. Upgrade execution and patch status were not established.",
      "status": "FAIL"
    },
    {
      "branch": "unknown",
      "evidence_sha256": "a24217af51109a5ed45e938e1beaab52aa3c8c59e4f80307f9ec37aaf23323f5",
      "expected": "The Workbench setting could not be established from complete native configuration. Upgrade execution and patch status were not established.",
      "status": "UNKNOWN"
    }
  ],
  "gcp.review.workbench.file_download_disabled": [
    {
      "branch": "pass",
      "evidence_sha256": "f74caa1dd99d4542d6042b0ca692d42d41377e3a315dcd1957d634d6e96cfe45",
      "expected": "JupyterLab file downloads are disabled in Workbench settings. Other transfer paths and effective DLP enforcement are not established.",
      "status": "PASS"
    },
    {
      "branch": "fail",
      "evidence_sha256": "dffc24ce527334a0202872403aac1bc9da0cfe77cee2e9de38347d3c945e4a75",
      "expected": "JupyterLab file downloads are enabled in Workbench settings. Other transfer paths and effective DLP enforcement are not established.",
      "status": "FAIL"
    },
    {
      "branch": "unknown",
      "evidence_sha256": "a24217af51109a5ed45e938e1beaab52aa3c8c59e4f80307f9ec37aaf23323f5",
      "expected": "The Workbench setting could not be established from complete native configuration. Other transfer paths and effective DLP enforcement are not established.",
      "status": "UNKNOWN"
    }
  ],
  "gcp.review.workbench.selected_referenced_source_secret_indicators_20261020": [
    {
      "branch": "pass",
      "evidence_sha256": "45607201e46a743e8c9298847a98ae9824c24d6913823df6cb14ed0434211615",
      "expected": "Both offline detectors found no supported secret in the selected Workbench referenced source. Only the captured current referenced source is covered; cached or previously executed bytes were not established.",
      "status": "PASS"
    },
    {
      "branch": "fail",
      "evidence_sha256": "f557ee28b5a304135beb7e8309e5824f2da15e33581c8e35d640fd4b6451a3a3",
      "expected": "A likely secret was detected in the selected Workbench referenced source. Its value is hidden and was not validated. Only the captured current referenced source is covered; cached or previously executed bytes were not established.",
      "status": "FAIL"
    },
    {
      "branch": "unknown",
      "evidence_sha256": "e8534e87096b03a7521d5a20de92d2d661d61354465bf15d8d411f8fd4c7687f",
      "expected": "The selected Workbench referenced source could not be completely read, identity-bound and scanned. Only the captured current referenced source is covered; cached or previously executed bytes were not established.",
      "status": "UNKNOWN"
    }
  ],
  "gcp.review.workbench.terminal_access_disabled": [
    {
      "branch": "pass",
      "evidence_sha256": "c3c73b39f49e6a22320bbee9cb3c6977081d2951746464dfde4cdb327f18e730",
      "expected": "The notebook terminal is disabled in Workbench settings. Kernel execution and other shell paths are outside this check.",
      "status": "PASS"
    },
    {
      "branch": "fail",
      "evidence_sha256": "e4816c06cfa17e3498220835f27dbdf4b549bd5d148231b84224fa7f3e0b76a3",
      "expected": "The notebook terminal is enabled in Workbench settings. Kernel execution and other shell paths are outside this check.",
      "status": "FAIL"
    },
    {
      "branch": "unknown",
      "evidence_sha256": "a24217af51109a5ed45e938e1beaab52aa3c8c59e4f80307f9ec37aaf23323f5",
      "expected": "The Workbench setting could not be established from complete native configuration. Kernel execution and other shell paths are outside this check.",
      "status": "UNKNOWN"
    }
  ]
}
''')


GOLDEN_PROSE_SUCCESSORS = json.loads(r'''
{
  "gcp.claude.bigquery_dataset.no_gmail_access|fail": {
    "expected": "The recorded evidence does not establish dataset ACL entries naming gmail.com accounts. Personal email or group ACLs may extend dataset sharing beyond approved owners; effective data access remains separate.",
    "historical_row_sha256": "6031cff37da81b35b718655c4a4222a1815f4066069e693443bc258b9ca81a05"
  },
  "gcp.claude.bigquery_dataset.no_googlegroups_access|fail": {
    "expected": "The recorded evidence does not establish dataset ACL entries naming googlegroups.com groups. Personal email or group ACLs may extend dataset sharing beyond approved owners; effective data access remains separate.",
    "historical_row_sha256": "584fbe3629443df423ae71620cfd531a3a79f103616d38230db9efb34e3c1f93"
  },
  "gcp.reviewed.network.flow_logs|fail": {
    "expected": "VPC flow logging is disabled. Traffic logging supports incident investigation; this configuration does not prove logs arrive or are retained.",
    "historical_row_sha256": "766e8c71d15cdb3e2403f83bb9cc3b9c4491ba271cb6bd4225264bcaf0ff21a2"
  },
  "gcp_cloud_armor_waf_enabled|fail": {
    "expected": "Cloud Armor policy p1 was assessed; the deciding rule settings were not stored. Checks the attached external-backend policy for a supported preconfigured WAF deny rule, including preview and earlier bypass rules. Public reachability and traffic blocking are not tested.",
    "historical_row_sha256": "00c7c9b2d05b1d4503c101139ec72512e3bfec5822c3b91e870e677704b6aaae"
  },
  "gcp_cloud_armor_waf_enabled|malformed": {
    "expected": "The recorded backend association or policy rules do not establish an enforced preconfigured WAF rule. Checks the attached external-backend policy for a supported preconfigured WAF deny rule, including preview and earlier bypass rules. Public reachability and traffic blocking are not tested.",
    "historical_row_sha256": "d83e36aa2f125acd0fcd714bd581800c5eb7b1fdf9c1f50290fccfc7ba8f0195"
  },
  "gcp_cloud_armor_waf_enabled|pass": {
    "expected": "The recorded backend association or policy rules do not establish an enforced preconfigured WAF rule. Checks the attached external-backend policy for a supported preconfigured WAF deny rule, including preview and earlier bypass rules. Public reachability and traffic blocking are not tested.",
    "historical_row_sha256": "c47f8d93a186839e517c937f50e9c3cd1dff9330a5f602994075bb9debf9ea53"
  },
  "gcp_cloud_armor_waf_enabled|unknown": {
    "expected": "The recorded backend association or policy rules do not establish an enforced preconfigured WAF rule. Checks the attached external-backend policy for a supported preconfigured WAF deny rule, including preview and earlier bypass rules. Public reachability and traffic blocking are not tested.",
    "historical_row_sha256": "f8c4bd8ec5981037cde1fd391b9f4f5606dc1040940bdd918e3a35f0ceb85d61"
  }
}
''')


WORKBENCH_CCC_ADDITIONS = json.loads(r'''
{
  "gcp.review.workbench.public_ip_disabled": "31ae388dce669a1e04260b89d4f27eeffa1d93f76963f06efa0c44bcd4873f33",
  "gcp.review.workbench.root_access_disabled": "7c377f55c5ad09e58c62f9037b69f82d39d0d1e623545713ac2d67c74cc1ecb5"
}
''')


OWNER_RUNTIME_RECEIPTS = json.loads(r'''
{
  "gcp.review.batch.selected_mounted_script_source_secret_indicators": {
    "path": "peaso/checks/gcp_dataflow_batch_source_runtime_admission_20261020.json",
    "sha256": "8277fadb5c0f67131c47755e10ac06f48454e40730088aba09234b92dd3451a1"
  },
  "gcp.review.cloudrun_job.declared_image_secret_indicators": {
    "path": "docs/gcp-review/recheck-20261020/gcp_cloudrun_job_image_runtime_20261020_receipt.json",
    "sha256": "dc63589448228096c334e087e84dd299cc49ac18a53941660a7a3ba8686eb8bc"
  },
  "gcp.review.dataflow.selected_package_referenced_source_secret_indicators": {
    "path": "peaso/checks/gcp_dataflow_batch_source_runtime_admission_20261020.json",
    "sha256": "8277fadb5c0f67131c47755e10ac06f48454e40730088aba09234b92dd3451a1"
  },
  "gcp.review.dataproc.selected_initialization_referenced_source_secret_indicators": {
    "path": "peaso/checks/gcp_dataproc_source_runtime_admission_20261020.json",
    "sha256": "7c8989576f2068d6868b6e51bba8e8d265aaa33b70d63fb0e84b6ab8e3dd8e0c"
  },
  "gcp.review.dataproc.selected_job_referenced_source_secret_indicators": {
    "path": "peaso/checks/gcp_dataproc_source_runtime_admission_20261020.json",
    "sha256": "7c8989576f2068d6868b6e51bba8e8d265aaa33b70d63fb0e84b6ab8e3dd8e0c"
  },
  "gcp.review.workbench.auto_upgrade_schedule_declared": {
    "path": "peaso/checks/gcp_workbench_head3_admission_20261020.json",
    "sha256": "2aa8483b6ba2583ab80a261c34e15cacdcf31e79e995210f180e4debd6a65179"
  },
  "gcp.review.workbench.file_download_disabled": {
    "path": "peaso/checks/gcp_workbench_head3_admission_20261020.json",
    "sha256": "2aa8483b6ba2583ab80a261c34e15cacdcf31e79e995210f180e4debd6a65179"
  },
  "gcp.review.workbench.selected_referenced_source_secret_indicators_20261020": {
    "path": "peaso/checks/gcp_workbench_source_runtime_admission_20261020.json",
    "sha256": "bfb1d6364bef185bd37ffb9f6c07dabb807b5ed29fb56760c52d68ba7a0e30bf"
  },
  "gcp.review.workbench.terminal_access_disabled": {
    "path": "peaso/checks/gcp_workbench_head3_admission_20261020.json",
    "sha256": "2aa8483b6ba2583ab80a261c34e15cacdcf31e79e995210f180e4debd6a65179"
  }
}
''')
