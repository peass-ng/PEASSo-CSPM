"""Conserve pinned source dispositions and their current individual native receipts.

This is source accounting, not a substitute for the native response matrices it
references. No historical source, fixture, predicate or review is rewritten.
"""
import csv
import hashlib
import inspect
import importlib
from copy import deepcopy

import pytest
import json
from collections import Counter
from pathlib import Path
import socket

from peaso.checks import CHECKS
from peaso.checks.native_only import exclusions
from tests.test_gcp_workbench_current_acceptance_20261020 import (
    JOB_ID, THEMATIC_IDS, current_thematic_admissions, checked_thematic_reference)

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / 'docs/gcp-review/recheck-20261020/current-source-reconciliation-20261020.json'
REPORT_SHA256 = '6e6fbdf6acff57100cfe468b851e075b967d0884c7da3ba0ed6faf866f912535'
CURRENT_RECEIPT = ROOT / 'docs/check-review/gcp-current-ledger-source-conservation-20261020.json'
CURRENT_RECEIPT_SHA256 = '6da9f2ca0ed2c588b0981edc54596658e89e53047eeeddfb8a6e27cb6a0a53e4'
FUNCTION_ID = 'gcp.review.function.literal_environment_secret_indicators'


# Retained 2026-10-20 records keep the bytes they reconciled.  Records that
# later reviewed edits changed are bound here: the retained digest must be the
# recorded ``before_sha256`` and the file on disk the current ``after_sha256``.
RECORD_SUCCESSORS = {
    'docs/check-review/gcp-function-current-ledger-erratum-20261020.json': {
        'before_sha256': 'a0e89befb7eb83f29b37c23f5409e52c0e1e6a10e786314fa50364bae660967a',
        'after_sha256': 'af88bde5ae184d1ecfaeaf016292e7aa59306dc4a3f45da859143a1ef09665ee',
    },
    'docs/check-review/gcp-current-ledger-source-conservation-20261020.json': {
        'before_sha256': '4359bc9fd55fdb429ff933c9470bd7d7eb8df6904d6a59a2167049c66d6a2879',
        'after_sha256': '6da9f2ca0ed2c588b0981edc54596658e89e53047eeeddfb8a6e27cb6a0a53e4',
    },
    'docs/check-review/dataproc-tde-current-acceptance-20261020.json': {
        'before_sha256': 'a30937e37b867ed860c12308487ec6be5284be6de214ab1b3017aa9cea8d6066',
        'after_sha256': 'd1514c76d5d1ad08ae5828930ef81fe6badd39b6e26dc0ca3ea6add202ef2202',
    },
    'docs/gcp-review/compute-network-review.json': {
        'before_sha256': '563b2dda950e28eb8d2eef684f12b36fa747ae22ef4afe8bd419af86d581ee8a',
        'after_sha256': 'eba7335be1c99ca0bae5722c5d355c30b1a85c6393479cc5dcb942686b398197',
    },
    'docs/gcp-review/recheck-20261020/compute-second-batch-review.json': {
        'before_sha256': '8698e17079527e53e3125be1543775dcec7c2921b3c929ac23bcf628e31bc5d3',
        'after_sha256': '9eee6fb0c56a204a8020dd86c9e0a8fe05ba51daa1e7bc06d72793eebeabbc8d',
    },
    'docs/gcp-review/recheck-20261020/final-services-fixes.json': {
        'before_sha256': '0d15ed1d459102d377fe51f8a62799ce752ca07b03b0d3a6a25b65b9b675b8f1',
        'after_sha256': '42490684afc028559790e188a47db8f6c4b3e7bbfcdff6ae4ecfc6f1e3acb459',
    },
    'docs/gcp-review/recheck-20261020/final-services-review.json': {
        'before_sha256': '68587d9f932c0cb49c964755d393e425596631fe510eb5e355800e8fb0cbc701',
        'after_sha256': 'e4f4fee07e5df95167b3795fba393af12fb51af2de3ddd01222bee9cd0565aa0',
    },
    'docs/gcp-review/recheck-20261020/identity_data-batch-review.json': {
        'before_sha256': '5191be52753a9b572802fac13955c17aec2b8f3bd67c6c7dc8e9bba28a91c51d',
        'after_sha256': 'b0395dd5059df02e2f09bf2da528ba5fc841a634958293f4cae16a265f81531c',
    },
    'docs/gcp-review/recheck-20261020/logging-batch-review.json': {
        'before_sha256': '5d1e119c7e716cb0459c9ccf4bc8ade3c8f81a4784e65e8f7baea2e99841d99a',
        'after_sha256': 'bddfaa7b1ad5882751f2f5794ce0a40d530c059874f1a32b605583ca5f8a9f38',
    },
    'docs/gcp-review/recheck-20261020/metadata-final-batch-review.json': {
        'before_sha256': '9101fb29c3023c95c42d209efe5b354a9f6e5241d6a8ee0e9ec12f11cfba7a83',
        'after_sha256': '4f2cda27db34e498c8a874cd6b7bd88c95edd5edc553bf89136ec980f5edf5ca',
    },
    'docs/gcp-review/recheck-20261020/native57-iam-kms-review.json': {
        'before_sha256': 'b5817d6a6a088399405695a89164738da50f6415293bd23090e2e12057523a2d',
        'after_sha256': '119b0b830e0541bce71666312e2b3b3f57a117127db1995582df9e4a7e56d98a',
    },
    'docs/gcp-review/recheck-20261020/prior-bounded-recheck.json': {
        'before_sha256': '7f153c988ae8d67bf29957c0664e671fc5b2d3e233533c8257c48bf0389f8401',
        'after_sha256': '9853680c83a5e49b95cdd4fbae041bddb5c5d4d714ddf16cd13da61b3f771a36',
    },
    'docs/gcp-review/recheck-20261020/secret-surface-audit.json': {
        'before_sha256': 'dd3819aafb4e0d45012496db1d3f8c0280f4771f3ac71ba0f165ac576c8f22e9',
        'after_sha256': 'fd1f073f57e6b0f37ee104a3f5ee03b364e56ccaec521b40449e58ae747e2e29',
    },
}


# Predicates that later reviewed commits changed after this reconciliation was
# written.  The retained report row and checks.csv keep the reconciled body
# (``before_body_sha256``); the current evaluator must be exactly the reviewed
# successor.  ``commit`` names the reviewed edit:
#   75087001  dataset_domain also reads BigQuery's ``domain`` principal field
#   45112721  default-network firewall/GKE scoping, Cloud Build log and image
#             stream secret evaluators
#   120406f2  unused service account/key activity moved to peaso.unused_iam_gcp
#   de012c38  confirmed GCP secret findings survive incomplete content scans
PREDICATE_SUCCESSORS = {
    'gcp.claude.bigquery_dataset.no_gmail_access': {'before_body_sha256': 'a135590e7828784d5440fb1938f83f5c5b13a6f3362010edcbfc5a8a11d07e29',
        'after_qualname': 'peaso.checks.claude_gcp_k8s_iam.dataset_domain.<locals>.evaluate', 'after_path': 'peaso/checks/claude_gcp_k8s_iam.py',
        'after_body_sha256': '885a1755b25320108e0743887be84f648a4b1128ae2b9b3428fe2a667584e3a0', 'commit': '75087001'},
    'gcp.claude.bigquery_dataset.no_googlegroups_access': {'before_body_sha256': 'a135590e7828784d5440fb1938f83f5c5b13a6f3362010edcbfc5a8a11d07e29',
        'after_qualname': 'peaso.checks.claude_gcp_k8s_iam.dataset_domain.<locals>.evaluate', 'after_path': 'peaso/checks/claude_gcp_k8s_iam.py',
        'after_body_sha256': '885a1755b25320108e0743887be84f648a4b1128ae2b9b3428fe2a667584e3a0', 'commit': '75087001'},
    'gcp.claude.firewall.default_rules_not_open': {'before_body_sha256': 'e01687972dd278223a925ce42f5e8588f7570d266891471a5ae55064f51f9740',
        'after_qualname': 'peaso.checks.claude_gcp_k8s_compute.firewall_default_rules', 'after_path': 'peaso/checks/claude_gcp_k8s_compute.py',
        'after_body_sha256': 'ac001b142f7db7b48bde4a0b6799d4477a55d4fe6f5e43659016a5e6a241a85f', 'commit': '45112721'},
    'gcp.claude.gke.no_default_network': {'before_body_sha256': '61979b1bf6c4991d90ec064284727c92ce96cec356e641fec28ab0de770b7900',
        'after_qualname': 'peaso.checks.claude_gcp_k8s_iam.gke_default_network', 'after_path': 'peaso/checks/claude_gcp_k8s_iam.py',
        'after_body_sha256': '3b57693d9d94717a39029959dae5f2a379fa205d95ae96f2048d455e0c2e0bc2', 'commit': '45112721'},
    'gcp.claude.service_account.recently_used': {'before_body_sha256': '304dc0b8914b44e35dda5fc732cfc734fd84c8b3bde8b385edf608b50704b67b',
        'after_qualname': 'peaso.unused_iam_gcp.evaluate_account', 'after_path': 'peaso/unused_iam_gcp.py',
        'after_body_sha256': 'aa25293eba7baa8bf9270f11154482ec46eaea64096a8c4e4ff9d18f5ae70b6e', 'commit': '120406f2'},
    'gcp.claude.service_account_key.recently_used': {'before_body_sha256': 'afb33386dbd5e3a1deade74acec5cf58f70c102fe2494f34867a15f905106c8c',
        'after_qualname': 'peaso.unused_iam_gcp.evaluate_key', 'after_path': 'peaso/unused_iam_gcp.py',
        'after_body_sha256': '21517e6bbe347b7ccd35366fae60c9ed1701e13b412381f26dc97bda5b2eaaa9', 'commit': '120406f2'},
    'gcp.review.artifact_image.content_secret_indicators': {'before_body_sha256': '3e7924e4bccdd5aa1ea83b3e9254deffce20b7322d528e640ba0afafd9c45866',
        'after_qualname': 'peaso.checks.gcp_image_stream_review_20261021.evaluate', 'after_path': 'peaso/checks/gcp_image_stream_review_20261021.py',
        'after_body_sha256': 'e589f341effbcb5c6677df442174e26bef216314ea56755a0d9b93188d116d9d', 'commit': '45112721'},
    'gcp.review.artifactregistry.selected_file_secret_indicators': {'before_body_sha256': '6f4b7c50441776d28a7a4e06f8610bf3b79ea0c9984e11cc49326d7479e5d3a6',
        'after_qualname': 'peaso.checks.gcp_artifact_file_secret_review_20261019.evaluate', 'after_path': 'peaso/checks/gcp_artifact_file_secret_review_20261019.py',
        'after_body_sha256': 'c41d3d5751c7dd70a0fb9e7d0c2f515570f2348cb506c1651f62436731d31c20', 'commit': 'de012c38'},
    'gcp.review.cloudbuild.stored_log_secret_indicators': {'before_body_sha256': '7a4d78e54b01344cae0539f479c8dc841be8b07e5a53fc171499ad080cb9390c',
        'after_qualname': 'peaso.checks.gcp_cloudbuild_log_secret_review_20261019.evaluate', 'after_path': 'peaso/checks/gcp_cloudbuild_log_secret_review_20261019.py',
        'after_body_sha256': '4259fc418c00fcf3818527e8b5837127bab64e00752618b4154e5af67ae64237', 'commit': '45112721'},
    'gcp.review.composer.dag_source_secret_indicators': {'before_body_sha256': 'f85e0b7feb17116f32cb5f8f3b030c549e00fbbcd6e8c2635da5c52957ff7acf',
        'after_qualname': 'peaso.checks.gcp_composer_source_secret_review_20261019.evaluate', 'after_path': 'peaso/checks/gcp_composer_source_secret_review_20261019.py',
        'after_body_sha256': 'cf50624ef905049ed067559a1f38faec8322215d55393c539ac68f5a7b20243e', 'commit': 'de012c38'},
    'gcp.review.sourcerepo.selected_file_secret_indicators': {'before_body_sha256': '9efdc7277d249274984369dfd0db9cf279fb154c75b31ae00119dbce484d91a5',
        'after_qualname': 'peaso.checks.gcp_sourcerepo_secret_review_20261019.evaluate', 'after_path': 'peaso/checks/gcp_sourcerepo_secret_review_20261019.py',
        'after_body_sha256': '8e508714233b7d84fc62d9f4a18c3c3f53271aa338d837601e836634e4629bf6', 'commit': 'de012c38'},
    'gcp.review.storage.selected_archive_secret_indicators': {'before_body_sha256': '67ae5ee1485f86d7a817c9ad180dcb5cc1254832d92af29bec618a6f8bff71c1',
        'after_qualname': 'peaso.checks.gcp_selected_archive_secret_review_20261019.evaluate', 'after_path': 'peaso/checks/gcp_selected_archive_secret_review_20261019.py',
        'after_body_sha256': 'd50d76c3d00fc766162a8aa4dd92f20cc0fcd34d0b3046e3c09f3da25d1fcc62', 'commit': 'de012c38'},
}


def record_matches(path, recorded, current):
    successor = RECORD_SUCCESSORS.get(path)
    if successor is None:
        return current == recorded
    return current == successor['after_sha256'] and recorded in (successor['before_sha256'], successor['after_sha256'])


def _checked_json(reference):
    raw = (ROOT / reference['path']).read_bytes()
    assert record_matches(reference['path'], reference['sha256'], hashlib.sha256(raw).hexdigest()), reference['path']
    return json.loads(raw)


def current_conservation():
    raw = CURRENT_RECEIPT.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == CURRENT_RECEIPT_SHA256
    return json.loads(raw)


def _validate_current_function(erratum, check):
    assert erratum['check_id'] == check.id == FUNCTION_ID
    predicate = erratum['predicate']
    fn = inspect.unwrap(check.evaluate)
    assert predicate['qualname'] == fn.__module__ + '.' + fn.__qualname__
    assert predicate['body_sha256'] == hashlib.sha256(inspect.getsource(fn).encode()).hexdigest()
    assert predicate['file_sha256'] == hashlib.sha256((ROOT / predicate['path']).read_bytes()).hexdigest()
    _checked_json(erratum['integration_receipt'])
    _checked_json(erratum['current_public_dtos'])
    return fn



def _bound_functions(value, seen=None):
    """Follow actual wrappers/closed dispatch maps without executing a predicate."""
    seen = set() if seen is None else seen
    if inspect.isfunction(value):
        value = inspect.unwrap(value)
    if id(value) in seen:
        return
    seen.add(id(value))
    if inspect.isfunction(value):
        yield value
        for part in (*(value.__defaults__ or ()), *(value.__kwdefaults__ or {}).values()):
            yield from _bound_functions(part, seen)
        for cell in value.__closure__ or ():
            try:
                part = cell.cell_contents
            except ValueError:
                continue
            yield from _bound_functions(part, seen)
    elif isinstance(value, dict):
        for part in value.values():
            yield from _bound_functions(part, seen)
    elif isinstance(value, (list, tuple)):
        for part in value:
            yield from _bound_functions(part, seen)


def test_pinned_gcp_sources_current_native_bindings_and_individual_receipts_conserve(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('source accounting must not access network or cloud authentication')

    for name in ('socket', 'create_connection', 'getaddrinfo'):
        monkeypatch.setattr(socket, name, forbidden)
    monkeypatch.setenv('AWS_EC2_METADATA_DISABLED', 'true')

    assert hashlib.sha256(REPORT.read_bytes()).hexdigest() == REPORT_SHA256
    report = json.loads(REPORT.read_text())
    inventory_path = ROOT / report['inputs']['pinned_inventory']['path']
    assert hashlib.sha256(inventory_path.read_bytes()).hexdigest() == report['inputs']['pinned_inventory']['sha256']
    inventory = json.loads(inventory_path.read_text())
    historical = {row['check_id']: row for row in inventory['checks']}
    upstream = {row['id']: row for row in report['upstream_records']}
    assert len(upstream) == len(report['upstream_records']) == len(historical) == 766
    assert upstream.keys() == historical.keys()
    assert Counter(row['status'] for row in upstream.values()) == {
        'mapped-active': 692, 'mapped-only-archived': 24, 'rejected': 50,
    } == report['counts']['upstream_dispositions']
    assert Counter(row['repository'] for row in upstream.values()) == report['counts']['by_repository']
    queries = [query for source in inventory['sources'] for query in source.get('query_inventory', [])]
    assert len(queries) == report['counts']['independent_query_definitions'] == 202
    assert all(query['control_ids'] and set(query['control_ids']) <= upstream.keys() for query in queries)
    assert report['pinned_sources'] == [
        {key: source[key] for key in ('repository', 'revision', 'corpus_sha256')}
        | {'file_count': len(source['files'])} for source in inventory['sources']
    ]

    current_native = {check.id: check for check in CHECKS if check.provider == 'gcp'}
    rows = {row['id']: row for row in report['native_records']}
    # Preserve all exact529 historical rows; each of the six later IDs has
    # its own source-bound acceptance rather than extending the old report.
    conservation = current_conservation()
    successor_receipts = {cid: r['path'] for cid, r in conservation['prior_admissions'].items()}
    successor_receipts.update({cid: r['receipt'] for cid, r in conservation['head_admissions'].items()})
    thematic = current_thematic_admissions()
    job_reference = thematic['thematic_admissions'][JOB_ID]
    successor_receipts[JOB_ID] = job_reference['path']
    # The reviewed 2026-10-22 native successor cohort admits later IDs with its
    # own branch evidence; they extend neither this report nor its conservation.
    cohort = json.loads((ROOT / 'docs/evidence-reviews/gcp-current-native-successor-20261022.json').read_text())
    cohort_ids = cohort['added'].keys()
    assert not cohort_ids & (rows.keys() | successor_receipts.keys())
    successor_ids = successor_receipts.keys() | cohort_ids
    assert current_native.keys() - rows.keys() == successor_ids
    assert len(current_native) == 536 + len(cohort_ids)
    assert len(current_native.keys() - exclusions().keys()) == 429 + len(cohort_ids - exclusions().keys())
    native = {cid: check for cid, check in current_native.items() if cid in rows}
    archived = native.keys() & exclusions().keys()
    assert len(native) == len(rows) == len(report['native_records']) == 529
    assert native.keys() == rows.keys()
    assert len(archived) == report['counts']['excluded_native_ids'] == 107
    assert len(native.keys() - archived) == report['counts']['active_native_ids'] == 422
    with (ROOT / 'docs/check-review/checks.csv').open() as handle:
        current_master = {row['check_id']: row for row in csv.DictReader(handle) if row['provider'] == 'gcp'}
    # checks.csv is byte-frozen; the successor cohort lives in its own record.
    assert current_master.keys() == current_native.keys() - cohort_ids
    for cid, path in successor_receipts.items():
        assert current_master[cid]['current_goal_receipt'] == path
        receipt = json.loads((ROOT / path).read_text())
        if cid in conservation['head_admissions']:
            registered, = [r for r in receipt['registered_predicates'] if r['id'] == cid]
            individual = {'id': cid, 'check_id': cid, 'kind': registered['kind'], 'active': True,
                          'predicate': conservation['head_admissions'][cid]['predicate']}
            assert registered['body_sha256'] == individual['predicate']['body_sha256']
        else:
            _checked_json(job_reference if cid == JOB_ID else conservation['prior_admissions'][cid])
            individual, = receipt['checks']
        assert individual['id'] == individual['check_id'] == cid
        assert individual['kind'] == current_native[cid].kind and individual['active'] is True
        function = inspect.unwrap(current_native[cid].evaluate)
        assert individual['predicate']['qualname'] == function.__module__ + '.' + function.__qualname__
        assert individual['predicate']['body_sha256'] == hashlib.sha256(inspect.getsource(function).encode()).hexdigest()
    master = {cid: row for cid, row in current_master.items() if cid in rows}
    assert master.keys() == native.keys()
    documents = {}
    for path, receipt in report['native_receipts'].items():
        raw = (ROOT / path).read_bytes()
        assert record_matches(path, receipt['sha256'], hashlib.sha256(raw).hexdigest()), path
        documents[path] = json.loads(raw)

    predicate_drift = []
    for cid, row in rows.items():
        assert row['active'] == (cid not in archived) == (master[cid]['active'].lower() == 'true')
        assert row['kind'] == native[cid].kind
        assert row['current_receipt'] == master[cid]['current_goal_receipt']
        assert row['current_review_status'] == master[cid]['current_goal_status']
        assert row['limits'] and row['receipt_basis']
        record = documents[row['individual_receipt']]
        for part in row['individual_record_path']:
            record = record[part]
        assert isinstance(record, dict) and (record.get('id') == cid or record.get('check_id') == cid
                                             or row['individual_record_path'][-1] == cid), cid
        assert row['directed_test_modules'], cid
        assert all((ROOT / path).is_file() for path in row['directed_test_modules'])
        predicate = row['predicate']
        if cid == FUNCTION_ID:
            erratum = _checked_json(conservation['current_predicate_errata'][cid])
            _validate_current_function(erratum, native[cid])
            assert erratum['historical_predicate'] == {k: predicate[k] for k in ('path', 'qualname', 'body_sha256')}
            module, _, attribute = predicate['qualname'].rpartition('.')
            old_function = getattr(importlib.import_module(module), attribute)
            bound = [old_function]
        else:
            successor = PREDICATE_SUCCESSORS.get(cid)
            if successor is not None:
                # A reviewed later edit replaced this predicate.  The retained
                # row keeps the reconciled body; the successor binds the
                # current body exactly.
                assert successor['before_body_sha256'] == predicate['body_sha256'], cid
                target = successor['after_qualname']
            else:
                target = predicate['qualname']
            bound = [fn for fn in _bound_functions(native[cid].evaluate)
                 if f'{fn.__module__}.{fn.__qualname__}' == target]
        if len(bound) != 1:
            current = inspect.unwrap(native[cid].evaluate)
            predicate_drift.append((cid, predicate['qualname'], predicate['body_sha256'],
                                    f'{current.__module__}.{current.__qualname__}',
                                    str(Path(inspect.getsourcefile(current)).relative_to(ROOT)),
                                    hashlib.sha256(inspect.getsource(current).encode()).hexdigest()))
            continue
        actual = bound[0]
        path = str(Path(inspect.getsourcefile(actual)).relative_to(ROOT))
        body = hashlib.sha256(inspect.getsource(actual).encode()).hexdigest()
        assert predicate['body_sha256'] == master[cid]['current_bound_predicate_sha256']
        if cid in PREDICATE_SUCCESSORS:
            assert (path, body) == (successor['after_path'], successor['after_body_sha256']), cid
        else:
            assert path == predicate['path'], cid
            if body != predicate['body_sha256']:
                predicate_drift.append((cid, predicate['qualname'], predicate['body_sha256'], target, path, body))
        assert predicate['qualname'] == master[cid]['bound_predicate_qualname']
        assert row['upstream_ids'] == sorted(sid for sid, source in historical.items() if cid in source['native_checks'])

    assert predicate_drift == [], '\n'.join(map(repr, predicate_drift))
    for sid, row in upstream.items():
        old = historical[sid]
        assert row['status'] == old['status'] and row['repository'] == old['repository']
        assert row['evaluator_sha256'] == old['upstream_evaluator']['sha256']
        assert row['resolved_sha256'] == old['upstream_evaluator'].get('resolved_sha256', row['evaluator_sha256'])
        direct = set(old['native_checks'])
        assert direct <= native.keys()
        assert row['native_ids'] == sorted(direct)
        assert row['active_native_ids'] == sorted(direct - archived)
        assert row['excluded_native_ids'] == sorted(direct & archived)
        assert row['semantic_equivalence'] == 'not_inferred_from_mapping_or_receipt_presence'
        related = set(old.get('review', {}).get('related_native_ids', []))
        successor = old.get('review', {}).get('current_native_reconciliation')
        if successor:
            related.add(successor['native_id'])
            assert successor['native_id'] in native.keys() - archived
            assert successor['full_upstream_equivalence'] is False
        assert row['related_native_ids'] == sorted(related) and related <= native.keys()
        if row['status'] != 'mapped-active':
            assert old['review']['assessment'] and old['review']['classification']
            assert sid in report['nonmapped_contract_families'][row['review_family']]['source_ids']

    nonmapped = [sid for family in report['nonmapped_contract_families'].values() for sid in family['source_ids']]
    assert len(nonmapped) == len(set(nonmapped)) == 74
    assert set(nonmapped) == {sid for sid, row in upstream.items() if row['status'] != 'mapped-active'}
    baseline = json.loads((ROOT / report['inputs']['native_baseline']['path']).read_text())['checks']
    assert native.keys() - {row['id'] for row in baseline} == set(report['baseline_delta']['new_native_ids']) == {
        'gcp.review.cloudtasks.selected_payload_secret_indicators',
        'gcp.review.bigquery.selected_routine_secret_indicators',
        'gcp.review.dataproc.selected_job_referenced_source_secret_indicators',
        'gcp.review.dataproc.selected_initialization_referenced_source_secret_indicators',
    }
    assert {row['id'] for row in baseline if row['active'] and row['id'] in archived} == set(
        report['baseline_delta']['newly_excluded_existing_ids'])
    assert all(not value for key, value in report['findings'].items() if isinstance(value, list))
    # Accounted limitations and potential advisory work must not be erased by a
    # green accounting result, or mislabeled as a full upstream implementation.
    assert {sid for row in report['remaining_bounded_upstream_candidates'] for sid in row['source_ids']} == {
        'gcp-compliance.control.cis_v300_7_4', 'gcp-compliance.control.cis_v400_7_4',
    }
    assert any(row['status'] == 'remaining_native_association_gap' for row in report['secret_surface_reconciliation'])


def test_pinned766_and_head769_are_separate_exact_conserved_source_epochs():
    current = current_conservation()
    assert current['counts'] == {
        'historical_native': 529, 'prior_admissions': 3, 'head_admissions': 3,
        'registered_native': 535, 'active_native': 428, 'excluded_native': 107,
        'historical_source_rows': 766, 'head_added_source_rows': 3, 'head_source_rows': 769,
    }
    historical = _checked_json(current['historical_source_report'])
    inventory = _checked_json(current['pinned_source_inventory'])
    audit = _checked_json(current['head_audit'])
    accounting = _checked_json(current['head_source_accounting'])
    runtime = _checked_json(current['head_runtime_admission'])
    old_ids = {r['check_id'] for r in inventory['checks']}
    assert len(old_ids) == len(inventory['checks']) == 766
    assert current['historical_dispositions'] == historical['counts']['upstream_dispositions']
    assert current['head_source_successors'] == accounting['source_rows']
    additions = {r['source_id']: r for r in current['head_source_successors']}
    queue = {r['source_id']: r for r in audit['new_candidate_queue']}
    assert additions.keys() == queue.keys()
    assert not old_ids & additions.keys()
    assert len(old_ids | additions.keys()) == 769
    assert len(additions) == len(current['head_admissions']) == 3
    assert {r['native_id'] for r in additions.values()} == current['head_admissions'].keys()
    prowler, = [r for r in audit['repositories'] if r['repository'] == 'prowler-cloud/prowler']
    assert prowler['head_commit'] == '4980ded0ae30cb93a251688b24ce55e5bd0ad466'
    for sid, successor in additions.items():
        cid = successor['native_id']
        assert successor['revision'] == prowler['head_commit']
        assert successor['full_upstream_semantic_equivalence'] is False
        assert queue[sid]['proposed_native_id'] == cid
        assert successor['registered_body_sha256'] == current['head_admissions'][cid]['predicate']['body_sha256']
        assert successor['limit']
    assert set(runtime['registered_ids']) == current['head_admissions'].keys()
    assert runtime['unique_passing_nodes'] == 50
    # Root/public metadata successors reuse their existing unchanged predicates.
    native = {c.id: c for c in CHECKS if c.provider == 'gcp'}
    old_native = {r['id']: r for r in historical['native_records']}
    assert len(audit['metadata_only_existing_ids']) == 2
    for row in audit['metadata_only_existing_ids']:
        cid = row['proposed_successor_native_id']
        assert cid == row['preserved_old_native_ids'] and cid in old_native
        assert row['source_evaluator_unchanged'] is True
        fn = inspect.unwrap(native[cid].evaluate)
        assert hashlib.sha256(inspect.getsource(fn).encode()).hexdigest() == old_native[cid]['predicate']['body_sha256']
    assert current['production_accepted'] is current['deployed'] is False
    assert current['root_owned_remaining']


def test_function_erratum_preserves_old_proof_and_binds_current_native_dtos():
    from peaso.checks.fixtures import CASES

    current = current_conservation()
    erratum = _checked_json(current['current_predicate_errata'][FUNCTION_ID])
    check, = [c for c in CHECKS if c.id == FUNCTION_ID]
    fn = _validate_current_function(erratum, check)
    ledger = json.loads((ROOT / 'docs/evidence-reviews/gcp.json').read_text())
    old_row = deepcopy(ledger['checks'][FUNCTION_ID])
    assert old_row.pop('current_erratum') == current['current_predicate_errata'][FUNCTION_ID]['path']
    assert hashlib.sha256(json.dumps(old_row, sort_keys=True).encode()).hexdigest() == erratum['historical_ledger_record_sha256']
    assert old_row['evaluator_sha256'] == erratum['historical_predicate']['body_sha256']
    assert old_row['evaluator_sha256'] != erratum['predicate']['body_sha256']
    integration = _checked_json(erratum['integration_receipt'])
    assert integration['check_id'] == FUNCTION_ID
    assert len(erratum['corrections']) == 3
    dtos = _checked_json(erratum['current_public_dtos'])
    expected = {'full_clean': ['PASS'], 'full_positive': ['FAIL'],
                'partial_positive': ['FAIL'], 'asymmetric': ['FAIL'],
                'partial_clean': ['UNKNOWN'], 'partial_inventory_positive': ['UNKNOWN', 'FAIL'],
                'partial_inventory_clean': ['UNKNOWN', 'UNKNOWN'],
                'partial_inventory_and_detector_positive': ['UNKNOWN', 'FAIL']}
    assert {r['case']: [f['status'] for f in r['public_findings']] for r in dtos['records']} == expected
    for record in dtos['records']:
        findings = record['public_findings']
        summary = erratum['native_cases'][record['case']]
        assert summary['statuses'] == expected[record['case']]
        assert summary['inventory_status'] == record['ordinary_inventory_status']
        assert summary['findings_sha256'] == hashlib.sha256(json.dumps(findings, sort_keys=True).encode()).hexdigest()
        for finding in findings:
            assert finding['check_id'] == FUNCTION_ID
            if finding['status'] == 'FAIL':
                evidence = finding['evidence']
                assert evidence['credential_validation'] == 'not_attempted'
                assert evidence['secret_leaks'] and evidence['function_secret_pairs']
                assert all(pair['secret_leaks'] for pair in evidence['function_secret_pairs'])
                if record['case'] != 'full_positive':
                    assert evidence['complete'] is False
            if record['case'].startswith('partial_inventory'):
                assert record['ordinary_inventory_status'] == 'partial'
        if record['case'].startswith('partial_inventory'):
            assert findings[0]['status'] == 'UNKNOWN'
            assert findings[0]['evidence']['collection_status'] == 'partial'
    for branch, expected_status in [('pass', 'PASS'), ('fail', 'FAIL'), ('partial', 'FAIL'),
                                    ('asymmetric', 'FAIL'), ('unknown', 'UNKNOWN'),
                                    ('partial_inventory', 'FAIL'), ('partial_inventory_clean', 'UNKNOWN')]:
        case = CASES[FUNCTION_ID]
        status, evidence = fn(deepcopy(case[branch]), deepcopy(case.get(branch + '_index', case['index'])))
        assert status == expected_status, (branch, status, evidence)
        if branch in {'partial', 'asymmetric', 'partial_inventory'}:
            assert evidence['complete'] is False


@pytest.mark.parametrize('field', ['check_id', 'qualname', 'body_sha256', 'file_sha256',
                                   'integration_receipt', 'current_public_dtos'])
def test_exact_function_erratum_rejects_modified_identity_body_source_or_receipt(field):
    current = current_conservation()
    erratum = _checked_json(current['current_predicate_errata'][FUNCTION_ID])
    check, = [c for c in CHECKS if c.id == FUNCTION_ID]
    altered = deepcopy(erratum)
    if field == 'check_id':
        altered[field] += '.unreviewed'
    elif field in {'integration_receipt', 'current_public_dtos'}:
        altered[field]['sha256'] = '0' * 64
    else:
        altered['predicate'][field] = 'unreviewed' if field == 'qualname' else '0' * 64
    with pytest.raises(AssertionError):
        _validate_current_function(altered, check)


@pytest.mark.parametrize('artifact', ['historical_source_report', 'pinned_source_inventory',
                                      'head_audit', 'head_source_accounting', 'head_runtime_admission'])
def test_conserved_source_artifacts_reject_changed_sha256(artifact):
    reference = deepcopy(current_conservation()[artifact])
    reference['sha256'] = '0' * 64
    with pytest.raises(AssertionError):
        _checked_json(reference)


def test_new_job_native_thematic_addition_preserves_exact766_and769_source_epochs():
    current = current_thematic_admissions()
    historical = current_conservation()
    assert _checked_json(current['historical_gcp_conservation']) == historical
    assert current['counts']['gcp_registered_before'] == historical['counts']['registered_native'] == 535
    assert current['counts']['gcp_registered'] == 536
    assert current['counts']['gcp_active'] == 429
    assert current['counts']['gcp_excluded'] == historical['counts']['excluded_native'] == 107
    assert current['counts']['historical_upstream_source_rows'] == historical['counts']['historical_source_rows'] == 766
    assert current['counts']['head_source_rows'] == historical['counts']['head_source_rows'] == 769
    assert current['counts']['new_upstream_source_rows'] == 0
    retained_erratum = current['historical_function_erratum']
    current_erratum = historical['current_predicate_errata'][FUNCTION_ID]
    assert retained_erratum['path'] == current_erratum['path']
    assert record_matches(current_erratum['path'], retained_erratum['sha256'], current_erratum['sha256'])
    assert _checked_json(current['historical_function_erratum'])['check_id'] == FUNCTION_ID
    accepted = checked_thematic_reference(current['thematic_admissions'][JOB_ID])
    assert accepted['source_epoch'].startswith('Separate native thematic addition')
    assert current['upstream_semantic_equivalence_claimed'] is False
    assert current['production_accepted'] is current['deployed'] is current['full_goal_complete'] is False
    assert current['root_owned_remaining']
    source = _checked_json(historical['historical_source_report'])
    assert JOB_ID not in {r['id'] for r in source['native_records']}
    assert not any(JOB_ID in r['native_ids'] for r in source['upstream_records'])
    assert JOB_ID not in historical['prior_admissions'] and JOB_ID not in historical['head_admissions']


@pytest.mark.parametrize('reference', ['historical_gcp_conservation', 'historical_function_erratum'])
def test_new_thematic_source_conservation_rejects_historical_receipt_drift(reference):
    altered = deepcopy(current_thematic_admissions()[reference])
    altered['sha256'] = '0' * 64
    with pytest.raises(AssertionError):
        _checked_json(altered)
