"""Current native witnesses are overlays; signed historical CASES stay unchanged."""
from copy import deepcopy
from functools import lru_cache
import json
import gzip
import hashlib
from pathlib import Path

from peaso.checks.facts import MemoIndex

PATH = Path(__file__).parent / 'fixtures/azure_storage_native_fixes_20261020.json'
CURRENT_GENERIC_SHA256 = '2dad45304498ed5f1ffa3f235689b4789dcbc674af0544465548701f79b351ca'


def _current_acr_stream_predecessor(name, raw):
    """Project only the exact reviewed batched stream to its retained witness source."""
    if (name != 'peaso/collectors/azure_acr_image_stream_inspection_20261021.py'
            or hashlib.sha256(raw).hexdigest() != '27228bceb4446654a8655af4f2f6e5e560c87e556ceb25046659039f16dee600'):
        return raw
    import base64
    import zlib
    inverse = json.loads(zlib.decompress(base64.b64decode('eNqVVst2ozgQ/RfWLIRAgBa9MEws41cSpwNYOVnwmAbb4HBiCMZfPyUetrtn5jS9cPm4dFWPW7fAb2+EUlmnuixJ7/KbYupEl7Gia0rnwCoyTLmz0jZ381CdZ3797Vt/aGJxaBJZunNSJJwUbjw9D04FCaeCjCGugkRcjODqYjKgsKLKnZUiNm3i2erovxyMNnF9AxEBwmgIhXHnEFXgc7b1TgMS6+0BhUq8cxbu0hP3pp9RcxgApiEAFEM+vE7DZMihaqIxVbuWq1GBJNCFFOa06pwEKcKJr2QRjFsH1L/F01PvVFuUTq8oQ3ChG1eHAWdgDbV3aIYJ5LRWelTX+61HKu49f/ZN7IOZWwVDE5op2tdMFf3ShGaKQYAlQ1iqQhMaJTcHDAkTRIZKiGIAY0QxlV9iQY9wFdrDA1IVuiCqqQpCHnqUCkrorBTnr9WLR/bDgd4eAJ+hb524v8m6Aw2LuIY+lEQMISliKteSqK7JnZWcxlpyz60dtv4awnDbqiPQR+AnyRanSpiXF4dNK/CjgLlFtLOyv9l0H08+Esee/P7TWKcQWo9Z9hUeV5XzMK0cllVbTMuInbOYvfZ5TvA9rUANyGHzzGEPi1Hx7VUS4wyFuXuJmjrhPoeZWgXfWanDNhDf3ceMNg5zy8DfIJh7sn2xyq2/2Qe2Ni7HHT/XvQQKTbmzUnRRwsi2YJudJLInVwCVOytBRWXvFGIFKxSRl1mUnY7X1XTLHff4V5S/DhFa+Qgr+aqVRsfN5TFDI3kRn5aHepnHWTy51m0YcmelOb41Nm8OSeCvEnc2V7g7MglT0v/vwv3RJwT5d/a+C3pTgPujv/zH0+BTWsMkP2AABiRMOXObZZ4duEfQoomqeVPWXhMDZo7mCkp4DkqYTZLA05J/519TezeK1U/uW+jJLeOR+FYYIXPToLEK0EL32FRuRPE8O3GXdv5LET8mI7er5eP8BZuDAo9WQogho3uHQdyd2LxV22uXmxy5//wxx3f4Jjot7P7JpyMEr4vWSv+d6AbU5M5KzqAr+EnkzkqQtuIYRGTH7Xhabf1M+UFIIWbpBSr6g1az/Od2i3YUy3xaR8yFh1RqLHZFS+PSju8fPMfH/O6eioqRo/vtqJ480P/seZx0Z+3Lp5Mby9LwL+U1Sm4E6nJnJf69bLi3hoSbcF7fAIYAKKh9HVb9MhVbrz763yHS0c1GdnUJcCYYO/iYFyCOy+KCzo/wXwQm1PApbDMui2hmiQXLA3hNRk0cC4z0/v4POtubFw==')))
    for start, end, prior in reversed(inverse):
        raw = raw[:start] + base64.b64decode(prior) + raw[end:]
    assert hashlib.sha256(raw).hexdigest() == '4f51b5162e6809840049aaa6f6528018d4c99f60b01d869759f50df961e0beeb'
    return raw


@lru_cache(maxsize=1)
def _native_rows():
    rows = json.loads(PATH.read_text())['cases']
    identity_path = PATH.with_name('azure_identity_native_successors_20261020.json')
    for cid, cases in json.loads(identity_path.read_text()).items():
        assert cid not in rows
        rows[cid] = {branch: {**case, 'status': branch.upper()} for branch, case in cases.items()}
    application = PATH.with_name('azure_application_compute_native_successors_20261020.json')
    for record in json.loads(application.read_text())['records']:
        cid, branch = record['check_id'], record['status'].lower()
        cases = rows.setdefault(cid, {})
        assert branch not in cases, (cid, branch)
        cases[branch] = record
    application2 = PATH.with_name('azure_application_compute_2_native_successors_20261020.json')
    for record in json.loads(application2.read_text())['captures']:
        if record['check_id'] == 'azure.claude2.prowler_function_identity_not_admin':
            # The earlier independent fixture used a 37-character principal,
            # rejected by the reviewed native Authorization identity guard.
            # Retain that file, replay current actual valid-GUID captures below.
            continue
        cid, branch = record['check_id'], record['mode']
        cases = rows.setdefault(cid, {})
        assert branch not in cases, (cid, branch)
        cases[branch] = record
    function_role = PATH.with_name('azure_function_role_native_successors_20261020.json')
    for record in json.loads(function_role.read_text())['captures']:
        cid, branch = record['check_id'], record['mode']
        assert cid == 'azure.claude2.prowler_function_identity_not_admin'
        cases = rows.setdefault(cid, {})
        assert branch not in cases, (cid, branch)
        cases[branch] = record
    database = PATH.with_name('azure_database_native_evaluator_inputs_20261020.json')
    for record in json.loads(database.read_text())['records']:
        cid, branch = record['check_id'], record['mode']
        cases = rows.setdefault(cid, {})
        assert branch not in cases, (cid, branch)
        cases[branch] = record
    database2 = PATH.with_name('azure_database_crypto_backup_2_evaluator_inputs_20261020.json')
    for record in json.loads(database2.read_text())['records']:
        cid, branch = record['check_id'], 'database2/' + record['mode']
        cases = rows.setdefault(cid, {})
        assert branch not in cases, (cid, branch)
        cases[branch] = record
    enforcement = PATH.with_name('azure_identity_enforcement_native_successors_20261020.json')
    for cid, cases in json.loads(enforcement.read_text()).items():
        assert cid not in rows
        rows[cid] = {branch: {**case, 'status': case['expected_status']} for branch, case in cases.items()}
    network = PATH.with_name('azure_network_native_evaluator_inputs_20261020.json')
    for record in json.loads(network.read_text())['inputs']:
        cid, branch = record['check_id'], record['native_testnode']
        cases = rows.setdefault(cid, {})
        assert branch not in cases, (cid, branch)
        cases[branch] = {**record, 'status': record['expected_status']}
    services1 = PATH.with_name('azure_services1_native_evaluator_inputs_20261020.json.gz')
    for record in json.loads(gzip.decompress(services1.read_bytes()))['captures']:
        if record['check_id'] == 'azure.claude.iam_custom_role_administers_locks':
            # Original literal-prefix witnesses are retained in the gzip file.
            # Current native write/delete witnesses below supersede only this ID.
            continue
        cid, branch = record['check_id'], 'services1/' + record['branch']
        assert len(record['captures']) == 1
        captured = record['captures'][0]
        cases = rows.setdefault(cid, {})
        assert branch not in cases, (cid, branch)
        cases[branch] = {'check_id': cid, 'item': captured['item'], 'index': captured['index'],
                         'status': captured['result'][0], 'evidence': captured['result'][1]}
    services2 = PATH.with_name('azure_services2_native_evaluator_inputs_20261020.json.gz')
    for record in json.loads(gzip.decompress(services2.read_bytes()))['inputs']:
        cid, branch = record['check_id'], 'services2/' + record['native_testnode']
        cases = rows.setdefault(cid, {})
        assert branch not in cases, (cid, branch)
        cases[branch] = {**record, 'status': record['expected_status']}
    services3 = PATH.with_name('azure_services3_native_evaluator_inputs_20261020.json.gz')
    for record in json.loads(gzip.decompress(services3.read_bytes()))['records']:
        if record['check_id'] == 'azure_application_gateway_app_http_logs_enabled_2de0361':
            # Retain the old L4 aggregate witness, supersede its narrowed source below.
            continue
        cid, branch = record['check_id'], 'services3/' + record['case']
        cases = rows.setdefault(cid, {})
        assert branch not in cases, (cid, branch)
        cases[branch] = record
    lock = PATH.with_name('azure_lock_native_successors_20261020.json.gz')
    for record in json.loads(gzip.decompress(lock.read_bytes()))['inputs']:
        cid, branch = record['check_id'], 'lock-successor/' + record['branch']
        cases = rows.setdefault(cid, {})
        assert branch not in cases, (cid, branch)
        cases[branch] = {**record, 'status': record['expected_status']}
    edge = PATH.with_name('azure_edge_native_current_inputs_20261020.json.gz')
    for number, record in enumerate(json.loads(gzip.decompress(edge.read_bytes()))['cases']):
        callable_path = record['evaluated_callable']['path']
        if not any(name in callable_path for name in ('azure_public_edge_config_review_20261020.py', 'azure_gateway_logging_review_20261020.py', 'azure_devops_visible_urls_review_20261020.py')):
            continue
        cid = record['check_id']
        if 'azure_devops_visible_urls_review' in callable_path:
            cid = 'azure.review.devops.visible_clone_urls_without_userinfo'
        expected = {f['status'] for f in record['findings']}
        assert len(expected) == 1
        for position, captured in enumerate(record['actual_evaluator_item_indexes']):
            branch = 'edge-successor/' + str(number) + '/' + str(position) + '/' + record['case']
            cases = rows.setdefault(cid, {})
            assert branch not in cases, (cid, branch)
            cases[branch] = {**captured, 'status': next(iter(expected))}
    # Fresh normal-collector witnesses supersede only these two stale generic
    # fixtures. Historical native captures and admission receipts stay intact.
    current = PATH.with_name('azure_current_generic_native_witnesses_20261024.json.gz')
    raw = current.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == CURRENT_GENERIC_SHA256
    captured = json.loads(gzip.decompress(raw))
    root = Path(__file__).resolve().parents[1]
    for name, expected in captured['source_sha256'].items():
        assert hashlib.sha256(_current_acr_stream_predecessor(name, (root / name).read_bytes())).hexdigest() == expected, name
    expected_pairs = {(cid, branch) for cid in (
        'azure_storage_account_10_3_4_7_02943e9',
        'azure.review.acr.selected_image_secret_indicators') for branch in ('pass', 'fail')}
    assert {(r['check_id'], r['branch']) for r in captured['records']} == expected_pairs
    assert len(captured['records']) == len(expected_pairs)
    for record in captured['records']:
        rows.setdefault(record['check_id'], {})[record['branch']] = {
            **record, 'status': record['branch'].upper()}
    return rows


def native_row(check_id, branch):
    rows = _native_rows().get(check_id, {})
    if branch in rows:
        return deepcopy(rows[branch])
    candidates = [r for r in rows.values() if r['status'] == branch.upper()]
    if not candidates:
        return None
    return deepcopy(candidates[0])


def current_cases(check_id, historical):
    result = deepcopy(historical)
    for branch in ('pass', 'fail'):
        row = native_row(check_id, branch)
        if row:
            result[branch] = row['item']
            result[branch + '_index'] = MemoIndex(row['index'])
    if check_id == 'azure.claude.managed_hsm_audit_logging':
        # Diagnostic storage retention ceased applying in2025. There is no
        # current native PASS for the old combined retention contract; preserve
        # that historical CASE and explicitly test its unresolved successor.
        row = native_row(check_id, 'unknown')
        assert row is not None
        result.pop('pass', None)
        result.pop('pass_index', None)
        result['unknown'], result['unknown_index'] = row['item'], MemoIndex(row['index'])
    if check_id == 'azure.htbp.sql.entra_only_authentication':
        # The 2026-10-20 capture predates the dedicated azureADOnlyAuthentications
        # child read (commit 66b47ab6). Its administrator row already recorded the
        # same server flag, so supply that value in the collector's normalized shape.
        for branch in ('pass', 'fail'):
            item = result.get(branch)
            if not (isinstance(item, dict) and 'azureADOnlyAuthentications' not in item
                    and item.get('serverAdministrators')):
                continue
            flag = item['serverAdministrators'][0]['properties'].get('azureADOnlyAuthentication')
            assert type(flag) is bool
            item['azureADOnlyAuthentications'] = [{
                'id': item['id'] + '/azureADOnlyAuthentications/Default', 'name': 'Default',
                'type': 'Microsoft.Sql/servers/azureADOnlyAuthentications', 'parent_id': item['id'],
                'properties': {'azureADOnlyAuthentication': flag}}]
            item.setdefault('_coverage', {})['azureADOnlyAuthentications'] = {'status': 'collected'}
    if check_id == 'azure.claude.vm_windows_secure_boot' and 'not_applicable' in result:
        # A Windows SQL offer is not a Linux OS declaration. Retain that old
        # CASES value and use an actual native Linux field for the current N/A.
        result['not_applicable']['properties']['storageProfile']['osDisk']['osType'] = 'Linux'
    return result
