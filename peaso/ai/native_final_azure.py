"""Separate, fail-closed Azure Hardening native-final admission.

The committed manifest is pending. Root may qualify it only after a hosted
same-snapshot quality and cost replay and an exact manifest SHA pin.
"""

import hashlib
import json
import os
from pathlib import Path


MANIFEST = Path(__file__).with_name('native_final_azure_allowlist.json')
SOURCE_SCAN = 'a79ff6f9331246bd9e4f4bf6ba6fa207'
SNAPSHOT_ID = 'sha256:08597df6a1b6f6199eab1c8018409c969bcd9eff2e81b6c2f0bb2bdf76aea301'
BASE_COMMIT = 'f204f3a5b25991390cb6baf2572710c4da8342bd'
SOURCE_PROOF_SHA256 = '2233a039a437c8506e14b86cdb8867541080cde613316a799fd239620f41e268'
SOURCE_PROOF = Path(__file__).resolve().parents[2] / 'docs/ai-review/native-final-azure-source-audit-v2.json'
SAVED_RECEIPT = Path(__file__).resolve().parents[2] / 'docs/ai-review/native-final-azure-saved-replay-v2.json'
SAVED_RECEIPT_SHA256 = '43dd2d85ffa361328f62ebd88a45949d73e3a3a21e5c5f19b98df58cd0c3455f'
HOSTED_RECEIPT = Path(__file__).resolve().parents[2] / 'docs/ai-review/native-final-azure-hosted-v2.json'
HOSTED_RECEIPT_SHA256 = '0dd4e19823345c12b1b0ecfd1bd26c63416e2569892693a39a325ae7b279fa2b'


def _source_proof():
    raw = SOURCE_PROOF.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_PROOF_SHA256:
        raise ValueError('azure_source_proof_drift')
    value = json.loads(raw)
    if (value.get('version') != 2 or value.get('scan_id') != SOURCE_SCAN
            or value.get('snapshot_id') != SNAPSHOT_ID
            or value.get('exercised_check_count') != 224
            or value.get('selected_check_count') != 124
            or value.get('selected_native_fail_count') != 274
            or value.get('exact_snapshot_status_evidence_parity') is not True):
        raise ValueError('azure_source_proof_invalid')
    return value


try:
    _PROOF = _source_proof()
    SOURCE_HASHES = _PROOF['source_hashes']
    EXPECTED = {row['check_id']: row for row in _PROOF['source_decisions']
                if row['decision'] == 'admit_source_proven'}
except (OSError, ValueError, TypeError, KeyError):
    SOURCE_HASHES = {}
    EXPECTED = {}


def _digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _qualified_receipts():
    """Bind saved parity and two hosted pairs to exact shipped public bytes."""
    try:
        saved_raw = SAVED_RECEIPT.read_bytes()
        hosted_raw = HOSTED_RECEIPT.read_bytes()
        if (hashlib.sha256(saved_raw).hexdigest() != SAVED_RECEIPT_SHA256
                or hashlib.sha256(hosted_raw).hexdigest() != HOSTED_RECEIPT_SHA256):
            return False
        saved = json.loads(saved_raw)
        hosted = json.loads(hosted_raw)
        if (saved.get('version') != 2 or saved.get('scan_id') != SOURCE_SCAN
                or saved.get('selected_native_fail_count') != 274
                or saved.get('saved_review_and_public_finding_action_parity') is not True
                or hosted.get('version') != 1 or hosted.get('scan_id') != SOURCE_SCAN
                or hosted.get('status') != 'hosted_measured_selected_quality_source_adjudicated'
                or hosted.get('selected_native_fail_ids') != 274
                or hosted.get('selected_baseline_unknown_distinct') != 33
                or hosted.get('selected_baseline_unknown_adjudicated') != 33
                or hosted.get('selected_baseline_unknown_pending') != 0
                or hosted.get('priorities_hosted_action_parity_evaluated') is not False):
            return False
        rounds = hosted.get('rounds')
        if (type(rounds) is not list or len(rounds) != 2
                or {row.get('round') for row in rounds if type(row) is dict} != {1, 2}
                or hosted.get('candidate_median_wall_seconds', float('inf')) >=
                   hosted.get('baseline_median_wall_seconds', 0)):
            return False
        for row in rounds:
            if (row.get('baseline_ai_ids') != 434 or row.get('candidate_ai_ids') != 160
                    or row.get('native_fail_ids') != 274
                    or row.get('combined_review_ids') != 434):
                return False
            baseline, candidate = row['baseline'], row['candidate']
            if any(candidate[key] >= baseline[key] for key in
                   ('model_calls', 'cpu_x_peak_rss_byte_seconds', 'wall_seconds')):
                return False
            if (candidate['input_tokens'] + candidate['output_tokens'] >=
                    baseline['input_tokens'] + baseline['output_tokens']):
                return False
        return True
    except (OSError, ValueError, TypeError, KeyError):
        return False


def admitted_check_ids(path=MANIFEST):
    if os.getenv('PEASO_AZURE_HARDENING_NATIVE_FINAL_ENABLED') != '1':
        return frozenset()
    pin = os.getenv('PEASO_AZURE_HARDENING_NATIVE_FINAL_SHA256', '')
    if not _digest(pin):
        return frozenset()
    try:
        raw = Path(path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != pin:
            return frozenset()
        manifest = json.loads(raw)
        if (type(manifest) is not dict or set(manifest) != {
                'version', 'source_scan_id', 'snapshot_id', 'base_commit',
                'source_proof_sha256', 'source_hashes', 'replay_qualification', 'checks'}
                or manifest['version'] != 2 or type(manifest['version']) is not int
                or manifest['source_scan_id'] != SOURCE_SCAN
                or manifest['snapshot_id'] != SNAPSHOT_ID
                or manifest['base_commit'] != BASE_COMMIT
                or manifest['source_proof_sha256'] != SOURCE_PROOF_SHA256
                or manifest['source_hashes'] != SOURCE_HASHES):
            return frozenset()
        replay = manifest['replay_qualification']
        if (type(replay) is not dict or set(replay) != {
                'status', 'saved_receipt_sha256', 'hosted_receipt_sha256'}
                or replay['status'] != 'qualified'
                or replay['saved_receipt_sha256'] != SAVED_RECEIPT_SHA256
                or replay['hosted_receipt_sha256'] != HOSTED_RECEIPT_SHA256
                or not _qualified_receipts()):
            return frozenset()
        checks = manifest['checks']
        if type(checks) is not list or len(checks) != len(EXPECTED):
            return frozenset()
        if not EXPECTED or not SOURCE_HASHES:
            return frozenset()
        actual = {}
        for check in checks:
            if type(check) is not dict or set(check) != {
                    'check_id', 'saved_fail_count', 'saved_ai_disagreements',
                    'source_kind', 'dependencies', 'source_file', 'source_line',
                    'function_sha256', 'source_basis'}:
                return frozenset()
            ident = check['check_id']
            if ident not in EXPECTED or ident in actual:
                return frozenset()
            expected = {key: value for key, value in EXPECTED[ident].items() if key != 'decision'}
            if check != expected:
                return frozenset()
            actual[ident] = check
        root = Path(__file__).resolve().parents[2]
        if hashlib.sha256(SOURCE_PROOF.read_bytes()).hexdigest() != SOURCE_PROOF_SHA256:
            return frozenset()
        for source, digest in SOURCE_HASHES.items():
            if hashlib.sha256((root / source).read_bytes()).hexdigest() != digest:
                return frozenset()
        return frozenset(actual)
    except (OSError, ValueError, TypeError, KeyError):
        return frozenset()


def partition(rows, admitted, coverage=None):
    # A recorded item may still evaluate FAIL inside a partial collection.
    # Native-final admission requires complete check and collection envelopes
    # for the exact scope, even when the item's own fields are decisive.
    complete = set()
    if isinstance(coverage, list):
        seen = {}
        for item in coverage:
            if not isinstance(item, dict):
                continue
            level, scope = item.get('level'), item.get('scope')
            if level == 'check':
                key = ('check', item.get('check_id'), scope)
            elif level == 'collection':
                key = ('collection', item.get('type'), scope)
            else:
                continue
            seen.setdefault(key, []).append(item.get('status'))
        for ident, entry in EXPECTED.items():
            for key, statuses in seen.items():
                if (key[0] == 'check' and key[1] == ident and statuses == ['evaluated']
                        and all(seen.get(('collection', kind, key[2])) in (['collected'], ['empty'])
                                for kind in entry['dependencies'])):
                    complete.add((ident, key[2]))
    native, ai = [], []
    for row in rows:
        evidence = row.get('evidence')
        if (row.get('provider') == 'azure' and row.get('category') == 'hardening'
                and row.get('status') == 'FAIL'
                and row.get('scanner_status', 'FAIL') == 'FAIL'
                and not (isinstance(evidence, dict) and 'incomplete_dependencies' in evidence)
                and row.get('check_id') in admitted
                and (row.get('check_id'), row.get('scope')) in complete):
            native.append(row)
        else:
            ai.append(row)
    return native, ai
