"""Checkpoint privacy work runs once per unchanged collection, with identical bytes."""
import copy
import hashlib
import json
from datetime import datetime, timezone

from peaso import redaction_memo
from peaso.auth import secrets
from peaso.auth.secrets import Redactor, redact
from peaso.redaction_memo import SnapshotRedactionMemo, credential_redaction
from peaso.secret_evidence import capture, EphemeralCipher
from peaso.snapshot import make_snapshot, seal
from tests.test_incremental_checkpoint import SCOPE, TENANT
from tests.test_incremental_report_cadence import manual_session


class _FixedClock(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 10, 25, tzinfo=timezone.utc)


FIRST = 'synthetic-checkpoint-secret-7731'
LATER = 'synthetic-later-secret-0519'


def _row(index, text='plain'):
    return {'type': 'bucket' if index == 0 else 'other', 'scope': SCOPE if index == 0 else f'scope-{index}',
            'status': 'collected', 'items': [{'id': f'r-{index}', 'note': text,
                                               'password': 'field-value', 'Tags': [{'Key': 'k', 'Value': index}]}]}


def _run(monkeypatch, tmp_path, *, memoized):
    """Settle, batch and publish twice, discovering one secret in between."""
    monkeypatch.setattr('peaso.snapshot.datetime', _FixedClock)
    if not memoized:
        monkeypatch.setattr(SnapshotRedactionMemo, '__call__', lambda self, snapshot: self.transform(snapshot))
    calls = []
    transform = SnapshotRedactionMemo._row
    def counted(self, row):
        before = self.misses
        public = transform(self, row)
        calls.append(self.misses - before)
        return public
    monkeypatch.setattr(SnapshotRedactionMemo, '_row', counted)
    session, _, _, _ = manual_session(monkeypatch, tmp_path)
    published = []
    connector = {'auth': {'secret_access_key': 'connector-credential-4410'}}
    try:
        with capture(EphemeralCipher(), tenant=TENANT, scan_id='a' * 32) as sink:
            sink.retain_redaction(FIRST, hashlib.sha256(FIRST.encode()).hexdigest())
            credentials = credential_redaction(connector, secrets.credential_values)
            def callback(raw):
                return seal(credentials(sink.public_snapshot(raw)))
            session.public_snapshot = callback
            original = session.on_checkpoint
            def record(snapshot, report, sequence):
                published.append(json.dumps([snapshot, report, sequence]))
                return original(snapshot, report, sequence)
            session.on_checkpoint = record
            rows = [_row(i, FIRST if i == 1 else LATER if i == 2 else 'connector-credential-4410' if i == 3 else 'plain')
                    for i in range(12)]
            for row in rows[:8]:
                session.on_collection(row)
            session._flush_pending()
            assert session._maybe_publish(force=True) is not None
            settled = len(calls)
            assert session._maybe_publish(force=True) is None  # unchanged sequence
            session.on_collection(rows[8])
            session._flush_pending()
            assert session._maybe_publish(force=True) is not None
            repeated = calls[settled:]
            sink.retain_redaction(LATER, hashlib.sha256(LATER.encode()).hexdigest())
            for row in rows[9:]:
                session.on_collection(row)
            session._flush_pending()
            assert session._maybe_publish(force=True) is not None
            session.finish_collection({})
    finally:
        session.close()
    return published, repeated, calls


def test_cumulative_reports_reuse_redaction_and_publish_identical_bytes(monkeypatch, tmp_path):
    with monkeypatch.context() as legacy:
        expected, _, _ = _run(legacy, tmp_path / 'legacy', memoized=False)
    published, repeated, calls = _run(monkeypatch, tmp_path / 'memo', memoized=True)
    assert published == expected
    text = '\n'.join(published)
    assert FIRST not in text and 'connector-credential-4410' not in text and 'field-value' not in text
    # The last report was built after LATER was found, so it carries no LATER value.
    assert LATER not in published[-2] and LATER not in published[-1]
    # Second report, two memos (capture secrets, connector credentials) per
    # row: the new row is redacted when it settles and once more by the secret
    # memo in its batch. Its credential pass in the batch and every row of the
    # cumulative report, including the eight already published, are reused.
    assert len(repeated) == 2 + 2 + 2 * 9
    assert sum(repeated) == 3


def test_memo_matches_redaction_for_type_and_order_variants():
    memo = SnapshotRedactionMemo(Redactor(['abcd-secret']))
    base = make_snapshot('aws', [SCOPE], [_row(0, 'x abcd-secret y')], created_at='2026-10-25T00:00:00+00:00')
    variants = [base, copy.deepcopy(base)]
    item = variants[1]['collections'][0]['items'][0]
    variants.append(dict(base, collections=[dict(base['collections'][0], items=[{**item, 'Tags': [{'Key': 'k', 'Value': True}]}])]))
    variants.append(dict(base, collections=[dict(base['collections'][0], items=[{1: 'one', **item}])]))
    variants.append(dict(base, collections=[dict(base['collections'][0], items=[{'1': 'one', **item}])]))
    variants.append(dict(base, collections=[dict(base['collections'][0], items=[dict(reversed(list(item.items())))])]))
    for snapshot in variants + variants:
        expected = redact(snapshot, ['abcd-secret'])
        observed = memo(snapshot)
        assert json.dumps(observed) == json.dumps(expected) and observed == expected
        assert [list(row['items'][0]) for row in observed['collections']] == [
            list(row['items'][0]) for row in expected['collections']]
    assert memo.hits >= 1 and memo.misses >= 5


def test_sensitive_or_renamed_collections_key_falls_back_to_whole_redaction(monkeypatch):
    snapshot = make_snapshot('aws', [SCOPE], [_row(0)], created_at='2026-10-25T00:00:00+00:00')
    memo = SnapshotRedactionMemo(lambda value: secrets.Redactor(['llect'])(
        {k.replace('llect', '[R]'): v for k, v in value.items()} if isinstance(value, dict) else value))
    observed = memo(snapshot)
    assert 'co[R]ions' in observed and memo.hits == memo.misses == 0


def test_capture_memo_is_rebuilt_for_new_secrets_and_never_shared_between_captures(tmp_path):
    raw = make_snapshot('aws', [SCOPE], [_row(0, LATER)], created_at='2026-10-25T00:00:00+00:00')
    with capture(EphemeralCipher(), tenant=TENANT, scan_id='a' * 32) as sink:
        sink.retain_redaction(FIRST, hashlib.sha256(FIRST.encode()).hexdigest())
        assert LATER in json.dumps(sink.public_snapshot(raw))
        assert LATER in json.dumps(sink.public_snapshot(raw))
        first_memo = redaction_memo._CAPTURES[sink][2]
        assert first_memo.hits == 1
        sink.retain_redaction(LATER, hashlib.sha256(LATER.encode()).hexdigest())
        assert LATER not in json.dumps(sink.public_snapshot(raw))
        assert redaction_memo._CAPTURES[sink][2] is not first_memo
    with capture(EphemeralCipher(), tenant='tenant-b', scan_id='b' * 32) as other:
        other.retain_redaction(FIRST, hashlib.sha256(FIRST.encode()).hexdigest())
        other.public_snapshot(raw)
        assert redaction_memo._CAPTURES[other][2] is not redaction_memo._CAPTURES[sink][2]
        assert redaction_memo._CAPTURES[other][2].hits == 0
    import gc
    import weakref
    memo = weakref.ref(first_memo)
    del sink, first_memo
    gc.collect()
    assert memo() is None  # the plaintext Redactor and memo die with their capture


def test_credential_redaction_reads_current_connector_values():
    connector = {'auth': {'secret_access_key': 'first-credential-1111'}}
    public = credential_redaction(connector, secrets.credential_values)
    raw = make_snapshot('aws', [SCOPE], [_row(0, 'first-credential-1111 second-credential-2222')],
                        created_at='2026-10-25T00:00:00+00:00')
    assert public(raw) == redact(raw, ('first-credential-1111',))
    connector['auth']['session_token'] = 'second-credential-2222'
    assert public(raw) == redact(raw, tuple(secrets.credential_values(connector['auth'])))
    assert 'second-credential-2222' not in json.dumps(public(raw))
