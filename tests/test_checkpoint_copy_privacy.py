"""Checkpoint copies remain isolated and every privacy revision is applied."""
import ast
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import peaso.checks
from peaso.redaction_memo import credential_redaction
from peaso import worker
from peaso.auth.secrets import redact
from peaso.secret_evidence import capture, EphemeralCipher
from peaso.snapshot import seal, validate
from peaso.snapshot_public_identity import public_snapshot_adapter
from tests.test_incremental_report_cadence import manual_session
from tests.test_incremental_checkpoint import SCOPE, TENANT


def callback_for(sink):
    def callback(raw):
        public = seal(redact(sink.public_snapshot(raw), ()))
        return public
    return callback


def test_settlement_and_batch_copy_are_independent_of_provider_input(monkeypatch, tmp_path):
    session, _, _, _ = manual_session(monkeypatch, tmp_path)
    source = {'type': 'bucket', 'scope': SCOPE, 'status': 'collected',
              'items': [{'id': 'one', 'nested': {'values': ['original']}}]}
    original = copy.deepcopy(source)
    def callback(raw):
        raw['collections'][0]['items'][0]['nested']['values'].append('private-projection')
        return seal(raw)
    session.public_snapshot = callback
    try:
        session.on_collection(source)
        assert source == original
        pending = session.pending[('bucket', SCOPE)][1]
        pending_before = copy.deepcopy(pending)
        session._flush_pending()
        assert source == original and pending == pending_before
        assert session.collections[('bucket', SCOPE)]['items'][0]['nested']['values'] == [
            'original', 'private-projection', 'private-projection']
    finally:
        session.close()


def test_state_only_watermark_does_not_mutate_prior_public_collection(monkeypatch, tmp_path):
    session, _, _, _ = manual_session(monkeypatch, tmp_path)
    source = {'type': 'bucket', 'scope': SCOPE, 'status': 'collected',
              'items': [{'id': 'one', 'nested': {'values': ['original']}}]}
    try:
        session.on_collection(source)
        session._flush_pending()
        prior = session.collections[('bucket', SCOPE)]
        before = copy.deepcopy(prior)
        def callback(raw):
            raw['collections'][0]['items'][0]['nested']['values'].append('watermark')
            return seal(raw)
        session.public_snapshot = callback
        session._advance_watermark()
        assert prior == before and source['items'][0]['nested']['values'] == ['original']
    finally:
        session.close()


def test_unchanged_native_replay_applies_new_secret_descriptors(monkeypatch, tmp_path):
    first, second = 'synthetic-secret-one-3293', 'synthetic-secret-two-6429'
    session, _, _, _ = manual_session(monkeypatch, tmp_path)
    source = {'type': 'bucket', 'scope': SCOPE, 'status': 'collected',
              'items': [{'id': 'one', 'observed_text': first + ' ' + second}]}
    original = copy.deepcopy(source)
    try:
        with capture(EphemeralCipher(), tenant=TENANT, scan_id='a'*32) as sink:
            session.public_snapshot = callback_for(sink)
            session.on_collection(source)
            session._flush_pending()
            sink.retain_redaction(first, hashlib.sha256(first.encode()).hexdigest())
            session.on_collection(source)
            session._flush_pending()
            one = json.dumps(session.collections[('bucket', SCOPE)])
            assert first not in one and second in one
            revision = session.sequence
            sink.retain_redaction(second, hashlib.sha256(second.encode()).hexdigest())
            session.on_collection(source)
            session._flush_pending()
            both = json.dumps(session.collections[('bucket', SCOPE)])
            assert first not in both and second not in both
            assert session.sequence > revision and source == original
    finally:
        session.close()


def test_batch_refreshes_descriptors_discovered_after_settlement(monkeypatch, tmp_path):
    value = 'synthetic-secret-before-batch-1329'
    session, _, _, _ = manual_session(monkeypatch, tmp_path)
    source = {'type': 'bucket', 'scope': SCOPE, 'status': 'collected',
              'items': [{'id': 'one', 'observed_text': value}]}
    try:
        with capture(EphemeralCipher(), tenant=TENANT, scan_id='a'*32) as sink:
            session.public_snapshot = callback_for(sink)
            session.on_collection(source)
            sink.retain_redaction(value, hashlib.sha256(value.encode()).hexdigest())
            session._flush_pending()
            assert value not in json.dumps(session.collections[('bucket', SCOPE)])
            assert source['items'][0]['observed_text'] == value
    finally:
        session.close()


def test_private_witness_bindings_survive_native_replay(monkeypatch, tmp_path):
    value = 'synthetic-private-witness-1329'
    fp = hashlib.sha256(value.encode()).hexdigest()
    session, _, _, _ = manual_session(monkeypatch, tmp_path)
    source = {'type': 'bucket', 'scope': SCOPE, 'status': 'collected', 'items': [{
        'id': 'one', 'observed_text': value,
        'leaks': [{'fingerprint': fp, 'locations': [{'path': 'fixture-file'}]}]}]}
    try:
        with capture(EphemeralCipher(), tenant=TENANT, scan_id='a'*32) as sink:
            sink.remember(value, fp, {'resource_id': 'one', 'scope': SCOPE,
                'path': 'fixture-file', 'witness_path': 'fixture-file'}, 'synthetic', 'fixture', set())
            session.public_snapshot = callback_for(sink)
            session.on_collection(source)
            session._flush_pending()
            session.on_collection(source)
            session._flush_pending()
            private = sink.cipher.decrypt(sink.records[fp])
            assert private['value'] == value
            location = private['locations'][0]
            assert location['_canonical_resource_id'] == 'one'
            assert location['_canonical_scope'] == SCOPE
            assert value not in json.dumps(session.collections[('bucket', SCOPE)])
    finally:
        session.close()


def worker_callback(namespace):
    tree = ast.parse(Path(worker.__file__).read_text())
    node = next(node for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef) and node.name == 'public_checkpoint')
    exec(compile(ast.Module(body=[node], type_ignores=[]), worker.__file__, 'exec'), namespace)
    return namespace['public_checkpoint']


@pytest.mark.parametrize('branch', ['disabled', 'no_entries', 'bound', 'error'])
def test_worker_reseals_only_changed_access_metadata(branch, tmp_path):
    calls = []
    def counted(value):
        calls.append(1)
        return seal(value)
    def peek():
        if branch == 'error':
            raise RuntimeError('synthetic private provider error')
        return [{'provider': 'fixture'}] if branch == 'bound' else []
    namespace = dict(vars(worker), seal=counted, redact=redact,
        secret_capture=SimpleNamespace(public_snapshot=lambda value: value),
        # The worker binds this outer-scope adapter before defining the callback.
        public_content=public_snapshot_adapter(lambda value: value, provider='aws', trusted_scopes=[SCOPE]),
        connector={'auth': {}}, request={'ai_enabled': branch != 'disabled'},
        credential_redaction=credential_redaction({'auth': {}}, worker.credential_values),
        ai_access=SimpleNamespace(peek=peek, bind_targets=lambda entries, public: entries),
        ai_access_cache={}, artifacts=object(), tenant=TENANT, ident='a'*32, _cached_ai_access_reference=lambda *a: 'opaque-private-reference')
    callback = worker_callback(namespace)
    raw = {'schema_version':'1.0','provider':'aws','scopes':[SCOPE],
           'created_at':'2026-10-24T00:00:00Z','collections':[], 'metadata':{}}
    public = callback(raw)
    assert validate(public) == public
    if branch in {'disabled', 'no_entries'}:
        assert len(calls) == 1 and public == seal(raw)
    else:
        assert len(calls) == 2
        key = 'ai_access_reference' if branch == 'bound' else 'ai_access_status'
        assert public['metadata'][key] == ('opaque-private-reference' if branch == 'bound' else 'unavailable')
    assert raw['metadata'] == {}
