"""Durable collection and analysis with optional post-scan AI and fenced jobs."""
import argparse
import hashlib
import json
import logging
import multiprocessing
import os
import re
import signal
import threading
import time
import traceback
from pathlib import Path
from fastapi import HTTPException
from peaso.auth import Authenticator, CredentialCipher, redact
from peaso.auth.secrets import credential_values
from peaso.server.config import Settings
from peaso.storage import SQLiteStore, FileArtifacts, S3Artifacts, StoreError
from peaso.storage.runtime import stores, WorkflowDispatcher

from peaso.runtime_metrics import span as _runtime_span

LOGGER = logging.getLogger(__name__)


def _worker_cgroup_memory():
    """Read only bounded numeric memory facts for this process's cgroup v2."""
    def read(path):
        with Path(path).open(encoding='ascii') as stream:
            value = stream.read(65537)
        if len(value) > 65536:
            raise ValueError('memory metadata bound')
        return value.strip()

    def number(value):
        if not re.fullmatch(r'[0-9]{1,20}', value) or int(value) > 2**64 - 1:
            raise ValueError('memory counter malformed')
        return int(value)

    try:
        memberships = [line.split(':', 2)[2] for line in read('/proc/self/cgroup').splitlines()
                       if line.startswith('0::')]
        if len(memberships) != 1:
            return None
        member = memberships[0]
        if not member.startswith('/') or '..' in member.split('/'):
            return None
        groups = []
        for line in read('/proc/self/mountinfo').splitlines():
            left, separator, right = line.partition(' - ')
            parts = right.split()
            if not separator or not parts or parts[0] != 'cgroup2':
                continue
            fields = left.split()
            if len(parts) < 3 or len(fields) < 6:
                return None
            unescape = lambda value: re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), value)
            root, mount = map(unescape, (fields[3], fields[4]))
            if not all(value.startswith('/') and '..' not in value.split('/') for value in (root, mount)):
                return None
            if root == '/':
                relative = member.lstrip('/')
            elif member == '/' or member == root:
                relative = ''
            elif member.startswith(root.rstrip('/') + '/'):
                relative = member[len(root):].lstrip('/')
            else:
                continue
            groups.append(Path(mount) / relative)
        if len(groups) != 1:
            return None
        group = groups[0]
        try:
            events, source = read(group / 'memory.events.local'), 'local'
        except OSError:
            events, source = read(group / 'memory.events'), 'hierarchical'
        counters = {}
        for line in events.splitlines():
            key, value = line.split()
            if key in {'low', 'high', 'max', 'oom', 'oom_kill', 'oom_group_kill'}:
                if key in counters:
                    return None
                counters[key] = number(value)
        if 'oom_kill' not in counters:
            return None
        maximum = read(group / 'memory.max')
        return {'_group': str(group), 'source': source, 'events': counters,
                'current': number(read(group / 'memory.current')),
                'peak': number(read(group / 'memory.peak')),
                'max': None if maximum == 'max' else number(maximum)}
    except (OSError, ValueError, IndexError, UnicodeError):
        return None


def _log_worker_interruption(process, memory_before):
    """Capture natural exit before cleanup; cgroup OOM facts never name a victim."""
    exitcode = getattr(process, 'exitcode', None)
    exitcode = exitcode if type(exitcode) is int else None
    memory_after = _worker_cgroup_memory() if exitcode is not None else None
    delta = None
    if (memory_before is not None and memory_after is not None
            and memory_before['_group'] == memory_after['_group']
            and memory_before['source'] == memory_after['source']):
        difference = memory_after['events']['oom_kill'] - memory_before['events']['oom_kill']
        if difference >= 0:
            delta = difference
    public_memory = lambda value: None if value is None else {key: value[key] for key in
        ('source', 'events', 'current', 'peak', 'max')}
    LOGGER.warning('Scan worker interrupted: child_exitcode=%s child_signal=%s '
                   'natural_exit_observed=%s cleanup_started=false group_oom_kill_delta=%s '
                   'group_memory_before=%s group_memory_after=%s',
                   exitcode, -exitcode if exitcode is not None and exitcode < 0 else None,
                   exitcode is not None, delta,
                   json.dumps(public_memory(memory_before), sort_keys=True),
                   json.dumps(public_memory(memory_after), sort_keys=True))


_EXPIRED_CODES = frozenset({"ExpiredToken", "ExpiredTokenException", "RequestExpired",
                            "TokenExpired", "token_expired", "invalid_grant"})


def _expired_exception(exc):
    response = getattr(exc, "response", None)
    error = response.get("Error", {}) if isinstance(response, dict) else {}
    return error.get("Code") in _EXPIRED_CODES or getattr(exc, "code", None) in _EXPIRED_CODES


def _expired_iam_report_error(envelope):
    """Read only the collector-owned IAM report status, never policy/app JSON."""
    if (not isinstance(envelope, dict) or envelope.get("service") != "iam"
            or envelope.get("type") not in {"iam_user", "iam_group", "iam_role", "iam_policy"}):
        return None
    account = str(envelope.get("scope", "")).split("/", 1)[0]
    kind = envelope["type"].removeprefix("iam_")
    for item in envelope.get("items", ()):
        if not isinstance(item, dict):
            continue
        arn = item.get("Arn")
        match = re.fullmatch(r"arn:[^:]+:iam::([0-9]{12}):" + kind + r"/.+", arn) if isinstance(arn, str) else None
        if match is None or match.group(1) != account:
            continue
        state = item.get("ServicesLastAccessedStatus")
        if (not isinstance(state, dict)
                or state.get("collection_status") not in {"denied", "unknown", "timeout", "partial", "malformed", "not_collected"}
                or state.get("operation", "iam:GetServiceLastAccessedDetails") != "iam:GetServiceLastAccessedDetails"
                or state.get("principal_arn", arn) != arn):
            continue
        error = state.get("error")
        if isinstance(error, dict) and error.get("code") in {"ExpiredToken", "ExpiredTokenException", "RequestExpired"}:
            return {"code": error["code"]}
    return None


def _expired_snapshot(snapshot):
    """Only explicit provider expiry codes qualify; ordinary denial stays denied."""
    for envelope in snapshot.get("collections", ()):
        error = envelope.get("error") or {}
        if error.get("code") in _EXPIRED_CODES:
            return True
        if any(item.get("code") in _EXPIRED_CODES for item in error.get("additional_errors", ()) if isinstance(item, dict)):
            return True
        if snapshot.get("provider") == "aws" and _expired_iam_report_error(envelope):
            return True
    return False


def _retryable_expired_snapshot(snapshot):
    """Keep IAM facts but leave an expired attached report unfinished for resume."""
    if snapshot.get("provider") != "aws":
        return snapshot
    rows = None
    for index, envelope in enumerate(snapshot.get("collections", ())):
        if envelope.get("status") not in {"collected", "empty"}:
            continue
        error = _expired_iam_report_error(envelope)
        if error is None:
            continue
        if rows is None:
            rows = list(snapshot["collections"])
        original_error = envelope.get("error")
        if isinstance(original_error, dict) and original_error:
            error = dict(original_error, additional_errors=[*original_error.get("additional_errors", ()), error])
        rows[index] = dict(envelope, status="partial", error=error)
    return dict(snapshot, collections=rows) if rows is not None else snapshot


def _resume_prior(checkpoint_session, prior):
    """Use every restored delta when a cumulative report lags collection."""
    if prior.get("metadata", {}).get("intentional_partial") is not True:
        checkpoint_session.restore_final(prior)
        return prior
    metadata = dict(prior.get("metadata") or {})
    for key in ("intentional_partial", "scope_coverage", "incremental", "sections"):
        metadata.pop(key, None)
    rows = list(checkpoint_session.collections.values())
    if not rows:
        raise ValueError("No restored checkpoint batches")
    # Do not copy a multi-account native inventory here: partition() validates
    # the composed candidate once and the checkpoint session retains its rows.
    return {"schema_version": prior["schema_version"], "provider": prior["provider"],
            "scopes": sorted({row["scope"] for row in rows}),
            "created_at": prior["created_at"], "collections": rows, "metadata": metadata}



def _seed_section_refresh(session, prior, revisions):
    """Preserve unchanged evidence revisions; never replay a damaged final over deltas."""
    with session.lock:
        session.collections = {(row['type'], row['scope']): row for row in prior['collections']}
        session.collection_revisions = {key: revisions.get(key, session.sequence)
                                        for key in session.collections}
        if prior.get('metadata', {}).get('native_refresh', {}).get('restored_native_context') == 'partial':
            session.collection_revisions = {key: session.sequence for key in session.collections}
        session.last_published = session.sequence


def _merge_section_refresh(snapshot, saved_rows, prior, plan):
    """Fresh native namespaces win; captured facts keep their exact target boundary."""
    import copy
    from peaso.snapshot import make_snapshot
    if snapshot['provider'] != prior['provider'] or snapshot['scopes'] != prior['scopes']:
        raise ValueError('Native section refresh returned a different target')
    rows = {(row['type'], row['scope']): row for row in snapshot['collections']}
    for row in saved_rows:
        rows.setdefault((row['type'], row['scope']), row)
    metadata = copy.deepcopy(prior.get('metadata') or {})
    metadata.update(snapshot.get('metadata') or {})
    if 'collection_plan' in prior.get('metadata', {}):
        metadata['collection_plan'] = copy.deepcopy(prior['metadata']['collection_plan'])
    metadata['native_refresh'] = {'plan_sha256': plan['plan_sha256'],
        'source_snapshot_id': prior['snapshot_id'], 'sections': list(plan['sections']),
        'reused_collections': len(saved_rows)}
    if prior.get('metadata', {}).get('native_refresh', {}).get('restored_native_context') == 'partial':
        metadata['native_refresh']['restored_native_context'] = 'partial'
    return make_snapshot(snapshot['provider'], prior['scopes'], list(rows.values()),
                         metadata=metadata, created_at=snapshot['created_at'])

def _partial_reuse_allowed(connector, partial_metadata):
    if partial_metadata is None:
        return True
    if connector["provider"] != "aws":
        return False
    plan = (partial_metadata.get("incremental") or {}).get("scope_plan")
    return plan is None or set(plan) == set(connector.get("scopes") or [])


def _verify_aws_credentials(connector):
    """Reject an expired selected session before scheduling native inventory."""
    if (connector.get("provider") != "aws" or
            connector.get("input_mode") in {"offline_snapshot", "demo"}):
        return
    from botocore.config import Config
    from peaso.collectors.aws import _session
    try:
        region = (connector.get("options", {}).get("regions") or ["us-east-1"])[0]
        session, _ = _session(connector.get("auth", {}), region)
        session.client("sts", config=Config(connect_timeout=5, read_timeout=10,
            retries={"max_attempts": 1})).get_caller_identity()
    except Exception as exc:
        # Provider exceptions can contain request/credential details. Keep this
        # early failure within the existing sanitized credential error path.
        if _expired_exception(exc):
            raise CredentialExpired("AWS connector authentication failed before collection") from None
        raise PermissionError("AWS connector authentication failed before collection") from None


class CredentialExpired(PermissionError):
    pass


def _import_checks():
    import peaso.checks  # noqa: F401


def _verify_aws_credentials_while(connector, work):
    """Run CPU-bound ``work`` while the AWS STS preflight waits on the network.

    Every live collection imports the native check registry before it plans
    collection, so importing it during the credential round trip only moves
    work earlier. Modules the preflight needs are imported here first, so the
    preflight thread never imports a peaso module concurrently with ``work``.
    Credential errors still surface before any collection is scheduled.
    """
    if (connector.get("provider") != "aws" or
            connector.get("input_mode") in {"offline_snapshot", "demo"}):
        _verify_aws_credentials(connector)
        return work()
    import boto3  # noqa: F401
    import botocore.config  # noqa: F401
    import peaso.collectors.aws  # noqa: F401
    failure = []

    def verify():
        try:
            _verify_aws_credentials(connector)
        except BaseException as exc:
            failure.append(exc)

    thread = threading.Thread(target=verify, name="peaso-credential-preflight", daemon=True)
    thread.start()
    try:
        result = work()
    finally:
        thread.join()
    if failure:
        raise failure[0]
    return result


class _SynchronizedPipe:
    """Serialize child progress and background checkpoint frames on one pipe."""
    def __init__(self, connection):
        self.connection = connection
        self.lock = threading.Lock()

    def send(self, value):
        with self.lock:
            self.connection.send(value)

    def recv(self):
        return self.connection.recv()

    def close(self):
        self.connection.close()


def _restore_secret_capture(sink, artifacts, tenant, scan_id):
    """Carry encrypted prior witnesses into a reclaimed collector attempt."""
    from peaso.secret_evidence import (SCHEMA, MAX_BYTES, MAX_LOCATIONS, MAX_VALUES,
                                       private_reference, _lock as private_evidence_lock)
    document = artifacts.get(tenant, private_reference(tenant, scan_id))
    if (not isinstance(document, dict) or document.get("schema") != SCHEMA
            or document.get("tenant") != tenant or document.get("scan_id") != scan_id
            or not isinstance(document.get("records"), dict)
            or len(document["records"]) > MAX_VALUES or not isinstance(document.get("index"), str)):
        raise ValueError("Private checkpoint evidence boundary mismatch")
    index = sink.cipher.decrypt(document["index"])
    related = index.get("related") if isinstance(index, dict) else None
    if not isinstance(related, dict):
        raise ValueError("Private checkpoint index malformed")
    count, size = 0, 0
    for fingerprint, sealed in document["records"].items():
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint) or not isinstance(sealed, str):
            raise ValueError("Private checkpoint record malformed")
        row = sink.cipher.decrypt(sealed)
        if not isinstance(row, dict) or not isinstance(row.get("value"), str) or not isinstance(row.get("locations"), list):
            raise ValueError("Private checkpoint record malformed")
        count += len(row["locations"])
        size += len(sealed) + len(fingerprint)
    if count > MAX_LOCATIONS or size > MAX_BYTES:
        raise ValueError("Private checkpoint evidence budget exceeded")
    with private_evidence_lock:
        sink.records = dict(document["records"])
        sink.related = {key: set(value) for key, value in related.items()
                        if isinstance(key, str) and isinstance(value, list)
                        and all(isinstance(item, str) for item in value)}
        sink.locations, sink.bytes = count, size
        sink.related_count = sum(len(value) for value in sink.related.values())
        sink.incomplete = bool(document.get("incomplete"))


def _reusable_stages(artifacts, tenant, sections, stage_results):
    """Accept only stage artifacts bound to a complete final data revision."""
    reused = {}
    for stage, result in (stage_results or {}).items():
        if stage not in {"network", "hardening", "exposure"} or not isinstance(result, dict):
            continue
        section = sections.get(stage)
        if (not isinstance(section, dict) or section.get("status") != "complete"
                or section.get("data_revision") != result.get("data_revision")):
            continue
        try:
            artifact = artifacts.get(tenant, result["result_ref"])
        except (KeyError, ValueError, OSError):
            continue
        if (isinstance(artifact, dict) and artifact.get("stage") == stage
                and artifact.get("data_revision") == result.get("data_revision")
                and isinstance(artifact.get("result"), dict)):
            reused[stage] = artifact["result"]
    return reused


def _cached_ai_access_reference(artifacts, tenant, ident, bound, cache, identity_dir):
    """Keep one sealed reference per exact bound access set in this scan process."""
    marker = hashlib.sha256(json.dumps(bound, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
    key = (tenant, ident, marker)
    reference = cache.get(key)
    if reference is None:
        from peaso.ai.crypto import AICipher
        reference = artifacts.put(tenant, ident, "ai-access", {"sealed":
            AICipher(identity_dir).encrypt({"entries": bound})})
        cache[key] = reference
    return reference

_ROLE_ARN = re.compile(r"arn:(?:aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}\Z")
_TARGET_MESSAGES = {
    "external_id_not_required_by_trust": "trust policy does not require External ID; add the sts:ExternalId condition shown in onboarding.",
    "external_id_trust_unverified": "the role's External ID boundary could not be verified; require an exact workspace External ID and retry.",
    "platform_owned_account": "this platform account cannot be a customer scan target.",
    "role_target_limit": "the hosted scan limit of 50 role targets was reached.",
}


def _curated_target_reasons(snapshot, connector):
    """Build bounded public reasons from known codes and configured role ARNs only."""
    if connector.get("provider") != "aws" or not connector.get("options", {}).get("hosted"):
        return []
    auth = connector.get("auth", {})
    roles = [auth.get("role_arn"), *auth.get("assume_roles", [])]
    configured = set()
    for entry in roles:
        arn = entry.get("role_arn") if isinstance(entry, dict) else entry
        if isinstance(arn, str) and _ROLE_ARN.fullmatch(arn):
            configured.add(arn)
    metadata = snapshot.get("metadata", {})
    if not isinstance(metadata, dict):
        return []
    errors = metadata.get("authentication_errors", [])
    if not isinstance(errors, list):
        return []
    reasons = []
    for entry in errors[:50]:
        if not isinstance(entry, dict) or not isinstance(entry.get("error"), dict):
            continue
        code, account = entry["error"].get("code"), entry.get("account")
        if not isinstance(code, str) or code not in _TARGET_MESSAGES or not isinstance(account, str):
            continue
        arn = entry.get("role_arn")
        if not isinstance(arn, str) or arn not in configured or arn.split(":")[4] != account:
            continue
        reasons.append({"code": code, "role_arn": arn,
                        "message": f"Role {arn} was refused: {_TARGET_MESSAGES[code]}"})
    return reasons


def _safe_failure_details(exc):
    """Diagnose application failures without logging exception values or locals."""
    root = Path(__file__).resolve().parent
    allowed = {"ValueError", "TypeError", "KeyError", "IndexError", "AttributeError", "ImportError",
               "ModuleNotFoundError", "PermissionError", "TimeoutError", "RuntimeError", "AssertionError"}
    name = type(exc).__name__
    details = {"exception_type": name if name in allowed else "provider_error", "source": "unavailable"}
    for frame in reversed(traceback.extract_tb(exc.__traceback__)):
        try:
            relative = Path(frame.filename).resolve().relative_to(root)
        except ValueError:
            continue
        if relative.suffix == ".py" and all(part.replace("_", "").replace(".", "").isalnum() for part in relative.parts):
            details["source"] = "peaso/" + relative.as_posix() + ":" + str(frame.lineno)
            break
    return details


def _collector_checkpoint_publisher(artifacts, publication_artifacts, tenant, ident,
                                    secret_capture, private_checkpoint, connection):
    """Durable raw batches must not wait for cumulative report rendering.

    Private-document writes and pipe exchanges remain serialized. Expensive
    public serialization/uploads run outside that lock; a full report refreshes
    private evidence again before its reference becomes visible.
    """
    from peaso.secret_evidence import without_private_values, _lock as private_evidence_lock
    handoff_lock = threading.Lock()

    def commit_private():
        with private_evidence_lock:
            document = private_checkpoint.document(secret_capture)
        artifacts.put_secret_evidence(tenant, ident, document)

    def checkpoint(snapshot, report, sequence):
        with _runtime_span("worker.public_checkpoint"):
            with handoff_lock:
                commit_private()
            snapshot_ref = artifacts.put(tenant, ident, "snapshot", snapshot)
            if report is not None:
                from peaso.storage.reports import publish_report
                report_ref = publish_report(publication_artifacts, tenant, ident,
                                            without_private_values(redact_report(report, fields=False)), snapshot)
            else:
                report_ref = None
            batch = (report is None and 'batch_revisions' in
                     snapshot.get('metadata', {}).get('incremental', {}))
            envelope = snapshot["collections"][0] if report is None and not batch else None
            with handoff_lock:
                if report is not None:
                    # Capture may advance while the public report is built. Never
                    # overwrite a newer private document with an older publisher.
                    commit_private()
                connection.send(("__checkpoint__", {"sequence": sequence, "stage": "collector",
                    "snapshot_ref": snapshot_ref, "report_ref": report_ref,
                    "kind": '__checkpoint_batch__' if batch else envelope["type"] if envelope else None,
                    "scope": str(sequence) if batch else envelope["scope"] if envelope else None}))
                if connection.recv() != ("__checkpoint_ack__", sequence, True):
                    raise RuntimeError("checkpoint lease or publication rejected")

    return checkpoint


# One placeholder scope per provider: an empty evaluation of the job's provider
# runs every lazy per-process install (admission bundles, framework and report
# template tables) that the first real evaluation would otherwise pay.
_PREWARM_SCOPES = {"aws": "123456789012", "gcp": "peaso-prewarm", "azure": "00000000-0000-0000-0000-000000000000",
                   "k8s": "peaso-prewarm"}


def _prewarm_evaluation(provider):
    scope = _PREWARM_SCOPES.get(provider)
    if scope is None:
        return
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot
    evaluate_snapshot(make_snapshot(provider, [scope], [], created_at="2026-01-01T00:00:00+00:00"),
                      include_not_applicable=False)


def _prewarmed_process(connection, provider=None):
    """Import and prove the native engine before an analyzer job arrives.

    The progressive analyzer starts this child while collection is still
    running, so the one-time pinned-source proof of ``peaso.checks`` uses idle
    analyzer time instead of delaying final evaluation. The job request then
    follows the exact fresh-child path; an import failure is reported there.
    """
    with open(os.devnull, "w") as sink:
        os.dup2(sink.fileno(), 1)
        os.dup2(sink.fileno(), 2)
    try:
        import peaso.checks  # noqa: F401
        import peaso.engine  # noqa: F401
        _prewarm_evaluation(provider)
    except Exception:  # noqa: BLE001 - _process re-imports and reports the failure
        pass
    try:
        message = connection.recv()
    except (EOFError, OSError):
        return
    if not (isinstance(message, tuple) and len(message) == 3 and message[0] == "__job__"):
        return
    _process(message[1], message[2], connection)


def _process(role, request, connection):
    connection = _SynchronizedPipe(connection)
    from peaso import runtime_metrics
    runtime_metrics.configure(connection.send, role=role)
    aws_metrics = None
    detector_metrics = None
    if role == "collector" and request.get("connector", {}).get("provider") == "aws":
        from peaso.aws_call_metrics import install as install_aws_metrics
        aws_metrics = install_aws_metrics(connection.send)
    if role == "collector":
        from peaso.secret_scanning_batch import configure_metrics
        configure_metrics(connection.send)
    # Provider exceptions and third-party libraries must never log credentials.
    with open(os.devnull, "w") as sink:
        os.dup2(sink.fileno(), 1)
        os.dup2(sink.fileno(), 2)
    failure_reasons = []
    resume_reference = None
    def stop_child(*_):
        raise SystemExit()
    signal.signal(signal.SIGTERM, stop_child)
    try:
        if role == "collector" and "deadline" in request:
            from peaso.collection_lease import configure as configure_collection_lease
            configure_collection_lease(request["deadline"])
        if role == "collector":
            # Optional diagnostics must never prevent a scan from starting.
            try:
                from peaso.detector_call_metrics import install as install_detector_metrics
                detector_metrics = install_detector_metrics(runtime_metrics.span)
            except Exception:
                pass
        config = request.pop("artifact_config")
        artifacts = FileArtifacts(Path(config["root"])) if config["mode"] == "file" else S3Artifacts(config["bucket"], kms_key=config.get("kms_key"))
        tenant, ident = request["tenant_id"], request["scan_id"]
        from peaso.storage.report_reuse import ReusableReportArtifacts
        publication_artifacts = ReusableReportArtifacts(artifacts, tenant, ident)
        if role == "collector":
            proof = request.pop("resume_proof", None)
            if proof is not None:
                from peaso.server.scan_resume import validate_resume_proof
                validate_resume_proof(proof, artifacts, tenant, ident,
                                      request["connector"], request.get("checkpoint_refs", []))
            with _runtime_span('worker.startup'):
                _verify_aws_credentials_while(request.get("connector", {}), _import_checks)
                from peaso.engine import collect_snapshot
            from peaso.snapshot import seal
            connector = request.get("connector", {})
            refresh_state = None
            if request.get('section_refresh_proof') is not None:
                from peaso.server.scan_resume import validate_claimed_section_refresh
                refresh_proof = request['section_refresh_proof']
                refresh_state = validate_claimed_section_refresh(refresh_proof['row'],
                    refresh_proof['entries'], artifacts, connector)
            if (role == "collector" and connector.get("provider") == "gcp"
                    and connector.get("auth", {}).get("method") == "platform-service-account"):
                from peaso.gcp_platform import load_service_account
                connector["auth"]["sa_json"] = load_service_account(Settings().gcp_platform_sa_secret_arn)
            from peaso.ai import access as ai_access
            if request.get("ai_enabled", True):
                # Scope labels do not restrict AWS or shared GCP credentials.
                ai_access.begin(allow_live=ai_access.may_capture_live(connector))
            from peaso.secret_evidence import capture
            from peaso.content_scan_selection import capture_checks, effective_options
            from peaso.private_evidence_checkpoint import PrivateEvidenceCheckpoint
            private_checkpoint = PrivateEvidenceCheckpoint()
            evidence_cipher = CredentialCipher(Path(request.get('ai_context', {}).get('identity_dir') or Settings().identity_dir))
            with capture(evidence_cipher, tenant=tenant, scan_id=ident, options=effective_options(request),
                         selected_checks=capture_checks(request)) as secret_capture:
                from peaso.incremental import CheckpointSession
                from peaso.secret_evidence import _lock as private_evidence_lock, without_private_values
                if request.get("checkpoint_refs"):
                    _restore_secret_capture(secret_capture, artifacts, tenant, ident)

                from peaso.snapshot_public_identity import public_snapshot_adapter
                public_content = public_snapshot_adapter(secret_capture.public_snapshot,
                    provider=connector["provider"], trusted_scopes=connector.get("scopes") or ["*"])
                ai_access_cache = {}
                from peaso.redaction_memo import credential_redaction as _credential_redaction
                # Each unchanged public collection is redacted once per exact
                # credential set across items, batches and cumulative reports.
                credential_redaction = _credential_redaction(connector, credential_values)

                def public_checkpoint(raw):
                    public = seal(credential_redaction(public_content(raw)))
                    changed = False
                    if request.get("ai_enabled", True):
                        try:
                            entries = ai_access.peek()
                            bound = ai_access.bind_targets(entries, public) if entries else []
                            if bound:
                                reference = _cached_ai_access_reference(artifacts, tenant, ident,
                                    bound, ai_access_cache, Path(request.get('ai_context', {}).get('identity_dir') or Settings().identity_dir))
                                public.setdefault("metadata", {})["ai_access_reference"] = reference
                                changed = True
                        except Exception:
                            public.setdefault("metadata", {})["ai_access_status"] = "unavailable"
                            changed = True
                    # The first seal already binds every redacted native fact.
                    # Recompute only when the access metadata changed afterward.
                    return seal(public) if changed else public

                public_checkpoint = public_snapshot_adapter(public_checkpoint,
                    provider=connector["provider"], trusted_scopes=connector.get("scopes") or ["*"])
                from peaso.settle_memo import public_state
                # Envelope output depends only on native content, the exact
                # connector credentials and the capture's private state.
                public_checkpoint.settle_state = lambda: public_state(
                    credential_values(connector.get("auth", {})), secret_capture)

                checkpoint = _collector_checkpoint_publisher(artifacts, publication_artifacts,
                    tenant, ident, secret_capture, private_checkpoint, connection)

                checkpoint_session = CheckpointSession(request, checkpoint, public_checkpoint)
                restored = ([] if refresh_state is not None else [artifacts.get(tenant, reference) for reference in
                    dict.fromkeys(request.get("checkpoint_refs", ()))])
                checkpoint_session.restore(restored, int(request.get("checkpoint_sequence", 0)))
                saved_rows = []
                prior = None
                refresh_plan = None
                remaining = None
                if refresh_state is not None:
                    refresh_plan, prior, revisions = refresh_state
                    _seed_section_refresh(checkpoint_session, prior, revisions)
                    saved_rows = [row for row in prior['collections'] if row['type'] not in refresh_plan['kinds']]
                    remaining = refresh_plan['kinds']
                if request.get("resume_snapshot_ref") and refresh_plan is None:
                    from peaso.snapshot import validate
                    prior = validate(artifacts.get(tenant, request["resume_snapshot_ref"]))
                    if prior["provider"] != connector["provider"]:
                        raise ValueError("Resume snapshot provider mismatch")
                    partial_metadata = prior.get("metadata", {}) if prior.get("metadata", {}).get(
                        "intentional_partial") is True else None
                    prior = _resume_prior(checkpoint_session, prior)
                    from peaso.engine import plan_collection
                    from peaso.collectors.resume import partition, scoped_gcp_lookup
                    requirements = plan_collection(request)
                    # Cumulative checkpoints are evidence, not authority to
                    # omit dynamically discovered units. Only an explicit AWS
                    # regional plan matching the frozen target can reuse kinds.
                    if _partial_reuse_allowed(connector, partial_metadata):
                        lookup = scoped_gcp_lookup(connector, requirements, prior)
                        if lookup is not None:
                            connector.setdefault("options", {})["_resume_collection_lookup"] = lookup
                        else:
                            remaining, saved_rows = partition(connector, requirements, prior)
                    if saved_rows:
                        # The original selection is retained in the row and
                        # checkpoint session.  This per-attempt inventory plan
                        # schedules only unfinished native kinds.
                        connector.setdefault("options", {}).pop("collect_all", None)
                        connector["options"]["inventories"] = remaining
                request["_collection_callback"] = checkpoint_session.on_collection
                request["_scope_plan_callback"] = checkpoint_session.on_scope_plan
                try:
                    from peaso.worker_progress import stream_progress
                    from peaso.collectors.aws_iam_usage_extension import capture_contexts
                    from peaso.collectors.iam_usage_finalize import least_privilege_selected
                    with capture_contexts(enabled=(connector.get("provider") == "aws"
                            and least_privilege_selected("aws", request))) as aws_usage_contexts:
                        with stream_progress(connection):
                            if saved_rows and not remaining:
                                from peaso.snapshot import make_snapshot
                                snapshot = make_snapshot(prior["provider"], prior["scopes"], saved_rows,
                                    created_at=prior["created_at"], metadata=prior.get("metadata"))
                            else:
                                with _runtime_span('worker.collect'):
                                    if refresh_plan is not None:
                                        from peaso.server.scan_resume import section_refresh_collection_request
                                        snapshot = collect_snapshot(section_refresh_collection_request(request, refresh_plan))
                                    else:
                                        snapshot = collect_snapshot(request)
                        if refresh_plan is not None:
                            snapshot = _merge_section_refresh(snapshot, saved_rows, prior, refresh_plan)
                        elif saved_rows and remaining:
                            from peaso.collectors.resume import merge
                            snapshot = merge(snapshot, saved_rows, prior)
                        from peaso.collectors.iam_usage_finalize import enrich_snapshot as enrich_iam_usage
                        with _runtime_span("worker.iam_usage"):
                            snapshot = enrich_iam_usage(snapshot, connector, request, aws_usage_contexts)
                    with _runtime_span("worker.checkpoint.finish"):
                        checkpoint_session.finish_collection(final_metadata=snapshot.get("metadata", {}))
                    snapshot.setdefault("metadata", {})["sections"] = checkpoint_session.sections()
                finally:
                    with _runtime_span("worker.checkpoint.close"):
                        checkpoint_session.close()
                    request.pop("_collection_callback", None)
                    request.pop("_scope_plan_callback", None)
                    ai_credentials = ai_access.finish()
                    # The checkpoint thread has stopped and its public copies
                    # are durable. Release that cumulative inventory before
                    # redacting and serializing the full native snapshot.
                    del checkpoint_session
            # Separate encrypted per-scan object; no reference or value enters
            # the native snapshot, public report, supervisor pipe or AI context.
            from peaso.gc_pause import gc_paused
            with _runtime_span('worker.redact'), gc_paused():
                snapshot = public_content(snapshot)
            with _runtime_span("worker.private_document"):
                artifacts.put_secret_evidence(tenant, ident, private_checkpoint.document(secret_capture))
            if request.get("ai_enabled", True) and ai_credentials:
                try:
                    ai_credentials = ai_access.bind_targets(ai_credentials, snapshot)
                    access_reference = _cached_ai_access_reference(artifacts, tenant, ident,
                        ai_credentials, ai_access_cache, Path(request.get("ai_context", {}).get("identity_dir") or Settings().identity_dir))
                    snapshot.setdefault("metadata", {})["ai_access_reference"] = access_reference
                except Exception:
                    snapshot.setdefault("metadata", {})["ai_access_status"] = "unavailable"
            del ai_credentials
            from peaso.snapshot import nothing_readable
            expired = _expired_snapshot(snapshot)
            if expired:
                snapshot = _retryable_expired_snapshot(snapshot)
            if nothing_readable(snapshot) and not expired:
                # Every read failed (expired/wrong credentials): fail the scan instead of publishing an empty assessment.
                failure_reasons = _curated_target_reasons(snapshot, request["connector"])
                raise PermissionError("no collection was readable with the connector credentials")
            snapshot.setdefault("metadata", {})["input_mode"] = request["connector"].get("input_mode", "live")
            with _runtime_span('worker.final_snapshot'), gc_paused():
                # redact() returns a fresh plain copy; seal adopts it instead
                # of copying the complete native inventory a second time.
                public_final = public_snapshot_adapter(
                    lambda native: seal(redact(native, tuple(credential_values(
                        request["connector"].get("auth", {}))), fields=False), owned=True), provider=connector["provider"], trusted_scopes=connector.get("scopes") or ["*"])
                value = public_final(snapshot)
            reference = artifacts.put(tenant, ident, "snapshot", value)
            if expired:
                resume_reference = reference
                raise CredentialExpired
        else:
            with _runtime_span('worker.startup'):
                from peaso.engine import evaluate_snapshot
            selectors = request["selectors"]
            from peaso.snapshot import frozen_view
            # Freeze the native items once; evaluation, publication and AI
            # review share them instead of each making a read-only copy.
            snapshot = frozen_view(artifacts.get(tenant, request["snapshot_ref"]))
            from peaso.related_snapshots import related_view
            related, sources = [], {}
            for entry in request.get("related", []):
                try:
                    item = artifacts.get(tenant, entry["snapshot_ref"])
                except Exception:  # noqa: BLE001 - an expired/removed sibling snapshot only means no join
                    continue
                # One full document at a time: the view drops the kinds no
                # privesc join reads, and the loaded document is released.
                item = related_view(item)
                related.append(item)
                sources[item.get("snapshot_id")] = {"scan_id": entry["scan_id"], "connector_id": entry["connector_id"]}
            item = None
            with _runtime_span('worker.evaluate'):
                report = evaluate_snapshot(snapshot, categories=selectors.get("categories") if selectors.get("content_checks") else selectors.get("categories") or None,
                               checks=selectors.get("checks") or None, frameworks=selectors.get("frameworks") or None,
                               content_checks=selectors.get("content_checks"),
                               include_not_applicable=bool(selectors.get("include_not_applicable", False)),
                               related_snapshots=related)
            # Only the privesc join reads related snapshots; publication and AI
            # review never do, so release them before those long phases.
            del related
            for row in report.get("related_snapshots", []):
                row.update(sources.get(row["snapshot_id"], {}))
            with _runtime_span('worker.redact'):
                value = redact_report(report, fields=False)
            value["input_mode"] = snapshot.get("metadata", {}).get("input_mode", "live")
            from peaso.storage.cost import runtime_estimate
            value["runtime"] = runtime_estimate(request["timeline"])
            from peaso.storage.reports import publish_report
            native_sequence = int(request.get("checkpoint_sequence", 0)) + 1
            # Snapshot-only artifacts are shared by the native and final bundles.
            publication_shared = {}
            sections = snapshot.get("metadata", {}).get("sections", {})
            sections = sections if isinstance(sections, dict) else {}
            from peaso.ai.pipeline import review_scan
            ai_disabled = selectors.get("ai_enabled", True) is False
            if ai_disabled:
                # The disabled branch is deterministic and performs no provider
                # or model work. Include its actual result in the first durable
                # native bundle instead of rebuilding every export afterward.
                with _runtime_span('worker.ai'):
                    value["ai"] = review_scan(value, snapshot, selectors, tenant=tenant, artifacts=artifacts,
                                              deadline=request.get("deadline"), context=request.get("ai_context"))
            native_value = dict(value, publication={"state": "final" if ai_disabled else "partial",
                "phase": "completed" if ai_disabled else "analyzing",
                "sequence": native_sequence, "sections": sections})
            with _runtime_span('worker.final_publish'):
                native_reference = publish_report(publication_artifacts, tenant, ident, native_value, snapshot,
                                                  _shared=publication_shared)
            connection.send(("__checkpoint__", {"sequence": native_sequence,
                "stage": "analyzer_native", "snapshot_ref": request["snapshot_ref"],
                "report_ref": native_reference, "kind": None, "scope": None}))
            if connection.recv() != ("__checkpoint_ack__", native_sequence, True):
                raise RuntimeError("native analysis checkpoint rejected")
            if request.get("refresh_stage_results"):
                connection.send(("__stage_results__", None))
                reply = connection.recv()
                if (not isinstance(reply, tuple) or len(reply) != 2
                        or reply[0] != "__stage_results__" or not isinstance(reply[1], dict)):
                    raise RuntimeError("progressive stage result handoff rejected")
                request["stage_results"] = reply[1]
            reused_stages = _reusable_stages(artifacts, tenant, sections, request.get("stage_results"))
            if ai_disabled:
                # Acknowledgement and progressive-stage fencing above remain
                # mandatory. The exact final native bundle is already durable.
                reference = native_reference
            else:
                with _runtime_span('worker.ai'):
                    value["ai"] = review_scan(value, snapshot, selectors, tenant=tenant, artifacts=artifacts,
                                              deadline=request.get("deadline"), context=request.get("ai_context"),
                                              reused_stages=reused_stages)
                from peaso.ai.network import with_findings
                value = with_findings(value, value["ai"].get("network", {}).get("findings", []))
                value["publication"] = {"state": "final", "phase": "completed", "sequence": native_sequence,
                                        "sections": sections}
                with _runtime_span('worker.final_publish'):
                    reference = publish_report(publication_artifacts, tenant, ident, value, snapshot,
                                               _shared=publication_shared)
        # Large evidence/report objects never cross the supervisor process pipe.
        if aws_metrics is not None:
            aws_metrics.close()
        # Stop the heartbeat and emit the final frame before the terminal
        # result: the supervisor stops reading once it receives the result.
        runtime_metrics.close()
        connection.send((True, reference))
    except BaseException as exc:
        if isinstance(exc, CredentialExpired) or _expired_exception(exc):
            code = "credentials_expired"
        elif isinstance(exc, (ValueError, TypeError, KeyError)):
            code = "invalid_input"
        elif isinstance(exc, ImportError):
            code = "dependency_unavailable"
        elif isinstance(exc, PermissionError):
            # OS errors name the inaccessible local artifact in filename. A
            # provider authorization failure has no local filename; never
            # include either the path or provider message in public details.
            code = "dependency_unavailable" if exc.filename else "credential_access_denied"
        elif isinstance(exc, TimeoutError):
            code = "collector_timeout"
        else:
            code = "provider_error"
        if aws_metrics is not None:
            aws_metrics.close()
        # Stop the heartbeat and emit the final frame before the terminal
        # result: the supervisor stops reading once it receives the result.
        runtime_metrics.close()
        connection.send((False, code, _safe_failure_details(exc), failure_reasons, resume_reference))
    finally:
        if detector_metrics is not None:
            try:
                detector_metrics.close()
            except Exception:
                pass
        if aws_metrics is not None:
            aws_metrics.close()
        runtime_metrics.close()
        connection.close()


def redact_report(report, *, fields=True):
    """redact() a report. check_frameworks / check_meta are keyed by public catalog check ids (e.g.
    "...client_secret"), so only their values are redacted, never the id keys: a secret-shaped id
    must not turn its per-check entry into "[REDACTED]". Published scan reports pass fields=False:
    secrets found in customer resources stay visible to the tenant."""
    per_check = {key: report[key] for key in ("check_frameworks", "check_meta") if isinstance(report.get(key), dict)}
    value = redact({key: item for key, item in report.items() if key not in per_check}, fields=fields)
    for key, mapping in per_check.items():
        value[key] = {check_id: redact(item, fields=fields) for check_id, item in mapping.items()}
    return value


# Scan group = same tenant: an analyzer run joins the latest collected snapshot of each other connector whose
# provider the privesc model joins with this one (K8s <-> clouds), so a GKE/EKS/AKS cluster scan and a scan of
# its cloud account/project show the cross-provider paths. Bounded in count and age (RAM, stale facts).
RELATED_PROVIDERS = {"k8s": {"aws", "gcp", "azure"}, "aws": {"k8s"}, "gcp": {"k8s"}, "azure": {"k8s"}}
RELATED_MAX_SNAPSHOTS = 8
RELATED_MAX_AGE_SECONDS = 8 * 86400  # a weekly schedule plus a day of slack


def related_snapshot_refs(store, job):
    """[{scan_id, connector_id, provider, snapshot_ref}] for the analyzer job's scan group (newest per connector)."""
    tenant = job["tenant"]
    provider = json.loads(job["connector"])["data"].get("provider")
    wanted = RELATED_PROVIDERS.get(provider, set())
    out, seen = [], {job["connector_id"]}
    if not wanted:
        return out
    for public in store.jobs(tenant):  # newest first
        if len(out) >= RELATED_MAX_SNAPSHOTS:
            break
        if public["id"] == job["id"] or public.get("connector_id") in seen or public["status"] not in {"collected", "analyzing", "completed"}:
            continue
        row = store.job(tenant, public["id"])
        if not row.get("snapshot") or abs(float(job["created"]) - float(row["created"])) > RELATED_MAX_AGE_SECONDS:
            continue
        other = json.loads(row["connector"])["data"].get("provider")
        if other not in wanted:
            continue
        seen.add(row["connector_id"])
        out.append({"scan_id": row["id"], "connector_id": row["connector_id"], "provider": other, "snapshot_ref": row["snapshot"]})
    return out


class Worker:
    def __init__(self, role, settings=None, *, store=None, artifacts=None, authenticator=None):
        self.settings = settings or Settings()
        self.role = role
        if store is None or artifacts is None:
            runtime_store, runtime_artifacts = stores(self.settings)
            store, artifacts = store or runtime_store, artifacts or runtime_artifacts
        self.store, self.artifacts = store, artifacts
        self.cipher = CredentialCipher(self.settings.identity_dir) if role == "collector" else None
        self.authenticator = authenticator or (Authenticator(self.settings) if role == "collector" else None)
        if isinstance(self.authenticator, Authenticator):
            self.authenticator.store = self.store
        self.stopping = threading.Event()
        self._prewarmed = None

    def prewarm(self, provider=None):
        """Start one analyzer child that imports the engine ahead of its job."""
        if self.role != "analyzer" or self._prewarmed is not None:
            return
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=True)
        process = context.Process(target=_prewarmed_process, args=(child, provider), daemon=True)
        try:
            process.start()
        except Exception:  # noqa: BLE001 - run_once falls back to a fresh child
            parent.close()
            return
        finally:
            child.close()
        self._prewarmed = (process, parent)

    def _take_prewarmed(self, request):
        warm, self._prewarmed = self._prewarmed, None
        if warm is None:
            return None
        process, parent = warm
        try:
            if not process.is_alive():
                raise OSError("prewarmed analyzer exited")
            parent.send(("__job__", self.role, request))
            return warm
        except Exception:  # noqa: BLE001 - discard it and spawn a fresh child
            self._discard(process, parent)
            return None

    @staticmethod
    def _discard(process, parent):
        parent.close()
        if process.is_alive():
            process.terminate()
        process.join(timeout=2)
        if process.is_alive():
            process.kill()
            process.join(timeout=2)

    def discard_prewarmed(self):
        warm, self._prewarmed = self._prewarmed, None
        if warm is not None:
            self._discard(*warm)

    def schedule_tick(self, now=None):
        if self.role != "collector":
            return []
        results = []
        for row in self.store.due_schedules(now):
            try:
                selectors = json.loads(row['data'])
                from peaso.server.schedule_credentials import scheduling_eligibility
                saved = self.store.connector(row['tenant'], selectors['connector_id'])
                data = json.loads(saved['data'])
                private = self.cipher.decrypt(saved['auth'])
                eligibility = scheduling_eligibility(data['provider'], private['auth'],
                    input_mode=data.get('input_mode'), options=private.get('options', {}), proof=private.get('scheduling_proof'), hosted=self.settings.auth_mode == 'cognito')
                if not eligibility['allowed']:
                    self.store.pause_schedule(row['tenant'], row['id'], reason=eligibility['reason'])
                    continue
                if selectors.get('ai_enabled', True):
                    from peaso.ai.auth import require_local_codex
                    require_local_codex(self.settings, self.store, selectors.get('ai_user_id', row['tenant']))
                paid = self.authenticator.is_paid(row["tenant"])
            except StoreError as exc:
                if exc.status == 404:
                    continue  # Connector deleted after the due-schedule read.
                raise
            except HTTPException as exc:
                if exc.status_code == 401:
                    self.store.pause_schedule(row["tenant"], row["id"])
                # An outage leaves the occurrence due for a later retry.
                continue
            result = self.store.trigger_schedule(row, 10 if paid else 1, self.settings.scan_timeout, now)
            if result:
                results.append(result)
                WorkflowDispatcher().dispatch(row["tenant"], result)
        return results

    def run_once(self, tenant=None, ident=None, *, stage_poll=None):
        job = self.store.claim(self.role, self.settings.lease_seconds, tenant=tenant, ident=ident)
        if not job:
            return False
        process, parent, child = None, None, None
        try:
            selectors = json.loads(job["data"])
            if self.role == "collector" and job.get("resume_phase") == "analyzer":
                if not job.get("snapshot"):
                    self.store.finish(job["id"], job["owner"], "failed", error_code="artifact_error")
                else:
                    self.store.finish(job["id"], job["owner"], "collected", job["snapshot"])
                return True
            if selectors.get('ai_enabled', True):
                from peaso.ai.providers import review_disabled
                if review_disabled(self.store, selectors.get('ai_user_id', job['tenant'])):
                    selectors['ai_enabled'] = False
            if self.role == "collector":
                encrypted = json.loads(job["connector"])
                private = self.cipher.decrypt(encrypted["auth"])
                connector = dict(encrypted["data"], auth=private["auth"], options=private["options"])
                if self.settings.auth_mode == "cognito":
                    from peaso.server.validation import validate_connector
                    validate_connector(connector["provider"], connector["auth"], connector["options"], self.settings,
                                       server_external_id=True, scopes=connector.get("scopes", []))
                    connector["options"] = dict(connector["options"], hosted=True)
                    if connector["provider"] == "aws" and connector["auth"].get("method") == "assume_role":
                        connector["auth"]["method"] = "access_keys" if connector["auth"].get("aws_access_key_id") else "task_role"
                elif connector["provider"] == "aws" and connector["auth"].get("method") == "assume_role":
                    connector["auth"]["method"] = "profile" if connector["auth"].get("profile") else "access_keys" if connector["auth"].get("aws_access_key_id") else "default"
                request = dict(selectors, connector=connector)
            else:
                request = {"snapshot_ref": job["snapshot"], "selectors": selectors,
                           "related": related_snapshot_refs(self.store, job),
                           "stage_results": self.store.stage_results(job["tenant"], job["id"])}
            if self.role == "analyzer" and stage_poll is not None:
                request["refresh_stage_results"] = True
            request["checkpoint_sequence"] = int(job.get("checkpoint_sequence") or 0)
            if self.role == "collector":
                checkpoint_rows = sorted(self.store.checkpoint_collections(job["tenant"], job["id"]),
                                         key=lambda row: row["sequence"])
                request["checkpoint_refs"] = [row["reference"] for row in checkpoint_rows]
                if job.get("resume_phase") == "collector":
                    from peaso.server.scan_resume import collector_source
                    reference = collector_source(job)
                    if reference:
                        request["resume_snapshot_ref"] = reference
                        if not job.get("snapshot"):
                            # The original terminal row's immutable refs and
                            # sequence are fenced by the new claim; the child
                            # performs the expensive content proof before SDKs.
                            proof_keys = ("tenant", "id", "connector", "resume_phase",
                                          "snapshot", "partial_snapshot", "partial_report",
                                          "partial_report_sequence", "checkpoint_sequence")
                            request["resume_proof"] = {"row": {key: job.get(key) for key in proof_keys},
                                                       "entries": checkpoint_rows}
            if self.role == 'collector' and job.get('native_refresh'):
                proof_keys = ('tenant', 'id', 'data', 'connector', 'resume_phase', 'resume_attempt',
                              'snapshot', 'report', 'checkpoint_sequence', 'native_refresh')
                request['section_refresh_proof'] = {'row': {key: job.get(key) for key in proof_keys},
                                                    'entries': checkpoint_rows}
            request.update(tenant_id=job["tenant"], scan_id=job["id"], deadline=job["deadline"], artifact_config={"mode": "file", "root": str(self.artifacts.root)} if isinstance(self.artifacts, FileArtifacts) else {"mode": "s3", "bucket": self.artifacts.bucket, "kms_key": self.artifacts.kms_key})
            request["ai_context"] = {"state_dir": str(self.settings.state_dir), "identity_dir": str(self.settings.identity_dir)}
            request["timeline"] = self.store.public_job(job)["timeline"]
            memory_before = _worker_cgroup_memory()
            warm = self._take_prewarmed(request) if self.role == "analyzer" else None
            if warm is not None:
                process, parent = warm
            else:
                context = multiprocessing.get_context("spawn")
                parent, child = context.Pipe(duplex=True)
                process = context.Process(target=_process, args=(self.role, request, child), daemon=True)
                process.start()
                child.close()
            next_heartbeat = 0
            result = None
            control_read = getattr(self.store, "job_control", self.store.job)
            stage_results_pending = False
            while not self.stopping.is_set():
                now = time.time()
                if now >= job["deadline"]:
                    self.store.expire_job(job["tenant"], job["id"], now)
                    return True
                if now >= next_heartbeat:
                    if not self.store.heartbeat(job["id"], job["owner"], self.settings.lease_seconds):
                        return True
                    next_heartbeat = now + max(0.2, self.settings.lease_seconds / 3)
                # Cancellation is checked independently of the heartbeat interval.
                control = control_read(job["tenant"], job["id"])
                if control["status"] not in {"collecting", "analyzing"}:
                    return True
                stages_settled = stage_poll(control) if stage_poll is not None else True
                if stage_results_pending and stages_settled:
                    parent.send(("__stage_results__", self.store.stage_results(job["tenant"], job["id"])))
                    stage_results_pending = False
                if parent.poll(0.2):
                    try:
                        result = parent.recv()
                        if (isinstance(result, tuple) and len(result) == 2
                                and result[0] == "__stage_results__"):
                            if self.role != "analyzer" or stage_poll is None or stage_results_pending:
                                raise RuntimeError("unexpected progressive stage result request")
                            stage_results_pending = True
                            result = None
                            continue
                        if isinstance(result, tuple) and len(result) == 2 and result[0] == "__aws_metrics__":
                            if self.role == "collector":
                                from peaso.aws_call_metrics import record_metrics as record_aws_metrics
                                record_aws_metrics(result[1], LOGGER)
                            result = None
                            continue
                        if isinstance(result, tuple) and len(result) == 2 and result[0] == "__runtime_metrics__":
                            from peaso.runtime_metrics import record
                            record(result[1], LOGGER)
                            result = None
                            continue
                        if isinstance(result, tuple) and len(result) == 2 and result[0] == "__content_metrics__":
                            from peaso.secret_scanning_batch import record_metrics
                            if self.role == "collector":
                                record_metrics(result[1], LOGGER)
                            result = None
                            continue
                        if isinstance(result, tuple) and len(result) == 2 and result[0] == "__progress__":
                            from peaso.worker_progress import record_progress
                            record_progress(self.store, job, result[1], LOGGER)
                            result = None
                            continue
                        if isinstance(result, tuple) and len(result) == 2 and result[0] == "__checkpoint__":
                            event = result[1]
                            accepted = self.store.record_checkpoint(job["tenant"], job["id"], job["owner"],
                                event["sequence"], event["snapshot_ref"], kind=event.get("kind"),
                                scope=event.get("scope"), report_ref=event.get("report_ref"),
                                stage=event.get("stage", "collector"))
                            parent.send(("__checkpoint_ack__", event["sequence"], bool(accepted)))
                            if not accepted:
                                return True
                            result = None
                            continue
                    except EOFError:
                        # A killed child cannot report a result. SIGKILL alone
                        # does not establish OOM; persist a safe interruption.
                        result = None
                    break
                if not process.is_alive():
                    break
            if self.stopping.is_set():
                # Leave lease to expire; restart can safely reclaim the job.
                return True
            if result and result[0]:
                kind = "snapshot" if self.role == "collector" else "report"
                self.store.finish(job["id"], job["owner"], "collected" if kind == "snapshot" else "completed", result[1])
            else:
                if result is None:
                    _log_worker_interruption(process, memory_before)
                if result and len(result) > 2:
                    LOGGER.warning("Scan worker failed: code=%s type=%s source=%s", result[1],
                                   result[2]["exception_type"], result[2]["source"])
                expired = bool(result and result[1] == "credentials_expired" and self.role == "collector")
                self.store.finish(job["id"], job["owner"], "credentials_expired" if expired else "failed",
                                  artifact=result[4] if expired and len(result) > 4 else None,
                                  error_code=result[1] if result else "worker_interrupted",
                                  failure_reasons=result[3] if result and len(result) > 3 else None)
            return True
        except Exception as exc:
            details = _safe_failure_details(exc)
            LOGGER.warning("Scan worker failed: code=artifact_error type=%s source=%s", details["exception_type"], details["source"])
            self.store.finish(job["id"], job["owner"], "failed", error_code="artifact_error")
            return True
        finally:
            if process is not None:
                terminate_requested, kill_requested = False, False
                if process.is_alive():
                    terminate_requested = True
                    process.terminate()
                process.join(timeout=2)
                if process.is_alive():
                    kill_requested = True
                    process.kill()
                    process.join(timeout=2)
                if terminate_requested or kill_requested:
                    LOGGER.info('Scan worker cleanup: terminate_requested=%s kill_requested=%s '
                                'exitcode_after_cleanup=%s', terminate_requested, kill_requested,
                                getattr(process, 'exitcode', None))
            if parent is not None:
                parent.close()
            if child is not None:
                child.close()

    def run(self):
        def schedule_loop():
            while not self.stopping.is_set():
                try:
                    self.schedule_tick()
                except Exception:
                    # A transient scheduler failure is retried without logging credentials.
                    pass
                self.stopping.wait(30)
        scheduler = threading.Thread(target=schedule_loop, name='scan-scheduler', daemon=True) if self.role == 'collector' else None
        if scheduler:
            scheduler.start()
        try:
            while not self.stopping.is_set():
                try:
                    if not self.run_once():
                        self.stopping.wait(1)
                except Exception:
                    # Do not serialize exceptions: SDK errors can embed auth material.
                    self.stopping.wait(2)
        finally:
            self.stopping.set()
            if scheduler:
                scheduler.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("collector", "analyzer"))
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--ai-smoke", action="store_true", help="Run the isolated live AI deployment acceptance check")
    parser.add_argument("--progressive", action="store_true", help="Watch one scan's completed sections while collection continues")
    parser.add_argument("--tenant-id")
    parser.add_argument("--scan-id")
    args = parser.parse_args()
    if bool(args.tenant_id) != bool(args.scan_id):
        parser.error("--tenant-id and --scan-id must be supplied together")
    if args.ai_smoke:
        if args.role != "analyzer" or args.once or args.tenant_id or args.scan_id or args.progressive:
            parser.error("--ai-smoke requires the analyzer role without scan selectors")
        from .ai.smoke import main as ai_smoke
        ai_smoke()
        return
    # Only this application's sanitized supervisor messages are enabled.
    # Provider/third-party child stdout and stderr remain suppressed.
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False
    worker = Worker(args.role)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: worker.stopping.set())
    if args.progressive:
        if args.role != "analyzer" or not args.tenant_id or not args.scan_id:
            parser.error("--progressive requires analyzer role and one tenant/scan selector")
        from .progressive_analyzer import run_progressive
        status = run_progressive(worker, args.tenant_id, args.scan_id)
        if status != "completed":
            # The workflow only sees the exit code; name the terminal status.
            LOGGER.warning("Progressive analyzer ended with scan status %s", status)
            raise SystemExit(1)
        return
    if args.once:
        worker.run_once(args.tenant_id, args.scan_id)
    else:
        worker.run()


if __name__ == "__main__":
    main()
