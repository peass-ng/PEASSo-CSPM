"""Conservative eligibility and connector identity checks for same-row scan resume."""
from __future__ import annotations

import json
import re
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

from peaso.storage.sqlite import StoreError, TERMINAL
from peaso.storage.artifacts import check_reference, job_prefix


_SECRET_FIELDS = {
    "aws": {"aws_access_key_id", "aws_secret_access_key", "aws_session_token"},
    "gcp": {"token", "subject_token"},
    "azure": {"token", "arm_token", "graph_token", "vault_token", "storage_token",
              "logs_token", "databricks_account_token", "databricks_workspace_token_secret", "client_secret",
              "certificate_data", "client_certificate", "certificate_password",
              "federated_token"},
    "k8s": {"token", "client_cert_data", "client_key_data"},
}
_RECOVERABLE = {"credentials_expired", "failed", "timed_out", "cancelled"}


def collector_source(row):
    """Prefer a sealed final snapshot; admit a fenced cumulative checkpoint."""
    if row.get("snapshot"):
        return row["snapshot"]
    sequence = row.get("checkpoint_sequence")
    published = row.get("partial_report_sequence")
    if (type(sequence) is int and type(published) is int and 0 < published <= sequence
            and row.get("partial_snapshot") and row.get("partial_report")):
        return row["partial_snapshot"]
    return None


def resume_stage(row):
    """Return the work that remains, only for an incomplete live terminal row."""
    row = dict(row)
    if row.get("status") not in _RECOVERABLE or row.get("status") not in TERMINAL:
        return None
    try:
        frozen = json.loads(row["connector"])
    except (KeyError, TypeError, ValueError):
        return None
    if frozen.get("data", {}).get("input_mode", "live") != "live":
        return None
    if (row.get("status") == "credentials_expired" or row.get("error_stage") == "collector"
            or row.get("status") == "cancelled" and row.get("resume_phase") == "collector"):
        return "collector" if collector_source(row) else None
    if row.get("snapshot"):
        return "analyzer"
    return None


def _boundary(auth, provider):
    if not isinstance(auth, dict):
        raise StoreError(422, "Connector authentication is invalid")
    value = {key: item for key, item in auth.items()
             if key not in _SECRET_FIELDS[provider]}
    if provider == "azure" and "databricks_workspace_token_secret" in auth:
        from peaso.collectors.azure_databricks_workspace_ip_native import validate_auth
        try:
            validate_auth(auth)
        except ValueError:
            raise StoreError(422, "Connector authentication is invalid") from None
        value["databricks_workspace_token_secret"] = sorted(
            rid.casefold() for rid in auth["databricks_workspace_token_secret"])
    if provider == "gcp" and "sa_json" in value:
        try:
            service_account = value["sa_json"]
            service_account = json.loads(service_account) if isinstance(service_account, str) else service_account
            if not isinstance(service_account, dict):
                raise ValueError
            value["sa_json"] = {key: item for key, item in service_account.items()
                                if key not in {"private_key", "private_key_id"}}
        except (TypeError, ValueError):
            raise StoreError(422, "Connector authentication is invalid") from None
    return value


def compatible_connector(row, latest, cipher):
    """Use fresh credentials without changing the frozen provider/target/selection."""
    if latest["id"] != row["connector_id"] or latest["tenant"] != row["tenant"]:
        raise StoreError(409, "The original connector is unavailable")
    prior = json.loads(row["connector"])
    current = json.loads(latest["data"])
    old_data = prior["data"]
    provider = old_data.get("provider")
    if (provider not in _SECRET_FIELDS or current.get("provider") != provider
            or current.get("scopes") != old_data.get("scopes")
            or current.get("input_mode", "live") != "live"):
        raise StoreError(409, "Connector target or scope changed; start a new scan")
    old_private = cipher.decrypt(prior["auth"])
    new_private = cipher.decrypt(latest["auth"])
    if (old_private.get("options") != new_private.get("options")
            or _boundary(old_private.get("auth"), provider)
               != _boundary(new_private.get("auth"), provider)):
        raise StoreError(409, "Connector options or identity changed; start a new scan")
    return {"data": current, "auth": latest["auth"]}


def recoverable_sources(row, store, artifacts, *, metadata_only=False):
    """Prove saved objects belong to this scan before resetting its queue state."""
    from peaso.snapshot import digest, validate
    stage = resume_stage(row)
    if stage is None:
        raise StoreError(409, "This scan has no recoverable work")
    prefix = job_prefix(row["tenant"], row["id"])
    provider = json.loads(row["connector"])["data"]["provider"]
    partial = stage == "collector" and not row.get("snapshot")
    if stage == "analyzer":
        references = [row["snapshot"]]
    else:
        entries = store.checkpoint_collections(row["tenant"], row["id"])
        references = [collector_source(row)] + ([row["partial_report"]] if partial else []) + [
            entry["reference"] for entry in entries]
        if not references or any(type(entry.get("sequence")) is not int
                              or not 0 < entry["sequence"] <= row["checkpoint_sequence"]
                              for entry in entries):
            raise StoreError(409, "Saved scan batches are unavailable")
        if partial and (not entries or max(entry["sequence"] for entry in entries)
                        != row["checkpoint_sequence"]):
            raise StoreError(409, "Saved scan batches are unavailable")
    if not references or any(not isinstance(ref, str) or not ref.startswith(prefix)
                             for ref in references):
        raise StoreError(409, "Saved scan results are unavailable")
    if partial and metadata_only:
        # The HTTP route checks durable row metadata and object existence,
        # while the collector child validates every byte before native work.
        # HEAD/stat reads stay small even for a 150 MB cumulative snapshot.
        try:
            for reference in references:
                check_reference(row["tenant"], reference)
            # Check only the cumulative publication here. Batch presence and
            # complete content are verified in the claimed collector, so API
            # latency does not grow with the number of acknowledged batches.
            publication_refs = [row["partial_snapshot"], row["partial_report"]]
            with ThreadPoolExecutor(max_workers=2) as pool:
                sizes = list(pool.map(lambda ref: artifacts.size(row["tenant"], ref), publication_refs))
            if any(type(size) is not int or size <= 0 for size in sizes):
                raise ValueError("Empty saved artifact")
        except Exception:
            raise StoreError(409, "Saved scan results are unavailable") from None
        return stage
    try:
        if not partial:
            for reference in dict.fromkeys(references):
                snapshot = validate(artifacts.get(row["tenant"], reference))
                if snapshot["provider"] != provider or not snapshot["collections"]:
                    raise ValueError("Saved scan provider mismatch")
        if partial:
            saved = validate(artifacts.get(row["tenant"], row["partial_snapshot"]))
            if saved["provider"] != provider or not saved["collections"]:
                raise ValueError("Saved scan provider mismatch")
            metadata = saved.get("metadata") or {}
            incremental = metadata.get("incremental") or {}
            frozen = json.loads(row["connector"])["data"]
            scopes = frozen.get("scopes")
            plan = incremental.get("scope_plan")
            if (metadata.get("intentional_partial") is not True
                    or incremental.get("phase") != "collecting"
                    or incremental.get("sequence") != row["partial_report_sequence"]
                    or incremental.get("completed_collections") != len(saved["collections"])
                    or not isinstance(scopes, list) or not scopes
                    or metadata.get("requested_scopes") != scopes):
                raise ValueError("Saved checkpoint plan mismatch")
            if provider == "aws":
                # An explicit regional target is its own complete boundary.
                # Wildcard discovery needs the native plan persisted after
                # on_scope_plan; observed rows alone cannot prove absent work.
                explicit = ("*" not in scopes and all(
                    isinstance(scope, str) and re.fullmatch(
                        r"[0-9]{12}/[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+", scope)
                    for scope in scopes))
                if plan is None:
                    globals_allowed = {scope.split("/", 1)[0] + "/global" for scope in scopes}
                    if not explicit or any(row["scope"] not in scopes and row["scope"] not in globals_allowed
                                           for row in saved["collections"]):
                        raise ValueError("Saved checkpoint scope plan unavailable")
                elif (not isinstance(plan, list) or not plan
                      or len(set(plan)) != len(plan)
                      or any(not isinstance(scope, str) or not re.fullmatch(
                          r"[0-9]{12}/[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+", scope)
                          for scope in plan)
                      or (explicit and not set(scopes) <= set(plan))):
                    raise ValueError("Saved checkpoint scope plan mismatch")
                else:
                    globals_allowed = {scope.split("/", 1)[0] + "/global" for scope in plan}
                    if any(row["scope"] not in plan and row["scope"] not in globals_allowed
                           for row in saved["collections"]):
                        raise ValueError("Saved checkpoint scope plan mismatch")
            report = artifacts.get(row["tenant"], row["partial_report"])
            publication = (report.get("summary", report).get("publication")
                           if isinstance(report, dict) else None)
            if (not isinstance(publication, dict)
                    or publication.get("state") != "partial"
                    or publication.get("phase") != "collecting"
                    or publication.get("sequence") != row["partial_report_sequence"]):
                raise ValueError("Saved checkpoint publication mismatch")
            observed = {(envelope["type"], envelope["scope"]): digest(envelope)
                        for envelope in saved["collections"]}
            # A cumulative AWS checkpoint can exceed 150 MB. Release it before
            # downloading bounded batches, and retain only envelope digests.
            del saved
            at_publication = {}
            def check_batch(entry, batch):
                if batch["provider"] != provider or not batch["collections"]:
                    raise ValueError("Saved batch provider mismatch")
                mark = (batch.get("metadata") or {}).get("incremental") or {}
                if (mark.get("sequence") != entry["sequence"] or mark.get("phase") != "collecting"
                        or batch.get("metadata", {}).get("requested_scopes") != scopes):
                    raise ValueError("Saved checkpoint sequence mismatch")
                batch_plan = mark.get("scope_plan")
                if provider == "aws" and batch_plan is not None and (
                        not isinstance(batch_plan, list)
                        or batch_plan != (plan if plan is not None else scopes)):
                    raise ValueError("Saved checkpoint scope plan changed")
                if entry["kind"] == "__checkpoint_batch__":
                    revisions = mark.get("batch_revisions")
                    if (entry["scope"] != str(entry["sequence"])
                            or not isinstance(revisions, list)
                            or len(revisions) != len(batch["collections"])):
                        raise ValueError("Saved checkpoint batch mismatch")
                elif (len(batch["collections"]) != 1
                      or batch["collections"][0]["type"] != entry["kind"]
                      or batch["collections"][0]["scope"] != entry["scope"]):
                    raise ValueError("Saved checkpoint envelope mismatch")
                else:
                    revisions = [mark.get("data_revision", entry["sequence"])]
                for revision, envelope in zip(revisions, batch["collections"]):
                    if type(revision) is not int or not 0 <= revision <= entry["sequence"]:
                        raise ValueError("Saved checkpoint revision mismatch")
                    if entry["sequence"] <= row["partial_report_sequence"]:
                        key = (envelope["type"], envelope["scope"])
                        value = digest(envelope)
                        previous = at_publication.get(key, (-1, None))
                        if revision == previous[0] and value != previous[1]:
                            raise ValueError("Conflicting checkpoint revision")
                        if revision > previous[0]:
                            at_publication[key] = (revision, value)
            # S3 round trips dominate hosted validation. At most four batch
            # bodies are in flight so large native envelopes stay memory bound.
            with ThreadPoolExecutor(max_workers=min(4, len(entries))) as pool:
                source = iter(entries)
                pending = {}
                for _ in range(min(4, len(entries))):
                    entry = next(source)
                    pending[pool.submit(artifacts.get, row["tenant"], entry["reference"])] = entry
                while pending:
                    done, _ = wait(pending, return_when=FIRST_COMPLETED)
                    for future in done:
                        entry = pending.pop(future)
                        check_batch(entry, validate(future.result()))
                        following = next(source, None)
                        if following is not None:
                            pending[pool.submit(artifacts.get, row["tenant"], following["reference"])] = following
            expected = {key: value for key, (_, value) in at_publication.items()}
            if not expected or expected != observed:
                raise ValueError("Saved cumulative checkpoint mismatch")
    except (KeyError, OSError, TypeError, ValueError):
        raise StoreError(409, "Saved scan results are unavailable") from None
    return stage


def validate_resume_proof(proof, artifacts, tenant, ident, connector, checkpoint_refs):
    """Verify a CAS-claimed collector's immutable checkpoint before any read."""
    if not isinstance(proof, dict) or not isinstance(proof.get("row"), dict):
        raise ValueError("Resume proof is unavailable")
    row, entries = proof["row"], proof.get("entries")
    if (row.get("tenant") != tenant or row.get("id") != ident
            or row.get("resume_phase") != "collector" or row.get("snapshot")
            or not isinstance(entries, list)
            or [entry.get("reference") for entry in entries] != checkpoint_refs):
        raise ValueError("Resume proof does not match the claimed scan")
    data = json.loads(row["connector"])["data"]
    if (data.get("provider") != connector.get("provider")
            or data.get("scopes") != connector.get("scopes")):
        raise ValueError("Resume proof target changed")

    class SavedRows:
        @staticmethod
        def checkpoint_collections(expected_tenant, expected_id):
            if expected_tenant != tenant or expected_id != ident:
                raise ValueError("Resume proof owner changed")
            return entries

    terminal = dict(row, status="failed", error_stage="collector")
    if recoverable_sources(terminal, SavedRows(), artifacts) != "collector":
        raise ValueError("Resume proof is incomplete")



# Completed scans need an explicit, artifact-proven native section refresh.
_REFRESH_SEAL = object()
_REFRESH_ISSUED = __import__('weakref').WeakKeyDictionary()
_REFRESH_LOCK = __import__('threading').Lock()
_REFRESH_SPECS = {
    'gcp': {'images': ('gcp.review.artifact_image.selected_image_vulnerabilities', 'artifact_selected_image_vulnerabilities', 'RegistryImageVulnerabilityReview'),
            'leaks': ('gcp.review.artifact_image.content_secret_indicators', 'artifact_image', 'ImageSecretIndicators')},
    'k8s': {'images': ('k8s.review.selected_registry_image_high_vulnerabilities', 'k8s_selected_registry_image_vulnerabilities', 'SelectedRegistryImage'),
            'leaks': ('k8s.review.selected_registry_image_secret_indicators', 'k8s_selected_registry_image_secrets', 'SelectedRegistryImage')},
    'azure': {'images': ('azure.review.acr.selected_image_high_critical_vulnerabilities', 'acr_selected_image_vulnerabilities', 'AcrSelectedImageVulnerabilities'),
              'leaks': ('azure.review.acr.selected_image_secret_indicators', 'acr_selected_image', 'SelectedAcrImageSecretIndicators')},
}


def _refresh_digest(value):
    import hashlib
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


class _RefreshGrant:
    __slots__ = ('seal', '__weakref__')
    def __init__(self):
        self.seal = _REFRESH_SEAL


def requested_refresh_sections(body):
    if (type(body) is not dict or set(body) != {'sections'}
            or type(body['sections']) is not list or not 1 <= len(body['sections']) <= 2
            or any(type(value) is not str or value not in {'images', 'leaks'} for value in body['sections'])
            or len(set(body['sections'])) != len(body['sections'])):
        raise StoreError(422, 'Section refresh requires unique images and/or leaks sections')
    return sorted(body['sections'])


def _refresh_binding(row):
    return {key: row.get(key) for key in ('tenant', 'id', 'connector_id', 'status', 'snapshot', 'report',
            'checkpoint_sequence', 'resume_attempt', 'connector', 'data')}


def _refresh_manifest_json(artifacts, tenant, reference):
    """Bound bytes before decode/JSON; never use the unbounded snapshot reader."""
    import gzip
    import io
    from peaso.storage.artifacts import FileArtifacts, S3Artifacts
    check_reference(tenant, reference)
    compressed_limit, expanded_limit = 4 * 1024 * 1024, 8 * 1024 * 1024
    if type(artifacts) is FileArtifacts:
        with (artifacts.root / reference).open('rb') as stream:
            raw = stream.read(compressed_limit + 1)
    elif type(artifacts) is S3Artifacts:
        response = artifacts.client.get_object(Bucket=artifacts.bucket, Key='artifacts/' + reference)
        stream = response['Body']
        try:
            if response.get('ContentLength', 0) > compressed_limit:
                raise ValueError('Manifest download exceeds limit')
            chunks, count = [], 0
            while count <= compressed_limit:
                chunk = stream.read(min(65536, compressed_limit + 1 - count))
                if not chunk:break
                count += len(chunk)
                chunks.append(chunk)
            raw = b''.join(chunks)
        finally:
            stream.close()
    else:
        raise ValueError('Bounded artifact reading unavailable')
    if len(raw) > compressed_limit:raise ValueError('Manifest download exceeds limit')
    if raw.startswith(b'\x1f\x8b'):
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            raw = stream.read(expanded_limit + 1)
    if len(raw) > expanded_limit:raise ValueError('Manifest expansion exceeds limit')
    def unique(pairs):
        value = {}
        for key, member in pairs:
            if key in value:raise ValueError('Duplicate manifest field')
            value[key] = member
        return value
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Non-finite JSON')))
    pending, count = [(value, 0)], 0
    while pending:
        member, depth = pending.pop()
        count += 1
        if count > 250000 or depth > 48:raise ValueError('Manifest JSON exceeds structural limit')
        if type(member) is dict:pending.extend((child, depth + 1) for child in member.values())
        elif type(member) is list:pending.extend((child, depth + 1) for child in member)
    if type(value) is not dict:raise ValueError('Invalid manifest JSON')
    return value


def _refresh_native_incomplete(snapshot, specs):
    damaged = (snapshot['provider'] == 'azure' and
        snapshot.get('metadata', {}).get('azure_storage_selected_source_redaction_complete') is False)
    incomplete = damaged
    for _, kind, marker in specs:
        rows = [item.get(marker) for envelope in snapshot['collections'] if envelope['type'] == kind
                for item in envelope['items']]
        incomplete |= not rows or any(type(value) is not dict or
            value.get('status') == 'UNKNOWN' or value.get('complete') is False for value in rows)
    return damaged, incomplete


def prove_section_refresh(row, store, artifacts, sections):
    """Issue a bounded manifest grant; the child must prove full native evidence."""
    from peaso.image_findings import build_report, SCHEMA
    sections = requested_refresh_sections({'sections': sections})
    if row.get('status') != 'completed' or not row.get('snapshot') or not row.get('report'):
        raise StoreError(409, 'Only a completed scan with saved native results can refresh sections')
    frozen = json.loads(row['connector'])['data']
    provider = frozen.get('provider')
    if frozen.get('input_mode', 'live') != 'live' or provider not in _REFRESH_SPECS:
        raise StoreError(409, 'This provider has no supported native section refresh')
    selected = json.loads(row['data'])
    named = set(selected.get('content_checks') or selected.get('checks') or ())
    specs = [_REFRESH_SPECS[provider][section] for section in sections]
    if any(spec[0] not in named for spec in specs):
        raise StoreError(409, 'The requested section was not explicitly selected in the original scan')
    # Both ACR consumers share one scan-local capture namespace. Refreshing
    # only one would unbind the other retained result when metadata is merged.
    # Closure is allowed only for consumers explicitly selected originally.
    if provider == 'azure' and all(_REFRESH_SPECS[provider][section][0] in named
                                   for section in ('images', 'leaks')):
        sections = ['images', 'leaks']
        specs = [_REFRESH_SPECS[provider][section] for section in sections]
    prefix = job_prefix(row['tenant'], row['id'])
    for reference in (row['snapshot'], row['report']):
        check_reference(row['tenant'], reference)
        if not reference.startswith(prefix):
            raise StoreError(409, 'Saved results belong to a different scan')
    try:
        manifest = _refresh_manifest_json(artifacts, row['tenant'], row['report'])
        summary = manifest['summary']
        if (manifest.get('bundle_version') != 1 or summary['provider'] != provider
                or summary['scopes'] != frozen.get('scopes') or not isinstance(summary['snapshot_id'], str)
                or artifacts.size(row['tenant'], row['snapshot']) <= 0):
            raise ValueError('Saved target mismatch')
        damaged = (provider == 'azure' and summary.get('snapshot_metadata', {}).get(
            'azure_storage_selected_source_redaction_complete') is False)
        projection = None
        if not damaged:
            reference = manifest['image_vulnerability_scan']['artifact']
            if (manifest['image_vulnerability_scan'].get('selected') is not True
                    or not reference.startswith(prefix)):
                raise ValueError('Native section summary missing')
            projection = _refresh_manifest_json(artifacts, row['tenant'], reference)
            if (projection.get('schema') != SCHEMA or projection.get('scan_id') != row['id']
                    or type(projection.get('observations')) is not list):
                raise ValueError('Native section summary changed')
            if build_report(projection['observations'], selected=True)['complete']:
                raise ValueError('Native sections are complete')
    except Exception:
        raise StoreError(409, 'Saved section evidence is unavailable, complete, or exceeds the bounded refresh limit') from None
    entries = store.checkpoint_collections(row['tenant'], row['id'])
    if type(entries) is not list or len(entries) > 4096:
        raise StoreError(409, 'Original checkpoint manifest exceeds the refresh limit')
    if damaged and not entries:
        raise StoreError(409, 'Original native checkpoints are unavailable')
    for entry in entries:
        reference = entry.get('reference')
        if (type(entry.get('sequence')) is not int or not 0 < entry['sequence'] <= row.get('checkpoint_sequence', 0)
                or type(reference) is not str or not reference.startswith(prefix)):
            raise StoreError(409, 'Original native checkpoint binding changed')
        check_reference(row['tenant'], reference)
    payload = {'version': 1, 'binding': _refresh_binding(row), 'provider': provider, 'sections': sections,
               'checks': [spec[0] for spec in specs], 'kinds': [spec[1] for spec in specs],
               'snapshot_id': summary['snapshot_id'], 'restore_checkpoints': damaged,
               'manifest_sha256': _refresh_digest(manifest),
               'projection_sha256': _refresh_digest(projection) if projection is not None else None,
               'checkpoint_entries_sha256': _refresh_digest(entries)}
    payload['plan_sha256'] = _refresh_digest(payload)
    grant = _RefreshGrant()
    with _REFRESH_LOCK:
        _REFRESH_ISSUED[grant] = json.dumps(payload,sort_keys=True,separators=(',',':'))
    return grant


def consume_section_refresh(grant, row):
    """Consume the proof once inside the store's normal queue/CAS boundary."""
    with _REFRESH_LOCK:
        if (type(grant) is not _RefreshGrant or grant.seal is not _REFRESH_SEAL
                or grant not in _REFRESH_ISSUED):
            raise StoreError(409, 'Section refresh evidence proof is required')
        payload = json.loads(_REFRESH_ISSUED.pop(grant))
    if row.get('status') != 'completed' or payload.get('binding') != _refresh_binding(row):
        raise StoreError(409, 'Scan changed after section refresh proof')
    if payload.get('plan_sha256') != _refresh_digest({key: value for key, value in payload.items() if key != 'plan_sha256'}):
        raise StoreError(409, 'Section refresh proof changed')
    return json.loads(json.dumps(payload))


def section_refresh_payload(row):
    value = row.get('native_refresh')
    if isinstance(value, str):
        value = json.loads(value)
    return value if type(value) is dict else None


def validate_claimed_section_refresh(row, entries, artifacts, connector):
    """Re-prove persisted source/attempt/tenant bindings in the claimed child."""
    from peaso.snapshot import validate
    value = section_refresh_payload(row)
    if value is None or value.get('version') != 1:
        raise ValueError('Native section refresh proof missing')
    binding = value['binding']
    if (row.get('tenant') != binding['tenant'] or row.get('id') != binding['id']
            or row.get('snapshot') != binding['snapshot'] or row.get('report') != binding['report']
            or row.get('checkpoint_sequence') != binding['checkpoint_sequence']
            or int(row.get('resume_attempt') or 0) != int(binding.get('resume_attempt') or 0) + 1
            or row.get('data') != binding['data'] or row.get('resume_phase') != 'collector'
            or value['provider'] != connector.get('provider')
            or _refresh_digest({key: member for key, member in value.items() if key != 'plan_sha256'}) != value.get('plan_sha256')):
        raise ValueError('Native section refresh claim changed')
    sections = requested_refresh_sections({'sections': value.get('sections')})
    specs = [_REFRESH_SPECS[value['provider']][section] for section in sections]
    named = set(json.loads(binding['data']).get('content_checks') or json.loads(binding['data']).get('checks') or ())
    if (value.get('checks') != [spec[0] for spec in specs] or value.get('kinds') != [spec[1] for spec in specs]
            or not set(value['checks']) <= named):
        raise ValueError('Native section refresh selection changed')
    frozen = json.loads(binding['connector'])['data']
    if connector.get('scopes') != frozen.get('scopes'):
        raise ValueError('Native section refresh target changed')
    prefix = job_prefix(row['tenant'], row['id'])
    for reference in (binding['snapshot'], binding['report']):
        check_reference(row['tenant'], reference)
        if not reference.startswith(prefix):raise ValueError('Native section refresh artifact owner changed')
    manifest = artifacts.get(row['tenant'], binding['report'])
    if _refresh_digest(manifest) != value.get('manifest_sha256'):
        raise ValueError('Native source manifest changed')
    if value.get('projection_sha256') is not None:
        reference = manifest['image_vulnerability_scan']['artifact']
        check_reference(row['tenant'], reference)
        if not reference.startswith(prefix):raise ValueError('Native projection owner changed')
        if _refresh_digest(artifacts.get(row['tenant'], reference)) != value['projection_sha256']:
            raise ValueError('Native projection changed')
    prior = validate(artifacts.get(row['tenant'], binding['snapshot']))
    if prior['provider'] != value['provider'] or prior['snapshot_id'] != value['snapshot_id']:
        raise ValueError('Native section refresh source changed')
    damaged, incomplete = _refresh_native_incomplete(prior, specs)
    if (prior['scopes'] != frozen['scopes'] or not incomplete or damaged != value['restore_checkpoints']):
        raise ValueError('Full native section proof is not incomplete or target changed')
    if _refresh_digest(entries) != value['checkpoint_entries_sha256']:
        raise ValueError('Native section refresh checkpoints changed')
    revisions, restored = {}, {}
    for entry in sorted(entries, key=lambda member: member['sequence']):
        reference = entry['reference']
        check_reference(row['tenant'], reference)
        if not reference.startswith(prefix):raise ValueError('Native checkpoint owner changed')
        if type(entry.get('sequence')) is not int or not 0 < entry['sequence'] <= binding['checkpoint_sequence']:
            raise ValueError('Native checkpoint sequence changed')
        batch = validate(artifacts.get(row['tenant'], reference))
        mark = batch.get('metadata', {}).get('incremental', {})
        if (batch['provider'] != value['provider'] or mark.get('phase') != 'collecting' or mark.get('sequence') != entry['sequence']
                or batch.get('metadata', {}).get('requested_scopes') != frozen['scopes']):
            raise ValueError('Native checkpoint scope or sequence changed')
        numbers = mark.get('batch_revisions')
        if entry['kind'] == '__checkpoint_batch__':
            if (entry['scope'] != str(entry['sequence']) or type(numbers) is not list
                    or len(numbers) != len(batch['collections'])):
                raise ValueError('Native checkpoint batch changed')
        else:
            if (len(batch['collections']) != 1 or batch['collections'][0]['type'] != entry['kind']
                    or batch['collections'][0]['scope'] != entry['scope']):
                raise ValueError('Native checkpoint key changed')
            numbers = [mark.get('data_revision', entry['sequence'])]
        for revision, envelope in zip(numbers, batch['collections']):
            if type(revision) is not int or not 0 <= revision <= entry['sequence']:
                raise ValueError('Native checkpoint revision changed')
            observed = envelope['scope']
            allowed = connector['scopes']
            if value['provider'] == 'gcp':
                scoped = observed in allowed
            elif value['provider'] == 'k8s':
                scoped = observed in allowed or observed in ('*', '/')
            else:
                tenant = connector.get('auth', {}).get('tenant_id')
                scoped = any(observed == scope or observed.startswith(scope + '/') for scope in allowed)
                scoped = scoped or bool(tenant and (observed == '/tenants/' + tenant or observed.startswith('/tenants/' + tenant + '/')))
                scoped = scoped or (observed == '/' and envelope['type'] in {'azure_unused_arm_role_evidence','role_assignment','role_definition','deny_assignment'})
            if not scoped:raise ValueError('Native checkpoint inventory outside selected scope')
            key = envelope['type'], envelope['scope']
            if revision >= revisions.get(key, -1):restored[key], revisions[key] = envelope, revision
    if value['restore_checkpoints'] and not restored:raise ValueError('Native checkpoint inventory missing')
    if value['restore_checkpoints']:
        # Retain original facts, without manufacturing the lost authorization
        # namespace or declaring those old reads newly complete.
        import copy
        rows = {}
        for key, envelope in restored.items():
            envelope = copy.deepcopy(envelope)
            envelope['status'] = 'partial'
            envelope['error'] = {'code': 'recovered_collector_context_unavailable'}
            rows[key] = envelope
        for envelope in prior['collections']:
            key = envelope['type'], envelope['scope']
            if key not in rows:rows[key] = envelope
        from peaso.snapshot import make_snapshot
        metadata = dict(prior.get('metadata') or {})
        metadata.pop('azure_storage_selected_source_redaction_complete', None)
        metadata['native_refresh'] = {'restored_native_context': 'partial', 'plan_sha256': value['plan_sha256']}
        prior = make_snapshot(prior['provider'], prior['scopes'], list(rows.values()),
                              metadata=metadata, created_at=prior['created_at'])
    return value, prior, revisions


def section_refresh_collection_request(request, plan):
    """Use original credentials/targets, with exact previously selected consumers."""
    import copy
    value = dict(request)
    value.update(categories=[], checks=[], frameworks=[], content_checks=list(plan['checks']))
    value.pop('leaks_enabled', None)
    value.pop('images_enabled', None)
    value['connector'] = copy.deepcopy(request['connector'])
    value['connector'].setdefault('options', {}).pop('inventories', None)
    value['connector']['options'].pop('collect_all', None)
    return value
