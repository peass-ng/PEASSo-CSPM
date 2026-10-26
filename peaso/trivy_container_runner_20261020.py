"""Unregistered opt-in Trivy archive vulnerability inspection, no image pull.

Only collector-owned immutable bytes and independent native verification enter
this seam. Existing vulnerability DB is opened read-only by pinned Trivy;
updates, remote lookups, telemetry, persistent scan cache and credentials are off.
"""
from datetime import datetime, timezone
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import tempfile
import time

from . import container_image_archive_20261020 as archive
from . import container_scan_process_20261020 as process
from .image_content_memo_20261026 import BoundedMemo
from .trivy_version_probe_20261026 import VersionProbe

# Clean offline reports for identical immutable content, the same executable
# file and the same unchanged DB generation. Inputs are re-proven against their
# digests before reuse, and native binding checks always run again.
_SCANS = BoundedMemo(256, 96 * 1024 * 1024)

SCHEMA = 'trivy-native-immutable-image-vulnerabilities-20261020-v1'
CLI_VERSION = '0.68.1'
DEFAULT_CLI = '/usr/local/bin/trivy'
MAX_SECONDS = 900
MAX_DB_METADATA = 8192
MAX_DB_AGE_SECONDS = 86400
MAX_RESULTS = 4096
MAX_VULNS = 100000
MAX_FINDINGS = 10000
TEXT = re.compile(r'[A-Za-z0-9@._:+/~%=-]{1,256}\Z')
VULN_ID = re.compile(r'(?:CVE-[0-9]{4}-[0-9]{4,}|GHSA-[a-z0-9-]{4,64}|[A-Z][A-Z0-9-]{1,120}-[0-9]{2,})\Z')
FIX = re.compile(r'(?:[<>]=?|[~^]=?|=)?\s*[0-9][A-Za-z0-9.*+_:-]*'
                 r'(?:\s*(?:\|\||[<>]=?|[~^]=?|=)\s*[0-9][A-Za-z0-9.*+_:-]*)*\Z')
FLAGS = ('--scanners', 'vuln', '--pkg-types', 'os,library', '--severity', 'HIGH,CRITICAL',
         '--format', 'json', '--exit-code', '0', '--cache-backend', 'memory',
         '--offline-scan', '--skip-db-update', '--skip-java-db-update', '--skip-check-update',
         '--skip-vex-repo-update', '--skip-version-check', '--disable-telemetry', '--parallel', '1')


def _base(identity=None):
    return {'schema': SCHEMA, 'status': 'UNKNOWN', 'scan_complete': False, 'complete': False,
            'coverage_status': 'UNKNOWN', 'reason': 'not_scanned', 'image': identity,
            'findings': [], 'scanned_classes': [], 'cli_version': CLI_VERSION,
            'scanners': ['vuln'], 'package_types': ['os', 'library'], 'severities': ['HIGH', 'CRITICAL'],
            'production_freshness_certified': False, 'runtime_image_proven': False}


def _safe(value):
    archive.require(type(value) is str and TEXT.fullmatch(value), 'unsafe_normalized_field')
    return value


def _timestamp(value):
    archive.require(type(value) is str and len(value) <= 40, 'db_timestamp_required')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    archive.require(result.tzinfo is not None, 'db_timezone_required')
    return result


def database_state(cache_dir, *, now=None):
    """No copy/download/hash pass over the existing large DB; bind stat + metadata."""
    cache = Path(cache_dir)
    db, metadata = cache / 'db/trivy.db', cache / 'db/metadata.json'
    archive.require(cache.is_absolute() and db.is_file() and metadata.is_file(), 'cached_db_required')
    for path in (db, metadata):
        info = path.lstat()
        archive.require(stat.S_ISREG(info.st_mode) and not path.is_symlink(), 'regular_cached_db_required')
    archive.require(0 < metadata.stat().st_size <= MAX_DB_METADATA and db.stat().st_size > 0,
                    'bounded_db_metadata_required')
    raw = metadata.read_bytes()
    archive.require(len(raw) <= MAX_DB_METADATA, 'bounded_db_metadata_required')
    value = archive.decode(raw)
    archive.require(type(value) is dict and type(value.get('Version')) is int and value['Version'] == 2,
                    'db_schema_2_required')
    updated, next_update, downloaded = (_timestamp(value.get(k)) for k in ('UpdatedAt', 'NextUpdate', 'DownloadedAt'))
    now = now or datetime.now(timezone.utc)
    age = (now - updated).total_seconds()
    archive.require(age >= -300 and next_update >= updated and downloaded >= updated,
                    'db_timestamps_inconsistent')
    info = db.stat()
    return {'schema_version': 2, 'updated_at': value['UpdatedAt'], 'next_update': value['NextUpdate'],
            'downloaded_at': value['DownloadedAt'], 'age_seconds_at_capture': max(0, int(age)),
            'fresh': age <= MAX_DB_AGE_SECONDS and now <= next_update,
            'freshness_policy_seconds': MAX_DB_AGE_SECONDS, 'updates_disabled': True,
            'db_bytes': info.st_size, 'db_stat_identity': [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns],
            'metadata_sha256': hashlib.sha256(raw).hexdigest()}


def _same_database(before, after):
    keys = ('schema_version', 'updated_at', 'next_update', 'downloaded_at',
            'db_stat_identity', 'metadata_sha256')
    return all(before[k] == after[k] for k in keys)


def _diagnostics(raw):
    text = raw.decode('utf-8', 'replace').lower()
    if not text.strip():
        return []
    messages = []
    lines = text.splitlines()
    eol_markers = ('no longer supported', 'vulnerability detection may be insufficient', 'not on the eol list')
    if any(any(marker in line for marker in eol_markers) for line in lines):
        messages.append('os_end_of_support')
    # This pinned Trivy notice describes severity attribution, not a skipped
    # package, failed scan, or loss of database coverage. Match the entire
    # tab-delimited WARN body; any extra text or other warning remains unresolved.
    severity_notice = ('using severities from other vendors for some vulnerabilities. read '
        'https://trivy.dev/docs/v0.68/guide/scanner/vulnerability#severity-selection for details.')
    def informational_notice(line):
        fields = line.split('\t')
        return len(fields) == 3 and fields[1] == 'warn' and fields[2] == severity_notice
    timestamp = re.compile(r'\d{4}-\d{2}-\d{2}t\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:z|[+-]\d{2}:\d{2})\Z')
    classified = []
    for line in lines:
        if any(marker in line for marker in eol_markers) or informational_notice(line):
            continue
        fields = line.split('\t')
        structured = False
        if (len(fields) >= 3 and timestamp.fullmatch(fields[0])
                and fields[1] in ('info', 'debug', 'warn', 'error', 'fatal')):
            try:
                structured = datetime.fromisoformat(fields[0].replace('z', '+00:00')).tzinfo is not None
            except ValueError:
                pass
        if structured:
            # A structured INFO attribute can contain a path named "warning"
            # or "error". Inspect only the message, but keep every real WARN.
            classified.append((line, fields[2], fields[1] in ('warn', 'error', 'fatal')))
        else:
            # Unknown log shapes cannot prove that a warning is harmless.
            classified.append((line, line, False))
    for category, fragments in (
        ('database_unavailable', ('failed to initialize db', 'database error', 'db error', 'first run cannot',
                                  'db schema', 'unable to open db', 'failed to open db', 'java db')),
        ('archive_or_image_unsupported', ('unsupported', 'unrecognized', 'unable to detect the os',
                                         'failed to initialize scanner', 'failed to initialize artifact',
                                         'unable to initialize archive image', 'file manifest.json not found')),
        ('analysis_incomplete', ('failed to analyze', 'unable to analyze', 'scan error', 'scan failed',
                                 'fatal', 'error', 'warn')),
    ):
        if category == 'analysis_incomplete':
            found = any(is_failure or any(fragment in line for fragment in fragments[:-3])
                        or any(fragment in message for fragment in fragments[-3:])
                        for line, message, is_failure in classified)
        else:
            found = any(fragment in line for line, _, _ in classified for fragment in fragments)
        if found:
            messages.append(category)
    return messages


def parse_report(raw, exit_code, image_identity, *, diff_ids, database, interrupted=None, stderr=b''):
    """Pinned report schema; only typed OS/application vulnerability rows survive."""
    selected = archive.identity(image_identity)
    result = _base(selected)
    result['database'] = database
    diagnostics = _diagnostics(stderr)
    result['diagnostics'] = diagnostics
    result['reason'] = interrupted or (diagnostics[0] if diagnostics else 'invalid_or_incomplete_trivy_report')
    if type(raw) is not bytes or not 0 < len(raw) <= process.MAX_STDOUT:
        return result
    try:
        report = archive.decode(raw)
        archive.require(type(report) is dict and type(report.get('SchemaVersion')) is int
                        and report['SchemaVersion'] == 2 and report.get('ArtifactType') == 'container_image',
                        'native_container_report_required')
        metadata = report.get('Metadata')
        archive.require(type(metadata) is dict and metadata.get('ImageID') == selected['config_digest']
                        and metadata.get('DiffIDs') == diff_ids, 'report_image_identity_mismatch')
        digests = metadata.get('RepoDigests', [])
        archive.require(type(digests) is list and all(d == selected['immutable_reference'] for d in digests),
                        'report_repository_identity_mismatch')
        if 'OS' in metadata:
            os_info = metadata['OS']
            archive.require(type(os_info) is dict and type(os_info.get('Family')) is str
                            and TEXT.fullmatch(os_info['Family']) and type(os_info.get('Name')) is str
                            and TEXT.fullmatch(os_info['Name'])
                            and type(os_info.get('EOSL', False)) is bool, 'typed_os_metadata_required')
        rows = report.get('Results')
        archive.require(type(rows) is list and 1 <= len(rows) <= MAX_RESULTS, 'reported_targets_required')
    except Exception:
        return result
    complete = (type(exit_code) is int and exit_code == 0 and interrupted is None
                and not any(d != 'os_end_of_support' for d in diagnostics))
    findings, classes, count = {}, set(), 0
    for row in rows:
        try:
            archive.require(type(row) is dict and row.get('Class') in ('os-pkgs', 'lang-pkgs')
                            and type(row.get('Type')) is str and TEXT.fullmatch(row['Type'])
                            and type(row.get('Target')) is str and bool(row['Target']), 'typed_target_required')
            classes.add(row['Class'])
            vulns = row.get('Vulnerabilities', [])
            packages = row.get('Packages', [])
            archive.require(type(vulns) is list and type(packages) is list and bool(vulns or packages),
                            'package_or_vulnerability_evidence_required')
            # This path is vulnerability-only. Other scanner results cannot prove clean.
            archive.require(not any(row.get(key) for key in ('Secrets', 'Licenses', 'Misconfigurations',
                                                             'ExperimentalModifiedFindings')), 'unexpected_scanner_result')
            for vuln in vulns:
                count += 1
                if count > MAX_VULNS:
                    complete = False
                    break
                try:
                    archive.require(type(vuln) is dict, 'typed_vulnerability_required')
                    severity = vuln.get('Severity')
                    archive.require(severity in ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'), 'known_severity_required')
                    if severity not in ('HIGH', 'CRITICAL'):
                        continue
                    identifier = vuln.get('VulnerabilityID')
                    archive.require(type(identifier) is str and VULN_ID.fullmatch(identifier), 'safe_vulnerability_id_required')
                    package, version = _safe(vuln.get('PkgName')), _safe(vuln.get('InstalledVersion'))
                    try:
                        fixed = vuln.get('FixedVersion', '')
                        archive.require(type(fixed) is str and len(fixed) <= 1024, 'bounded_fix_required')
                        fixes = set()
                        for part in fixed.split(','):
                            if not part.strip(): continue
                            part = part.strip()
                            archive.require(len(part) <= 256 and FIX.fullmatch(part), 'safe_fix_range_required')
                            fixes.add(part)
                        archive.require(len(fixes) <= 64, 'fix_advice_bound')
                        fixes = sorted(fixes)
                        status = vuln.get('Status', 'unknown')
                        archive.require(status in ('unknown', 'not_affected', 'affected', 'fixed', 'under_investigation',
                                                  'will_not_fix', 'fix_deferred', 'end_of_life'), 'typed_fix_status_required')
                    except Exception:
                        complete = False
                        fixes, status = [], 'unknown'
                    # Report paths and alternative analyzers must not duplicate
                    # one package/version/advisory within this immutable image.
                    key = package, version, identifier
                    if key not in findings:
                        archive.require(len(findings) < MAX_FINDINGS, 'finding_bound')
                        findings[key] = {'vulnerability_id': identifier, 'severity': severity,
                            'package_types': [row['Type']], 'package': package, 'version': version,
                            'fixed_in': fixes, 'fix_status': status, 'classes': [row['Class']],
                            'image_digest': selected['manifest_digest']}
                    else:
                        old = findings[key]
                        old['fixed_in'] = sorted(set(old['fixed_in']) | set(fixes))[:64]
                        old['classes'] = sorted(set(old['classes']) | {row['Class']})
                        old['package_types'] = sorted(set(old['package_types']) | {row['Type']})
                        if severity == 'CRITICAL': old['severity'] = severity
                except Exception:
                    complete = False
        except Exception:
            complete = False
    result['scan_complete'] = complete
    os_info = metadata.get('OS', {})
    eosl = type(os_info) is dict and os_info.get('EOSL') is True
    current = complete and database.get('fresh') is True and not eosl and 'os_end_of_support' not in diagnostics
    result.update(findings=[findings[key] for key in sorted(findings)], scanned_classes=sorted(classes),
                  complete=current, coverage_status='COMPLETE' if current else 'UNKNOWN',
                  status='FAIL' if findings else 'PASS' if current else 'UNKNOWN',
                  os_end_of_support=eosl, diagnostics=diagnostics,
                  reason=None if current else interrupted or (diagnostics[0] if diagnostics else
                    'scan_incomplete' if not complete else 'os_end_of_support' if eosl else 'database_stale'))
    return result


def _environment(root):
    for part in ('home', 'cache', 'tmp'):
        (root / part).mkdir(mode=0o700)
    return {'PATH': '/usr/bin:/bin', 'HOME': str(root / 'home'), 'XDG_CONFIG_HOME': str(root / 'home/.config'),
            'XDG_CACHE_HOME': str(root / 'cache'), 'TMPDIR': str(root / 'tmp'), 'LANG': 'C.UTF-8', 'NO_COLOR': '1'}


def scan_image(image_identity, manifest, config, layers, *, native_verifier=None, enabled=False,
               db_cache=None, cli=DEFAULT_CLI, archive_format='docker', timeout=MAX_SECONDS,
               cancel=lambda: None, scratch_parent=None):
    """Owned archive seam only; no integration hook, native IAM inference or tag pull."""
    result = _base()
    result['reason'] = 'disabled'
    if enabled is not True:
        return result
    scratch = None
    try:
        selected = archive.identity(image_identity)
        result['image'] = selected
        archive.require(type(timeout) in (float, int) and 0 < timeout <= MAX_SECONDS,
                        'bounded_timeout_required')
        end = time.monotonic() + timeout
        def check():
            cancel()
            archive.require(time.monotonic() < end, 'deadline')
        check()
        archive.require(callable(native_verifier) and native_verifier() == selected, 'native_binding_unavailable')
        check()
        executable = Path(cli)
        archive.require(executable.is_absolute() and executable.is_file() and os.access(executable, os.X_OK),
                        'installed_trivy_required')
        before = database_state(db_cache)
        result['database'] = before
        scratch = tempfile.TemporaryDirectory(prefix='peaso-trivy-image-', dir=scratch_parent)
        root = Path(scratch.name)
        root.chmod(0o700)
        env = _environment(root)
        path = root / 'image.tar'
        diff_ids = archive.decode(config)['rootfs']['diff_ids']
        info = executable.stat()
        executable_key = (str(executable), info.st_dev, info.st_ino, info.st_size,
                          info.st_mtime_ns, info.st_ctime_ns)
        key = (selected['manifest_digest'], selected['config_digest'], archive_format,
               str(Path(db_cache)), executable_key,
               tuple(repr(before.get(k)) for k in ('schema_version', 'updated_at', 'next_update',
                                               'downloaded_at', 'db_stat_identity', 'metadata_sha256')))
        with _SCANS.single_flight(key, check):
            cached = _SCANS.get(key)
            if cached is not None:
                # Same verified bytes, executable file and unchanged DB generation:
                # the offline report is identical. Re-prove the current inputs first.
                archive.validate(selected, manifest, config, layers, check)
                proof, raw, stderr, code, peak = cached
                proof, reason = dict(proof), None
            else:
                probe = VersionProbe(executable, env, root, end, cancel)
                try:
                    proof = archive.write_archive(path, selected, manifest, config, layers,
                                                  archive_format=archive_format, check=check)
                finally:
                    probe.wait()
                result['archive'] = proof
                policy = root / 'trivy.yaml'
                policy.write_text('{}\n')
                ignore = root / '.trivyignore'
                ignore.write_text('')
                version, _, version_exit, version_reason, _ = probe.result()
                archive.require(version_exit == 0 and version_reason is None
                                and re.search(rb'(?m)^Version: 0\.68\.1\s*$', version), 'pinned_trivy_version_unavailable')
                argv = [str(executable), 'image', '--input', str(path), *FLAGS,
                        '--cache-dir', str(Path(db_cache)), '--config', str(policy), '--ignorefile', str(ignore),
                        '--timeout', str(max(1, math.ceil(end - time.monotonic()))) + 's']
                raw, stderr, code, reason, peak = process._execute(argv, env, root, end, cancel)
                if type(code) is int and code == 0 and reason is None and raw:
                    _SCANS.put(key, (dict(proof), raw, stderr, code, peak), len(raw) + len(stderr))
        result['archive'] = proof
        result.update(parse_report(raw, code, selected, diff_ids=diff_ids, database=before,
                                   interrupted=reason, stderr=stderr))
        result['archive'] = proof
        result['invocation'] = {'command': 'trivy image --input <owned archive>', 'flags': list(FLAGS),
            'archive_format': archive_format, 'exit_code': code, 'stdout_bytes': len(raw),
            'stderr_bytes': len(stderr), 'stdout_sha256': hashlib.sha256(raw).hexdigest(),
            'scratch_peak_bytes_observed': peak, 'process_group_cleanup': reason != 'process_group_cleanup_failed'}
        if not raw:
            diagnostics = _diagnostics(stderr)
            result['diagnostics'] = diagnostics
            if diagnostics and reason is None: result['reason'] = diagnostics[0]
        after = database_state(db_cache)
        db_same = _same_database(before, after)
        result['database_revalidated'] = db_same
        try:
            same = native_verifier() == selected
        except Exception:
            same = False
        if not same or not db_same:
            result.update(status='UNKNOWN', complete=False, scan_complete=False, coverage_status='UNKNOWN',
                          reason='native_binding_changed' if not same else 'database_changed')
            result['historical_findings'] = result['findings']
            result['findings'] = []
    except Exception as exc:
        allowed = {'bounded_timeout_required', 'native_binding_unavailable', 'installed_trivy_required',
                   'cached_db_required', 'regular_cached_db_required', 'bounded_db_metadata_required',
                   'db_schema_2_required', 'db_timestamps_inconsistent', 'pinned_trivy_version_unavailable'}
        result.update(status='UNKNOWN', complete=False, scan_complete=False, coverage_status='UNKNOWN',
            reason=str(exc) if type(exc) is ValueError and str(exc) in allowed else 'input_or_scan_unavailable')
    finally:
        archive.release_staged(image_identity, manifest, config, layers)
        if scratch is not None:
            try:
                scratch.cleanup()
                result['owned_scratch_removed'] = True
            except Exception:
                result.update(complete=False, coverage_status='UNKNOWN', reason='scratch_cleanup_failed',
                              owned_scratch_removed=False)
                if result['status'] != 'FAIL': result['status'] = 'UNKNOWN'
    return result
