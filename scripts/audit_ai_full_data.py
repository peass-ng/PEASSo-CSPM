#!/usr/bin/env python3
"""Offline saved-snapshot AI input audit. Emits counts/hashes, never evidence values."""
import argparse
from collections import Counter
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import sqlite3
import subprocess
import sys
import tempfile
import time

from peaso.ai import briefing, network
from peaso.ai.pipeline import private_json
from peaso.snapshot import resources


def load(path):
    # Avoid simultaneously holding compressed bytes, expanded bytes, decoded
    # text and the object graph. Agent readers do not run this capture loader.
    with Path(path).open('rb') as source:
        compressed = source.read(2) == b'\x1f\x8b'
    with (gzip.open(path, 'rt') if compressed else Path(path).open()) as source:
        return json.load(source)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


_AUDIT_STATE = {'phase': 'argument_parse', 'output': None, 'workspace': None}


def _receipt(path, payload):
    """Atomically write count-only audit state in a private persistent directory."""
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(payload, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _checkpoint(phase, **counts):
    _AUDIT_STATE['phase'] = phase
    payload = {'phase': phase, 'counts': counts, 'utc_unix_seconds': time.time()}
    output = _AUDIT_STATE['output']
    if output is not None:
        _receipt(str(output) + '.progress.json', payload)
    print(json.dumps(payload, sort_keys=True), file=sys.stderr, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--stage', choices=('network', 'priorities'), required=True)
    parser.add_argument('--baseline', default='ec306486')
    parser.add_argument('--output', required=True)
    parser.add_argument('--only-after', action='store_true')
    parser.add_argument('--saved-ai', help='Cached AI result from the exact same scan; no live call')
    parser.add_argument('--retain-workspace', help='Private directory for bounded reader measurement')
    args = parser.parse_args()
    _AUDIT_STATE['output'] = args.output
    _checkpoint('load_start')
    snapshot, report = load(args.snapshot), load(args.report)
    saved_ai = load(args.saved_ai) if args.saved_ai else report.get('ai', {})
    if saved_ai.get('network', {}).get('findings'):
        report = network.with_findings(report, saved_ai['network']['findings'])
    _checkpoint('load_complete', report_findings=len(report.get('findings', [])),
                cached_network_findings=len(saved_ai.get('network', {}).get('findings', [])))
    inventory = resources(snapshot)
    from peaso.engine import hydrate_finding
    findings = [hydrate_finding(row, report.get('check_frameworks'), report.get('check_meta'),
                report.get('check_meta_encoding'), report.get('remediation_templates')) for row in report['findings']]
    expected_findings = Counter(f"{row.get('category')}:{row.get('status')}" for row in findings)
    from peaso.collectors import supported_types
    from peaso.analysis.network import NETWORK_TYPES
    from peaso.analysis.reachability import REACHABILITY_TYPES
    from peaso.checks import CHECKS
    from peaso.analysis import ANALYSIS_CHECKS
    catalog = {}
    for provider in ('aws', 'gcp', 'azure', 'k8s'):
        kinds = set(supported_types(provider))
        catalog[provider] = {
            'network_collections': sorted(kinds & (NETWORK_TYPES | set(REACHABILITY_TYPES[provider]))),
            'all_collections_reachable_in_original_inventory': sorted(kinds),
            'native_network_checks': sorted(c.id for c in CHECKS if c.provider == provider and
                (c.category == 'network' or c.kind in NETWORK_TYPES | set(REACHABILITY_TYPES[provider]))),
            'analysis_network_checks': sorted(c['id'] for c in ANALYSIS_CHECKS if c.get('category') == 'network')}
    if args.stage == 'priorities':
        _checkpoint('priorities_project_start', inventory_records=len(inventory))
        from peaso.least_privilege import project
        platform = {'report': report, 'inventory': inventory,
                    'snapshot_context': network.snapshot_context(snapshot),
                    'least_privilege': project(report['provider'], inventory, snapshot=snapshot),
                    'network_review': saved_ai.get('network', {'status': 'not_saved'})}
        _checkpoint('priorities_project_complete', inventory_records=len(inventory))
    result = {'stage': args.stage, 'baseline_revision': args.baseline,
              'snapshot_sha256': sha(args.snapshot), 'report_sha256': sha(args.report),
              'provider': report['provider'], 'snapshot_id': snapshot['snapshot_id'],
              'saved_ai_sha256': sha(args.saved_ai) if args.saved_ai else None,
              'cached_network_findings_added': len(saved_ai.get('network', {}).get('findings', [])),
              'input_inventory_by_type': dict(Counter(row['type'] for row in inventory)),
              'input_findings_by_category_status': dict(expected_findings), 'catalog': catalog, 'measurements': {}}
    with tempfile.TemporaryDirectory(prefix='ai-quality-baseline-') as baseline_dir:
        baseline_dir = Path(baseline_dir)
        modules = {}
        for name in ('briefing', 'network', 'context_reader'):
            path = baseline_dir/(name+'.py')
            path.write_bytes(subprocess.check_output(['git', 'show', args.baseline+':peaso/ai/'+name+'.py']))
            if name != 'context_reader':
                spec = importlib.util.spec_from_file_location('peaso.ai._audit_'+name, path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                modules[name] = module
        _checkpoint('baseline_modules_loaded')
        for arm in (('after',) if args.only_after else ('before', 'after')):
            builder = modules['briefing'] if arm == 'before' else briefing
            network_builder = modules['network'] if arm == 'before' else network
            with tempfile.TemporaryDirectory(prefix='ai-quality-'+arm+'-') as workspace:
                root = Path(workspace)
                _AUDIT_STATE['workspace'] = str(root)
                _checkpoint(arm + '_build_start')
                wall, cpu = time.perf_counter(), time.process_time()
                if args.stage == 'network':
                    prepared = network_builder.prepare(report, inventory, snapshot)
                    # Network's relative import must use the same arm's builder.
                    original = sys.modules['peaso.ai.briefing']
                    sys.modules['peaso.ai.briefing'] = builder
                    try:
                        network_builder.build(root, prepared, [], private_json)
                    finally:
                        sys.modules['peaso.ai.briefing'] = original
                else:
                    builder.build(root, platform, [], [], private_json)
                _checkpoint(arm + '_build_complete', files={p.name: p.stat().st_size for p in root.iterdir()})
                metrics = {'wall_seconds': round(time.perf_counter()-wall, 3),
                           'cpu_seconds': round(time.process_time()-cpu, 3),
                           'process_peak_rss_bytes': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                           'cloud_api_calls': 0, 'model_calls': 0,
                           'transport_file_bytes': {p.name: p.stat().st_size for p in root.iterdir()}}
                _checkpoint(arm + '_materialize_start')
                builder.materialize_context(root)
                _checkpoint(arm + '_materialize_complete', sqlite_bytes=(root/'context.sqlite').stat().st_size)
                if arm == 'after' and args.retain_workspace:
                    import shutil
                    target = Path(args.retain_workspace)
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    _checkpoint('retain_start', sqlite_bytes=(root/'context.sqlite').stat().st_size)
                    for name in ('context.py', 'context.sqlite', 'platform.json'):
                        shutil.copy2(root/name, target/name)
                    _checkpoint('retain_complete', sqlite_bytes=(target/'context.sqlite').stat().st_size)
                _checkpoint(arm + '_verify_start', inventory_records=len(inventory), report_fields=len(report))
                with sqlite3.connect(root/'context.sqlite') as db:
                    metrics['domain_counts'] = dict(db.execute('SELECT domain,COUNT(*) FROM records GROUP BY domain'))
                    metrics['findings_by_category_status'] = dict(Counter(
                        f"{r.get('category')}:{r.get('status')}"
                        for (raw,) in db.execute("SELECT summary FROM records WHERE domain='findings'") for r in [json.loads(raw)]))
                    if arm == 'after':
                        domain = 'source_resources' if args.stage == 'network' else 'resources'
                        def verify_original(domain, ident, expected):
                            original = db.execute('SELECT detail FROM records WHERE domain=? AND id=?', (domain, ident)).fetchone()
                            assert original is not None, 'original_missing'
                            stored = json.loads(original[0])
                            if stored != {'_exact_parts': True}:
                                assert stored == expected, 'original_mismatch'
                                return
                            for pointer, kind, raw, count in db.execute('SELECT path,kind,value,count FROM record_parts WHERE domain=? AND id=?', (domain, ident)):
                                value = expected
                                components = pointer.split('/')[1:] if pointer else []
                                # Text chunk paths use the character chunk index.
                                for encoded in components:
                                    key = encoded.replace('~1', '/').replace('~0', '~')
                                    if isinstance(value, str):
                                        value = value[int(key)*8192:(int(key)+1)*8192]
                                    else:
                                        value = value[int(key)] if isinstance(value, list) else value[key]
                                if kind == 'json':
                                    assert json.loads(raw) == value, 'fragment_mismatch'
                                else:
                                    assert count == len(value), 'fragment_count_mismatch'
                                    if kind in ('object', 'array'):
                                        keys = [row[0] for row in db.execute('SELECT key FROM record_parts WHERE domain=? AND id=? AND parent=? ORDER BY position', (domain, ident, pointer))]
                                        assert keys == (list(value) if kind == 'object' else [str(i) for i in range(len(value))]), 'fragment_keys_mismatch'
                        for row in inventory:
                            verify_original(domain, row['id'], row)
                        for key, value in report.items():
                            verify_original('source_report', key, value)
                        metrics['exact_original_inventory_records_verified'] = len(inventory)
                        metrics['exact_original_report_fields_verified'] = len(report)
                        if args.stage == 'priorities':
                            assert metrics['findings_by_category_status'] == dict(expected_findings)
                        baseline_ids = {ident for action in saved_ai.get('actions', []) for ident in action.get('finding_ids', [])}
                        present_ids = {ident for (ident,) in db.execute("SELECT id FROM records WHERE domain='findings'")}
                        metrics['cached_high_action_citations'] = {'total': len(baseline_ids),
                            'reachable': len(baseline_ids & present_ids), 'missing_ids': sorted(baseline_ids - present_ids)}
                        metrics['network_review_status'] = platform.get('network_review', {}).get('status') if args.stage == 'priorities' else None
                        metrics['critical_categories_preserved'] = sorted({row.get('category') for row in findings if row.get('severity') == 'critical'})
                        metrics['verification'] = 'Every original inventory record and every report field compared by decoded exact equality; all native statuses retained. This is input coverage, not a model-output quality claim.'
                    if arm == 'after':
                        metrics['largest_record_bytes'] = db.execute('SELECT MAX(length(CAST(detail AS BLOB))) FROM records').fetchone()[0]
                        if db.execute("SELECT 1 FROM sqlite_master WHERE name='record_parts'").fetchone():
                            metrics['exact_fragment_count'], metrics['largest_fragment_bytes'] = db.execute('SELECT COUNT(*),MAX(length(CAST(value AS BLOB))) FROM record_parts').fetchone()
                            assert metrics['largest_fragment_bytes'] <= 128 * 1024
                        assert metrics['largest_record_bytes'] <= 128 * 1024
                metrics['transport_total_bytes'] = sum(metrics['transport_file_bytes'].values())
                _checkpoint(arm + '_verify_complete', transport_bytes=metrics['transport_total_bytes'],
                            exact_inventory_records=metrics.get('exact_original_inventory_records_verified', 0))
                assert metrics['transport_total_bytes'] < 512 * 1024 * 1024, 'workspace_transport_exceeds_cap'
                result['measurements'][arm] = metrics
    _receipt(args.output, result)
    _checkpoint('complete', inventory_records=len(inventory), report_findings=len(findings))
    print(json.dumps({'stage': args.stage, 'output': args.output, 'inventory': len(inventory),
                      'findings': len(findings), 'measurements': {arm: {key: values[key] for key in
                        ('wall_seconds', 'cpu_seconds', 'process_peak_rss_bytes')} for arm, values in result['measurements'].items()}}))


if __name__ == '__main__':
    try:
        main()
    except BaseException as exc:
        output = _AUDIT_STATE.get('output')
        workspace = _AUDIT_STATE.get('workspace')
        files = {}
        if workspace and Path(workspace).exists():
            files = {p.name: p.stat().st_size for p in Path(workspace).iterdir() if p.is_file()}
        failure = {'phase': _AUDIT_STATE['phase'], 'exception_type': type(exc).__name__,
                   'workspace_file_bytes': files, 'utc_unix_seconds': time.time()}
        if output is not None:
            _receipt(str(output) + '.failure.json', failure)
        print(json.dumps(failure, sort_keys=True), file=sys.stderr, flush=True)
        raise
