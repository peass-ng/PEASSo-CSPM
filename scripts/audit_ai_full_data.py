#!/usr/bin/env python3
"""Offline saved-snapshot AI input audit. Emits counts/hashes, never evidence values."""
import argparse
from collections import Counter
import gzip
import hashlib
import importlib.util
import json
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
    raw = Path(path).read_bytes()
    return json.loads(gzip.decompress(raw) if raw.startswith(b'\x1f\x8b') else raw)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--stage', choices=('network', 'priorities'), required=True)
    parser.add_argument('--baseline', default='ec306486')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    snapshot, report = load(args.snapshot), load(args.report)
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
        from peaso.least_privilege import project
        platform = {'report': report, 'inventory': inventory,
                    'snapshot_context': network.snapshot_context(snapshot),
                    'least_privilege': project(report['provider'], inventory, snapshot=snapshot),
                    'network_review': (report.get('ai') or {}).get('network', {'status': 'not_saved'})}
    result = {'stage': args.stage, 'baseline_revision': args.baseline,
              'snapshot_sha256': sha(args.snapshot), 'report_sha256': sha(args.report),
              'provider': report['provider'], 'snapshot_id': snapshot['snapshot_id'],
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
        for arm in ('before', 'after'):
            builder = modules['briefing'] if arm == 'before' else briefing
            network_builder = modules['network'] if arm == 'before' else network
            with tempfile.TemporaryDirectory(prefix='ai-quality-'+arm+'-') as workspace:
                root = Path(workspace)
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
                metrics = {'wall_seconds': round(time.perf_counter()-wall, 3),
                           'cpu_seconds': round(time.process_time()-cpu, 3),
                           'process_peak_rss_bytes': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                           'cloud_api_calls': 0, 'model_calls': 0,
                           'transport_file_bytes': {p.name: p.stat().st_size for p in root.iterdir()}}
                builder.materialize_context(root)
                with sqlite3.connect(root/'context.sqlite') as db:
                    metrics['domain_counts'] = dict(db.execute('SELECT domain,COUNT(*) FROM records GROUP BY domain'))
                    metrics['findings_by_category_status'] = dict(Counter(
                        f"{r['finding'].get('category')}:{r['finding'].get('status')}"
                        for (raw,) in db.execute("SELECT detail FROM records WHERE domain='findings'") for r in [json.loads(raw)]))
                    if arm == 'after':
                        domain = 'source_resources' if args.stage == 'network' else 'resources'
                        for row in inventory:
                            original = db.execute('SELECT detail FROM records WHERE domain=? AND id=?', (domain, row['id'])).fetchone()
                            assert original is not None and json.loads(original[0]) == row, 'original_inventory_mismatch'
                        for key, value in report.items():
                            original = db.execute("SELECT detail FROM records WHERE domain='source_report' AND id=?", (key,)).fetchone()
                            assert original is not None and json.loads(original[0]) == value, 'original_report_mismatch'
                        metrics['exact_original_inventory_records_verified'] = len(inventory)
                        metrics['exact_original_report_fields_verified'] = len(report)
                        if args.stage == 'priorities':
                            assert metrics['findings_by_category_status'] == dict(expected_findings)
                        metrics['critical_categories_preserved'] = sorted({row.get('category') for row in findings if row.get('severity') == 'critical'})
                        metrics['verification'] = 'Every original inventory record and every report field compared by decoded exact equality; all native statuses retained. This is input coverage, not a model-output quality claim.'
                result['measurements'][arm] = metrics
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
    print(json.dumps({'stage': args.stage, 'output': args.output, 'inventory': len(inventory),
                      'findings': len(findings), 'measurements': {arm: {key: values[key] for key in
                        ('wall_seconds', 'cpu_seconds', 'process_peak_rss_bytes')} for arm, values in result['measurements'].items()}}))


if __name__ == '__main__':
    main()
