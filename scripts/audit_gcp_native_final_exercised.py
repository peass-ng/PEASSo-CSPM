#!/usr/bin/env python3
"""Build the source-reviewed, offline GCP Hardening admission receipt.

Reads only private saved pairs. The decision list is intentionally explicit;
zero AI disagreement alone never admits a check.
"""
import gzip
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from peaso.ai.native_final import reviews as native_reviews
from peaso.ai.pipeline import inputs
from peaso.ai.review_groups import plan

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = Path.home() / 'peaso-work/native-final-gcp-private'
SCANS = ('0864235ed9db4305a594e55bf8bceb82',
         '1504c3e6f26f4f64a1997d12ab0b259e',
         '60569e3d2b9a4d08b63873355bc7b6c8',
         '753bd3eebb7340ca8f7d496106577b8d')
# Reviewed evaluator sources: API property, immutable scan clock, complete
# inventory join, bounded enum, or a count of those properties only.
ADMIT = frozenset('''
gcp.compute.secure_boot
gcp.gke.secrets_encryption
gcp.network.custom_subnets
gcp.reviewed.compute.deletion_protection
gcp.subnetwork.private_google_access
gcp.claude.firewall.logging_enabled
gcp.claude2.bigquery_dataset.default_cmek
gcp.claude.bucket.retention_90_days
gcp.reviewed.storage.access_logging
gcp.reviewed.storage.versioning
gcp.reviewed.storage.lifecycle
gcp_bucket_logging_enabled_fb7cc594582a
gcp.storage.uniform_access
gcp_pubsub_topic_cmek
gcp.ports.compute_network_dns_logging_scoped
gcp.claude.instance.disks_csek
gcp.htbp.kms.destroy_window_not_shortened
gcp.ports.compute_disk_encrypted_with_csk
gcp.ports.compute_instance_with_no_public_ip_addresses
gcp.reviewed.network.no_default_vpc
gcp.claude.instance_group_manager.autohealing
gcp.claude.instance_group_manager.multiple_zones
gcp.claude.gke.binary_authorization
gcp.claude.gke.zone_redundant
gcp.ports.kubernetes_cluster_intra_node_visibility_enabled
'''.split())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def signature(evidence):
    return [[key, type(value).__name__] for key, value in sorted(evidence.items())]


def reason(cid, disagreement):
    if disagreement:
        return 'saved AI/native verdict disagreement'
    if 'metric_alert' in cid or cid in {
            'gcp_kms_key_destroy_alert', 'gcp_logging_enumeration_alert',
            'gcp_cloudsql_backup_failure_alert'}:
        return 'filter or alert condition text requires semantic interpretation'
    if 'secret_indicators' in cid:
        return 'content and intent inference'
    if cid in ADMIT:
        return 'source-proven recorded API field/count/membership predicate'
    return 'source reviewed; saved evidence does not establish a bounded admission proof'


def main():
    source_map = {}
    for line in (PRIVATE / 'check-source-map.tsv').read_text().splitlines():
        cid, source, line_number, function = line.split('\t')
        if cid == 'gcp.htbp.kms.destroy_window_not_shortened':
            source, line_number = 'peaso/checks/hacktricks_bp_gcp.py', '273'
        source_map[cid] = (source, int(line_number), function)
    all_rows = defaultdict(lambda: {'rows': 0, 'representatives': 0,
                                    'disagreements': 0, 'by_scan': {}, 'signatures': set()})
    scan_receipts = []
    for scan in SCANS:
        pre, final = [PRIVATE / f'{scan}-{suffix}.json.gz'
                      for suffix in ('pre-ai', 'final')]
        with gzip.open(pre, 'rt') as stream:
            before = json.load(stream)
        with gzip.open(final, 'rt') as stream:
            after = json.load(stream)
        if before['snapshot_id'] != after['snapshot_id'] or after['ai']['status'] != 'completed':
            raise ValueError('pair is not completed same-snapshot: ' + scan)
        flat = [row for group in before['findings']
                for row in (group.get('observations') or [group])]
        hard, _, _ = inputs(dict(before, findings=flat))
        representatives, _ = plan(hard)
        rep_counts = Counter(row['check_id'] for row in representatives)
        reviews = {row['finding_id']: row for row in after['ai']['reviews']['hardening']}
        synthetic = {row['finding_id']: row for row in native_reviews(hard)}
        per_scan = defaultdict(lambda: {'rows': 0, 'representatives': 0, 'disagreements': 0})
        for row in hard:
            cid = row['check_id']
            disagreement = reviews.get(row['id']) != synthetic.get(row['id'])
            bucket = all_rows[cid]
            bucket['rows'] += 1
            bucket['disagreements'] += disagreement
            bucket['signatures'].add(json.dumps(signature(row['evidence'])))
            per_scan[cid]['rows'] += 1
            per_scan[cid]['disagreements'] += disagreement
        for cid, count in rep_counts.items():
            all_rows[cid]['representatives'] += count
            per_scan[cid]['representatives'] = count
        for cid, values in per_scan.items():
            all_rows[cid]['by_scan'][scan] = values
        scan_receipts.append({'scan_id': scan, 'pre_ai_sha256': sha(pre),
                              'final_sha256': sha(final),
                              'snapshot_id_sha256': hashlib.sha256(before['snapshot_id'].encode()).hexdigest(),
                              'hardening_rows': len(hard), 'representatives': len(representatives)})
    if set(all_rows) != set(source_map) or not ADMIT <= set(all_rows):
        raise ValueError('source map or admitted IDs do not cover exact exercised checks')
    checks = []
    for cid in sorted(all_rows):
        value = all_rows[cid]
        source, line, function = source_map[cid]
        if cid in ADMIT and value['disagreements']:
            raise ValueError('admitted disagreement: ' + cid)
        checks.append({'check_id': cid, 'decision': 'admit' if cid in ADMIT else 'exclude',
                       'reason': reason(cid, value['disagreements']),
                       'source': source, 'source_line': line, 'source_function': function,
                       'source_sha256': sha(ROOT / source),
                       'rows': value['rows'], 'representatives': value['representatives'],
                       'disagreements': value['disagreements'],
                       'by_scan': value['by_scan'],
                       'evidence_signatures': [json.loads(s) for s in sorted(value['signatures'])]})
    receipt = {'version': 2, 'provider': 'gcp', 'mode': 'offline_source_audit',
               'scans': scan_receipts, 'checks': checks,
               'admitted_check_ids': sorted(ADMIT),
               'admitted_rows': sum(row['rows'] for row in checks if row['decision'] == 'admit'),
               'admitted_representatives': sum(row['representatives'] for row in checks if row['decision'] == 'admit'),
               'hosted_qualified': False, 'runtime_enabled': False}
    target = ROOT / 'docs/ai-review/native-final-gcp-exercised-audit-v2.json'
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'checks': len(checks), 'admitted': len(ADMIT),
                      'rows': receipt['admitted_rows'],
                      'representatives': receipt['admitted_representatives']}))


if __name__ == '__main__':
    main()
