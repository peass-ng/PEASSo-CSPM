"""Compact prioritization overview with indexed, lossless local evidence lookup."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import gzip
import stat
from collections import Counter, defaultdict

RISK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
REJECTED = {'PASS', 'NOT_APPLICABLE', 'EMPTY'}
CONTEXT_COMPRESS_THRESHOLD = 64 * 1024 * 1024
MAX_CONTEXT_BYTES = 2 * 1024 * 1024 * 1024


def encode(value, *, canonical=False):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), default=str, sort_keys=canonical)


def compact(value, depth=0):
    """Samples are explicitly marked; the database retains original values."""
    if isinstance(value, str):
        return value if len(value) <= 240 else value[:240] + '… [more in detail]'
    if isinstance(value, dict):
        if depth >= 3:
            return {'keys': list(value)[:8], 'key_count': len(value), 'detail_required': True}
        result = {key: compact(item, depth + 1) for key, item in list(value.items())[:8]}
        if len(value) > 8:
            result['_omitted_keys'] = len(value) - 8
        return result
    if isinstance(value, (list, tuple)):
        return {'count': len(value), 'sample': [compact(item, depth + 1) for item in value[:3]]}
    return value


REFERENCE_KEYS = {'id', 'resource_id', 'resource_ref', 'native_id', 'native_resource_ref', 'source', 'target',
    'principal', 'principal_id', 'principalId', 'member', 'members', 'arn', 'Arn', 'RoleArn', 'roleArn',
    'email', 'upn', 'role', 'role_id', 'roleDefinitionId', 'policyArn', 'policy_arn',
    'node_id', 'source_node', 'target_node', 'source_id', 'target_id', 'edge_ids',
    'findings', 'finding_id', 'evidence_id', 'evidence_refs', 'referenced_grants'}


def strings(value, reference=False):
    if isinstance(value, str):
        if value != '*' and (reference or value.startswith(('arn:', 'k8s://', 'projects/', 'organizations/',
                '/subscriptions/', '/tenants/', 'serviceAccount:', 'user:', 'group:'))):
            yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if key not in {'scope', 'scopes', 'label', 'title', 'description', 'rationale', 'remediation',
                           'reason', 'review', 'provider', 'category', 'service', 'severity', 'status', 'confidence', 'check_id'}:
                yield from strings(item, key in REFERENCE_KEYS)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from strings(item, reference)


def bounded(value):
    if len(encode(value)) <= 600:
        return value
    return {'detail_required': True, 'type': type(value).__name__,
            'count': len(value) if isinstance(value, (list, dict, str)) else None,
            'keys': list(value)[:8] if isinstance(value, dict) else None}


def build(root, platform, assigned, reviews, write_json):
    root = Path(root)
    database = root / 'context.sqlite'
    os.close(os.open(database, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    db = sqlite3.connect(database)
    try:
        db.executescript('''
            CREATE TABLE records(domain TEXT, id TEXT, summary TEXT, detail TEXT,
                                 risk INTEGER, candidate INTEGER, PRIMARY KEY(domain,id));
            CREATE TABLE links(a_domain TEXT,a_id TEXT,b_domain TEXT,b_id TEXT,
                               PRIMARY KEY(a_domain,a_id,b_domain,b_id));
            CREATE TABLE members(group_id TEXT,finding_id TEXT,PRIMARY KEY(group_id,finding_id));
        ''')
        aliases = defaultdict(set)
        identity_aliases = defaultdict(set)
        providers = {}
        groups = {}
        verdict_counts = Counter()
        report = platform.get('report', {})
        assigned_by_id = {row['id']: row for row in assigned}
        reviewed = {row['finding_id']: row for row in reviews}
        pending_records = []

        def flush_records():
            if pending_records:
                db.executemany('INSERT INTO records VALUES(?,?,?,?,?,?)', pending_records)
                pending_records.clear()

        def put(domain, ident, summary, detail, *, severity='info', candidate=False, names=(), identities=()):
            ident = str(ident)
            summary = {key: value if key in ('source', 'target', 'resource_id', 'native_id') else bounded(value)
                       for key, value in summary.items()}
            summary['id'] = ident
            pending_records.append((domain, ident, encode(summary), encode(detail),
                                    RISK.get(severity, 4), int(candidate)))
            if len(pending_records) >= 512:
                flush_records()
            provider = detail.get('provider') if isinstance(detail, dict) else None
            if not provider and isinstance(detail, dict) and isinstance(detail.get('finding'), dict):
                provider = detail['finding'].get('provider')
            providers[domain, ident] = provider or report.get('provider')
            for alias in (ident, *names):
                if isinstance(alias, str) and alias:
                    aliases[alias].add((domain, ident))
            for alias in identities:
                if isinstance(alias, str) and '@' in alias:
                    identity_aliases[providers[domain, ident], alias].add((domain, ident))

        from peaso.engine import hydrate_finding
        source_findings = report.get('findings', assigned)
        for index, raw in enumerate(source_findings):
            ident = raw.get('id', str(index))
            row = assigned_by_id.get(ident) or hydrate_finding(raw, report.get('check_frameworks'),
                report.get('check_meta'), report.get('check_meta_encoding'), report.get('remediation_templates'))
            category = row.get('category')
            review = None if category in ('hardening', 'exposure') else reviewed.get(ident)
            verdict = review['verdict'] if review else row.get('status')
            # Keep every native status reachable; uncertainty is evidence too.
            verdict_counts[f'{category}:{verdict}'] += 1
            summary = {key: row[key] for key in ('check_id', 'category', 'title', 'scope', 'severity', 'resource_id', 'status') if key in row}
            summary['verdict'] = verdict
            if review and review.get('reason'):
                summary['review_reason'] = review['reason']
            put('findings', ident, summary, {'finding': row, 'review': review}, severity=row.get('severity', 'info'))
            if (verdict in REJECTED or row.get('status') not in ('FAIL', 'UNKNOWN', 'MANUAL', 'DENIED')):
                continue
            key = (category, row.get('check_id'), verdict)
            group = groups.setdefault(key, {'category': category, 'check_id': row.get('check_id'),
                'title': row.get('title'), 'verdict': verdict, 'severity': row.get('severity', 'info'),
                'members': [], 'resources': set(), 'scopes': set(), 'variants': set(),
                'example_finding_id': ident,
                'evidence_sample': compact(row.get('evidence', {})), 'remediation': compact(row.get('remediation', ''))})
            group['members'].append(ident)
            group['resources'].add(row.get('resource_id'))
            group['scopes'].add(row.get('scope'))
            group['variants'].add(hashlib.sha256(encode(row.get('evidence', {}), canonical=True).encode()).hexdigest())
            if RISK.get(row.get('severity'), 4) < RISK.get(group['severity'], 4):
                group['severity'] = row['severity']
                group['example_finding_id'] = ident
                group['evidence_sample'] = compact(row.get('evidence', {}))
                group['remediation'] = compact(row.get('remediation', ''))
        for key, group in groups.items():
            ident = hashlib.sha256(encode(key).encode()).hexdigest()[:24]
            summary = {key: group[key] for key in ('category', 'check_id', 'title', 'verdict', 'severity', 'example_finding_id', 'evidence_sample', 'remediation')}
            summary.update(finding_count=len(group['members']), resource_count=len(group['resources']),
                           scope_count=len(group['scopes']), scope_sample=sorted(scope for scope in group['scopes'] if isinstance(scope, str))[:3],
                           evidence_variant_count=len(group['variants']))
            put('finding_groups', ident, summary, summary, severity=group['severity'], candidate=True)
            flush_records()
            db.executemany('INSERT INTO members VALUES(?,?)', ((ident, member) for member in group['members']))

        for index, row in enumerate(platform.get('inventory', [])):
            email = (row.get('data') or {}).get('email')
            identities = [email]
            if row.get('provider', report.get('provider')) == 'gcp' and row.get('type') == 'service_account' and isinstance(email, str):
                identities.append('serviceAccount:' + email)
            put('resources', row.get('id', str(index)),
                {key: row[key] for key in ('native_id', 'type', 'provider', 'scope') if key in row}, row,
                names=(row.get('native_id'),), identities=identities)
        least = platform.get('least_privilege', {})
        for index, row in enumerate(least.get('items', [])):
            counts = Counter(item.get('confidence', 'unknown') for item in row.get('suggestions', []))
            summary = {key: compact(row[key]) for key in ('principal', 'label', 'severity', 'scopes', 'exposures') if key in row}
            summary.update(suggestion_counts=dict(counts), suggestions=compact(row.get('suggestions', [])))
            put('least_privilege', row.get('id', str(index)), summary, row,
                severity=row.get('severity', 'info'), candidate=bool(row.get('suggestions') or row.get('exposures')),
                names=(row.get('principal'),), identities=(row.get('principal'),))

        graphs = report.get('graphs', {})
        for name in ('privesc', 'iam', 'network'):
            graph = graphs.get(name) or {}
            put('metadata', name, compact({key: value for key, value in graph.items() if key not in ('nodes', 'edges')}),
                {key: value for key, value in graph.items() if key not in ('nodes', 'edges')})
            for kind in ('nodes', 'edges'):
                records = graph.get(kind, [])
                original_ids = Counter(str(row.get('id', index)) for index, row in enumerate(records))
                seen_records = set()
                for index, row in enumerate(records):
                    original_id = str(row.get('id', index))
                    record_id = original_id
                    if original_ids[original_id] > 1:
                        # Historical maps used an unordered edge hash: opposite
                        # directions could share an ID. Keep every distinct row,
                        # with ambiguous original aliases linked to neither one.
                        signature = encode(row, canonical=True)
                        record_id += ':' + hashlib.sha256(signature.encode()).hexdigest()
                        if record_id in seen_records:
                            continue
                    seen_records.add(record_id)
                    summary = {key: row[key] if key in ('source', 'target', 'resource_id', 'native_id') else compact(row[key]) for key in ('source', 'target', 'type', 'label', 'scope', 'provider',
                        'resource_id', 'native_id', 'confidence', 'layer', 'techniques', 'findings', 'risk_annotations',
                        'underlying_count', 'unresolved', 'unresolved_reason', 'facts_needed', 'exposures') if key in row}
                    card = row.get('card') or {}
                    if card:
                        summary['grants'] = compact({key: card[key] for key in ('grant_summary', 'effective_access', 'restrictions', 'source_grants_truncated') if key in card})
                        summary['grant_sample'] = compact([grant for grant in card.get('source_grants', [])
                            if grant.get('allowed_declaration') and RISK.get(grant.get('severity'), 4) <= 1][:3])
                    evidence = row.get('evidence') or {}
                    if name == 'network' and kind == 'edges':
                        for key in ('reachability', 'uncertainty', 'telemetry', 'native_rule'):
                            if key in evidence:
                                summary[key] = compact(evidence[key])
                    details = row.get('technique_details', [])
                    if details:
                        summary['technique_details'] = compact([{key: item[key] for key in ('id', 'severity', 'confidence', 'conditions', 'mitigation') if key in item} for item in details])
                    risk = (kind == 'edges' if name == 'privesc' else
                            bool(row.get('risk_annotations') or row.get('exposures') or (card.get('grant_summary') or {}).get('high_risk_allowed')) if name == 'iam' else
                            row.get('type') == 'rule_candidate' or bool(row.get('risk_annotations')))
                    severity = min((item.get('severity', 'info') or 'info' for item in details), key=lambda value: RISK.get(value, 4), default='info')
                    if risk and severity == 'info':
                        severity = 'high' if name == 'privesc' and row.get('confidence') == 'derived' else 'medium'
                    put(name + '_' + kind, record_id, summary, row, severity=severity, candidate=risk,
                        names=(original_id, row.get('resource_id'), row.get('native_id')),
                        identities=((row.get('attrs') or {}).get('email'), (row.get('attrs') or {}).get('upn')))

        put('metadata', 'least_privilege_coverage', compact(least.get('coverage', {})), least.get('coverage', {}))
        gaps = [row for row in report.get('coverage', []) if row.get('status') not in ('evaluated', 'collected', 'empty')]
        put('metadata', 'coverage_gaps', {'count': len(gaps), 'sample': compact(gaps[:3])}, gaps)
        scan = {key: report[key] for key in ('provider', 'snapshot_id', 'created_at', 'scopes') if key in report}
        put('metadata', 'scan', compact(scan), scan)
        flush_records()

        # Link only exact, unambiguous record references. No topology or access is
        # inferred from matching names, public addresses or broad permissions.
        rows = db.execute('SELECT domain,id,detail FROM records WHERE domain != ? ORDER BY domain,id', ('finding_groups',))
        pending_links = []
        for domain, ident, detail in rows:
            for value in set(strings(json.loads(detail))):
                matches = set(aliases.get(value, ())) | identity_aliases.get((providers.get((domain, ident)), value), set())
                by_domain = defaultdict(list)
                for target in matches:
                    by_domain[target[0]].append(target)
                for targets in by_domain.values():
                    if len(targets) == 1 and targets[0] != (domain, ident):
                        pending_links.append((domain, ident, *targets[0]))
                        if len(pending_links) >= 512:
                            db.executemany('INSERT OR IGNORE INTO links VALUES(?,?,?,?)', pending_links)
                            pending_links.clear()
        if pending_links:
            db.executemany('INSERT OR IGNORE INTO links VALUES(?,?,?,?)', pending_links)
        # Secondary indexes are built once after the bulk load (same schema and
        # rows) instead of being maintained on every insert.
        db.executescript('''
            CREATE INDEX record_order ON records(domain,candidate DESC,risk,id);
            CREATE INDEX reverse_links ON links(b_domain,b_id);
        ''')
        db.commit()
        from .decision_brief import catalog
        sections = catalog(db)
        db.commit()
        # Preserve original source fields after graph linking: large raw fields
        # need exact lookup, not another expensive reference traversal.
        for key, value in platform.get('source_report', report).items():
            put('source_report', key, {'field': key}, value)
        for key, value in platform.get('snapshot_context', {}).items():
            put('source_snapshot', key, {'field': key}, value)
        for row in platform.get('source_inventory', []):
            put('source_resources', row['id'],
                {key: row[key] for key in ('native_id', 'type', 'provider', 'scope', 'service') if key in row}, row)
        if 'network_review' in platform:
            put('metadata', 'network_review', {'field': 'network_review'}, platform['network_review'])
        flush_records()
        db.commit()
        resource_counts = dict(Counter(row.get('type', 'unknown') for row in platform.get('source_inventory', platform.get('inventory', []))))
        source_counts = dict(db.execute("SELECT domain,COUNT(*) FROM records WHERE domain NOT LIKE 'decision_%' GROUP BY domain ORDER BY domain"))
        overview = {'version': 2, 'scan': {key: compact(value) for key, value in scan.items()},
            'review_counts': dict(sorted(verdict_counts.items())),
            'data_index': {'domains': source_counts, 'resource_types': resource_counts,
                'report_fields': list(platform.get('source_report', report)),
                'snapshot_fields': list(platform.get('snapshot_context', {})),
                'lookup': "python context.py list DOMAIN --all; python context.py get DOMAIN ID --path ''; use --keys to page object keys and JSON Pointer paths for large values",
                'semantics': 'Every native finding status is reachable. Cases are critical-first candidates; source_report retains every original report field. source_resources retains unprojected inventory when resources is projected. source_snapshot retains account metadata and collection receipts.'},
            'counts': {'cases': {key: len(value) for key, value in sections.items()}, 'source_records': source_counts},
            'coverage': {'least_privilege': compact(least.get('coverage', {})), 'scan_gaps': compact(gaps)},
            'sections': sections,
            'reading_notes': [
                'Sections contain every decision group, not a top-N sample. Read all five compact sections before ranking actions.',
                'Counts describe underlying observations, not automatically distinct resources or attack paths. Samples and detail_required values require targeted lookup.',
                'Groups preserve state/confidence; member facts and conditions may differ. Inspect selected members before prescribing one change.',
                'Related counts mean shared explicit record references, not proof of reachability, effective permission, federation or an attack chain.',
                'Declared grants are review candidates; provider recommendations are distinct. Preserve conditions, uncertainty and coverage limitations.',
                'All full findings, resource properties, graph nodes/edges and least-privilege records are in context.sqlite. No platform administrator token is needed.']}
        if 'network_review' in platform:
            overview['network_review'] = platform['network_review']
        write_json(root / 'platform.json', overview)
        source = Path(__file__).with_name('context_reader.py').read_text()
        fd = os.open(root / 'context.py', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(source)
    finally:
        db.close()
    compress_context(root)
def compress_context(root):
    """Preserve large SQLite contexts within the existing bounded transport."""
    root = Path(root)
    database, packed = root / 'context.sqlite', root / 'context.sqlite.gz'
    metadata = database.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError('invalid_briefing_context_file')
    if metadata.st_size > MAX_CONTEXT_BYTES:
        raise ValueError('briefing_context_too_large')
    if metadata.st_size < CONTEXT_COMPRESS_THRESHOLD:
        return
    source_fd = os.open(database, os.O_RDONLY | os.O_NOFOLLOW)
    output_fd = None
    created = False
    try:
        output_fd = os.open(packed, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created = True
        with os.fdopen(output_fd, 'wb') as output:
            output_fd = None
            with gzip.GzipFile(filename='', mode='wb', fileobj=output, compresslevel=1, mtime=0) as writer:
                with os.fdopen(source_fd, 'rb') as source:
                    source_fd = None
                    total = 0
                    while chunk := source.read(1024 * 1024):
                        total += len(chunk)
                        if total > MAX_CONTEXT_BYTES:
                            raise ValueError('briefing_context_too_large')
                        writer.write(chunk)
        database.unlink()
    except BaseException:
        if output_fd is not None:
            os.close(output_fd)
        # Only remove the output created by this invocation.
        if created:
            packed.unlink(missing_ok=True)
        raise
    finally:
        if source_fd is not None:
            os.close(source_fd)


def materialize_context(root):
    """Expand a compressed context before starting an agent, with finite disk use."""
    root = Path(root)
    packed, database = root / 'context.sqlite.gz', root / 'context.sqlite'
    try:
        metadata = packed.lstat()
    except FileNotFoundError:
        return
    from .fargate import MAX_INPUT
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_INPUT:
        raise ValueError('invalid_briefing_context_file')
    source_fd = os.open(packed, os.O_RDONLY | os.O_NOFOLLOW)
    output_fd = None
    created = False
    try:
        output_fd = os.open(database, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created = True
        with os.fdopen(output_fd, 'wb') as output:
            output_fd = None
            with os.fdopen(source_fd, 'rb') as source:
                source_fd = None
                with gzip.GzipFile(fileobj=source, mode='rb') as reader:
                    total = 0
                    while chunk := reader.read(1024 * 1024):
                        if not total and not chunk.startswith(b'SQLite format 3\x00'):
                            raise ValueError('invalid_briefing_context_header')
                        total += len(chunk)
                        if total > MAX_CONTEXT_BYTES:
                            raise ValueError('briefing_context_too_large')
                        output.write(chunk)
                    if not total:
                        raise ValueError('invalid_briefing_context_header')
        packed.unlink()
    except BaseException:
        if output_fd is not None:
            os.close(output_fd)
        if created:
            database.unlink(missing_ok=True)
        raise
    finally:
        if source_fd is not None:
            os.close(source_fd)
