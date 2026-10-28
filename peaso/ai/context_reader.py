"""Read-only, paginated exact lookups for Network and Priorities evidence."""
import argparse
import json
import sqlite3


def small(value, budget=650):
    if len(json.dumps(value, ensure_ascii=False, default=str)) <= budget:
        return value
    return {'detail_required': True, 'count': len(value) if isinstance(value, (dict, list, str)) else None,
            'keys': list(value)[:12] if isinstance(value, dict) else None}


def fields(value):
    if not isinstance(value, dict):
        return small(value)
    important = ('confidence', 'outcome', 'outcome_inferred', 'conditions', 'technique_conditions',
                 'blockers_not_evaluated', 'blocker_verdicts', 'facts_needed', 'reachability', 'uncertainty',
                 'grants', 'granting_permissions', 'mitigation', 'native_rule')
    keys = [key for key in important if key in value]
    keys += [key for key in value if key not in keys]
    result = {key: small(value[key], 350) for key in keys[:10]}
    if len(keys) > 10:
        result['_omitted_fields'] = len(keys) - 10
    return result


def focus(db, domain, ident, limit):
    row = db.execute('SELECT detail FROM records WHERE domain=? AND id=?', (domain, ident)).fetchone()
    if row is None or not domain.startswith('decision_'):
        return {'error': 'decision_case_not_found'}
    case = json.loads(row[0])
    refs = '''WITH refs AS (
        SELECT domain,id,domain AS a_domain,id AS a_id FROM case_members WHERE case_domain=? AND case_id=?
        UNION SELECT m.domain,m.id,l.b_domain,l.b_id FROM case_members m JOIN links l
            ON m.domain=l.a_domain AND m.id=l.a_id WHERE m.case_domain=? AND m.case_id=?
        UNION SELECT m.domain,m.id,l.a_domain,l.a_id FROM case_members m JOIN links l
            ON m.domain=l.b_domain AND m.id=l.b_id WHERE m.case_domain=? AND m.case_id=?)
        SELECT r.domain,r.id,r.risk,COUNT(DISTINCT b.case_domain) AS breadth FROM refs a
        JOIN records r ON r.domain=a.domain AND r.id=a.id LEFT JOIN case_anchors b
            ON b.domain=a.a_domain AND b.id=a.a_id AND b.case_domain!=?
        GROUP BY r.domain,r.id'''
    params = (domain, ident) * 3 + (domain,)
    highest = db.execute(refs + ' ORDER BY r.risk,breadth DESC,r.domain,r.id LIMIT ?', (*params, min(3, limit))).fetchall()
    connected = db.execute(refs + ' ORDER BY breadth DESC,r.risk,r.domain,r.id LIMIT 1', params).fetchone()
    selected = highest[:1]
    if connected and connected not in selected and limit > 1:
        selected.append(connected)
    selected += [item for item in highest if item not in selected][:max(0, min(3, limit) - len(selected))]
    members = []
    for source_domain, source_id, _, breadth in selected:
        record = db.execute('SELECT summary,detail FROM records WHERE domain=? AND id=?', (source_domain, source_id)).fetchone()
        original = json.loads(record[1])
        item = {'ref': {'domain': source_domain, 'id': source_id}, 'summary': json.loads(record[0]),
                'linked_sections': breadth, 'evidence': {}, 'related_total': 0, 'related': []}
        if source_domain == 'findings':
            finding = original.get('finding', {})
            item['evidence'] = {'observed': fields(finding.get('evidence', {})),
                                'review': original.get('review'), 'remediation': small(finding.get('remediation'))}
        elif source_domain == 'least_privilege':
            facts = case['facts']
            matching = [entry for entry in original.get('suggestions', []) if
                entry.get('confidence', 'unknown') == case['state'] and entry.get('kind', 'access') == facts.get('kind')
                and entry.get('source', 'collected evidence') == facts.get('source')]
            item['evidence'] = {'principal': original.get('principal'), 'matching_suggestion_count': len(matching),
                'matching_suggestions_sample': [fields(entry) for entry in matching[:3]],
                'exposures': small(original.get('exposures', []))}
        elif source_domain.startswith('privesc_'):
            details = original.get('technique_details', [])
            associated = []
            for finding_id in original.get('findings', [])[:2]:
                finding_row = db.execute("SELECT detail FROM records WHERE domain='findings' AND id=?", (finding_id,)).fetchone()
                if finding_row:
                    evidence = json.loads(finding_row[0]).get('finding', {}).get('evidence', {})
                    associated.append({'finding_id': finding_id, **{key: small(evidence[key], 350) for key in
                        ('conditions', 'technique_conditions', 'blockers_not_evaluated', 'blocker_verdicts', 'facts_needed') if key in evidence}})
            item['evidence'] = {'source': original.get('source'), 'target': original.get('target'),
                'confidence': original.get('confidence'), 'technique_count': len(details),
                'techniques_sample': [fields(entry) for entry in details[:2]], 'finding_constraints_sample': associated}
        elif source_domain.startswith('iam_'):
            card = original.get('card') or {}
            grants = card.get('source_grants', [])
            grants = sorted(grants, key=lambda entry: (not entry.get('allowed_declaration'),
                {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(entry.get('severity'), 4)))
            item['evidence'] = {key: small(card[key]) for key in
                ('effective_access', 'grant_summary', 'restrictions', 'trust', 'source_grants_truncated') if key in card}
            item['evidence'].update(grant_count=card.get('grant_count', len(grants)),
                                    grants_sample=[fields(entry) for entry in grants[:2]],
                                    source=original.get('source'), target=original.get('target'))
        else:
            item['evidence'] = {'source': original.get('source'), 'target': original.get('target'),
                                'confidence': original.get('confidence'), **fields(original.get('evidence', {}))}
        related = db.execute('''WITH refs AS (
            SELECT ? AS domain,? AS id UNION SELECT b_domain,b_id FROM links WHERE a_domain=? AND a_id=?
            UNION SELECT a_domain,a_id FROM links WHERE b_domain=? AND b_id=?)
            SELECT b.case_domain,b.case_id,MIN(json_array(a.domain,a.id)),r.summary,COUNT(*) OVER() FROM refs a JOIN case_anchors b
                ON a.domain=b.domain AND a.id=b.id JOIN records r ON r.domain=b.case_domain AND r.id=b.case_id
            WHERE b.case_domain!=? GROUP BY b.case_domain,b.case_id
            ORDER BY ROW_NUMBER() OVER(PARTITION BY b.case_domain ORDER BY r.risk,b.case_id),
                     r.risk,b.case_domain,b.case_id LIMIT 4''',
            (source_domain, source_id) * 3 + (domain,)).fetchall()
        for target_domain, target_id, via_json, summary_json, related_total in related:
            item['related_total'] = related_total
            via_domain, via_id = json.loads(via_json)
            target = json.loads(summary_json)
            witness = db.execute('''SELECT m.domain,m.id FROM case_members m WHERE case_domain=? AND case_id=? AND (
                (m.domain=? AND m.id=?) OR EXISTS(SELECT 1 FROM links l WHERE
                  (l.a_domain=m.domain AND l.a_id=m.id AND l.b_domain=? AND l.b_id=?) OR
                  (l.b_domain=m.domain AND l.b_id=m.id AND l.a_domain=? AND l.a_id=?))) ORDER BY m.domain,m.id LIMIT 1''',
                (target_domain, target_id, via_domain, via_id, via_domain, via_id, via_domain, via_id)).fetchone()
            item['related'].append({'section': target_domain.removeprefix('decision_'), 'case_id': target_id,
                'signal': target['signal'], 'state': target['state'], 'via': {'domain': via_domain, 'id': via_id},
                'member': {'domain': witness[0], 'id': witness[1]} if witness else None})
        members.append(item)
    total = db.execute('SELECT COUNT(*) FROM case_members WHERE case_domain=? AND case_id=?', (domain, ident)).fetchone()[0]
    return {'case_id': ident, 'section': domain.removeprefix('decision_'), 'total_members': total, 'members': members,
            'notes': ['Samples prefer high source severity and broad cross-domain reference context; they do not represent every member.',
                      'Related entries give concrete shared-reference witnesses, not proof of an attack chain.',
                      'Only matching least-privilege suggestions are shown. Samples and detail_required markers require full lookup if material.']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('list', 'get', 'members', 'related', 'related_cases', 'focus'))
    parser.add_argument('domain')
    parser.add_argument('id', nargs='?')
    parser.add_argument('--offset', type=int, default=0)
    parser.add_argument('--limit', type=int, default=8)
    parser.add_argument('--path', default='', help='JSON Pointer into the full record; defaults to the complete original record')
    parser.add_argument('--chars', type=int, help='Read a window of a long string, up to 8000 characters')
    parser.add_argument('--all', action='store_true', help='Include all records (the default; retained for compatibility)')
    parser.add_argument('--candidates', action='store_true', help='Explicitly restrict listing to decision candidates')
    parser.add_argument('--query', help='Literal substring to search in complete records, including unindexed native fields')
    parser.add_argument('--type', help='Exact resource type filter for list')
    parser.add_argument('--summary', action='store_true', help='Explicitly request index metadata instead of full get details')
    parser.add_argument('--keys', action='store_true', help='Page every key of the selected object; combine with --path')
    args = parser.parse_args()
    limit = min(20, max(1, args.limit))
    offset = max(0, args.offset)
    db = sqlite3.connect('file:context.sqlite?mode=ro', uri=True)
    try:
        if args.command == 'focus':
            result = focus(db, args.domain, args.id, min(3, limit))
            while len(result.get('members', [])) > 1 and len(json.dumps(result, ensure_ascii=False, default=str)) > 11500:
                result['members'].pop()
            result['returned_members'] = len(result.get('members', []))
        elif args.command == 'list':
            where = 'domain=?' + (' AND candidate=1' if args.candidates and not args.all else '')
            params = [args.domain]
            if args.query is not None:
                where += ' AND instr(detail,?)>0'
                params.append(args.query)
            if args.type is not None:
                where += " AND json_extract(summary,'$.type')=?"
                params.append(args.type)
            total = db.execute('SELECT COUNT(*) FROM records WHERE ' + where, params).fetchone()[0]
            rows = db.execute('SELECT summary FROM records WHERE ' + where + ' ORDER BY risk,id LIMIT ? OFFSET ?', (*params, limit, offset))
            result = {'total': total, 'offset': offset, 'items': [json.loads(row[0]) for row in rows]}
        elif args.command == 'get':
            row = db.execute('SELECT summary,detail FROM records WHERE domain=? AND id=?', (args.domain, args.id)).fetchone()
            if row is None:
                result = {'error': 'record_not_found'}
            else:
                detail = json.loads(row[1])
                if args.summary and not args.keys:
                    result = {'summary': json.loads(row[0]), 'detail_keys': list(detail) if isinstance(detail, dict) else None}
                else:
                    selected = detail
                    if args.path and not args.path.startswith('/'):
                        raise ValueError('Use a JSON Pointer starting with /, or an empty path for the full record')
                    for part in args.path.split('/')[1:] if args.path else []:
                        key = part.replace('~1', '/').replace('~0', '~')
                        selected = selected[int(key)] if isinstance(selected, list) else selected[key]
                    if args.keys:
                        if not isinstance(selected, dict):
                            raise ValueError('Selected value is not an object')
                        result = {'total': len(selected), 'offset': offset, 'items': list(selected)[offset:offset + limit]}
                    elif isinstance(selected, str) and args.chars is not None:
                        result = {'type': 'text', 'total': len(selected), 'offset': offset,
                                  'text': selected[offset:offset + min(8000, max(1, args.chars))]}
                    else:
                        result = {'total': len(selected), 'offset': offset, 'items': selected[offset:offset + limit]} if isinstance(selected, list) else selected
        elif args.command == 'members':
            if args.id:
                params = (args.domain, args.id)
                total = db.execute('SELECT COUNT(*) FROM case_members WHERE case_domain=? AND case_id=?', params).fetchone()[0]
                rows = db.execute('''SELECT r.domain,r.summary FROM case_members m JOIN records r
                    ON r.domain=m.domain AND r.id=m.id WHERE m.case_domain=? AND m.case_id=?
                    ORDER BY r.risk,r.domain,r.id LIMIT ? OFFSET ?''', (*params, limit, offset))
                result = {'total': total, 'offset': offset, 'items': [{'domain': row[0], 'summary': json.loads(row[1])} for row in rows]}
            else:
                # Legacy finding-group lookup.
                total = db.execute('SELECT COUNT(*) FROM members WHERE group_id=?', (args.domain,)).fetchone()[0]
                rows = db.execute('SELECT r.summary FROM members m JOIN records r ON r.domain=\'findings\' AND r.id=m.finding_id WHERE m.group_id=? ORDER BY r.risk,r.id LIMIT ? OFFSET ?', (args.domain, limit, offset))
                result = {'total': total, 'offset': offset, 'items': [json.loads(row[0]) for row in rows]}
        elif args.command == 'related_cases':
            query = '''SELECT DISTINCT b.case_domain,b.case_id FROM case_anchors a JOIN case_anchors b
                ON a.domain=b.domain AND a.id=b.id WHERE a.case_domain=? AND a.case_id=? AND b.case_domain!=?'''
            params = (args.domain, args.id, args.domain)
            total = db.execute('SELECT COUNT(*) FROM (' + query + ')', params).fetchone()[0]
            rows = db.execute('''SELECT r.domain,r.summary FROM (''' + query + ''') q JOIN records r
                ON r.domain=q.case_domain AND r.id=q.case_id ORDER BY r.risk,r.domain,r.id LIMIT ? OFFSET ?''', (*params, limit, offset))
            result = {'total': total, 'offset': offset, 'semantics': 'Shared explicit references only',
                      'items': [{'domain': row[0], 'summary': json.loads(row[1])} for row in rows]}
        else:
            query = '''SELECT b_domain,b_id FROM links WHERE a_domain=? AND a_id=?
                       UNION SELECT a_domain,a_id FROM links WHERE b_domain=? AND b_id=?'''
            params = (args.domain, args.id, args.domain, args.id)
            total = db.execute('SELECT COUNT(*) FROM (' + query + ')', params).fetchone()[0]
            related = db.execute(query + ' ORDER BY 1,2 LIMIT ? OFFSET ?', (*params, limit, offset)).fetchall()
            result = {'total': total, 'offset': offset, 'semantics': 'Exact record references only', 'items': [
                {'domain': domain, 'summary': json.loads(db.execute('SELECT summary FROM records WHERE domain=? AND id=?', (domain, ident)).fetchone()[0])}
                for domain, ident in related]}
        if isinstance(result, dict) and 'items' in result and 'total' in result:
            while len(result['items']) > 1 and len(json.dumps(result, ensure_ascii=False, default=str)) > 11500:
                result['items'].pop()
            following = result.get('offset', 0) + len(result['items'])
            result['next_offset'] = following if following < result['total'] else None
        rendered = json.dumps(result, ensure_ascii=False, default=str)
        if len(rendered) > 12000:
            result = {'error': 'selected_value_too_large', 'hint': 'Use a smaller --limit, a more specific --path, or --chars 4000 for a string; no data was truncated.',
                      'keys': list(result) if isinstance(result, dict) else None}
            rendered = json.dumps(result)
        print(rendered)
    except (KeyError, IndexError, ValueError) as exc:
        print(json.dumps({'error': 'invalid_path_or_value', 'kind': type(exc).__name__}))
    finally:
        db.close()


if __name__ == '__main__':
    main()
