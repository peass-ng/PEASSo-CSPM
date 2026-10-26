"""Pure, conservative Security Hub finding-history SLA evidence evaluation.

The caller must supply a complete, unfiltered GetFindingHistory pagination result
for one finding. No API calls or owner-policy decisions happen here.
"""

from datetime import datetime, timedelta, timezone
from functools import lru_cache
from math import isfinite
import re

KIND = 'securityhub_finding_history'
PROFILE = 'securityhub-workflow-history-metadata-v1'
PROJECTION_OPERATIONS = frozenset({('securityhub', 'get_finding_history')})
READ_ACTIONS = set(PROJECTION_OPERATIONS)
SPECS = {KIND: ('securityhub', 'get_finding_history', 'Records')}
NATIVE_IDS = {KIND: 'id'}
_STATUS = {'NEW', 'NOTIFIED', 'RESOLVED', 'SUPPRESSED'}


def _instant(value):
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return None
    else:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None


def workflow_sla_from_history(finding, records, *, history_complete, capture_at, response_hours,
                              authorized_response_identities):
    """Return status and reason for a historical *first* workflow response.

    A PASS or FAIL requires complete, unfiltered history from the finding's
    creation through capture. A customer BatchUpdateFindings transition from
    NEW to NOTIFIED/RESOLVED, or NOTIFIED to RESOLVED in the initial workflow,
    proves a response. Automation and provider updates do not prove one.
    """
    def unknown(reason):
        return {'status': 'UNKNOWN', 'reason': reason}

    if not isinstance(finding, dict) or not isinstance(records, list):
        return unknown('finding or history shape invalid')
    if history_complete is not True:
        return unknown('finding history is incomplete or time filtered')
    if (isinstance(response_hours, bool) or not isinstance(response_hours, (int, float))
            or not isfinite(response_hours) or response_hours <= 0):
        return unknown('approved response window unavailable')
    if (not isinstance(authorized_response_identities, list) or not authorized_response_identities
            or any(not isinstance(value, str) or not value.startswith('arn:')
                   for value in authorized_response_identities)
            or len(set(authorized_response_identities)) != len(authorized_response_identities)):
        return unknown('operator-approved response identities unavailable')
    created, capture = _instant(finding.get('CreatedAt')), _instant(capture_at)
    if created is None or capture is None or capture < created:
        return unknown('finding or capture timestamp invalid')
    identity = (finding.get('Id'), finding.get('ProductArn'))
    if not all(isinstance(value, str) and value for value in identity):
        return unknown('finding identity unavailable')
    deadline = created + timedelta(hours=response_hours)
    transitions = []
    creation = []
    for row in records:
        if not isinstance(row, dict):
            return unknown('history record malformed')
        row_id = row.get('FindingIdentifier')
        if not isinstance(row_id, dict) or (row_id.get('Id'), row_id.get('ProductArn')) != identity:
            return unknown('history finding identity mismatch')
        instant = _instant(row.get('UpdateTime'))
        if instant is None or instant < created or instant > capture:
            return unknown('history timestamp outside finding lifetime')
        if row.get('FindingCreated') is True:
            creation.append(instant)
        updates = row.get('Updates', [])
        if not isinstance(updates, list):
            return unknown('history updates malformed')
        for update in updates:
            if not isinstance(update, dict):
                return unknown('history update malformed')
            if update.get('UpdatedField') != 'Workflow.Status':
                continue
            old, new = update.get('OldValue'), update.get('NewValue')
            if old not in _STATUS or new not in _STATUS:
                return unknown('workflow transition value unavailable')
            source = row.get('UpdateSource')
            if not isinstance(source, dict) or not isinstance(source.get('Type'), str):
                return unknown('workflow transition source unavailable')
            actor = source.get('Identity')
            if source['Type'] == 'BATCH_UPDATE_FINDINGS' and new in {'NOTIFIED', 'RESOLVED'} and not isinstance(actor, str):
                return unknown('workflow transition actor unavailable')
            transitions.append((instant, old, new, source['Type'], actor))
    if len(creation) != 1:
        return unknown('finding creation record unavailable or ambiguous')
    transitions.sort(key=lambda row: row[0])
    if any(row[0] < creation[0] for row in transitions):
        return unknown('workflow transition precedes finding creation')
    if len({row[0] for row in transitions}) != len(transitions):
        return unknown('workflow transition order ambiguous')
    prior = 'NEW'
    for _, old, new, _, _ in transitions:
        if old != prior:
            return unknown('workflow transition history is discontinuous')
        prior = new
    workflow = finding.get('Workflow')
    if not isinstance(workflow, dict) or workflow.get('Status') != prior:
        return unknown('history does not match observed workflow state')
    first_response = None
    initial_workflow = True
    for at, old, new, source, actor in transitions:
        if (initial_workflow and source == 'BATCH_UPDATE_FINDINGS'
                and actor in authorized_response_identities
                and (old == 'NEW' and new in {'NOTIFIED', 'RESOLVED'}
                     or old == 'NOTIFIED' and new == 'RESOLVED')):
            first_response = (at, new)
            break
        if new == 'SUPPRESSED' or (old in {'NOTIFIED', 'RESOLVED'} and new == 'NEW'):
            initial_workflow = False
    if first_response is not None:
        at, state = first_response
        return {'status': 'PASS' if at <= deadline else 'FAIL', 'reason': 'customer workflow transition observed',
                'first_response_at': at.isoformat(), 'first_response_status': state}
    if capture < deadline:
        return {'status': 'NOT_APPLICABLE', 'reason': 'response window has not elapsed'}
    return {'status': 'FAIL', 'reason': 'complete finding history has no customer workflow response by deadline'}


def _invalid(code='securityhub_history_metadata_invalid'):
    from .aws import ReadFailure
    raise ReadFailure('malformed', code)


@lru_cache(maxsize=1)
def _history_shape():
    # The installed SDK model is immutable for the process; load it once
    # instead of building a fresh SDK session for every history page.
    import botocore.session
    return botocore.session.get_session().get_service_model('securityhub').operation_model('GetFindingHistory').output_shape


def project_response(response, service, operation, arguments):
    """Validate SDK shape, then discard all unrelated ASFF change values."""
    from botocore.validate import validate_parameters
    from botocore.exceptions import ParamValidationError

    if (service, operation) not in PROJECTION_OPERATIONS or not isinstance(response, dict):
        _invalid()
    shape = _history_shape()
    try:
        validate_parameters({key: value for key, value in response.items() if key != 'ResponseMetadata'}, shape)
    except ParamValidationError:
        _invalid()
    original = response.get('Records')
    if not isinstance(original, list) or len(original) > 100:
        _invalid()
    identity = arguments.get('FindingIdentifier')
    if not isinstance(identity, dict) or not all(isinstance(identity.get(key), str) and identity[key] for key in ('Id', 'ProductArn')):
        _invalid()
    rows = []
    for record in original:
        if not isinstance(record, dict) or record.get('FindingIdentifier') != identity:
            _invalid('securityhub_history_identity_mismatch')
        when = _instant(record.get('UpdateTime'))
        if when is None:
            _invalid()
        updates = record.get('Updates')
        if not isinstance(updates, list):
            _invalid()
        safe_updates = []
        for update in updates:
            if not isinstance(update, dict):
                _invalid()
            if update.get('UpdatedField') != 'Workflow.Status':
                continue
            safe = {'UpdatedField': 'Workflow.Status'}
            for field in ('OldValue', 'NewValue'):
                if update.get(field) in _STATUS:
                    safe[field] = update[field]
            safe_updates.append(safe)
        source = record.get('UpdateSource')
        safe_source = {'Type': source['Type']} if isinstance(source, dict) and source.get('Type') in {
            'BATCH_UPDATE_FINDINGS', 'BATCH_IMPORT_FINDINGS'} else {}
        if safe_updates and safe_source.get('Type') == 'BATCH_UPDATE_FINDINGS':
            actor = source.get('Identity')
            if isinstance(actor, str) and re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:[^:]+:[^:]*:[0-9]{12}:.{1,1024}', actor):
                safe_source['Identity'] = actor
        row = {'FindingIdentifier': dict(identity), 'UpdateTime': when.isoformat(),
               'UpdateSource': safe_source, 'Updates': safe_updates}
        if type(record.get('FindingCreated')) is bool:
            row['FindingCreated'] = record['FindingCreated']
        rows.append(row)
    projected = {'Records': rows, '_metadata_projection': PROFILE}
    if 'NextToken' in response:
        token = response['NextToken']
        if not isinstance(token, str) or not token:
            _invalid()
        projected['NextToken'] = token
    return projected


def collect(requests, session, region, account):
    """Read bounded per-finding workflow history without retaining note text."""
    from .aws import ReadResult
    arguments = {'Filters': {'AwsAccountId': [{'Comparison': 'EQUALS', 'Value': account}],
        'Region': [{'Comparison': 'EQUALS', 'Value': region}],
        'RecordState': [{'Comparison': 'EQUALS', 'Value': 'ACTIVE'}]}}
    findings = requests.pages(session, 'securityhub', region, 'get_findings', 'Findings',
        _metadata_profile='securityhub-findings-metadata-v1', **arguments)
    if findings.status not in {'collected', 'empty'}:
        return ReadResult([], findings.status, findings.error)
    capture = requests.observed_at.astimezone(timezone.utc)
    rows, seen, selected, stop = [], set(), [], None
    partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    # Pass 1 validates findings in order and stops where the serial loop
    # returned; pass 2 consumes the independent history reads in that order.
    for finding in findings.items:
        if not isinstance(finding, dict):
            stop = 'securityhub_finding_invalid'
            break
        severity = finding.get('Severity')
        if not isinstance(severity, dict) or severity.get('Label') not in {'HIGH', 'CRITICAL'}:
            continue
        fid, product = finding.get('Id'), finding.get('ProductArn')
        created = _instant(finding.get('CreatedAt'))
        if (not isinstance(fid, str) or not fid or not isinstance(product, str)
                or not re.fullmatch(r'arn:' + partition + ':securityhub:' + re.escape(region) + r':[0-9]{0,12}:product/.+', product)
                or finding.get('AwsAccountId') != account or finding.get('Region') != region
                or created is None or created > capture or (fid, product) in seen):
            stop = 'securityhub_history_finding_scope_invalid'
            break
        seen.add((fid, product))
        row = {'id': fid, 'ProductArn': product, 'AccountId': account, 'Region': region,
               'CreatedAt': created.isoformat(), 'capture_at': capture.isoformat(),
               'complete': False, 'Records': [], '_metadata_projection': PROFILE,
               '_provenance': {'read_only': True, 'source_operation': 'GetFindingHistory',
                   'history_retention_days_at_most': 90}}
        if capture - created >= timedelta(days=90):
            row['_coverage'] = {'history': {'status': 'not_collected', 'reason': 'creation_older_than_history_retention'}}
        selected.append((row, created))
    def history_read(entry):
        row = entry[0]
        if '_coverage' in row:
            return None
        return requests.pages(session, 'securityhub', region, 'get_finding_history', 'Records',
            _metadata_profile=PROFILE, FindingIdentifier={'Id': row['id'], 'ProductArn': row['ProductArn']},
            EndTime=capture, MaxResults=100)
    from .aws_request_pool import ordered_map
    for (row, created), history in zip(selected, ordered_map(requests, selected, history_read)):
        if history is None:
            rows.append(row)
            continue
        if history.status not in {'collected', 'empty'}:
            row['_coverage'] = {'history': {'status': 'not_collected', 'reason': 'history_read_incomplete'}}
            rows.append(row)
            continue
        records = history.items
        creation = [record for record in records if record.get('FindingCreated') is True]
        if (len(creation) != 1 or any(_instant(record.get('UpdateTime')) is None
                or not created <= _instant(record['UpdateTime']) <= capture for record in records)):
            row['_coverage'] = {'history': {'status': 'not_collected', 'reason': 'creation_or_capture_horizon_unproven'}}
            rows.append(row)
            continue
        row['Records'] = records
        row['complete'] = True
        rows.append(row)
    if stop is not None:
        return ReadResult(rows, 'partial' if rows else 'malformed', {'code': stop})
    return ReadResult(rows, 'collected' if rows else 'empty')


FETCHERS = {KIND: collect}


def enrich_securityhub_findings(requests, session, region, rows):
    """Bind the two-field history identity to existing safe finding rows."""
    if not rows:
        return rows
    account = rows[0].get('AccountId')
    arguments = {'Filters': {'AwsAccountId': [{'Comparison': 'EQUALS', 'Value': account}],
        'Region': [{'Comparison': 'EQUALS', 'Value': region}],
        'RecordState': [{'Comparison': 'EQUALS', 'Value': 'ACTIVE'}]}}
    read = requests.pages(session, 'securityhub', region, 'get_findings', 'Findings',
        _metadata_profile='securityhub-findings-metadata-v1', **arguments)
    if read.status != 'collected':
        _invalid('securityhub_product_identity_unavailable')
    by_id = {}
    for finding in read.items:
        if not isinstance(finding, dict) or not isinstance(finding.get('Id'), str) or finding['Id'] in by_id:
            _invalid('securityhub_product_identity_ambiguous')
        by_id[finding['Id']] = finding
    for row in rows:
        original = by_id.get(row.get('Id'))
        product = original.get('ProductArn') if isinstance(original, dict) else None
        if (not isinstance(product, str) or not product or original.get('AwsAccountId') != row.get('AccountId')
                or original.get('Region') != region):
            _invalid('securityhub_product_identity_unavailable')
        row['ProductArn'] = product
    return rows


ENRICHERS = {'securityhub_finding': enrich_securityhub_findings}
