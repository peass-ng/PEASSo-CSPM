"""Sensitive Data Protection configuration references; never persist findings or credentials."""

from .gcp import ReadError
from .gcp_network_catalog import SERVICE_ENDPOINTS, _location_validations


ROOT = 'https://dlp.googleapis.com/v2'


def _table(value):
    if not isinstance(value, dict):
        return None
    return {key: value[key] for key in ('projectId', 'datasetId', 'tableId') if isinstance(value.get(key), str)}


def _actions(actions, discovery=False):
    safe = []
    for action in actions if isinstance(actions, list) else []:
        if not isinstance(action, dict):
            continue
        row = {}
        if discovery:
            export = action.get('exportData') or {}
            if isinstance(export, dict):
                row['exportData'] = {key: _table(export[key]) for key in ('profileTable', 'sampleFindingsTable')
                                     if key in export}
            pubsub = action.get('pubSubNotification') or {}
            if isinstance(pubsub, dict) and isinstance(pubsub.get('topic'), str):
                row['pubSubNotification'] = {key: pubsub[key] for key in ('topic', 'detailOfMessage') if key in pubsub}
            if 'publishToChronicle' in action:
                row['publishToChronicle'] = True
        else:
            findings = action.get('saveFindings') or {}
            output = findings.get('outputConfig') if isinstance(findings, dict) else None
            if isinstance(output, dict):
                row['saveFindings'] = {'table': _table(output.get('table')),
                                       'storagePath': (output.get('storagePath') or {}).get('path')
                                       if isinstance(output.get('storagePath'), dict) else None}
            deidentify = action.get('deidentify') or {}
            if isinstance(deidentify, dict):
                row['deidentify'] = {key: deidentify[key] for key in ('cloudStorageOutput',)
                                     if isinstance(deidentify.get(key), str)}
            pubsub = action.get('pubSub') or {}
            if isinstance(pubsub, dict) and isinstance(pubsub.get('topic'), str):
                row['pubSub'] = {'topic': pubsub['topic']}
        if row:
            safe.append(row)
    return safe


def _project(row, kind):
    if not isinstance(row.get('name'), str):
        raise ReadError('malformed', 'dlp_resource_name_missing')
    safe = {'name': row['name'], 'resourceKind': kind}
    if kind == 'jobTrigger':
        config = row.get('inspectJob') or {}
        safe['status'] = row.get('status')
        safe['actions'] = _actions(config.get('actions')) if isinstance(config, dict) else []
    elif kind == 'dlpJob':
        safe['state'] = row.get('state')
        safe['jobType'] = row.get('type')
        details = row.get('inspectDetails') or row.get('riskDetails') or {}
        options = details.get('requestedOptions') or {} if isinstance(details, dict) else {}
        config = options.get('jobConfig') or {} if isinstance(options, dict) else {}
        safe['actions'] = _actions(config.get('actions')) if isinstance(config, dict) else []
        safe['jobTriggerName'] = row.get('jobTriggerName')
    elif kind == 'discoveryConfig':
        safe['status'] = row.get('status')
        safe['actions'] = _actions(row.get('actions'), discovery=True)
    return safe


def collection_pages(collector, scope):
    selected = collector.options.get('regions')
    locations = _location_validations(selected) if selected is not None else sorted(SERVICE_ENDPOINTS['dlp'])
    locations = list(dict.fromkeys(['global', *locations]))
    for location in locations:
        parent = f'{scope}/locations/{location}'
        kinds = [('discoveryConfigs', 'discoveryConfig', None)]
        if scope.startswith('projects/'):
            kinds = [('jobTriggers', 'jobTrigger', None),
                     ('dlpJobs', 'dlpJob', 'INSPECT_JOB'),
                     ('dlpJobs', 'dlpJob', 'RISK_ANALYSIS_JOB'), *kinds]
        for segment, kind, job_type in kinds:
            params = {'type': job_type} if job_type else None
            for rows, receipt in collector.pages(f'{ROOT}/{parent}/{segment}', scope, key=segment, params=params):
                # DlpJob.list can omit requestedOptions. Get only those jobs to
                # retain their configured actions; never request finding content.
                if kind == 'dlpJob':
                    for row in rows:
                        details = row.get('inspectDetails') or row.get('riskDetails') or {}
                        if not isinstance(details, dict) or details.get('requestedOptions'):
                            continue
                        name = row.get('name')
                        legacy = scope + '/dlpJobs/' if location == 'global' else None
                        if (not isinstance(name, str) or not name.startswith(parent + '/dlpJobs/')
                                and not (legacy and name.startswith(legacy))):
                            raise ReadError('malformed', 'dlp_job_name_invalid')
                        for detail, detail_receipt in collector.pages(f'{ROOT}/{name}', scope, single=True):
                            row.update(detail[0])
                            yield [], detail_receipt
                yield [_project(row, kind) for row in rows], receipt
