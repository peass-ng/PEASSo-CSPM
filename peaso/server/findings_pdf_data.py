"""Project tenant-owned assessments into the public PDF presentation."""
from collections import defaultdict
import json

from peaso.storage.sqlite import utc

_PROVIDER = {"aws": "AWS", "azure": "Azure", "gcp": "Google Cloud", "k8s": "Kubernetes"}
_SERVICE = {
    "accessanalyzer": "IAM Access Analyzer", "acm": "Certificate Manager", "bedrock": "Bedrock",
    "cloudtrail": "CloudTrail", "cloudwatch": "CloudWatch", "config": "AWS Config",
    "ec2": "EC2", "ecs": "ECS", "ecr": "ECR", "eks": "EKS", "efs": "EFS", "iam": "IAM",
    "elasticloadbalancing": "Elastic Load Balancing", "elb": "Elastic Load Balancing", "elbv2": "Elastic Load Balancing",
    "kms": "KMS", "rds": "RDS", "s3": "S3", "secretsmanager": "Secrets Manager",
    "securityhub": "Security Hub", "sns": "SNS", "sqs": "SQS", "ssm": "Systems Manager", "vpc": "VPC",
}


def _object(value, kind):
    try:
        value=json.loads(value) if isinstance(value, str) else value
    except ValueError:
        return kind()
    return value if isinstance(value,kind) else kind()


def scope_entry(source, row=None, bundle=None):
    """Use the frozen connector and observed scopes, with archived metadata as a fallback."""
    row = row or {}
    connector = _object(_object(row.get('connector'), dict).get('data'), dict)
    summary = (bundle or {}).get('summary', bundle or {})
    history = _object(row.get('history'), list)
    completed = next((event.get('at') for event in reversed(history)
                      if isinstance(event, dict) and event.get('status') == 'completed'), None)
    provider = summary.get('provider') or source.get('provider') or connector.get('provider') or ''
    scopes = summary.get('scopes') or connector.get('scopes') or ()
    return {
        'name': source.get('connector_name') or connector.get('name') or 'Assessment',
        'provider': _PROVIDER.get(provider, provider),
        'started': source.get('created_at') or (utc(row['created']) if row.get('created') else None),
        'completed': completed,
        'scopes': sorted({item for item in scopes if isinstance(item, str)}) if isinstance(scopes, (tuple, list)) else [],
    }


def check_ids(issue):
    return {row['id'] for row in issue.get('references', ()) if row.get('domain') == 'findings' and row.get('id')}


def native_services(findings, ids, meta):
    """Read only matching index entries and retain captured service names."""
    values={}
    for row in findings:
        ident=row.get('id')
        if ident in ids:
            service=row.get('service') or (meta.get(row.get('check_id')) or {}).get('service')
            if isinstance(service,str) and service:
                values[ident]=service
    return values


def issue_services(issues, native, source_issue_services=None):
    assigned=[]
    for issue in issues:
        names={native[ident] for ident in check_ids(issue) if ident in native}
        if source_issue_services:
            for reference in issue.get('references',()):
                names.update(source_issue_services.get((reference.get('report_id'),reference.get('issue_id')),()))
        for asset in issue.get('affected_assets', ()):
            if isinstance(asset,str) and asset.startswith('arn:') and len(asset.split(':',3)) == 4:
                names.add(asset.split(':',3)[2])
        assigned.append(dict(issue, services=sorted({_SERVICE.get(n,n.replace('_',' ').replace('-', ' ').title())
                                                   for n in names if n},key=str.casefold)))
    return assigned


def captured_services(frozen, loaded):
    """Resolve the services of the exact assessment issue version in the saved report."""
    grouped=defaultdict(set)
    for assessment in frozen:
        scan=assessment['scan_id']
        services=loaded.get(scan,{})
        for issue in assessment.get('issues',()):
            grouped[scan,issue['id']].update(services[ident] for ident in check_ids(issue) if ident in services)
    return grouped
