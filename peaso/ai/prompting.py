"""Compose task and access instructions from this invocation's actual inputs."""
from pathlib import Path
import json

AGENTS = Path(__file__).parent / 'agents'


def access_instructions(entries):
    if not entries:
        return ('No live cloud access is supplied for this task. Use the supplied evidence; '
                'use UNKNOWN for checks needing unavailable live data. Do not discover another credential chain or metadata endpoint.')
    lines = ['Your live access is in credentials.json, a JSON object with an entries array. '
             'Load entries inside a script; the entry records include capture time and expiration when known. '
             'target_scopes lists the assigned targets; scope identifies the credential context and is not a replacement for that list.']
    aws_indices = []
    gcp_indices = []
    azure_indices = []
    kube_indices = []
    for index, entry in enumerate(entries):
        kind = (entry.get('provider'), entry.get('format'))
        if kind == ('aws', 'aws-session'):
            aws_indices.append(index)
        elif kind == ('gcp', 'bearer'):
            gcp_indices.append(index)
        elif kind == ('azure', 'bearer'):
            azure_indices.append(index)
        elif kind == ('k8s', 'kubeconfig'):
            kube_indices.append(index)
        else:
            raise ValueError('unsupported_ai_access_format')
    def locations(indices):
        return ', '.join(f'entries[{index}]' for index in indices)
    if aws_indices:
        lines.append(f'AWS sessions: {locations(aws_indices)}. Each entry is for its account_id. '
                     'Load aws_access_key_id, aws_secret_access_key and aws_session_token into boto3.Session; '
                     'set the region for the resource being checked. Verify sts.get_caller_identity()["Account"] '
                     'matches account_id before account reads. Select the matching account entry for each finding. Never reuse one account session for another account.')
        for index in aws_indices:
            entry = entries[index]
            if entry.get('account_id'):
                lines.append(f'entries[{index}]: AWS account {json.dumps(entry["account_id"])}; assigned scopes: '
                             + json.dumps(entry.get('target_scopes', [])) + '.')
    if gcp_indices:
        lines.append(f'GCP access tokens: {locations(gcp_indices)}. Load token into an Authorization: Bearer header '
                     'for Google Cloud API requests in the assigned project scopes. The audience identifies the API access context. A single token can be used for multiple assigned projects; '
                     'iterate every listed project scope and use its project ID in the API path or request, rather than treating the credential as one project.')
        for index in gcp_indices:
            entry = entries[index]
            if 'target_scopes' in entry:
                lines.append(f'entries[{index}]: GCP projects, folders or organizations to check: ' + json.dumps(entry['target_scopes']) + '.')
            if entry.get('quota_project'):
                lines.append(f'For entries[{index}], set X-Goog-User-Project from its quota_project field; this billing/quota project is not a replacement for the target projects.')
    if azure_indices:
        names = {'https://management.azure.com': 'ARM', 'https://graph.microsoft.com': 'Microsoft Graph',
                 'https://vault.azure.net': 'Key Vault', 'https://storage.azure.com': 'Storage',
                 'https://api.loganalytics.io': 'Log Analytics'}
        for index in azure_indices:
            audience = str(entries[index].get('audience') or '').rstrip('/')
            label = names.get(audience, 'the Azure API identified by its audience')
            lines.append(f'Azure access: entries[{index}] is for {label}. Load its token into an Authorization: Bearer '
                         'header for APIs matching that entry\'s audience. Keep requests within the assigned resource scopes.')
            entry = entries[index]
            if entry.get('endpoints'):
                lines.append(f'entries[{index}]: send this token only to these captured HTTPS API origins: '
                             + json.dumps(entry['endpoints']) + '. The audience names the API, while these origins identify its request endpoints.')
            elif audience in ('https://vault.azure.net', 'https://storage.azure.com'):
                lines.append('No resource API endpoints were captured for this entry; live requests using it are unavailable. Do not infer an endpoint from the audience.')
            else:
                lines.append(f'Send this token only to the HTTPS origin {json.dumps(audience)}.')
            if entry.get('tenant_id'):
                lines.append(f'entries[{index}]: tenant ' + json.dumps(entry['tenant_id']) + '.')
            if 'target_scopes' in entry:
                lines.append(f'entries[{index}]: assigned subscriptions or tenant scopes: ' + json.dumps(entry['target_scopes']) + '.')
                if audience == 'https://management.azure.com':
                    lines.append('Iterate every listed subscription; use its subscription ID in ARM request paths.')
        if len(azure_indices) > 1:
            lines.append('Select the credential context matching both tenant and API audience; do not interchange these entries or assume a token for one tenant can access another.')
    if kube_indices:
        lines.append(f'Kubernetes access: {locations(kube_indices)}. Load the matching entry\'s kubeconfig object with '
                     'kubernetes.config.new_client_from_config_dict(entry["kubeconfig"]). It already contains the resolved '
                     'authentication and TLS settings. Use a separate API client for each supplied cluster context; iterate its assigned namespaces. '
                     'For cluster-scoped checks use that cluster client without a namespace; a namespace value of * means all namespaces within that cluster, not other clusters.')
        for index in kube_indices:
            entry = entries[index]
            if entry.get('cluster_id'):
                lines.append(f'entries[{index}]: cluster ' + json.dumps(entry['cluster_id']) + '.')
            if 'namespaces' in entry:
                lines.append(f'entries[{index}]: namespaces to check: ' + json.dumps(entry['namespaces']) + '.')
    if any(entry.get('target_scopes') == [] for entry in entries if 'target_scopes' in entry):
        lines.append('Entries with an empty target_scopes array have no bound targets for this task. Do not use them for live queries or guess other targets.')
    lines.append('Target scopes are assigned scan targets, not proof of permission. Record access denial per target and continue checking the other assigned targets; never silently skip a failed project, account, subscription or namespace.')
    lines.append('If a supplied credential is expired or rejected, record unavailable live verification. '
                 'Do not discover a default credential chain or metadata endpoint.')
    return '\n\n'.join(lines)


def agent_config_path(stage):
    if stage not in ('network', 'priorities'):
        raise ValueError('unknown_ai_stage')
    return AGENTS / (stage + '.yaml')
