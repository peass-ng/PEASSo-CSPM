"""Route reviewed aliases and explicitly retain unavailable evidence as UNKNOWN.

A missing native projection is an inventory gap, never a successful empty API
response. No synthetic positive facts or owner attestations are manufactured.
"""
import copy
from pathlib import Path
import json
from peaso.snapshot import make_snapshot

ALIASES={'aws':{'s3_bucket':'bucket','ec2_instance':'instance','classic_elb':'classic_load_balancer','cloudwatch_log_group':'log_group','cloudwatch_subscription_filter':'log_subscription_filter','autoscaling_launch_configuration':'launch_configuration','apigateway_stage':'rest_api_stage',
                'resolver_firewall_association':'resolver_firewall_rule_group_association','cloudwatch_subscription_filter':'log_subscription_filter','resolver_log_subscription':'log_subscription_filter'},'azure':{'virtual_machine':'vm','vnet_gateway':'virtual_network_gateway','application':'directory_application','database_server':'sql_server','web_app':'app_service','monitor_action_group':'action_group','entra_domain':'directory_domain'},'gcp':{},'k8s':{}}
CONTRACT=json.loads(Path(__file__).with_name('bulk_evidence.json').read_text())

def declared_types(provider):return set(CONTRACT['types'][provider])

def coverage():
    """Separate declared evidence contracts from inventories collected natively."""
    from importlib import import_module
    result={}
    for provider in ALIASES:
        module=import_module('peaso.collectors.'+provider)
        native=set(getattr(module,'AWS_TYPES',getattr(module,'SUPPORTED_TYPES',getattr(module,'TYPES',()))))
        aliases={k:v for k,v in ALIASES[provider].items() if v in native}
        result[provider]={'native_types':sorted(native),'native_aliases':aliases,
                          'unavailable_projections':sorted(declared_types(provider)-native-set(aliases))}
    return result

def expand_native_requirements(provider,kinds):
    """Expand exact native projection parents without changing check selection."""
    expanded=set(kinds)
    if provider=='aws' and 'ec2_effective_ingress' in expanded:
        from peaso.analysis.aws_public_ingress import DEPENDENCIES
        expanded.update(DEPENDENCIES)
    if provider=='azure':
        from peaso.collectors.azure_aks_workloads_native import required_types
        expanded.update(required_types(expanded))
    return expanded


def collect(module,connector,requirements):
    provider=connector['provider'];native=set(getattr(module,'AWS_TYPES',getattr(module,'SUPPORTED_TYPES',getattr(module,'TYPES',()))))
    options=connector.get('options',{})
    if not isinstance(options,dict):raise ValueError('options must be an object')
    requested=options.get('inventories')
    if requested is not None and (not isinstance(requested,list) or any(not isinstance(k,str) for k in requested)):
        raise ValueError('inventories must be a list of strings')
    parameters=options.get('compliance_parameters');policy=options.get('compliance_policy')
    for label,value in (('parameters',parameters),('policy',policy)):
        if value is None:continue
        try:
            valid=isinstance(value,dict) and len(json.dumps(value,allow_nan=False))<=50000
        except (TypeError,ValueError):
            valid=False
        if not valid:raise ValueError('invalid compliance '+label)
    desired=set(requirements or ()) | (set(requested)if isinstance(requested,list)else set())
    aliases={k:v for k,v in ALIASES[provider].items()if k in desired and v in native}
    gaps=(desired-native-set(aliases)) & declared_types(provider)
    unknown=desired-native-set(aliases)-gaps
    if unknown:raise ValueError('unrecognized inventory requirements: '+', '.join(sorted(unknown)))
    forwarded={**connector,'options':dict(options)}
    if requested is not None:forwarded['options']['inventories']=sorted(expand_native_requirements(provider,{ALIASES[provider].get(k,k)for k in requested if k in native or k in aliases}))
    selected=None if requirements is None else sorted(expand_native_requirements(provider,(set(requirements)&native)|{aliases[k]for k in set(requirements)&set(aliases)}))
    snapshot=module.collect(forwarded,selected)
    parameters=options.get("compliance_parameters")
    policy=options.get("compliance_policy")
    if not aliases and not gaps and parameters is None and policy is None:return snapshot
    collections=list(snapshot['collections'])
    for alias,source in aliases.items():
        for envelope in snapshot['collections']:
            if envelope['type']==source:
                projection=copy.deepcopy(envelope);projection['type']=alias;projection['source_inventory']=source
                if provider == 'aws' and alias == 'cloudwatch_subscription_filter':
                    # This legacy consumer expects an explicit read status on
                    # each native filter. It asserts configured routing only,
                    # never delivery or receiver availability. Partial source
                    # inventories retain that status on the whole projection.
                    for row in projection['items']:
                        row['collection_status'] = projection['status']
                if provider == 'azure' and alias == 'database_server':
                    # ARM inventory cannot produce SQL catalog or authentication
                    # outcomes. This alias only supplies supporting metadata.
                    for row in projection['items']:
                        row.pop('defaultCredentialAssessment', None)
                        row.setdefault('_coverage', {})['defaultCredentialAssessment'] = {
                            'status': 'not_collected',
                            'reason': 'ARM_metadata_does_not_prove_SQL_authentication_outcomes'}
                if provider == 'azure' and alias == 'web_app':
                    # Sites metadata cannot certify application-wide secret
                    # classification across settings, slots and code stores.
                    for row in projection['items']:
                        row.pop('workloadSecrets', None)
                        row.setdefault('_coverage', {})['workloadSecrets'] = {
                            'status': 'not_collected',
                            'reason': 'ARM_sites_metadata_does_not_classify_all_workload_secrets'}
                if provider == 'azure' and alias == 'entra_domain':
                    # Domain expiration metadata says nothing about newly
                    # provisioned identities, lockout, complexity or an IdP.
                    for row in projection['items']:
                        for field in ('newlyProvisionedIdentities', 'effectivePasswordPolicies'):
                            row.pop(field, None)
                            row.setdefault('_coverage', {})[field] = {
                                'status': 'not_collected',
                                'reason': 'Graph_domain_metadata_does_not_prove_effective_identity_password_policy'}
                collections.append(projection)
    scopes=snapshot['scopes']
    for kind in sorted(gaps):
        for scope in scopes:
            if not any(c['type']==kind and c['scope']==scope for c in collections):collections.append({'type':kind,'scope':scope,'service':'reviewed_evidence','status':'not_collected','items':[], 'error':{'code':'native_evidence_projection_unavailable','reason':'The check definition is integrated; this exact evidence is not available from the selected native collector.'}})
    metadata=copy.deepcopy(snapshot.get('metadata',{}));metadata['bulk_evidence']={'native_aliases':aliases,'unavailable_projections':sorted(gaps),'absence_semantics':'unknown'}
    if parameters is not None:
        metadata['parameters']=copy.deepcopy(parameters)
        if provider == 'aws' and 'aws_environment_separation' in parameters:
            from datetime import datetime
            from .aws_environment_boundaries_native import normalize, owner_metadata
            approved = normalize(options, connector.get('scopes') or [])
            observed_at = datetime.fromisoformat(snapshot['created_at'].replace('Z', '+00:00'))
            metadata['parameters'].update(owner_metadata(approved, observed_at))
    if policy is not None:
        metadata['compliance_policy']={**copy.deepcopy(policy),**metadata.get('compliance_policy',{})}
    if gaps:metadata['intentional_partial']=True
    return make_snapshot(provider,scopes,collections,metadata=metadata,created_at=snapshot['created_at'])
