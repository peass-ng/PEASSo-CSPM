"""Read-only projection of bounded, positive direct IPv4 configuration proofs."""
from peaso.analysis.aws_public_ingress import DEPENDENCIES, MODEL, witness, prepare, blocked

SPECS={'ec2_effective_ingress':('ec2','describe_instances','Reservations[].Instances[]')}
NATIVE_IDS={'ec2_effective_ingress':'InstanceId'}
READ_ACTIONS={('ec2',operation)for operation in('describe_instances','describe_network_interfaces','describe_vpcs',
    'describe_subnets','describe_security_groups','describe_network_acls','describe_route_tables','describe_internet_gateways',
    'describe_vpc_block_public_access_options')}


def effective_ingress(requests,session,region,account):
    from .aws import ReadResult,SPECS as native_specs,_safe
    from .aws_facts_cb_ca import _vpc_block_public_access
    from peaso.snapshot import make_snapshot
    scope=account+'/'+region;collections=[]
    for kind in sorted(DEPENDENCIES):
        if kind=='vpc_block_public_access_options':read=_vpc_block_public_access(requests,session,region,account)
        else:
            service,operation,key=native_specs[kind]
            read=requests.pages(session,service,region,operation,key)
        if read.status not in('collected','empty'):
            return ReadResult([],read.status,read.error or {'code':'public_ingress_dependency_incomplete'})
        collections.append({'type':kind,'scope':scope,'service':'ec2','status':read.status,'items':_safe(read.items)})
    snapshot=make_snapshot('aws',[scope],collections)
    instances=next(c['items']for c in collections if c['type']=='instance')
    rows=[];prepared=prepare(snapshot,scope)
    for instance in instances:
        ident=instance.get('InstanceId')
        if not isinstance(ident,str):return ReadResult([],'malformed',{'code':'public_ingress_instance_identity_missing'})
        proof=witness(snapshot,scope,ident,prepared=prepared)if prepared is not None else None
        rows.append({'InstanceId':ident,'proof_model':MODEL,'joins_complete':False,'direct_public_paths':[],
            'public_listener_target_paths':[],'configured_path_witness':proof, 'configured_block_witness':blocked(snapshot,scope,ident),
            '_provenance':{'native_dependencies':sorted(DEPENDENCIES),'read_only':True,'network_probes':False,
                           'all_paths_evaluated':False,'absence_semantics':'unknown'}})
    return ReadResult(rows,'collected'if rows else'empty')

FETCHERS={'ec2_effective_ingress':effective_ingress}
