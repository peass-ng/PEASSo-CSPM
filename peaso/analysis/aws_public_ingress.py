"""Positive-only direct IPv4 configuration witnesses, never traffic probes.

This deliberately does not close the public-path universe. IPv6, load balancers,
BPA exclusions, appliance routes and managed ENIs remain unsupported.
"""
from __future__ import annotations
import ipaddress
from .reachability import _Model, _aws_endpoint, _aws_sg, _aws_acl, _aws_route_table

MODEL = 'aws-public-config-witness-v1'
DEPENDENCIES = frozenset({'instance','network_interface','vpc','subnet','security_group',
                         'network_acl','route_table','internet_gateway','vpc_block_public_access_options'})


def _ip(value):
    try:
        result=ipaddress.ip_address(value)
        return result if result.version==4 else None
    except (ValueError,TypeError):return None


def _global(address):
    return address is not None and address.version==4 and address.is_global and not address.is_multicast


def _route(table,address):
    """Unique active longest-prefix IPv4 route; unsupported prefix lists reject."""
    entries=table['data'].get('Routes')
    if not isinstance(entries,list):return None
    choices=[]
    for route in entries:
        if not isinstance(route,dict) or route.get('DestinationPrefixListId'):return None
        if 'DestinationIpv6CidrBlock'in route:continue
        try:prefix=ipaddress.ip_network(route['DestinationCidrBlock'],strict=False)
        except (ValueError,KeyError,TypeError):return None
        if prefix.version!=4:return None
        if address in prefix:choices.append((prefix.prefixlen,route))
    if not choices:return None
    longest=max(n for n,_ in choices);matches=[r for n,r in choices if n==longest]
    return matches[0]if len(matches)==1 and matches[0].get('State')=='active'else None


def _candidates(model,endpoint):
    """Bounded actual-rule samples; failure to sample any path proves nothing."""
    sources={ipaddress.ip_address('8.8.8.8'),ipaddress.ip_address('1.1.1.1')}
    ports={22,80,443};protocols=set()
    for ident in endpoint['group_ids']or[]:
        group=model.find('security_group',ident,endpoint['scope'])
        if group is None:continue
        for rule in group['data'].get('IpPermissions',[]):
            proto=str(rule.get('IpProtocol'))
            protocols.update(('tcp','udp')if proto=='-1'else('tcp',)if proto in('tcp','6')else('udp',)if proto in('udp','17')else())
            for key in('FromPort','ToPort'):
                value=rule.get(key)
                if isinstance(value,int)and not isinstance(value,bool)and 1<=value<=65535:ports.add(value)
            for selector in rule.get('IpRanges',[]):
                try:
                    network=ipaddress.ip_network(selector['CidrIp'],strict=False)
                    for address in(network.network_address,network.network_address+1,network.broadcast_address-1,network.broadcast_address):
                        if address in network and _global(address):sources.add(address)
                except (KeyError,TypeError,ValueError):continue
    for protocol in sorted(protocols):
        for port in sorted(ports):
            for source in sorted(sources):yield protocol,port,source


def prepare(snapshot,scope):
    """Index complete native dependencies once, shared by all instance witnesses."""
    model=_Model(snapshot,{})
    if any(not model.complete(kind,scope)for kind in DEPENDENCIES):return None
    # Resource indexing deduplicates identities; reject duplicates beforehand.
    for kind in DEPENDENCIES:
        rows=model.collections[(kind,scope)][0]['items']
        if len(rows)!=len([r for r in model.kinds[kind]if r['scope']==scope]):return None
        identity_key={'instance':'InstanceId','network_interface':'NetworkInterfaceId','vpc':'VpcId','subnet':'SubnetId',
                      'security_group':'GroupId','network_acl':'NetworkAclId','route_table':'RouteTableId','internet_gateway':'InternetGatewayId'}.get(kind)
        if identity_key:
            identities=[r.get(identity_key)for r in rows]
            if any(not isinstance(ident,str)or not ident for ident in identities)or len(identities)!=len(set(identities)):return None
        if any(r.get('AccountId',scope.split('/')[0])!=scope.split('/')[0] or
               r.get('Region',scope.split('/')[1])!=scope.split('/')[1]for r in rows):return None
    bpa=model.collections[('vpc_block_public_access_options',scope)][0]['items']
    if len(bpa)!=1:return None
    options=bpa[0].get('VpcBlockPublicAccessOptions',{})
    if (options.get('InternetGatewayBlockMode')!='off' or options.get('State')not in('default-state','update-complete')
            or options.get('AwsAccountId',scope.split('/')[0])!=scope.split('/')[0]
            or options.get('AwsRegion',scope.split('/')[1])!=scope.split('/')[1]):return None
    model.public_scope=scope
    return model


def witness(snapshot,scope,instance_id,budget=128,prepared=None):
    """Return one independently native-supported counterexample, else None."""
    model=prepared if prepared is not None else prepare(snapshot,scope)
    if model is None or model.public_scope!=scope:return None
    model.result['unresolved_dependencies'].clear()
    model.result['routes'].clear();model.result['policy_decisions'].clear()
    model.result['evidence_refs'].clear();model._evidence.clear()
    instance=model.find('instance',instance_id,scope)
    if not instance or instance['data'].get('State',{}).get('Name')!='running':return None
    declarations=instance['data'].get('NetworkInterfaces')
    if not isinstance(declarations,list)or not declarations:return None
    attempts=0
    for declared in declarations:
        eni=model.find('network_interface',declared.get('NetworkInterfaceId'),scope)
        if not eni:continue
        data=eni['data'];attachment=data.get('Attachment',{})
        if (attachment.get('InstanceId')!=instance_id or attachment.get('Status')!='attached'
                or data.get('Status')!='in-use' or data.get('InterfaceType')!='interface'
                or data.get('RequesterManaged')is not False):continue
        if any(declared.get(k)!=data.get(k)for k in('SubnetId','VpcId','Groups')):continue
        if any(instance['data'].get(k)!=data.get(k)for k in('SubnetId','VpcId')):continue
        if declared.get('Attachment',{}).get('AttachmentId')!=attachment.get('AttachmentId')or not attachment.get('AttachmentId'):continue
        if declared.get('Attachment',{}).get('Status')!='attached':continue
        for mapping in data.get('PrivateIpAddresses',[]):
            private=_ip(mapping.get('PrivateIpAddress'));public=_ip(mapping.get('Association',{}).get('PublicIp'))
            if private is None or not _global(public):continue
            matching=[m for m in declared.get('PrivateIpAddresses',[])if m.get('PrivateIpAddress')==str(private)]
            if len(matching)!=1 or matching[0].get('Association',{}).get('PublicIp')!=str(public):continue
            # The shared evaluator selects exactly one native private address.
            # Support the primary mapping only; secondary mappings stay unknown.
            if mapping.get('Primary')is not True or data.get('PrivateIpAddress')!=str(private):continue
            if instance['data'].get('PublicIpAddress',str(public))!=str(public):continue
            endpoint=_aws_endpoint(model,eni,'ipv4')
            if not endpoint or endpoint['address']!=private or model.result['unresolved_dependencies']:continue
            vpc_id=data['VpcId'];subnet_id=data['SubnetId']
            if endpoint['subnet']['data'].get('State')!='available' or endpoint['vpc']['data'].get('State')!='available':continue
            if any(r['data'].get('OwnerId',scope.split('/')[0])!=scope.split('/')[0]for r in(eni,endpoint['subnet'],endpoint['vpc'])):continue
            # Reject any incomplete association state in this VPC, including
            # transitions that could invalidate fallback to its main table.
            tables=[r for r in model.kinds['route_table']if r['scope']==scope and r['data'].get('VpcId')==vpc_id]
            if any(not isinstance(t['data'].get('Associations'),list)or any(a.get('AssociationState',{}).get('State')!='associated'for a in t['data']['Associations'])for t in tables):continue
            table=_aws_route_table(model,endpoint)
            if table is None:continue
            acls=[r for r in model.kinds['network_acl']if r['scope']==scope and any(a.get('SubnetId')==subnet_id for a in r['data'].get('Associations',[]))]
            if len(acls)!=1 or acls[0]['data'].get('VpcId')!=vpc_id:continue
            for protocol,port,source in _candidates(model,endpoint):
                if source==public:continue
                attempts+=1
                if attempts>budget:return None
                route=_route(table,source)
                if route is None:continue
                gateway=route.get('GatewayId')
                igw=next((r for r in model.kinds['internet_gateway']if r['scope']==scope and r['data'].get('InternetGatewayId')==gateway),None)
                if not igw or not isinstance(gateway,str)or not gateway.startswith('igw-'):continue
                if igw['data'].get('Attachments')!=[{'VpcId':vpc_id,'State':'available'}]:continue
                # No edge-table support initially: a middlebox can change the
                # inbound path independently of the subnet's return route.
                if any(a.get('GatewayId')==gateway for t in model.kinds['route_table']if t['scope']==scope for a in t['data'].get('Associations',[])):continue
                peer={'address':source,'group_ids':[],'vpc':None,'scope':scope,'resource':eni}
                query={'protocol':protocol,'destination_port':port}
                before=len(model.result['unresolved_dependencies'])
                decisions=[_aws_sg(model,endpoint,peer,'ingress',query),
                    _aws_acl(model,endpoint,peer,False,port,protocol,'forward'),
                    _aws_acl(model,endpoint,peer,True,49152,protocol,'return')]
                if decisions!=['allowed']*3 or len(model.result['unresolved_dependencies'])!=before:continue
                native_keys={'security_group':'GroupId','network_acl':'NetworkAclId','network_interface':'NetworkInterfaceId',
                             'vpc':'VpcId','subnet':'SubnetId','route_table':'RouteTableId','instance':'InstanceId'}
                refs=[{'type':ref['type'],'scope':ref['scope'],'native_id':model.by_id[ref['resource_id']]['data'].get(native_keys.get(ref['type']),ref['native_id']),
                       'path':ref['path']}for ref in model.result['evidence_refs']]
                refs.extend([{'type':'internet_gateway','scope':scope,'native_id':gateway,'path':'Attachments'},
                             {'type':'route_table','scope':scope,'native_id':table['data']['RouteTableId'],'path':'Associations/Routes'},
                             {'type':'network_interface','scope':scope,'native_id':data['NetworkInterfaceId'],'path':'Attachment/PrivateIpAddresses/Groups'},
                             {'type':'instance','scope':scope,'native_id':instance_id,'path':'State/NetworkInterfaces'},
                             {'type':'vpc_block_public_access_options','scope':scope,'native_id':scope,'path':'VpcBlockPublicAccessOptions'}])
                return {'model':MODEL,'instance_id':instance_id,'network_interface_id':data['NetworkInterfaceId'],
                    'vpc_id':vpc_id,'subnet_id':subnet_id,'public_address':str(public),'private_address':str(private),
                    'source_address':str(source),'protocol':protocol,'source_port':49152,'destination_port':port,
                    'internet_gateway_id':gateway,'route_table_id':table['data']['RouteTableId'],'native_evidence_refs':refs,
                    'semantics':'configured direct IPv4 allowance; application listening and packet delivery unknown',
                    'application_listening':'unknown','network_probes':False,'all_paths_evaluated':False}
    return None


def blocked(snapshot, scope, instance_id):
    """Prove the common ingress cut: every attached ENI has only empty SGs.

    This does not infer a block from failure to find a route. Empty ingress
    rules block new inbound connections on both IP families, including traffic
    forwarded by a load balancer; stateful replies to outbound traffic differ.
    """
    model = _Model(snapshot, {})
    kinds = ('instance', 'network_interface', 'security_group')
    if any(not model.complete(kind, scope) for kind in kinds):
        return None
    for kind, key in [('instance', 'InstanceId'), ('network_interface', 'NetworkInterfaceId'), ('security_group', 'GroupId')]:
        rows = model.collections[(kind, scope)][0]['items']
        ids = [row.get(key) for row in rows]
        if (any(not isinstance(value, str) or not value for value in ids) or len(ids) != len(set(ids))
                or any(row.get('AccountId', scope.split('/')[0]) != scope.split('/')[0]
                       or row.get('Region', scope.split('/')[1]) != scope.split('/')[1] for row in rows)):
            return None
    instance = model.find('instance', instance_id, scope)
    if not instance:
        return None
    native = instance['data']
    if native.get('State', {}).get('Name') != 'running' or native.get('SecondaryInterfaces', []):
        return None
    declarations = native.get('NetworkInterfaces')
    if not isinstance(declarations, list) or not declarations:
        return None
    account = scope.split('/')[0]
    declared = [row.get('NetworkInterfaceId') for row in declarations if isinstance(row, dict)]
    attached = [r['data'].get('NetworkInterfaceId') for r in model.kinds['network_interface']
                if r['scope'] == scope and r['data'].get('Attachment', {}).get('InstanceId') == instance_id]
    if len(declared) != len(declarations) or len(set(declared)) != len(declared) or sorted(declared) != sorted(attached):
        return None
    group_ids = set()
    for declaration in declarations:
        eni = model.find('network_interface', declaration.get('NetworkInterfaceId'), scope)
        if eni is None:
            return None
        data = eni['data']
        if (data.get('Status') != 'in-use' or data.get('InterfaceType') != 'interface'
                or data.get('RequesterManaged') is not False or data.get('OwnerId', account) != account
                or data.get('Attachment', {}).get('Status') != 'attached'
                or declaration.get('Attachment', {}).get('Status') != 'attached'
                or not data.get('Attachment', {}).get('AttachmentId')
                or declaration.get('Attachment', {}).get('AttachmentId') != data['Attachment']['AttachmentId']
                or any(data.get(k) != declaration.get(k) for k in ('SubnetId', 'VpcId', 'Groups'))):
            return None
        groups = data.get('Groups')
        if not isinstance(groups, list) or not groups:
            return None
        for reference in groups:
            if not isinstance(reference, dict) or not isinstance(reference.get('GroupId'), str):
                return None
            group = model.find('security_group', reference['GroupId'], scope)
            if (group is None or group['data'].get('OwnerId', account) != account
                    or group['data'].get('VpcId') != data.get('VpcId') or group['data'].get('IpPermissions') != []):
                return None
            group_ids.add(reference['GroupId'])
    return {'model': 'aws-empty-ingress-security-groups-v1', 'instance_id': instance_id,
            'network_interface_ids': sorted(declared), 'security_group_ids': sorted(group_ids),
            'reason': 'Every attached network interface has only security groups with zero ingress rules',
            'semantics': 'New inbound IPv4/IPv6 network connections are blocked; stateful outbound replies are excluded'}
