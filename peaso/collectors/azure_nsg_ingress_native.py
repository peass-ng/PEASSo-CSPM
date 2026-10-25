"""Bounded metadata queries and exact NSG ingress facts; never a traffic probe.

Only authoritative complete native topology is accepted. Unsupported source,
route, override or association shapes never become a successful empty path.
"""
from __future__ import annotations
from collections import namedtuple
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
import threading
import time
from urllib.parse import parse_qsl, urlsplit
from urllib.request import Request, build_opener

ARM = 'https://management.azure.com'
VERSION = '2025-05-01'
NATIVE_TYPES = frozenset({'nsg_effective_internet_path'})
DEPENDENCIES = frozenset({'nsg', 'nic', 'vnet', 'public_ip', 'vm', 'load_balancer', 'application_gateway'})
NAMESPACE = 'azure_nsg_ingress'
CHECK = 'azure_nsg_world_ingress_approved_ports'
UUID = r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
SEG = r'[A-Za-z0-9_.()-]{1,90}'
TYPES = {'nsg':'Microsoft.Network/networkSecurityGroups', 'nic':'Microsoft.Network/networkInterfaces',
         'vnet':'Microsoft.Network/virtualNetworks', 'public_ip':'Microsoft.Network/publicIPAddresses',
         'vm':'Microsoft.Compute/virtualMachines', 'load_balancer':'Microsoft.Network/loadBalancers',
         'application_gateway':'Microsoft.Network/applicationGateways'}
SUFFIXES = {'nsg':'effectiveNetworkSecurityGroups', 'routes':'effectiveRouteTable',
            'admin':'listNetworkManagerEffectiveSecurityAdminRules'}
ReadResponse = namedtuple('ReadResponse', 'status data headers')


def unavailable(code):
    from .azure import AzureReadError
    raise AzureReadError(code)


def _scope(scope):
    if not isinstance(scope, str) or not re.fullmatch('/subscriptions/' + UUID, scope):
        raise ValueError('NSG subscription scope invalid')
    return scope


def _id(value, scope, kind):
    _scope(scope)
    if (not isinstance(value, str) or not re.fullmatch(re.escape(scope) + '/resourceGroups/' + SEG +
            '/providers/' + re.escape(TYPES[kind]) + '/' + SEG, value, re.I)
            or any(part in ('.', '..') for part in value.split('/'))):
        raise ValueError('Foreign or malformed NSG native resource identity')
    return value


def _date(value):
    if not isinstance(value, str) or len(value)>64:raise ValueError('NSG approval timestamp invalid')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.utcoffset() is None:raise ValueError('NSG approval timezone required')
    return result.astimezone(timezone.utc)


def normalize(options, selected_scopes=None):
    """Operator criteria only; no caller-supplied path, runtime or coverage facts."""
    if not isinstance(options, dict):raise ValueError('NSG options must be an object')
    parent = options.get('compliance_parameters', {})
    if not isinstance(parent, dict):raise ValueError('NSG parameter object required')
    if NAMESPACE not in parent:return None
    raw = parent[NAMESPACE]
    fields = {'status', 'scope', 'observed_at', 'max_age_seconds', 'approvedInternetPorts'}
    if not isinstance(raw, dict) or set(raw) != fields or raw['status'] != 'collected':
        raise ValueError('NSG approval fields invalid')
    _scope(raw['scope']);_date(raw['observed_at'])
    if type(raw['max_age_seconds']) is not int or not 1 <= raw['max_age_seconds'] <= 86400:
        raise ValueError('NSG approval age invalid')
    ports = raw['approvedInternetPorts']
    if (not isinstance(ports, list) or len(ports) > 4096 or any(type(p) is not int or not 1 <= p <= 65535 for p in ports)
            or len(set(ports)) != len(ports)):
        raise ValueError('NSG approved ports invalid')
    flat = options.get('compliance_policy', {})
    if not isinstance(flat, dict) or 'sw31' in flat:
        raise ValueError('Competing NSG approval authority')
    if selected_scopes is not None:
        if (not isinstance(selected_scopes, (list, tuple, set)) or not selected_scopes
                or any(not isinstance(s, str) for s in selected_scopes)
                or {s.casefold() for s in selected_scopes} != {raw['scope'].casefold()}):
            raise ValueError('NSG approval differs from selected subscription')
    return deepcopy(raw)


def owner_metadata(policy, created_at):
    if policy is None:return {}
    age = (_date(created_at) - _date(policy['observed_at'])).total_seconds()
    if not 0 <= age <= policy['max_age_seconds']:return {}
    return {'approvedInternetPorts': list(policy['approvedInternetPorts'])}


def required_types(wanted):
    return set(DEPENDENCIES) if set(wanted) & NATIVE_TYPES else set()


class NetworkQueries:
    """Exactly three semantic metadata POSTs, with bound GET result polling.

    Existing AzureTransport.request and its POST allowlist remain unchanged.
    The typed response preserves status/selected headers needed for a query LRO.
    """
    def __init__(self, reader, transport, scope, *, sleep=time.sleep, monotonic=time.monotonic):
        self.reader, self.transport, self.scope = reader, transport, _scope(scope)
        self.sleep, self.clock = sleep, monotonic
        self.started = monotonic()
        self.calls = 0
        self.bytes = 0
        self.proofs = []
        # Effective-route reads may share one query budget across threads.
        self._budget_lock = threading.Lock()

    def _url(self, url, parent, kind, nsg_ids, *, initial):
        if not isinstance(url, str) or any(ord(c) < 33 for c in url):unavailable('unsafe_network_metadata_query')
        parsed = urlsplit(url)
        if (parsed.scheme != 'https' or parsed.netloc != 'management.azure.com' or parsed.fragment
                or parsed.username or parsed.password or '%' in parsed.path or '\\' in parsed.path):
            unavailable('unsafe_network_metadata_query')
        path = parsed.path
        # Microsoft's NSG Location example alone has this doubled leading slash.
        if path.startswith('//subscriptions/') and not initial:path = path[1:]
        if '//' in path or any(p in ('.','..') for p in path.split('/')):unavailable('unsafe_network_metadata_query')
        try:pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
        except ValueError:unavailable('unsafe_network_metadata_query')
        if len({k.casefold() for k,v in pairs}) != len(pairs):unavailable('ambiguous_network_metadata_query')
        query = dict(pairs)
        versions = {VERSION} if initial else {VERSION, '2025-07-01'}
        if query.get('api-version') not in versions or set(query) - {'api-version','$skiptoken','$skipToken'}:
            unavailable('unsafe_network_metadata_query')
        if any(not isinstance(v,str) or not v or len(v)>4096 for v in query.values()):unavailable('unsafe_network_metadata_query')
        expected = parent + '/' + SUFFIXES[kind]
        if initial:
            if path != expected or set(query) != {'api-version'}:unavailable('unsafe_network_metadata_query')
        else:
            parents = [parent] + list(nsg_ids) if kind == 'nsg' else [parent]
            results = any(re.fullmatch(re.escape(r) + '/operationResults/' + UUID, path, re.I) for r in parents)
            if kind == 'admin' or not (results or path == expected):unavailable('foreign_network_query_result')
        return ARM + path + ('?' + parsed.query if parsed.query else '')

    def _response(self, url, parent, kind, nsg_ids, *, initial, body=None):
        from .azure import _native_open
        _id(parent, self.scope, 'vnet' if kind == 'admin' else 'nic')
        for nsg in nsg_ids:_id(nsg, self.scope, 'nsg')
        url = self._url(url, parent, kind, nsg_ids, initial=initial)
        if initial:
            if kind == 'admin':
                if (not isinstance(body, dict) or set(body) - {'skipToken'} or
                        'skipToken' in body and (not isinstance(body['skipToken'], str) or not 0<len(body['skipToken'])<=4096)):
                    unavailable('unsafe_network_metadata_body')
            elif body is not None:unavailable('unsafe_network_metadata_body')
        elif body is not None:unavailable('unsafe_network_metadata_body')
        self.reader.check_cancelled()
        with self._budget_lock:
            if self.clock()-self.started >= 120 or self.calls >= 300:unavailable('network_query_budget')
            self.calls += 1
        token = self.transport.token(ARM)
        data = json.dumps(body).encode() if body is not None else None
        req = Request(url, data=data, headers={'Authorization':'Bearer '+token,'Accept':'application/json',
                      'Content-Type':'application/json'}, method='POST' if initial else 'GET')
        with _native_open(req, min(20,max(0.1,120-(self.clock()-self.started))), build_opener) as response:
            status = response.status
            headers = {k:response.headers[k] for k in ('Location','Retry-After','ETag','x-ms-request-id') if k in response.headers}
            raw = response.read(8*1024*1024+1)
        with self._budget_lock:
            self.bytes += len(raw)
            total = self.bytes
        if len(raw)>8*1024*1024 or total>32*1024*1024:unavailable('network_query_body_budget')
        if status not in (200,202):unavailable('network_query_status_unavailable')
        result = json.loads(raw) if raw else None
        if result is not None and not isinstance(result,dict):unavailable('network_query_response_invalid')
        return ReadResponse(status,result,headers)

    def get(self, url, *, body=None, audience=ARM):
        """Bound authoritative inventory bytes before parsing, without generic GET caching."""
        from .azure import _native_open
        if (body is not None or audience != ARM or not isinstance(url,str)
                or any(ord(char)<33 for char in url)):unavailable('unsafe_network_inventory_get')
        p = urlsplit(url)
        if (p.scheme != 'https' or p.netloc != 'management.azure.com' or p.fragment
                or p.username or p.password or '%' in p.path or '\\' in p.path
                or '//' in p.path or any(part in ('.','..') for part in p.path.split('/'))):
            unavailable('unsafe_network_inventory_get')
        try: pairs = parse_qsl(p.query,keep_blank_values=True,strict_parsing=True)
        except ValueError:unavailable('unsafe_network_inventory_get')
        if len({key.casefold() for key,value in pairs}) != len(pairs):unavailable('unsafe_network_inventory_get')
        query = dict(pairs)
        if (set(query)-{'api-version','$skiptoken','$skipToken'} or 'api-version' not in query
                or any(not value or len(value)>4096 for value in query.values())):unavailable('unsafe_network_inventory_get')
        matched = None
        for kind,typ in TYPES.items():
            version = '2024-07-01' if kind == 'vm' else VERSION
            root = self.scope+'/providers/'+typ
            resource = re.escape(self.scope)+'/resourceGroups/'+SEG+'/providers/'+re.escape(typ)+'/'+SEG
            if p.path.casefold() == root.casefold():matched = (version,True);break
            if re.fullmatch(resource,p.path,re.I):matched = (version,False);break
        subnet_pattern = re.escape(self.scope)+'/resourceGroups/'+SEG+'/providers/Microsoft.Network/virtualNetworks/'+SEG+'/subnets/'+SEG
        if re.fullmatch(subnet_pattern,p.path,re.I):matched = (VERSION,False)
        if matched is None or query['api-version']!=matched[0] or not matched[1] and set(query)!={'api-version'}:
            unavailable('unsafe_network_inventory_get')
        self.reader.check_cancelled()
        with self._budget_lock:
            if self.clock()-self.started>=120 or self.calls>=300:unavailable('network_query_budget')
            self.calls += 1
        token = self.transport.token(ARM)
        req = Request(url,headers={'Authorization':'Bearer '+token,'Accept':'application/json'},method='GET')
        with _native_open(req,min(20,max(0.1,120-(self.clock()-self.started))),build_opener) as response:
            status = response.status
            raw = response.read(8*1024*1024+1)
        with self._budget_lock:
            self.bytes += len(raw)
            total = self.bytes
        if len(raw)>8*1024*1024 or total>32*1024*1024:unavailable('network_query_body_budget')
        if status!=200:unavailable('network_inventory_status_unavailable')
        value = json.loads(raw)
        if not isinstance(value,dict):unavailable('network_inventory_response_invalid')
        self.proofs.append({'source_operation':'native_inventory_get','read_only':True,
            'representation':'full','api_version':query['api-version'],
            'response_sha256':hashlib.sha256(raw).hexdigest()})
        return value

    def pages(self, kind, parent, *, nsg_ids=(), proof_sink=None):
        proofs = self.proofs if proof_sink is None else proof_sink
        if kind not in SUFFIXES:unavailable('unsafe_network_metadata_operation')
        _id(parent,self.scope,'vnet' if kind=='admin' else 'nic')
        url = ARM+parent+'/'+SUFFIXES[kind]+'?api-version='+VERSION
        body = {} if kind=='admin' else None
        seen = set()
        initial = True
        cap = min(32,self.reader.budget.max_pages) if self.reader.budget.max_pages is not None else 32
        for page in range(cap):
            response = self.reader.call(self._response,url,parent,kind,nsg_ids,initial=initial,body=body)
            for poll in range(12):
                if response.status == 200:break
                if kind=='admin':unavailable('admin_query_unexpected_lro')
                location = response.headers.get('Location')
                if not location:unavailable('network_query_result_missing')
                location = self._url(location,parent,kind,nsg_ids,initial=False)
                delay = response.headers.get('Retry-After','1')
                if not isinstance(delay,str) or not re.fullmatch(r'[0-9]{1,2}',delay):unavailable('network_query_retry_after_invalid')
                delay = max(1,int(delay))
                if delay>30 or self.clock()+delay-self.started>=120:unavailable('network_query_budget')
                if self.reader.deadline is not None and self.clock()+delay>=self.reader.deadline:unavailable('network_query_budget')
                if self.reader.budget.deadline is not None and time.time()+delay>=self.reader.budget.deadline:unavailable('network_query_budget')
                self.reader.check_cancelled();self.sleep(delay)
                response = self.reader.call(self._response,location,parent,kind,nsg_ids,initial=False)
            if response.status != 200 or not isinstance(response.data,dict) or not isinstance(response.data.get('value'),list):
                unavailable('network_query_incomplete')
            if any(not isinstance(v,dict) for v in response.data['value']):unavailable('network_query_response_invalid')
            proofs.append({'source_operation':SUFFIXES[kind],'resource_id':parent,
                'api_version':VERSION,'read_only':True,'representation':'full',
                'observed_at':datetime.now(timezone.utc).isoformat(),
                'response_sha256':hashlib.sha256(json.dumps(response.data,sort_keys=True,separators=(',',':')).encode()).hexdigest()})
            yield response.data['value']
            cursor = response.data.get('skipToken') if kind=='admin' else response.data.get('nextLink')
            if cursor is None or cursor=='':return
            if not isinstance(cursor,str) or len(cursor)>4096 or cursor in seen:unavailable('network_query_pagination_invalid')
            seen.add(cursor)
            if kind=='admin':body={'skipToken':cursor}
            else:url=self._url(cursor,parent,kind,nsg_ids,initial=False);body=None;initial=False
        unavailable('network_query_page_budget')


def _selectors(rule, single, plural):
    one, many = rule.get(single), rule.get(plural)
    if one is not None and many is not None:unavailable('nsg_ambiguous_selector')
    values = [one] if one is not None else many
    if not isinstance(values,list) or not values or any(not isinstance(v,str) or not v for v in values):
        unavailable('nsg_selector_missing')
    return values


def _ports(values):
    result=set()
    for value in values:
        if value=='*':result.update(range(1,65536));continue
        if not re.fullmatch(r'[0-9]{1,5}(?:-[0-9]{1,5})?',value):unavailable('nsg_port_expression_unsupported')
        parts=value.split('-');low=int(parts[0]);high=int(parts[-1])
        if not 0<=low<=high<=65535:unavailable('nsg_port_expression_invalid')
        result.update(range(max(1,low),high+1))
    return result


def _nonworld(net):
    ranges = ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','fc00::/7','fe80::/10','::1/128')
    return any(net.version == known.version and net.subnet_of(known) for known in map(ipaddress.ip_network,ranges))


def _world_source(rule,address):
    values=_selectors(rule,'sourceAddressPrefix','sourceAddressPrefixes')
    if values == ['0.0.0.0/0'] and address.version != 4:return False
    if values == ['::/0'] and address.version != 6:return False
    if any(v in ('*','Internet','0.0.0.0/0','::/0') for v in values):
        if not all(v in ('*','Internet','0.0.0.0/0','::/0')for v in values):unavailable('nsg_source_union_unsupported')
        return True
    if values==['AzureLoadBalancer']:return False  # Azure's health-probe tag, not world traffic.
    expanded=rule.get('expandedSourceAddressPrefix',values)
    if not isinstance(expanded,list)or not expanded:unavailable('nsg_source_expansion_missing')
    try:nets=[ipaddress.ip_network(v,strict=False) for v in expanded]
    except (ValueError,TypeError):unavailable('nsg_source_selector_unsupported')
    nets = [n for n in nets if n.version == address.version]
    if not nets or all(_nonworld(n)for n in nets):return False
    # Narrow public sources and mixed selectors cannot silently become world or private.
    unavailable('nsg_public_source_subset_unsupported')


def _destination(rule,address):
    values=_selectors(rule,'destinationAddressPrefix','destinationAddressPrefixes')
    if values==['*']:return True
    expanded=rule.get('expandedDestinationAddressPrefix',values)
    if not isinstance(expanded,list)or not expanded:unavailable('nsg_destination_expansion_missing')
    try:nets=[ipaddress.ip_network(v,strict=False)for v in expanded]
    except (ValueError,TypeError):unavailable('nsg_destination_selector_unsupported')
    return any(address.version==n.version and address in n for n in nets)


def effective_allowed(rules,address):
    """Full native effective rules, no synthesized default; only proved world sources."""
    if not isinstance(rules,list)or not rules:unavailable('nsg_effective_rules_missing')
    by_direction=set();parsed=[]
    for rule in rules:
        if not isinstance(rule,dict):unavailable('nsg_effective_rule_invalid')
        priority,direction=rule.get('priority'),rule.get('direction')
        if type(priority)is not int or not 100<=priority<=65535 or direction not in {'Inbound','Outbound'}:
            unavailable('nsg_effective_priority_invalid')
        if (direction,priority)in by_direction:unavailable('nsg_effective_priority_duplicate')
        by_direction.add((direction,priority));parsed.append(rule)
    allowed={p:set()for p in ('Tcp','Udp')};decided={p:set()for p in allowed}
    for rule in sorted(parsed,key=lambda r:r['priority']):
        if rule['direction']!='Inbound':continue
        access=rule.get('access');protocol=rule.get('protocol')
        if access not in {'Allow','Deny'}or protocol not in {'Tcp','Udp','All','*','Icmp'}:unavailable('nsg_effective_action_unsupported')
        if protocol=='Icmp':continue  # Frozen contract explicitly covers TCP/UDP ports.
        if not _world_source(rule,address)or not _destination(rule,address):continue
        if _ports(_selectors(rule,'sourcePortRange','sourcePortRanges'))!=set(range(1,65536)):
            unavailable('nsg_source_port_constraint_unsupported')
        ports=_ports(_selectors(rule,'destinationPortRange','destinationPortRanges'))
        for proto in allowed if protocol in {'All','*'}else [protocol]:
            new=ports-decided[proto]
            if access=='Allow':allowed[proto].update(new)
            decided[proto].update(ports)
    # A missing native/default decision is never supplied by this projector.
    if any(len(v)!=65535 for v in decided.values()):unavailable('nsg_effective_terminal_decision_missing')
    return allowed


def _native_nsg_rules(row):
    """Validate native parent metadata without importing registering check modules."""
    props = row.get('properties')
    if not isinstance(props, dict):unavailable('nsg_parent_properties_missing')
    values = []
    for field in ('securityRules', 'defaultSecurityRules'):
        rules = props.get(field)
        if not isinstance(rules, list):unavailable('nsg_parent_rules_missing')
        values.extend(rules)
    seen = set()
    for rule in values:
        p = rule.get('properties') if isinstance(rule, dict) else None
        if not isinstance(p, dict):unavailable('nsg_parent_rule_invalid')
        priority, direction = p.get('priority'), p.get('direction')
        if (type(priority) is not int or not 100 <= priority <= 65500
                or direction not in ('Inbound', 'Outbound')):unavailable('nsg_parent_rule_invalid')
        key = (direction, priority)
        if key in seen:unavailable('nsg_parent_rule_duplicate')
        seen.add(key)
    return values


def _ref(props,field):
    value=props.get(field)
    if value is None:return None
    if not isinstance(value,dict)or set(value)-{'id'}or not isinstance(value.get('id'),str):
        unavailable('nsg_native_reference_ambiguous')
    return value['id']


def _objects(props,field):
    value=props.get(field,[])
    if not isinstance(value,list)or any(not isinstance(v,dict)for v in value):unavailable('nsg_native_array_invalid')
    return value


def _empty(props,fields):
    for field in fields:
        if props.get(field) not in (None,[]):unavailable('nsg_topology_unsupported_'+field)


class _Inventory:
    def __init__(self,reader,transport,scope):
        self.reader,self.transport,self.scope=reader,transport,scope
        self.queries=NetworkQueries(reader,transport,scope)
        self.objects={};self.versions={};self.starts={};self.capture_start=datetime.now(timezone.utc).isoformat()

    def get(self,url,**kwargs):
        return self.queries.get(url,**kwargs)  # Exact dedicated GET is byte-bounded before JSON parsing.

    def fetch(self,rid,kind):
        _id(rid,self.scope,kind)
        key=rid.casefold()
        if kind in self.starts and key not in self.starts[kind]:
            unavailable('nsg_native_reference_absent_from_complete_inventory')
        if key in self.objects:return self.objects[key]
        version='2024-07-01'if kind=='vm'else VERSION
        raw=self.reader.call(self.get,ARM+rid+'?api-version='+version)
        if (not isinstance(raw,dict)or str(raw.get('id','')).casefold()!=key
                or str(raw.get('type','')).casefold()!=TYPES[kind].casefold()
                or not isinstance(raw.get('etag'),str)or not raw['etag']
                or not isinstance(raw.get('properties'),dict)):
            unavailable('nsg_native_resource_version_missing')
        if raw['properties'].get('provisioningState')not in (None,'Succeeded'):unavailable('nsg_native_resource_not_ready')
        self.objects[key]=raw;self.versions[key]=(rid,kind,version,raw['etag'])
        return raw

    def list_ids(self,kind):
        version='2024-07-01'if kind=='vm'else VERSION
        ids=set()
        for page in self.reader.pages(self.get,ARM+self.scope+'/providers/'+TYPES[kind]+'?api-version='+version):
            for row in page:
                if not isinstance(row,dict):unavailable('nsg_inventory_invalid')
                rid=_id(row.get('id'),self.scope,kind).casefold()
                if rid in ids:unavailable('nsg_inventory_duplicate')
                ids.add(rid)
                if len(ids)>1000:unavailable('nsg_inventory_resource_budget')
        return ids

    def initial(self):
        for kind in DEPENDENCIES:
            collections=[c for c in self.reader.collections if c['type']==kind and c['scope'].casefold()==self.scope.casefold()]
            if len(collections)!=1 or collections[0]['status']not in {'collected','empty'}:unavailable('nsg_required_inventory_incomplete')
            declared=set()
            for row in collections[0]['items']:
                rid=_id(row.get('id'),self.scope,kind).casefold()
                if rid in declared:unavailable('nsg_required_inventory_duplicate')
                declared.add(rid)
            listed=self.list_ids(kind)
            if kind in {'load_balancer','application_gateway'} and listed:
                unavailable('nsg_managed_ingress_universe_unsupported')
            if declared!=listed:unavailable('nsg_inventory_generation_changed')
            self.starts[kind]=listed
        for kind,ids in self.starts.items():
            for rid in sorted(ids):self.fetch(rid,kind)

    def postcheck(self):
        for kind,ids in self.starts.items():
            if self.list_ids(kind)!=ids:unavailable('nsg_inventory_generation_changed')
        for key,(rid,kind,version,etag)in self.versions.items():
            raw=self.reader.call(self.get,ARM+rid+'?api-version='+version)
            if not isinstance(raw,dict)or str(raw.get('id','')).casefold()!=key or raw.get('etag')!=etag:
                unavailable('nsg_native_resource_version_changed')

    def subnet(self,rid):
        if not isinstance(rid,str)or '/subnets/'not in rid:unavailable('nsg_subnet_identity_invalid')
        vnet_id,name=rid.rsplit('/subnets/',1);vnet=self.fetch(vnet_id,'vnet')
        if not re.fullmatch(SEG,name)or name in ('.','..'):unavailable('nsg_subnet_identity_invalid')
        raw=self.reader.call(self.get,ARM+rid+'?api-version='+VERSION)
        if not isinstance(raw,dict)or str(raw.get('id','')).casefold()!=rid.casefold()or not isinstance(raw.get('etag'),str)or not raw['etag']:
            unavailable('nsg_subnet_version_missing')
        if not isinstance(raw.get('properties'),dict):unavailable('nsg_subnet_properties_missing')
        _empty(raw['properties'],('delegations','serviceAssociationLinks','resourceNavigationLinks','applicationGatewayIPConfigurations','privateEndpoints','ipConfigurationProfiles','ipAllocations'))
        if raw['properties'].get('routeTable'):unavailable('nsg_user_route_table_unsupported')
        vp=vnet['properties'];_empty(vp,('virtualNetworkPeerings',))
        self.versions[rid.casefold()] = (rid,'subnet',VERSION,raw['etag'])
        return raw,vnet

    def paths(self):
        nsgs={rid:self.objects[rid]for rid in self.starts['nsg']};nics={rid:self.objects[rid]for rid in self.starts['nic']}
        configs={};associations={rid:set()for rid in nsgs};subnets={}
        for nrid,nic in nics.items():
            p=nic['properties']
            if p.get('enableIPForwarding')not in (None,False):unavailable('nsg_forwarding_unsupported')
            nic_nsg=_ref(p,'networkSecurityGroup')
            if nic_nsg and nic_nsg.casefold()not in nsgs:unavailable('nsg_foreign_nic_nsg')
            for config in _objects(p,'ipConfigurations'):
                cid=config.get('id');cp=config.get('properties')
                if not isinstance(cid,str)or not cid.casefold().startswith(nrid+'/ipconfigurations/')or not isinstance(cp,dict)or cid.casefold()in configs:
                    unavailable('nsg_ip_configuration_identity_invalid')
                subnet_id=_ref(cp,'subnet')
                if not subnet_id:unavailable('nsg_ip_configuration_subnet_missing')
                if subnet_id.casefold()not in subnets:subnets[subnet_id.casefold()]=self.subnet(subnet_id)
                subnet,vnet=subnets[subnet_id.casefold()]
                snsg=_ref(subnet['properties'],'networkSecurityGroup')
                parents={n.casefold()for n in(nic_nsg,snsg)if n}
                if not parents<=set(nsgs):unavailable('nsg_subnet_nsg_missing')
                configs[cid.casefold()]=(nic,config,subnet,vnet,parents)
                for nsg in parents:associations[nsg].add(cid.casefold())
        # Resolve every subnet of every implicated VNet, including frontend bindings
        # outside the target subnet. NIC membership alone cannot exclude proxy paths.
        for vnet_id in self.starts['vnet']:
            vnet = self.objects[vnet_id]
            _empty(vnet['properties'],('virtualNetworkPeerings',))
            subnet_refs = vnet['properties'].get('subnets')
            if not isinstance(subnet_refs,list):unavailable('nsg_vnet_subnet_universe_missing')
            seen_subnets = set()
            for ref in subnet_refs:
                sid = ref.get('id') if isinstance(ref,dict) else None
                if (not isinstance(sid,str) or not sid.casefold().startswith(vnet_id+'/subnets/')
                        or sid.casefold() in seen_subnets):unavailable('nsg_vnet_subnet_universe_invalid')
                seen_subnets.add(sid.casefold())
                if sid.casefold() not in subnets:subnets[sid.casefold()] = self.subnet(sid)
            if {sid for sid,(subnet,parent) in subnets.items() if parent['id'].casefold()==vnet_id} != seen_subnets:
                unavailable('nsg_vnet_subnet_universe_mismatch')
        for sid,(subnet,vnet) in subnets.items():
            if 'ipConfigurations' not in subnet['properties']:unavailable('nsg_subnet_ip_universe_missing')
            refs = _objects(subnet['properties'],'ipConfigurations')
            reverse = {str(ref.get('id','')).casefold() for ref in refs}
            actual = {cid for cid,(nic,config,parent,vnet,parents) in configs.items() if parent['id'].casefold()==sid}
            if len(reverse)!=len(refs) or reverse!=actual:unavailable('nsg_managed_subnet_universe_unresolved')
        # Every allocated public address must bind to an enumerated native NIC
        # config with the exact reverse reference. Foreign frontend refs fail shut.
        for pid in self.starts['public_ip']:
            public = self.objects[pid]
            cid = _ref(public['properties'],'ipConfiguration')
            if not cid or cid.casefold() not in configs:unavailable('nsg_public_ip_universe_unresolved')
            if (_ref(configs[cid.casefold()][1]['properties'],'publicIPAddress') or '').casefold()!=pid:
                unavailable('nsg_public_ip_backlink_mismatch')
        # Every native NSG attachment and every subnet IP-config must be resolved.
        for rid,nsg in nsgs.items():
            p=nsg['properties']
            _native_nsg_rules(nsg)
            for field,kind in(('networkInterfaces','nic'),('subnets','subnet')):
                for ref in _objects(p,field):
                    target=ref.get('id')
                    if not isinstance(target,str):unavailable('nsg_attachment_identity_missing')
                    if kind=='nic':
                        if target.casefold()not in nics or (_ref(nics[target.casefold()]['properties'],'networkSecurityGroup')or'').casefold()!=rid:
                            unavailable('nsg_attachment_unresolved')
                    else:
                        if target.casefold()not in subnets:subnets[target.casefold()]=self.subnet(target)
                        subnet,vnet=subnets[target.casefold()]
                        if (_ref(subnet['properties'],'networkSecurityGroup')or'').casefold()!=rid:unavailable('nsg_attachment_unresolved')
                        for ref in _objects(subnet['properties'],'ipConfigurations'):
                            if str(ref.get('id','')).casefold()not in configs:unavailable('nsg_managed_subnet_universe_unresolved')
            reverse_nics={str(r.get('id','')).casefold()for r in _objects(p,'networkInterfaces')}
            actual_nics={nrid for nrid,nic in nics.items()if (_ref(nic['properties'],'networkSecurityGroup')or'').casefold()==rid}
            if reverse_nics!=actual_nics:unavailable('nsg_attachment_generation_mismatch')
            reverse_subnets={str(r.get('id','')).casefold()for r in _objects(p,'subnets')}
            actual_subnets={sid for sid,(subnet,vnet)in subnets.items()if (_ref(subnet['properties'],'networkSecurityGroup')or'').casefold()==rid}
            if reverse_subnets!=actual_subnets:unavailable('nsg_attachment_generation_mismatch')
        by_nic={};admin={};out=[]
        for cid,(nic,config,subnet,vnet,parents)in configs.items():
            if not parents:continue
            np,cp=nic['properties'],config['properties'];nrid=nic['id']
            _empty(cp,('loadBalancerBackendAddressPools','loadBalancerInboundNatRules','applicationGatewayBackendAddressPools','applicationSecurityGroups','virtualNetworkTaps'))
            vm_id=_ref(np,'virtualMachine')
            if not vm_id:unavailable('nsg_non_vm_nic_unsupported')
            vm=self.fetch(vm_id,'vm');network=vm['properties'].get('networkProfile',{})
            if not isinstance(network,dict)or [str(r.get('id','')).casefold()for r in _objects(network,'networkInterfaces')]!=[nrid.casefold()]:
                unavailable('nsg_multinic_vm_unsupported')
            vp=vnet['properties'];vid=vnet['id']
            if vid.casefold()not in admin:
                rows=[r for page in self.queries.pages('admin',vid)for r in page]
                if rows:unavailable('nsg_admin_override_unsupported')
                admin[vid.casefold()]=True
            if nrid.casefold()not in by_nic:
                groups=[r for page in self.queries.pages('nsg',nrid,nsg_ids=tuple(nsgs[n]['id']for n in parents))for r in page]
                routes=[r for page in self.queries.pages('routes',nrid)for r in page]
                by_nic[nrid.casefold()]=(groups,routes)
            groups,routes=by_nic[nrid.casefold()]
            effective={}
            for group in groups:
                nid=str((group.get('networkSecurityGroup')or{}).get('id','')).casefold()
                if nid not in parents or nid in effective:unavailable('nsg_effective_association_mismatch')
                assoc=group.get('association')
                if not isinstance(assoc,dict)or assoc.get('networkManager'):unavailable('nsg_effective_association_missing')
                if (assoc.get('networkInterface')and str(assoc['networkInterface'].get('id','')).casefold()!=nrid.casefold()
                        or assoc.get('subnet')and str(assoc['subnet'].get('id','')).casefold()!=subnet['id'].casefold()):
                    unavailable('nsg_effective_association_mismatch')
                if not (assoc.get('networkInterface')or assoc.get('subnet')):unavailable('nsg_effective_association_missing')
                effective[nid]=group['effectiveSecurityRules']
            if set(effective)!=parents:unavailable('nsg_effective_universe_missing')
            ip=ipaddress.ip_address(cp.get('privateIPAddress'))
            if not ip.is_private:unavailable('nsg_private_address_unsupported')
            allowed={p:set(range(1,65536))for p in('Tcp','Udp')}
            for rules in effective.values():
                decisions=effective_allowed(rules,ip)
                for proto in allowed:allowed[proto]&=decisions[proto]
            world_route=False
            for route in routes:
                if route.get('state')!='Active':unavailable('nsg_effective_route_state_unresolved')
                if route.get('source')!='Default'or route.get('nextHopType')not in {'Internet','VnetLocal','None'}:
                    unavailable('nsg_effective_route_unsupported')
                prefixes=route.get('addressPrefix')
                if not isinstance(prefixes,list)or not prefixes:unavailable('nsg_effective_route_prefix_missing')
                for prefix in prefixes:
                    net=ipaddress.ip_network(prefix,strict=False)
                    if net.version!=ip.version:continue
                    if route['nextHopType']=='Internet'and net.prefixlen==0:world_route=True
                    elif route['nextHopType']=='Internet':unavailable('nsg_partial_internet_route_unsupported')
                    elif not _nonworld(net):unavailable('nsg_nonprivate_specific_route_unsupported')
            if not world_route:unavailable('nsg_internet_route_unproven')
            pip=_ref(cp,'publicIPAddress')
            if not pip:unavailable('nsg_private_config_ingress_unproven')
            public=self.fetch(pip,'public_ip');pp=public['properties']
            if (_ref(pp,'ipConfiguration')or'').casefold()!=cid:unavailable('nsg_public_ip_backlink_mismatch')
            address=ipaddress.ip_address(pp.get('ipAddress'))
            if not address.is_global or address.version!=ip.version:unavailable('nsg_public_ip_address_unproven')
            for parent in parents:
                for proto,ports in allowed.items():
                    for port in sorted(ports):
                        if len(out)>=4096:unavailable('nsg_path_projection_budget')
                        digest=hashlib.sha256((cid+'|'+proto+'|'+str(port)).encode()).hexdigest()[:24]
                        out.append({'id':nsgs[parent]['id']+'/effectiveIngress/'+digest,'parent_id':nsgs[parent]['id'],
                            'properties':{'protocol':proto,'destinationPort':port,'worldSource':True,'allowed':True},
                            '_provenance':{'source_operation':'NetworkInterfaces_ListEffectiveNetworkSecurityGroups',
                                'read_only':True,'representation':'full','nic_id':nrid,'ip_configuration_id':config['id']}})
        # Empty effective-admin answers are reread; VNet ETags alone do not bind manager overrides.
        for vid in admin:
            if any(page for page in self.queries.pages('admin',vid)):unavailable('nsg_admin_generation_changed')
        self.postcheck()
        return out


def collect(reader,request,transport,scopes,wanted,options):
    if not set(wanted)&NATIVE_TYPES:return
    normalize(options,scopes)
    from .azure import _safe_error
    for scope in scopes:
        rows=[];metadata={};error=None;status='collected'
        try:
            inventory=_Inventory(reader,transport,_scope(scope));inventory.initial();rows=inventory.paths()
            if reader.budget.max_items is not None and reader.total+len(rows)>reader.budget.max_items:unavailable('resource_limit')
            metadata={'native_query_proofs':inventory.queries.proofs,'resource_etags':{k:v[3]for k,v in inventory.versions.items()},
                'capture_started_at':inventory.capture_start,'capture_completed_at':datetime.now(timezone.utc).isoformat(),
                'supported_topology':'direct single-NIC VM; no security-admin override; no user/BGP/appliance/managed ingress'}
            # Signed parent rule validation consumes these full native GET facts too.
            for c in reader.collections:
                if c['type']=='nsg'and c['scope'].casefold()==scope.casefold():
                    from .azure import _metadata_only
                    c['items']=[_metadata_only(inventory.objects[row['id'].casefold()])for row in c['items']]
        except Exception as exc:
            status,error=_safe_error(exc);rows=[]
        envelope={'type':'nsg_effective_internet_path','scope':scope,'service':'Microsoft.Network',
            'status':status if error else 'collected'if rows else 'empty','items':rows}
        if error:envelope['error']=error
        else:envelope['metadata']=metadata
        reader.collections.append(envelope);reader.total+=len(rows)
        reader.progress(scope=scope,settled=envelope)
