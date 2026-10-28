"""Short presentation of the six non-path analysis projections."""
HOW = {
    'analysis.grant_review': 'Classifies each declared Allow grant using the bundled permission-risk catalog; it does not calculate complete effective access.',
    'analysis.inactive_identity': 'Reports an explicit zero activity count in the collected usage window; missing activity is not proof that an identity is unused.',
    'analysis.principal_exposure': 'Classifies declared principals against the scanned scopes and collected organization membership, retaining restrictive conditions and attribution gaps.',
    'analysis.network_review': 'Finds Internet-wide allow rules in security groups, firewalls, NSGs or NetworkPolicies; it does not establish an endpoint path.',
    'analysis.coverage': 'Reports missing, denied or malformed inventory required by the identity analysis.',
    'analysis.federated_trust': 'Checks federated trust declarations against collected provider inventory and declared audience and subject restrictions; unresolved identity details remain undetermined.',
}
ACTION = {
    'analysis.grant_review': 'Remove unnecessary broad permissions; retain only the actions and resources the workload needs.',
    'analysis.inactive_identity': 'Confirm whether the identity is still needed before disabling its credentials or removing its permissions.',
    'analysis.principal_exposure': 'Keep public or external principals only where access is intended; restrict the granting policy or binding otherwise.',
    'analysis.network_review': 'Consider whether public access is needed; restrict unnecessary source networks or ports.',
    'analysis.coverage': 'Collect the named missing inventory or resolve its read-permission error before drawing a conclusion.',
    'analysis.federated_trust': 'Restrict the trust policy to the intended issuer, audience and subjects.',
}


def _web_ports(native):
    """Return only explicit TCP80/443 declarations; unrecognized rules retain risk."""
    if not isinstance(native,dict):
        return None
    if 'IpProtocol' in native:
        if native.get('IpProtocol') not in ('tcp','6'):
            return None
        a,b=native.get('FromPort'),native.get('ToPort')
        return [a] if type(a) is int and a==b and a in (80,443) else None
    if 'allowed' in native:
        entries=native['allowed']
        if not isinstance(entries,list) or not entries:return None
        ports=[]
        for entry in entries:
            if not isinstance(entry,dict) or entry.get('IPProtocol') not in ('tcp','6'):return None
            values=entry.get('ports')
            if not isinstance(values,list) or not values:return None
            for v in values:
                if v not in ('80','443','80-80','443-443'):return None
                ports.append(int(v.split('-')[0]))
        return ports
    props=native.get('properties',native)
    if not isinstance(props,dict):return None
    if 'destinationPortRange' in props or 'destinationPortRanges' in props:
        if props.get('protocol') not in ('Tcp','TCP','tcp'):return None
        values=props.get('destinationPortRanges') or [props.get('destinationPortRange')]
        if not isinstance(values,list) or not values or any(v not in ('80','443','80-80','443-443') for v in values):return None
        return [int(v.split('-')[0]) for v in values]
    if 'ports' in native:
        values=native['ports'];out=[]
        if not isinstance(values,list) or not values:return None
        for p in values:
            if not isinstance(p,dict) or p.get('protocol','TCP')!='TCP' or type(p.get('port')) is not int or p['port'] not in (80,443) or p.get('endPort',p['port'])!=p['port']:return None
            out.append(p['port'])
        return out
    return None


def network_priority(evidence, default='high'):
    rules=evidence.get('rules') if isinstance(evidence,dict) else None
    if not isinstance(rules,list) or not rules:return default
    ports=[_web_ports(row.get('native_rule')) if isinstance(row,dict) else None for row in rules]
    return 'medium' if all(ports) else default


def evidence_summary(finding):
    if not isinstance(finding,dict):return None
    cid=finding.get('check_id');e=finding.get('evidence');status=finding.get('status')
    if not isinstance(cid,str) or cid not in HOW and cid!='analysis.internet_exposure' or not isinstance(e,dict):return None
    if cid=='analysis.internet_exposure':return _internet_summary(finding)
    if cid=='analysis.federated_trust' and e.get('reason')=='malformed_native_fact':
        return 'The collected federation declaration is malformed, so issuer and claim restrictions cannot be assessed.'
    if cid=='analysis.network_review' and isinstance(e.get('rules'),list) and e['rules']:
        def valid_rule(row):
            if not isinstance(row,dict) or not isinstance(row.get('native_rule'),dict):return False
            native=row['native_rule'];source=row.get('source')
            if not native:
                return isinstance(source,dict) and source.get('resource_type')=='networkpolicy' and isinstance(source.get('path'),str) and source['path'].startswith('spec.ingress[')
            props=native.get('properties',native)
            if 'IpProtocol' in native:
                protocol=native['IpProtocol']
                if protocol in ('tcp','udp','6','17'):
                    a,b=native.get('FromPort'),native.get('ToPort')
                    return type(a) is int and type(b) is int and 0<=a<=b<=65535
                return isinstance(protocol,str) and bool(protocol) and (protocol in ('icmp','icmpv6','-1') or protocol.isdigit())
            if 'allowed' in native:
                allowed=native['allowed']
                if not isinstance(allowed,list) or not allowed:return False
                for value in allowed:
                    if not isinstance(value,dict):return False
                    protocol=value.get('IPProtocol')
                    if not isinstance(protocol,str) or not (protocol in ('tcp','udp','icmp','esp','ah','ipip','sctp','all') or protocol.isascii() and protocol.isdigit() and 0<=int(protocol)<=255):return False
                    ports=value.get('ports')
                    if ports is not None:
                        if not _strings(ports):return False
                        for port in ports:
                            parts=port.split('-')
                            if len(parts)>2 or not all(p.isascii() and p.isdigit() and 0<=int(p)<=65535 for p in parts) or int(parts[0])>int(parts[-1]):return False
                return True
            if isinstance(props,dict) and 'protocol' in props:return props['protocol'] in ('Tcp','TCP','tcp','Udp','UDP','udp','Icmp','ICMP','icmp','*')
            if 'ports' in native:
                return isinstance(native['ports'],list) and all(isinstance(v,dict) and v.get('protocol','TCP') in ('TCP','UDP','SCTP') and (type(v.get('port')) is int or isinstance(v.get('port'),str)) for v in native['ports'])
            return isinstance(native.get('from'),list) and all(isinstance(v,dict) for v in native['from'])
        def public_origin(row):
            # Reuse the native projection's public-source semantics rather than
            # interpreting a port declaration as evidence of public ingress.
            from .network import public_rules
            native=row['native_rule'];source=row.get('source')
            if 'IpProtocol' in native:kind,data='security_group',{'IpPermissions':[native]}
            elif 'allowed' in native:kind,data='firewall',native
            elif 'properties' in native or 'sourceAddressPrefix' in native or 'sourceAddressPrefixes' in native:
                kind,data='nsg',{'securityRules':[native]}
            elif 'ports' in native or 'from' in native or isinstance(source,dict) and source.get('resource_type')=='networkpolicy':
                kind,data='networkpolicy',{'spec':{'policyTypes':['Ingress'],'ingress':[native]}}
            else:return False
            try:return any(public_rules({'type':kind,'data':data}))
            except (AttributeError,TypeError,ValueError,KeyError):return False
        if not all(valid_rule(row) and public_origin(row) for row in e['rules']):return None
        ports=[_web_ports(x.get('native_rule')) if isinstance(x,dict) else None for x in e['rules']]
        if all(ports):
            names=', '.join('TCP/'+str(p) for p in sorted({p for group in ports for p in group}))
            return f'The collected rules allow Internet-wide sources on {names}; these ports may expose web services, but endpoint reachability is not established.'
        details = _network_details(e['rules'])
        return 'The collected rules allow Internet-wide sources'+(' on '+details if details else '')+'; this can expose services, but endpoint reachability is not established.'
    if cid=='analysis.inactive_identity':
        usage=e.get('usage')
        if isinstance(usage,dict) and usage.get('inactive_observation') is True:
            window=usage.get('window')
            interval=(' from '+window['start']+' to '+window['end']) if isinstance(window,dict) and _text(window.get('start'),50) and _text(window.get('end'),50) else ' in the recorded window'
            return 'No activity was recorded for this identity'+interval+'; telemetry can miss use, so the identity may still be needed.'
    if cid=='analysis.grant_review' and isinstance(e.get('grants'),list) and e['grants']:
        grants=e['grants']
        if not all(isinstance(g,dict) and g.get('allowed_declaration') is True
                   and isinstance(g.get('native_grant'),(dict,str)) and bool(g['native_grant'])
                   and (g.get('broad') is True or g.get('severity') in ('high','critical')) for g in grants):return None
        return _grant_summary(finding,grants)
    if cid=='analysis.coverage':return _coverage_summary(e)
    from .provider_observed_evidence import evidence_summary as provider_summary
    observed=provider_summary(finding)
    if observed is not None:return observed
    if cid=='analysis.principal_exposure':
        entries=e.get('principals')
        if not isinstance(entries,list) or not entries or any(not isinstance(v,dict) for v in entries):return None
        public=[]
        for entry in entries:
            grant=entry.get('native_grant')
            if entry.get('classification')!='public' or not isinstance(grant,dict) or grant.get('Effect')!='Allow':continue
            principal=grant.get('Principal')
            candidates=[principal] if isinstance(principal,str) else list(principal.values()) if isinstance(principal,dict) and set(principal)<={'AWS','Service','Federated','CanonicalUser'} else []
            values=[v for group in candidates for v in (group if isinstance(group,list) else [group])]
            if '*' in values:public.append(entry)
        if public:
            from .trust import restrictive_conditions
            constrained=[v.get('reason')=='public_conditional' or bool(v.get('restrictive_conditions'))
                         or bool(restrictive_conditions(v['native_grant'].get('Condition'))) for v in public]
            actions=[]
            for entry in public:
                value=entry['native_grant'].get('Action')
                for action in value if isinstance(value,list) else [value]:
                    if isinstance(action,str) and 0<len(action)<=100 and all(ord(c)>=32 for c in action):
                        if action not in actions:actions.append(action)
            if not actions:return None
            extra=len(actions)-2
            permission=('all actions' if '*' in actions else ', '.join(actions[:2])+
                        (f' and {extra} other action'+('s' if extra!=1 else '') if extra>0 else '')) if actions else 'the listed actions'
            target='this Lambda function' if finding.get('service') in ('lambda','lambda_function') else 'this IAM role' if finding.get('service')=='iam_role' else 'the resources covered by the statement'
            observation=f'Principal “*” (anyone) is allowed {permission} on {target}.'
            if finding.get('service')=='iam_role' and actions==['sts:AssumeRole']:
                observation='Principal “*” (anyone) is allowed to assume this IAM role.'
            if finding.get('service') in ('lambda','lambda_function') and actions==['lambda:InvokeFunction']:
                observation='Principal “*” (anyone) is allowed to invoke this Lambda function.'
            if all(constrained):
                return observation+' Recorded conditions restrict this grant; other policies may still block requests.'
            if any(constrained):
                return observation+' Only some grants have limiting conditions; other policies may still block requests.'
            return observation+' This may admit unintended callers; other policies may still block requests.'
        external=_aws_principal_summary(finding,entries)
        if external:return external
    if cid=='analysis.federated_trust':
        trusts=e.get('federated_trusts')
        if not isinstance(trusts,list) or not trusts or any(not isinstance(v,dict) for v in trusts):return None
        messages=[];reviewed=[]
        for trust in trusts:
            issuer,principal,problems=trust.get('issuer'),trust.get('federated_principal'),trust.get('problems')
            if not isinstance(issuer,str) or not issuer or len(issuer)>240 or any(c in issuer for c in '\n\r\x00') or not isinstance(principal,str):return None
            oidc=principal.startswith('arn:') and ':oidc-provider/' in principal and principal.split(':oidc-provider/',1)[1]==issuer
            cognito=principal==issuer=='cognito-identity.amazonaws.com'
            if not (oidc or cognito) or not isinstance(problems,list) or any(not isinstance(p,dict) for p in problems):return None
            codes=[p.get('code') for p in problems]
            if any(not isinstance(code,str) for code in codes):return None
            from .trust import _conditions, POSITIVE, _wildcard_subject
            conditions=trust.get('conditions')
            if conditions is not None and not isinstance(conditions,dict):return None
            if isinstance(conditions,dict):
                for operator,clauses in conditions.items():
                    if not _text(operator,80) or not isinstance(clauses,dict):return None
                    for key,value in clauses.items():
                        if not _text(key) or not (_text(value) or _strings(value) and value):return None
            def claim(name):
                return [value for operator,key,values in _conditions(conditions)
                    if key.lower()==issuer.lower()+':'+name and 'ifexists' not in operator.lower()
                    and POSITIVE.match(operator.lower()) for value in values]
            if 'no_sub_condition' in codes and claim('sub'):return None
            if any(code in codes for code in ('no_aud_condition','cognito_no_aud')) and claim('aud'):return None
            if 'wildcard_sub' in codes and not any(_wildcard_subject(issuer.lower(),v) for v in claim('sub')):return None
            if 'cognito_unauthenticated' in codes and not any('unauthenticated' in v for v in claim('amr')):return None
            if 'oidc_audience_disjoint' in codes:
                clients=trust.get('provider_client_ids')
                exact=[value for operator,key,values in _conditions(conditions)
                       if operator.lower()=='stringequals' and key.lower()==issuer.lower()+':aud' for value in values]
                if not oidc or not _strings(clients) or not clients or not exact or set(exact)&set(clients):return None
            if not codes and not claim('aud' if cognito else 'sub'):return None
            for code in codes:
                if code=='no_sub_condition' and oidc:messages.append('The OIDC trust for '+issuer+' does not restrict which token subjects it accepts.')
                elif code=='wildcard_sub' and oidc:messages.append('The OIDC subject pattern leaves the tenant or repository owner unrestricted.')
                elif code=='no_aud_condition' and oidc:messages.append('The OIDC trust does not restrict the token audience.')
                elif code=='cognito_no_aud' and cognito:messages.append('The Cognito trust does not pin an identity-pool audience.')
                elif code=='cognito_unauthenticated' and cognito:messages.append('The trust condition includes unauthenticated Cognito identities.')
                elif code=='oidc_provider_unknown' and oidc:messages.append('The IAM OIDC provider inventory is missing or incomplete, so this role trust cannot be resolved.')
                elif code=='oidc_provider_absent' and oidc:messages.append('The IAM OIDC provider is absent from the complete account inventory, so this role trust cannot use it.')
                elif code=='oidc_provider_detail_unknown' and oidc:messages.append('The IAM OIDC provider URL or registered client IDs are not completely collected.')
                elif code=='oidc_audience_disjoint' and oidc:messages.append('The trust audience does not match any registered client ID for this IAM OIDC provider.')
                else:return None
            reviewed.append(issuer)
        if messages:
            unique=list(dict.fromkeys(messages))
            neutral={'oidc_provider_unknown','oidc_provider_absent','oidc_provider_detail_unknown','oidc_audience_disjoint'}
            all_codes={p['code'] for trust in trusts for p in trust['problems']}
            if all_codes<=neutral:return ' '.join(unique[:2])
            risk=next((message for message in unique if 'does not restrict' in message or 'leaves the tenant' in message or 'does not pin' in message or 'includes unauthenticated' in message),unique[0])
            return risk+' This may admit unintended token holders; other trust and session controls still affect access.'
        unique=list(dict.fromkeys(reviewed))
        return 'No checked subject or audience restriction issue is recorded for '+', '.join(unique[:1])+(f' and {len(unique)-1} other issuers' if len(unique)>1 else '')+'; provider-side claim customization and effective role access remain unverified.'
    return None


def _text(value, limit=240):
    return isinstance(value,str) and 0<len(value)<=limit and all(ord(c)>=32 for c in value)


def _strings(value):
    return isinstance(value,list) and all(_text(v) for v in value)


def _items(values):
    if len(values)==1:return values[0]
    if len(values)==2:return values[0]+' and '+values[1]
    return ', '.join(values[:2])+f' and {len(values)-2} other '+('item' if len(values)==3 else 'items')


def _network_details(rows):
    labels=[]
    for row in rows[:2]:
        n=row['native_rule'];p=n.get('properties',n)
        if 'IpProtocol' in n:
            proto={'6':'TCP','17':'UDP','-1':'all protocols'}.get(n['IpProtocol'],n['IpProtocol'].upper())
            a,b=n.get('FromPort'),n.get('ToPort')
            labels.append(proto+('/'+str(a)+(('-'+str(b)) if a!=b else '') if type(a)is int and type(b)is int else ''))
        elif 'allowed' in n:
            for allow in n['allowed'][:2]:
                ports=allow.get('ports')
                if ports is not None and not _strings(ports):return None
                labels.append(allow['IPProtocol'].upper()+('/'+_items(ports) if ports else ' (all ports)'))
        elif 'protocol' in p:
            values=p.get('destinationPortRanges') or [p.get('destinationPortRange')]
            if not _strings(values):return None
            labels.append(p['protocol'].upper()+'/'+_items(values))
        elif isinstance(n.get('ports'),list):
            for port in n['ports'][:2]:
                value=port.get('port')
                if not (type(value)is int and 0<=value<=65535 or _text(value,80)):return None
                labels.append(port.get('protocol','TCP')+'/'+str(value))
        elif 'from' in n or not n:
            labels.append('all ports at the NetworkPolicy layer')
    return _items(list(dict.fromkeys(labels))) if labels else None


def _grant_summary(finding,grants):
    provider=finding.get('provider');examples=[]
    for grant in grants:
        native=grant['native_grant']
        if provider=='aws':
            if not isinstance(native,dict) or native.get('Effect')!='Allow':return None
            actions=native.get('Action');actions=[actions] if isinstance(actions,str) else actions
            if actions is None and 'NotAction' in native:
                actions=native['NotAction'];actions=[actions] if isinstance(actions,str) else actions
                if not _strings(actions) or not actions:return None
                label='all actions except '+_items(actions)
            elif _strings(actions) and actions:
                label='all actions' if '*' in actions else _items(actions)
            else:return None
            resources=native.get('Resource');resources=[resources] if isinstance(resources,str) else resources
            if resources is not None and not _strings(resources):return None
            if resources:label+=' on '+('all resources' if '*' in resources else _items(resources))
            examples.append(label)
        elif provider=='gcp':
            if isinstance(native,str) and _text(native):examples.append(native)
            elif isinstance(native,dict) and _text(native.get('role')):
                members=native.get('members')
                if not _strings(members) or not members:return None
                role={'roles/owner':'the Owner role','roles/editor':'the Editor role','roles/viewer':'the Viewer role'}.get(native['role'],'role '+native['role'])
                people=[{'allUsers':'anyone, including anonymous users','allAuthenticatedUsers':'any authenticated Google identity'}.get(m,m) for m in members]
                examples.append(role+' to '+_items(people))
            else:return None
        elif provider=='azure':
            if not isinstance(native,dict):return None
            actions=native.get('actions',[]);data=native.get('dataActions',[])
            if not _strings(actions) or not _strings(data) or not actions+data:return None
            labels=[]
            if actions:labels.append('all management actions' if '*' in actions else _items(actions))
            if data:labels.append('all data actions' if '*' in data else _items(data))
            description=_items(labels)
            if native.get('notActions') or native.get('notDataActions'):description+=', subject to the recorded exclusions'
            examples.append(description)
        elif provider=='k8s':
            if not isinstance(native,dict) or not _strings(native.get('verbs')) or not native['verbs']:return None
            targets=native.get('resources',native.get('nonResourceURLs'))
            if not _strings(targets) or not targets:return None
            verbs='every action' if '*' in native['verbs'] else _items(native['verbs'])
            resources='every Kubernetes resource in the declared API groups' if '*' in targets else _items(targets)
            examples.append(verbs+' on '+resources)
        else:return None
    prefix=('The policy assigns ' if provider=='gcp' else 'The role permits ' if provider in ('azure','k8s') else 'The policy allows ')+_items(list(dict.fromkeys(examples)))+'.'
    assignment=finding['evidence'].get('assignment')
    if provider=='azure' and isinstance(assignment,dict) and _text(assignment.get('principalId')):
        prefix='The assigned role for '+assignment['principalId']+' permits '+_items(list(dict.fromkeys(examples)))+'.'
    conditional=any(g.get('conditional')is True for g in grants)
    return prefix+' These broad or high-impact grants can widen control; '+('recorded restrictions and ' if conditional else '')+'other policies still affect usable access.'


_INVENTORY_LABELS={
    'iam_user':'IAM users','iam_role':'IAM roles','iam_group':'IAM groups','iam_policy':'IAM policies',
    'instance_profile':'instance profiles','organization_account':'organization accounts',
    'service_account':'service accounts','iam_binding':'IAM bindings','role_assignment':'role assignments',
    'role_definition':'role definitions','directory_user':'directory users','directory_group':'directory groups',
    'directory_service_principal':'directory service principals','directory_application':'directory applications',
    'directory_role_assignment':'directory role assignments','directory_role_definition':'directory role definitions',
    'directory_membership':'directory memberships','deny_assignment':'deny assignments','iam_deny_policy':'IAM deny policies',
    'role':'namespace roles','clusterrole':'cluster roles','rolebinding':'namespace role bindings',
    'clusterrolebinding':'cluster role bindings','serviceaccount':'Kubernetes service accounts',
    'user':'users','group':'groups','principal':'principals',
}

def _coverage_summary(e):
    reason=e.get('reason')
    if reason=='malformed_native_fact':return 'A collected inventory record is malformed, preventing reliable identity or permission analysis.'
    if reason=='permission_criticality_unknown' and isinstance(e.get('unclassified_grants'),list) and e['unclassified_grants']:
        return 'The permission catalog could not classify '+str(len(e['unclassified_grants']))+' recorded grants; their security impact remains undetermined.'
    gaps=e.get('gaps')
    if not isinstance(gaps,list) or not gaps:return None
    absent=[];denied=[]
    for gap in gaps:
        if not isinstance(gap,dict) or not _text(gap.get('type'),80):return None
        status=gap.get('status');label=_INVENTORY_LABELS.get(gap['type'],gap['type'].replace('_',' '))
        if status not in ('not_collected','denied','partial','missing','failed','error','unsupported','unknown'):return None
        (denied if status=='denied' else absent).append(label)
    def names(values):
        remaining = len(values)-2
        return _items(values[:2])+(f' and {remaining} other required '+('inventory' if remaining == 1 else 'inventories') if remaining > 0 else '')
    clauses=[]
    if absent:clauses.append('The scan lacks complete inventory for '+names(absent))
    if denied:clauses.append(('reads were denied for ' if clauses else 'The scan was denied access to ')+names(denied))
    return '; '.join(clauses)+'. Missing records can hide grants or principals, so full access cannot be assessed.'


def _aws_principal_summary(finding,entries):
    if finding.get('provider')!='aws':return None
    from .common import principal_scope
    for entry in entries:
        identity,native=entry.get('principal'),entry.get('native_grant')
        if not _text(identity) or not isinstance(native,dict) or native.get('Effect')!='Allow':continue
        p=native.get('Principal');values=[]
        if isinstance(p,str):values=[p]
        elif isinstance(p,dict):
            for group in p.values():values.extend(group if isinstance(group,list) else [group])
        if identity not in values:continue
        actions=native.get('Action');actions=[actions] if isinstance(actions,str) else actions
        if not _strings(actions) or not actions:continue
        permission='all actions (*)' if '*' in actions else _items(actions)
        classification=entry.get('classification')
        if classification=='external':
            account=principal_scope('aws',identity)
            if not account or account!=entry.get('external_scope_id'):continue
            return f'The policy allows {permission} for {identity}, outside the trusted account scope. This can extend access to another account; conditions and other policies still apply.'
        if classification=='unknown':
            return f'The policy allows {permission} for {identity}, but its trusted or external ownership could not be resolved. The intended trust boundary and usable access remain undetermined.'
        if classification=='service_unscoped' and isinstance(p,dict) and identity in (p.get('Service') if isinstance(p.get('Service'),list) else [p.get('Service')]):
            return f'The policy allows {permission} for service {identity} without a recorded source restriction. Intended source accounts and effective access need review.'
    return None


_EXPOSURE_KINDS={
    'public_ip':'public IP path','load_balancer':'load-balancer frontend','database':'database endpoint',
    'managed_endpoint':'managed service endpoint','control_plane':'cluster control-plane endpoint',
    'function_url':'Lambda function URL','external_lambda_invoke':'Lambda direct invocation grant','external_layer_share':'Lambda layer sharing','api':'API endpoint','data_share':'stored-data sharing',
    'external_share':'external snapshot sharing','external_generic_policy_grant':'AWS resource policy grant','external_cluster_snapshot_share':'DocumentDB or Neptune snapshot sharing','external_redshift_snapshot_share':'Redshift snapshot sharing','external_redshift_serverless_snapshot_share':'Redshift Serverless snapshot sharing','external_network':'external VPC peering route','vpn_client_authorization':'Client VPN authorization grant','public_registry':'public image registry','external_log_stream':'log subscription destination','external_registry_share':'ECR repository sharing','external_registry_policy_pull':'ECR registry pull grant','external_registry_template_pull':'ECR future repository grant','external_secret_grant':'secret read grant','external_queue_receive':'SQS message receive grant','external_topic_subscription':'SNS subscription owner','external_topic_subscribe_grant':'SNS Subscribe grant','external_kms_decrypt_grant':'KMS Decrypt grant','external_kms_grant':'KMS grant','serverless':'serverless endpoint','web_app':'web application endpoint',
    'service':'Kubernetes service','ingress':'Kubernetes ingress','malformed':'internet path',
}

def _internet_summary(finding):
    e=finding['evidence'];status=finding.get('status');kind=e.get('exposure_kind')
    if e.get('reason')=='malformed_native_fact':return 'Malformed network inventory prevented the internet-path assessment; public exposure remains undetermined.'
    if kind is None and isinstance(e.get('gaps'),list):
        return _coverage_summary(e)
    if not isinstance(kind,str) or kind not in _EXPOSURE_KINDS:return None
    label=_EXPOSURE_KINDS[kind]
    if kind=='vpn_client_authorization':
        if status=='FAIL':
            return 'An active Client VPN rule declares access for every authenticated client to the recorded destination network. Route and destination controls remain unverified.'
        return 'Client VPN all-client authorization cannot be resolved from the collected rules.'
    if kind=='external_generic_policy_grant':
        principals=e.get('external_scope_ids')
        if status=='FAIL' and _strings(principals) and principals:
            audience='any AWS principal' if '*' in principals else 'external account '+', '.join(principals)
            return 'The collected resource policy declares an unconditional grant to '+audience+'. Caller permissions, service requirements and actual use remain unobserved.'
        if status=='UNKNOWN':
            return 'The resource policy owner, conditions or applicable Deny could not be resolved; foreign use remains uncertain.'
        return None
    if kind=='external_cluster_snapshot_share':
        principals=e.get('external_scope_ids')
        if status=='FAIL' and _strings(principals) and principals:
            audience='all AWS accounts' if '*' in principals else 'external account '+', '.join(principals)
            return 'The owned manual cluster snapshot authorizes '+audience+' to copy or restore it. KMS permissions and actual use were not observed.'
        if status=='UNKNOWN':
            return 'The cluster snapshot identity, restore attributes or recipient scope could not be resolved; sharing remains uncertain.'
        return None
    if kind=='external_redshift_serverless_snapshot_share':
        principals=e.get('external_scope_ids')
        if status=='FAIL' and _strings(principals) and principals:
            return 'The owned Redshift Serverless snapshot authorizes restore by external account '+', '.join(principals)+'. Caller IAM permission, any KMS access and actual restore were not observed.'
        if status=='UNKNOWN':
            return 'The Redshift Serverless snapshot owner, status or restore recipients could not be resolved; foreign restore access remains uncertain.'
        return None
    if kind=='external_redshift_snapshot_share':
        principals=e.get('external_scope_ids')
        if status=='FAIL' and _strings(principals) and principals:
            return 'The owned Redshift manual snapshot authorizes restore by '+', '.join(principals)+'. Caller IAM permission, any KMS access and actual restore were not observed.'
        if status=='UNKNOWN':
            return 'The Redshift snapshot owner, status or restore authorization could not be resolved; foreign restore access remains uncertain.'
        return None
    if kind=='external_registry_template_pull':
        principals=e.get('external_scope_ids')
        if status=='FAIL' and _strings(principals) and principals:
            audience='all AWS accounts' if '*' in principals else 'external account '+', '.join(principals)
            return 'An ECR creation template would grant image-pull actions to '+audience+' on matching future repositories. It does not change existing repositories.'
        if status=='UNKNOWN':
            return 'The ECR creation template or applicable policy conditions could not be resolved; a future foreign pull grant remains uncertain.'
        return None
    if kind=='external_registry_policy_pull':
        principals=e.get('external_scope_ids')
        if status=='FAIL' and _strings(principals) and principals:
            audience='all AWS accounts' if '*' in principals else 'external account '+', '.join(principals)
            return 'The ECR registry policy grants image-pull actions to '+audience+'. A token, matching repository and actual image pull were not observed.'
        if status=='UNKNOWN':
            return 'The ECR registry policy or applicable Deny and conditions could not be resolved; foreign image-pull capability remains uncertain.'
        return None
    if kind=='external_layer_share':
        principals=e.get('external_scope_ids')
        if status=='FAIL' and _strings(principals) and principals:
            audience='all AWS accounts' if '*' in principals else 'external account '+', '.join(principals)
            return 'The Lambda layer version policy grants GetLayerVersion to '+audience+'. Caller permissions and actual download were not observed.'
        if status=='UNKNOWN':
            return 'The Lambda layer policy or applicable Deny and conditions could not be resolved; foreign layer access remains uncertain.'
        return None
    if kind=='external_lambda_invoke':
        principals=e.get('external_scope_ids')
        if status=='FAIL' and _strings(principals) and principals:
            audience='any AWS principal' if '*' in principals else 'external account '+', '.join(principals)
            return 'The function or alias policy grants InvokeFunction to '+audience+'. The caller also needs identity permission; no invocation was observed.'
        if status=='UNKNOWN':
            return 'The Lambda policy or applicable Deny and conditions could not be resolved; foreign direct invocation remains uncertain.'
        return None
    if kind=='external_kms_grant':
        principals=e.get('external_scope_ids')
        if status=='FAIL' and _strings(principals) and principals:
            return 'An active KMS grant permits Decrypt for a principal in external account '+', '.join(principals)+'. Other authorization controls and possession of decryptable ciphertext were not observed.'
        if status=='PASS':
            return 'The KMS grant key cannot currently decrypt.'
        if status=='UNKNOWN':
            return 'The KMS grant, encryption context constraints, key state or key-policy Deny could not be resolved; foreign decryption remains uncertain.'
        return None
    if kind=='external_kms_decrypt_grant':
        principals=e.get('external_scope_ids')
        if status=='FAIL' and _strings(principals) and principals:
            audience='any principal' if '*' in principals else 'external account '+', '.join(principals)
            return 'The enabled customer KMS key policy grants Decrypt to '+audience+'. The caller also needs its own IAM permission and decryptable ciphertext; no decryption was observed.'
        if status=='PASS':
            return 'The KMS key is disabled or unavailable for decryption in its current state.'
        if status=='UNKNOWN':
            return 'The KMS key metadata, policy, or applicable Deny and conditions could not be resolved; foreign decryption remains uncertain.'
        return None
    if kind=='external_topic_subscribe_grant':
        accounts=e.get('external_scope_ids')
        if status=='FAIL' and _strings(accounts) and accounts:
            audience='any principal' if '*' in accounts else 'external account '+', '.join(accounts)
            return 'The SNS topic policy permits '+audience+' to request a subscription. An endpoint still needs confirmation; no message delivery was observed.'
        if status=='UNKNOWN':
            return 'The SNS topic policy or applicable Deny and conditions could not be resolved; foreign subscription capability remains uncertain.'
        return None
    if kind=='external_topic_subscription':
        accounts=e.get('external_scope_ids')
        if status=='FAIL' and _strings(accounts) and accounts:
            return 'A confirmed subscription to the SNS topic is owned by external account '+', '.join(accounts)+'. The endpoint was not retained, and message delivery was not observed.'
        if status=='UNKNOWN':
            return 'The SNS subscription is pending confirmation or its topic and owner cannot be attributed; external delivery remains uncertain.'
        return None
    if kind=='external_queue_receive':
        accounts=e.get('external_scope_ids')
        if status=='FAIL' and _strings(accounts) and accounts:
            return 'The SQS queue policy grants ReceiveMessage to external account '+', '.join(accounts)+'. The caller also needs its own identity permission and any customer KMS Decrypt access; no messages were read.'
        if status=='PASS':
            return 'The queue uses the AWS managed SQS KMS key, which cannot grant cross-account decrypt access.'
        if status=='UNKNOWN':
            return 'The SQS policy, KMS key, or applicable Deny and conditions could not be resolved; foreign message receive remains uncertain.'
        return None
    if kind=='external_secret_grant':
        accounts=e.get('external_scope_ids')
        if status=='FAIL' and _strings(accounts) and accounts:
            return 'The secret policy grants GetSecretValue to external account '+', '.join(accounts)+'. The caller also needs its own identity permission and KMS Decrypt access; no secret value was read.'
        if status=='PASS':
            return 'The secret uses the AWS managed default KMS key, which cannot support cross-account secret reads.'
        if status=='UNKNOWN':
            return 'The secret policy, customer KMS key, or applicable Deny and conditions could not be resolved; external secret-read access remains uncertain.'
        return None
    if kind=='external_registry_share':
        path=e.get('path')
        rows=[step for step in path if isinstance(step,dict) and step.get('layer')=='repository_policy'] if isinstance(path,list) else []
        accounts=e.get('external_scope_ids')
        if status=='FAIL' and len(rows)==1 and rows[0].get('decision')=='allow' and _strings(accounts) and accounts:
            return 'The ECR repository policy grants image pull actions to external account '+', '.join(accounts)+'. The caller still needs authentication and its own permissions; image pulls were not observed.'
        if status=='UNKNOWN':
            return 'The ECR repository policy or applicable Deny and conditions could not be resolved; external image pull access remains uncertain.'
        return None
    if kind=='external_log_stream':
        path=e.get('path')
        rows=[step for step in path if isinstance(step,dict) and step.get('layer')=='subscription'] if isinstance(path,list) else []
        external=e.get('external_scope_ids')
        if (status=='FAIL' and len(rows)==1 and rows[0].get('decision')=='allow' and _strings(external) and external and
                rows[0].get('recipient_account')==external[0] and _text(rows[0].get('destination_arn')) and
                _text(rows[0].get('log_group'))):
            return 'The CloudWatch Logs subscription for '+rows[0]['log_group']+' targets a destination in external account '+external[0]+'. Matching log events may be sent there; delivery was not verified.'
        if status=='UNKNOWN' and isinstance(e.get('unresolved'),list) and e['unresolved']:
            return 'The CloudWatch Logs subscription source or destination is incomplete; external delivery cannot be attributed.'
        return None
    if kind=='public_registry':
        path=e.get('path')
        rows=[step for step in path if isinstance(step,dict) and step.get('layer')=='public_repository'] if isinstance(path,list) else []
        if (status=='FAIL' and len(rows)==1 and rows[0].get('decision')=='allow' and
                _text(rows[0].get('repository_arn')) and _text(rows[0].get('repository_name')) and
                rows[0]['repository_arn'].startswith('arn:aws:ecr-public::') and
                rows[0]['repository_arn'].endswith(':repository/'+rows[0]['repository_name'])):
            return 'The ECR Public repository '+rows[0]['repository_name']+' is publicly readable; any published images can be pulled anonymously. Image contents were not enumerated.'
        if status=='UNKNOWN' and isinstance(e.get('unresolved'),list) and e['unresolved']:
            return 'The ECR Public repository identity or regional scope is incomplete; public image access cannot be attributed.'
        return None
    if kind=='external_network':
        path=e.get('path')
        resource_type=(e.get('source') if isinstance(e.get('source'),dict) else {}).get('resource_type')
        if resource_type=='transit_gateway_attachment':
            routes=[step for step in path if isinstance(step,dict) and step.get('layer')=='transit_route'] if isinstance(path,list) else []
            external=e.get('external_scope_ids')
            if status=='FAIL' and len(routes)==1 and routes[0].get('decision')=='allow' and _strings(external) and external and routes[0].get('foreign_account')==external[0] and _text(routes[0].get('foreign_attachment')):
                return 'A local VPC route and associated Transit Gateway route select a VPC attachment owned by external account '+external[0]+'. Return routing and endpoint access remain unverified.'
            if status=='UNKNOWN' and isinstance(e.get('unresolved'),list) and e['unresolved']:
                return 'The route from a local VPC to the foreign Transit Gateway attachment is unresolved.'
            return None
        routes=[step for step in path if isinstance(step,dict) and step.get('layer')=='peering_route'] if isinstance(path,list) else []
        external=e.get('external_scope_ids')
        if status=='FAIL' and len(routes)==1 and routes[0].get('decision')=='allow' and _strings(external) and external and routes[0].get('peer_account')==external[0] and isinstance(routes[0].get('routes'),list) and routes[0]['routes']:
            return 'An active VPC peering connection has a local route toward external account '+external[0]+'. Peer routing, endpoint filtering and application access remain unverified.'
        if status=='PASS' and len(routes)==1 and routes[0].get('decision')=='block':
            return 'The active external VPC peering connection has no active local route in the collected route tables.'
        if status=='UNKNOWN' and isinstance(e.get('unresolved'),list) and e['unresolved']:
            return 'The external VPC peering state or local route inventory is incomplete; access cannot be resolved.'
        return None
    if status=='UNKNOWN':
        if finding.get('provider')=='k8s' and kind in ('service','ingress') and isinstance(e.get('path'),list):
            invalid=[value for step in e['path'] if isinstance(step,dict)
                     and step.get('layer')=='source_ranges' and step.get('decision')=='unknown'
                     for value in step.get('invalid_source_ranges',[]) if _text(value,200)]
            if invalid:
                noun='Service' if kind=='service' else 'Ingress'
                value=_items(invalid[:2])
                return (f'The {noun} has source range {value}, which is not a valid IP range.\n'
                        "The controller's treatment of that value is not recorded, so its public source rule is unclear.\n"
                        'The source rule may admit public requests if the controller ignores that range.\n'
                        f'That could expose data served through this {noun}.')
        if finding.get('provider')=='k8s' and kind=='service' and isinstance(e.get('path'),list):
            declarations=[step.get('declared_public_addresses') for step in e['path']
                          if isinstance(step,dict) and step.get('layer')=='external_ip'
                          and step.get('decision')=='unknown']
            addresses=[address for group in declarations if isinstance(group,list)
                       for address in group if _text(address,200)]
            ports=e.get('exposed_ports')
            if addresses and _strings(ports) and ports:
                return ('The Service declares externalIPs '+_items(addresses)+'.\n'
                        'It declares '+_items(ports)+' for that address.\n'
                        'Address ownership and routing to a cluster node are not observed.\n'
                        'Cloud firewall admission and live reachability remain unknown.')
        unresolved=e.get('unresolved')
        if not isinstance(unresolved,list) or not unresolved:return None
        layers=[v.get('layer') for v in unresolved if isinstance(v,dict) and _text(v.get('layer'),60)]
        detail='; '+_items([x.replace('_',' ') for x in layers])+' evidence is incomplete' if layers else ''
        return 'The '+label+' cannot be resolved'+detail+'. Missing path layers prevent a public-reachability conclusion.'
    if status=='PASS':
        blocked=e.get('blocked_by')
        path=e.get('path')
        if kind=='function_url' and e.get('authenticated_endpoint')is True and isinstance(path,list) and any(isinstance(p,dict) and p.get('layer')=='authorization' and p.get('auth_type')=='AWS_IAM' for p in path):
            return 'The Lambda function URL requires signed AWS requests, limiting anonymous invocation. Effective caller permissions and runtime behavior were not tested.'
        if blocked is None and e.get('exposed_ports')==[] and isinstance(path,list) and path:
            return 'The path model records no exposed ports; its deciding blocking layer was not stored. Live access was not tested.'
        if not _text(blocked,80) or not isinstance(path,list) or not any(isinstance(p,dict) and p.get('layer')==blocked and p.get('decision')=='block' for p in path):return None
        return 'The configured '+label+' is blocked at the '+blocked.replace('_',' ')+' layer. This is a configuration assessment; no connection was attempted.'
    if status not in ('FAIL','MANUAL'):return None
    path=e.get('path')
    if not isinstance(path,list) or not path or any(not isinstance(p,dict) or not _text(p.get('layer'),80) or p.get('decision') not in ('allow','block','unknown','not_public') for p in path):return None
    if not any(p.get('decision')=='allow' for p in path) or e.get('blocked_by')is not None:return None
    ports=e.get('exposed_ports');addresses=e.get('public_addresses');external=e.get('external_scope_ids')
    if not _strings(ports) or not _strings(addresses):return None
    if kind=='external_share' and _strings(external) and external:
        source=e.get('source') if isinstance(e.get('source'),dict) else {}
        if source.get('resource_type')=='ec2_image':
            return 'AMI launch access is declared for external principals '+_items(external)+'. They may launch the shared image; actual use and other controls were not tested.'
        return 'Snapshot restore access is declared for external accounts '+_items(external)+'. These accounts may copy the data; actual restores and other controls were not tested.'
    if e.get('data_exposure')is True:
        source=e.get('source') if isinstance(e.get('source'),dict) else {}
        if kind=='data_share' and source.get('resource_type')=='ec2_image':
            if not any(step.get('decision')=='allow' and
                       (step.get('layer')=='attributes' and step.get('public_group')=='all' or
                        step.get('layer')=='image_public_flag' and step.get('public') is True)
                       for step in path):return None
            return 'The AMI has public launch permission. Other accounts may launch it; successful use and backing snapshot access were not tested.'
        noun='Snapshot restore access' if kind=='data_share' and 'snapshot' in str((e.get('source') if isinstance(e.get('source'),dict) else {}).get('resource_type','')) else 'Stored-data access'
        return noun+' is declared public. This may expose data to unintended readers; actual reads and other access controls were not tested.'
    target=(' at '+_items(addresses)) if addresses else ''
    services=(' on '+_items(ports)) if ports else ''
    limit=' Authentication still governs application access; no connection was attempted.' if e.get('authenticated_endpoint')is True else ' This can admit internet callers; no connection was attempted.'
    if isinstance(e.get('unresolved'),list) and e['unresolved']:limit=' Some path layers remain unresolved, so usable access is not established.'
    return 'The '+label+target+' is configured to accept internet traffic'+services+'.'+limit
