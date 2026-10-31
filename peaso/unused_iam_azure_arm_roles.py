"""ARM custom-role structural consumers, across declared assignable scopes."""
from datetime import timedelta
from pathlib import Path
import json
from peaso.azure_unused_arm_role_contract import ARM,KIND,META,SCHEMA,REPORTS,MG,scope,subscription,path,role_id,project,guid
from peaso.iam_usage_evidence import instant
from peaso.unused_iam_azure import EvidenceError,_field
from peaso.unused_iam_azure_roles import ACTIVE,INACTIVE

CHECK='azure.iam.custom_arm_role_has_declared_consumers'
TITLE='Custom ARM role has consumers across its assignable scopes'


def memo(index,key,build):
    from peaso.checks.facts import memoized
    return memoized(index,('unused_azure_arm_role',key),build)


def bound(proof,meta,tenant=False):
    return (isinstance(proof,dict) and all(isinstance(meta.get(k),str) and meta[k] and proof.get(k)==meta[k] for k in ('credential_context_id','customer_context_id'))
        and (not tenant or proof.get('read_only') is True and proof.get('tenant_verified') is True and str(proof.get('tenant_id','')).casefold()==str(meta.get('tenant_id','')).casefold()))


def authority(index):
    context=index.get('context',{});meta=context.get('metadata',{})
    if context.get('provider')!='azure' or meta.get('tenant_verified') is not True:raise EvidenceError('verified Azure tenant is unavailable')
    guid(meta.get('tenant_id'));sc=scope(context.get('scope'),root=True)
    return context,meta,sc


def collection(index,kind,sc,meta):
    rows=index.get('collections',{}).get(kind)
    projected=index.get(kind)
    if not isinstance(rows,list) or len(rows)!=1 or not isinstance(projected,list):raise EvidenceError('unique native '+kind+' inventory is unavailable')
    row=rows[0]
    if (scope(row.get('scope'),root=True)!=sc or row.get('type')!=kind or row.get('service')!='Microsoft.Authorization'
            or not bound(row.get('_provenance'),meta) or not isinstance(row.get('items'),list)
            or any(not isinstance(r,dict) or r.get('type')!=kind or scope(r.get('scope'),root=True)!=sc for r in projected)
            or [r.get('data') for r in projected]!=row['items']):raise EvidenceError('ARM source and scoped resource projection disagree')
    return row


def current(item,index,sc,meta):
    identity=role_id(_field(item,'id'));guid(_field(item,'name'))
    if guid(item['name'])!=identity or str(item.get('type','')).casefold()!='microsoft.authorization/roledefinitions':raise EvidenceError('current ARM role identity is malformed')
    if not bound(item.get('_provenance'),meta):raise EvidenceError('ARM role belongs to another credential capture')
    native=item.get('_authorization_native_list',{});expected=sc.rstrip('/')+'/providers/Microsoft.Authorization/roleDefinitions'
    if (native.get('read_only') is not True or native.get('source_operation')!='roleDefinitions_ListForScope' or native.get('api_version')!='2022-04-01'
            or scope(native.get('requested_scope'),root=True)!=sc or str(native.get('request_path','')).casefold()!=expected.casefold()
            or native.get('filter') not in (None,"type eq 'CustomRole'")):
        raise EvidenceError('complete native ARM role-definition List is unavailable')
    def build():
        source=collection(index,'role_definition',sc,meta)
        if source.get('status') not in ('collected','partial'):raise EvidenceError('ARM role definitions are unavailable','DENIED' if source.get('status')=='denied' else 'UNKNOWN')
        mapping={}
        for row in source['items']:
            rid=role_id(row.get('id'))
            if rid in mapping:raise EvidenceError('current ARM role identity is duplicated')
            mapping[rid]=row
        return mapping
    if memo(index,'current_roles',build).get(identity)!=item:raise EvidenceError('assessed role differs from its current native definition')
    return identity


def frame(index,sc,meta,now):
    def build():
        source=collection(index,KIND,sc,meta)
        if source.get('status')!='collected':raise EvidenceError('ARM role-consumer evidence is unavailable','DENIED' if source.get('status')=='denied' else 'UNKNOWN')
        if len(source['items'])!=1:raise EvidenceError('ARM role evidence reference is ambiguous')
        ref=source['items'][0];proof=ref.get('_provenance',{})
        data=meta.get(META);dp=data.get('_provenance',{}) if isinstance(data,dict) else {}
        if (ref.get('schema')!=SCHEMA or ref.get('metadata_key')!=META or ref.get('id','').casefold()!=sc.rstrip('/')+'/unusedarmroleevidence'
                or not bound(proof,meta,True) or not isinstance(data,dict) or data.get('schema')!=SCHEMA or not bound(dp,meta,True)
                or proof!=dp or dp.get('endpoint')!='native-unused-arm-role-projection' or dp.get('schema')!=SCHEMA
                or abs(instant(dp.get('observed_at'))-now)>timedelta(days=1)):
            raise EvidenceError('ARM role evidence capture or tenant binding is unavailable')
        selected=data.get('selected_subscriptions')
        if (not isinstance(selected,list) or any(subscription(s)!=scope(s) for s in selected)
                or len(set(map(scope,selected)))!=len(selected) or not isinstance(data.get('bindings'),dict)
                or not isinstance(data.get('hierarchies'),dict) or not isinstance(data.get('sources'),list)):
            raise EvidenceError('ARM role source frame is malformed')
        return data,{scope(s) for s in selected}
    return memo(index,'source_frame',build)


def binding(data,sc,meta):
    row=data['bindings'].get(sc)
    if not isinstance(row,dict):raise EvidenceError('owning-scope tenant read is unavailable: '+sc)
    if row.get('status')!='collected':
        raise EvidenceError('owning-scope tenant read is incomplete: '+sc,'DENIED' if row.get('status')=='denied' else 'UNKNOWN')
    if (row.get('scope')!=sc or row.get('path')!=sc or row.get('api_version')!=('2020-05-01' if sc.startswith(MG) else '2022-12-01')
            or row.get('method')!='GET' or row.get('body','missing') is not None or row.get('audience')!=ARM
            or guid(row.get('tenant_id'))!=guid(meta.get('tenant_id'))):raise EvidenceError('ARM owning-scope tenant identity disagrees')


def hierarchy(data,sc,meta,selected):
    binding(data,sc,meta)
    row=data['hierarchies'].get(sc)
    if not isinstance(row,dict):raise EvidenceError('management-group descendants were not read: '+sc)
    if row.get('status') not in ('collected','empty'):
        cause=row.get('error',{}).get('cause_status',row.get('status'))
        raise EvidenceError('complete management-group descendants are unavailable: '+sc,'DENIED' if cause=='denied' else 'UNKNOWN')
    if (row.get('scope')!=sc or row.get('path')!=sc+'/descendants' or row.get('api_version')!='2020-05-01' or row.get('audience')!=ARM
            or row.get('method')!='GET' or row.get('body','missing') is not None or row.get('filter','missing') is not None
            or row.get('integrity_error') is not False or not isinstance(row.get('items'),list)):
        raise EvidenceError('unfiltered management-group descendant source is unavailable')
    children={}
    for item in row['items']:
        sid,parent=scope(item.get('id')),scope(item.get('parent'))
        if sid==sc or sid in children or not parent.startswith(MG) or not (sid.startswith(MG) or sid==subscription(sid)):
            raise EvidenceError('management-group descendant identity is inconsistent')
        children[sid]=parent
    for sid in children:
        seen=set();parent=sid
        while parent!=sc:
            if parent in seen or parent not in children:raise EvidenceError('management-group ancestry is missing or cyclic')
            seen.add(parent);parent=children[parent]
    subs={s for s in children if subscription(s)}
    if not subs<=selected:raise EvidenceError('management group includes subscriptions outside the selected scope: '+sc)
    for sub in subs:binding(data,sub,meta)
    return {sc,*children}


def graph(index,data,selected,meta,now):
    def build():
        allowed=set();scope_errors={}
        for sub in selected:
            try:binding(data,sub,meta);allowed.add(sub)
            except (EvidenceError,ValueError) as exc:scope_errors[sub]=exc
        mg_allowed=set()
        for sc in data['hierarchies']:
            try:mg_allowed|=hierarchy(data,scope(sc),meta,selected)
            except (EvidenceError,ValueError) as exc:scope_errors[sc]=exc
        allowed|=mg_allowed
        sources={};issues={};consumers={}
        for source in data['sources']:
            if not isinstance(source,dict):raise EvidenceError('native ARM consumer source is malformed')
            sc=scope(source.get('scope'));name=source.get('name');key=(sc,name)
            if name not in REPORTS or key in sources:raise EvidenceError('ARM consumer source is unknown or duplicated')
            sources[key]=source
            try:
                p,version=path(sc,name)
                if not ((subscription(sc) in allowed) if subscription(sc) else sc in allowed):raise EvidenceError('ARM consumer source is outside the verified tenant or selected boundary')
                if (str(source.get('path','')).casefold()!=p.casefold() or source.get('api_version')!=version or source.get('audience')!=ARM or source.get('method')!='GET'
                        or source.get('body','missing') is not None or source.get('filter','missing') is not None or source.get('integrity_error') is not False
                        or not isinstance(source.get('items'),list)):
                    raise EvidenceError('unfiltered native ARM consumer source is unavailable')
                status=source.get('status')
                if (status=='empty' and source['items'] or status=='collected' and not source['items']
                        or status not in ('empty','collected','partial','denied','unknown','not_collected','malformed','timeout')):
                    raise EvidenceError('ARM consumer source status contradicts its rows')
                if status not in ('collected','empty'):
                    cause=source.get('error',{}).get('cause_status',status)
                    issues[key]=EvidenceError('ARM assignment/PIM inventory is incomplete: '+sc+'/'+name,'DENIED' if cause=='denied' else 'UNKNOWN')
                seen=set();local={};errors=[]
                for raw in source['items']:
                    row=project(name,raw,sc);rid=row['id'].casefold()
                    declared_sub=subscription(row['properties']['scope']) if row['properties']['scope']!='/' else None
                    if declared_sub:
                        if declared_sub not in selected:raise EvidenceError('consumer belongs to an unselected subscription')
                        binding(data,declared_sub,meta)
                    if rid in seen:raise EvidenceError('ARM consumer identity is duplicated')
                    seen.add(rid);props=row['properties'];role=role_id(props['roleDefinitionId'])
                    try:
                        if name!='assignments':
                            state=_field(props,'status')
                            if state in INACTIVE:continue
                            if state not in ACTIVE:raise EvidenceError('ARM PIM schedule state is unavailable')
                            start=instant(_field(props,'startDateTime'))
                            end=_field(props,'endDateTime')
                            if end is not None:
                                end=instant(end)
                                if end<=start:raise EvidenceError('ARM PIM schedule lifetime is contradictory')
                                if end<=now:continue
                        if props.get('condition') is not None and not isinstance(props['condition'],str):raise EvidenceError('ARM assignment condition is malformed')
                        local.setdefault(role,[]).append({'source_scope':sc,'source':name,**row})
                    except (EvidenceError,ValueError,TypeError,OverflowError) as exc:errors.append(exc)
                if errors and key not in issues:issues[key]=errors[0]
                for role,rows in local.items():consumers.setdefault(role,[]).extend(rows)
            except (EvidenceError,ValueError,TypeError,KeyError,AttributeError) as exc:issues[key]=exc
        return consumers,sources,issues,scope_errors
    cache=getattr(index,'memo',None)
    if cache is None:return build()
    shared=cache.get(('_shared_snapshot_memo',),cache)
    key=('unused_azure_arm_role_consumer_graph',id(data))
    if key not in shared:shared[key]=build()
    return shared[key]


def evaluate(item,index):
    try:
        context,meta,sc=authority(index);now=instant(context.get('created_at'));identity=current(item,index,sc,meta)
        props=_field(item,'properties');kind=_field(props,'type')
        if kind=='BuiltInRole':return 'NOT_APPLICABLE',{'reason':'Microsoft built-in ARM role'}
        if kind!='CustomRole':raise EvidenceError('ARM role type is unrecognized')
        scopes=_field(props,'assignableScopes');permissions=_field(props,'permissions')
        if not isinstance(scopes,list) or not scopes or len(set(map(scope,scopes)))!=len(scopes):raise EvidenceError('complete role assignable scopes are unavailable or duplicated')
        scopes=[scope(s) for s in scopes]
        if not isinstance(permissions,list):raise EvidenceError('ARM role permission declarations are unavailable')
        for block in permissions:
            if not isinstance(block,dict):raise EvidenceError('ARM role permission block is malformed')
            if not any(key in block for key in ('actions','dataActions')):raise EvidenceError('ARM role action declarations are unavailable')
            for name in ('actions','notActions','dataActions','notDataActions'):
                if name in block and (not isinstance(_field(block,name),list) or any(not isinstance(v,str) or not v for v in block[name])):
                    raise EvidenceError('ARM role action/exclusion declarations are malformed')
        data,selected=frame(index,sc,meta,now)
        consumers,sources,issues,scope_errors=graph(index,data,selected,meta,now)
        found=consumers.get(identity,[]);name=props.get('roleName') or identity
        evidence={'role_id':identity,'native_role_id':item['id'],'role_name':name,'permissions':permissions,'assignable_scopes':scopes,
            'declared_consumers':found,'semantics':'Captured declarations and all declared assignable scopes; not action-use history, business approval or safe deletion.'}
        if found:return 'PASS',{**evidence,'summary':f'Custom ARM role {name} has a captured assignment or PIM consumer.\nThe captured principal, condition and scope describe that declared use of the role definition.\nAn assignment does not establish recent use of its permissions.'}
        required=set();failures=[]
        has_data=any(block.get('dataActions') for block in permissions)
        for s in scopes:
            try:
                sub=subscription(s)
                if sub:
                    if sub not in selected:raise EvidenceError('role can be assigned in an unselected subscription: '+s)
                    binding(data,sub,meta);required.add(s)
                else:
                    nodes=hierarchy(data,s,meta,selected)
                    required|={n for n in nodes if not has_data or subscription(n)}
            except (EvidenceError,ValueError) as exc:failures.append(exc)
        for s in required:
            for source in REPORTS:
                key=(s,source)
                if key not in sources:failures.append(EvidenceError('native assignment/PIM read is missing: '+s+'/'+source))
                elif key in issues:failures.append(issues[key])
        if failures:raise next((exc for exc in failures if getattr(exc,'status',None)=='DENIED'),failures[0])
        return 'FAIL',{**evidence,'summary':f'Custom ARM role {name} has no captured assignment or unexpired PIM consumer across its {len(scopes)} assignable scopes.\nComplete native reads cover those scopes and their required management-group descendants.\nAn obsolete permission definition adds configuration that still needs maintenance and review.'}
    except (EvidenceError,ValueError,TypeError,KeyError,AttributeError,OverflowError) as exc:
        return getattr(exc,'status','UNKNOWN'),{'reason':str(exc),'summary':str(exc).rstrip('.')+'.\nThe custom role’s declared consumers are unresolved.\nMissing scope or PIM evidence cannot establish an unused role definition.'}


def install(registry):
    from peaso.checks.fixtures import CASES
    raw=Path(__file__).with_name('checks').joinpath('unused_iam_azure_arm_roles_cases.json').read_bytes()
    cases=json.loads(raw)
    if set(cases)!={CHECK}:raise ValueError('ARM unused-role case IDs changed')
    CASES.update(cases)
    registry.register(CHECK,'azure','hardening','role_definition',TITLE,'low','AC-2',
        'Review role ownership, pending assignments and all assignable scopes before removing an obsolete custom role.',
        dependencies=('role_definition',KIND),allow_incomplete_failure=True)(evaluate)
