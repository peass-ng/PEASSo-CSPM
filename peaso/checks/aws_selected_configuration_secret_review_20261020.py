"""Pure, explicitly installed proposal for selected AWS configuration content."""
from copy import deepcopy
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors.aws_selected_configuration_secret_indicators import (
    KIND,CHECK,MARKER,SCHEMA,SURFACES,MAX_TARGETS,MAX_RESPONSE,MAX_CONTENT,MAX_PAIRS,MAX_LEAKS,MAX_LOCATIONS,SCOPE)
import re

DECLARATIONS=[{'id':CHECK,'provider':'aws','category':'exposure','kind':KIND,'finding_type':'secrets','group':'Secrets',
 'severity':'high','requirements':[],'dependencies':['aws_account',KIND],'allow_incomplete_failure':True,
 'title':'Selected AWS configuration literals have no detected secrets',
 'remediation':'Remove exposed credential literals from the selected configuration and rotate confirmed exposed credentials. Prefer scoped workload identities or appropriate secret references.',
 'evidence_sentences':['A likely secret was detected in the selected AWS configuration content.','Its value is hidden; offline detection did not validate the credential.']}]


class _Reason(ValueError):
    """An UNKNOWN with a concrete, provider-text-free cause."""


def evaluate(item,index):
    try:
        ctx=index['context'];scope=ctx['scope'];meta=ctx['metadata'];match=SCOPE.fullmatch(scope)
        if ctx['provider']!='aws' or not match or meta[KIND+'_authorized'] is not True:raise ValueError()
        account,region=match.groups();selected=meta[KIND+'_selection'][scope]
        if (not isinstance(selected,list) or not 1<=len(selected)<=MAX_TARGETS or len(set(selected))!=len(selected)
                or any(not isinstance(v,str) or not re.fullmatch(KIND+':[0-9a-f]{64}',v) for v in selected)):raise ValueError()
        own=[c for c in index['collections'][KIND] if c.get('scope')==scope]
        if len(own)!=1 or own[0].get('status') not in ('collected','partial') or own[0].get('account_id')!=account:raise ValueError()
        own=own[0];rows=own.get('items')
        if (not isinstance(rows,list) or any(not isinstance(r,dict) for r in rows) or sum(r==item for r in rows)!=1
                or len({r.get('id') for r in rows})!=len(rows) or any(r.get('id') not in selected for r in rows)):raise ValueError()
        parent=[c for c in index['collections']['aws_account'] if c.get('scope')==account+'/global']
        if (len(parent)!=1 or parent[0].get('status')!='collected' or parent[0].get('account_id')!=account
                or parent[0].get('global') is not True or len(parent[0].get('items',[]))!=1
                or parent[0]['items'][0].get('Account')!=account):raise ValueError()
        identities=[r for r in meta['caller_identities'] if r.get('Account')==account]
        if len(identities)!=1 or identities[0].get('UserId')!=parent[0]['items'][0].get('UserId'):raise ValueError()
        ident=item['id'];m=item[MARKER];surface=m['surface']
        if m.get('status')=='unavailable' and m.get('complete') is False and m.get('identity')==ident:
            raise _Reason(m.get('reason') if isinstance(m.get('reason'),str) and re.fullmatch(r'[a-z][a-z_]{2,63}',m['reason'])
                          else 'selected_configuration_read_unavailable')
        if (set(m)!={'schema','kind','surface','identity','scope','account','region','partition','version','capture','principal',
                'native_complete','complete','verification','literal_count','bytes','response_bytes','engines','leaks','requests','status','selection_locator'}
                or m['schema']!=SCHEMA or m['kind']!=KIND or surface not in SURFACES or m['identity']!=ident
                or ident not in selected or m['selection_locator']!=ident or m['scope']!=scope or m['account']!=account or m['region']!=region
                or m['partition']!=('aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws')
                or m['native_complete'] is not True or type(m['complete']) is not bool or m['status']!='collected'
                or m['verification']!='not_attempted' or m['capture']!=meta[KIND+'_capture']
                or not isinstance(m['capture'],str) or not re.fullmatch('configuration-capture:[0-9a-f]{32}',m['capture'])
                or not isinstance(m['principal'],str) or not re.fullmatch('configuration-principal:[0-9a-f]{64}',m['principal'])
                or m['principal']!=meta[KIND+'_principals'][account]
                or item.get('AccountId')!=account or item.get('Region')!=region
                or item.get('_provenance')!={'scope':scope,'capture':m['capture'],'selection_locator':ident}):raise ValueError()
        if surface in ('ssm_document','launch_template_userdata','codepipeline_configuration'):
            if type(m['version']) is not int or not 1<=m['version']<=2147483647:raise ValueError()
        elif m['version'] is not None:raise ValueError()
        if (type(m['literal_count']) is not int or not 1<=m['literal_count']<=MAX_PAIRS
                or type(m['bytes']) is not int or not 1<=m['bytes']<=MAX_CONTENT or type(m['response_bytes']) is not int
                or not 1<=m['response_bytes']<=MAX_RESPONSE):raise ValueError()
        service,operation,_,_=SURFACES[surface];receipts=m['requests']
        expected=[('ssm','describe_document'),('ssm','get_document')] if surface=='ssm_document' else [(service,operation)]
        if not isinstance(receipts,list) or len(receipts)!=len(expected):raise ValueError()
        seen=set()
        for r,(service,operation) in zip(receipts,expected):
            if (not isinstance(r,dict) or set(r)!={'locator','service','operation','method','http_status','request_id'}
                    or r['service']!=service or r['operation']!=operation or r['method']!=('GET' if service in ('apigateway','amplify') else 'POST')
                    or type(r['http_status']) is not int or r['http_status']!=200 or not isinstance(r['locator'],str)
                    or not re.fullmatch('configuration-request:[0-9a-f]{64}',r['locator']) or (service,operation,r['locator']) in seen
                    or not isinstance(r['request_id'],str) or not re.fullmatch('configuration-response:[0-9a-f]{64}',r['request_id'])):raise ValueError()
            seen.add((service,operation,r['locator']))
        engines=m['engines'];versions={'kingfisher':KINGFISHER_VERSION,'trufflehog':TRUFFLEHOG_VERSION}
        if (not isinstance(engines,list) or len(engines)!=2 or any(not isinstance(e,dict) for e in engines)
                or {e.get('engine') for e in engines}!=set(versions)
                or any(set(e)!={'engine','version','status'} or e.get('version')!=versions.get(e.get('engine'))
                       or e.get('status') not in ('complete','unavailable') for e in engines)):raise ValueError()
        leaks=m['leaks']
        if (not isinstance(leaks,list) or len(leaks)>MAX_LEAKS or merge_leaks(leaks)!=leaks
                or sum(len(l['locations']) for l in leaks)>MAX_LOCATIONS
                or any(location.get('path')!=ident+'.content' for leak in leaks for location in leak['locations'])
                or any(next(e['status'] for e in engines if e['engine']==d['engine'])!='complete' for leak in leaks for d in leak['detectors'])):raise ValueError()
        complete=(m['complete'] is True and all(e['status']=='complete' for e in engines)
                  and meta[KIND+'_redaction_complete'] is True
                  and own['status']=='collected' and len(rows)==len(selected) and {r['id'] for r in rows}==set(selected))
        if not leaks and not complete:
            raise _Reason('secret_engine_unavailable' if any(e['status']!='complete' for e in engines) else
                          'selected_configuration_redaction_incomplete' if meta[KIND+'_redaction_complete'] is not True else
                          'selected_configuration_content_incomplete' if m['complete'] is not True else
                          'selected_configuration_inventory_partial')
        observed=('A likely secret was detected in the selected AWS configuration content. Its value is hidden; offline detection did not validate the credential.' if leaks else
                  'Both offline detectors completed without detecting a supported secret in the selected AWS configuration content. Coverage is limited to the returned literal values.')
        return ('FAIL' if leaks else 'PASS'),{'observed':observed,'secret_leaks':deepcopy(leaks),'credential_validation':'not_attempted',
            'complete':complete,'surface':surface,'engines':deepcopy(engines),'coverage':'selected_returned_literals_only','literal_count':m['literal_count']}
    except _Reason as reason:
        return 'UNKNOWN',{'observed':'The selected AWS configuration content was unreadable, unsupported, incomplete or unbound. Secret absence could not be assessed.',
                          'reason':str(reason)}
    except (ValueError,TypeError,KeyError,IndexError,AttributeError,OverflowError,StopIteration):
        return 'UNKNOWN',{'observed':'The selected AWS configuration content was unreadable, unsupported, incomplete or unbound. Secret absence could not be assessed.',
                          'reason':'selected_configuration_evidence_unbound'}


def install(register):
    """Explicit proposal hook; module import changes no runtime registration."""
    from . import CHECKS
    if any(c.id==CHECK for c in CHECKS):return
    d=DECLARATIONS[0]
    register(CHECK,'aws','exposure',KIND,d['title'],'high','security_configuration',d['remediation'],
             dependencies=['aws_account',KIND],allow_incomplete_failure=True)(evaluate)
