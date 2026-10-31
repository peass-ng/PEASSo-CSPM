"""Pure unregistered bounded message-sample checks; no all-history assertion."""
from copy import deepcopy
from datetime import datetime, timezone
import re
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors import azure_selected_log_sample_secret_indicators as source

DECLARATIONS = [dict(id=p['check'],provider='azure',category='exposure',kind=p['kind'],finding_type='secrets',severity='high',
    requirements=[],dependencies=[p['kind']],allow_incomplete_failure=True,ui_group='Secrets',
    title=('Selected Log Analytics message samples have no detected secrets'if name=='workspace'else'Selected Application Insights trace samples have no detected secrets'),
    remediation='Remove credential literals from application logging, rotate confirmed exposed credentials and review retained copies. Use managed identities or supported secret references.',
    scope='Explicit selected application message samples from a fixed preceding hour only, the whole hour up to 10000 rows total (a filled budget stays UNKNOWN). No whole-history, ingestion, runtime, protected-store or credential-validation claim.')for name,p in source.PROFILES.items()]


def _evaluate(profile,item,index):
    try:
        detail=source.PROFILES[profile];kind=detail['kind'];ctx=index['context'];meta=ctx['metadata'];scope=ctx['scope']
        if (ctx['provider']!='azure'or not source.SCOPE.fullmatch(scope)or meta[kind+'_authorized']is not True
                or meta['context_binding']!='scan_local'or meta.get('tenant_verified')is not True
                or not re.fullmatch(source.GUID,meta['tenant_id'],re.I)):raise ValueError()
        capture=meta[kind+'_capture']
        if not re.fullmatch(r'log-sample-capture:[0-9a-f]{32}',capture):raise ValueError()
        selected=meta[kind+'_selection'][scope]
        if (not isinstance(selected,list)or not 1<=len(selected)<=source.MAX_TARGETS or len(set(selected))!=len(selected)
                or any(not re.fullmatch(kind+':[0-9a-f]{64}',ident)for ident in selected)):raise ValueError()
        own,=[row for row in index['collections'][kind]if row.get('scope')==scope]
        if own['status']not in('collected','partial')or own['service']!=detail['service']:raise ValueError()
        ids=[obj['id']for obj in own['items']]
        if len(set(ids))!=len(ids)or any(ident not in selected for ident in ids)or sum(obj==item for obj in own['items'])!=1:raise ValueError()
        for obj in(own,item):
            proof=obj['_provenance']
            if any(not isinstance(meta.get(k),str)or not meta[k]or proof.get(k)!=meta[k]for k in('credential_context_id','customer_context_id')):raise ValueError()
        ident=item['id'];m=item[source.MARKER]
        if (set(m)!={'schema','identity','scope','profile','table','capture','window_start','window_end','complete','query_partial','row_count','row_limit','first_row_at','last_row_at','target_binding','parts','leaks','source_requests','verification'}
                or m['schema']!=source.SCHEMA or m['identity']!=ident or m['scope']!=scope or m['profile']!=profile or m['capture']!=capture
                or m['table']not in(source.TABLES if profile=='workspace'else('traces',))or type(m['complete'])is not bool or type(m['query_partial'])is not bool
                or m['verification']!='not_attempted'or item['_provenance']['scope']!=scope or item['_provenance']['capture']!=capture
                or type(m['row_count'])is not int or type(m['row_limit'])is not int or not 1<=m['row_count']<=m['row_limit']<=source.MAX_ROWS
                or not re.fullmatch('[0-9a-f]{64}',m['target_binding'])):raise ValueError()
        window=meta[kind+'_window'];start=source.instant(m['window_start']);end=source.instant(m['window_end'])
        created=datetime.fromisoformat(ctx['created_at'].replace('Z','+00:00'))
        if (window!={'start':m['window_start'],'end':m['window_end']}or(end-start).total_seconds()!=source.WINDOW_SECONDS
                or created.tzinfo is None or not 0<=(created-end).total_seconds()<=source.MAX_SECONDS+15
                or not start<=source.instant(m['first_row_at'])<=source.instant(m['last_row_at'])<=end):raise ValueError()
        # One shared producer row budget, never a caller-supplied completeness flag.
        used=sum(obj[source.MARKER]['row_count']for k in source.KINDS for row in index['collections'].get(k,[])for obj in row['items'])
        if not 1<=used<=source.MAX_ROWS:raise ValueError()
        refs=m['source_requests'];ledger=meta[kind+'_receipts']
        if (not isinstance(refs,list)or len(refs)!=3 or len(set(refs))!=3 or item['_provenance']['source_requests']!=refs
                or not isinstance(ledger,list)or not 1<=len(ledger)<=source.MAX_CALLS or len({r['id']for r in ledger})!=len(ledger)):raise ValueError()
        for ref,operation in zip(refs,('subscription','resource','query')):
            receipt,=[r for r in ledger if r.get('id')==ref];query=operation=='query'
            if (set(receipt)!={'id','identity','scope','profile','operation','method','host','audience','request_digest','capture','status','bytes','tenant_id','identity_bound','target_binding'}
                    or not re.fullmatch(r'log-sample-read-[1-9][0-9]*',ref)or receipt['identity']!=ident or receipt['scope']!=scope
                    or receipt['profile']!=profile or receipt['operation']!=operation or receipt['method']!=('POST'if query else'GET')
                    or receipt['host']!=(detail['host']if query else'management.azure.com')or receipt['audience']!=(detail['audience']if query else source.ARM)
                    or not re.fullmatch('[0-9a-f]{64}',receipt['request_digest'])or receipt['capture']!=capture
                    or receipt['status']!=('partial'if query and m['query_partial']else'collected')or receipt['identity_bound']is not True
                    or str(receipt['tenant_id']).casefold()!=meta['tenant_id'].casefold()or type(receipt['bytes'])is not int or not 1<=receipt['bytes']<=source.MAX_WIRE
                    or receipt['target_binding']!=(None if operation=='subscription'else m['target_binding'])):raise ValueError()
        if profile=='application'and m['query_partial']:raise ValueError()
        part,=m['parts']
        if set(part)!={'bytes','engines','complete'}or type(part['bytes'])is not int or not 1<=part['bytes']<=source.MAX_CONTENT or type(part['complete'])is not bool:raise ValueError()
        versions={'kingfisher':KINGFISHER_VERSION,'trufflehog':TRUFFLEHOG_VERSION};engines=part['engines']
        if (not isinstance(engines,list)or len(engines)!=2 or {e['engine']for e in engines}!=set(versions)
                or any(set(e)!={'engine','version','status'}or e['version']!=versions[e['engine']]or e['status']not in('complete','unavailable')for e in engines)
                or part['complete']!=all(e['status']=='complete'for e in engines)):raise ValueError()
        leaks=m['leaks'];trusted={e['engine']for e in engines if e['status']=='complete'}
        if (not isinstance(leaks,list)or merge_leaks(leaks)!=leaks or len(leaks)>source.MAX_LEAKS or sum(len(l['locations'])for l in leaks)>source.MAX_LOCATIONS
                or any(not re.fullmatch('[0-9a-f]{64}',l['fingerprint'])or not l['detectors']or not l['locations']
                    or any(d['engine']not in trusted for d in l['detectors'])or any(loc['path']!=ident+'.sample_messages'for loc in l['locations'])for l in leaks)):raise ValueError()
        complete=bool(m['complete']and not m['query_partial']and part['complete']and own['status']=='collected'and set(ids)==set(selected)
            and all(obj.get(source.MARKER,{}).get('complete')is True for obj in own['items']))
        if not leaks and not complete:raise ValueError()
        observed=('A likely secret was detected in the selected message sample. Its value is hidden and was not validated.'if leaks else
            'Both offline detectors completed without detecting a supported secret in the selected message sample. This result covers only the returned sample from the fixed preceding hour.')
        if not complete:observed+=' Sample inspection is incomplete.'
        return('FAIL'if leaks else'PASS'),{'observed':observed,'secret_leaks':deepcopy(leaks),'complete':complete,'coverage':'selected_message_sample_only'if complete else'incomplete_selected_message_sample',
            'window':deepcopy(window),'row_count':m['row_count'],'row_limit':m['row_limit'],'table':m['table'],'first_row_at':m['first_row_at'],'last_row_at':m['last_row_at'],
            'credential_validation':'not_attempted','whole_history_covered':False,'parts':deepcopy(m['parts'])}
    except(KeyError,TypeError,ValueError,AttributeError,IndexError):
        return'UNKNOWN',{'complete':False,'coverage':'incomplete_selected_message_sample','whole_history_covered':False,
            'observed':'The selected message sample was unavailable, empty, unbound or incompletely inspected. A clean sample result cannot be established.'}


def workspace(item,index):return _evaluate('workspace',item,index)
def application(item,index):return _evaluate('application',item,index)
EVALUATORS={'workspace':workspace,'application':application}
