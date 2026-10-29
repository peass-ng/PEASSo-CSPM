"""Offline Filestore list-stage comparison; no credentials or provider calls.

Run each arm in its own process. The before arm loads exactly scope_jobs from
committed eb7e9e55; all helpers are the current unchanged helpers. Two inventory
workers and eight location workers consume 48 native rows over two pages per
wildcard inventory at 10ms simulated latency per request. This measures only
the two list factories, excluding collector startup and snapshot publication.
"""
import sys,time,resource,json,hashlib,pathlib,ast,subprocess,textwrap
from concurrent.futures import ThreadPoolExecutor
ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
if len(sys.argv)!=2 or sys.argv[1] not in ('before','after'):
    raise SystemExit('usage: python docs/multicloud-test/bench_filestore_all_locations.py before|after')
from tests.test_peaso_collectors_gcp import FixtureTransport,connector
from peaso.collectors import gcp
locations=[f'us-test{i}-a' for i in range(24)]+[f'europe-test{i}' for i in range(24)]
def rows(key):
    chosen=locations[:24] if key=='instances' else locations[24:]
    return [dict(name=f'projects/p-one/locations/{loc}/{key}/item{i}', state='READY', network='projects/p-one/global/networks/test') for i,loc in enumerate(chosen)]
def resolve(r):
    time.sleep(.01)
    if r['url'].endswith('/locations'):
        return {'locations':[{'locationId':loc} for loc in locations]}
    key=r['url'].rsplit('/',1)[-1];loc=r['url'].split('/locations/')[1].split('/')[0]
    items=rows(key)
    if loc=='-':
        second=bool(r.get('params',{}).get('pageToken'))
        return {key:items[12:] if second else items[:12],**({} if second else {'nextPageToken':'second'})}
    return {key:[item for item in items if '/locations/'+loc+'/' in item['name']]}
if sys.argv[1]=='before':
    old=subprocess.check_output(['git','show','eb7e9e552ff1e321c69c55068729c9452cff5898:peaso/collectors/gcp.py'],cwd=ROOT,text=True)
    cls=next(n for n in ast.parse(old).body if isinstance(n,ast.ClassDef) and n.name=='GCPCollector')
    fn=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='scope_jobs')
    source=textwrap.dedent('\n'.join(old.splitlines()[fn.lineno-1:fn.end_lineno]))
    ns=dict(vars(gcp));exec(compile(source,'historical-scope-jobs','exec'),ns)
    gcp.GCPCollector.scope_jobs=ns['scope_jobs']
transport=FixtureTransport(resolve)
c=gcp.GCPCollector(connector(['filestore_instance','filestore_backup'],concurrency=8),transport=transport)
with ThreadPoolExecutor(max_workers=8,thread_name_prefix='gcp-location') as locations_pool, ThreadPoolExecutor(max_workers=2) as jobs_pool:
    c.location_pool=locations_pool
    jobs=[job for job in c.scope_jobs('projects/p-one') if job[0] in ('filestore_instance','filestore_backup')]
    assert len(jobs)==2
    def consume(job):
        items=[row for page,_ in job[3]() for row in page]
        return {'type':job[0],'status':'collected' if items else 'empty','items':sorted(items,key=lambda row:row['name'])}
    a=time.perf_counter();cpu=time.process_time()
    content=sorted(jobs_pool.map(consume,jobs),key=lambda row:row['type'])
    wall=time.perf_counter()-a;cpu=time.process_time()-cpu
report={'stage':'two Filestore list factories only','wall_s':wall,'cpu_s':cpu,'peak_rss_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*(1 if sys.platform=='darwin' else 1024),'calls':len(transport.requests),'items':sum(len(row['items']) for row in content),'statuses':[row['status'] for row in content],'content_sha256':hashlib.sha256(json.dumps(content,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'simulated_latency_s':.01,'regions_and_zones':48,'live_provider_calls':0,'model_calls':0,'location_workers':8,'inventory_workers':2,'before_commit':'eb7e9e552ff1e321c69c55068729c9452cff5898'}
print(json.dumps(report,sort_keys=True))
