"""Offline BackupDR list-stage benchmark; no credentials or provider requests.

Run before|after in separate processes. Before loads the exact catalog helper
from public f617504f. All48 locations (including eu/us) and144 native rows remain;
management-server IAM reads continue against each concrete regional endpoint.
"""
import sys,pathlib,json,time,resource,hashlib,subprocess
from concurrent.futures import ThreadPoolExecutor
ROOT=pathlib.Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from peaso.collectors import gcp
from peaso.collectors import gcp_network_catalog as catalog
from tests.test_peaso_collectors_gcp import NativeDataFixtureTransport,connector
if len(sys.argv)!=2 or sys.argv[1] not in ('before','after'):
    raise SystemExit('usage: python docs/multicloud-test/bench_gcp_backupdr_all_locations.py before|after')
if sys.argv[1]=='before':
    source=subprocess.check_output(['git','show','f617504f7015da4210d87da8dad18431c6314440:peaso/collectors/gcp_network_catalog.py'],cwd=ROOT)
    exec(compile(source,catalog.__file__,'exec'),catalog.__dict__)
KINDS=['backupdr_backup_plan','backupdr_backup_plan_association','backupdr_management_server']
LOCATIONS=['eu','us']+[f'test-region{i}' for i in range(46)]
SEGMENTS={catalog.PRIVATE_SERVICES[kind]['segment'] for kind in KINDS}
def native_rows(segment):
    return [dict(name=f'projects/p-one/locations/{loc}/{segment}/item',state='ACTIVE',
                 nativeField={'keep':loc},networks=[{'network':'projects/p-one/global/networks/test'}]) for loc in LOCATIONS]
def resolve(request):
    time.sleep(.01)
    if request['url'].endswith('/locations'):
        return {'locations':[{'locationId':loc} for loc in LOCATIONS]}
    if ':getIamPolicy' in request['url']:
        return {'version':3,'bindings':[{'role':'roles/backupdr.viewer','members':['domain:example.invalid']}]}
    segment=request['url'].rsplit('/',1)[-1];assert segment in SEGMENTS
    location=request['url'].split('/locations/')[1].split('/')[0];rows=native_rows(segment)
    if location=='-':
        offset=int(request.get('params',{}).get('pageToken','0'))
        return {segment:rows[offset:offset+12],**({'nextPageToken':str(offset+12)} if offset+12<len(rows) else {})}
    return {segment:[row for row in rows if '/locations/'+location+'/' in row['name']]}
transport=NativeDataFixtureTransport(resolve)
reader=gcp.GCPCollector(connector(KINDS,concurrency=8,hydration_concurrency=8),transport=transport)
def normalized(value,path=()):
    if isinstance(value,dict):
        return {k:normalized(v,path+(k,)) for k,v in value.items() if not
                (('_provenance' in path or '_coverage' in path) and k in
                 {'collected_at','credential_context_id','customer_context_id','source_requests'})}
    if isinstance(value,list):return [normalized(v,path+('*',)) for v in value]
    return value
try:
    jobs=[job for job in reader.scope_jobs('projects/p-one') if job[0] in KINDS]
    a=time.perf_counter();cpu=time.process_time()
    with ThreadPoolExecutor(max_workers=3) as pool:
        rows=list(pool.map(lambda job:reader.envelope(*job),jobs))
    wall=time.perf_counter()-a;cpu=time.process_time()-cpu
finally:
    reader.hydration_pool.shutdown(wait=True)
    if reader.location_pool is not None:reader.location_pool.shutdown(wait=True)
content=[{'type':row['type'],'status':row['status'],'items':sorted(normalized(row['items']),key=lambda v:v['name'])} for row in sorted(rows,key=lambda v:v['type'])]
report={'mode':sys.argv[1],'stage':'three BackupDR list factories and IAM hydration','wall_s':wall,'cpu_s':cpu,
        'process_peak_rss_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*(1 if sys.platform=='darwin' else 1024),
        'calls':len(transport.requests),'resources':sum(len(row['items']) for row in rows),'collections':len(rows),
        'statuses':[row['status'] for row in rows],'native_content_sha256':hashlib.sha256(json.dumps(content,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        'regions_including_multi_regions':48,'simulated_request_latency_s':.01,'inventory_workers':3,'location_workers':8,'hydration_workers':8,
        'provider_network_calls':0,'model_calls':0}
print(json.dumps(report,sort_keys=True))
