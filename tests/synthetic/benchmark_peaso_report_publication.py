"""Complete report publication through the real hosted adapter and publisher.

python -m tests.synthetic.benchmark_peaso_report_publication --findings 10000 --latency-ms 20
S3 PUT latency is simulated. Native catalog initialization is outside timing.
"""
import argparse
import gc
import json
from pathlib import Path
import statistics
import sys
import time
import tracemalloc

from tests.synthetic.benchmark_peaso_publication import SimulatedS3,content_digest,synthetic_report
from tests.synthetic.reference_peaso_publication import original_publisher
from peaso.storage.artifacts import S3Artifacts
from peaso.storage.reports import publish_report
from peaso.snapshot import digest,make_snapshot,resources


def fixture(count,compact):
    report=synthetic_report(count)
    snapshot=None
    if compact:
        from peaso.engine import REPORT_SCHEMA_VERSION
        scope='projects/benchmark'
        snapshot=make_snapshot('gcp',[scope],[{'type':'instance','scope':scope,'status':'collected',
            'items':[{'name':f'resource-{i}','recorded_configuration':{'ordinal':i,'labels':{'app':'native'}}}
                for i in range(count)]}],created_at='2026-01-01T00:00:00+00:00')
        inventory=resources(snapshot)
        report.update(schema_version=REPORT_SCHEMA_VERSION,snapshot_id=snapshot['snapshot_id'],
            resources=[{key:value for key,value in row.items() if key!='data'} for row in inventory])
        for finding,row in zip(report['findings'],inventory):
            finding['resource_id']=row['id']
        for node,row in zip(report['graphs']['iam']['nodes'],inventory):
            node['evidence']={'native_resource_ref':row['id']}
    return report,snapshot


def compare(findings=10000,latency_ms=20,*,compact=False,memory=False):
    if findings<1 or latency_ms<0:
        raise ValueError('positive finding count and nonnegative latency required')
    # A completed scan has already initialized this catalog. Warm the actual
    # implementation rather than substituting metadata or admission guards.
    from peaso.checks.catalog import framework_catalog
    framework_catalog()
    report,snapshot=fixture(findings,compact)
    before=digest(report),digest(snapshot)
    variants=(('baseline',original_publisher()),('optimized',publish_report))
    results={name:{'seconds':[],'cpu_seconds':[],'digests':[]} for name,_ in variants}
    for iteration in range(3):
        for name,publisher in variants if iteration%2==0 else variants[::-1]:
            client=SimulatedS3(latency_ms/1000)
            store=S3Artifacts('private',client=client,kms_key='synthetic-key')
            gc.collect()
            start,cpu=time.perf_counter(),time.process_time()
            reference=publisher(store,'benchmark','a'*32,report,snapshot)
            results[name]['seconds'].append(time.perf_counter()-start)
            results[name]['cpu_seconds'].append(time.process_time()-cpu)
            print(name, iteration+1, 'findings', findings, 'compact', compact,
                'seconds', round(results[name]['seconds'][-1],3),
                'cpu', round(results[name]['cpu_seconds'][-1],3), file=sys.stderr, flush=True)
            assert list(client.objects)[-1]=='artifacts/'+reference
            assert all(request['ServerSideEncryption']=='aws:kms' and request['SSEKMSKeyId']=='synthetic-key'
                for request in client.objects.values())
            results[name]['digests'].append(content_digest(client.objects))
            results[name]['objects']=len(client.objects)
            results[name]['peak_uploads']=client.peak
            del client,store
    if memory:
        for name,publisher in variants:
            client=SimulatedS3(latency_ms/1000)
            store=S3Artifacts('private',client=client,kms_key='synthetic-key')
            gc.collect()
            tracemalloc.start()
            publisher(store,'benchmark','a'*32,report,snapshot)
            results[name]['peak_allocated_bytes']=tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
            assert content_digest(client.objects)==results[name]['digests'][0]
            del client,store
    for result in results.values():
        fingerprints=result.pop('digests')
        assert len(set(fingerprints))==1
        result['content_digest']=fingerprints[0]
    assert results['baseline']['content_digest']==results['optimized']['content_digest']
    assert (digest(report),digest(snapshot))==before
    return {**results,'findings':findings,'compact_report':compact,'simulated_put_latency_ms':latency_ms,
        'identical_artifact_contents':True,'input_unchanged':True,
        'speedup':round(statistics.median(results['baseline']['seconds'])/statistics.median(results['optimized']['seconds']),2),
        'cpu_speedup':round(statistics.median(results['baseline']['cpu_seconds'])/statistics.median(results['optimized']['cpu_seconds']),2),
        'limitations':'Complete actual publication includes sanitization, reviews, grouping, Markdown generation, '
            'native expansion when compact, indexes, compression and all artifact writes. Catalog initialization '
            'and fixture setup are excluded. S3 PUT delay is simulated; no cloud calls occur. Content digests '
            'normalize generated references only. Optional peaks include the in-memory simulated store and are not process RSS.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--findings',type=int,default=10000)
    parser.add_argument('--latency-ms',type=float,default=20)
    parser.add_argument('--compact',action='store_true')
    parser.add_argument('--memory',action='store_true')
    args=parser.parse_args()
    print(json.dumps(compare(args.findings,args.latency_ms,compact=args.compact,memory=args.memory),indent=2))
