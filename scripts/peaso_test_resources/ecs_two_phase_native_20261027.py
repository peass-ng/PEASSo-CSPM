"""Network-free canonical current SDK/detector parity against exact retained baseline.
"""
import copy,hashlib,importlib.util,json,resource,sys,time
from pathlib import Path
import boto3
from botocore.awsrequest import AWSResponse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from peaso import secret_scanning as scanner,secret_scanning_batch as batch,secret_scan_clean as clean,secret_evidence as evidence
from peaso.collectors import aws,aws_selected_configuration_secret_indicators as canonical
P=Path('/review');A='123456789012';R='us-east-1';S=A+'/'+R
CALLER={'Account':A,'Arn':f'arn:aws:iam::{A}:user/fixture','UserId':'fixture'}
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,P/path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
import peaso.checks
ROOT=Path(__file__).resolve().parents[2]
assert len(peaso.checks.CHECKS)==4179
# Comparison baseline: the retained pre-two-phase module kept with the tests.
_spec=importlib.util.spec_from_file_location('peaso.collectors._ecs_phase_retained_baseline',
    ROOT/'tests/ecs_selected_configuration_retained_baseline_20261027.py')
baseline=importlib.util.module_from_spec(_spec)
sys.modules[baseline.__name__]=baseline
_spec.loader.exec_module(baseline)
candidate=canonical
key=rsa.generate_private_key(public_exponent=65537,key_size=2048).private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()
scanner._trufflehog();scanner._kingfisher()
assert scanner.scan_content(b'mode=ordinary','warmup',timeout=60)['complete']
assert scanner.scan_content(key.encode(),'warmup',timeout=60)['complete']
HMAC=scanner._KEY

def clear():
    with scanner._RESULT_LOCK:scanner._RESULTS.clear()
    with clean._LOCK:clean._CLEAN.clear()

def normalize(v):
    if isinstance(v,dict):return{k:normalize(x)for k,x in v.items()}
    if isinstance(v,list):return sorted([normalize(x)for x in v],key=lambda x:json.dumps(x,sort_keys=True))
    return v

def measure(module,positive):
    clear();targets=[{'surface':'ecs_environment','scope':S,'resource_id':f'arn:aws:ecs:{R}:{A}:task-definition/fixture-{i}:1'}for i in range(16)]
    options={'workers':8,'content_secret_scans':True,'_content_secret_scan_kinds':[module.KIND],module.OPTION:targets}
    requests=aws.Requests(options);requests.content_secret_scan_kinds=frozenset({module.KIND})
    module.initialize(requests,options,[S]);requests.configuration_content_metadata[module.KIND+'_capture']='configuration-capture:'+'a'*32
    session=boto3.Session(aws_access_key_id='offline-fixture',aws_secret_access_key='offline-fixture',region_name=R)
    native_calls=[]
    def stub(model,params,**kwargs):
        args=json.loads(params['body']);arn=args['taskDefinition'];i=int(arn.split('fixture-')[1].split(':')[0]);native_calls.append(i)
        text=key if positive and i%2 else f'ordinary-{i}'
        response={'taskDefinition':{'taskDefinitionArn':arn,'family':'fixture-'+str(i),'revision':1,'status':'ACTIVE','containerDefinitions':[{'name':'app','environment':[{'name':'MODE','value':text}]}]},'ResponseMetadata':{'HTTPStatusCode':200,'RequestId':'fixture-request-'+str(i)}}
        return AWSResponse('https://ecs.us-east-1.amazonaws.com',200,{},None),response
    session.events.register('before-call.ecs.DescribeTaskDefinition',stub)
    # Actual Requests authority/client/profile/cache; only the comparison arm
    # temporarily binds its exact retained projector. Current arm is canonical.
    old=canonical.project_response;canonical.project_response=module.project_response
    original=batch._prepare_trufflehog_batch;groups=[]
    def counted(items,timeout):groups.append(len(items));return original(items,timeout)
    batch._prepare_trufflehog_batch=counted
    cipher=evidence.EphemeralCipher();start=time.monotonic();before=resource.getrusage(resource.RUSAGE_CHILDREN);pc=time.process_time()
    try:
        with evidence.capture(cipher,tenant='fixture',scan_id='a'*32)as sink:
            result=module.collect_selected(requests,session,R,CALLER,options,[S])
        private=[cipher.decrypt(v)for _,v in sorted(sink.records.items())]
    finally:canonical.project_response=old;batch._prepare_trufflehog_batch=original
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    assert len(result.items)==16 and sorted(native_calls)==list(range(16))
    assert all(row[module.MARKER]['complete']for row in result.items)
    count=sum(bool(row[module.MARKER]['leaks'])for row in result.items)
    assert count==(8 if positive else 0)
    if positive:assert private
    assert scanner._KEY==HMAC
    # Native response bodies must never survive in a cached projected Future.
    cache=[f.result()for f in requests._cache.values()if f.done()and f.exception()is None]
    assert 'containerDefinitions'not in json.dumps(cache)and 'BEGIN PRIVATE KEY'not in json.dumps(cache)
    for row in result.items:
        assert any(v.get('id')==row['id']and v[module.MARKER]==row[module.MARKER]for v in cache)
    return {'wall_seconds':round(time.monotonic()-start,6),'parent_cpu_seconds':round(time.process_time()-pc,6),'child_cpu_seconds':round(after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,6),'native_calls':len(native_calls),'native_call_set_sha256':hashlib.sha256(json.dumps(sorted(native_calls)).encode()).hexdigest(),'response_counters':{k:v for k,v in requests.configuration_content_state.items()if k!='deadline'},'raw_preparation_groups':groups,'positive_sources':count,'private_records':len(private),'public_sha256':hashlib.sha256(json.dumps(result.items,sort_keys=True).encode()).hexdigest(),'private_sha256':hashlib.sha256(json.dumps(normalize(private),sort_keys=True).encode()).hexdigest()}
results=[]
for name,pos in [('allunique_clean',False),('mixed_rsa',True)]:
    a=measure(baseline,pos);b=measure(candidate,pos)
    assert a['public_sha256']==b['public_sha256']and a['private_sha256']==b['private_sha256']
    assert a['response_counters']==b['response_counters']
    results.append({'case':name,'memo_state':'cold_both','baseline':a,'candidate':b})
    print(json.dumps({'completed_case':results[-1]},sort_keys=True),flush=True)
print(json.dumps({'results':results,'real_detectors':True,'private_capture_stubs':False,'actual_requests_profile_and_native_client':True,'network':'none','candidate_is_canonical_module':True,'baseline_is_retained_comparison':True,'pinned_TH':scanner.TRUFFLEHOG_VERSION},sort_keys=True))
