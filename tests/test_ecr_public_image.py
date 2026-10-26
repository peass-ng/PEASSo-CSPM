"""Offline SDK-shaped ECR Public + real bounded OCI reader -> typed consumers."""
import importlib.util
import io
import json
from pathlib import Path
import socket
import sys
import tarfile
import threading
from types import SimpleNamespace

import pytest

HERE=Path(__file__).resolve().parents[1]
from peaso import container_image_archive_20261020 as archive
from peaso import oci_index_20261021 as index
from peaso import secret_scanning, trivy_container_runner_20261020 as trivy
from tests.pinned_secret_scanners import require_pinned_scanners
from peaso import aws_ecr_public_selection_20261021 as selection
from peaso.collectors import k8s_selected_registry_image_20261021 as k8s
from peaso.collectors import aws_ecr_public_image_native_20261021 as source
from peaso.collectors import aws_ecr_public_image_runtime_20261021 as runtime
from peaso.checks import aws_ecr_public_image_review_20261021 as consumer
ACCOUNT='123456789012';SCOPE=ACCOUNT+'/us-east-1';ALIAS='fixture-alias';REPO='fixture/image'
TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
META={'HTTPStatusCode':200}


def wire(value):return json.dumps(value,separators=(',',':')).encode()


def image(hit=False,escaped_config=False):
    data=('TOKEN='+TOKEN+'\n' if hit else 'MODE=ready\n').encode()
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT) as tar:
        member=tarfile.TarInfo('etc/source.env');member.size=len(data);tar.addfile(member,io.BytesIO(data))
    layer=stream.getvalue()
    config=wire({'os':'linux','architecture':'amd64','rootfs':{'type':'layers','diff_ids':[archive.sha(layer)]},
                 'config':{'Env':['PRIVATE='+TOKEN if escaped_config else 'MODE=ready']}})
    if escaped_config:config=config.replace(b'ghp_',b'\\u0067hp_')
    manifest=wire({'schemaVersion':2,'mediaType':archive.OCI,
        'annotations':{'fixture':TOKEN if hit else 'mode=ready'},
        'config':{'mediaType':next(t for t in archive.CONFIGS if 'oci' in t),'size':len(config),'digest':archive.sha(config)},
        'layers':[{'mediaType':'application/vnd.oci.image.layer.v1.tar','size':len(layer),'digest':archive.sha(layer)}]})
    digest=archive.sha(manifest)
    return SimpleNamespace(manifest=manifest,config=config,layer=layer,digest=digest,
        target={'scope':SCOPE,'registry_alias':ALIAS,'repository_name':REPO,'image_digest':digest})


class SDK:
    def __init__(self,img,case):self.img,self.case,self.calls=img,case,[];self.closed=False
    def response(self,operation,value):
        self.calls.append(operation)
        if self.case=='denied_native' and len(self.calls)>3:raise RuntimeError('denied')
        if self.case=='foreign_account' and operation=='describe_registries':value['registries'][0]['registryId']='999999999999'
        if self.case=='foreign_alias' and operation=='describe_registries':value['registries'][0]['aliases'][0]['name']='foreign-alias'
        if self.case=='foreign_repo' and operation=='describe_repositories':value['repositories'][0]['registryId']='999999999999'
        if self.case=='digest_drift' and len(self.calls)>3 and operation=='describe_images':value['imageDetails'][0]['imageDigest']='sha256:'+'0'*64
        return value
    def describe_registries(self):
        return self.response('describe_registries',{'ResponseMetadata':META,'registries':[{
            'registryId':ACCOUNT,'registryArn':f'arn:aws:ecr-public::{ACCOUNT}:registry/{ACCOUNT}',
            'registryUri':f'public.ecr.aws/{ALIAS}',
            'aliases':[{'name':ALIAS,'status':'ACTIVE','primaryRegistryAlias':True,'defaultRegistryAlias':True}]}]})
    def describe_repositories(self,**kwargs):
        assert kwargs=={'registryId':ACCOUNT,'repositoryNames':[REPO]}
        return self.response('describe_repositories',{'ResponseMetadata':META,'repositories':[{
            'registryId':ACCOUNT,'repositoryName':REPO,'repositoryArn':f'arn:aws:ecr-public::{ACCOUNT}:repository/{REPO}',
            'repositoryUri':f'public.ecr.aws/{ALIAS}/{REPO}'}]})
    def describe_images(self,**kwargs):
        assert kwargs=={'registryId':ACCOUNT,'repositoryName':REPO,'imageIds':[{'imageDigest':self.img.digest}]}
        return self.response('describe_images',{'ResponseMetadata':META,'imageDetails':[{
            'registryId':ACCOUNT,'repositoryName':REPO,'imageDigest':self.img.digest,
            'imageManifestMediaType':archive.OCI,'imageSizeInBytes':len(self.img.layer)+len(self.img.config)}]})
    def close(self):self.closed=True


class Session:
    def __init__(self,img,case):self.sdk=SDK(img,case)
    def client(self,service,*,region_name,config):
        assert service=='ecr-public' and region_name=='us-east-1'
        assert config.retries['total_max_attempts']==1 and config.ignore_configured_endpoint_urls
        return self.sdk


class Response:
    def __init__(self,body,status=200,mime=None):
        self.status=status;self.closed=False;self.stream=io.BytesIO(body)
        self.headers={'Content-Length':str(len(body)),'Content-Type':mime or 'application/octet-stream','Docker-Content-Digest':archive.sha(body)}
    def read(self,n):return self.stream.read(n)
    def close(self):self.closed=True


class Connection:
    def __init__(self):self.closed=False
    def close(self):self.closed=True


def trivy_runner(positive=False,fresh=True,complete=True):
    def run(identity,manifest,config,layers,**kwargs):
        assert kwargs['native_verifier']()==identity
        archive.validate(identity,manifest,config,layers)
        diff=archive.sha(layers[0].read_bytes())
        vulnerability={'VulnerabilityID':'CVE-2026-12345','PkgName':'fixture-package','InstalledVersion':'1.0',
            'FixedVersion':'1.1','Status':'fixed','Severity':'HIGH'}
        report={'SchemaVersion':2,'ArtifactType':'container_image',
            'Metadata':{'ImageID':identity['config_digest'],'DiffIDs':[diff],
                        'RepoDigests':[identity['immutable_reference']]},
            'Results':[{'Target':'fixture-image','Class':'os-pkgs','Type':'alpine',
                        'Packages':[{'Name':'fixture-package'}],
                        'Vulnerabilities':[vulnerability] if positive else []}]}
        result=trivy.parse_report(wire(report),0,identity,diff_ids=[diff],database={'fresh':fresh})
        if not complete:result['scan_complete']=False;result['complete']=False
        return result
    return run


def capture(*,hit=False,case='clean',vuln=False,vuln_hit=False,vuln_fresh=True,engine_missing=False,
            escaped_config=False,
            real_detectors=False):
    img=image(hit,escaped_config);session=Session(img,case)
    request=SimpleNamespace(check_deadline=lambda:None,_lock=threading.RLock(),max_calls=80,calls=0)
    responses=[];connections=[];scans=[];redacted=set()
    def open_https(host,path,headers,timeout):
        assert host==source.HOST and headers.get('Authorization') is None
        assert 0<timeout<=10 and path.startswith('/v2/'+ALIAS+'/'+REPO+'/')
        category,digest=path.rsplit('/',2)[-2:]
        if category=='manifests':body=img.manifest;mime=archive.OCI
        else:body={archive.sha(img.config):img.config,archive.sha(img.layer):img.layer}[digest];mime=None
        status=403 if case=='denied_registry' else 200
        response=Response(body,status,mime);connection=Connection()
        responses.append(response);connections.append(connection)
        return connection,response
    def factory(host,repository,check,authorization=None):
        assert host==source.HOST and repository==ALIAS+'/'+REPO and authorization is None
        return k8s.RegistryReader(host,repository,check,authorization=None,open_https=open_https)
    def detector(raw,path,timeout):
        scans.append(path)
        return [(TOKEN,'github-pat',1)] if TOKEN.encode() in raw else []
    from pytest import MonkeyPatch
    mp=MonkeyPatch()
    if not real_detectors:
        mp.setattr(secret_scanning,'_scan_kingfisher',detector)
        if engine_missing:
            def unavailable(*args):raise RuntimeError('offline engine unavailable')
            mp.setattr(secret_scanning,'_scan_trufflehog',unavailable)
        else:
            mp.setattr(secret_scanning,'_scan_trufflehog',detector)
    secret_scanning._RESULTS.clear()
    try:
        native=source.NativeReader(request,session,ACCOUNT)
        marker=source.inspect(img.target,native,registry_factory=factory,
            secret_enabled=True,trivy_enabled=vuln,trivy_runner=trivy_runner(vuln_hit,vuln_fresh) if vuln else None,
            redact_values=redacted.update)
        native.close()
    finally:
        mp.undo();secret_scanning._RESULTS.clear()
    item={'id':source.identity(img.target),'ECRPublicImageContent':marker}
    meta={selection.OPTION:[img.target],selection.KIND+'_secret_authorized':True,
          selection.KIND+'_vulnerability_authorized':vuln}
    index={'context':{'provider':'aws','scope':SCOPE,'metadata':meta},
           'collections':{selection.KIND:[{'type':selection.KIND,'scope':SCOPE,'service':'ecr-public',
               'status':'collected' if marker['native_stable'] else 'partial','items':[item]}]}}
    return SimpleNamespace(item=item,index=index,secret=consumer.evaluate(item,index,selection.SECRET_CHECK),
        vuln=consumer.evaluate(item,index,selection.VULN_CHECK),sdk=session.sdk,responses=responses,
        connections=connections,scans=scans,redacted=redacted,img=img)


@pytest.mark.parametrize('hit',[False,True])
def test_native_secret_positive_clean(hit):
    case=capture(hit=hit)
    assert case.secret[0]==('FAIL' if hit else 'PASS'),case.secret
    assert len(case.sdk.calls)==6 and case.sdk.closed
    assert all(r.closed for r in case.responses) and all(c.closed for c in case.connections)
    assert TOKEN not in json.dumps([case.item,case.index,case.secret])
    # Found values stay visible: nothing is queued for redaction.
    if hit:assert not case.redacted and {d['engine'] for d in case.item['ECRPublicImageContent']['leaks'][0]['detectors']}=={'kingfisher','trufflehog'}


@pytest.mark.parametrize('hit',[False,True])
def test_real_pinned_offline_detectors(hit):
    require_pinned_scanners()
    case=capture(hit=hit,real_detectors=True)
    assert case.secret[0]==('FAIL' if hit else 'PASS'),case.secret


@pytest.mark.parametrize('hit',[False,True])
def test_one_detector_unavailable_keeps_positive_only(hit):
    case=capture(hit=hit,engine_missing=True)
    assert case.secret[0]==('FAIL' if hit else 'UNKNOWN'),case.secret


def test_decoded_config_string_detected_when_json_escaped():
    case=capture(escaped_config=True)
    assert case.secret[0]=='FAIL' and not case.redacted  # found values are not redacted
    assert TOKEN.encode() not in case.img.config
    assert TOKEN not in json.dumps([case.item,case.index,case.secret])


@pytest.mark.parametrize('case',['foreign_account','foreign_alias','foreign_repo','digest_drift','denied_native','denied_registry'])
@pytest.mark.parametrize('hit',[False,True])
def test_foreign_denied_drift_never_clean(case,hit):
    result=capture(hit=hit,case=case)
    expected='FAIL' if hit and case in ('digest_drift','denied_native') else 'UNKNOWN'
    assert result.secret[0]==expected,(case,hit,result.secret)
    assert TOKEN not in json.dumps([result.item,result.index,result.secret])


@pytest.mark.parametrize('positive',[False,True])
@pytest.mark.parametrize('fresh',[False,True])
def test_trivy_typed_freshness(positive,fresh):
    result=capture(vuln=True,vuln_hit=positive,vuln_fresh=fresh)
    assert result.vuln[0]==('FAIL' if positive else 'PASS' if fresh else 'UNKNOWN'),result.vuln


def test_default_off_and_invalid_selector_zero_io():
    options={selection.OPTION:[{'scope':SCOPE,'registry_alias':ALIAS,'repository_name':REPO,
                               'image_digest':'sha256:'+'a'*64}]}
    runtime.issue_engine_grant(options,[SCOPE],[])
    assert runtime.GRANT not in options and runtime.authorize_collector(options,[SCOPE])==([],False,False)
    assert selection.selected_targets(options,[SCOPE,ACCOUNT+'/us-west-2'])==options[selection.OPTION]
    for change in ({'registry_alias':'foreign/alias'},{'scope':'999999999999/us-east-1'},
                   {'image_digest':'latest'},{'repository_name':'../evil'}):
        bad={**options,selection.OPTION:[{**options[selection.OPTION][0],**change}]}
        with pytest.raises(ValueError):selection.selected_targets(bad,[SCOPE])


def test_pure_server_preflight_accepts_exact_digest_and_rejects_foreign():
    from peaso.server import validation as api
    options={selection.OPTION:[image().target],'content_secret_scans':True}
    api.validate_connector('aws',{},options,SimpleNamespace(auth_mode='local'),scopes=[SCOPE])
    wrong={selection.OPTION:[{**image().target,'registry_alias':'other/alias'}]}
    with pytest.raises(Exception) as exc:
        api.validate_connector('aws',{},wrong,SimpleNamespace(auth_mode='local'),scopes=[SCOPE])
    assert getattr(exc.value,'status_code',None)==422


def test_native_capture_cases():
    cases={}
    for check_id in (selection.SECRET_CHECK,selection.VULN_CHECK):
        is_vuln=check_id==selection.VULN_CHECK
        p=capture(vuln=is_vuln)
        f=capture(hit=not is_vuln,vuln=is_vuln,vuln_hit=is_vuln)
        u=capture(case='digest_drift',vuln=is_vuln)
        missing={'context':p.index['context'],'collections':{selection.KIND:[{
            'type':selection.KIND,'scope':SCOPE,'service':'ecr-public','status':'partial','items':[]}]}}
        pairs={'pass':p,'fail':f,'unknown':u}
        cases[check_id]={key:result.item for key,result in pairs.items()}
        cases[check_id].update({key+'_index':result.index for key,result in pairs.items()})
        cases[check_id]['missing']={};cases[check_id]['missing_index']=missing
        assert [consumer.evaluate(cases[check_id][key],cases[check_id][key+'_index'],check_id)[0]
                for key in ('pass','fail','unknown')]==['PASS','FAIL','UNKNOWN']
    assert set(cases)=={selection.SECRET_CHECK,selection.VULN_CHECK}
    for check_id,group in cases.items():
        assert consumer.evaluate(group['missing'],group['missing_index'],check_id)[0]=='UNKNOWN'
    assert TOKEN not in json.dumps(cases)
