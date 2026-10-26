"""Offline two-platform ECR Public SDK and digest-bound registry transport proof."""
import io
import json
import threading
from types import SimpleNamespace

import pytest
import test_ecr_public_image as prior

archive=prior.archive;source=prior.source;consumer=prior.consumer
selection=prior.selection;index=prior.index;k8s=prior.k8s
ACCOUNT=prior.ACCOUNT;SCOPE=prior.SCOPE;ALIAS=prior.ALIAS;REPO=prior.REPO


def graph(*, hit=True, first_hit=False, second=True, attest=False):
    leaves=[prior.image(first_hit),prior.image(hit)] if second else [prior.image(first_hit)]
    if second:
        old_config_digest=archive.sha(leaves[1].config)
        leaves[1].config=leaves[1].config.replace(b'"architecture":"amd64"',b'"architecture":"arm64"')
        assert archive.sha(leaves[1].config)!=old_config_digest
        leaves[1].manifest=leaves[1].manifest.replace(old_config_digest.encode(),archive.sha(leaves[1].config).encode())
        leaves[1].digest=archive.sha(leaves[1].manifest)
    if second and first_hit == hit:
        leaves[1].manifest=leaves[1].manifest.replace(b'mode=ready',b'mode=ready2')
        leaves[1].digest=archive.sha(leaves[1].manifest)
    descriptions=[]
    for n,leaf in enumerate(leaves):
        descriptions.append({'mediaType':archive.OCI,'digest':leaf.digest,'size':len(leaf.manifest),
            'platform':{'os':'linux','architecture':'amd64' if n==0 else 'arm64'}})
    if attest:
        descriptions.append({'mediaType':archive.OCI,'digest':'sha256:'+'a'*64,'size':100,
                             'platform':{'os':'unknown','architecture':'unknown'}})
    parent=prior.wire({'schemaVersion':2,'mediaType':index.OCI_INDEX,'manifests':descriptions})
    digest=archive.sha(parent)
    target={'scope':SCOPE,'registry_alias':ALIAS,'repository_name':REPO,'image_digest':digest}
    content={digest:(parent,index.OCI_INDEX)}
    for leaf in leaves:
        content[leaf.digest]=(leaf.manifest,archive.OCI)
        content[archive.sha(leaf.config)]=(leaf.config,None)
        content[archive.sha(leaf.layer)]=(leaf.layer,None)
    return SimpleNamespace(leaves=leaves,parent=parent,digest=digest,target=target,content=content)


class SDK(prior.SDK):
    def describe_images(self,**kwargs):
        assert kwargs=={'registryId':ACCOUNT,'repositoryName':REPO,
                         'imageIds':[{'imageDigest':self.img.digest}]}
        return self.response('describe_images',{'ResponseMetadata':prior.META,'imageDetails':[{
            'registryId':ACCOUNT,'repositoryName':REPO,'imageDigest':self.img.digest,
            'imageManifestMediaType':index.OCI_INDEX,'imageSizeInBytes':sum(len(x.layer)+len(x.config) for x in self.img.leaves)}]})

class Session(prior.Session):
    def __init__(self,img,case):self.sdk=SDK(img,case)


def capture(*, hit=True, first_hit=False, case='clean', attest=False, vuln=False, vuln_hit=False,
            vuln_first_hit=False):
    img=graph(hit=hit,first_hit=first_hit,attest=attest);session=Session(img,case)
    requests=SimpleNamespace(check_deadline=lambda:None,_lock=threading.RLock(),max_calls=100,calls=0)
    responses=[];connections=[];scans=[];redacted=set()
    def open_https(host,path,headers,timeout):
        assert host==source.HOST and headers.get('Authorization') is None
        assert index.OCI_INDEX in headers['Accept'] if '/manifests/' in path else True
        category,digest=path.rsplit('/',2)[-2:]
        assert digest in img.content
        body,mime=img.content[digest]
        if case=='truncated' and digest==img.leaves[-1].digest:body=body[:-1]
        if case=='denied_child' and digest==img.leaves[-1].digest:status=403
        else:status=200
        response=prior.Response(body,status,mime)
        connection=prior.Connection();responses.append(response);connections.append(connection)
        return connection,response
    def factory(host,repository,check,authorization=None):
        assert host==source.HOST and repository==ALIAS+'/'+REPO and authorization is None
        return k8s.RegistryReader(host,repository,check,authorization=None,open_https=open_https)
    def detector(raw,path,timeout):
        scans.append(path)
        return [(prior.TOKEN,'github-pat',1)] if prior.TOKEN.encode() in raw else []
    mp=pytest.MonkeyPatch()
    mp.setattr(prior.secret_scanning,'_scan_kingfisher',detector)
    mp.setattr(prior.secret_scanning,'_scan_trufflehog',detector)
    prior.secret_scanning._RESULTS.clear()
    def trivy_runner(identity,manifest,config,layers,**kwargs):
        assert kwargs['native_verifier']()==identity
        archive.validate(identity,manifest,config,layers)
        selected=(vuln_hit and identity['manifest_digest']==img.leaves[-1].digest or
                  vuln_first_hit and identity['manifest_digest']==img.leaves[0].digest)
        diff=archive.sha(layers[0].read_bytes())
        vulnerability={'VulnerabilityID':'CVE-2026-0001','PkgName':'fixture-package',
            'InstalledVersion':'1.0','FixedVersion':'1.1','Status':'fixed','Severity':'HIGH'}
        report={'SchemaVersion':2,'ArtifactType':'container_image',
            'Metadata':{'ImageID':identity['config_digest'],'DiffIDs':[diff],
                        'RepoDigests':[identity['immutable_reference']]},
            'Results':[{'Target':'fixture-image','Class':'os-pkgs','Type':'alpine',
                        'Packages':[{'Name':'fixture-package'}],
                        'Vulnerabilities':[vulnerability] if selected else []}]}
        return prior.trivy.parse_report(prior.wire(report),0,identity,diff_ids=[diff],database={'fresh':True})
    try:
        native=source.NativeReader(requests,session,ACCOUNT)
        marker=source.inspect(img.target,native,registry_factory=factory,secret_enabled=True,
            trivy_enabled=vuln,trivy_runner=trivy_runner if vuln else None,redact_values=redacted.update)
        native.close()
    finally:
        mp.undo();prior.secret_scanning._RESULTS.clear()
    item={'id':source.identity(img.target),'ECRPublicImageContent':marker}
    meta={selection.OPTION:[img.target],selection.KIND+'_secret_authorized':True,
          selection.KIND+'_vulnerability_authorized':vuln}
    context={'context':{'provider':'aws','scope':SCOPE,'metadata':meta},
             'collections':{selection.KIND:[{'type':selection.KIND,'scope':SCOPE,'service':'ecr-public',
                'status':'collected' if marker['native_stable'] else 'partial','items':[item]}]}}
    return SimpleNamespace(img=img,marker=marker,secret=consumer.evaluate(item,context,selection.SECRET_CHECK),
        vulnerability=consumer.evaluate(item,context,selection.VULN_CHECK),
        responses=responses,connections=connections,redacted=redacted,session=session)


def test_two_supported_children_clean_and_positive():
    clean=capture(hit=False)
    assert clean.secret[0]=='PASS',clean.secret
    assert len(clean.marker['graph']['children'])==2 and clean.marker['graph']['complete']
    positive=capture(hit=True)
    assert positive.secret[0]=='FAIL',positive.secret
    assert not positive.redacted  # found values are not redacted
    assert prior.TOKEN not in json.dumps(positive.marker)
    assert all(x.closed for x in positive.responses+positive.connections)


def test_unsupported_or_denied_later_child_keeps_first_positive():
    for case in ('denied_child','truncated'):
        output=capture(hit=False,case=case)
        assert output.secret[0]=='UNKNOWN', (case,output.secret)
        positive=capture(hit=False,first_hit=True,case=case)
        assert positive.secret[0]=='FAIL',(case,positive.secret)
    unsupported=capture(hit=False,attest=True)
    assert unsupported.secret[0]=='UNKNOWN',unsupported.secret
    positive=capture(hit=False,first_hit=True,attest=True)
    assert positive.secret[0]=='FAIL',positive.secret


def test_foreign_native_alias_or_digest_drift_is_unknown():
    for case in ('foreign_alias','digest_drift'):
        output=capture(hit=False,case=case)
        assert output.secret[0]=='UNKNOWN',(case,output.secret)


def test_each_child_vulnerability_identity_is_explicit():
    output=capture(hit=False,vuln=True,vuln_hit=True)
    assert output.vulnerability[0]=='FAIL',output.vulnerability
    finding=output.vulnerability[1]['vulnerabilities'][0]
    assert finding['image_digest']==output.img.leaves[-1].digest
    scans=output.marker['child_vulnerability_scans']
    assert len(scans)==2 and all(s['schema']==prior.trivy.SCHEMA for s in scans)
    assert [s['image']['manifest_digest'] for s in scans]==[x.digest for x in output.img.leaves]
    assert output.marker['graph']['parent_digest']==output.img.digest
    clean=capture(hit=False,vuln=True,vuln_hit=False)
    assert clean.vulnerability[0]=='PASS',clean.vulnerability
    partial=capture(hit=False,case='denied_child',vuln=True,vuln_first_hit=True)
    assert partial.vulnerability[0]=='FAIL',partial.vulnerability
    assert partial.vulnerability[1]['complete'] is False
