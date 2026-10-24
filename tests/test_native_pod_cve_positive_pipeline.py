"""Real native OCI/Pod/ARM consumers to private image artifact and UI data rows.

Only provider HTTPS transport and Trivy process output are offline substitutes.
The actual native collector, exact image bindings, check, immutable view,
projection, privacy storage and table row builder execute normally.
"""
from copy import deepcopy
import pytest
from peaso.collectors import k8s_selected_registry_image_20261021 as native
from peaso.collectors import azure_selected_aks_image_20261021 as aks
from peaso.checks import k8s_selected_registry_image_review_20261021 as review
from peaso.checks import azure_selected_aks_image_review_20261021 as aks_review
from peaso import selected_image_observations_20261021 as presentation
from peaso.image_findings import build_report
from peaso.image_findings_storage import attach_to_manifest
from peaso.snapshot import digest, freeze, resource_id
from peaso.storage.artifacts import FileArtifacts
from tests.test_azure_selected_aks_image_20261021 import fixture, Wire, scanner, RID, SCOPE


@pytest.mark.parametrize('provider', ['k8s', 'azure'])
@pytest.mark.parametrize('variant', ['clean', 'positive', 'clean_marker_positive', 'unknown_marker_positive', 'foreign_pod', 'foreign_child_digest', 'malformed_finding', 'registry_denied'])
def test_bound_native_pod_cve_reaches_private_artifact_and_rows(provider, variant, tmp_path):
    projection = presentation
    target, pod, blobs = fixture()
    scanner.hit = scanner.partial = False
    finding = {'vulnerability_id':'CVE-2026-1001','severity':'HIGH','package_types':['debian'],
        'package':'openssl','version':'1.0','fixed_in':['1.1'],'fix_status':'fixed','classes':['os-pkgs'],
        'image_digest':target['image'].rsplit('@',1)[1]}
    if variant == 'malformed_finding': finding['severity'] = 'INVALID'
    status = 'PASS' if variant in {'clean', 'clean_marker_positive'} else 'UNKNOWN' if variant == 'unknown_marker_positive' else 'FAIL'
    def trivy(image, manifest, config, layers, **kwargs):
        assert kwargs['native_verifier']() == image
        assert kwargs['archive_format'] == 'oci'
        return {'image':deepcopy(image),'status':status,'complete':status!='UNKNOWN',
            'scan_complete':status!='UNKNOWN','coverage_status':'UNKNOWN' if status=='UNKNOWN' else 'COMPLETE',
            'database':{'fresh':True},'findings':[] if variant=='clean' else [deepcopy(finding)]}
    wire = Wire(blobs, 'denied' if variant == 'registry_denied' else None)
    factory = lambda host, repo, cancel, **kw: native.RegistryReader(host, repo, cancel, open_https=wire, **kw)
    if provider == 'k8s':
        marker = native.inspect(target, lambda _:deepcopy(pod),allowed_hosts=['ghcr.io'],registry_factory=factory,
            scanner=scanner,trivy_enabled=True,trivy_runner=trivy)
        kind, check, scope, field = native.VULN_KIND,native.VULN_CHECK,target['namespace'],'SelectedRegistryImage'
        item={'id':native.identity(target),'name':native.identity(target),field:marker}
        holder = marker
        evaluate = lambda i,x:review.evaluate(i,x,kind)
    else:
        arm={'id':RID,'name':'aks','type':'Microsoft.ContainerService/managedClusters',
            'properties':{'provisioningState':'Succeeded','fqdn':'aks.example.com','resourceUID':'arm-uid'}}
        marker=aks.inspect_selected(target,arm_get=lambda _:deepcopy(arm),
            namespace_get=lambda:{'apiVersion':'v1','kind':'Namespace','metadata':{'name':'kube-system','uid':'cluster-uid'}},
            pod_get=lambda _:deepcopy(pod),context={'cluster_id':RID,'server':'https://aks.example.com','ca_cert_data':'test-only','token':'test-only'},
            tenant='tenant-id',allowed_hosts=['ghcr.io'],registry_factory=factory,scanner=scanner,
            trivy_enabled=True,trivy_runner=trivy)
        kind,check,scope,field=aks.VULN_KIND,aks.VULN_CHECK,SCOPE,'SelectedAksImage'
        item={'id':aks.identity(target),field:marker};holder=marker['image']
        evaluate=aks_review.evaluate_vulnerability
    if variant == 'foreign_pod': holder['native_after']['uid']='foreign-pod'
    if variant == 'foreign_child_digest': holder['child_vulnerability_scans'][0]['image']['manifest_digest']='sha256:'+'f'*64
    metadata={kind+'_authorized':True,native.OPTION if provider=='k8s' else aks.OPTION:[target]}
    collection={'type':kind,'scope':scope,'service':'kubernetes' if provider=='k8s' else 'Microsoft.ContainerService',
        'status':'partial' if variant=='registry_denied' else 'collected','items':[item]}
    index={'context':{'provider':provider,'scope':scope,'metadata':metadata},'collections':{kind:[collection]}}
    before = deepcopy((item,index))
    actual_status,evidence=evaluate(item,index)
    expected='PASS' if variant=='clean' else 'UNKNOWN' if variant in {'foreign_pod','malformed_finding','registry_denied'} else 'FAIL'
    assert actual_status==expected,evidence
    assert (item,index)==before
    native_id=resource_id(provider,kind,scope,item);asset=digest([provider,scope,kind,native_id])
    snapshot={'provider':provider,'scopes':[scope],'metadata':{},'collections':[{**collection,'items':[freeze(item)]}]}
    report={'provider':provider,'findings':[{'provider':provider,'check_id':check,'scope':scope,'resource_id':asset,'status':actual_status}]}
    current=projection.metadata_for_report(snapshot,report)
    artifacts=FileArtifacts(tmp_path/'artifacts')
    manifest=attach_to_manifest({},artifacts,'owner','a'*32,current)
    stored=artifacts.get('owner',manifest['image_vulnerability_scan']['artifact'])
    with pytest.raises(ValueError):artifacts.get('other-user',manifest['image_vulnerability_scan']['artifact'])
    rows=build_report(stored['observations'],selected=True)
    if variant in {'positive','clean_marker_positive','unknown_marker_positive'}:
        assert len(rows['rows'])==1,rows
        row=rows['rows'][0]
        assert row['vulnerability_id']==finding['vulnerability_id'] and row['image_digest']==finding['image_digest']
        assert row['affected_assets']==[{'resource_id':asset,'kind':kind,**({'namespace':scope} if provider=='k8s' else {})}]
        if variant in {'clean_marker_positive','unknown_marker_positive'}:
            assert rows['coverage']=='UNKNOWN' and rows['complete'] is False and row['coverage']=='UNKNOWN'
            assert evidence['complete'] is False and evidence['coverage_status']=='UNKNOWN'
    elif variant=='clean':assert rows['rows']==[] and rows['complete'] is True
    else:assert rows['rows']==[] and rows['coverage']=='UNKNOWN'
    assert all(response.closed for response in wire.responses)
