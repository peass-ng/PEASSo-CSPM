"""Per-technique resource effects: never full principal control or definite edges."""
import copy
from pathlib import Path
import yaml
import pytest
from peaso import privesc
from peaso.privesc.effective_permissions.bounded_evidence import CONTRACT
from peaso.privesc.schema import validate_entry
from peaso.privesc.versioned_catalog import _verified_prior
from tests.test_peaso_privesc_schema_ext import reached,aws_snap,user,allow
from tests.test_peaso_privesc_schema_ext_azure import az,SUB,ROLE_ID
from tests.test_peaso_privesc_v4_batch import _snapshot,_required_actions

ENTRIES=[e for path in Path(__file__).with_name('fixtures').joinpath('privesc_bounded').glob('*.yaml')for e in yaml.safe_load(path.read_text())]


def case(entry, permissions=True):
    actions=_required_actions(entry.get('requires',{}))
    provider=entry['provider'];kind=provider+'_privesc_challenge_evidence'
    if provider=='aws':
        source='arn:aws:iam::111111111111:user/alice';scope='111111111111/us-east-1'
        snap=_snapshot(entry);target='arn:aws:'+entry['service']+':us-east-1:111111111111:resource/test'
        if not permissions:
            next(c for c in snap['collections']if c['type']=='iam_user')['items'][0]['UserPolicyList']=[]
    elif provider=='gcp':
        source='user:alice@corp.com';scope='projects/p1';target='projects/p1/resources/test'
        snap=_snapshot(entry)
        if not permissions:next(c for c in snap['collections']if c['type']=='iam_role')['items'][0]['includedPermissions']=[]
    else:
        source='u-alice';scope=SUB;target=SUB+'/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/test'
        snap=az(assignments=[(source,'User',SUB,ROLE_ID)],roles={ROLE_ID:(actions if permissions else [],actions if permissions else [])})
        snap['collections'].append({'type':kind,'scope':scope,'service':'privesc','status':'collected','items':[],'error':None})
    fact={'TechniqueId':entry['id'],'TargetKind':entry['target']['kind'],'TargetId':target,'Status':'verified','VerifiedPreconditions':True,
          'EvidenceRef':'fixture-exact-resource-review','EffectType':'bounded_resource_operation','VerifiedConditionIds':CONTRACT[entry['id']]['conditions']}
    fact.update({'SourceArn':source,'TargetAccount':scope.split('/')[0]}if provider=='aws'else {'SourceId':source,'TargetScope':scope})
    collection=next(c for c in snap['collections']if c['type']==kind);collection['items']=[fact]
    return snap,source,collection


@pytest.mark.parametrize('entry',ENTRIES,ids=lambda e:e['id'])
def test_exact_bounded_effect_is_conditional_terminal(entry):
    assert validate_entry(entry)[0]==[]
    snap,source,_=case(entry);before=copy.deepcopy(snap)
    result=privesc.analyze(snap,entries=[entry]);got=reached(result,source,entry['id'])
    assert len(got)==1 and set(got.values())=={'conditional'},(entry['id'],result.get('coverage'),result.get('findings'))
    assert snap==before
    assert all(f['status']!='FAIL'for f in result['findings'])
    targets=set(got)
    assert not any(e['source']in targets for e in result['graph']['edges'])
    assert entry['target']['outcome']=='bounded_authority'


@pytest.mark.parametrize('entry',ENTRIES,ids=lambda e:e['id'])
def test_bounded_effect_rejects_unbound_incomplete_duplicate_or_missing_facts(entry):
    for mutation in ({'EvidenceRef':''},{'VerifiedConditionIds':['wrong']},{'VerifiedPreconditions':False},{'EffectType':'principal_control'},{'Status':'disproven'},
                     {'TargetId':'arn:aws:lambda:us-east-1:999999999999:resource/foreign'}if entry['provider']=='aws'else {'TargetId':'projects/foreign/resources/test'}):
        snap,source,col=case(entry);col['items'][0].update(mutation)
        got=reached(privesc.analyze(snap,entries=[entry]),source,entry['id']);assert 'conditional'not in got.values(),(entry['id'],mutation,got)
    for state in ('partial','denied'):
        snap,source,col=case(entry);col['status']=state
        assert 'conditional'not in reached(privesc.analyze(snap,entries=[entry]),source,entry['id']).values()
    snap,source,col=case(entry);col['items']*=2
    assert 'conditional'not in reached(privesc.analyze(snap,entries=[entry]),source,entry['id']).values()
    snap,source,col=case(entry);col['items']=[]
    assert not reached(privesc.analyze(snap,entries=[entry]),source,entry['id'])


@pytest.mark.parametrize('entry',[e for e in ENTRIES if _required_actions(e.get('requires',{}))],ids=lambda e:e['id'])
def test_exact_fact_does_not_replace_effective_permissions(entry):
    snap,source,_=case(entry,False)
    assert 'conditional'not in reached(privesc.analyze(snap,entries=[entry]),source,entry['id']).values()



@pytest.mark.parametrize('entry',[e for e in ENTRIES if e['provider']in ('aws','gcp') and _required_actions(e.get('requires',{}))],ids=lambda e:e['id'])
def test_permissions_on_another_resource_do_not_authorize_exact_bounded_effect(entry):
    snap,source,_=case(entry)
    if entry['provider']=='aws':
        user=next(c for c in snap['collections']if c['type']=='iam_user')['items'][0]
        user['UserPolicyList'][0]['PolicyDocument']['Statement'][0]['Resource']='arn:aws:'+entry['service']+':us-east-1:111111111111:resource/other'
    else:
        col=next(c for c in snap['collections']if c['type']=='iam_policy')
        col['items'][0]['name']='projects/foreign'
    assert 'conditional'not in reached(privesc.analyze(snap,entries=[entry]),source,entry['id']).values()
