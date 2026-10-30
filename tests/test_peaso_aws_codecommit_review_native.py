"""Native CodeCommit SDK shapes through the public collection and evaluation pipeline."""
import copy
import json
from datetime import datetime, timezone, timedelta
import pytest
from test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from peaso.collectors import aws, collect_live
from tests.archived_check_contract import evaluate_snapshot, plan_collection
CHECK='aws.pci.codecommit.pr_review_approval'
SCOPE=ACCOUNT+'/'+REGION
AUTHOR='arn:aws:iam::'+ACCOUNT+':user/author'
REVIEWER='arn:aws:iam::'+ACCOUNT+':role/security'
TIME=datetime(2026,10,15,1,tzinfo=timezone.utc)
COMMIT='a'*40
SECRET='PRIVATE_DESCRIPTION_NOT_FOR_CACHE'


def capture(sdk,monkeypatch,mode,validated_options=None):
    session,add=sdk;sts=add('sts');cc=add('codecommit')
    sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':AUTHOR,'UserId':'author'}, {})
    repos=[{'repositoryName':'repo','repositoryId':'id'}]
    if mode=='list_denied':cc.add_client_error('list_repositories','AccessDeniedException',expected_params={})
    else:cc.add_response('list_repositories',{'repositories':repos*2 if mode=='duplicate_repo' else repos,**({'nextToken':'next'} if mode=='repo_partial' else {})},{})
    early=mode in ('list_denied','duplicate_repo','repo_partial')
    if not early:
        cc.add_response('list_pull_requests',{'pullRequestIds':['1'] if mode=='unmerged' else []},{'repositoryName':'repo','pullRequestStatus':'OPEN'})
        cc.add_response('list_pull_requests',{'pullRequestIds':[] if mode=='unmerged' else ['1']},{'repositoryName':'repo','pullRequestStatus':'CLOSED'})
        target={'repositoryName':'other' if mode=='foreign_repo' else 'repo','destinationReference':'refs/heads/main',
                'mergeMetadata':{'isMerged':mode!='unmerged','mergeCommitId':COMMIT,'mergedBy':AUTHOR,'mergeOption':'THREE_WAY_MERGE'}}
        pr={'pullRequestId':'2' if mode=='foreign_pr' else '1','title':SECRET,'description':SECRET,
            'authorArn':AUTHOR.replace(ACCOUNT,'999999999999') if mode=='foreign_author' else AUTHOR,
            'pullRequestStatus':'OPEN' if mode=='unmerged' else 'CLOSED','revisionId':'revision','pullRequestTargets':[target]}
        if mode=='optional_missing_get_commit':target['mergeMetadata'].pop('mergeCommitId')
        if mode=='optional_missing_get_actor':target['mergeMetadata'].pop('mergedBy')
        if mode=='optional_missing_get_option':target['mergeMetadata'].pop('mergeOption')
        cc.add_response('get_pull_request',{'pullRequest':pr},{'pullRequestId':'1'})
        early=mode in ('foreign_repo','foreign_pr','foreign_author','unmerged','optional_missing_get_commit')
    if not early:
        event={'pullRequestId':'2' if mode=='foreign_event' else '1','eventDate':TIME+timedelta(hours=2) if mode=='after_merge' else TIME,
            'actorArn':REVIEWER.replace(ACCOUNT,'999999999999') if mode=='foreign_actor' else REVIEWER,
            'pullRequestEventType':'PULL_REQUEST_APPROVAL_STATE_CHANGED','approvalStateChangedEventMetadata':{
            'revisionId':'old' if mode=='old_revision' else 'revision','approvalStatus':'REVOKE' if mode=='revoked' else 'APPROVE'}}
        merged={'pullRequestId':'1','eventDate':TIME+timedelta(hours=1),'actorArn':AUTHOR,
            'pullRequestEventType':'PULL_REQUEST_MERGE_STATE_CHANGED','pullRequestMergedStateChangedEventMetadata':{
            'repositoryName':'repo','destinationReference':'refs/heads/other' if mode=='wrong_branch' else 'refs/heads/main',
            'mergeMetadata':{'isMerged':True,'mergeCommitId':'b'*40 if mode=='wrong_commit' else COMMIT}}}
        if mode.startswith('optional_'):
            mm=merged['pullRequestMergedStateChangedEventMetadata']['mergeMetadata']
            mm.pop('mergeCommitId');mm.update(mergedBy=AUTHOR,mergeOption='THREE_WAY_MERGE')
            if mode=='optional_foreign_commit':mm['mergeCommitId']='b'*40
            if mode=='optional_actor':merged['actorArn']=REVIEWER
            if mode=='optional_merged_by':mm['mergedBy']=REVIEWER
            if mode=='optional_option':mm['mergeOption']='SQUASH_MERGE'
            if mode=='optional_branch':merged['pullRequestMergedStateChangedEventMetadata']['destinationReference']='refs/heads/other'
            if mode=='optional_id':merged['pullRequestId']='2'
            if mode=='optional_missing_actor':merged.pop('actorArn')
        mixed=None
        if mode.startswith('optional_mixed_'):
            mixed=copy.deepcopy(merged)
            suffix=mode.removeprefix('optional_mixed_')
            mm=merged['pullRequestMergedStateChangedEventMetadata']['mergeMetadata']
            if suffix=='foreign':mm['mergeCommitId']='b'*40
            elif suffix=='actor':merged['actorArn']=REVIEWER
            elif suffix=='option':mm['mergeOption']='SQUASH_MERGE'
        events=[] if mode=='no_events' else [event]
        if mode!='missing_merge':events.append(merged)
        if mixed is not None:events.append(mixed)
        if mode in ('duplicate_merge','optional_duplicate'):events.append(copy.deepcopy(merged))
        if mode=='same_time_conflict':
            revoke=copy.deepcopy(event);revoke['approvalStateChangedEventMetadata']['approvalStatus']='REVOKE';events.append(revoke)
        if mode=='events_denied':cc.add_client_error('describe_pull_request_events','AccessDeniedException',expected_params={'pullRequestId':'1'})
        else:
            paged=mode in ('events_partial','events_two_pages')
            cc.add_response('describe_pull_request_events',{'pullRequestEvents':[] if paged else events,**({'nextToken':'next-events'} if paged else {})},{'pullRequestId':'1'})
            if paged:cc.add_response('describe_pull_request_events',{'pullRequestEvents':events},{'pullRequestId':'1','nextToken':'next-events'})
        early=mode in ('foreign_event','foreign_actor','missing_merge','duplicate_merge','wrong_branch','wrong_commit','events_denied','events_partial')
        early=early or (mode.startswith('optional_') and mode!='optional_good')
        if not early:
            states=[] if mode=='no_states' else [{'userArn':AUTHOR if mode=='self_review' else REVIEWER,'approvalState':'REVOKE' if mode=='revoked' else 'APPROVE'}]
            if mode=='duplicate_states':states*=2
            params={'pullRequestId':'1','revisionId':'revision'}
            if mode=='states_denied':cc.add_client_error('get_pull_request_approval_states','AccessDeniedException',expected_params=params)
            else:cc.add_response('get_pull_request_approval_states',{'approvals':states},params)
    monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fixture-pinned'))
    options={'service_concurrency':1,'retry_attempts':1,'compliance_policy':{'status':'collected','scope':SCOPE,'security_reviewer_arns':[REVIEWER]}}
    if validated_options is not None:options.update(copy.deepcopy(validated_options))
    if mode=='no_policy':options.pop('compliance_policy')
    if mode in ('events_partial','repo_partial'):options['max_pages']=1
    connector={'provider':'aws','scopes':[SCOPE],'options':options}
    requirements=plan_collection({'connector':connector,'checks':[CHECK]})
    assert requirements==['codecommit_pull_request']
    snapshot=collect_live(connector,requirements)
    findings=evaluate_snapshot(snapshot,checks=[CHECK])['findings']
    assert len(findings)==1
    assert SECRET not in json.dumps(snapshot)
    if mode=='events_partial':
        assert len(cc._queue)==1 and cc._queue[0]['expected_params']['nextToken']=='next-events'
        env=next(c for c in snapshot['collections'] if c['type']=='codecommit_pull_request')
        assert env['status'] not in ('collected','empty') and env['error']['code']=='page_limit'
    else:cc.assert_no_pending_responses()
    return findings[0]['status'],snapshot


@pytest.mark.parametrize('mode,expected',[
 ('good','PASS'),('events_two_pages','PASS'),('no_events','FAIL'),('no_states','FAIL'),('old_revision','FAIL'),
 ('after_merge','FAIL'),('revoked','FAIL'),('self_review','FAIL'),('unmerged','NOT_APPLICABLE'),
 ('no_policy','UNKNOWN'),('list_denied','DENIED'),('repo_partial','UNKNOWN'),('duplicate_repo','UNKNOWN'),
 ('foreign_pr','UNKNOWN'),('foreign_author','UNKNOWN'),('foreign_repo','UNKNOWN'),('foreign_event','UNKNOWN'),
 ('foreign_actor','UNKNOWN'),('missing_merge','UNKNOWN'),('duplicate_merge','UNKNOWN'),('wrong_branch','UNKNOWN'),
 ('wrong_commit','UNKNOWN'),('events_denied','DENIED'),('events_partial','UNKNOWN'),('states_denied','DENIED'),
 ('duplicate_states','UNKNOWN'),('same_time_conflict','UNKNOWN')])
def test_native_pipeline(sdk,monkeypatch,mode,expected):
    status,snapshot=capture(sdk,monkeypatch,mode)
    assert status==expected
    if mode=='good':
        item=next(c for c in snapshot['collections'] if c['type']=='codecommit_pull_request')['items'][0]
        assert item['pullRequestTargets'][0]['mergeMetadata']['MergedAt']==(TIME+timedelta(hours=1)).isoformat()
        assert item['_provenance']['approval_revision']=='revision'


@pytest.mark.parametrize('change',[{'status':'denied'},{'scope':'999999999999/us-east-1'},
 {'security_reviewer_arns':[]},{'security_reviewer_arns':[REVIEWER,REVIEWER]},{'security_reviewer_arns':None},{'ApprovalStates':[]},{'finding_coverage_complete':True}])
def test_invalid_policy_before_requests(monkeypatch,change):
    policy={'status':'collected','scope':SCOPE,'security_reviewer_arns':[REVIEWER]};policy.update(change)
    monkeypatch.setattr(aws,'_session',lambda *a:pytest.fail('API before preflight'))
    with pytest.raises(ValueError):aws.collect({'scopes':[SCOPE],'options':{'compliance_policy':policy}},['codecommit_pull_request'])


def test_pre_cache_projection(sdk):
    session,add=sdk;cc=add('codecommit')
    cc.add_response('get_pull_request',{'pullRequest':{'pullRequestId':'1','title':SECRET,'description':SECRET,
        'approvalRules':[{'approvalRuleName':'secret','approvalRuleContent':SECRET}]}},{'pullRequestId':'1'})
    requests=aws.Requests({});requests.detail(session,'codecommit',REGION,'get_pull_request',pullRequestId='1')
    assert SECRET not in repr([f.result() for f in requests._cache.values()])
    assert requests.calls==1
    cc.assert_no_pending_responses()


@pytest.mark.parametrize('auth_mode',['local','cognito'])
def test_validated_intake_reaches_real_pipeline(sdk,monkeypatch,auth_mode):
    from types import SimpleNamespace
    from peaso.server.validation import validate_connector
    options={'compliance_policy':{'status':'collected','scope':SCOPE,'security_reviewer_arns':[REVIEWER]}}
    validate_connector('aws',{'method':'assume_role','role_arn':'arn:aws:iam::'+ACCOUNT+':role/reader','external_id':'peaso-fixture'},
        options,SimpleNamespace(auth_mode=auth_mode),server_external_id=True)
    status,snapshot=capture(sdk,monkeypatch,'good',options)
    assert status=='PASS' and snapshot['metadata']['compliance_policy']==options['compliance_policy']


@pytest.mark.parametrize('auth_mode',['local','cognito'])
@pytest.mark.parametrize('provider',['aws','gcp','azure','k8s'])
def test_intake_rejects_invalid_or_foreign_review_before_auth(auth_mode,provider):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from peaso.server.validation import validate_connector
    options={'compliance_policy':{'status':'collected','scope':SCOPE,'security_reviewer_arns':[] if provider=='aws' else [REVIEWER]}}
    with pytest.raises(HTTPException) as exc:
        validate_connector(provider,{},options,SimpleNamespace(auth_mode=auth_mode))
    assert exc.value.status_code==422


def test_mapping_preserves_all_previous_iam_grants():
    from scripts import peaso_deploy_customer_policy as policy
    from peaso.collectors.aws_codecommit_review_native import READ_ACTIONS
    from tests.customer_policy_history import historical_role_template
    proposed=policy.build_policy(aws.READ_ACTIONS)
    previous=policy.split_policy(policy.build_policy(aws.READ_ACTIONS-READ_ACTIONS))
    updated=policy.split_policy(proposed)
    historical=historical_role_template('a4c004efe171a0c94977fefc31fbc30c0d879b7c4e98875862aa498aa4d7a873')
    reviewed=[s for r in historical['Resources'].values() if r['Type']=='AWS::IAM::ManagedPolicy'
              for s in r['Properties']['PolicyDocument']['Statement'] if s['Sid'].startswith('NativeCodeCommit')]
    statements=[s for d in updated for s in d['Statement']]
    # b72d527e packs whole oversized companion statements largest-first into
    # spare partition space, so document order can move; IAM statement order
    # carries no meaning, but each reviewed statement must survive exactly once.
    by_sid=lambda rows:sorted(rows,key=lambda s:s['Sid'])
    assert by_sid([s for s in statements if s['Sid'].startswith('NativeCodeCommit')])==by_sid(reviewed)
    # Later metadata reviews may add partitions, but adding these five reads
    # must preserve every previous statement exactly, add no attachment, and
    # keep each ordinary read partition in place. Since b72d527e, whole scoped
    # companion statements are packed into spare space, so they may move
    # between documents without any action or resource changing.
    assert len(updated)==len(previous)
    assert [d['Statement'][0] for d in updated]==[d['Statement'][0] for d in previous]
    kept=[s for d in updated for s in d['Statement'] if s not in reviewed]
    before=[s for d in previous for s in d['Statement']]
    assert len({s['Sid'] for s in kept})==len(kept)
    assert by_sid(kept)==by_sid(before)
    assert len(updated)<=policy.IAM_MANAGED_POLICIES_PER_ROLE
    assert all(policy.policy_size(d)<=6144 for d in updated)
    for service,operation in READ_ACTIONS:
        action=policy.iam_action(service,operation)
        matches=[s for s in statements if s['Action']==action]
        assert len(matches)==1
        assert matches[0]['Resource']==('*' if operation=='list_repositories' else {'Fn::Sub':'arn:${AWS::Partition}:codecommit:*:${AWS::AccountId}:*'})


def test_other_existing_owner_policies_are_not_reinterpreted():
    from peaso.collectors.aws_codecommit_review_native import review_policy
    review_policy({'compliance_policy':{'status':'collected','scope':SCOPE,'other_existing_review':[]}},[SCOPE])


@pytest.mark.parametrize('mode,expected',[
 ('optional_good','PASS'),('optional_mixed_foreign','UNKNOWN'),('optional_mixed_actor','UNKNOWN'),('optional_mixed_option','UNKNOWN'),('optional_foreign_commit','UNKNOWN'),
 ('optional_actor','UNKNOWN'),('optional_merged_by','UNKNOWN'),
 ('optional_option','UNKNOWN'),('optional_branch','UNKNOWN'),
 ('optional_id','UNKNOWN'),('optional_duplicate','UNKNOWN'),
 ('optional_missing_actor','UNKNOWN'),('optional_missing_get_actor','UNKNOWN'),('optional_missing_get_option','UNKNOWN'),('optional_missing_get_commit','UNKNOWN')])
def test_native_optional_merge_commit_event(sdk,monkeypatch,mode,expected):
    status,snapshot=capture(sdk,monkeypatch,mode)
    assert status==expected
    if expected=='PASS':
        item=next(c for c in snapshot['collections'] if c['type']=='codecommit_pull_request')['items'][0]
        assert item['pullRequestTargets'][0]['mergeMetadata']['MergedAt']==(TIME+timedelta(hours=1)).isoformat()


@pytest.mark.parametrize('value',[None,True,{},'', 'not-a-commit'])
@pytest.mark.parametrize('mixed',[False,True])
def test_present_malformed_event_commit_never_uses_absent_fallback(sdk,monkeypatch,value,mixed):
    # Malformed native responses are injected after the SDK's valid-shape stub;
    # project_response must reject them or the join must remain unavailable.
    from peaso.collectors import aws_codecommit_review_native as native
    original=native.project_response
    def malformed(response,operation):
        response=copy.deepcopy(response)
        if operation=='describe_pull_request_events':
            for event in response.get('pullRequestEvents',[]):
                if (event.get('pullRequestEventType')=='PULL_REQUEST_MERGE_STATE_CHANGED'
                        and 'mergeCommitId' in event.get('pullRequestMergedStateChangedEventMetadata',{}).get('mergeMetadata',{})):
                    event['pullRequestMergedStateChangedEventMetadata']['mergeMetadata']['mergeCommitId']=value
        return original(response,operation)
    monkeypatch.setattr(native,'project_response',malformed)
    # This mode queues no approval-state read because the merge join must fail.
    assert capture(sdk,monkeypatch,'optional_mixed_foreign' if mixed else 'optional_foreign_commit')[0]=='UNKNOWN'
