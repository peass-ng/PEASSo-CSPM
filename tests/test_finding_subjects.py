from peaso.ai.findings_report import source_index
from peaso.engine import evaluate_snapshot
from peaso.finding_subjects import DEPLOYMENT_ADMIN, SubjectIndex, labels, set_issue_subjects, subject, unique
from peaso.snapshot import make_snapshot


SCOPE = '123456789012/us-east-1'


def test_unencrypted_ebs_counts_the_failed_volume_only():
    snapshot = make_snapshot('aws', [SCOPE], [{'type': 'ebs_volume', 'scope': SCOPE, 'service': 'ec2',
        'status': 'collected', 'items': [
            {'id': 'vol-one', 'VolumeId': 'vol-one', 'State': 'in-use', 'Encrypted': False,
             'Attachments': [{'InstanceId': 'i-parent'}]},
            {'id': 'vol-two', 'VolumeId': 'vol-two', 'State': 'available', 'Encrypted': False},
            {'id': 'vol-encrypted', 'VolumeId': 'vol-encrypted', 'State': 'in-use', 'Encrypted': True},
        ]}])
    report = evaluate_snapshot(snapshot, checks=['aws.ebs.encryption'])
    sources = source_index({'report': report})
    assert sorted(asset for source in sources for asset in source['assets']) == ['vol-one', 'vol-two']
    assert not any('affected_subjects' in row for row in report['findings'] if row['status'] != 'FAIL')


def test_joined_ebs_check_binds_volumes_and_excludes_its_cluster_anchor():
    resources = [dict(id=kind+name, provider='aws', scope=SCOPE, type=kind, native_id=name)
                 for kind, name in [('ecs_cluster', 'cluster'), ('instance', 'i-parent'),
                                    ('ebs_volume', 'vol-one'), ('ebs_volume', 'vol-two')]]
    row = dict(id='joined', provider='aws', scope=SCOPE, check_id='aws.c2b.ecs.cluster_instance_volumes_encrypted',
               status='FAIL', resource_id='ecs_clustercluster', evidence={'unencrypted_volumes': ['vol-one'],
                                                                        'resource_ids': ['instancei-parent']})
    direct = SubjectIndex(resources, 'aws').direct(row)
    assert labels(direct) == ['vol-one']
    assert SubjectIndex(resources, 'aws').direct(dict(row, evidence={'resource_ids': ['instancei-parent']})) == []


def test_deployment_role_problem_needs_both_trust_and_grant_on_the_same_identity():
    policy = {'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}
    statement = {'Effect': 'Allow', 'Action': 'sts:AssumeRoleWithWebIdentity',
                 'Principal': {'Federated': 'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com'}}
    role = dict(id='deployment', provider='aws', scope=SCOPE, type='iam_role',
                native_id='arn:aws:iam::123456789012:role/deploy')
    row = dict(id='role', provider='aws', scope=SCOPE, check_id='aws.claude_a.iam.role_no_administrator_access',
               status='FAIL', resource_id='deployment', evidence={'administrator_access': True})
    trust = {'Statement': [statement]}
    for data, expected in [({'AttachedManagedPolicies': [policy]}, row['check_id']),
                           ({'AssumeRolePolicyDocument': trust}, row['check_id']),
                           ({'AttachedManagedPolicies': [policy], 'AssumeRolePolicyDocument': trust}, DEPLOYMENT_ADMIN)]:
        index = SubjectIndex([dict(role, data=data)], 'aws')
        assert index.problem(row) == expected


def test_same_asset_collapses_by_native_identity_but_scoped_names_stay_distinct():
    repository = 'arn:aws:ecr:us-east-1:123456789012:repository/app'
    items = [subject('aws', SCOPE, 'ecr_repository', repository),
             subject('aws', SCOPE, 'resource_policy', repository),
             subject('aws', SCOPE, 'athena_workgroup', 'primary'),
             subject('aws', '123456789012/us-west-2', 'athena_workgroup', 'primary'),
             subject('aws', SCOPE, 'account-setting', SCOPE, 'scope')]
    item = {}
    set_issue_subjects(item, unique(items))
    assert item['affected_assets'] == [repository, 'primary (123456789012/us-east-1, athena_workgroup)',
                                       'primary (123456789012/us-west-2, athena_workgroup)']
    assert item['affected_scopes'] == [SCOPE]
