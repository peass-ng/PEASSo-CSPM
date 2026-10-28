"""Exact IAM admission for the EventBridgeV2–Cloud Map exposure reads."""

from scripts import peaso_deploy_customer_policy as builder


READS = {
    ('eventbridgev2', 'get_resource_policy'),
    ('eventbridgev2', 'list_resource_policies'),
    ('eventbridgev2', 'list_subscribers'),
    ('gamelift', 'describe_fleet_port_settings'),
    ('glacier', 'get_vault_lock'),
    ('glacier', 'get_vault_notifications'),
    ('glacier', 'list_jobs'),
    ('globalaccelerator', 'list_cross_account_attachments'),
    ('globalaccelerator', 'list_custom_routing_accelerators'),
    ('globalaccelerator', 'list_custom_routing_endpoint_groups'),
    ('globalaccelerator', 'list_custom_routing_listeners'),
    ('iot', 'describe_domain_configuration'),
    ('iot', 'describe_endpoint'),
    ('iot', 'get_topic_rule'),
    ('iot', 'list_domain_configurations'),
    ('iot', 'list_topic_rules'),
    ('lakeformation', 'get_data_lake_settings'),
    ('lightsail', 'get_distributions'),
    ('rum', 'get_app_monitor'),
    ('rum', 'list_rum_metrics_destinations'),
    ('servicediscovery', 'list_instances'),
    ('servicediscovery', 'list_namespaces'),
    ('servicediscovery', 'list_services'),
}


def test_second_half_read_actions_are_exact_and_resource_scoped():
    actions = {builder.iam_action(*read) for read in READS}
    assert actions <= set(builder.EXPOSURE_SWEEP_READ_REFERENCES)
    assert len(actions) == len(READS) == 23
    assert {action for action in actions if action.startswith('events:')} == {
        'events:GetResourcePolicy', 'events:ListResourcePolicies', 'events:ListSubscribers'}
    policy = builder.build_policy(READS, include_credential_report_generation=False)
    actual = {action for statement in policy['Statement']
              for action in ([statement['Action']] if isinstance(statement['Action'], str)
                             else statement['Action'])}
    assert actual == actions
    for read, (action, resource) in builder.EXPOSURE_SWEEP_SCOPED_READS.items():
        assert read in READS
        assert {'Fn::Sub': resource} == next(statement['Resource'] for statement in policy['Statement']
                                            if statement['Action'] == action)
        assert '${AWS::AccountId}' in resource
    documents = builder.split_policy(policy)
    assert len(documents) <= builder.IAM_MANAGED_POLICIES_PER_ROLE
    assert all(builder.policy_size(document) <= builder.IAM_MANAGED_POLICY_LIMIT
               for document in documents)


def test_eventbridgev2_sdk_gap_is_finite_and_mutations_stay_fenced():
    assert set(builder._sdk_operation_names('eventbridgev2')) == {
        'get_resource_policy', 'list_resource_policies', 'list_subscribers'}
    for operation in ('put_resource_policy', 'delete_resource_policy', 'create_subscriber'):
        try:
            builder.iam_action('eventbridgev2', operation)
        except ValueError:
            pass
        else:
            raise AssertionError('eventbridgev2 mutation admitted')
