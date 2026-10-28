"""The native ECS detail supplies the later name-only view without another read."""
from types import SimpleNamespace

from peaso.collectors import aws_b_services, aws_facts_compute_edge


ARN = 'arn:aws:ecs:us-east-1:123456789012:task-definition/example:1'


def test_ecs_definition_names_use_one_read_without_plaintext_values():
    calls = []
    def detail(*args, **kwargs):
        calls.append(kwargs)
        return {'collection_status': 'collected', 'taskDefinition': {
            'taskDefinitionArn': ARN, 'containerDefinitions': [
                {'name': 'web', 'environment': [{'name': 'PASSWORD'}, {'name': 'REGION'}]}]}}
    requests = SimpleNamespace(detail=detail,
        call=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('duplicate definition read')))
    item = {'taskDefinitionArn': ARN,
        'Definition': aws_b_services._detail(requests, object(), 'us-east-1', 'ecs',
            'describe_task_definition', taskDefinition=ARN)}
    result, = aws_facts_compute_edge._ecs_environment_names(requests, object(), 'us-east-1', [item])
    assert calls == [{'taskDefinition': ARN}]
    assert result['Definition']['taskDefinition']['containerDefinitions'][0]['environment'] == [
        {'name': 'PASSWORD'}, {'name': 'REGION'}]
    assert 'value' not in str(result)


def test_ecs_definition_mismatched_identity_cannot_supply_names():
    requests = SimpleNamespace(detail=lambda *args, **kwargs: {
        'collection_status': 'collected', 'taskDefinition': {
            'taskDefinitionArn': ARN[:-1] + '2',
            'containerDefinitions': [{'name': 'web', 'environment': [{'name': 'PASSWORD'}]}]}},
        call=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('duplicate definition read')))
    item = {'taskDefinitionArn': ARN,
        'Definition': aws_b_services._detail(requests, object(), 'us-east-1', 'ecs',
            'describe_task_definition', taskDefinition=ARN)}
    result, = aws_facts_compute_edge._ecs_environment_names(requests, object(), 'us-east-1', [item])
    assert 'environment' not in result['Definition']['taskDefinition']['containerDefinitions'][0]
