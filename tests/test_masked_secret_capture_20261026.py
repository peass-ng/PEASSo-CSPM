"""Values masked at collection stay visible to the owner through private evidence.

Each case is a field the collector masks while a check still reports on it.
The clear value must reach the finding's authorized detail.
"""
import base64

from peaso import secret_evidence as se
from peaso.collectors import aws_additional_secret_indicators as additional
from peaso.collectors import aws_launch_configuration_redaction as launch
from peaso.collectors import k8s
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

ACCOUNT, REGION = '123456789012', 'us-east-1'
ACCESS = 'AKIA' + 'Q' * 16
SECRET = 'S3cr' * 10


def _detail(capture, cipher, finding):
    return se.details(finding, capture.document(), cipher, tenant='t', scan_id='s')


def _values(detail):
    return sorted(match['value'] for match in detail['matches'])


def _finding(check_id, resource_id, scope=ACCOUNT + '/' + REGION):
    return {'id': 'x', 'check_id': check_id, 'provider': 'aws', 'status': 'FAIL', 'scope': scope,
            'resource_id': resource_id, 'native_resource_id': resource_id, 'evidence': {}}


def test_k8s_pod_env_value_attaches_under_all_namespaces_scope():
    value = 'synthetic-k8s-password-Q9w8'
    pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'p', 'namespace': 'default', 'uid': 'u1'},
           'spec': {'containers': [{'name': 'c', 'image': 'x', 'env': [{'name': 'DB_PASSWORD', 'value': value}]}]}}
    cipher = se.EphemeralCipher()
    with se.capture(cipher, tenant='t', scan_id='s') as capture:
        native = k8s._native(pod, 'pod', 'cluster1', '*', True)
        snapshot = make_snapshot('k8s', ['*'], [{'type': 'pod', 'scope': '*', 'status': 'collected', 'items': [native]}])
        capture.bind_snapshot(snapshot)
    report = evaluate_snapshot(snapshot, checks=['k8s.claude.pod.no_literal_secret_env'])
    findings = report['findings'] if isinstance(report, dict) else report
    finding = next(f for f in findings if f['check_id'] == 'k8s.claude.pod.no_literal_secret_env')
    assert finding['status'] == 'FAIL' and finding['scope'] == '*'
    detail = _detail(capture, cipher, finding)
    assert detail['status'] == 'available'
    assert _values(detail) == [value]


def test_ec2_user_data_secret_named_values_and_open_private_key_are_kept():
    text = ('#!/bin/bash\nexport API_TOKEN=tok-abcdef123\nmytool --client-secret cs-998877aa --region us-east-1\n'
            'echo secret_thing foo\nSECRET_ARN=arn:aws:secretsmanager:x\nTOKEN=${FROM_ENV}\n'
            '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n')
    cipher = se.EphemeralCipher()
    instance = 'i-0123456789abcdef0'
    with se.capture(cipher, tenant='t', scan_id='s') as capture:
        se.legacy_text(text, instance)
    detail = _detail(capture, cipher, _finding('aws.a.ec2.user_data_source_indicators', instance, scope=''))
    assert _values(detail) == sorted(['tok-abcdef123', 'cs-998877aa', '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n'])


def test_ecs_name_check_values_survive_strict_parse_rejection():
    arn = f'arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/app:1'
    row = {'taskDefinitionArn': arn, 'containerDefinitions': [
        {'name': 'a', 'environment': [{'name': 'AWS_SECRET_ACCESS_KEY', 'value': SECRET}, {'name': 'MODE', 'value': 'prod'}]},
        {'name': 'b', 'environment': [{'name': 'BROKEN'}]}]}
    cipher = se.EphemeralCipher()
    with se.capture(cipher, tenant='t', scan_id='s') as capture:
        projected = additional._row('ecs_task_definition', row, REGION, 'ecs:DescribeTaskDefinition', {})
    assert projected['AdditionalSecretIndicators']['collection_status'] == 'malformed'
    detail = _detail(capture, cipher, _finding('aws.c2b.ecs.no_credential_named_env_vars', arn))
    assert _values(detail) == [SECRET]
    assert detail['matches'][0]['locations'][0]['path'] == 'containerDefinitions[0].environment[name="AWS_SECRET_ACCESS_KEY"].value'


def test_codebuild_name_check_values_survive_strict_parse_rejection():
    arn = f'arn:aws:codebuild:{REGION}:{ACCOUNT}:project/build'
    project = {'arn': arn, 'name': 'build', 'environment': {'environmentVariables': [
        {'name': 'AWS_SECRET_ACCESS_KEY', 'value': SECRET, 'type': 'PLAINTEXT'},
        {'name': 'REF', 'value': '/param', 'type': 'PARAMETER_STORE'},
        {'name': 'ODD', 'value': 'x', 'type': 'UNKNOWN'}]}}
    cipher = se.EphemeralCipher()
    with se.capture(cipher, tenant='t', scan_id='s') as capture:
        assert additional.codebuild_indicator(project)['collection_status'] == 'malformed'
    detail = _detail(capture, cipher, _finding('aws.c2b.codebuild.no_plaintext_sensitive_env_names', arn))
    assert _values(detail) == [SECRET]


def test_launch_configuration_key_pair_kept_when_payload_reader_rejects_text():
    arn = (f'arn:aws:autoscaling:{REGION}:{ACCOUNT}:launchConfiguration:'
           '00000000-0000-0000-0000-000000000000:launchConfigurationName/lc')
    # A control character makes the payload reader reject text the key-pair check accepts.
    text = f'\x01\naws_access_key_id={ACCESS}\naws_secret_access_key={SECRET}\n'
    row = {'LaunchConfigurationARN': arn, 'LaunchConfigurationName': 'lc', 'UserData': base64.b64encode(text.encode()).decode()}
    cipher = se.EphemeralCipher()
    with se.capture(cipher, tenant='t', scan_id='s') as capture:
        projected = launch.project_response({'LaunchConfigurations': [row]})['LaunchConfigurations'][0]
    assert projected['UserDataIndicators']['HasAwsKeyPair'] is True
    assert projected['PayloadSecretIndicators']['collection_status'] == 'malformed'
    detail = _detail(capture, cipher, _finding('aws_autoscaling_userdata_plaintext_aws_key', arn))
    assert _values(detail) == sorted([ACCESS, SECRET])
