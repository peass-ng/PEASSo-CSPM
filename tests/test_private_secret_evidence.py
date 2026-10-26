"""Private value capture proofs. All credentials are synthetic and never validated."""
import concurrent.futures
from contextlib import ExitStack
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from peaso import secret_evidence as evidence
from peaso import secret_scanning as scanning
from peaso.storage.artifacts import FileArtifacts, S3Artifacts

VALUE = 'synthetic-full-value-Q9w8e7R6!'
ARN = 'arn:aws:lambda:us-east-1:123456789012:function:fixture'
SCAN = 'a' * 32


def finding(fp=None, **extra):
    return {'id': 'secret-' + (fp or 'legacy'), 'check_id': 'aws.htbp.lambda.env_var_names_not_credentials',
            'provider': 'aws', 'status': 'FAIL', 'finding_type': 'secrets', 'scope': '123456789012/us-east-1',
            'resource_id': ARN, 'native_resource_id': ARN, 'evidence': {},
            **({'secret_fingerprint': fp} if fp else {}), **extra}


class CaptureTests(unittest.TestCase):
    def setUp(self):
        scanning._RESULTS.clear()
        self.cipher = evidence.EphemeralCipher()

    def engines(self, rows):
        stack = ExitStack()
        for name in ('kingfisher', 'trufflehog'):
            stack.enter_context(patch.object(scanning, '_scan_' + name, return_value=rows))
        self.addCleanup(stack.close)

    def test_full_value_exact_path_line_and_public_parity(self):
        self.engines([(VALUE, 'synthetic', 3)])
        path = 'src/' + VALUE + '.py'
        payload = ('line1\nline2\n' + VALUE).encode()
        baseline = scanning.scan_content(payload, path)
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            with evidence.source_context(resource_id=ARN, scope='123456789012/us-east-1'):
                actual = scanning.scan_content(payload, path)
        self.assertEqual(actual, baseline)
        fp = actual['leaks'][0]['fingerprint']
        # The found value stays visible in its exact detector path.
        self.assertEqual(actual['leaks'][0]['locations'], [{'path': path, 'line': 3}])
        self.assertNotIn(VALUE, repr(scanning._RESULTS))
        self.assertNotIn(VALUE, json.dumps(sink.document()))
        private = evidence.details(finding(fp), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        match = private['matches'][0]
        self.assertEqual(match['value'], VALUE)
        self.assertEqual(match['locations'][0]['path'], path)
        self.assertEqual(match['locations'][0]['line'], 3)
        self.assertEqual(match['locations'][0]['resource_id'], ARN)
        self.assertEqual({d['engine'] for d in match['detectors']}, {'kingfisher', 'trufflehog'})

    def test_image_alias_before_pseudonymization_and_layer_identity(self):
        from peaso.collectors.gcp_image_secret_indicators import _tar
        import hashlib
        # Exercise retained origin before pseudonymization with an admitted path.
        value = VALUE.rstrip('!')
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            info = tarfile.TarInfo('app/' + value + '/config.env')
            payload = ('\npassword=' + value).encode(); info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        raw = raw.getvalue(); digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
        self.engines([(value, 'synthetic', 2)])
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            with evidence.source_context(resource_id='image@sha256:abc', image_digest='sha256:abc', layer=digest):
                safe, _ = _tar(raw, 'application/vnd.oci.image.layer.v1.tar', digest)
                with tarfile.open(fileobj=io.BytesIO(safe)) as archive:
                    member = archive.getmembers()[0]
                    outcome = scanning.scan_content(archive.extractfile(member).read(), member.name)
        self.assertEqual(member.name, 'member-1')
        self.assertNotIn(value, json.dumps(outcome))
        fp = outcome['leaks'][0]['fingerprint']
        canonical = [dict(leak, locations=[dict(loc, resource_id='image@sha256:abc') for loc in leak['locations']]) for leak in outcome['leaks']]
        observed = finding(fp, resource_id='image@sha256:abc', native_resource_id='image@sha256:abc', scope=None,
            evidence={'secret_leaks': canonical})
        loc = evidence.details(observed, sink.document(), self.cipher, tenant='alice', scan_id=SCAN)['matches'][0]['locations'][0]
        self.assertEqual(loc['path'], 'app/' + value + '/config.env')
        self.assertEqual((loc['image_digest'], loc['layer'], loc['line']), ('sha256:abc', digest, 2))
        self.assertEqual(sink.aliases, {})

    def test_configuration_original_field_and_honest_unknown_lines(self):
        self.engines([(VALUE, 'synthetic', 7)])
        for kind in ('configuration', 'log'):
            with self.subTest(kind=kind), evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
                result = evidence.scan_with_source(scanning.scan_content, ('\n' * 6 + VALUE).encode(), 'safe-path',
                    source={'resource_id': ARN, 'location_kind': kind}, native={'environment': {'DB_PASSWORD': VALUE}})
            private = evidence.details(finding(result['leaks'][0]['fingerprint']), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
            loc = private['matches'][0]['locations'][0]
            self.assertIsNone(loc['line'])
            if kind == 'configuration': self.assertEqual(loc['field'], '$["environment"]["DB_PASSWORD"]')

    def test_filename_match_does_not_claim_a_body_line(self):
        self.engines([(VALUE, 'synthetic', 4)])
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            result = evidence.scan_with_source(scanning.scan_content, ('body\n\n\n' + VALUE).encode(), 'file', source={'content_lines': '3'})
        loc = evidence.details(finding(result['leaks'][0]['fingerprint'], evidence={'secret_leaks': result['leaks']}), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)['matches'][0]['locations'][0]
        self.assertIsNone(loc['line']); self.assertEqual(loc['location_kind'], 'filename')

    def test_legacy_config_pattern_and_plaintext_names_without_resolving_references(self):
        from peaso.collectors.aws_configuration_secret_indicators import lambda_indicators
        native = {'FunctionArn': ARN, 'FunctionName': 'fixture', 'Environment': {'Variables': {'DB_PASSWORD': VALUE}}}
        public = lambda_indicators(native, 'lambda:GetFunctionConfiguration')
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            self.assertEqual(lambda_indicators(native, 'lambda:GetFunctionConfiguration'), public)
            evidence.named_environment({'env': [{'name': 'API_TOKEN', 'valueFrom': {'secretKeyRef': {'name': 'not-read'}}},
                                               {'name': 'PASSWORD_SECRET_ARN', 'value': 'arn:metadata'}]},
                                       provider='aws', resource_id=ARN)
        private = evidence.details(finding(), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual({m['value'] for m in private['matches']}, {VALUE})
        self.assertEqual({l['path'] for l in private['matches'][0]['locations']}, {'Environment.Variables["DB_PASSWORD"]'})
        pattern = evidence.details(finding(check_id='aws.review.lambda.configuration_secret_indicators'),
            sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual({m['value'] for m in pattern['matches']}, {VALUE})
        self.assertTrue(any(l.get('field') == '$["DB_PASSWORD"]' for l in pattern['matches'][0]['locations']))
        self.assertNotIn(VALUE, json.dumps(public))
        self.assertTrue(all(l['line'] is None for l in private['matches'][0]['locations']))

    def test_legacy_user_data_actual_multiline_pem_and_password(self):
        from peaso.collectors.aws_user_data_secret_indicators import project
        pem = '-----BEGIN PRIVATE KEY-----\nsynthetic-Q12\n-----END PRIVATE KEY-----'
        text = 'line1\nDB_PASSWORD="' + VALUE + '"\n' + pem
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            with evidence.source_context(path='ec2/user-data'):
                public = project(text, 'i-synthetic')
        private = evidence.details(finding(resource_id='i-synthetic', native_resource_id='i-synthetic', check_id='aws.a.ec2.user_data_source_indicators'), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual({m['value'] for m in private['matches']}, {VALUE, pem})
        self.assertEqual({l['line'] for m in private['matches'] for l in m['locations']}, {2, 3})
        self.assertNotIn(VALUE, json.dumps(public))

    def test_cross_tenant_scan_and_ciphertext_replay_never_return_values(self):
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            evidence.named_environment({'Variables': {'DB_PASSWORD': VALUE}}, provider='aws', resource_id=ARN)
        doc = sink.document()
        for tenant, scan in [('bob', SCAN), ('alice', 'b' * 32)]:
            self.assertEqual(evidence.details(finding(), doc, self.cipher, tenant=tenant, scan_id=scan)['status'], 'unavailable')
        doc['tenant'] = 'bob'
        with self.assertRaisesRegex(ValueError, 'scope mismatch'):
            evidence.details(finding(), doc, self.cipher, tenant='bob', scan_id=SCAN)
        self.assertEqual(evidence.details(finding(), None, self.cipher, tenant='alice', scan_id=SCAN)['status'], 'unavailable')
        self.assertEqual(evidence.details(finding(check_id='metadata.expiry'), None, self.cipher, tenant='alice', scan_id=SCAN)['status'], 'metadata_only')

    def test_unknown_engine_line_and_capture_bounds_never_invent_truncated_value(self):
        self.engines([(VALUE, 'synthetic', None)])
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            result = scanning.scan_content(VALUE.encode(), 'f')
        fp = result['leaks'][0]['fingerprint']
        self.assertIsNone(evidence.details(finding(fp, evidence={'secret_leaks': result['leaks']}), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)['matches'][0]['locations'][0]['line'])
        with patch.object(evidence, 'MAX_VALUE_BYTES', 3), evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            scanning.scan_content(VALUE.encode(), 'f')
        self.assertTrue(sink.incomplete); self.assertFalse(sink.records)

    def test_thread_source_context_isolated_with_same_value_dedup(self):
        fp = scanning._fingerprint(VALUE)
        def task(i):
            with evidence.source_context(resource_id='resource-' + str(i)):
                evidence.remember(VALUE, fp, path='file-' + str(i), line=i + 1, engine='test', rule='test')
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(task, range(8)))
        self.assertEqual(len(sink.records), 1)
        canonical = [{'resource_id': 'resource-' + str(i), 'path': 'file-' + str(i), 'line': i + 1} for i in range(8)]
        private = evidence.details(finding(fp, resource_id='secret:' + fp, native_resource_id=None, evidence={'secret_leaks': [{'fingerprint': fp, 'locations': canonical}]}), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual({l['resource_id'] for l in private['matches'][0]['locations']}, {'resource-' + str(i) for i in range(8)})

    def test_capture_budget_includes_locations_and_encrypted_aliases(self):
        with patch.object(evidence, 'MAX_BYTES', 300), evidence.capture(self.cipher) as sink:
            evidence.alias_path('member-1', 'private/path')
            evidence.remember(VALUE, scanning._fingerprint(VALUE), path='p' * 290, engine='test', rule='test')
        self.assertTrue(sink.incomplete)
        self.assertFalse(sink.records)

    def test_encrypted_private_artifact_tenant_boundary_and_no_presign(self):
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            evidence.named_environment({'Variables': {'DB_PASSWORD': VALUE}}, provider='aws', resource_id=ARN)
        with tempfile.TemporaryDirectory() as directory:
            artifacts = FileArtifacts(Path(directory))
            ref = artifacts.put_secret_evidence('alice', SCAN, sink.document())
            raw = (Path(directory) / ref).read_text()
            self.assertNotIn(VALUE, raw)
            self.assertEqual((Path(directory) / ref).stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError): artifacts.get('bob', ref)
            self.assertEqual(evidence.load_details(artifacts, self.cipher, 'alice', SCAN, finding())['matches'][0]['value'], VALUE)
            s3 = S3Artifacts('private', client=object())
            with self.assertRaises(ValueError): s3.presign('alice', ref)
            artifacts.delete_job('alice', SCAN)
            self.assertFalse((Path(directory) / ref).exists())

    def test_literal_predicates_and_explicit_policies_include_actual_values_only(self):
        policy = {'parameters': {'approved_database_connection_environment_variable_names': ['CUSTOM_DB']},
                  'compliance_policy': {'sw26': {'azure_aks_cluster_3_5_1_14_247ebcd': {'secretKeys': ['CUSTOM_KEY']}}}}
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN, options=policy) as sink:
            evidence.named_environment({'Variables': {'AWS_ACCESS_KEY_ID': VALUE, 'CUSTOM_DB': 'observed-db-value', 'STAGE': 'production'}}, provider='aws', resource_id=ARN)
            evidence.named_environment({'environmentVariables': [{'name': 'MODE', 'value': 'x'}, {'name': 'PASSWORD_REF', 'secureValue': None}]},
                provider='azure', resource_id='azure-resource', path='properties.containers[0].properties')
            evidence.pod_environment({'spec': {'containers': [{'env': [{'name': 'CUSTOM_KEY', 'value': 'actual-custom'}, {'name': 'CUSTOM_REF', 'valueFrom': {'secretKeyRef': {'name': 'not-read'}}}]}]}},
                kind='pod', resource_id='k8s-resource', scope='123456789012/us-east-1')
        cases = [('aws.nist.codebuild_exact_aws_key_env_names', ARN, {VALUE}),
                 ('aws_cis_lambda_database_secrets_manager', ARN, {'observed-db-value'}),
                 ('azure.claude.container_group_secure_environment_variables', 'azure-resource', {'x'}),
                 ('azure_aks_cluster_3_5_1_14_247ebcd', 'k8s-resource', {'actual-custom'})]
        for check, resource, values in cases:
            with self.subTest(check=check):
                result = evidence.details(finding(check_id=check, resource_id=resource, native_resource_id=resource), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
                self.assertEqual({m['value'] for m in result['matches']}, values)
        self.assertNotIn('production', str(sink.document()))
        self.assertEqual(len(sink.records), 4)

    def test_bounded_pages_keep_every_value_and_location_without_truncation(self):
        matches = [{'fingerprint': 'a', 'value': VALUE, 'detectors': [], 'locations': [{'path': 'file-' + str(i), 'line': i + 1} for i in range(205)]}]
        offset = 0; paths = []
        while offset is not None:
            page, offset, total = evidence.page_matches(matches, offset, 100000)
            self.assertEqual(total, 205)
            self.assertEqual(page[0]['value'], VALUE)
            paths.extend(l['path'] for m in page for l in m['locations'])
        self.assertEqual(paths, ['file-' + str(i) for i in range(205)])

    def test_private_fields_cannot_enter_generic_or_ai_outputs(self):
        private = {'findings': [{'id': 'f', 'secret_evidence': {'matches': [{'value': VALUE}]},
                                  'evidence': {'safe': 'redacted'}}]}
        clean = evidence.without_private_values(private)
        self.assertNotIn(VALUE, json.dumps(clean))
        self.assertEqual(clean['findings'][0]['evidence'], {'safe': 'redacted'})
        self.assertIn(VALUE, json.dumps(private))

    def test_complete_aws_pair_keeps_public_identity_and_retains_actual_secret_component(self):
        access = 'AKIA' + '7MQ2ZR9WL4CV8NK1'
        secret = ('7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT1vW8')[:40]
        payload = ('AWS_ACCESS_KEY_ID=' + access + '\nAWS_SECRET_ACCESS_KEY=' + secret + '\n').encode()
        row = {'Raw': access, 'RawV2': access + ':' + secret, 'DetectorName': 'AWS', 'Verified': False}
        with patch.object(scanning, '_run', return_value=json.dumps(row).encode()), patch.object(scanning, '_trufflehog', return_value='offline'), patch.object(scanning, '_scan_kingfisher', return_value=[]):
            public = scanning.scan_content(payload, 'app/config.env')
            with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
                with evidence.source_context(resource_id=ARN):
                    captured = scanning.scan_content(payload, 'app/config.env')
        self.assertEqual(captured, public)
        self.assertEqual(len(captured['leaks']), 1)
        fp = captured['leaks'][0]['fingerprint']
        private = evidence.details(finding(fp), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual({m['value'] for m in private['matches']}, {access, secret, access + ':' + secret})
        complete = next(m for m in private['matches'] if m['value'] == secret)
        self.assertEqual(complete['locations'][0]['line'], 2)
        self.assertEqual(complete['locations'][0]['path'], 'app/config.env')
        self.assertNotIn(access, json.dumps(sink.document()))
        self.assertNotIn(secret, json.dumps(sink.document()) + json.dumps(public))
        self.assertEqual(self.cipher.decrypt(sink.records[fp])['value'], access)

    def test_nonverbatim_complete_detector_match_is_preserved_with_unknown_line(self):
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            with evidence.source_context(resource_id=ARN):
                evidence.remember_full_match('primary', 'complete-decoded-pair', payload=b'encoded source', path='source.txt', engine='trufflehog', rule='composite')
                evidence.remember('primary', scanning._fingerprint('primary'), path='source.txt', engine='trufflehog', rule='composite')
        result = evidence.details(finding(scanning._fingerprint('primary')), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        complete = next(m for m in result['matches'] if m['value'] == 'complete-decoded-pair')
        self.assertIsNone(complete['locations'][0]['line'])
        self.assertEqual(complete['locations'][0]['location_kind'], 'detector_composite')
        self.assertIsNone(complete['locations'][0]['path'])
        self.assertEqual(complete['locations'][0]['detector_input_path'], 'source.txt')

    def test_one_public_primary_keeps_multiple_complete_observed_pairs_without_identity_conflict(self):
        access = 'AKIA' + '7MQ2ZR9WL4CV8NK1'
        first, second = '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT1vW8', '8nR3aS0xM5dW9pL2tG7bJ4kQ6vE1yC3zF0sU2wX9'
        payload = (access + '\n' + first + '\n' + access + '\n' + second).encode()
        output = b'\n'.join(json.dumps({'Raw': access, 'RawV2': access + ':' + value,
            'Verified': False, 'DetectorName': 'AWS'}).encode() for value in (first, second))
        with patch.object(scanning, '_scan_kingfisher', return_value=[]), patch.object(scanning, '_trufflehog', return_value='synthetic'), patch.object(scanning, '_run', return_value=output):
            baseline = scanning.scan_content(payload, '/app/aws.env')
            with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
                with evidence.source_context(resource_id=ARN):
                    result = scanning.scan_content(payload, '/app/aws.env')
        self.assertEqual(result, baseline)
        self.assertEqual(len(result['leaks']), 1)
        fp = result['leaks'][0]['fingerprint']
        private = evidence.details(finding(fp), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual({row['value'] for row in private['matches']}, {access, first, second, access + ':' + first, access + ':' + second})
        self.assertEqual(self.cipher.decrypt(sink.records[fp])['value'], access)
        for value, line in ((first, 2), (second, 4)):
            row = next(row for row in private['matches'] if row['value'] == value)
            self.assertEqual(row['locations'][0]['line'], line)

    def test_rawv2_components_redact_public_paths_and_metadata_even_when_capture_is_full(self):
        access, secret = 'AKIA' + '7MQ2ZR9WL4CV8NK1', '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT1vW8'
        output = json.dumps({'Raw': access, 'RawV2': access + ':' + secret, 'Verified': False, 'DetectorName': 'AWS'}).encode()
        with patch.object(scanning, '_scan_kingfisher', return_value=[]), patch.object(scanning, '_trufflehog', return_value='synthetic'), patch.object(scanning, '_run', return_value=output):
            for full in (False, True):
                with self.subTest(capture_full=full), ExitStack() as context:
                    scanning._RESULTS.clear()
                    if full:
                        context.enter_context(patch.object(evidence, 'MAX_VALUE_BYTES', 3))
                        sink = context.enter_context(evidence.capture(self.cipher))
                    redactions = set()
                    public = scanning.scan_content((access + '\n' + secret).encode(), '/app/' + secret + '.env', _redact_values=redactions.update)
                    self.assertEqual(len(public['leaks']), 1)
                    self.assertEqual(public['leaks'][0]['fingerprint'], scanning._fingerprint(access))
                    # Found values stay visible: nothing is redacted and the path is kept.
                    self.assertEqual(redactions, set())
                    self.assertIn(secret, json.dumps(public))
                    self.assertNotIn(secret, repr(scanning._RESULTS))
                    if full:
                        self.assertTrue(sink.incomplete)
                        self.assertFalse(sink.records)

    def test_cached_image_layer_retains_all_linked_components_at_each_image_origin(self):
        access, secret = 'AKIA' + '7MQ2ZR9WL4CV8NK1', '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT1vW8'
        fp = scanning._fingerprint(access)
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            with evidence.source_context(resource_id='image-one', layer='sha256:layer', image_digest='sha256:one'):
                evidence.remember_full_match(access, access + ':' + secret, payload=(access + '\n' + secret).encode(), path='/app/config', engine='trufflehog', rule='AWS')
                evidence.remember(access, fp, path='/app/config', line=1, engine='trufflehog', rule='AWS')
            evidence.reuse_image_layer([{'fingerprint': fp}], resource_id='image-two', layer='sha256:layer', image_digest='sha256:two')
        canonical = [{'resource_id': ident, 'path': '/app/config', 'layer': 'sha256:layer', 'line': 1} for ident in ('image-one', 'image-two')]
        result = evidence.details(finding(fp, resource_id='secret:' + fp, native_resource_id=None, evidence={'secret_leaks': [{'fingerprint': fp, 'locations': canonical}]}), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual(len(result['matches']), 3)
        for match in result['matches']:
            self.assertEqual({loc['resource_id'] for loc in match['locations']}, {'image-one', 'image-two'})
        self.assertEqual(self.cipher.decrypt(sink.records[fp])['value'], access)

    def test_reference_literals_do_not_fabricate_resolved_values(self):
        references = ['arn:aws:secretsmanager:us-east-1:123456789012:secret:db-Q123',
                      'projects/project/secrets/db/versions/latest',
                      'https://fixture.vault.azure.net/secrets/db/version', '${DB_PASSWORD}']
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            for value in references:
                evidence.named_environment({'Variables': {'DB_PASSWORD': value}}, provider='aws', resource_id=ARN)
        self.assertFalse(sink.records)

    def test_private_resource_index_survives_different_collector_and_api_hmac_keys(self):
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            evidence.named_environment({'Variables': {'DB_PASSWORD': VALUE}}, provider='aws', resource_id=ARN)
        document = sink.document()
        with patch.object(scanning, '_KEY', b'independent-api-process-key'):
            result = evidence.details(finding(), document, self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual(result['matches'][0]['value'], VALUE)

    def test_url_userinfo_preserves_observed_percent_encoding_not_reference(self):
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            evidence.url_credentials('https://user:synthetic%21token@bitbucket.org/x', resource_id=ARN, path='source.location', check_id='aws.c2b.codebuild.source_url_no_credentials')
        result = evidence.details(finding(check_id='aws.c2b.codebuild.source_url_no_credentials'), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual(result['matches'][0]['value'], 'synthetic%21token')
        self.assertEqual(result['matches'][0]['locations'][0]['path'], 'source.location')

    def test_legacy_join_is_bound_to_observed_check_not_just_same_resource(self):
        package = 'aws.review.lambda_function.package_content_secret_indicators'
        config = 'aws.review.lambda.configuration_secret_indicators'
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            for check, value, path in [(package, VALUE, '/app/config.py'), (config, 'unrelated-configuration-Q12!', 'Environment.Variables')]:
                with evidence.source_context(resource_id=ARN, check_ids={check}):
                    evidence.remember(value, scanning._fingerprint(value), path=path, line=2, engine='configuration', rule='password_assignment')
        result = evidence.details(finding(check_id=package), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual([m['value'] for m in result['matches']], [VALUE])
        self.assertEqual(result['matches'][0]['locations'][0]['path'], '/app/config.py')
        self.assertEqual(evidence.details(finding(check_id=config), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)['matches'][0]['value'], 'unrelated-configuration-Q12!')

    def test_legacy_archive_pattern_keeps_actual_member_path_without_engine_positive(self):
        from peaso.collectors.aws_package_content_indicators import _scan
        from types import SimpleNamespace
        self.engines([])
        check = 'aws.review.lambda_function.package_content_secret_indicators'
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            with evidence.source_context(resource_id=ARN, check_ids={check}):
                public = _scan(('line1\nDB_PASSWORD="' + VALUE + '"').encode(), 'src/private/config.py', SimpleNamespace(check_deadline=lambda: None))
        self.assertEqual(public[0]['Leaks'], [])
        self.assertIn('password_assignment', public[0]['Categories'])
        result = evidence.details(finding(check_id=check), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual(result['matches'][0]['value'], VALUE)
        self.assertEqual(result['matches'][0]['locations'][0]['path'], 'src/private/config.py')
        self.assertEqual(result['matches'][0]['locations'][0]['line'], 2)

    def test_datapipeline_pattern_retains_original_field_instead_of_flattened_json_line(self):
        from peaso.collectors.aws_configuration_payload_secret_indicators import project_response
        native = {'pipelineObjects': [{'id': 'object-1', 'name': 'fixture', 'fields': [{'key': 'DB_PASSWORD', 'stringValue': VALUE}]}]}
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            public = project_response(native, service='datapipeline', operation='get_pipeline_definition', arguments={'pipelineId': 'df-fixture', 'version': 'latest'}, region='us-east-1')
        self.assertTrue(public['PayloadSecretIndicators']['HighConfidenceSecretPresent'])
        result = evidence.details(finding(check_id='aws.review.datapipeline_pipeline.payload_secret_indicators', resource_id='df-fixture', native_resource_id='df-fixture', scope='us-east-1'), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual(result['matches'][0]['value'], VALUE)
        location = result['matches'][0]['locations'][0]
        self.assertEqual(location['field'], '$["pipelineObjects"][0]["fields"][0]["stringValue"]')
        self.assertEqual(location['path'], 'DataPipelineDefinition')
        self.assertIsNone(location['line'])

    def test_fingerprint_and_related_locations_require_exact_canonical_scope_resource_and_check(self):
        fp = scanning._fingerprint(VALUE)
        first_check = 'aws.review.lambda_function.package_content_secret_indicators'
        other_check = 'aws.review.lambda.configuration_secret_indicators'
        other = ARN.replace('123456789012', '999999999999')
        scopes = ('123456789012/us-east-1', '999999999999/us-east-1')
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            for resource, scope, check in ((ARN, scopes[0], first_check), (other, scopes[1], other_check)):
                with evidence.source_context(resource_id=resource, scope=scope, check_ids={check}):
                    evidence.remember_full_match(VALUE, VALUE + ':derived-component', payload=VALUE.encode(), path='/app/shared.env', engine='trufflehog', rule='composite')
                    evidence.remember(VALUE, fp, path='/app/shared.env', public_path='/app/shared.env', line=1, engine='trufflehog', rule='composite')
        canonical = [{'resource_id': ARN, 'scope': scopes[0], 'path': '/app/shared.env', 'line': 1}]
        exact = finding(fp, check_id=first_check, evidence={'secret_leaks': [{'fingerprint': fp, 'locations': canonical}]})
        detail = evidence.details(exact, sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual(len(detail['matches']), 2)
        for row in detail['matches']:
            self.assertEqual({loc['resource_id'] for loc in row['locations']}, {ARN})
            self.assertEqual({loc['scope'] for loc in row['locations']}, {scopes[0]})
        canonical.append({'resource_id': other, 'scope': scopes[1], 'path': '/app/shared.env', 'line': 1})
        grouped = dict(exact, resource_id='secret:' + fp, native_resource_id=None, linked_check_ids=[first_check, other_check])
        detail = evidence.details(grouped, sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        for row in detail['matches']:
            self.assertEqual({loc['resource_id'] for loc in row['locations']}, {ARN, other})
        unknown = dict(grouped, evidence={})
        self.assertEqual(evidence.details(unknown, sink.document(), self.cipher, tenant='alice', scan_id=SCAN)['status'], 'unavailable')

    def test_native_workload_hooks_reject_unrelated_routes_kinds_scopes_and_nested_fields(self):
        azure_id = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ContainerInstance/containerGroups/app'
        valid = {'id': azure_id, 'type': 'Microsoft.ContainerInstance/containerGroups',
            'properties': {'containers': [{'properties': {'environmentVariables': [{'name': 'MODE', 'value': VALUE}]}}]},
            'metadata': {'environmentVariables': [{'name': 'MODE', 'value': 'unrelated-metadata-value'}]}}
        url = 'https://management.azure.com' + azure_id + '?api-version=2023-05-01'
        with evidence.capture(self.cipher) as sink:
            evidence.native_environment_resources(valid, provider='azure', method='POST', url=url)
            evidence.native_environment_resources(valid, provider='azure', method='GET', url=url.replace('Microsoft.ContainerInstance/containerGroups', 'Microsoft.Compute/virtualMachines'))
            evidence.native_environment_resources(dict(valid, type='Microsoft.Compute/virtualMachines'), provider='azure', method='GET', url=url)
            evidence.native_environment_resources(dict(valid, id=azure_id.replace('/sub/', '/other/')), provider='azure', method='GET', url=url)
            evidence.pod_environment({'spec': {'containers': [{'env': [{'name': 'PASSWORD', 'value': VALUE}]}]}}, kind='config_map', resource_id='not-pod', scope='ns')
        self.assertFalse(sink.records)
        untouched = {'unrelated': VALUE}
        self.assertIs(sink.public_snapshot(untouched), untouched)
        with evidence.capture(self.cipher) as sink:
            evidence.native_environment_resources(valid, provider='azure', method='GET', url=url)
        rows = [self.cipher.decrypt(row) for row in sink.records.values()]
        self.assertEqual([row['value'] for row in rows], [VALUE])
        self.assertEqual(rows[0]['locations'][0]['path'], 'properties.containers[0].properties.environmentVariables[0].value')
        self.assertEqual(rows[0]['check_ids'], ['azure.claude.container_group_secure_environment_variables'])

    def test_gcp_native_workload_hook_uses_only_exact_function_or_run_env_fields(self):
        scope = 'projects/fixture'
        identity = scope + '/locations/us-east1/functions/app'
        raw = {'functions': [{'name': identity, 'serviceConfig': {'environmentVariables': {'DB_PASSWORD': VALUE}},
            'metadata': {'environmentVariables': {'DB_PASSWORD': 'unrelated-metadata-value'}}}]}
        url = 'https://cloudfunctions.googleapis.com/v2/' + scope + '/locations/-/functions'
        with evidence.capture(self.cipher) as sink:
            evidence.native_environment_resources(raw, provider='gcp', method='GET', url=url, scope='projects/other')
            evidence.native_environment_resources(raw, provider='gcp', method='GET', url=url.replace('cloudfunctions.googleapis.com', 'bigquery.googleapis.com'), scope=scope)
            evidence.native_environment_resources(raw, provider='gcp', method='POST', url=url, scope=scope)
        self.assertFalse(sink.records)
        with evidence.capture(self.cipher) as sink:
            evidence.native_environment_resources(raw, provider='gcp', method='GET', url=url, scope=scope)
        rows = [self.cipher.decrypt(row) for row in sink.records.values()]
        self.assertEqual([row['value'] for row in rows], [VALUE])
        self.assertEqual(rows[0]['locations'][0]['path'], 'serviceConfig.environmentVariables["DB_PASSWORD"]')
        self.assertEqual(rows[0]['check_ids'], ['gcp.htbp.function.secret_env_from_secret_manager'])

    def test_native_workload_name_capture_respects_selected_check_and_framework_result(self):
        identity = 'projects/fixture/locations/us-east1/functions/app'
        native = {'functions': [{'name': identity, 'serviceConfig': {'environmentVariables': {'DB_PASSWORD': VALUE}}}]}
        args = {'provider': 'gcp', 'method': 'GET', 'url': 'https://cloudfunctions.googleapis.com/v2/projects/fixture/locations/-/functions', 'scope': 'projects/fixture'}
        for selected in (set(), {'gcp.htbp.function.runtime_no_default_sa'}):
            with self.subTest(selected=selected), evidence.capture(self.cipher, selected_checks=selected) as sink:
                evidence.native_environment_resources(native, **args)
            self.assertFalse(sink.records)
            unchanged = {'label': VALUE}
            self.assertIs(sink.public_snapshot(unchanged), unchanged)
        with evidence.capture(self.cipher, selected_checks={'gcp.htbp.function.secret_env_from_secret_manager'}) as sink:
            evidence.native_environment_resources(native, **args)
        self.assertEqual(len(sink.records), 1)

    def test_native_environment_entries_never_recurse_into_nested_lookalike_fields(self):
        nested = 'unrelated-nested-metadata-value'
        azure_id = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ContainerInstance/containerGroups/app'
        azure = {'id': azure_id, 'type': 'Microsoft.ContainerInstance/containerGroups', 'properties': {'containers': [
            {'properties': {'environmentVariables': [{'name': 'MODE', 'value': VALUE,
                'metadata': {'environmentVariables': [{'name': 'MODE', 'value': nested}]}}]}}]}}
        run_id = 'projects/fixture/locations/us-east1/services/app'
        run = {'name': run_id, 'template': {'containers': [{'env': [{'name': 'DB_PASSWORD', 'value': VALUE,
            'metadata': {'env': [{'name': 'DB_PASSWORD', 'value': nested}]}}]}]}}
        job_id = run_id.replace('/services/', '/jobs/')
        job = {'name': job_id, 'template': {'template': run['template']}}
        function_id = run_id.replace('/services/', '/functions/')
        function = {'name': function_id, 'serviceConfig': {'environmentVariables': {'DB_PASSWORD': VALUE,
            'metadata': {'environmentVariables': {'DB_PASSWORD': nested}}}}}
        for native, kwargs in ((azure, dict(provider='azure', url='https://management.azure.com' + azure_id)),
                (run, dict(provider='gcp', scope='projects/fixture', url='https://run.googleapis.com/v2/' + run_id)),
                (job, dict(provider='gcp', scope='projects/fixture', url='https://run.googleapis.com/v2/' + job_id)),
                (function, dict(provider='gcp', scope='projects/fixture', url='https://cloudfunctions.googleapis.com/v2/' + function_id))):
            with self.subTest(provider=kwargs['provider']), evidence.capture(self.cipher) as sink:
                evidence.native_environment_resources(native, method='GET', **kwargs)
            self.assertEqual([self.cipher.decrypt(row)['value'] for row in sink.records.values()], [VALUE])

    def test_aci_policy_capture_follows_existing_aci_and_pod_rule_and_selected_names(self):
        check = 'azure_aks_cluster_3_5_1_14_247ebcd'
        policy = {'compliance_policy': {'sw26': {check: {'secretKeys': ['CUSTOM_KEY']}}}}
        ident = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ContainerInstance/containerGroups/app'
        for name, expected in (('CUSTOM_KEY', {VALUE}), ('UNSELECTED_NAME', set())):
            native = {'id': ident, 'type': 'Microsoft.ContainerInstance/containerGroups', 'properties': {'containers': [
                {'properties': {'environmentVariables': [{'name': name, 'value': VALUE}]}}]}}
            with self.subTest(name=name), evidence.capture(self.cipher, options=policy, selected_checks={check}) as sink:
                evidence.native_environment_resources(native, provider='azure', method='GET', url='https://management.azure.com' + ident)
            self.assertEqual({self.cipher.decrypt(row)['value'] for row in sink.records.values()}, expected)
            for sealed in sink.records.values():
                self.assertEqual(self.cipher.decrypt(sealed)['check_ids'], [check])

    def test_individual_scope_conflict_is_withheld_without_fallback_and_aggregate_is_explicit(self):
        fp = scanning._fingerprint(VALUE)
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            with evidence.source_context(resource_id=ARN, scope='123456789012/us-east-1'):
                evidence.remember(VALUE, fp, path='config.env', line=1, engine='synthetic', rule='synthetic')
        leak = {'fingerprint': fp, 'locations': [{'resource_id': ARN, 'scope': '123456789012/us-east-1', 'path': 'config.env'}]}
        observed = finding(fp, scope='different-scope', evidence={'secret_leaks': [leak]})
        private = evidence.details(observed, sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual(private['status'], 'unavailable')
        self.assertFalse(private['complete'])
        self.assertEqual(private['matches'], [])
        wrong_resource = dict(observed, scope='123456789012/us-east-1', resource_id='other', native_resource_id='other')
        private = evidence.details(wrong_resource, sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual(private['status'], 'unavailable')
        self.assertFalse(private['complete'])
        aggregate = dict(observed, resource_id='secret:' + fp, native_resource_id=None)
        private = evidence.details(aggregate, sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual(private['status'], 'available')
        self.assertEqual(private['matches'][0]['locations'][0]['scope'], '123456789012/us-east-1')

    def test_encoded_only_pair_keeps_private_detector_provenance_separate_from_public_redaction(self):
        import base64
        primary, component = 'AKIA' + '7MQ2ZR9WL4CV8NK1', '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT1vW8'
        payload = base64.b64encode(('AWS_ACCESS_KEY_ID=' + primary + '\nAWS_SECRET_ACCESS_KEY=' + component).encode())
        raw = json.dumps({'Raw': primary, 'RawV2': primary + ':' + component, 'Verified': False, 'DetectorName': 'AWS'}).encode()
        path = '/app/' + component + '.env'
        with patch.object(scanning, '_scan_kingfisher', return_value=[]), patch.object(scanning, '_trufflehog', return_value='synthetic'), patch.object(scanning, '_run', return_value=raw):
            baseline = scanning.scan_content(payload, path)
            with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
                with evidence.source_context(resource_id=ARN):
                    public = scanning.scan_content(payload, path)
        self.assertEqual(public, baseline)
        # The found component stays visible in the exact detector path.
        self.assertEqual(public['leaks'][0]['locations'], [{'path': path}])
        fp = public['leaks'][0]['fingerprint']
        private = evidence.details(finding(fp, evidence={'secret_leaks': public['leaks']}), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual({match['value'] for match in private['matches']}, {primary, primary + ':' + component})
        kinds = set()
        for match in private['matches']:
            for loc in match['locations']:
                self.assertIsNone(loc['path'])
                self.assertIsNone(loc['line'])
                self.assertEqual(loc['detector_input_path'], path)
                kinds.add(loc['location_kind'])
        self.assertEqual(kinds, {'detector_composite', 'detector_decoded'})
        self.assertNotIn(scanning._fingerprint(component), sink.records)
        self.assertEqual(sink.redactions, {})

    def test_privacy_redaction_capacity_failure_refuses_snapshot_publication(self):
        # Found values are not redacted, so there is no redaction capacity to
        # exceed: the snapshot is published unchanged and nothing is retained.
        with patch.object(evidence, 'MAX_VALUE_BYTES', 3), evidence.capture(self.cipher) as sink:
            evidence.remember_redactions({VALUE})
        self.assertFalse(sink.redaction_incomplete)
        self.assertFalse(sink.incomplete)
        snapshot = {'label': VALUE}
        self.assertIs(sink.public_snapshot(snapshot), snapshot)
        self.assertNotIn(VALUE, json.dumps(sink.document()))

    def test_unbound_shared_path_never_guesses_between_canonical_resource_origins(self):
        fp = scanning._fingerprint(VALUE)
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            with evidence.source_context(resource_id=ARN, scope='123456789012/us-east-1'):
                evidence.remember(VALUE, fp, path='known.env', line=1, engine='trufflehog', rule='synthetic')
            evidence.remember(VALUE, fp, path='shared.env', line=1, engine='trufflehog', rule='synthetic')
        locations = [{'resource_id': ARN, 'path': 'known.env', 'line': 1},
            {'resource_id': 'resource-a', 'path': 'shared.env', 'line': 1}, {'resource_id': 'resource-b', 'path': 'shared.env', 'line': 1}]
        observed = finding(fp, resource_id='secret:' + fp, native_resource_id=None, evidence={'secret_leaks': [{'fingerprint': fp, 'locations': locations}]})
        detail = evidence.details(observed, sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual(detail['status'], 'available')
        self.assertFalse(detail['complete'])
        self.assertEqual([loc['resource_id'] for loc in detail['matches'][0]['locations']], [ARN])

    def test_group_with_unavailable_member_keeps_observed_value_but_is_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            artifacts = FileArtifacts(Path(directory))
            with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
                evidence.named_environment({'Variables': {'DB_PASSWORD': VALUE}}, provider='aws', resource_id=ARN)
            artifacts.put_secret_evidence('alice', SCAN, sink.document())
            other = ARN.replace(':fixture', ':not-observed')
            detail = evidence.load_group_details(artifacts, self.cipher, 'alice', SCAN,
                [finding(), finding(resource_id=other, native_resource_id=other)])
        self.assertEqual(detail['status'], 'available')
        self.assertFalse(detail['complete'])
        self.assertEqual([row['value'] for row in detail['matches']], [VALUE])
        self.assertEqual({loc['resource_id'] for row in detail['matches'] for loc in row['locations']}, {ARN})

    def test_known_resource_with_unknown_layer_or_scope_never_picks_first_origin(self):
        fp = scanning._fingerprint(VALUE)
        check = 'aws.review.ecr_repository.package_content_secret_indicators'
        for field in ('layer', 'scope'):
            with self.subTest(field=field), evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
                with evidence.source_context(resource_id=ARN, check_ids={check}):
                    evidence.remember(VALUE, fp, path='/app/shared.env', line=1, engine='synthetic', rule='synthetic')
            canonical = [dict(resource_id=ARN, path='/app/shared.env', **{field: value}) for value in ('first', 'second')]
            observed = finding(fp, check_id=check, scope=None, evidence={'secret_leaks': [{'fingerprint': fp, 'locations': canonical}]})
            detail = evidence.details(observed, sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
            self.assertEqual(detail['status'], 'unavailable')
            self.assertEqual(detail['matches'], [])
            self.assertFalse(detail['complete'])

    def test_native_lambda_list_preserves_literal_for_only_actual_lambda_name_check(self):
        from peaso.collectors.aws_configuration_secret_indicators import lambda_indicators
        native = {'FunctionArn': ARN, 'FunctionName': 'fixture', 'Environment': {'Variables': {
            'DB_PASSWORD': VALUE, 'AWS_ACCESS_KEY_ID': 'not-a-lambda-name-witness'}}}
        baseline = lambda_indicators(native, 'lambda:ListFunctions')
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            result = lambda_indicators(native, 'lambda:ListFunctions')
        self.assertEqual(result, baseline)
        self.assertEqual(len(sink.records), 1)
        private = evidence.details(finding(), sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual(private['matches'][0]['value'], VALUE)
        self.assertEqual(private['matches'][0]['locations'][0]['path'], 'Environment.Variables["DB_PASSWORD"]')
        other = finding(check_id='aws.nist.codebuild_exact_aws_key_env_names')
        self.assertEqual(evidence.details(other, sink.document(), self.cipher, tenant='alice', scan_id=SCAN)['status'], 'unavailable')

    def test_native_ecs_name_witness_retains_container_and_exact_name_selector(self):
        from peaso.collectors.aws_additional_secret_indicators import _scan
        arn = 'arn:aws:ecs:us-east-1:123456789012:task-definition/fixture:1'
        groups = [[('MODE', 'production')], [('AWS_SECRET_ACCESS_KEY', VALUE)]]
        args = ('ecs_task_definition', arn, groups, 'us-east-1', 'ecs:DescribeTaskDefinition', 'plaintext_environment')
        baseline = _scan(*args, arn=arn)
        with evidence.capture(self.cipher, tenant='alice', scan_id=SCAN) as sink:
            result = _scan(*args, arn=arn)
        self.assertEqual(result, baseline)
        observed = finding(check_id='aws.c2b.ecs.no_credential_named_env_vars', resource_id=arn, native_resource_id=arn)
        private = evidence.details(observed, sink.document(), self.cipher, tenant='alice', scan_id=SCAN)
        self.assertEqual(private['matches'][0]['value'], VALUE)
        loc = private['matches'][0]['locations'][0]
        self.assertEqual(loc['path'], 'containerDefinitions[1].environment[name="AWS_SECRET_ACCESS_KEY"].value')
        self.assertIsNone(loc['line'])
        other = dict(observed, check_id='aws.nist.codebuild_exact_aws_key_env_names')
        self.assertEqual(evidence.details(other, sink.document(), self.cipher, tenant='alice', scan_id=SCAN)['status'], 'unavailable')


if __name__ == '__main__':
    unittest.main()
