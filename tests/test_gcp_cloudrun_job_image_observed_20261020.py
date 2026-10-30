"""Typed copy from accepted actual native/public Job image witnesses only."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from peaso.checks.gcp_cloudrun_job_image_observed_20261020 import observation, UNKNOWN

FIXTURE = Path(__file__).with_name('fixtures') / 'gcp-cloudrun-job-image-observed-20261020.json'
CAPTURE = json.loads(FIXTURE.read_text())
RECORDS = {r['name']: r['finding'] for r in CAPTURE['records']}


@pytest.mark.parametrize('name', ['native_pass', 'native_fail', 'native_partial_fail', 'public_fail', 'public_partial_fail'])
def test_status_does_not_manufacture_clean_evidence(name):
    finding = deepcopy(RECORDS[name])
    finding['status'] = 'FAIL' if finding['status'] == 'PASS' else 'PASS'
    assert observation(finding) == UNKNOWN


@pytest.mark.parametrize('fault', ['scope', 'image_tag', 'runtime_digest', 'deployed_claim', 'kind', 'uid',
    'container', 'source_path', 'generation', 'detectors', 'version', 'layers', 'requests', 'credential_validation'])
def test_native_fields_must_be_typed_and_bound(fault):
    f = deepcopy(RECORDS['native_pass'])
    e = f['evidence']
    if fault == 'scope': f['scope'] = 'projects/foreign'
    elif fault == 'image_tag': e['image_uri'] = 'us-central1-docker.pkg.dev/review/images/app:latest'
    elif fault == 'runtime_digest': e['observed_runtime_digest'] = 'sha256:' + '0' * 64
    elif fault == 'deployed_claim': e['deployed_bytes_proven'] = True
    elif fault == 'kind': e['job_declaration']['kind'] = 'Execution'
    elif fault == 'uid': e['job_declaration']['uid'] = 'wrong'
    elif fault == 'container': e['job_declaration']['container_name'] = ''
    elif fault == 'source_path': e['job_declaration']['image_json_pointer'] = '/status/imageDigest'
    elif fault == 'generation': e['job_declaration']['generation'] = 8
    elif fault == 'detectors': e['config_engines'][0]['status'] = 'unavailable'
    elif fault == 'version': e['config_engines'][0]['version'] = 'unknown'
    elif fault == 'layers': e['layer_coverage'][0]['status'] = 'unavailable'
    elif fault == 'requests': e['source_requests'].append(e['source_requests'][0])
    else: e['credential_validation'] = 'validated'
    assert observation(f) == UNKNOWN


@pytest.mark.parametrize('fault', ['fingerprint', 'linked_check', 'resource', 'scope', 'location_scope', 'location_resource',
    'layer', 'path', 'line', 'raw_value', 'detector', 'complete', 'coverage', 'empty_leaks'])
def test_actual_public_projection_never_invents_missing_native_parts(fault):
    f = deepcopy(RECORDS['public_fail'])
    e = f['evidence']
    leak = e['secret_leaks'][0]
    if fault == 'fingerprint': f['secret_fingerprint'] = '0' * 64
    elif fault == 'linked_check': f['linked_check_ids'].append('another-check')
    elif fault == 'resource': f['resource_id'] = 'not-a-secret'
    elif fault == 'scope': f['scope'] = 'projects/foreign'
    elif fault == 'location_scope': leak['locations'][0]['scope'] = 'projects/foreign'
    elif fault == 'location_resource': leak['locations'][0]['resource_id'] = 'projects/review/locations/us-central1/services/api'
    elif fault == 'layer': leak['locations'][0]['layer'] = 'tag:latest'
    elif fault == 'path': leak['locations'][0]['path'] = 'invented.txt'
    elif fault == 'line': leak['locations'][0]['line'] = -1
    elif fault == 'raw_value': leak['value'] = 'never-render-this'
    elif fault == 'detector': leak['detectors'][0]['engine'] = 'invented'
    elif fault == 'complete': e['complete'] = 'true'
    elif fault == 'coverage': e['coverage'] = 'incomplete'
    else: e['secret_leaks'] = []
    assert observation(f) == UNKNOWN
    assert 'parts' not in e


@pytest.mark.parametrize('field,value', [('provider', 'aws'), ('check_id', 'gcp.review.other'), ('status', 'MANUAL')])
def test_other_findings_are_untouched(field, value):
    f = deepcopy(RECORDS['native_pass'])
    f[field] = value
    assert observation(f) is None
