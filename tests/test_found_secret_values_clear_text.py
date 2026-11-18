"""Found secrets reach the finding evidence in clear text so the tenant can rotate them."""
import json

import pytest

from peaso import secret_evidence as evidence
from peaso import secret_scanning as scanning
from peaso.secret_findings import deduplicate_secret_findings
from peaso.snapshot import make_snapshot, validate

SECRET = 'amp_live_' + 'Q7w2E9r4T6y1U8i3O5p0'
SCOPE = '123456789012/us-east-1'
REPO = 'arn:aws:ecr:us-east-1:123456789012:repository/cade/frontend'
CHUNK = 'app/apps/frontend/.next/static/chunks/0sf186v8dn5t6.js'
PAYLOAD = ('self.__next_f.push([1,"x"]);\n'
           'var amp=init({apiKey:"' + SECRET + '",serverZone:"EU"});render(amp);\n').encode()


@pytest.fixture(autouse=True)
def detectors(monkeypatch):
    scanning._RESULTS.clear()
    def kingfisher(payload, path, timeout):
        return [(value, 'betterleaks.amplitude-secret-key', 2) for value in (SECRET, LONG) if value.encode() in payload]
    monkeypatch.setattr(scanning, '_scan_kingfisher', kingfisher)
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *args: [])
    yield
    scanning._RESULTS.clear()


LONG = 'k' * (evidence.PUBLIC_VALUE_CHARS + 50)


def fail(leaks, resource, check='aws.review.ecr_repository.package_content_secret_indicators'):
    return {'provider': 'aws', 'check_id': check, 'scope': SCOPE, 'resource_id': resource,
            'native_resource_id': resource, 'status': 'FAIL', 'frameworks': [], 'finding_type': 'secrets',
            'evidence': {'secret_leaks': leaks, 'credential_validation': 'not_attempted'}}


def published(sink):
    """The snapshot a scan publishes, round-tripped through JSON like the stored artifact."""
    snapshot = make_snapshot('aws', [SCOPE], [], created_at='2026-11-18T00:00:00Z')
    snapshot = validate(snapshot, **evidence.secret_values_entry(sink))
    return validate(json.loads(json.dumps(snapshot)), read_only=True)


def test_grouped_secret_finding_shows_value_and_context_from_every_location():
    with evidence.capture(evidence.EphemeralCipher()) as sink:
        first = scanning.scan_content(PAYLOAD, CHUNK)['leaks']
        second = scanning.scan_content(b'AMPLITUDE_KEY=' + SECRET.encode(), 'app/.env')['leaks']
    findings = [fail(first, REPO), fail(second, REPO.replace('frontend', 'lander'))]
    result = deduplicate_secret_findings(findings, evidence.snapshot_secret_values(published(sink)))
    assert len(result) == 1
    leak, = result[0]['evidence']['secret_leaks']
    assert leak['value'] == SECRET
    assert 'value_truncated' not in leak
    assert leak['context'] == 'var amp=init({apiKey:"' + SECRET + '",serverZone:"EU"});render(amp);'
    assert {loc['path'] for loc in leak['locations']} == {CHUNK, 'app/.env'}
    observed = result[0]['evidence']['observed']
    assert 'hidden' not in observed and 'clear text' in observed
    assert result[0]['evidence_summary'] == observed


def test_long_value_is_bounded_not_dropped():
    with evidence.capture(evidence.EphemeralCipher()) as sink:
        leaks = scanning.scan_content(b'token=' + LONG.encode(), 'app/token.txt')['leaks']
    leak, = deduplicate_secret_findings([fail(leaks, REPO)], evidence.snapshot_secret_values(published(sink)))[0]['evidence']['secret_leaks']
    assert leak['value'] == LONG[:evidence.PUBLIC_VALUE_CHARS] and leak['value_truncated'] is True


def test_value_restored_from_a_prior_attempts_private_records():
    with evidence.capture(evidence.EphemeralCipher()) as sink:
        leaks = scanning.scan_content(PAYLOAD, CHUNK)['leaks']
        sink.public_values.clear()  # A reclaimed attempt restores only the encrypted records.
    leak, = deduplicate_secret_findings([fail(leaks, REPO)], evidence.snapshot_secret_values(published(sink)))[0]['evidence']['secret_leaks']
    assert leak['value'] == SECRET


def test_scan_without_retained_values_says_so_instead_of_hiding():
    leaks = scanning.scan_content(PAYLOAD, CHUNK)['leaks']
    row, = deduplicate_secret_findings([fail(leaks, REPO)])
    assert 'value' not in row['evidence']['secret_leaks'][0]
    assert 'hidden' not in row['evidence']['observed']


def test_ai_workspace_files_omit_found_values(tmp_path):
    from peaso.ai.pipeline import private_json
    with evidence.capture(evidence.EphemeralCipher()) as sink:
        leaks = scanning.scan_content(PAYLOAD, CHUNK)['leaks']
    values = evidence.snapshot_secret_values(published(sink))
    row, = deduplicate_secret_findings([fail(leaks, REPO)], values)
    assert SECRET in json.dumps(row)
    private_json(tmp_path / 'findings.json', {'findings': [row], 'metadata': {evidence.SNAPSHOT_VALUES_KEY: values}})
    written = (tmp_path / 'findings.json').read_text()
    assert SECRET not in written and row['secret_fingerprint'] in written
