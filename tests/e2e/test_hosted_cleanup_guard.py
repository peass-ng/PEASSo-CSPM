import pytest

from scripts.peaso_test_resources.hosted_data_cleanup import validate_record


JOB = 'a' * 32
OTHER_JOB = 'b' * 32
CHECKPOINT = 'c' * 64


def record(key, subject='fixture', status='completed'):
    return {'PK': {'S': 'tenant/' + subject}, 'SK': {'S': key}, 'status': {'S': status}}


@pytest.mark.parametrize('key', [f'scan_checkpoint/{JOB}/{CHECKPOINT}', f'scan_stage/{JOB}/network',
                                 f'job/{JOB}', 'ai/configuration_error'])
def test_cleanup_accepts_only_bound_scan_data(key):
    validate_record(record(key), 'fixture', {JOB})


@pytest.mark.parametrize('key', [f'scan_checkpoint/{OTHER_JOB}/{CHECKPOINT}', f'scan_stage/{OTHER_JOB}/network',
                                 f'scan_checkpoint/{JOB}', 'ai/auth'])
def test_cleanup_rejects_unknown_scan_or_credential_data(key):
    with pytest.raises(RuntimeError):
        validate_record(record(key), 'fixture', {JOB})


def test_cleanup_rejects_active_jobs_and_foreign_subjects():
    with pytest.raises(RuntimeError, match='still active'):
        validate_record(record(f'job/{JOB}', status='analyzing'), 'fixture', {JOB})
    with pytest.raises(RuntimeError, match='subject mismatch'):
        validate_record(record(f'scan_stage/{JOB}/network', subject='another-tenant'), 'fixture', {JOB})
