"""Current PodSpec leaf verdicts and customer copy use the same native fact."""
from __future__ import annotations

import pytest

from peaso.engine import evaluate_snapshot
from peaso.finding_observation import evidence_summary
from peaso.snapshot import make_snapshot
from peaso.checks.k8s_workload_finding_summary import pod_level_observation


def finding(cid, spec):
    snapshot = make_snapshot('k8s', ['*'], [{
        'type': 'pod', 'scope': '*', 'status': 'collected',
        'items': [{'metadata': {'name': 'workload', 'namespace': 'apps'}, 'spec': spec}],
    }], created_at='2026-10-17T00:00:00Z')
    rows = [row for row in evaluate_snapshot(snapshot, checks=[cid])['findings']
            if row['check_id'] == cid]
    assert len(rows) == 1
    return rows[0]


@pytest.mark.parametrize('cid,spec,status,first', [
    ('k8s.ports.pod.host_namespaces', {'hostPID': True}, 'FAIL', 'The PodSpec declares hostPID=true.'),
    ('k8s.ports.pod.host_namespaces', {}, 'PASS', 'The PodSpec declares hostPID=false and hostIPC=false.'),
    ('k8s.ports.pod.host_namespaces', {'_coverage': {'hostIPC': {'status': 'denied'}}},
     'UNKNOWN', 'The PodSpec hostIPC declaration was unavailable.'),
    ('k8s.ports.pod.host_network', {'hostNetwork': True}, 'FAIL', 'The PodSpec declares hostNetwork=true.'),
    ('k8s.ports.pod.host_network', {'hostNetwork': False}, 'PASS', 'The PodSpec declares hostNetwork=false.'),
    ('k8s.ports.pod.host_network', {'_coverage': {'hostNetwork': {'status': 'denied'}}},
     'UNKNOWN', 'The PodSpec hostNetwork declaration was unavailable or malformed.'),
    ('k8s.ports.pod.explicit_serviceaccount', {}, 'FAIL', 'The PodSpec declares no ServiceAccount name.'),
    ('k8s.ports.pod.explicit_serviceaccount', {'serviceAccountName': 'app'},
     'PASS', 'The PodSpec declares ServiceAccount “app”.'),
    ('k8s.ports.pod.explicit_serviceaccount', {'serviceAccountName': 7},
     'UNKNOWN', 'The PodSpec serviceAccountName declaration was unavailable or malformed.'),
    ('k8s.ports.pod.pod_runtime_default_seccomp', {},
     'FAIL', 'The PodSpec declares no Pod-level seccomp profile.'),
    ('k8s.ports.pod.pod_runtime_default_seccomp',
     {'securityContext': {'seccompProfile': {'type': 'RuntimeDefault'}}},
     'PASS', 'The PodSpec declares seccompProfile.type=RuntimeDefault.'),
    ('k8s.ports.pod.pod_runtime_default_seccomp',
     {'_coverage': {'securityContext': {'status': 'denied'}}},
     'UNKNOWN', 'The PodSpec seccompProfile declaration was unavailable or malformed.'),
])
def test_pod_level_fact_and_three_line_observation(cid, spec, status, first):
    spec = {**spec, '_coverage': {**spec.get('_coverage', {}),
                                 'containers': {'status': 'denied'}}}
    row = finding(cid, spec)
    assert row['status'] == status
    lines = evidence_summary(row).splitlines()
    assert len(lines) == 3
    assert lines[0] == first
    assert all(line.endswith('.') and 0 < len(line) < 170 for line in lines)
    assert not any(word in line.lower() for line in lines
                   for word in ('the check', 'the scan', 'the result', 'runtime enforcement was not tested'))
    assert any('may' in line or 'could' in line for line in lines[1:])


@pytest.mark.parametrize('cid', [
    'k8s.ports.pod.host_namespaces', 'k8s.ports.pod.host_network',
    'k8s.ports.pod.explicit_serviceaccount',
    'k8s.ports.pod.pod_runtime_default_seccomp',
])
def test_unexpected_or_absent_reason_never_invents_a_declaration(cid):
    base = {'provider': 'k8s', 'check_id': cid, 'status': 'UNKNOWN'}
    assert pod_level_observation({**base, 'evidence': {}}) is None
    assert pod_level_observation({**base, 'evidence': {'reason': '\nmalformed'}}) is None
    lines = pod_level_observation({**base, 'evidence': {'reason': 'missing fact: spec'}}).splitlines()
    assert len(lines) == 3 and lines[1] == 'The recorded reason was “missing fact: spec”.'
    assert 'could expose' not in lines[2]


def test_container_specific_fact_still_needs_readable_containers():
    row = finding('k8s.ports.pod.cpu_limit',
                  {'_coverage': {'containers': {'status': 'denied'}}})
    assert row['status'] == 'UNKNOWN'
    assert row['evidence']['reason'] == 'fact unavailable or malformed coverage: containers'


def test_unvalidated_service_account_value_is_not_inserted():
    row = {'provider': 'k8s', 'check_id': 'k8s.ports.pod.explicit_serviceaccount',
           'status': 'PASS', 'evidence': {'declared_service_account': 'bad\nvalue'}}
    assert pod_level_observation(row) is None
