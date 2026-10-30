"""Brief, non-secret observations for reviewed workload and RBAC findings."""
from .k8s_workload_clarity_reviewed import ROWS


_POD_LEVEL_IDS = {
    'k8s.ports.pod.host_namespaces',
    'k8s.ports.pod.host_network',
    'k8s.ports.pod.explicit_serviceaccount',
    'k8s.ports.pod.pod_runtime_default_seccomp',
}


def _unknown_pod_level(cid, reason):
    reason = _text(reason)
    if reason is None:
        return None
    if cid.endswith('.host_namespaces'):
        missing = reason.removeprefix('host namespace declaration unavailable: ')
        if missing in ('hostPID', 'hostIPC', 'hostPID, hostIPC'):
            return (f'The PodSpec {missing} declaration was unavailable.',
                    'The workload may share a host process or shared-memory namespace.',
                    'That could expose host details if sharing is enabled.')
        field = 'hostPID or hostIPC'
    elif cid.endswith('.host_network'):
        field = 'hostNetwork'
        if reason in ('fact unavailable or malformed coverage: hostNetwork', 'malformed fact: hostNetwork'):
            return (f'The PodSpec {field} declaration was unavailable or malformed.',
                    'The workload may share the node’s network namespace if this setting is enabled.',
                    'That could expose node network ports or traffic.')
    elif cid.endswith('.explicit_serviceaccount'):
        field = 'serviceAccountName'
        if reason in ('fact unavailable or malformed coverage: serviceAccountName', 'malformed service account name'):
            return (f'The PodSpec {field} declaration was unavailable or malformed.',
                    'The workload may use a named or default ServiceAccount.',
                    'Its permissions could affect access to other resources.')
    else:
        field = 'seccompProfile'
        if reason in ('fact unavailable or malformed coverage: securityContext',
                      'fact unavailable or malformed coverage: seccompProfile',
                      'unknown seccomp profile type'):
            return (f'The PodSpec {field} declaration was unavailable or malformed.',
                    'The workload may have fewer system-call restrictions.',
                    'A container override could also change the effective restriction.')
    return (f'The PodSpec {field} declaration could not be determined.',
            f'The recorded reason was “{reason}”.',
            f'The {field} setting remains unclear from that fact.')


def pod_level_observation(finding):
    """Explain only recorded PodSpec declarations affected by leaf authority."""
    if (not isinstance(finding, dict) or finding.get('provider') != 'k8s'
            or finding.get('check_id') not in _POD_LEVEL_IDS
            or finding.get('status') not in ('PASS', 'FAIL', 'UNKNOWN')
            or not isinstance(finding.get('evidence'), dict)):
        return None
    cid, status, evidence = finding['check_id'], finding['status'], finding['evidence']
    lines = None
    if status == 'UNKNOWN':
        lines = _unknown_pod_level(cid, evidence.get('reason'))
    elif cid.endswith('.host_namespaces'):
        pid, ipc = evidence.get('hostPID'), evidence.get('hostIPC')
        if status == 'FAIL' and (pid is True or ipc is True):
            if pid is True and ipc is True:
                lines = ('The PodSpec declares hostPID=true and hostIPC=true.',
                         'The workload may share the node’s process and shared-memory namespaces.',
                         'That could expose host process and shared-memory details to the workload.')
            elif pid is True:
                lines = ('The PodSpec declares hostPID=true.',
                         'The workload may share the node’s process namespace.',
                         'That could expose host process details to the workload.')
            else:
                lines = ('The PodSpec declares hostIPC=true.',
                         'The workload may share the node’s shared-memory namespace.',
                         'That could expose host shared-memory details to the workload.')
        elif status == 'PASS' and pid is False and ipc is False:
            lines = ('The PodSpec declares hostPID=false and hostIPC=false.',
                     'These settings call for separate process and shared-memory namespaces.',
                     'That may reduce the workload’s access to host process and shared-memory details.')
    elif cid.endswith('.host_network') and type(evidence.get('hostNetwork')) is bool:
        if status == 'FAIL' and evidence['hostNetwork'] is True:
            lines = ('The PodSpec declares hostNetwork=true.',
                     'The workload may share the node’s network namespace.',
                     'That could expose node network ports or traffic to the workload.')
        elif status == 'PASS' and evidence['hostNetwork'] is False:
            lines = ('The PodSpec declares hostNetwork=false.',
                     'This setting calls for a network namespace separate from the node.',
                     'That may limit the workload’s access to node network traffic.')
    elif cid.endswith('.explicit_serviceaccount'):
        value = evidence.get('declared_service_account')
        safe_value = _text(value)
        if status == 'PASS' and safe_value:
            lines = (f'The PodSpec declares ServiceAccount “{safe_value}”.',
                     'The workload may use this identity for Kubernetes API requests.',
                     'Its assigned permissions could allow access to other resources.')
        elif status == 'FAIL' and 'declared_service_account' in evidence and value in (None, ''):
            lines = ('The PodSpec declares no ServiceAccount name.',
                     'The workload may use the namespace’s default ServiceAccount.',
                     'That identity could have permissions shared with other workloads.')
    elif cid.endswith('.pod_runtime_default_seccomp'):
        value = evidence.get('declared_pod_profile')
        if status == 'PASS' and value == 'RuntimeDefault':
            lines = ('The PodSpec declares seccompProfile.type=RuntimeDefault.',
                     'This profile may restrict system calls available to the workload.',
                     'A container override could change the effective restriction.')
        elif status == 'FAIL' and 'declared_pod_profile' in evidence and value in (None, 'Localhost', 'Unconfined'):
            declaration = ('no Pod-level seccomp profile' if value is None else
                           f'seccompProfile.type={value}')
            lines = (f'The PodSpec declares {declaration}.',
                     'The workload may have fewer system-call restrictions.',
                     'A compromised process could have more ways to affect the node.')
    return '\n'.join(lines) if lines else None


def _text(value):
    return value if isinstance(value, str) and 0 < len(value) <= 160 and all(ord(c) >= 32 for c in value) else None


def _row(finding):
    if not isinstance(finding, dict) or finding.get("provider") != "k8s" or finding.get("status") != "FAIL":
        return None
    check_id = finding.get("check_id")
    return ROWS.get(check_id) if isinstance(check_id, str) else None


def workload_evidence_summary(finding):
    row = _row(finding)
    if row is None or not isinstance(finding.get("evidence"), dict):
        return None
    evidence = finding["evidence"]
    predicate = row["reviewed_binding"]["predicate"]
    if predicate == "runtime_default_seccomp":
        # This current source resolves overrides across regular/init/ephemeral rows.
        profiles, pod = evidence.get("container_profiles"), evidence.get("pod_profile")
        supported = (None, "RuntimeDefault", "Localhost", "Unconfined")
        if (not isinstance(profiles, list) or not profiles or pod not in supported
                or any(profile not in supported for profile in profiles)):
            return None
        effective = [profile if profile is not None else pod for profile in profiles]
        bad = next((profile for profile in effective if profile != "RuntimeDefault"), "no-failure")
        if bad == "no-failure":
            return None
        if bad is None:
            return "An assessed regular, init or ephemeral container has no declared or inherited RuntimeDefault seccomp profile."
        return "An assessed regular, init or ephemeral container declares or inherits " + bad + " seccomp instead of RuntimeDefault."
    if predicate == "effective_runtime_seccomp":
        failures = evidence.get("non_runtime_default")
        if isinstance(failures, list):
            for failure in failures[:100]:
                if not isinstance(failure, dict):
                    continue
                name, profile = _text(failure.get("container")), failure.get("effective_profile")
                if name and profile in ("Localhost", "Unconfined"):
                    return "Assessed Linux container “" + name + "” declares or inherits " + profile + " seccomp instead of RuntimeDefault."
        return None
    if finding["check_id"] == "k8s.claude.pod.no_host_ports":
        failures = evidence.get("violations")
        if isinstance(failures, list):
            for failure in failures[:100]:
                if not isinstance(failure, dict):
                    continue
                name, ports = _text(failure.get("container")), failure.get("host_ports")
                if (name and isinstance(ports, list) and ports
                        and all(type(port) is int and 1 <= port <= 65535 for port in ports)):
                    return "Regular container “" + name + "” declares hostPort " + str(ports[0]) + "."
        return None
    if row.get("static_observed_sentence"):
        return row["static_observed_sentence"]
    if predicate == "host_namespaces":
        names = [label for key, label in (("hostPID", "PID"), ("hostIPC", "IPC")) if evidence.get(key) is True]
        return "The PodSpec declares shared host " + " and ".join(names) + " namespaces." if names else None
    if predicate == "explicit_serviceaccount":
        if evidence.get("declared_service_account", object()) not in (None, ""):
            return None
        return "The PodSpec has no ServiceAccount name declared."
    if predicate == "no_literal_secret_env":
        values = evidence.get("literal_credential_env")
        if isinstance(values, list):
            for entry in values[:100]:
                if isinstance(entry, dict):
                    container, env = _text(entry.get("container")), _text(entry.get("env"))
                    if container and env:
                        return "Container “" + container + "” declares a nonempty literal in credential-like environment variable “" + env + "”."
        return None
    if predicate == "no_secret_env":
        values = evidence.get("violations")
        if isinstance(values, list):
            for entry in values[:100]:
                if not isinstance(entry, dict):
                    continue
                container, names = _text(entry.get("container")), entry.get("env")
                if container and isinstance(names, list) and names and _text(names[0]):
                    return "Container “" + container + "” loads environment variable “" + names[0] + "” from a Secret."
        return None
    observed_fields = row.get("evidence_presence_fields", [])
    if observed_fields and any(field in evidence for field in observed_fields):
        return "The resource " + row["observed_failure_phrase"] + "."
    if row["reviewed_binding"]["kind"] in ("role", "clusterrole"):
        values = evidence.get("matching_rules")
        if isinstance(values, list):
            for entry in values[:100]:
                if not isinstance(entry, dict):
                    continue
                verbs, resources = entry.get("verbs"), entry.get("resources")
                if isinstance(verbs, list) and verbs and isinstance(resources, list) and resources and _text(verbs[0]) and _text(resources[0]):
                    return "The role declares “" + verbs[0] + "” access to “" + resources[0] + "”."
        return None
    names = evidence.get("containers_needing_review")
    if names is None:
        names = evidence.get("privileged_containers")
    if names is None and isinstance(evidence.get("violations"), list):
        names = [entry.get("container") for entry in evidence["violations"] if isinstance(entry, dict)]
    if isinstance(names, list) and names and _text(names[0]):
        return "Container “" + names[0] + "” " + row["observed_failure_phrase"] + "."
    return None


def reviewed_workload_severity(finding):
    """Presentation risk for the specific failed configuration, not signed metadata."""
    row = _row(finding)
    return row["reviewed_severity"] if row is not None else None
