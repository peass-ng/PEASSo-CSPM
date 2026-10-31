"""Project short, check-specific observations without changing recorded findings."""


def evidence_summary(finding):
    observation = _evidence_summary(finding)
    if not isinstance(finding, dict) or finding.get('provider') != 'azure':
        return observation
    from peaso.checks.azure_platform_defaults import first_lines
    # A property read as its documented Azure default is named first.
    lines = first_lines(finding.get('evidence'))
    if not lines:
        return observation
    rest = [line for line in (observation or '').split('\n') if line and line not in lines]
    if len(rest) >= 3:
        rest = rest[1:]  # Its first line restated the value the default line now names.
    return '\n'.join([*lines, *rest][:5])


def _evidence_summary(finding):
    if not isinstance(finding, dict):
        return None
    from peaso.provider_followup_observations_20261021 import evidence_summary as provider_followup
    followup = provider_followup(finding)
    if followup is not None:
        return followup
    from peaso.checks.aws_ai_recheck_evidence_20261020 import evidence_summary as rechecked
    correction = rechecked(finding)
    if correction:
        return correction
    provider = finding.get('provider')
    if provider == 'k8s':
        from peaso.checks.k8s_workload_finding_summary import pod_level_observation
        pod_observation = pod_level_observation(finding)
        if pod_observation is not None:
            return pod_observation
    if finding.get('category') == 'privesc' or finding.get('check_id') == 'admin-equivalent':
        if provider == 'aws':
            from peaso.privesc.aws_observed_evidence_v3 import evidence_summary as privilege_path
        elif provider == 'gcp':
            from peaso.privesc.gcp_observed_impact import evidence_summary as privilege_path
        else:
            from peaso.privesc.finding_explanation import evidence_summary as privilege_path
        return privilege_path(finding)
    from peaso.checks.aws_evidence_explanations import evidence_summary as aws
    from peaso.checks.gcp_evidence_explanations import evidence_summary as gcp
    from peaso.checks.azure_evidence_explanations import evidence_summary as azure
    from peaso.checks.k8s_evidence_explanations import evidence_summary as k8s
    reviewed = {'aws': aws, 'gcp': gcp, 'azure': azure, 'k8s': k8s}.get(provider)
    observation = reviewed(finding) if reviewed else None
    if observation:
        return observation
    if provider == 'azure':
        from peaso.checks.azure_evidence_explanations import ROWS, reviewed_explanation
        cid, status = finding.get('check_id'), finding.get('status')
        row = ROWS.get(cid) if isinstance(cid, str) else None
        if row is not None:
            if status not in ('PASS', 'FAIL', 'UNKNOWN', 'DENIED', 'MANUAL', 'NOT_APPLICABLE', 'EMPTY'):
                return None
            key = {'MANUAL': 'manual_observation', 'NOT_APPLICABLE': 'not_applicable_observation'}.get(status, 'missing_observation')
            missing = row.get(key) or row.get('missing_observation') or 'No usable deciding evidence was recorded.'
            return reviewed_explanation(cid, missing, status)
    if finding.get('category') == 'privesc' or finding.get('check_id') == 'admin-equivalent':
        from peaso.privesc.finding_explanation import evidence_summary as privilege_path
        return privilege_path(finding)
    return _legacy_observation(finding)


def _legacy_observation(finding):
    if not isinstance(finding, dict):
        return None
    provider = finding.get('provider')
    cid = finding.get('check_id')
    if isinstance(cid, str) and cid.startswith('analysis.'):
        from peaso.analysis.finding_clarity import evidence_summary as analysis
        return analysis(finding)
    if provider in ('azure', 'gcp'):
        from peaso.checks.provider_scope_observed_evidence import provider_scope
        observation = provider_scope(finding)
        if observation:
            return observation
    if provider == 'k8s':
        # No static failure-prose fallback: malformed witnesses stay unclaimed.
        from peaso.checks.k8s_observed_configuration import evidence_summary as k8s
        return k8s(finding)
    if provider == 'gcp':
        from peaso.checks.gcp_observed_evidence import evidence_summary as gcp
        observation = gcp(finding)
        if observation:
            return observation
    if provider == 'azure':
        from peaso.checks.azure_bulk_observed_evidence import evidence_summary as azure
        observation = azure(finding)
        if observation:
            return observation
    if provider == 'aws':
        from peaso.checks.aws_scope_observed_evidence import evidence_summary as aws_scope
        from peaso.checks.aws_core_observed_evidence import evidence_summary as aws_core
        from peaso.checks.aws_typed_finding_summary import evidence_summary as aws
        from peaso.checks.aws_pass_observed_evidence import evidence_summary as aws_pass
        observation = aws_scope(finding) or aws_core(finding) or aws(finding) or aws_pass(finding)
        if observation:
            return observation
    from peaso.checks.gcp_remaining_finding_summary import evidence_summary as gcp_remaining
    from peaso.checks.aws_database_clarity_reviewed import evidence_summary as database
    from peaso.analysis.finding_clarity import evidence_summary as analysis
    from peaso.checks.aws_remaining_finding_summary import evidence_summary as aws_remaining
    from peaso.checks.aws_final_clarity_reviewed import evidence_summary as aws_final
    from peaso.checks.aws_bulk_finding_summary import evidence_summary as aws_bulk
    from peaso.checks.aws_compute_storage_finding_summary import evidence_summary as aws_compute
    return (aws_final(finding) or aws_bulk(finding) or aws_compute(finding)
            or aws_remaining(finding) or analysis(finding)
            or database(finding) or gcp_remaining(finding))
