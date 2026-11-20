from peaso.ai.pipeline import selected_stages


def test_scan_ai_stages_follow_selected_sections():
    assert selected_stages({'categories': ['least_privilege', 'privesc'],
                            'ai_priorities_enabled': False}) == {'findings_report'}
    assert selected_stages({'categories': ['network'], 'ai_network_enabled': False,
                            'ai_priorities_enabled': False}) == {'findings_report'}
    assert selected_stages({'categories': ['network'], 'ai_network_enabled': True,
                            'ai_priorities_enabled': False}) == {'network', 'findings_report'}
    assert selected_stages({'categories': ['exposure'], 'ai_priorities_enabled': False}) == {'findings_report'}
    assert selected_stages({'categories': ['hardening', 'network'], 'ai_network_enabled': False,
                            'ai_priorities_enabled': True}) == {'priorities', 'findings_report'}


def test_legacy_scans_use_only_remaining_ai_stages():
    assert selected_stages({}) == {'network', 'priorities', 'findings_report'}
    assert selected_stages({}, {'priorities'}) == {'network', 'priorities'}
    assert selected_stages({}, {'hardening', 'exposure'}) == frozenset()


def test_report_can_be_selected_without_other_agents_or_disabled_explicitly():
    assert selected_stages({'categories': ['hardening'], 'ai_priorities_enabled': False,
                            'ai_findings_report_enabled': False}) == frozenset()
    assert selected_stages({}, {'findings_report'}) == {'findings_report'}
