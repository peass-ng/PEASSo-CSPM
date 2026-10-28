from peaso.ai.pipeline import selected_stages


def test_scan_ai_stages_follow_selected_sections():
    assert selected_stages({'categories': ['least_privilege', 'privesc'],
                            'ai_priorities_enabled': False}) == frozenset()
    assert selected_stages({'categories': ['network'], 'ai_network_enabled': False,
                            'ai_priorities_enabled': False}) == frozenset()
    assert selected_stages({'categories': ['network'], 'ai_network_enabled': True,
                            'ai_priorities_enabled': False}) == {'network'}
    assert selected_stages({'categories': ['exposure'], 'ai_priorities_enabled': False}) == {'exposure'}
    assert selected_stages({'categories': ['hardening', 'network'], 'ai_network_enabled': False,
                            'ai_priorities_enabled': True}) == {'hardening', 'priorities'}


def test_legacy_scans_keep_all_ai_stages():
    assert selected_stages({}) == {'hardening', 'exposure', 'network', 'priorities'}
    assert selected_stages({}, {'priorities'}) == {'hardening', 'exposure', 'network', 'priorities'}


def test_hosted_agent_switches_keep_network_and_priorities(monkeypatch):
    monkeypatch.setenv('PEASO_AI_HARDENING_AGENT_ENABLED', '0')
    monkeypatch.setenv('PEASO_AI_EXPOSURE_AGENT_ENABLED', '0')
    assert selected_stages({}) == {'network', 'priorities'}
    assert selected_stages({}, {'priorities'}) == {'network', 'priorities'}
    assert selected_stages({}, {'hardening', 'exposure'}) == frozenset()
