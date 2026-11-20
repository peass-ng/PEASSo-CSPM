"""Keep the two production AI agents on the platform alias and turn budget."""

from pathlib import Path

import pytest
import yaml


AGENTS = Path(__file__).resolve().parents[1] / "peaso" / "ai" / "agents"


@pytest.mark.parametrize("name", ("network", "priorities"))
def test_agent_inherits_the_platform_alias_and_keeps_its_turn_budget(name):
    config = yaml.safe_load((AGENTS / f"{name}.yaml").read_text())
    agent = config["agent"]

    assert agent["primary"] == "OPENAI_CHEAP_BUT_QUALITY"
    assert agent["thinking_effort"] == "preset"
    assert agent["max_turns"] == 30
