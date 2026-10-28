"""Keep the two production AI agents on the reviewed quality contract."""

from pathlib import Path

import pytest
import yaml


AGENTS = Path(__file__).resolve().parents[1] / "peaso" / "ai" / "agents"


@pytest.mark.parametrize("name", ("network", "priorities"))
def test_agent_keeps_best_quality_alias_high_effort_and_full_turn_budget(name):
    config = yaml.safe_load((AGENTS / f"{name}.yaml").read_text())
    agent = config["agent"]

    assert agent["primary"] == "OPENAI_BEST_QUALITY"
    assert agent["thinking_effort"] == "high"
    assert agent["max_turns"] == 30
