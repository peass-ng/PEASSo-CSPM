"""The recorded installed-SDK recipe support equals loading every botocore model, and is used only when valid."""
import importlib

import botocore
import botocore.session
import pytest

from peaso.collectors import aws_resource_policy_families as families
from peaso.collectors import aws_sdk_recipe_capabilities as capabilities


def _live(session):
    return {r.id: missing for r in families.RECIPES
            if (missing := families.unsupported_operations(r, session))}


def _recorded(session=None):
    return capabilities.recorded(families.RECIPES, families.recipe_operations,
                                 session or botocore.session.get_session())


def test_recorded_answer_applies_to_the_pinned_sdk_and_equals_loading_every_model(monkeypatch):
    monkeypatch.delenv("AWS_DATA_PATH", raising=False)
    monkeypatch.delenv("BOTOCORE_EXPERIMENTAL__PLUGINS", raising=False)
    session = botocore.session.get_session()
    assert botocore.__version__ in capabilities.RECORDED, "record the answer for the pinned botocore"
    recorded = _recorded(session)
    assert recorded is not None, "the recorded answer must apply in the pinned environment"
    assert recorded == _live(botocore.session.get_session())
    assert families.UNSUPPORTED_RECIPES == _live(botocore.session.get_session())
    expected = {(r.service, operation) for r in families.RECIPES if r.id not in families.UNSUPPORTED_RECIPES
                for operation in families.recipe_operations(r)}
    assert families.READ_ACTIONS == expected


def test_any_model_override_falls_back_to_loading_models(monkeypatch, tmp_path):
    (tmp_path / "ssm").mkdir()
    monkeypatch.setenv("AWS_DATA_PATH", str(tmp_path))
    assert _recorded() is None
    monkeypatch.setenv("AWS_DATA_PATH", str(tmp_path / "absent"))
    assert _recorded() is not None
    monkeypatch.delenv("AWS_DATA_PATH")
    monkeypatch.setenv("BOTOCORE_EXPERIMENTAL__PLUGINS", "x=y")
    assert _recorded() is None


def test_another_release_or_recipe_set_falls_back_to_loading_models(monkeypatch):
    monkeypatch.delenv("AWS_DATA_PATH", raising=False)
    monkeypatch.delenv("BOTOCORE_EXPERIMENTAL__PLUGINS", raising=False)
    session = botocore.session.get_session()
    assert capabilities.recorded(families.RECIPES[1:], families.recipe_operations, session) is None
    entry = capabilities.RECORDED[botocore.__version__]
    monkeypatch.setitem(entry, "api_versions", {**entry["api_versions"], "ssm": "1999-01-01"})
    assert capabilities.recorded(families.RECIPES, families.recipe_operations, session) is None
    monkeypatch.setattr(botocore, "__version__", "0.0.0")
    assert capabilities.recorded(families.RECIPES, families.recipe_operations, session) is None
    calls = []
    got = capabilities.unsupported_recipes(families.RECIPES[:3], families.recipe_operations,
                                           lambda r, s: calls.append(r.id) or ["missing_op"], session)
    assert calls == [r.id for r in families.RECIPES[:3]] and got == {r.id: ["missing_op"] for r in families.RECIPES[:3]}


def test_recorded_unsupported_entries_keep_recipe_order_and_are_fresh_lists(monkeypatch):
    monkeypatch.delenv("AWS_DATA_PATH", raising=False)
    monkeypatch.delenv("BOTOCORE_EXPERIMENTAL__PLUGINS", raising=False)
    entry = capabilities.RECORDED[botocore.__version__]
    rows = [[families.RECIPES[2].id, ["b_op"]], [families.RECIPES[0].id, ["a_op"]]]
    monkeypatch.setitem(entry, "unsupported", rows)
    got = _recorded()
    assert list(got) == [families.RECIPES[2].id, families.RECIPES[0].id]
    got[families.RECIPES[2].id].append("x")
    assert rows[0][1] == ["b_op"]
