"""privesc_technique_details renders nested requirement groups (schema all_of/any_of nodes) readably."""
from peaso import engine
from peaso.privesc.schema import expand_requires, flatten_requirements

PASS = {"action": "iam:PassRole"}
CREATE = {"action": "lambda:CreateFunction"}
INVOKE = {"action": "lambda:InvokeFunction"}
URL = {"action": "lambda:CreateFunctionUrlConfig"}


def test_v1_shape_is_unchanged():
    requires = {"all_of": [PASS], "any_of": [[CREATE, INVOKE], URL]}
    out = engine._required_permissions(requires)
    assert out["all_of"] == ["iam:PassRole"]
    assert out["any_of"] == [["lambda:CreateFunction", "lambda:InvokeFunction"], ["lambda:CreateFunctionUrlConfig"]]
    assert out["leaves"] == [engine._permission_text(r) for r in flatten_requirements(requires)]
    assert out["alternatives"] == [["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
                                   ["iam:PassRole", "lambda:CreateFunctionUrlConfig"]]


def test_nested_groups_render_and_expand():
    requires = {"all_of": [PASS, {"any_of": [INVOKE, [CREATE, URL]]}]}
    out = engine._required_permissions(requires)
    assert out["all_of"] == ["iam:PassRole", "(lambda:InvokeFunction OR (lambda:CreateFunction AND lambda:CreateFunctionUrlConfig))"]
    assert not any("any_of=" in text for text in out["all_of"])  # no raw dict dump of the group
    assert out["leaves"] == ["iam:PassRole", "lambda:InvokeFunction", "lambda:CreateFunction", "lambda:CreateFunctionUrlConfig"]
    assert out["alternatives"] == [[engine._permission_text(r) for r in alt] for alt in expand_requires(requires)]
    assert out["alternatives"] == [["iam:PassRole", "lambda:InvokeFunction"],
                                   ["iam:PassRole", "lambda:CreateFunction", "lambda:CreateFunctionUrlConfig"]]


def test_nested_group_inside_any_of_and_all_of_node():
    requires = {"any_of": [{"all_of": [CREATE, {"any_of": [INVOKE, URL]}]}]}
    out = engine._required_permissions(requires)
    assert out["any_of"] == [["(lambda:CreateFunction AND (lambda:InvokeFunction OR lambda:CreateFunctionUrlConfig))"]]
    assert out["alternatives"] == [["lambda:CreateFunction", "lambda:InvokeFunction"], ["lambda:CreateFunction", "lambda:CreateFunctionUrlConfig"]]


def test_catalog_details_use_the_renderer():
    details = engine.privesc_technique_details(["admin-equivalent"])
    assert details["admin-equivalent"]["required_permissions"]["alternatives"] == [["administrator-equivalent grant on the scope"]]
    from peaso import privesc
    entry = next(e for e in privesc.catalog()["entries"] if (e.get("requires") or {}).get("all_of"))
    detail = engine.privesc_technique_details([entry["id"]])[entry["id"]]
    assert detail["requires"] and detail["required_permissions"] == engine._required_permissions(detail["requires"])
    assert detail["required_permissions"]["leaves"]
