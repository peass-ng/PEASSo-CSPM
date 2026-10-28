"""Keep the native exposure dispatcher callable after provider source merges.

This test parses source without importing the analyzer or loading release data.
"""

import ast
from collections import defaultdict
from functools import lru_cache
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "peaso/analysis/internet_exposure.py"


@lru_cache(maxsize=1)
def _source():
    module = ast.parse(SOURCE.read_text())
    functions = {
        node.name: node
        for node in module.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    bindings = set(functions)
    bindings.update(node.name for node in module.body if isinstance(node, ast.ClassDef))
    for node in module.body:
        if isinstance(node, ast.Assign):
            bindings.update(
                target.id for target in node.targets if isinstance(target, ast.Name)
            )
    return module, functions, bindings


def _handler_map(functions):
    assess = functions["assess"]
    assignment = next(
        node
        for node in assess.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "handlers"
            for target in node.targets
        )
    )
    # The dispatcher uses the selected provider's dictionary via .get().
    expression = assignment.value
    if isinstance(expression, ast.Call) and isinstance(expression.func, ast.Attribute):
        expression = expression.func.value
    assert isinstance(expression, ast.Dict)
    return expression


def test_exposure_dispatcher_handlers_are_defined():
    _, functions, bindings = _source()
    missing = []
    for provider_node, provider_map in zip(
        _handler_map(functions).keys, _handler_map(functions).values
    ):
        provider = ast.literal_eval(provider_node)
        assert isinstance(provider_map, ast.Dict)
        for key_node, value_node in zip(provider_map.keys, provider_map.values):
            if key_node is None:
                # Dict unpack groups use either a dictionary comprehension or
                # dict.fromkeys; both supply handler values at runtime.
                if isinstance(value_node, ast.DictComp):
                    references = [value_node.value]
                    references.extend(
                        generator.iter for generator in value_node.generators
                    )
                else:
                    assert isinstance(value_node, ast.Call)
                    assert isinstance(value_node.func, ast.Attribute)
                    assert value_node.func.attr == "fromkeys"
                    references = [value_node.args[0], value_node.args[1]]
                label = "dynamic group"
            else:
                references = [value_node]
                label = ast.literal_eval(key_node)
            for reference in references:
                for node in ast.walk(reference):
                    if isinstance(node, ast.Name) and node.id.startswith("_"):
                        if node.id not in bindings:
                            missing.append((provider, label, node.id))
    assert not missing, f"Undefined exposure handlers or group names: {missing}"


def test_exposure_dispatcher_does_not_override_distinct_handlers():
    _, functions, _ = _source()
    conflicting = []
    for provider_node, provider_map in zip(
        _handler_map(functions).keys, _handler_map(functions).values
    ):
        provider = ast.literal_eval(provider_node)
        seen = defaultdict(set)
        for key_node, value_node in zip(provider_map.keys, provider_map.values):
            if key_node is not None:
                seen[ast.literal_eval(key_node)].add(ast.unparse(value_node))
        conflicting.extend(
            (provider, key, sorted(handlers))
            for key, handlers in seen.items()
            if len(handlers) > 1
        )
    assert not conflicting, f"Exposure handlers silently overridden: {conflicting}"


def test_exposure_entry_point_passes_only_supported_assess_arguments():
    _, functions, _ = _source()
    assess = functions["assess"]
    entry_point = functions["internet_findings"]
    parameters = {
        node.arg for node in assess.args.posonlyargs + assess.args.args + assess.args.kwonlyargs
    }
    calls = [
        node
        for node in ast.walk(entry_point)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "assess"
    ]
    assert calls, "Exposure entry point no longer calls assess"
    unsupported = [
        keyword.arg
        for call in calls
        for keyword in call.keywords
        if keyword.arg is not None and keyword.arg not in parameters
    ]
    assert not unsupported, f"Exposure entry point passes unsupported assess arguments: {unsupported}"
