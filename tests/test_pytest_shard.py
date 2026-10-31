"""The CI splitter must run every collected test exactly once for any shard count."""
from pathlib import Path

import pytest

from scripts import pytest_shard


@pytest.mark.parametrize('count', [1, 3, 8, 32])
def test_every_file_and_node_runs_on_exactly_one_shard(count):
    files = pytest_shard.test_files()
    shards = pytest_shard.partition(files, count)
    pytest_shard._verify(files, shards)
    owners = pytest_shard._placements(shards)
    for path in files:
        assert len(owners[path]) == min(pytest_shard.SPLIT_COUNTS.get(path.name, 1), count)
        for suffix in ('test_plain', 'test_param[value-1]', 'test_param[value-2]'):
            assert pytest_shard.owner_for(f'{path}::{suffix}', path, owners) in owners[path]


def test_split_module_nodes_are_divided_not_duplicated():
    files = pytest_shard.test_files()
    owners = pytest_shard._placements(pytest_shard.partition(files, 8))
    split = next(path for path in files if len(owners[path]) > 1)
    nodes = [f'{split}::test_case[{i}]' for i in range(200)]
    used = {pytest_shard.owner_for(node, split, owners) for node in nodes}
    assert used <= set(owners[split]) and len(used) > 1


def test_hook_selects_only_this_shard(monkeypatch):
    files = pytest_shard.test_files()
    owners = pytest_shard._placements(pytest_shard.partition(files, 4))
    path = files[0]
    item = type('Item', (), {'path': Path.cwd() / path, 'nodeid': f'{path}::test_x'})()
    expected = pytest_shard.owner_for(item.nodeid, path, owners)
    monkeypatch.setenv('PEASO_CI_PYTEST_SHARDS', '4')
    for shard in range(4):
        monkeypatch.setenv('PEASO_CI_PYTEST_SHARD', str(shard))
        items, deselected = [item], []
        config = type('Config', (), {'hook': type('Hook', (), {'pytest_deselected': lambda self, items: deselected.extend(items)})()})()
        pytest_shard.pytest_collection_modifyitems(config, items)
        assert (items == [item]) == (shard == expected) and (deselected == [item]) == (shard != expected)
