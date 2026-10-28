"""Large Network inputs must open the same exact context sent to the agent."""

import gzip
import sqlite3
import sys
from types import ModuleType

import pytest

from peaso.ai import runner


def test_network_runner_expands_compressed_context_before_agent_setup(tmp_path, monkeypatch):
    database = tmp_path / 'context.sqlite'
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE proof (value TEXT)')
        db.execute('INSERT INTO proof VALUES (?)', ('saved-network-context',))
    packed = tmp_path / 'context.sqlite.gz'
    with gzip.open(packed, 'wb') as output:
        output.write(database.read_bytes())
    database.unlink()
    (tmp_path / 'codex-auth.json').write_text('{}')
    (tmp_path / 'credentials.json').write_text('{"entries":[]}')

    class ContextReady(Exception):
        pass

    def check_context(_path):
        assert database.is_file()
        assert not packed.exists()
        with sqlite3.connect(database) as db:
            assert db.execute('SELECT value FROM proof').fetchone() == ('saved-network-context',)
        raise ContextReady()

    fake = ModuleType('chack_agent')
    fake.Chack = object
    fake.load_config = check_context
    monkeypatch.setitem(sys.modules, 'chack_agent', fake)
    monkeypatch.setattr(sys, 'argv', ['runner', 'network'])
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ContextReady):
        runner.main()
