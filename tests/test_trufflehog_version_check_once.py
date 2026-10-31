"""The TruffleHog version check runs once per binary, not once per content item."""
import shutil
import sys

import pytest

from peaso import secret_scanning as scanning


@pytest.fixture
def fake_trufflehog(tmp_path, monkeypatch):
    log = tmp_path / 'calls.log'
    binary = tmp_path / 'trufflehog'
    binary.write_text(
        '#!' + sys.executable + '\n'
        'import sys\n'
        'open(' + repr(str(log)) + ', "a").write(sys.argv[1] + "\\n")\n'
        'if sys.argv[1] == "--version":\n'
        '    print("trufflehog ' + scanning.TRUFFLEHOG_VERSION + '")\n'
        'else:\n'
        '    sys.stdin.buffer.read()\n')
    binary.chmod(0o755)
    real_which = shutil.which
    monkeypatch.setattr(shutil, 'which',
                        lambda name, *a, **kw: str(binary) if name == 'trufflehog' else real_which(name, *a, **kw))
    scanning._trufflehog.cache_clear()
    yield binary, log
    scanning._trufflehog.cache_clear()


def test_many_content_items_check_the_version_once(fake_trufflehog):
    binary, log = fake_trufflehog
    for number in range(3):
        assert scanning._scan_trufflehog(b'synthetic item %d' % number, 'item', 15) == []
    calls = log.read_text().split()
    assert calls.count('--version') == 1 and calls.count('stdin') == 3


def test_replaced_binary_is_checked_again(fake_trufflehog):
    binary, log = fake_trufflehog
    scanning._trufflehog()
    binary.write_text(binary.read_text().replace(scanning.TRUFFLEHOG_VERSION, '0.0.1') + '\n')
    with pytest.raises(RuntimeError):
        scanning._trufflehog()
    assert log.read_text().split().count('--version') == 2
