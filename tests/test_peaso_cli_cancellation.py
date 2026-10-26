"""Real CLI signals allow a provider to release scan-owned resources first."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import textwrap

import pytest


@pytest.mark.parametrize('signum', [signal.SIGINT, signal.SIGTERM])
def test_cli_signal_waits_for_provider_cleanup_and_returns_signal_exit(tmp_path, signum):
    script = textwrap.dedent('''
        import pathlib, sys, time
        # Import-time source attestation must see the pristine collector; patch
        # the provider seam only after the attested catalog is loaded.
        import peaso.checks
        from peaso import cli
        from peaso.collectors import aws
        from peaso.snapshot import make_snapshot
        root = pathlib.Path(sys.argv[1])
        def collect(connector, requirements):
            assert 'cancel_event' in connector['options']
            event = connector['options']['cancel_event']
            print('READY', flush=True)
            try:
                while not event.wait(.05):
                    pass
            finally:
                (root / 'cleanup').write_text('owned temporary resource released')
            return make_snapshot('aws', ['123456789012'], [])
        aws.collect = collect
        code = cli.main(['scan', '--provider', 'aws', '--scopes', '123456789012',
                         '--checks', 'aws.ec2.imdsv2', '--quiet', '--output', str(root / 'report.json')])
        raise SystemExit(code)
    ''')
    process = subprocess.Popen([sys.executable, '-u', '-c', script, str(tmp_path)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert process.stdout.readline().strip() == 'READY'
        os.kill(process.pid, signum)
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 128 + signum
        assert (tmp_path / 'cleanup').read_text() == 'owned temporary resource released'
        assert not (tmp_path / 'report.json').exists()
        assert not stdout
        assert 'cancelled' in stderr and 'Traceback' not in stderr
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
