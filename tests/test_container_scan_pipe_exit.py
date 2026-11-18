"""Synthetic owned process lifecycles; never starts an image/secret scanner."""
import os
import sys
import time
from peaso import container_scan_process_20261020 as runner


def execute(tmp_path, program, budget=5):
    return runner._execute([sys.executable, '-I', '-c', program], dict(os.environ),
                           tmp_path, time.monotonic() + budget, lambda: None)


def test_parent_success_drains_short_lived_inherited_pipes_without_truncation(tmp_path):
    # A helper retains inherited stdout briefly after the parent exits. The
    # parent's complete document and zero exit code must survive that tail.
    child = 'import time;time.sleep(0.25)'
    program = ('import subprocess,sys;subprocess.Popen([sys.executable,"-I","-c",' + repr(child) + ']);'
               'print("complete-document",flush=True)')
    out, err, code, reason, _ = execute(tmp_path, program)
    assert (out, code, reason) == (b'complete-document\n', 0, None)


def test_parent_failure_keeps_stderr_and_exit_status_through_pipe_tail(tmp_path):
    child = 'import time;time.sleep(0.25)'
    program = ('import subprocess,sys;subprocess.Popen([sys.executable,"-I","-c",' + repr(child) + ']);'
               'print("bad-input",file=sys.stderr,flush=True);sys.exit(7)')
    out, err, code, reason, _ = execute(tmp_path, program)
    assert code == 7 and reason is None and err == b'bad-input\n'


def test_long_lived_descendant_is_still_incomplete_and_group_is_cleaned_up(tmp_path):
    child = 'import time;time.sleep(60)'
    program = ('import subprocess,sys;p=subprocess.Popen([sys.executable,"-I","-c",' + repr(child) + ']);'
               'print(p.pid,flush=True)')
    out, err, code, reason, _ = execute(tmp_path, program)
    assert reason == 'descendant_pipe_open' and code is None
    # The process group cannot retain a live pipe after supervision returns.
    # A zombie may remain briefly for the operating system's reaper.
    pid = int(out.strip())
    import subprocess
    result = subprocess.run(['ps','-p',str(pid),'-o','stat='],capture_output=True,text=True)
    assert not result.stdout.strip() or result.stdout.lstrip().startswith('Z')
