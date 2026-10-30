"""Replay one sealed proposal assertion, then verify its admitted successor.

The original test bytes and its registration failure remain reproducible. This
test-only plugin handles that exact historical node; no skips, registry changes
or production imports of this plugin are involved.
"""
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path

import pytest

NODE = 'tests/test_aws_codebuild_buildspec_source_20261020.py::test_receipt_and_unregistered_declaration'
SOURCE = Path(__file__).with_name('test_aws_codebuild_buildspec_source_20261020.py').resolve()
SOURCE_SHA256 = 'f5db76345cd4b95c5281df4cfeddbf396c29e213142001a639d341eca35ddc35'


def replay_and_verify(function):
    assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == SOURCE_SHA256
    assert function.__name__ == 'test_receipt_and_unregistered_declaration'
    assert Path(function.__code__.co_filename).resolve() == SOURCE
    assert function.__code__.co_firstlineno == 303
    try:
        function()
    except AssertionError as error:
        trace = error.__traceback__
        while trace.tb_next:
            trace = trace.tb_next
        assert trace.tb_frame.f_code is function.__code__ and trace.tb_lineno == 308
    else:
        raise AssertionError('The preserved unregistered proposal must differ from the admitted runtime.')

    from peaso.checks import CHECKS
    from peaso.checks import aws_codebuild_buildspec_runtime_admission_20261020 as admission
    from peaso.checks import aws_codebuild_buildspec_runtime_consumer_20261020 as current
    from peaso.checks.fixtures import CASES
    admission.reviewed_inputs()
    check, = [c for c in CHECKS if c.id == current.DECLARATION['id']]
    assert inspect.unwrap(check.evaluate) is current.evaluate
    assert check.kind == current.DECLARATION['kind']
    cases = CASES[check.id]
    for branch in ('pass', 'fail', 'unknown'):
        status, _ = current.evaluate(deepcopy(cases[branch]), deepcopy(cases[branch + '_index']))
        assert status == branch.upper()
    receipt = json.loads((SOURCE.parents[1] / 'docs/check-review/aws-codebuild-buildspec-source-20261020.json').read_text())
    assert receipt['source_hashes'][SOURCE.relative_to(SOURCE.parents[1]).as_posix()] == SOURCE_SHA256


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    if pyfuncitem.nodeid != NODE:
        return None
    replay_and_verify(pyfuncitem.obj)
    return True
