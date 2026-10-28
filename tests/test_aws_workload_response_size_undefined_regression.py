"""Nonfinite SDK values must fail before JSON encoding or content capture."""

import pytest

from peaso.collectors.aws_workload_command_source_20261020 import response_size


@pytest.mark.parametrize('value', [float('nan'), float('inf'), -float('inf')])
def test_nonfinite_response_number_is_rejected(value):
    with pytest.raises(ValueError, match='response_shape'):
        response_size({'value': value})
