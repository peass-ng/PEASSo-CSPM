from pathlib import Path

import pytest

from peaso import private_secret_source_epoch_20261021 as epoch
from peaso.private_secret_current_source_successor_20261028 import (
    reviewed_predecessor,
    unchanged_callable_projection,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    "peaso/collectors/aws_code_log_content_indicators.py",
    "peaso/collectors/aws_workload_command_source_20261020.py",
    "peaso/collectors/azure.py",
    "peaso/collectors/gcp.py",
)


@pytest.mark.parametrize("relative", SOURCES)
def test_exact_current_source_reverses_and_tamper_fails(relative):
    current = (ROOT / relative).read_bytes()
    prior = reviewed_predecessor(relative, current, ROOT)
    if relative.startswith("peaso/collectors/aws_"):
        assert epoch._sha(prior) == epoch.source_rows()[relative]["after_sha256"]
    with pytest.raises(epoch.AdmissionError):
        reviewed_predecessor(relative, current + b"\n", ROOT)


def test_unchanged_aws_producers_use_current_reviewed_witnesses():
    from peaso.collectors import aws_code_log_content_indicators as logs
    from peaso.collectors import aws_workload_command_source_20261020 as workload

    for module, name in ((logs, "project_response"), (workload, "collect")):
        relative = module.__name__.replace(".", "/") + ".py"
        definition = next(row for row in epoch.source_rows()[relative]["definitions"]
                          if row["name"] == name)
        current = unchanged_callable_projection(
            getattr(module, name), {"path": relative, "sha256": definition["before"]}, ROOT)
        assert current["sha256"] == epoch._sha(__import__("inspect").getsource(getattr(module, name)).encode())
