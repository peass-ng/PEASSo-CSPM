"""Register the bounded ECS/Batch command literal secret check."""
from . import aws_workload_command_runtime_consumer_20261020 as consumer
from peaso.collectors import aws_workload_command_runtime_20261020 as runtime


def install():
    from . import CHECKS, register
    if any(check.id == runtime.CHECK for check in CHECKS):
        return
    declaration = consumer.DECLARATION
    register(runtime.CHECK, 'aws', declaration['category'], runtime.KIND, declaration['title'], 'high',
        'security_configuration', declaration['remediation'], dependencies=[runtime.KIND],
        allow_incomplete_failure=True)(consumer.evaluate)
