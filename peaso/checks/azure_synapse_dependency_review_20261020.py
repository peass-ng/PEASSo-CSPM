"""Add the private-endpoint evidence dependency to the Synapse workspace check."""
from dataclasses import replace

CHECK_ID = 'azure_pci_1_3_1_33'
BEFORE = ('synapse_workspace',)
AFTER = (*BEFORE, 'synapse_sql_private_endpoint_evidence')


def reviewed_check(check):
    if (check.id != CHECK_ID or check.provider != 'azure' or check.kind != 'synapse_workspace'
            or check.target != 'resource' or check.declared_dependencies not in (BEFORE, AFTER)):
        raise ValueError('Reviewed Synapse dependency predecessor changed')
    return replace(check, declared_dependencies=AFTER)


def install():
    from . import CHECKS
    matches = [position for position, check in enumerate(CHECKS) if check.id == CHECK_ID]
    if len(matches) != 1:
        raise ValueError('Reviewed Synapse dependency target is missing or ambiguous')
    position = matches[0]
    CHECKS[position] = reviewed_check(CHECKS[position])
