"""Capture the description/remediation rows the product passes to an overlay."""
from copy import deepcopy


def captured_originals(module):
    """Return ({cid: description input}, {cid: remediation input}) for module.ROWS.

    The real catalog and remediation chains run with the overlay wrapped, so
    each recorded value is exactly what the product hands to the overlay.
    """
    from peaso import remediation as remediation_module
    from peaso.checks.catalog import description_for

    descriptions, remediations = {}, {}
    real_description, real_remediation = module.description, module.remediation

    def description(cid, original, *args, **kwargs):
        descriptions.setdefault(cid, deepcopy(original))
        return real_description(cid, original, *args, **kwargs)

    def remediation(cid, original, *args, **kwargs):
        remediations.setdefault(cid, deepcopy(original))
        return real_remediation(cid, original, *args, **kwargs)

    module.description, module.remediation = description, remediation
    try:
        for cid in module.ROWS:
            description_for(cid)
        remediation_module.rules.__wrapped__()
    finally:
        module.description, module.remediation = real_description, real_remediation
    return descriptions, remediations
