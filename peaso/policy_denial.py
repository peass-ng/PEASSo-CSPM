"""AWS Organizations policy denials, kept apart from IAM permission gaps.

AWS names the policy type that denied a request in the AccessDenied message
("... with an explicit deny in a service control policy", "... because no
service control policy allows ..."). Such a denial applies to every principal
the organization policy governs, so granting the scanning identity more IAM
permissions cannot fix it. A typical case is a Region-restriction SCP, which
turns every read in a disabled Region into AccessDenied.

Messages are never stored: only the recognised policy type is retained.
"""
import re

SERVICE_CONTROL_POLICY = "service_control_policy"
RESOURCE_CONTROL_POLICY = "resource_control_policy"
POLICY_TYPES = frozenset({SERVICE_CONTROL_POLICY, RESOURCE_CONTROL_POLICY})

# Coverage status for reads an organization policy blocks.
BLOCKED_BY_POLICY = "blocked_by_policy"

_MESSAGE = re.compile(r"\b(?:with an explicit deny in an?|because no) (service|resource) control policy\b", re.I)


def policy_from_message(message):
    """Return the AWS Organizations policy type an AccessDenied message names, or None."""
    if not isinstance(message, str) or len(message) > 4096:
        return None
    match = _MESSAGE.search(message)
    if match is None:
        return None
    return SERVICE_CONTROL_POLICY if match[1].lower() == "service" else RESOURCE_CONTROL_POLICY


class PolicyDenialCode(str):
    """An AWS error code that remembers, in memory only, which organization
    policy produced the denial. It compares, hashes and serializes as the plain
    AWS code, so every existing code check keeps working; collectors copy the
    policy type into an explicit ``denied_by`` field before persisting."""

    def __new__(cls, code, denied_by):
        value = super().__new__(cls, code)
        value.denied_by = denied_by
        return value

    def __reduce__(self):
        return (PolicyDenialCode, (str(self), self.denied_by))

    def __deepcopy__(self, memo):
        return self

    def __copy__(self):
        return self


def denied_by(error):
    """Policy type recorded on a collection error, from its explicit field or a carried code."""
    if not isinstance(error, dict):
        return None
    value = error.get("denied_by")
    if value in POLICY_TYPES:
        return value
    for key in ("code", "cause_code"):
        value = getattr(error.get(key), "denied_by", None)
        if value in POLICY_TYPES:
            return value
    return None
