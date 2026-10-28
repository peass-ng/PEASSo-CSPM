"""Remove newly collected VPN and OpenShift secrets before metadata retention."""


def without_added_secrets(value):
    if isinstance(value, dict):
        return {key: without_added_secrets(item) for key, item in value.items()
                if key.casefold() not in {"radiusserversecret", "pullsecret"}}
    if isinstance(value, list):
        return [without_added_secrets(item) for item in value]
    return value
