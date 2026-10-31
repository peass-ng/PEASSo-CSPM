"""A list against a resource provider the subscription never registered is an empty inventory."""
import io
import json
from urllib.error import HTTPError

import pytest

from peaso.collectors import azure

SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"


def _error(status, code):
    body = json.dumps({"error": {"code": code, "message": "fixture"}}).encode()
    return HTTPError("https://management.azure.com" + SCOPE, status, "fixture", {}, io.BytesIO(body))


def _run(exc):
    reader = azure._ReaderExposure({"retries": 0, "concurrency": 1})
    def fetch():
        raise exc
        yield []
    reader.run([("newrelic_monitor", SCOPE, "NewRelic.Observability", fetch)])
    return reader.collections[0]


@pytest.mark.parametrize("status,code", [(404, "SubscriptionNotRegistered"), (409, "MissingSubscriptionRegistration")])
def test_unregistered_provider_list_is_empty(status, code):
    result = _run(_error(status, code))
    assert result["status"] == "empty" and result["items"] == [] and "error" not in result


@pytest.mark.parametrize("status,code", [(404, "ResourceNotFound"), (403, "SubscriptionNotRegistered"), (500, "SubscriptionNotRegistered")])
def test_other_failures_stay_incomplete(status, code):
    result = _run(_error(status, code))
    assert result["status"] not in ("collected", "empty")
