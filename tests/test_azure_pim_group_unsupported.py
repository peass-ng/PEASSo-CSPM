"""Groups PIM cannot manage (synced or dynamic) hold no PIM rows instead of an unknown read."""
import io
import json
from urllib.error import HTTPError

import pytest

from peaso.collectors import azure

SCOPE = "/tenants/00000000-0000-0000-0000-000000000001/groups/g1"


class Reader(azure._ReaderExposure):
    def __init__(self, exc):
        super().__init__({"retries": 0, "concurrency": 1})
        self.exc = exc

    def pages(self, request, url, **kwargs):
        raise self.exc
        yield []


def _collect(status, code):
    body = json.dumps({"error": {"code": code, "message": "fixture"}}).encode()
    reader = Reader(HTTPError("https://graph.microsoft.com/v1.0/x", status, "fixture", {}, io.BytesIO(body)))
    reader.run([("directory_group_pim_policy", SCOPE, "Microsoft.Graph",
                 lambda: azure._pim_group_pages(reader, None, "https://graph.microsoft.com/v1.0/x"))])
    return reader.collections[0]


def test_unsupported_group_type_has_no_pim_rows():
    assert _collect(400, "ResourceTypeNotSupported")["status"] == "empty"


@pytest.mark.parametrize("status,code", [(400, "BadRequest"), (403, "ResourceTypeNotSupported")])
def test_other_errors_stay_incomplete(status, code):
    assert _collect(status, code)["status"] not in ("collected", "empty")
