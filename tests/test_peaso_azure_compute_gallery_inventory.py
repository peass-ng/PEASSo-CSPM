"""Compute Gallery sharing policy is read once through the cached ARM inventory."""

from urllib.parse import urlsplit

from peaso.collectors import azure


SUB = "11111111-1111-1111-1111-111111111111"
SCOPE = "/subscriptions/" + SUB
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.Compute/galleries/images"


class Transport:
    tenant = verified_tenant = "22222222-2222-2222-2222-222222222222"

    def __init__(self):
        self.calls = []

    def request(self, url, *, body=None, audience=azure.ARM):
        self.calls.append(url)
        path = urlsplit(url).path
        if path == SCOPE + "/providers/Microsoft.Compute/galleries":
            return {"value": [{"id": RID, "name": "images", "type": "Microsoft.Compute/galleries",
                              "properties": {"sharingProfile": {"permissions": "Community"}}}]}
        if path == RID:
            return {"id": RID, "name": "images", "type": "Microsoft.Compute/galleries",
                    "properties": {"sharingProfile": {"permissions": "Community"}}}
        return {"value": []}


def test_compute_gallery_list_get_are_cached_once():
    transport = Transport()
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["compute_gallery"], transport=transport)
    collection = next(row for row in snapshot["collections"] if row["type"] == "compute_gallery")
    assert collection["status"] == "collected"
    assert collection["items"][0]["properties"]["sharingProfile"]["permissions"] == "Community"
    assert sum(urlsplit(url).path == SCOPE + "/providers/Microsoft.Compute/galleries" for url in transport.calls) == 1
    assert sum(urlsplit(url).path == RID for url in transport.calls) == 1


def test_gallery_image_versions_are_read_once_with_bound_identities():
    image = RID + "/images/base"
    version = image + "/versions/1.0.0"
    class GalleryTransport(Transport):
        def request(self, url, *, body=None, audience=azure.ARM):
            path = urlsplit(url).path
            if path == RID + "/images":
                self.calls.append(url)
                return {"value": [{"id": image, "name": "base", "type": "Microsoft.Compute/galleries/images"}]}
            if path == image + "/versions":
                self.calls.append(url)
                return {"value": [{"id": version, "name": "1.0.0",
                                   "type": "Microsoft.Compute/galleries/images/versions",
                                   "properties": {"provisioningState": "Succeeded",
                                                  "publishingProfile": {"publishedDate": "2026-10-01", "sourceUri": "SECRET"}}}]}
            return super().request(url, body=body, audience=audience)
    transport = GalleryTransport()
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["compute_gallery"], transport=transport)
    gallery = next(row for row in snapshot["collections"] if row["type"] == "compute_gallery")["items"][0]
    assert gallery["_coverage"]["images"]["status"] == "collected"
    assert gallery["images"][0]["_coverage"]["versions"]["status"] == "collected"
    assert gallery["images"][0]["versions"] == [{"id": version, "name": "1.0.0",
        "type": "Microsoft.Compute/galleries/images/versions",
        "properties": {"provisioningState": "Succeeded", "publishingProfile": {"publishedDate": "2026-10-01"}}}]
    assert sum(urlsplit(url).path == RID + "/images" for url in transport.calls) == 1
    assert sum(urlsplit(url).path == image + "/versions" for url in transport.calls) == 1
