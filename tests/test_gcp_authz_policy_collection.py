"""Project authz-policy inventory covers global and discovered regional paths."""
from test_gcp_config_delivery_location import catalog


PROJECT = "projects/demo-project1"
GLOBAL = PROJECT + "/locations/global/authzPolicies/edge"
REGIONAL = PROJECT + "/locations/us-central1/authzPolicies/inside"
ROOT = "https://networksecurity.googleapis.com/v1"


class Collector:
    options = {}

    def __init__(self):
        self.urls = []

    def pages(self, url, scope, *, key=None, single=False, params=None, page_size_key="pageSize"):
        assert page_size_key == "pageSize"
        self.urls.append(url)
        assert scope == PROJECT
        if url == ROOT + "/" + PROJECT + "/locations":
            yield [{"locationId": "us-central1"}], "locations"
        elif url == ROOT + "/" + PROJECT + "/locations/global/authzPolicies":
            yield [{"name": GLOBAL}], "global"
        elif url == ROOT + "/" + PROJECT + "/locations/us-central1/authzPolicies":
            yield [{"name": REGIONAL}], "regional"
        elif single and url in (ROOT + "/" + GLOBAL, ROOT + "/" + REGIONAL):
            yield [{"name": url.removeprefix(ROOT + "/")}], "detail"
        else:
            raise AssertionError(url)

    def hydrate(self, item, field, url, scope, *, params=None):
        self.urls.append(url)
        assert params == {"options.requestedPolicyVersion": 3}
        return {**item, "iamPolicy": {"bindings": []},
                "_coverage": {"iamPolicy": {"status": "collected"}}}


def test_global_and_regional_authorization_policy_policies_are_collected():
    module = catalog()
    collector = Collector()
    pages = list(module.regional_pages(collector, PROJECT,
                                      "ngfw_authz_policy"))
    names = {row["name"] for batch, _ in pages for row in batch}
    assert names == {GLOBAL, REGIONAL}
    assert ROOT + "/" + GLOBAL + ":getIamPolicy" in collector.urls
    assert ROOT + "/" + REGIONAL + ":getIamPolicy" in collector.urls
