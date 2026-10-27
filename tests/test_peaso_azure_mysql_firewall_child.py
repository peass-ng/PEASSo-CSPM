"""MySQL flexible firewall rules use the reviewed per-scan child reader."""

from peaso.collectors import azure


def test_mysql_flexible_firewall_child_list_once():
    rid = ("/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/"
           "providers/Microsoft.DBforMySQL/flexibleServers/db")
    child = {"id": rid + "/firewallRules/public", "name": "public",
             "type": "Microsoft.DBforMySQL/flexibleServers/firewallRules",
             "properties": {"startIpAddress": "8.8.8.8", "endIpAddress": "8.8.8.8"}}
    urls = []

    def request(url, **kwargs):
        urls.append(url)
        return {"value": [child] if "/firewallRules?" in url else []}

    item = {"id": rid, "type": "Microsoft.DBforMySQL/flexibleServers", "properties": {}}
    azure._embed(azure._Reader({}), request, [("mysql_flexible_server", item)],
                 skip=("diagnosticSettings",))
    firewall_url = "https://management.azure.com" + rid + "/firewallRules?api-version=2023-12-30"
    assert urls.count(firewall_url) == 1
    assert len(urls) == 3
    assert item["_coverage"]["firewallRules"]["status"] == "collected"
    assert item["firewallRules"][0]["properties"] == child["properties"]
