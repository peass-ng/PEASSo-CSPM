"""Azure Data Share provider recipient collection and native exposure decisions."""

from urllib.parse import urlsplit

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources
from tests.test_peaso_azure_bulk_native import BASE, SCOPE, SUB, Transport, parent

ACCOUNT = BASE + "Microsoft.DataShare/accounts/account"
SHARE = ACCOUNT + "/shares/share"
INVITATION = SHARE + "/invitations/invite"
SUBSCRIPTION = SHARE + "/providerShareSubscriptions/receiver"
OWNER = "22222222-2222-2222-2222-222222222222"
FOREIGN = "33333333-3333-3333-3333-333333333333"


def test_selected_data_share_reads_each_provider_list_once():
    paths = {
        SCOPE + "/providers/Microsoft.DataShare/accounts": {
            "value": [parent(ACCOUNT, "Microsoft.DataShare/accounts", {})]},
        ACCOUNT: parent(ACCOUNT, "Microsoft.DataShare/accounts", {}),
        ACCOUNT + "/shares": {"value": [parent(SHARE, "Microsoft.DataShare/accounts/shares", {})]},
        SHARE + "/invitations": {"value": [parent(INVITATION,
            "Microsoft.DataShare/accounts/shares/invitations",
            {"invitationStatus": "Accepted", "targetActiveDirectoryId": FOREIGN})]},
        SHARE + "/providerShareSubscriptions": {"value": [parent(SUBSCRIPTION,
            "Microsoft.DataShare/accounts/shares/providerShareSubscriptions",
            {"shareSubscriptionStatus": "Active", "consumerTenantName": "Other"})]},
    }
    api = Transport(paths)
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["data_share_invitation", "data_share_provider_subscription"], transport=api)
    for kind in ("data_share_account", "data_share_share", "data_share_invitation",
                 "data_share_provider_subscription"):
        assert len([row for row in snapshot["collections"] if row["type"] == kind]) == 1
    expected = (set(paths) - {ACCOUNT}) | {
        ACCOUNT + "/providers/Microsoft.Insights/diagnosticSettings"}
    assert {urlsplit(url).path for url in api.calls} == expected
    assert len(api.calls) == len(expected)


def test_foreign_share_list_cannot_trigger_recipient_reads():
    foreign = SHARE.replace("/accounts/account/", "/accounts/other/")
    api = Transport({
        SCOPE + "/providers/Microsoft.DataShare/accounts": {
            "value": [parent(ACCOUNT, "Microsoft.DataShare/accounts", {})]},
        ACCOUNT + "/shares": {"value": [parent(foreign,
            "Microsoft.DataShare/accounts/shares", {})]},
    })
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["data_share_invitation"], transport=api)
    shares = [row for row in snapshot["collections"] if row["type"] == "data_share_share"]
    assert len(shares) == 1 and shares[0]["status"] != "empty"
    assert not any("/invitations" in url for url in api.calls)


def test_data_share_external_and_revoked_recipient_decisions():
    def decision(kind, status, props=None, metadata=None):
        rid = INVITATION if kind == "data_share_invitation" else SUBSCRIPTION
        item = parent(rid, "Microsoft.DataShare/accounts/shares/" +
                      ("invitations" if kind == "data_share_invitation" else "providerShareSubscriptions"),
                      {("invitationStatus" if kind == "data_share_invitation" else "shareSubscriptionStatus"): status,
                       **(props or {})})
        snapshot = make_snapshot("azure", [SCOPE], [{"type": kind, "scope": SHARE,
            "service": "Microsoft.DataShare", "status": "collected", "items": [item]}],
            metadata=metadata or {})
        rows = assess(snapshot, resources(snapshot))
        assert len(rows) == 1
        return rows[0]

    owner = {"subscription_tenants": {SCOPE: OWNER}}
    accepted = decision("data_share_invitation", "Accepted",
                        {"targetActiveDirectoryId": FOREIGN}, owner)
    assert accepted.verdict() == "UNKNOWN" and accepted.external_ids == [FOREIGN]
    assert decision("data_share_invitation", "Pending",
                    {"targetActiveDirectoryId": FOREIGN}, owner).verdict() == "UNKNOWN"
    assert decision("data_share_invitation", "Accepted",
                    {"targetEmail": "someone@example.org"}, owner).verdict() == "UNKNOWN"
    assert decision("data_share_invitation", "Rejected", metadata=owner).verdict() == "PASS"
    assert decision("data_share_provider_subscription", "Active").verdict() == "FAIL"
    assert decision("data_share_provider_subscription", "Revoked").verdict() == "PASS"
