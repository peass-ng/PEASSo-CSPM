"""Instance-level VM scale set public IPs are joined to their NIC and NSG."""

from peaso.analysis.internet_exposure import Inventory, _azure_backend_nics, assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/ss"
NIC = RID + "/virtualMachines/0/networkInterfaces/nic1"
CONFIG = NIC + "/ipConfigurations/ip1"
PUBLIC = CONFIG + "/publicIPAddresses/pub1"
SUBNET = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/default"


def _result(public_address="8.8.8.8", public_ref=PUBLIC, malformed=False, sku="Basic"):
    parent = {"id": RID, "type": "Microsoft.Compute/virtualMachineScaleSets", "properties": {}}
    nic = {"id": NIC, "name": "nic1", "properties": {"ipConfigurations": [
        {"id": CONFIG, "name": "ip1", "properties": {"privateIPAddress": "10.0.0.4",
          "subnet": {"id": SUBNET}, "publicIPAddress": {"id": public_ref}}}]}}
    public = {"id": PUBLIC, "name": "pub1", "sku": {"name": sku}, "properties": {
        "ipAddress": public_address, "ipConfiguration": {"id": CONFIG}, "provisioningState": "Succeeded"}}
    calls = []

    def request(url, **kwargs):
        calls.append(url)
        if "/networkInterfaces?" in url:
            return {"value": [{**nic, "id": "/subscriptions/foreign/invalid"}] if malformed else [nic]}
        if "/publicipaddresses?" in url:
            return {"value": [public]}
        return {"value": []}

    azure._embed(azure._Reader({}), request, [("vm_scale_set", parent)],
                 skip=("diagnosticSettings", "virtualMachines"))
    snap = make_snapshot("azure", [SCOPE], [
        {"type": "vm_scale_set", "scope": SCOPE, "service": "Microsoft.Compute",
         "status": "collected", "items": [parent]},
        {"type": "subnet", "scope": SCOPE, "service": "Microsoft.Network",
         "status": "collected", "items": [{"id": SUBNET, "properties": {}}]},
    ])
    result = next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "vm_scale_set")
    return result, calls, parent


def test_vmss_instance_public_ip_is_detected_once():
    result, calls, parent = _result()
    assert result.verdict() == "FAIL" and result.addresses == ["8.8.8.8"]
    assert len([url for url in calls if "/networkInterfaces?" in url]) == 1
    assert len([url for url in calls if "/publicipaddresses?" in url]) == 1
    assert parent["_coverage"]["vmssNetworkInterfaces"]["status"] == "collected"
    assert parent["_coverage"]["vmssPublicIPAddresses"]["status"] == "collected"


def test_vmss_public_ip_binding_and_collection_uncertainty():
    assert _result(public_ref=CONFIG + "/publicIPAddresses/other")[0].verdict() == "UNKNOWN"
    assert _result(public_address=None)[0].verdict() == "UNKNOWN"
    assert _result(malformed=True)[0].verdict() == "UNKNOWN"
    assert _result(sku="Standard")[0].verdict() == "PASS"


def test_vmss_nics_feed_load_balancer_backend_join():
    result, _, parent = _result()
    pool = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb/backendAddressPools/pool"
    parent["vmssNetworkInterfaces"][0]["properties"]["ipConfigurations"][0]["properties"][
        "loadBalancerBackendAddressPools"] = [{"id": pool}]
    snap = make_snapshot("azure", [SCOPE], [{"type": "vm_scale_set", "scope": SCOPE,
        "service": "Microsoft.Compute", "status": "collected", "items": [parent]}])
    matches = list(_azure_backend_nics(Inventory(snap, resources(snap)), {pool}))
    assert len(matches) == 1 and matches[0][0]["id"] == NIC


def test_legacy_vmss_inbound_nat_pool_reaches_instance():
    _, _, parent = _result()
    base = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network"
    lb, pip = base + "/loadBalancers/lb", base + "/publicIPAddresses/frontend"
    front, pool = lb + "/frontendIPConfigurations/front", lb + "/inboundNatPools/ssh"
    parent["vmssNetworkInterfaces"][0]["properties"]["ipConfigurations"][0]["properties"][
        "loadBalancerInboundNatPools"] = [{"id": pool}]
    snap = make_snapshot("azure", [SCOPE], [
        {"type": "vm_scale_set", "scope": SCOPE, "service": "Microsoft.Compute", "status": "collected",
         "items": [parent]},
        {"type": "load_balancer", "scope": SCOPE, "service": "Microsoft.Network", "status": "collected",
         "items": [{"id": lb, "sku": {"name": "Basic"}, "properties": {
             "frontendIPConfigurations": [{"id": front, "properties": {"publicIPAddress": {"id": pip}}}],
             "inboundNatPools": [{"id": pool, "name": "ssh", "properties": {
                 "frontendIPConfiguration": {"id": front}, "protocol": "Tcp",
                 "frontendPortRangeStart": 50000, "frontendPortRangeEnd": 50010,
                 "backendPort": 22}}]}}]},
        {"type": "public_ip", "scope": SCOPE, "service": "Microsoft.Network", "status": "collected",
         "items": [{"id": pip, "properties": {"ipAddress": "9.9.9.9"}}]},
        {"type": "subnet", "scope": SCOPE, "service": "Microsoft.Network", "status": "collected",
         "items": [{"id": SUBNET, "properties": {}}]},
    ])
    lb_result = next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "load_balancer")
    assert lb_result.verdict() == "FAIL"
    assert lb_result.ports == {"tcp": ((50000, 50010),)}
    backend_pool = lb + "/backendAddressPools/pool"
    snap["collections"][0]["items"][0]["vmssNetworkInterfaces"][0]["properties"]["ipConfigurations"][0]["properties"][
        "loadBalancerBackendAddressPools"] = [{"id": backend_pool}]
    lb_data = snap["collections"][1]["items"][0]
    lb_data["properties"]["inboundNatPools"] = []
    lb_data["properties"]["inboundNatRules"] = [{"id": lb + "/inboundNatRules/ssh2", "name": "ssh2",
        "properties": {"frontendIPConfiguration": {"id": front},
                       "backendAddressPool": {"id": backend_pool}, "protocol": "Tcp",
                       "frontendPortRangeStart": 51000, "frontendPortRangeEnd": 51010,
                       "backendPort": 22}}]
    v2 = next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "load_balancer")
    assert v2.verdict() == "FAIL" and v2.ports == {"tcp": ((51000, 51010),)}
