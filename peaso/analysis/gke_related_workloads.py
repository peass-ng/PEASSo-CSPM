"""Use a supplied Kubernetes snapshot of a GKE cluster when the GCP side could not read its workloads.

The GCP collector reads Services, Pods, Nodes, Ingresses and EndpointSlices from each GKE
control plane. When that read failed (private endpoint, authorized networks, missing RBAC),
a scan of the same cluster with --provider k8s holds the same objects. Its items go through
the GCP collector's own projections, so exposure analysis sees exactly the fields it would
have read itself; the inventory marker records that the rows came from the related snapshot.
"""
import hashlib
from types import SimpleNamespace

from peaso.collectors import gcp_gke_exposure_services as gke

READERS = {
    gke.KIND: ("service", gke.ServiceReader, "ServiceList", "v1"),
    gke.POD_KIND: ("pod", gke.PodReader, "PodList", "v1"),
    gke.NODE_KIND: ("node", gke.NodeReader, "NodeList", "v1"),
    gke.INGRESS_KIND: ("ingress", gke.IngressReader, "IngressList", "networking.k8s.io/v1"),
    gke.ENDPOINTSLICE_KIND: ("endpointslice", gke.EndpointSliceReader, "EndpointSliceList", "discovery.k8s.io/v1"),
}
K8S_ONLY_FIELDS = ("id", "provenance", "_static_pod_metadata")


def _clusters(resources):
    clusters = {}
    for resource in resources:
        data = resource.get("data")
        if resource.get("type") != "gke_cluster" or not isinstance(data, dict):
            continue
        name, location, endpoint = data.get("name"), data.get("location"), data.get("endpoint")
        if not all(isinstance(value, str) and value for value in (name, location, endpoint)):
            continue
        selection = f"{resource['scope']}/locations/{location}/clusters/{name}"
        identities = {selection, "//container.googleapis.com/" + selection,
                      "k8s-cluster:" + hashlib.sha256(f"https://{endpoint}".encode()).hexdigest()}
        clusters[selection] = (endpoint, identities)
    return clusters


def join(resources, related_snapshots):
    """Return resources with unread GKE workload inventories filled from a matching K8s snapshot."""
    from peaso.snapshot import resources as snapshot_resources
    related = [r for r in related_snapshots or () if r.get("provider") == "k8s"]
    markers = [r for r in resources if r.get("type") in READERS and isinstance(r.get("data"), dict)
               and r["data"].get("inventoryStatus") not in (None, "collected")]
    if not related or not markers:
        return resources
    clusters = _clusters(resources)
    replaced, added = {}, []
    for marker in markers:
        selection = marker["data"].get("cluster")
        if selection not in clusters:
            continue
        endpoint, identities = clusters[selection]
        matches = [r for r in related if (r.get("metadata") or {}).get("cluster_id") in identities]
        if len(matches) != 1:
            continue
        snapshot = matches[0]
        k8s_type, reader_type, list_kind, api_version = READERS[marker["type"]]
        states = {c.get("status") for c in snapshot.get("collections", []) if c.get("type") == k8s_type}
        if not states or not states <= {"collected", "empty"}:
            continue
        items = [{k: v for k, v in r["data"].items() if k not in K8S_ONLY_FIELDS}
                 for r in snapshot_resources(snapshot) if r["type"] == k8s_type and isinstance(r.get("data"), dict)]
        binding = {"selection": selection, "endpoint": endpoint, "ca_sha256": None,
                   "endpointTrust": "related_k8s_snapshot"}
        reader = reader_type(SimpleNamespace(transport=None), binding, None, {"resources": 0})
        try:
            rows = [row for start in range(0, len(items), gke.PAGE_SIZE)
                    for row in reader.project_list({"apiVersion": api_version, "kind": list_kind,
                                                    "metadata": {"resourceVersion": "0"},
                                                    "items": items[start:start + gke.PAGE_SIZE]}, reader.PATH)["items"]]
        except (ValueError, TypeError, KeyError, AttributeError):
            continue
        data = {k: v for k, v in marker["data"].items() if k != "reason"}
        data.update(inventoryStatus="collected", source="related_k8s_snapshot",
                    relatedSnapshotId=snapshot.get("snapshot_id"), gcpReadReason=marker["data"].get("reason"))
        replaced[marker["id"]] = dict(marker, data=data)
        for row in rows:
            added.append({"id": "sha256:" + hashlib.sha256(("related:" + row["name"]).encode()).hexdigest(),
                          "native_id": row["name"], "type": marker["type"], "service": marker.get("service"),
                          "scope": marker["scope"], "provider": marker.get("provider"), "data": row})
    if not replaced:
        return resources
    return [replaced.get(r.get("id"), r) for r in resources] + added
