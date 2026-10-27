# Azure ML online endpoint child source proof

The reviewed Azure collector changes from SHA-256
`542fdd09cadd2d82b619656d4fdb5ebd92d2f02d8e8d64d8bca2e5302b7f56f6`
to `ff572e31bb8c51971f261bfd28a86305bf73f3e42007fb0db644a907d856a315`.
The collector diff adds one `onlineEndpoints` entry to the existing
`ml_workspace` `EMBEDDED_LISTS` tuple and includes that field in the existing
child identity/type validation and page-dedup sets. No other collector read is
changed. The new call is a read-only paged ARM
`GET {workspace-id}/onlineEndpoints?api-version=2024-04-01` through the same
per-scan cached reader. `_coverage.onlineEndpoints` distinguishes completed,
empty, denied and partial reads. It reads endpoint metadata and scoring URI,
not models, scoring data or credentials.

[Microsoft's online endpoint LIST API](https://learn.microsoft.com/en-us/rest/api/azureml/online-endpoints/list?view=rest-azureml-2024-04-01)
documents the exact child path and public access fields. The existing
2024-04-01 workspace response does not document the newer `networkAcls`
selected-IP policy, so an enabled public gate without that policy remains
`UNKNOWN` in the native assessment. The
[current workspace schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.machinelearningservices/workspaces)
documents the additional ACL field; a separately reviewed read is needed to
close that remaining fact.

`scripts/peaso_repin_sources.py` refreshes current-byte successor pins after
this diff. Archived epoch source and predecessor digests stay fixed. Focused
tests cover one cached child request, foreign child rejection, and online
endpoint plus workspace ACL decisions.
