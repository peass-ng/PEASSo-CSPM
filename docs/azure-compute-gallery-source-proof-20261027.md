# Azure Compute Gallery sharing inventory source proof

The reviewed collector changes from SHA-256
`ff572e31bb8c51971f261bfd28a86305bf73f3e42007fb0db644a907d856a315`
to `68cc1bfea5378023def4918d28648e04237cd0beaad12b8e5a18896344adabce`.
The collector source diff adds the `ENDPOINTS` entry and requires a full
resource GET for each listed gallery:

```diff
+    'compute_gallery': ('Microsoft.Compute/galleries', '2026-04-01'),
-                            "image_template",
+                            "image_template", "compute_gallery",
```

The existing ARM inventory path performs one read-only paged subscription
`GET /providers/Microsoft.Compute/galleries` and a cached GET for each listed
gallery. Existing identity/type validation and per-scan request caching apply.
The [Microsoft Gallery LIST API](https://learn.microsoft.com/en-us/rest/api/compute/galleries/list?view=rest-compute-2026-04-01)
documents `properties.sharingProfile.permissions` (`Private`, `Groups`,
`Community`) and sharing groups. This read does not enumerate gallery image
versions or inspect image data. The native assessment describes a community
sharing policy as a capability, not proof that an image version is published.

Current-byte source pins are refreshed with `scripts/peaso_repin_sources.py`.
The reviewed successor's archived epoch source and predecessor digests remain
fixed. A focused transport test checks one list and one GET through the
collector; native tests check community, private and direct-sharing policy.
