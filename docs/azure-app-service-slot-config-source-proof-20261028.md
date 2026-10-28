# Azure App Service slot configuration source proof

The reviewed Azure collector changes from SHA-256
`68cc1bfea5378023def4918d28648e04237cd0beaad12b8e5a18896344adabce`
to `7f44e70205f6fb4ffbea3b787af2947871236d16e50095eb8660f6ac846d690f`.
Its only source change adds `config/web` to the existing slot singleton reads:

```diff
-    "app_service_slot": (("scmBasicAuthPolicy", "basicPublishingCredentialsPolicies/scm", "2023-12-01"),),
+    "app_service_slot": (("configuration", "config/web", "2023-12-01"),
+                         ("scmBasicAuthPolicy", "basicPublishingCredentialsPolicies/scm", "2023-12-01")),
```

The [Microsoft slot configuration GET API](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/get-configuration-slot?view=rest-appservice-2025-05-01)
defines this read-only child path. Existing singleton collection uses a per-scan
request cache and stores collection status. It projects only `APP_CONFIG_FIELDS`
from `properties`, so application settings and connection-string values are not
stored. The native assessor accepts only a collected config whose ID matches the
slot's own `/config/web` child; a partial read or mismatched ID stays `UNKNOWN`.

`scripts/peaso_repin_sources.py` refreshed the current-byte pins. The archived
epoch source and predecessor digests remain fixed. The collector test verifies
the slot read and absence of a mock secret in the saved snapshot.
