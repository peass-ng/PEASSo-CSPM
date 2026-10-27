# Azure Redis firewall child read source proof

The reviewed collector source changes from SHA-256
`f899464d9897f9c957d83bad386c4638bbbf6b16e5471666fa05f86593fb9065`
to `ffaaf9f9eee4ad30ff7b8cdcb38925d9a66539defea703954a5c4303dcd3a3e8`.
The sole collector edit is this line in `EMBEDDED_LISTS`:

```diff
+    "redis_cache": (("firewallRules", "firewallRules", "2024-11-01"),),
```

For each collected Redis cache, `_embed` now schedules one read-only paged ARM
`GET {cache-id}/firewallRules?api-version=2024-11-01` through the existing
scan reader. The reader bounds calls/pages, validates child IDs and records
`_coverage.firewallRules`; noncomplete reads remain unresolved. It does not
read keys, credentials, or cache data. The existing `_azure_redis` assessment
uses the resulting `startIP`/`endIP` rules. A completed empty list means no
configured firewall restriction, as [Microsoft's network isolation guidance](https://learn.microsoft.com/azure/azure-cache-for-redis/cache-network-isolation)
states. The [Microsoft ARM resource reference](https://learn.microsoft.com/azure/templates/microsoft.cache/redis/firewallrules)
documents the child type and 2024-11-01 version.

The reviewed whole-file successor retains its archived epoch source and
predecessor digests. Current-byte pins are refreshed with
`scripts/peaso_repin_sources.py`; source and runtime admission tests must pass
before this change is used. Tests cover a single request, a public rule, an
empty list, and a malformed response that must yield `UNKNOWN`.
The focused collector, exposure, re-pin, and next-main provider-source suite
passed 67/67 after refreshing the pins. A structural JSON comparison of the
reviewed collector successor confirms that only
`sources.peaso/collectors/azure.py.current_sha256` changed; both archived
epoch digests are unchanged.
