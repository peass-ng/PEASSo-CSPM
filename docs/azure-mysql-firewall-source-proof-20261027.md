# Azure MySQL flexible firewall child read source proof

The collector changes from SHA-256
`ffaaf9f9eee4ad30ff7b8cdcb38925d9a66539defea703954a5c4303dcd3a3e8`
to `542fdd09cadd2d82b619656d4fdb5ebd92d2f02d8e8d64d8bca2e5302b7f56f6`.
The sole collector diff adds this tuple to the existing MySQL flexible
`EMBEDDED_LISTS` entry:

```diff
+("firewallRules", "firewallRules", "2023-12-30")
```

`_embed` schedules one read-only paged ARM GET at
`{server-id}/firewallRules?api-version=2023-12-30` through the bounded scan
reader. Existing child-ID validation and `_coverage.firewallRules` distinguish
complete, empty and incomplete reads. The read contains firewall IP ranges;
it does not fetch database contents or credentials. The
[Microsoft MySQL firewall API](https://learn.microsoft.com/en-us/rest/api/mysql/firewall-rules?view=rest-mysql-2023-12-30)
lists the child read, and [Microsoft's public networking guidance](https://learn.microsoft.com/en-us/azure/mysql/flexible-server/concepts-networking-public)
describes the default-deny rule semantics and cross-tenant Azure option.

`scripts/peaso_repin_sources.py` refreshes only current-byte successor pins.
The archived epoch source and predecessor digests must remain fixed. Focused
tests check the single child request and the native MySQL/PostgreSQL public,
cross-tenant, empty, malformed and incomplete decisions.
The focused collector, exposure, re-pin and provider-source suite passed 70/70;
the combined internet-exposure suite passed 125/125. Structural comparison of
the reviewed collector successor confirms that only the Azure collector's
`current_sha256` field changed; both archived epoch digests are unchanged.
