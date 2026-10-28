# Azure ML scoring deny-assignment proof

The existing Azure snapshot already includes ARM deny assignments; this
analysis change adds no read or source pin. Microsoft's [deny-assignment
documentation](https://learn.microsoft.com/en-us/azure/role-based-access-control/deny-assignments)
states that a deny can block a role grant, that `actions` and `dataActions`
apply to control-plane and data-plane operations respectively, and that
`notActions`, `notDataActions`, principal exclusions, and child-scope inheritance
limit a deny.

The native ML scoring review now recognizes an unconditional All Principals
deny inherited by the observed endpoint for its exact mode-specific action.
It reports that particular outside-principal grant as blocked, with deny
provenance. A scoped deny that does not inherit, a principal exclusion, an
action exclusion, a condition, or a different endpoint leaves the declared
grant unresolved. This does not establish whether another credential or
network path exists. Tests use local snapshots only; no cloud read or policy
mutation occurs.
