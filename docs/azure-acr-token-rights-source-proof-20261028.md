# Azure Container Registry token-rights evidence

The Azure collector already reads registry `tokens` and `scopeMaps` through
paged ARM LISTs and retains only token `status`/`scopeMapId` and scope-map
`actions`. This change adds no collector call or source pin. The native
registry assessment joins an explicitly enabled token to a collected scope
map and records its repository actions. It also records an explicitly enabled
registry admin user. Missing or denied token/scope-map inventory is reported
as incomplete; disabled tokens are not reported as active rights.

Microsoft's [repository-token documentation](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-token-based-repository-permissions)
states that a token and generated password permit the listed repository
actions, and that token passwords cannot be retrieved after generation. The
scan therefore records configured capability, not a known password holder or
an observed third-party recipient. The network listener verdict remains
separate. Tests use snapshot fixtures and the existing metadata-only child
projection; no cloud access or credential read occurs.
