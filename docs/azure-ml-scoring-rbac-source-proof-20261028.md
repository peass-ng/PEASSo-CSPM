# Azure ML scoring RBAC source proof

The existing snapshot includes online endpoint `authMode`, ARM role assignments
and role definitions, and observed Entra Guest, foreign service-principal, and
group membership facts. This analysis change adds no collector call or source
pin. It joins an assignment inherited by the exact observed endpoint to its
role definition and outside principal, including observed group members.

Microsoft's [online-endpoint authorization guide](https://learn.microsoft.com/en-us/azure/machine-learning/concept-endpoints-online-auth?view=azureml-api-2)
identifies the required actions: `score/action` to invoke an `AADToken`
endpoint, `token/action` to obtain an `AMLToken`, and `listKeys/action` to
obtain a key. The [Azure RBAC permission catalog](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/ai-machine-learning)
lists these exact operation names. Native findings match the mode-specific
action against role grants and exclusions, preserve assignment conditions as
MANUAL, and report outside identities with source provenance. An observed
grant is a declared capability; deny assignments, PIM activation, network
access, and runtime authorization remain outside this decision. Tests use
local snapshots; no cloud read or credential retrieval occurs.
