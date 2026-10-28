# Microsoft Sentinel automation playbooks

The [Automation Rules List API](https://learn.microsoft.com/en-us/rest/api/securityinsights/automation-rules/list?view=rest-securityinsights-2025-09-01) returns read-only, paged rules for a Sentinel workspace. `properties.triggeringLogic.isEnabled` and `expirationTimeUtc` determine whether a rule can run; a `RunPlaybook` action includes the Logic App resource ID and optional tenant ID. [Sentinel automation guidance](https://learn.microsoft.com/en-us/azure/sentinel/automate-incident-handling-with-automation-rules) says playbooks can receive incident/alert details and can run in a different tenant under Azure Lighthouse.

`azure_sentinel_automation_exposure.collect` reuses the cached Sentinel workspace or Log Analytics workspace inventory, checks onboarding only when needed, and reads each Sentinel workspace's automation-rule LIST once through the per-scan cache. It projects only enabled/expiration state and Logic App resource/tenant IDs, discarding rule names, conditions, task descriptions, and unrelated action contents.

`internet_exposure._azure_sentinel_automation_rule` reports an enabled, unexpired rule routing an incident or alert payload to a playbook in another subscription or tenant. A local playbook is `UNKNOWN` because the automation-rule API does not return its downstream connector recipients. Disabled or expired rules are not active exposure routes.

Microsoft Sentinel product review remains open for repository/source-control integrations and other service-specific access paths.
